# FasilOS Automation Manager task runner (Phase FA1 Manual mode, Phase FB AI modes). Source of src/p27run.js (build-runner.mjs).
# Runs on a GitHub Actions runner. Talks ONLY to the FasilOS Worker (session token). Has no GitHub or provider keys.
import os, re, pty, ssl, json, time, fcntl, hmac, base64, select, signal, socket, struct, termios, hashlib, urllib.request, urllib.parse
URL = os.environ.pop('FASIL_URL').rstrip('/'); KEY = os.environ.pop('FASIL_KEY'); SID = os.environ.pop('SID')
TOK = hmac.new(KEY.encode(), SID.encode(), hashlib.sha256).hexdigest(); del KEY
T0 = time.time(); MAX_FILE = 95 * 1000 * 1000; MAX_FILES = 500; LOG_CAP = 20 * 1000 * 1000; TG_LOG = 20 * 1000 * 1000
ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[=>()][0-9A-B]?')
PATS = [re.compile(p) for p in (r'gh[pousr]_[A-Za-z0-9]{20,}', r'github_pat_[A-Za-z0-9_]{20,}', r'sk-[A-Za-z0-9_-]{20,}', r'AIza[0-9A-Za-z_-]{30,}', r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b', r'xox[baprs]-[A-Za-z0-9-]{10,}', r'(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}')]

def scrub(t):
    for s in (TOK, SID):
        if s: t = t.replace(s, '***')
    for p in PATS: t = p.sub('***', t)
    return t

def frame(d, op):
    n = len(d); m = os.urandom(4)
    h = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0xfe]) + n.to_bytes(2, 'big') if n < 65536 else bytes([0xff]) + n.to_bytes(8, 'big'))
    return h + m + bytes(b ^ m[i % 4] for i, b in enumerate(d))

def parse(buf):
    while len(buf) >= 2:
        n = buf[1] & 127; at = 2
        if n >= 126:
            w = 2 if n == 126 else 8
            if len(buf) < 2 + w: return
            n = int.from_bytes(buf[2:2 + w], 'big'); at = 2 + w
        if len(buf) < at + n: return
        op, d = buf[0] & 15, bytes(buf[at:at + n]); del buf[:at + n]; yield op, d

def http(route, data=None, size=None, timeout=300):
    h = {'Authorization': 'Bearer ' + TOK, 'User-Agent': 'fasilos-session'}
    if data is not None: h['Content-Type'] = 'application/octet-stream'; h['Content-Length'] = str(len(data) if size is None else size)
    q = urllib.parse.urlencode({'sid': SID})
    return urllib.request.urlopen(urllib.request.Request(URL + route + '?' + q, data=data, method='GET' if data is None else 'POST', headers=h), timeout=timeout).read()

def connect():
    u = urllib.parse.urlsplit(URL); s = socket.create_connection((u.hostname, u.port or (443 if u.scheme == 'https' else 80)), 20)
    if u.scheme == 'https': s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
    s.sendall(('GET /agent/term?sid=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nAuthorization: Bearer %s\r\nUser-Agent: fasilos-session\r\n\r\n' % (SID, u.netloc, base64.b64encode(os.urandom(16)).decode(), TOK)).encode())
    buf = bytearray()
    while b'\r\n\r\n' not in buf:
        d = s.recv(4096)
        if not d: raise SystemExit('closed')
        buf += d
    head, rest = bytes(buf).split(b'\r\n\r\n', 1)
    if b' 101 ' not in head.split(b'\r\n')[0]: raise SystemExit('refused')
    return s, bytearray(rest)

task = json.loads(http('/agent/task'))
safe = lambda x: re.sub(r'[^\w.-]+', '-', x).strip('-')[:50] or 'task'
BASE = os.path.expanduser('~/work/' + safe(task['name'])); OUT = BASE + '/output'; LOGS = OUT + '/logs'
for d in ('scripts', 'input', 'output/logs'): os.makedirs(BASE + '/' + d, exist_ok=True)
for sc in task['scripts']:
    p = BASE + '/scripts/' + sc['file']; open(p, 'w', encoding='utf-8').write(sc['text']); os.chmod(p, 0o755)
AI = bool(task.get('ai')); LOGNAME = 'ai-system.log' if AI else 'system.log'; SIL = float(task.get('silenceSec', 300)); NCMD = [0]; CUR = ''
MISS = re.compile(r'command not found|ModuleNotFoundError|No module named|Cannot find module|not installed|Unable to locate package', re.I)
END = T0 + float(task['limitSec']); FAIL = task.get('failRule', 'stop'); NONCE = base64.b32encode(os.urandom(6)).decode().lower().rstrip('=')
TOKEN = '__FOSEND_' + NONCE + '_'; MRE = re.compile(re.escape(TOKEN) + r'(\d+)__\r?\n?')
# ---- logs: ONE file, system.log (everything the terminal printed, with time and step). Secrets are scrubbed.
LOGF = open(LOGS + '/' + LOGNAME, 'w', encoding='utf-8'); logn = 0; label = 'start'; lbuf = ''
def lg(line, lab=None):
    global logn
    if logn > LOG_CAP: return
    t = '[%s] [%s] %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()), lab or label, scrub(line)); logn += len(t)
    LOGF.write(t); LOGF.flush()
    if logn > LOG_CAP: LOGF.write('[log is too long: the rest is not saved]\n'); LOGF.flush()
def logtext(txt):
    global lbuf
    lbuf += ANSI.sub('', txt).replace('\r\n', '\n'); *ls, lbuf = lbuf.split('\n')
    for l in ls: lg(l.split('\r')[-1])
lg('Automation Manager task "%s" (times are UTC)' % task['name'])
S = None; ring = bytearray(); viewing = False
def emit(txt):
    global ring
    b = txt.encode('utf-8', 'replace'); ring += b; del ring[:-20000]
    if viewing and S:
        try: S.sendall(frame(b, 2))
        except OSError: pass
def note(txt): emit(txt.replace('\n', '\r\n')); logtext(txt)
pend = ''
def feed(raw):  # returns (marker exit codes found); shows the rest
    global pend, CUR
    t = pend + raw.decode('utf-8', 'replace'); pend = ''; codes = []; vis = ''; pos = 0
    for m in MRE.finditer(t): vis += t[pos:m.start()]; codes.append(int(m.group(1))); pos = m.end()
    rest = t[pos:]; i = rest.rfind('__FOSEND_')
    if i >= 0 and (TOKEN.startswith(rest[i:]) or re.fullmatch(re.escape(TOKEN) + r'\d{0,4}_?', rest[i:])): pend = rest[i:]; rest = rest[:i]
    else:
        for k in range(min(len(TOKEN) - 1, len(rest)), 0, -1):
            if TOKEN.startswith(rest[-k:]): pend = rest[-k:]; rest = rest[:-k]; break
    vis += rest
    if vis: emit(vis); logtext(vis); CUR = (CUR + ANSI.sub('', vis))[-400000:]
    return codes
def tail(txt):
    txt = scrub('\n'.join(l.split('\r')[-1] for l in txt.replace('\r\n', '\n').split('\n'))).strip('\n')
    return txt[-4000:], len(txt) > 4000
def netprobe():  # Phase G: one short speed check (3 TCP connects to 1.1.1.1:443 = ping, one 1 MB download = speed). Runs only when the owner clicks.
    out = {'ping': None, 'down': None, 'bytes': 0, 'ms': 0}; t = []
    for _ in range(3):
        try: a = time.time(); socket.create_connection(('1.1.1.1', 443), 2).close(); t.append((time.time() - a) * 1000)
        except OSError: pass
    if t: out['ping'] = round(sum(t) / len(t), 1)
    try:
        a = time.time(); n = 0; r = urllib.request.urlopen(urllib.request.Request('https://speed.cloudflare.com/__down?bytes=1000000', headers={'User-Agent': 'fasilos-net'}), timeout=4)
        while time.time() - a < 4:
            c = r.read(65536)
            if not c: break
            n += len(c)
        dt = time.time() - a; out['bytes'] = n; out['ms'] = round(dt * 1000)
        if n and dt > 0: out['down'] = round(n * 8 / dt / 1e6, 2)
    except Exception: pass
    return out
def ev(o):
    try: S.sendall(frame(json.dumps(o).encode(), 1))
    except (OSError, AttributeError): pass
RB = os.path.realpath(BASE)
def dowrite(m):
    rel = str(m.get('path') or ''); p = os.path.realpath(os.path.join(BASE, rel)); code = 0
    if not rel or p == RB or not p.startswith(RB + os.sep): code = 1; msg = 'refused: the path is outside the work folder'
    else:
        try: os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'w', encoding='utf-8').write(str(m.get('text') or '')); msg = 'wrote %d bytes to %s' % (os.path.getsize(p), rel)
        except OSError as e: code = 1; msg = 'write failed: %s' % e
    lg('write %s: %s' % (rel, msg), str(m.get('who') or 'ai')); NCMD[0] += 1; ev({'ev': 'res', 'id': m.get('id'), 'code': code, 'sec': 0, 'out': msg})
def aimsg(m):
    k = str(m.get('k') or 'say'); x = str(m.get('x') or ''); lg('%s: %s' % (k.upper(), x.replace('\n', ' | ')), str(m.get('who') or 'system'))
    if k in ('say', 'done', 'ask', 'next', 'owner', 'warn', 'bench', 'sys'): emit('\r\n\x1b[35m[%s] %s\x1b[0m\r\n' % (str(m.get('who') or 'ai')[:30], x[:300].replace('\n', ' ')))
RC = os.path.expanduser('~/.fasiltask')
open(RC, 'w').write("PS1=''\nPS2=''\nunset HISTFILE\nstty -echo\nbind 'set enable-bracketed-paste off' 2>/dev/null\n[ -f venv/bin/activate ] && . venv/bin/activate\nprintf '\\n%s0__\\n'\n" % TOKEN)
def spawn():
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(BASE); os.environ.update(TERM='xterm-256color', DEBIAN_FRONTEND='noninteractive', PIP_NO_INPUT='1', PIP_DISABLE_PIP_VERSION_CHECK='1')
        os.execvp('bash', ['bash', '--noprofile', '--rcfile', RC, '-i'])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 110, 0, 0)); return pid, fd
def kill(pid):
    try: os.killpg(pid, signal.SIGKILL)
    except OSError: pass
    try: os.waitpid(pid, os.WNOHANG)
    except OSError: pass
# ---- the steps: setup (from the Worker) then the scripts, one by one in order. AI Automation (autorun false): setup only, the AI runs everything.
INT = {'py': 'python', 'sh': 'bash', 'js': 'node'}; en = task['scripts'] if task.get('autorun', True) else []
steps = [{'label': 'setup: ' + x['label'], 'cmd': x['cmd'] + ' < /dev/null', 'to': 1200, 'sc': None} for x in task['setup']]
for j, sc in enumerate(en):
    steps.append({'label': 'script %d/%d %s' % (j + 1, len(en), sc['name']), 'cmd': '%s scripts/%s < /dev/null' % (INT[sc['type']], sc['file']), 'to': int(task.get('scriptSec', 1800)), 'sc': sc})
os.makedirs(BASE + '/.cmd', exist_ok=True)
def run():
    global S, viewing, label, CUR
    S, buf = connect(); pid, fd = spawn(); idx = 0; cur = None; boot = True; st0 = time.time(); sto = 120; status = None; by = None; res = []; ping = time.time(); intr = 0; stop = None
    paused = False; ext = []; sil = False; lastout = time.time(); fin = None
    def endstep(code):
        nonlocal cur, paused, status
        global label
        st = cur; cur = None; sec = int(time.time() - st0); label = st['label']
        note('[fasilos] %s: exit %d (%d s)\n' % (st['label'], code, sec))
        if st.get('xid'):
            NCMD[0] += 1; o, cut = tail(CUR); ev({'ev': 'res', 'id': st['xid'], 'code': code, 'sec': sec, 'out': o, 'cut': cut}); return
        if st.get('killed'): return
        res.append(dict(step=st, code=code, sec=sec))
        if AI:
            if code: paused = True; o, cut = tail(CUR); ev({'ev': 'wake', 'why': 'missing' if MISS.search(CUR) else 'failed', 'label': st['label'], 'code': code, 'out': o})
        elif code and FAIL == 'stop': status = 'failed'
    def start(st):
        nonlocal cur, st0, sto, intr, sil, lastout
        global label, CUR
        now = time.time(); cur = st; label = st['label']; CUR = ''; st0 = now; intr = 0; sil = False; lastout = now
        lg('$ ' + st.get('show', st['cmd']).replace('\n', ' <NL> ')[:2000], st.get('who'))
        emit('\r\n\x1b[1;36m[fasilos] %s\x1b[0m\r\n$ %s\r\n' % (st['label'], st.get('show', st['cmd'])[:300].replace('\n', ' ')))
        os.write(fd, (st['cmd'] + "; printf '\\n" + TOKEN + "%d__\\n' $?\n").encode())
        sto = max(5, min(st['to'], END - now)) if (st['sc'] or st.get('xid')) else st['to']
    def restart():
        nonlocal pid, fd, boot, intr
        kill(pid); pid, fd = spawn(); boot = True; intr = 0
    while status is None and not stop and not fin:
        now = time.time()
        if now >= END: status = 'time limit'; break
        if cur is None and not boot:
            if ext:
                x = ext.pop(0); f = BASE + '/.cmd/' + x['id'] + '.sh'; open(f, 'w', encoding='utf-8').write(x['cmd'] + '\n')
                start({'label': 'ai command ' + x['id'], 'cmd': '. .cmd/%s.sh < /dev/null' % x['id'], 'show': x['cmd'], 'to': x['to'], 'sc': None, 'xid': x['id'], 'who': x['who']})
            elif not paused and idx < len(steps): idx += 1; start(steps[idx - 1])
            elif not paused and idx >= len(steps):
                if not AI: break
                paused = True; ev({'ev': 'wake', 'why': 'all_done' if en else 'ready', 'label': 'script list', 'out': ''})
        elif cur and not boot and ext and not cur.get('xid') and not intr:  # the AI takes over a running script (for example a silent one)
            cur['killed'] = True; paused = True; intr = now; lg('the AI stops the running step', 'system'); os.write(fd, b'\x03')
        elif cur and not boot and not intr and now - st0 > sto:
            intr = now; lg('timeout: Ctrl-C sent'); os.write(fd, b'\x03')
        elif cur and not boot and AI and not sil and not intr and not cur.get('xid') and now - lastout > SIL:
            sil = True; o, cut = tail(CUR); ev({'ev': 'wake', 'why': 'silence', 'label': cur['label'], 'sec': int(now - lastout), 'out': o})
        if intr and now - intr > 8 and cur:
            lg('the step did not stop: shell restarted'); endstep(124)
            if status is None: restart()
            continue
        rl = select.select([S, fd], [], [], 1)[0]
        if getattr(S, 'pending', lambda: 0)() or S in rl:
            try: d = S.recv(65536)
            except OSError: d = b''
            if not d: stop = 'link'; break
            buf += d
        for op, d in parse(buf):
            if op == 8: stop = 'link'
            elif op == 9: S.sendall(frame(d, 10))
            elif op == 1:
                try: m = json.loads(d)
                except ValueError: continue
                if m.get('net'): r = netprobe(); r['net'] = str(m['net'])[:20]; S.sendall(frame(json.dumps(r).encode(), 1)); continue
                c = m.get('ctl')
                if c == 'stop' or (c == 'finish' and not AI): stop = 'owner'
                elif AI and c == 'finish': fin = {'status': m.get('status') if m.get('status') in ('ok', 'failed') else 'ok', 'note': str(m.get('note') or '')[:300]}
                elif AI and c == 'run' and len(ext) < 5: ext.append({'id': re.sub(r'\W', '', str(m.get('id'))) or 'x', 'cmd': str(m.get('cmd') or ''), 'to': max(10, min(float(m.get('to') or 1800), 19800)), 'who': str(m.get('who') or 'ai')})
                elif AI and c == 'write': dowrite(m)
                elif AI and c == 'next': paused = False
                elif AI and c == 'ai': aimsg(m)
                if 'v' in m:
                    viewing = bool(m['v'])
                    if viewing and ring: S.sendall(frame(bytes(ring), 2))
        if fd in rl:
            try: raw = os.read(fd, 32768)
            except OSError: raw = b''
            if not raw:
                lg('the shell ended')
                if cur: endstep(255)
                if status is None: restart()
                continue
            lastout = time.time()
            for code in feed(raw):
                if boot: boot = False; continue
                if cur: endstep(code)
        if time.time() - ping > 50: S.sendall(frame(b'', 9)); ping = time.time()
    if stop: status = 'stopped'; by = stop
    elif fin: status = fin['status']; by = 'ai'
    if status in ('stopped', 'time limit'):
        label = 'end'
        try: os.write(fd, b'\x03'); time.sleep(0.6); feed(os.read(fd, 32768))
        except OSError: pass
        if cur and not boot and not cur.get('xid') and not cur.get('killed'): res.append(dict(step=cur, code=130 if status == 'stopped' else 124, sec=int(time.time() - st0)))
    kill(pid)
    if status is None: status = 'ok' if all(r['code'] == 0 for r in res) else 'failed'
    return status, by, res, (fin or {}).get('note', '')
# ---- output rule: real files = files in output/ other than output/logs/
def collect():
    real = []; skipped = []; total = 0; limit = float(task.get('outMB', 500)) * 1e6
    for root, dirs, files in os.walk(OUT):
        dirs.sort()
        if root == OUT: dirs[:] = [d for d in dirs if d != 'logs']
        for f in sorted(files):
            p = os.path.join(root, f); rel = os.path.relpath(p, OUT)
            if os.path.islink(p) or not os.path.isfile(p): continue
            n = os.path.getsize(p)
            if n > MAX_FILE or total + n > limit or len(real) >= MAX_FILES - 5: skipped.append(rel + ' (%d MB)' % (n // 1000000)); continue
            real.append((p, rel, n)); total += n
    return real, skipped, total
def finish():
    global label
    status, by, res, anote = run(); label = 'end'; note('[fasilos] ending: %s\n' % status)
    real, skipped, total = collect(); done = []; push_fail = False; dirp = None; logsent = None
    for p, rel, n in real:
        try:
            with open(p, 'rb') as fh: done.append({'path': rel, 'sha': json.loads(http('/agent/out', fh, n))['sha']})
        except Exception as e: skipped.append(rel + ' (upload failed)'); total -= n
    if skipped: open(LOGS + '/SKIPPED.txt', 'w').write('Not saved (limit per file 95 MB, total size limit, 500 files, or upload failed):\n' + '\n'.join(skipped[:500]) + '\n')
    lg('files: %d saved, %d skipped, %d bytes' % (len(done), len(skipped), total)); LOGF.close()
    logb = open(LOGS + '/' + LOGNAME, 'rb').read()
    try: summ = open(LOGS + '/summary.md', encoding='utf-8', errors='replace').read(1500)
    except OSError: summ = ''
    if done:
        for f in sorted(os.listdir(LOGS)):
            p = os.path.join(LOGS, f)
            try:
                with open(p, 'rb') as fh: done.append({'path': 'logs/' + f, 'sha': json.loads(http('/agent/out', fh, os.path.getsize(p)))['sha']})
            except Exception: pass
        try: dirp = json.loads(http('/agent/commit', json.dumps({'files': done, 'skipped': []}).encode()))['dir']
        except Exception: push_fail = True
    if not done or push_fail:
        if len(logb) > TG_LOG: logb = logb[-TG_LOG:]; logsent = 'tail'
        else: logsent = 'all'
    rep = {'status': status, 'by': by, 'sec': int(time.time() - T0), 'files': len([d for d in done if not d['path'].startswith('logs/')]), 'bytes': total, 'skipped': skipped[:20], 'nskipped': len(skipped), 'dir': dirp, 'pushFailed': push_fail, 'logSent': logsent,
           'scripts': [{'name': r['step']['sc']['name'], 'ok': r['code'] == 0, 'code': r['code'], 'sec': r['sec']} for r in res if r.get('step') and r['step']['sc']], 'setupFailed': [r['step']['label'] for r in res if r.get('step') and not r['step']['sc'] and r['code']], 'planned': len(en), 'ai': 1 if AI else 0, 'cmds': NCMD[0], 'note': anote, 'summary': summ}
    body = json.dumps(rep).encode() + b'\n' + (logb if logsent else b'')
    for i in range(3):
        try: http('/agent/finish', body); break
        except Exception: time.sleep(2 + i * 3)
    try: S.sendall(frame(b'', 8)); S.close()
    except OSError: pass
finish()
