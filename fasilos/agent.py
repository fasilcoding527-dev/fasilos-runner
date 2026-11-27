# FasilOS Fixzii AI Agent runner (4.8.0 Phase 6a, BETA). Source of src/p32run.js (build-runner.mjs).
# Runs on a GitHub Actions runner (a full Ubuntu Linux). Talks ONLY to the FasilOS Worker (session token). Has no GitHub or provider keys.
# The Worker sends {"x":{id,k,...}} requests (bash, write, read, save, kill, quit). This runner answers with {"ev":...} text frames:
#   hello (ready + system info) | o (live output chunk) | x (finished: code, ms) | saved | bye
# Work folder ~/work is scratch and is never saved. Deliverables go to ~/space: they are saved to GPR "fixzii-space/<chat folder>/".
import os, ssl, json, time, hmac, base64, select, signal, socket, hashlib, threading, subprocess, urllib.request, urllib.parse, shutil
URL = os.environ.pop('FASIL_URL').rstrip('/'); KEY = os.environ.pop('FASIL_KEY'); SID = os.environ['SID']
TOK = hmac.new(KEY.encode(), SID.encode(), hashlib.sha256).hexdigest(); del KEY
HOME = os.path.expanduser('~'); SPACE = os.path.join(HOME, 'space'); WORK = os.path.join(HOME, 'work')
START = time.time(); END = START + 5.5 * 3600; IDLE = 25 * 60
os.makedirs(SPACE, exist_ok=True); os.makedirs(WORK, exist_ok=True)
CWD = [WORK]; LAST = [time.time()]; SOCK = []; LOCK = threading.Lock(); PROCS = {}; SAVED = {}; FOLDER = ['chat']

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
def send(o):
    d = frame(json.dumps(o).encode(), 1)
    with LOCK:
        for s in SOCK:
            try: s.sendall(d)
            except OSError: pass

def sysinfo():
    def sh(c):
        try: return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=8).stdout.strip()
        except Exception: return ''
    return {'os': sh('. /etc/os-release; echo $PRETTY_NAME'), 'kernel': sh('uname -r'), 'cpu': sh('nproc'), 'mem': sh("free -m | awk '/Mem:/{print $2}'"), 'disk': sh("df -h / | awk 'NR==2{print $4}'"),
            'py': sh('python3 --version'), 'node': sh('node --version'), 'git': sh('git --version'), 'user': sh('whoami'), 'sudo': 'yes' if sh('sudo -n true && echo y') == 'y' else 'no'}

def run_bash(r):
    rid = r['id']; cmd = str(r.get('cmd', '')); tmo = max(1, min(int(r.get('t') or 120), 1800)); t0 = time.time()
    mark = os.path.join('/tmp', '.fcwd_' + rid)
    script = cmd + '\n__rc=$?\npwd > ' + mark + ' 2>/dev/null\nexit $__rc\n'
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', CI='1', TERM='dumb', PAGER='cat', GIT_PAGER='cat', GIT_TERMINAL_PROMPT='0', PIP_BREAK_SYSTEM_PACKAGES='1', FIXZII_SPACE=SPACE)
    try:
        p = subprocess.Popen(['bash', '-c', script], cwd=CWD[0], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, preexec_fn=os.setsid)
    except Exception as e:
        send({'ev': 'x', 'id': rid, 'code': 127, 'ms': 0, 'err': str(e)[:300]}); return
    PROCS[rid] = p; buf = b''; last = time.time(); sent = 0; cut = False; reason = ''
    fd = p.stdout.fileno(); done_at = None
    while True:
        if time.time() - t0 > tmo: reason = 'timeout'; break
        if rid not in PROCS: reason = 'stopped'; break
        rl = select.select([fd], [], [], 0.2)[0]
        if rl:
            c = os.read(fd, 16384)
            if c:
                buf += c
            elif p.poll() is not None: break
            else: time.sleep(0.05)
        if p.poll() is not None:  # main shell ended: take what is left, but do not wait for background jobs that keep the pipe open
            if done_at is None: done_at = time.time()
            if not rl and time.time() - done_at > 0.3: break
            if time.time() - done_at > 2: break
        if buf and (time.time() - last > 0.3 or len(buf) > 4096):
            if sent < 300000: send({'ev': 'o', 'id': rid, 'd': buf.decode('utf8', 'replace')}); sent += len(buf)
            elif not cut: cut = True; send({'ev': 'o', 'id': rid, 'd': '\n[output too long: the rest is not shown]\n'})
            buf = b''; last = time.time()
    if buf and sent < 300000: send({'ev': 'o', 'id': rid, 'd': buf.decode('utf8', 'replace')})
    if reason:
        try: os.killpg(p.pid, signal.SIGKILL)
        except OSError: pass
    try: code = p.wait(timeout=3)
    except Exception: code = -9
    PROCS.pop(rid, None)
    try:
        d = open(mark).read().strip()
        if d and os.path.isdir(d): CWD[0] = d
        os.remove(mark)
    except OSError: pass
    send({'ev': 'x', 'id': rid, 'code': code if not reason else (124 if reason == 'timeout' else 130), 'ms': int((time.time() - t0) * 1000), 'cwd': CWD[0], 'err': ('timed out after %d s' % tmo) if reason == 'timeout' else ('stopped' if reason else '')})

def rp(p):
    p = os.path.expanduser(str(p)); return p if os.path.isabs(p) else os.path.join(CWD[0], p)
def run_write(r):
    rid = r['id']; t0 = time.time()
    try:
        p = rp(r['path']); os.makedirs(os.path.dirname(p) or '/', exist_ok=True)
        with open(p, 'a' if r.get('append') else 'w', encoding='utf8') as f: f.write(str(r.get('text', '')))
        send({'ev': 'x', 'id': rid, 'code': 0, 'ms': int((time.time() - t0) * 1000), 'res': 'wrote %d bytes to %s' % (os.path.getsize(p), p)})
    except Exception as e: send({'ev': 'x', 'id': rid, 'code': 1, 'ms': 0, 'err': str(e)[:300]})
def run_read(r):
    rid = r['id']; t0 = time.time()
    try:
        p = rp(r['path']); mx = max(200, min(int(r.get('max') or 20000), 60000))
        if os.path.isdir(p): out = '\n'.join(sorted(os.listdir(p))[:300]); res = '(directory)\n' + out
        else:
            with open(p, 'rb') as f: b = f.read(mx + 1)
            res = b[:mx].decode('utf8', 'replace') + ('\n[cut at %d bytes]' % mx if len(b) > mx else '')
        send({'ev': 'o', 'id': rid, 'd': res}); send({'ev': 'x', 'id': rid, 'code': 0, 'ms': int((time.time() - t0) * 1000)})
    except Exception as e: send({'ev': 'x', 'id': rid, 'code': 1, 'ms': 0, 'err': str(e)[:300]})

# ---- saving to Fixzii Space (GPR fixzii-space/<folder>/): only ~/space. Same Worker routes as the Terminal session.
SKIP = {'node_modules', '__pycache__', 'venv', 'env', 'site-packages', '.git'}
MAX_FILE, MAX_TOTAL, MAX_N = 99 * 1000 * 1000, 500 * 1000 * 1000, 500
def retry(fn, waits=(3, 10, 30)):
    for w in waits:
        try: return fn()
        except Exception: time.sleep(w)
    return fn()
def post(route, data, size):
    q = urllib.parse.urlencode({'sid': SID})
    h = {'Authorization': 'Bearer ' + TOK, 'User-Agent': 'fasilos-agent', 'Content-Length': str(size), 'Content-Type': 'application/octet-stream'}
    return json.load(urllib.request.urlopen(urllib.request.Request(URL + route + '?' + q, data=data, method='POST', headers=h), timeout=300))
def space_files(only=None):
    out = []
    for root, dirs, files in os.walk(SPACE):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not d.startswith('.'))
        for f in sorted(files):
            p = os.path.join(root, f); rel = os.path.relpath(p, SPACE)
            if f.startswith('.') or os.path.islink(p) or not os.path.isfile(p): continue
            if only is not None and not any(rel == o or rel.startswith(o.rstrip('/') + '/') for o in only): continue
            out.append((p, rel))
    return out
def save(paths=None):
    # paths outside ~/space are copied into it first (keeps the file name), so everything saved lives in ONE place
    only = None
    if paths:
        only = []
        for x in paths:
            try:
                p = rp(x)
                if not os.path.exists(p): continue
                if not os.path.realpath(p).startswith(os.path.realpath(SPACE) + os.sep):
                    d = os.path.join(SPACE, os.path.basename(p.rstrip('/')))
                    if os.path.isdir(p): shutil.copytree(p, d, dirs_exist_ok=True, ignore=shutil.ignore_patterns(*SKIP))
                    else: shutil.copy2(p, d)
                    p = d
                only.append(os.path.relpath(p, SPACE))
            except Exception: pass
        if not only: return {'files': [], 'note': 'nothing found to save'}
    done = []; skipped = []; total = 0
    for p, rel in space_files(only):
        try:
            n = os.path.getsize(p); sig = (n, int(os.path.getmtime(p)))
            if SAVED.get(rel) == sig: continue
            if n > MAX_FILE or total + n > MAX_TOTAL or len(done) >= MAX_N: skipped.append(rel); continue
            def up(p=p, n=n):
                with open(p, 'rb') as fh: return post('/agent/out', fh, n)['sha']
            done.append({'path': rel, 'sha': retry(up), 'sig': sig, 'n': n}); total += n
        except Exception: skipped.append(rel)
    if not done and not skipped: return {'files': [], 'note': 'nothing new to save'}
    body = json.dumps({'files': [{'path': d['path'], 'sha': d['sha']} for d in done], 'skipped': skipped, 'folder': FOLDER[0]}).encode()
    try: r = retry(lambda: post('/agent/commit', body, len(body)))
    except Exception: return {'files': [], 'note': 'Saving to Fixzii Space FAILED (Worker or GitHub did not answer)'}
    for d in done: SAVED[d['path']] = d['sig']
    return {'dir': r.get('dir'), 'files': [{'path': d['path'], 'n': d['n']} for d in done], 'skipped': skipped}
def run_save(r):
    rid = r['id']; t0 = time.time()
    if r.get('folder'): FOLDER[0] = str(r['folder'])[:60]
    try: res = save(r.get('paths') or None)
    except Exception as e: res = {'files': [], 'note': str(e)[:200]}
    send({'ev': 'x', 'id': rid, 'code': 0 if res.get('files') or not res.get('note', '').endswith('FAILED (Worker or GitHub did not answer)') else 1, 'ms': int((time.time() - t0) * 1000), 'save': res})

def handle(m):
    k = m.get('k')
    if k in ('bash', 'write', 'read', 'save'): LAST[0] = time.time()
    if k == 'bash': threading.Thread(target=run_bash, args=(m,), daemon=True).start()
    elif k == 'write': threading.Thread(target=run_write, args=(m,), daemon=True).start()
    elif k == 'read': threading.Thread(target=run_read, args=(m,), daemon=True).start()
    elif k == 'save': threading.Thread(target=run_save, args=(m,), daemon=True).start()
    elif k == 'kill':
        p = PROCS.pop(m.get('id'), None)
        if p:
            try: os.killpg(p.pid, signal.SIGKILL)
            except OSError: pass
    elif k == 'folder': FOLDER[0] = str(m.get('folder') or 'chat')[:60]
    elif k == 'quit': return True

def main():
    u = urllib.parse.urlsplit(URL); s = socket.create_connection((u.hostname, u.port or (443 if u.scheme == 'https' else 80)), 20)
    if u.scheme == 'https': s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
    s.sendall(('GET /agent/term?sid=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nAuthorization: Bearer %s\r\nUser-Agent: fasilos-agent\r\n\r\n' % (SID, u.netloc, base64.b64encode(os.urandom(16)).decode(), TOK)).encode())
    buf = bytearray()
    while b'\r\n\r\n' not in buf:
        d = s.recv(4096)
        if not d: raise SystemExit('closed')
        buf += d
    head, rest = bytes(buf).split(b'\r\n\r\n', 1); buf = bytearray(rest)
    if b' 101 ' not in head.split(b'\r\n')[0]: raise SystemExit('refused')
    SOCK.append(s); ping = time.time()
    send({'ev': 'hello', 'info': sysinfo(), 'space': SPACE, 'work': WORK, 'end': int(END)})
    why = 'ended'
    try:
        while time.time() < END:
            for op, d in parse(buf):
                if op == 8: return 'closed'
                if op == 9: s.sendall(frame(d, 10))
                if op == 1:
                    try: m = json.loads(d)
                    except Exception: continue
                    if 'x' in m and handle(m['x']): return 'quit'
            p = getattr(s, 'pending', lambda: 0)()
            r = select.select([s], [], [], 0 if p else 2)[0]
            if p or s in r:
                d = s.recv(65536)
                if not d: return 'closed'
                buf += d
            if time.time() - ping > 40:
                with LOCK: s.sendall(frame(b'', 9))
                ping = time.time()
            if time.time() - LAST[0] > IDLE and not PROCS: return 'idle'
    except OSError: why = 'connection lost'
    return why

why = 'ended'
try: why = main()
finally:
    for p in list(PROCS.values()):
        try: os.killpg(p.pid, signal.SIGKILL)
        except OSError: pass
    try: r = save()
    except Exception: r = {'files': [], 'note': 'final save failed'}
    send({'ev': 'bye', 'why': why, 'save': r})
    time.sleep(0.5)
    for s in SOCK:
        try: s.close()
        except OSError: pass
