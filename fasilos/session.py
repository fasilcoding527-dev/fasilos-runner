import os, pty, ssl, socket, select, json, time, struct, fcntl, termios, signal, base64, hmac, hashlib, urllib.request, urllib.parse
URL = os.environ.pop('FASIL_URL').rstrip('/'); KEY = os.environ.pop('FASIL_KEY'); SID = os.environ['SID']
TOK = hmac.new(KEY.encode(), SID.encode(), hashlib.sha256).hexdigest(); del KEY
OUT = os.path.expanduser('~/output'); END = time.time() + 5.5 * 3600
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
RC = os.path.expanduser('~/.fasilrc')
open(RC, 'w').write('[ -f /etc/profile ] && . /etc/profile\n[ -f ~/.bashrc ] && . ~/.bashrc\nPS1="\\[\\e[1;32m\\]fasil@terminal\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ "\n')
def shell():
    u = urllib.parse.urlsplit(URL); s = socket.create_connection((u.hostname, u.port or (443 if u.scheme == 'https' else 80)), 20)
    if u.scheme == 'https': s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
    s.sendall(('GET /agent/term?sid=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nAuthorization: Bearer %s\r\nUser-Agent: fasilos-session\r\n\r\n' % (SID, u.netloc, base64.b64encode(os.urandom(16)).decode(), TOK)).encode())
    buf = bytearray()
    while b'\r\n\r\n' not in buf:
        d = s.recv(4096)
        if not d: raise SystemExit('closed')
        buf += d
    head, rest = bytes(buf).split(b'\r\n\r\n', 1); buf = bytearray(rest)
    if b' 101 ' not in head.split(b'\r\n')[0]: raise SystemExit('refused')
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(OUT); os.environ['TERM'] = 'xterm-256color'; os.execvp('bash', ['bash', '--rcfile', RC, '-i'])
    SOCK.append(s); ping = time.time()
    try:
        while time.time() < END:
            for op, d in parse(buf):
                if op == 8: return
                if op == 9: s.sendall(frame(d, 10))
                if op == 1:
                    m = json.loads(d)
                    if 'i' in m:
                        b = m['i'].encode()
                        while b: b = b[os.write(fd, b):]
                    if 'r' in m: fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', int(m['r'][1]), int(m['r'][0]), 0, 0))
                    if m.get('net'): r = netprobe(); r['net'] = str(m['net'])[:20]; s.sendall(frame(json.dumps(r).encode(), 1))
            p = getattr(s, 'pending', lambda: 0)()
            r = select.select([s, fd], [], [], 0 if p else 10)[0]
            if p or s in r:
                d = s.recv(65536)
                if not d: return
                buf += d
            if fd in r:
                time.sleep(0.03); d = os.read(fd, 32768)
                if not d: return
                s.sendall(frame(d, 2))
            if time.time() - ping > 50: s.sendall(frame(b'', 9)); ping = time.time()
    except OSError: pass
    finally:
        try: os.killpg(pid, signal.SIGKILL)
        except OSError: pass
SKIP = {'node_modules', '__pycache__', 'venv', 'env', 'site-packages'}
MAX_FILE, MAX_TOTAL, MAX_N = 99 * 1000 * 1000, 500 * 1000 * 1000, 500
def post(route, data, size):
    q = urllib.parse.urlencode({'sid': SID})
    h = {'Authorization': 'Bearer ' + TOK, 'User-Agent': 'fasilos-session', 'Content-Length': str(size), 'Content-Type': 'application/octet-stream'}
    return json.load(urllib.request.urlopen(urllib.request.Request(URL + route + '?' + q, data=data, method='POST', headers=h), timeout=300))
def upload():
    done = []; skipped = []; total = 0
    for root, dirs, files in os.walk(OUT):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not d.startswith('.'))
        for f in sorted(files):
            p = os.path.join(root, f); rel = os.path.relpath(p, OUT)
            if f.startswith('.') or os.path.islink(p) or not os.path.isfile(p): continue
            try:
                n = os.path.getsize(p)
                if n > MAX_FILE or total + n > MAX_TOTAL or len(done) >= MAX_N: skipped.append(rel); continue
                with open(p, 'rb') as fh: done.append({'path': rel, 'sha': post('/agent/out', fh, n)['sha']})
                total += n
            except Exception: skipped.append(rel)
    if not done and not skipped: return None
    body = json.dumps({'files': done, 'skipped': skipped}).encode()
    try: r = post('/agent/commit', body, len(body))
    except Exception: return 'Saving the output FAILED.'
    return 'Saved %d file(s) to %s%s' % (len(done), r['dir'], ', skipped %d (see SKIPPED.txt)' % len(skipped) if skipped else '')
os.makedirs(OUT, exist_ok=True)
SOCK = []
try: shell()
finally:
    msg = upload()
    for s in SOCK:
        try:
            if msg: s.sendall(frame(('\r\n' + msg + '\r\n').encode(), 2))
            s.close()
        except OSError: pass
