#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║           GDrive Downloader — GitHub Actions                 ║
║  Download waterfall:                                         ║
║    1. aria2c  — HTTP/HTTPS, 16 parallel, 1MB splits          ║
║    2. aria2c  — Magnet/torrent (BitTorrent protocol)         ║
║    3. yt-dlp  — Cloudflare bypass via curl_cffi              ║
║    4. curl_cffi — browser TLS fingerprint                    ║
║    5. requests — plain HTTP fallback                         ║
║  Upload: OAuth → resumable Drive API, 512MB chunks           ║
╚══════════════════════════════════════════════════════════════╝
"""

import os, sys, re, time, json, subprocess, tempfile, threading
from pathlib import Path
from urllib.parse import urlparse, unquote

# ── Force unbuffered output — THE fix for GitHub Actions live logs ──
os.environ['PYTHONUNBUFFERED'] = '1'
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

import requests as req_lib
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build

# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════
GDRIVE_FOLDER_ID = '1TRND8VlWi0U7wdHk3HLJ7hvzOw90PDE3'
UPLOAD_CHUNK     = 512 * 1024 * 1024   # 512MB — fewer API round trips
DL_CHUNK         = 16  * 1024 * 1024   # 16MB read buffer
ARIA2C_CONNS     = 16
LOG_INTERVAL     = 8                   # seconds between live log lines
TMP              = tempfile.mkdtemp(prefix='dl_')

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
      'AppleWebKit/537.36 (KHTML, like Gecko) '
      'Chrome/122.0.0.0 Safari/537.36')

HEADERS = {
    'User-Agent':      UA,
    'Accept':          '*/*',
    'Accept-Encoding': 'identity',
    'Accept-Language': 'en-US,en;q=0.9',
}

# ══════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════
def log(msg=''):      print(msg, flush=True)
def hr():             log('─' * 65)
def fmt(b):           return f'{b/1e9:.2f} GB' if b >= 1e9 else f'{b/1e6:.1f} MB'
def spd(bps):         return f'{bps/1e6:.1f} MB/s'

def pct(done, total):
    return f'{done/total*100:.1f}%' if total else fmt(done)

def eta_str(done, total, elapsed):
    if not total or not done or not elapsed or done >= total:
        return ''
    rem = (total - done) / (done / elapsed)
    m, s = divmod(int(rem), 60)
    return f' ETA {m}m{s:02d}s' if m else f' ETA {s}s'

# ══════════════════════════════════════════════════════════════
# HTTP SESSION
# ══════════════════════════════════════════════════════════════
def make_session():
    s     = req_lib.Session()
    s.headers.update(HEADERS)
    retry = req_lib.adapters.Retry(
        3, backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=['GET', 'HEAD', 'PUT', 'POST']
    )
    s.mount('http://',  req_lib.adapters.HTTPAdapter(max_retries=retry))
    s.mount('https://', req_lib.adapters.HTTPAdapter(max_retries=retry))
    return s

SESSION = make_session()

# ══════════════════════════════════════════════════════════════
# OAUTH
# ══════════════════════════════════════════════════════════════
_creds = None

def get_creds() -> Credentials:
    global _creds
    if _creds and not _creds.expired:
        return _creds
    _creds = Credentials(
        token=None,
        refresh_token=os.environ['GDRIVE_REFRESH_TOKEN'],
        token_uri='https://oauth2.googleapis.com/token',
        client_id=os.environ['GDRIVE_CLIENT_ID'],
        client_secret=os.environ['GDRIVE_CLIENT_SECRET'],
        scopes=['https://www.googleapis.com/auth/drive'],
    )
    _creds.refresh(GoogleAuthRequest())
    return _creds

def get_token() -> str:
    c = get_creds()
    if c.expired:
        c.refresh(GoogleAuthRequest())
    return c.token

def get_drive():
    return build('drive', 'v3', credentials=get_creds(), cache_discovery=False)

# ══════════════════════════════════════════════════════════════
# DRIVE HELPERS
# ══════════════════════════════════════════════════════════════
def file_exists(drive, folder_id, fname, expected_size) -> bool:
    safe = fname.replace("'", "\\'")
    q    = f"name='{safe}' and '{folder_id}' in parents and trashed=false"
    res  = drive.files().list(
        q=q, fields='files(id,size)',
        supportsAllDrives=True, includeItemsFromAllDrives=True
    ).execute()
    if not res['files']:
        return False
    ds = int(res['files'][0].get('size', 0))
    return bool(expected_size and ds >= expected_size * 0.98)

# ══════════════════════════════════════════════════════════════
# UTILS
# ══════════════════════════════════════════════════════════════
def sanitize(name: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    name = re.sub(r'_+', '_', name).strip('_ ')
    return name[:200] or f'file_{int(time.time())}'

def referer(url: str) -> str:
    p = urlparse(url)
    return f'{p.scheme}://{p.netloc}/'

def is_magnet(url: str) -> bool:
    return url.strip().lower().startswith('magnet:')

# ══════════════════════════════════════════════════════════════
# URL / MAGNET RESOLVER
# ══════════════════════════════════════════════════════════════
def resolve_url(url: str):
    log('  Resolving...')
    r = None
    for method in ('HEAD', 'GET'):
        try:
            if method == 'HEAD':
                r = SESSION.head(url, allow_redirects=True, timeout=25)
            else:
                r = SESSION.get(url, stream=True, allow_redirects=True, timeout=25)
                r.close()
            if r and r.status_code < 400:
                break
        except Exception as e:
            if method == 'GET':
                log(f'  Resolve warning: {e}')

    final = r.url if r else url
    cd    = r.headers.get('Content-Disposition', '') if r else ''
    m     = re.findall(r"filename\*?=['\"]?(?:UTF-8'')?([^'\";\r\n]+)", cd, re.I)
    if m:
        fname = sanitize(unquote(m[-1].strip()))
    else:
        path  = unquote(urlparse(final).path)
        fname = sanitize(Path(path).name or f'file_{int(time.time())}')
    size = int(r.headers.get('Content-Length', 0)) if r else 0

    log(f'  File : {fname}')
    log(f'  Size : {fmt(size) if size else "unknown"}')
    return final, fname, size

def resolve_magnet(url: str) -> str:
    m = re.search(r'[?&]dn=([^&]+)', url)
    fname = sanitize(unquote(m.group(1).replace('+', ' '))) if m else f'torrent_{int(time.time())}'
    log(f'  Magnet : {fname}')
    return fname

# ══════════════════════════════════════════════════════════════
# PROGRESS MONITOR — background thread, logs every N seconds
# Runs in a daemon thread so it doesn't block anything.
# This is how we get truly live logs in GitHub Actions.
# ══════════════════════════════════════════════════════════════
class ProgressMonitor:
    def __init__(self, path, total_size, label, interval=LOG_INTERVAL):
        self.path     = path
        self.total    = total_size
        self.label    = label
        self.interval = interval
        self._stop    = threading.Event()
        self._t0      = time.time()
        self._thread  = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._t0 = time.time()
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=3)
        try:
            cur = os.path.getsize(self.path)
            e   = time.time() - self._t0
            if cur > 0 and e > 0:
                log(f'  ↳ {self.label} | done | {fmt(cur)} | avg {spd(cur/e)}')
        except OSError:
            pass

    def _run(self):
        last = time.time()
        while not self._stop.is_set():
            now = time.time()
            if now - last >= self.interval:
                try:
                    cur = os.path.getsize(self.path)
                    e   = now - self._t0
                    if cur > 0 and e > 0:
                        p = pct(cur, self.total)
                        e_str = eta_str(cur, self.total, e)
                        log(f'  ↳ {self.label} | {p} | {fmt(cur)} | {spd(cur/e)}{e_str}')
                except OSError:
                    pass
                last = now
            time.sleep(1)

# ══════════════════════════════════════════════════════════════
# STREAMING UPLOAD — 512MB RAM chunks, resumable Drive API
# No disk needed for upload. Handles any file size.
# ══════════════════════════════════════════════════════════════
class StreamUploader:
    def __init__(self, folder_id, fname, total_size):
        self.folder_id  = folder_id
        self.fname      = fname
        self.total_size = total_size
        self._uri       = None

    def _start(self):
        meta = json.dumps({'name': self.fname, 'parents': [self.folder_id]})
        r = req_lib.post(
            'https://www.googleapis.com/upload/drive/v3/files'
            '?uploadType=resumable&supportsAllDrives=true',
            headers={
                'Authorization':           f'Bearer {get_token()}',
                'Content-Type':            'application/json; charset=UTF-8',
                'X-Upload-Content-Type':   'application/octet-stream',
                'X-Upload-Content-Length': str(self.total_size or 0),
            },
            data=meta, timeout=30)
        r.raise_for_status()
        self._uri = r.headers['Location']

    def _put_chunk(self, data: bytes, start: int, is_last: bool):
        end   = start + len(data) - 1
        total = self.total_size if (self.total_size and is_last) else '*'
        for attempt in range(7):
            try:
                r = req_lib.put(
                    self._uri,
                    headers={
                        'Authorization': f'Bearer {get_token()}',
                        'Content-Range': f'bytes {start}-{end}/{total}',
                        'Content-Type':  'application/octet-stream',
                    },
                    data=data, timeout=900)
                if r.status_code in (200, 201, 308):
                    return
                raise RuntimeError(f'HTTP {r.status_code}: {r.text[:200]}')
            except Exception as e:
                if attempt == 6: raise
                wait = min(2 ** attempt, 60)
                log(f'  Upload retry {attempt+1}/7 in {wait}s — {e}')
                time.sleep(wait)

    def upload_file(self, path: str):
        """Upload from disk — used after aria2c/torrent downloads."""
        self.total_size = os.path.getsize(path)
        self._start()
        uploaded = 0; t0 = time.time(); last_log = 0
        log(f'  Uploading {fmt(self.total_size)} to GDrive...')
        with open(path, 'rb') as f:
            while True:
                data = f.read(UPLOAD_CHUNK)
                if not data: break
                is_last = (uploaded + len(data) >= self.total_size)
                self._put_chunk(data, uploaded, is_last)
                uploaded += len(data)
                now = time.time()
                if now - last_log >= LOG_INTERVAL:
                    e = now - t0
                    log(f'  ↳ GDrive  | {pct(uploaded, self.total_size)} | '
                        f'{fmt(uploaded)} | {spd(uploaded/e)}'
                        f'{eta_str(uploaded, self.total_size, e)}')
                    last_log = now
        e = time.time() - t0
        log(f'  ↳ GDrive  | done | {fmt(uploaded)} | avg {spd(uploaded/e)}')

    def upload_stream(self, gen):
        """Upload from generator — zero disk, for streaming methods."""
        self._start()
        buf = b''; uploaded = 0
        t0 = time.time(); last_log = 0
        for chunk in gen:
            if not chunk: continue
            buf += chunk
            while len(buf) >= UPLOAD_CHUNK:
                piece = buf[:UPLOAD_CHUNK]; buf = buf[UPLOAD_CHUNK:]
                self._put_chunk(piece, uploaded, is_last=False)
                uploaded += len(piece)
                now = time.time()
                if now - last_log >= LOG_INTERVAL:
                    e = now - t0
                    log(f'  ↳ GDrive  | {pct(uploaded, self.total_size)} | '
                        f'{fmt(uploaded)} | {spd(uploaded/e)}')
                    last_log = now
        if buf:
            if not self.total_size:
                self.total_size = uploaded + len(buf)
            self._put_chunk(buf, uploaded, is_last=True)
            uploaded += len(buf)
        e = time.time() - t0
        log(f'  ↳ GDrive  | done | {fmt(uploaded)} | avg {spd(uploaded/e)}')
        return uploaded

# ══════════════════════════════════════════════════════════════
# METHOD 1 — aria2c HTTP/HTTPS
# ══════════════════════════════════════════════════════════════
def try_aria2c(url, fname, size, uploader) -> bool:
    log('  [1/5] aria2c HTTP — 16 connections, 1MB splits')
    out = f'{TMP}/{fname}'
    cmd = [
        'aria2c', url,
        '--dir', TMP, '--out', fname,
        f'-x{ARIA2C_CONNS}', f'-s{ARIA2C_CONNS}',
        '-k1M', '--min-split-size=1M',
        '--max-tries=5', '--retry-wait=3',
        '--connect-timeout=20', '--timeout=120',
        '--continue=true', '--auto-file-renaming=false',
        '--file-allocation=none', '--allow-overwrite=true',
        '--console-log-level=error', '--summary-interval=0',
        f'--user-agent={UA}',
        '--header=Accept: */*',
        '--header=Accept-Encoding: identity',
        f'--header=Referer: {referer(url)}',
    ]
    mon  = ProgressMonitor(out, size, f'aria2c  {fname[:40]}').start()
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    proc.wait()
    mon.stop()
    stderr = proc.stderr.read().decode(errors='ignore').strip()
    if proc.returncode != 0 or not os.path.exists(out) or os.path.getsize(out) < 1024:
        if stderr: log(f'  aria2c error: {stderr[-400:]}')
        return False
    log(f'  aria2c done: {fmt(os.path.getsize(out))}')
    uploader.upload_file(out)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════
# METHOD 2 — aria2c MAGNET/TORRENT
# ══════════════════════════════════════════════════════════════
def try_magnet(url, fname, size, uploader) -> bool:
    log('  [2/5] aria2c Magnet — BitTorrent, finding peers...')
    cmd = [
        'aria2c', url,
        '--dir', TMP,
        '--seed-time=0',
        '--max-connection-per-server=1',
        '--bt-stop-timeout=120',
        '--bt-max-peers=100',
        '--enable-dht=true',
        '--enable-peer-exchange=true',
        '--follow-torrent=mem',
        '--auto-file-renaming=false',
        '--allow-overwrite=true',
        '--console-log-level=error',
        '--summary-interval=0',
        '--file-allocation=none',
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    # Wait for aria2c to resolve the magnet and start creating a file
    t0 = time.time(); mon = None
    while proc.poll() is None:
        candidates = [p for p in Path(TMP).iterdir()
                      if p.is_file() and not p.name.endswith('.aria2')
                      and p.stat().st_size > 0]
        if candidates:
            found = max(candidates, key=lambda p: p.stat().st_size)
            fname = found.name
            uploader.fname = fname
            mon = ProgressMonitor(str(found), size, f'torrent {fname[:40]}').start()
            log(f'  Resolved: {fname}')
            break
        elapsed = time.time() - t0
        if elapsed > 30 and int(elapsed) % 30 == 0:
            log(f'  Waiting for peers... ({int(elapsed)}s)')
        time.sleep(2)

    proc.wait()
    if mon: mon.stop()

    stderr = proc.stderr.read().decode(errors='ignore').strip()
    candidates = sorted(
        [p for p in Path(TMP).iterdir()
         if p.is_file() and not p.name.endswith('.aria2')],
        key=lambda p: p.stat().st_size, reverse=True
    )
    if not candidates or candidates[0].stat().st_size < 1024:
        if stderr: log(f'  Magnet error: {stderr[-400:]}')
        return False

    out   = str(candidates[0])
    fname = candidates[0].name
    uploader.fname = fname
    log(f'  Torrent done: {fname} ({fmt(os.path.getsize(out))})')
    uploader.upload_file(out)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════
# METHOD 3 — yt-dlp + curl_cffi (Cloudflare bypass)
# ══════════════════════════════════════════════════════════════
def try_ytdlp(url, fname, size, uploader) -> bool:
    log('  [3/5] yt-dlp + curl_cffi (Cloudflare bypass)')
    stem     = Path(fname).stem
    out_tmpl = f'{TMP}/{stem}.%(ext)s'
    cmd = [
        'yt-dlp', '--no-playlist', '--no-warnings',
        '-o', out_tmpl,
        '--user-agent', UA,
        '--add-header', f'Referer: {referer(url)}',
        '--add-header', 'Accept: */*',
        '--add-header', 'Accept-Encoding: identity',
        '--retries', '5', '--fragment-retries', '5',
        '--concurrent-fragments', '16',
        '--no-check-certificate',
        '--extractor-args', 'generic:impersonate',
        '--newline', url
    ]
    t0 = time.time(); last_log = 0
    env  = {**os.environ, 'PYTHONUNBUFFERED': '1'}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, env=env)
    for line in proc.stdout:
        line = line.strip()
        if not line: continue
        m = re.search(
            r'\[download\]\s+([\d.]+)%\s+of\s+~?\s*([\d.]+)(GiB|MiB|KiB|B)'
            r'(?:.*?at\s+([\d.]+)(GiB|MiB|KiB|B)/s)?', line)
        if m:
            p    = float(m.group(1))
            mult = {'GiB': 1<<30, 'MiB': 1<<20, 'KiB': 1<<10, 'B': 1}[m.group(3)]
            cur  = int(p / 100 * float(m.group(2)) * mult)
            now  = time.time()
            if now - last_log >= LOG_INTERVAL:
                spd_s = ''
                if m.group(4):
                    sm    = {'GiB': 1<<30, 'MiB': 1<<20, 'KiB': 1<<10, 'B': 1}[m.group(5)]
                    spd_s = f' | {spd(float(m.group(4)) * sm)}'
                log(f'  ↳ yt-dlp  | {p:.1f}% | {fmt(cur)}{spd_s}')
                last_log = now
        elif '[download]' not in line:
            log(f'    {line}')
    proc.wait()

    candidates = sorted(Path(TMP).glob(f'{stem}.*'),
                        key=lambda p: p.stat().st_size, reverse=True)
    if not candidates or candidates[0].stat().st_size < 1024:
        log(f'  yt-dlp failed (code {proc.returncode})')
        return False
    out = str(candidates[0])
    log(f'  yt-dlp done: {fmt(os.path.getsize(out))}')
    uploader.upload_file(out)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════
# METHOD 4 — curl_cffi (Chrome TLS fingerprint)
# ══════════════════════════════════════════════════════════════
def try_curl_cffi(url, fname, size, uploader) -> bool:
    log('  [4/5] curl_cffi (Chrome TLS fingerprint)')
    try:
        from curl_cffi import requests as cffi_req
    except ImportError:
        log('  curl_cffi not installed, skipping')
        return False

    out  = f'{TMP}/{fname}'
    part = out + '.part'
    t0   = time.time(); done = 0; last_log = 0
    try:
        r = cffi_req.get(url, stream=True, timeout=120,
                         impersonate='chrome120', headers=HEADERS)
        r.raise_for_status()
        with open(part, 'wb') as f:
            for chunk in r.iter_content(chunk_size=DL_CHUNK):
                if not chunk: continue
                f.write(chunk); done += len(chunk)
                now = time.time()
                if now - last_log >= LOG_INTERVAL:
                    e = now - t0
                    log(f'  ↳ cffi    | {pct(done, size)} | {fmt(done)} | '
                        f'{spd(done/e)}{eta_str(done, size, e)}')
                    last_log = now
        os.rename(part, out)
    except Exception as e:
        log(f'  curl_cffi failed: {e}')
        try: os.remove(part)
        except: pass
        return False

    if not os.path.exists(out) or os.path.getsize(out) < 1024:
        log('  curl_cffi: empty file')
        return False
    log(f'  curl_cffi done: {fmt(os.path.getsize(out))}')
    uploader.upload_file(out)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════
# METHOD 5 — requests stream (plain fallback)
# ══════════════════════════════════════════════════════════════
def try_requests(url, fname, size, uploader) -> bool:
    log('  [5/5] requests stream (plain HTTP fallback)')
    t0 = time.time(); last_log = [0]

    def gen():
        done = 0
        with SESSION.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=DL_CHUNK):
                if not chunk: continue
                done += len(chunk)
                now = time.time()
                if now - last_log[0] >= LOG_INTERVAL:
                    e = now - t0
                    log(f'  ↳ stream  | {pct(done, size)} | {fmt(done)} | '
                        f'{spd(done/e)}{eta_str(done, size, e)}')
                    last_log[0] = now
                yield chunk

    try:
        uploader.upload_stream(gen())
        return True
    except Exception as e:
        log(f'  requests failed: {e}')
        return False

# ══════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════
def process(url: str, drive, folder_id: str):
    url = url.strip()
    if not url or url.startswith('#'):
        return
    hr()
    log(f'URL: {url[:100]}')

    try:
        magnet = is_magnet(url)

        if magnet:
            fname = resolve_magnet(url)
            size  = 0
            final = url
        else:
            final, fname, size = resolve_url(url)
            if file_exists(drive, folder_id, fname, size):
                log('  ✓ Already on GDrive — skipping')
                return

        uploader = StreamUploader(folder_id, fname, size)
        t0       = time.time()
        methods  = [try_magnet] if magnet else [try_aria2c, try_ytdlp, try_curl_cffi, try_requests]

        for fn in methods:
            stem = Path(fname).stem
            for p in Path(TMP).glob(f'{stem}*'):
                try: p.unlink()
                except: pass
            try:
                if fn(final, fname, size, uploader):
                    log(f'  ✓ Done in {(time.time()-t0)/60:.1f} min')
                    return
            except Exception as e:
                import traceback
                log(f'  ✗ {fn.__name__}: {e}')
                traceback.print_exc()

        log(f'  ✗ FAILED — all methods exhausted for: {fname}')

    except Exception as e:
        import traceback
        traceback.print_exc()
        log(f'  ✗ Fatal: {e}')

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
def main():
    raw = os.environ.get('DOWNLOAD_URLS', '').strip()
    if not raw:
        log('ERROR: No URLs provided. Set DOWNLOAD_URLS.')
        sys.exit(1)

    urls = [u.strip() for u in re.split(r'[,\n]+', raw)
            if u.strip() and not u.strip().startswith('#')]
    if not urls:
        log('ERROR: No valid URLs found.')
        sys.exit(1)

    log('=' * 65)
    log(f'  GDrive Downloader — {len(urls)} file(s)')
    log(f'  Folder  : {GDRIVE_FOLDER_ID}')
    log(f'  Methods : aria2c | torrent | yt-dlp | cffi | requests')
    log(f'  Upload  : 512MB chunks, resumable API')
    log(f'  Logs    : live, every {LOG_INTERVAL}s')
    log('=' * 65)

    for key in ('GDRIVE_CLIENT_ID', 'GDRIVE_CLIENT_SECRET', 'GDRIVE_REFRESH_TOKEN'):
        if not os.environ.get(key):
            log(f'ERROR: Missing secret "{key}"')
            sys.exit(1)

    log('Connecting to GDrive...')
    drive = get_drive()
    log('Connected ✓\n')

    t0 = time.time()
    for i, url in enumerate(urls, 1):
        log(f'\n[{i}/{len(urls)}]')
        process(url, drive, GDRIVE_FOLDER_ID)

    hr()
    log(f'All done in {(time.time()-t0)/60:.1f} min')

if __name__ == '__main__':
    main()
