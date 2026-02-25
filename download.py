#!/usr/bin/env python3
"""
GDrive Downloader — GitHub Actions
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Download waterfall:
  1. aria2c     — 16 connections, 1MB splits (no tail slowdown)
  2. yt-dlp     — curl_cffi impersonation, bypasses Cloudflare
  3. curl_cffi  — browser TLS fingerprint
  4. requests   — plain fallback

Upload:
  Primary  : rclone → Drive (config written from env vars at runtime)
  Fallback : StreamUploader → OAuth resumable API (always works)
"""

import os, sys, re, time, json, subprocess, tempfile
from pathlib import Path
from urllib.parse import urlparse, unquote

import requests as req_lib
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build

# ══════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════
GDRIVE_FOLDER_ID = '1TRND8VlWi0U7wdHk3HLJ7hvzOw90PDE3'

UPLOAD_CHUNK  = 256 * 1024 * 1024   # 256MB per PUT — sweet spot for Drive API
DL_CHUNK      = 16  * 1024 * 1024   # 16MB read buffer for disk→upload
ARIA2C_CONNS  = 16
TMP           = tempfile.mkdtemp(prefix='dl_')

RCLONE_REMOTE = 'gdrive'
RCLONE_CONFIG  = f'{TMP}/rclone.conf'

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
      'AppleWebKit/537.36 (KHTML, like Gecko) '
      'Chrome/122.0.0.0 Safari/537.36')

COMMON_HEADERS = {
    'User-Agent':      UA,
    'Accept':          '*/*',
    'Accept-Encoding': 'identity',
    'Accept-Language': 'en-US,en;q=0.9',
}

# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════
def log(msg): print(msg, flush=True)
def hr():     log('─' * 65)
def fmt(b):   return f'{b/1e9:.2f} GB' if b > 1e9 else f'{b/1e6:.1f} MB'
def spd(b):   return f'{b/1e6:.1f} MB/s'

def sanitize(name: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    return name[:200].strip() or f'file_{int(time.time())}'

def clean_url(u: str) -> str:
    """Strip backslash escapes zsh adds to ? & = in URLs."""
    return u.replace('\\?', '?').replace('\\&', '&').replace('\\=', '=')

def referer(url):
    p = urlparse(url)
    return f'{p.scheme}://{p.netloc}/'

def make_session():
    s = req_lib.Session()
    s.headers.update(COMMON_HEADERS)
    retry = req_lib.adapters.Retry(3, backoff_factor=1)
    s.mount('http://',  req_lib.adapters.HTTPAdapter(max_retries=retry))
    s.mount('https://', req_lib.adapters.HTTPAdapter(max_retries=retry))
    return s

SESSION = make_session()

# ══════════════════════════════════════════════════════════════════
# OAUTH
# ══════════════════════════════════════════════════════════════════
_creds = None

def get_creds() -> Credentials:
    global _creds
    if _creds:
        if _creds.expired:
            _creds.refresh(GoogleAuthRequest())
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

# ══════════════════════════════════════════════════════════════════
# DRIVE HELPERS
# ══════════════════════════════════════════════════════════════════
def file_exists(drive, folder_id, fname, expected_size) -> bool:
    q = f"name='{fname}' and '{folder_id}' in parents and trashed=false"
    res = drive.files().list(
        q=q, fields='files(id,size)',
        supportsAllDrives=True, includeItemsFromAllDrives=True
    ).execute()
    if not res['files']:
        return False
    ds = int(res['files'][0].get('size', 0))
    return bool(expected_size and ds >= expected_size * 0.99)

# ══════════════════════════════════════════════════════════════════
# URL RESOLVER
# ══════════════════════════════════════════════════════════════════
def resolve_url(url: str):
    log('  Resolving...')
    r = None
    for method in ('HEAD', 'GET'):
        try:
            if method == 'HEAD':
                r = SESSION.head(url, allow_redirects=True, timeout=20)
            else:
                r = SESSION.get(url, stream=True, allow_redirects=True, timeout=20)
                r.close()
            if r.status_code < 400:
                break
        except Exception as e:
            if method == 'GET':
                log(f'  Resolve failed: {e} — using original URL')
                path  = unquote(urlparse(url).path)
                fname = sanitize(Path(path).name or f'file_{int(time.time())}')
                return url, fname, 0

    final = r.url if r else url
    cd    = r.headers.get('Content-Disposition', '') if r else ''
    m     = re.findall(r"filename\*?=['\"]?(?:UTF-8'')?([^'\";\r\n]+)", cd, re.I)
    fname = sanitize(unquote(m[-1].strip())) if m else sanitize(
            Path(unquote(urlparse(final).path)).name or f'file_{int(time.time())}')
    size  = int(r.headers.get('Content-Length', 0)) if r else 0

    log(f'  File : {fname}')
    log(f'  Size : {fmt(size) if size else "unknown"}')
    log(f'  URL  : {final[:100]}')
    return final, fname, size

# ══════════════════════════════════════════════════════════════════
# RCLONE UPLOAD — primary upload path
# Config is written from env vars at runtime — no rclone.conf in repo
# ══════════════════════════════════════════════════════════════════
_rclone_ok = None

def setup_rclone() -> bool:
    """Write rclone.conf from env vars. Returns True on success."""
    client_id     = os.environ.get('GDRIVE_CLIENT_ID', '')
    client_secret = os.environ.get('GDRIVE_CLIENT_SECRET', '')
    refresh_token = os.environ.get('GDRIVE_REFRESH_TOKEN', '')
    if not all([client_id, client_secret, refresh_token]):
        return False
    config = (
        f'[{RCLONE_REMOTE}]\n'
        f'type = drive\n'
        f'client_id = {client_id}\n'
        f'client_secret = {client_secret}\n'
        f'token = {{"access_token":"","token_type":"Bearer",'
        f'"refresh_token":"{refresh_token}",'
        f'"expiry":"2000-01-01T00:00:00Z"}}\n'
        f'scope = drive\n'
        f'root_folder_id = {GDRIVE_FOLDER_ID}\n'
    )
    with open(RCLONE_CONFIG, 'w') as f:
        f.write(config)
    os.chmod(RCLONE_CONFIG, 0o600)
    return True

def rclone_available() -> bool:
    global _rclone_ok
    if _rclone_ok is not None:
        return _rclone_ok
    try:
        r = subprocess.run(['rclone', 'version'], capture_output=True, timeout=10)
        _rclone_ok = (r.returncode == 0) and setup_rclone()
    except Exception:
        _rclone_ok = False
    log(f'  rclone available: {_rclone_ok}')
    return _rclone_ok

def rclone_upload(path: str, fname: str) -> bool:
    """Upload file via rclone. Returns True on success."""
    size = os.path.getsize(path)
    log(f'  Uploading {fmt(size)} via rclone...')
    cmd = [
        'rclone', 'copyto',
        path,
        f'{RCLONE_REMOTE}:{fname}',
        '--config',              RCLONE_CONFIG,
        '--drive-chunk-size',    '512M',
        '--drive-upload-cutoff', '512M',
        '--retries',             '5',
        '--retries-sleep',       '5s',
        '--low-level-retries',   '10',
        '--stats',               '8s',
        '--stats-one-line',
        '--stats-log-level',     'NOTICE',
        '--use-mmap',
        '-v',
    ]
    t0   = time.time()
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1
    )
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        if any(x in line for x in ('Transferred:', 'ETA', 'ERROR', 'error',
                                    'failed', 'Fatal', 'unknown', 'flag')):
            log(f'  ↳ rclone | {line}')
    proc.wait()
    e = time.time() - t0
    if proc.returncode != 0:
        log(f'  rclone failed (exit {proc.returncode}) — falling back to API')
        return False
    log(f'  ↳ rclone | done | {fmt(size)} | avg {spd(size/e) if e else "?"}')
    return True

# ══════════════════════════════════════════════════════════════════
# STREAMING UPLOAD — 512MB RAM chunks → Drive API resumable
# Fallback when rclone is unavailable or fails
# ══════════════════════════════════════════════════════════════════
class StreamUploader:
    def __init__(self, folder_id, fname, total_size):
        self.folder_id  = folder_id
        self.fname      = fname
        self.total_size = total_size
        self._uri       = None

    def _start(self):
        token = get_token()
        meta  = json.dumps({'name': self.fname, 'parents': [self.folder_id]})
        r = req_lib.post(
            'https://www.googleapis.com/upload/drive/v3/files'
            '?uploadType=resumable&supportsAllDrives=true',
            headers={
                'Authorization':           f'Bearer {token}',
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
        for attempt in range(6):
            try:
                token = get_token()
                r = req_lib.put(
                    self._uri,
                    headers={
                        'Authorization': f'Bearer {token}',
                        'Content-Range': f'bytes {start}-{end}/{total}',
                        'Content-Type':  'application/octet-stream',
                    },
                    data=data, timeout=600)
                if r.status_code in (200, 201, 308):
                    return
                raise RuntimeError(f'HTTP {r.status_code}: {r.text[:300]}')
            except Exception as e:
                if attempt == 5:
                    raise
                wait = 2 ** attempt
                log(f'  Upload retry {attempt+1}/6 in {wait}s: {e}')
                time.sleep(wait)

    def run_file(self, path: str):
        """Upload a file directly — no intermediate buffer, reads in UPLOAD_CHUNK blocks."""
        self.total_size = os.path.getsize(path)
        self._start()
        uploaded = 0; t0 = time.time(); last_log = 0
        log(f'  Uploading {fmt(self.total_size)} to GDrive...')
        with open(path, 'rb') as f:
            while True:
                data = f.read(UPLOAD_CHUNK)
                if not data:
                    break
                is_last = (uploaded + len(data) >= self.total_size)
                self._put_chunk(data, uploaded, is_last)
                uploaded += len(data)
                now = time.time()
                if now - last_log >= 8:
                    e = now - t0
                    pct = f'{uploaded*100//self.total_size}%' if self.total_size else '?'
                    log(f'  ↳ GDrive | {pct} | {fmt(uploaded)} | {spd(uploaded/e)}')
                    last_log = now
        e = time.time() - t0
        log(f'  ↳ GDrive | done | {fmt(uploaded)} | avg {spd(uploaded/e)}')
        return uploaded

    def run(self, stream_iter, bar_desc='Upload'):
        """Legacy stream-based upload — kept for requests fallback method."""
        self._start()
        buf = b''; uploaded = 0; t0 = time.time(); last_log = 0
        log(f'  Uploading to GDrive (streaming)...')
        for chunk in stream_iter:
            if not chunk: continue
            buf += chunk
            while len(buf) >= UPLOAD_CHUNK:
                piece = buf[:UPLOAD_CHUNK]; buf = buf[UPLOAD_CHUNK:]
                self._put_chunk(piece, uploaded, is_last=False)
                uploaded += len(piece)
                now = time.time()
                if now - last_log >= 8:
                    e = now - t0
                    log(f'  ↳ GDrive | {fmt(uploaded)} | {spd(uploaded/e)}')
                    last_log = now
        if buf:
            if not self.total_size:
                self.total_size = uploaded + len(buf)
            self._put_chunk(buf, uploaded, is_last=True)
            uploaded += len(buf)
        e = time.time() - t0
        log(f'  ↳ GDrive | done | {fmt(uploaded)} | avg {spd(uploaded/e)}')
        return uploaded

# ══════════════════════════════════════════════════════════════════
# UPLOAD — direct Drive API, 256MB chunks, plain progress logging
# ══════════════════════════════════════════════════════════════════
def upload_file(path: str, uploader: StreamUploader):
    """Upload file to GDrive using resumable API with 256MB chunks."""
    uploader.run_file(path)

# ══════════════════════════════════════════════════════════════════
# PROGRESS BAR POLLER
# ══════════════════════════════════════════════════════════════════
def poll_bar(proc, out_path, size, desc):
    t0 = time.time(); prev = 0; last_log = 0
    while proc.poll() is None:
        try:   cur = os.path.getsize(out_path)
        except OSError: cur = 0
        now = time.time()
        if cur > prev and now - last_log >= 8:
            e = now - t0
            pct = f'{cur*100//size}%' if size else fmt(cur)
            log(f'  ↳ {desc} | {pct} | {fmt(cur)} | {spd(cur/e)}')
            last_log = now
            prev = cur
        time.sleep(1)
    try:
        cur = os.path.getsize(out_path)
        e = time.time() - t0
        if e and cur:
            log(f'  ↳ {desc} | done | {fmt(cur)} | avg {spd(cur/e)}')
    except OSError: pass

# ══════════════════════════════════════════════════════════════════
# METHOD 1 — aria2c (16 connections, 1MB splits)
# ══════════════════════════════════════════════════════════════════
def try_aria2c(url, fname, size, uploader) -> bool:
    log('  [1/4] aria2c — 16 connections, 1MB splits')
    out = f'{TMP}/{fname}'
    cmd = [
        'aria2c', url, '--dir', TMP, '--out', fname,
        f'-x{ARIA2C_CONNS}',
        f'-s{ARIA2C_CONNS}',
        '-k1M',
        '--min-split-size=1M',
        '--max-tries=5', '--retry-wait=3',
        '--connect-timeout=20', '--timeout=120',
        '--continue=true', '--auto-file-renaming=false',
        '--file-allocation=none', '--quiet=true',
        '--allow-overwrite=true',
        f'--user-agent={UA}',
        '--header=Accept: */*',
        '--header=Accept-Encoding: identity',
        '--header=Accept-Language: en-US,en;q=0.9',
        f'--header=Referer: {referer(url)}',
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    poll_bar(proc, out, size, f'aria2c  {fname[:35]}')
    proc.wait()
    stderr = proc.stderr.read().decode(errors='ignore').strip()
    if proc.returncode != 0 or not os.path.exists(out) or os.path.getsize(out) < 10000:
        log(f'  aria2c failed (code {proc.returncode}): {stderr[-300:]}')
        return False
    log(f'  aria2c done: {fmt(os.path.getsize(out))}')
    log('  Uploading to GDrive...')
    upload_file(out, uploader)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════════
# METHOD 2 — yt-dlp + curl_cffi (Cloudflare bypass)
# ══════════════════════════════════════════════════════════════════
def try_ytdlp(url, fname, size, uploader) -> bool:
    log('  [2/4] yt-dlp + curl_cffi (Cloudflare impersonation)')
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
        '--progress', '--newline',
        url
    ]
    t0   = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in proc.stdout:
        line = line.strip()
        if line and '[download]' in line:
            log(f'  {line}')
        elif line and '[download]' not in line:
            log(f'    {line}')
    proc.wait()
    candidates = sorted(Path(TMP).glob(f'{stem}.*'),
                        key=lambda p: p.stat().st_size, reverse=True)
    if not candidates or candidates[0].stat().st_size < 10000:
        log(f'  yt-dlp failed (code {proc.returncode})')
        return False
    out = str(candidates[0])
    log(f'  yt-dlp done: {fmt(os.path.getsize(out))}')
    log('  Uploading to GDrive...')
    uploader.fname = Path(out).name
    upload_file(out, uploader)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════════
# METHOD 3 — curl_cffi (browser TLS fingerprint)
# ══════════════════════════════════════════════════════════════════
def try_curl_cffi(url, fname, size, uploader) -> bool:
    log('  [3/4] curl_cffi (browser TLS fingerprint)')
    try:
        from curl_cffi import requests as cffi_req
    except ImportError:
        log('  curl_cffi not available, skipping')
        return False

    out  = f'{TMP}/{fname}'
    part = out + '.part'
    t0 = time.time(); done = 0; last_log = 0
    try:
        r = cffi_req.get(url, stream=True, timeout=120,
                         impersonate='chrome120',
                         headers=COMMON_HEADERS)
        r.raise_for_status()
        with open(part, 'wb') as f:
            for chunk in r.iter_content(chunk_size=DL_CHUNK):
                if chunk:
                    f.write(chunk); done += len(chunk)
                    now = time.time()
                    if now - last_log >= 8:
                        e = now - t0
                        pct = f'{done*100//size}%' if size else fmt(done)
                        log(f'  ↳ cffi | {pct} | {fmt(done)} | {spd(done/e)}')
                        last_log = now
        os.rename(part, out)
    except Exception as e:
        log(f'  curl_cffi failed: {e}')
        return False

    if not os.path.exists(out) or os.path.getsize(out) < 10000:
        log('  curl_cffi produced empty file')
        return False
    log(f'  curl_cffi done: {fmt(os.path.getsize(out))}')
    log('  Uploading to GDrive...')
    upload_file(out, uploader)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════════
# METHOD 4 — requests stream (last resort)
# ══════════════════════════════════════════════════════════════════
def try_requests(url, fname, size, uploader) -> bool:
    log('  [4/4] requests stream (plain fallback)')
    out  = f'{TMP}/{fname}'
    part = out + '.part'
    t0 = time.time(); done = 0; last_log = 0
    try:
        with SESSION.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            with open(part, 'wb') as f:
                for chunk in r.iter_content(chunk_size=DL_CHUNK):
                    if chunk:
                        f.write(chunk); done += len(chunk)
                        now = time.time()
                        if now - last_log >= 8:
                            e = now - t0
                            pct = f'{done*100//size}%' if size else fmt(done)
                            log(f'  ↳ stream | {pct} | {fmt(done)} | {spd(done/e)}')
                            last_log = now
        os.rename(part, out)
    except Exception as e:
        log(f'  requests failed: {e}')
        return False

    if not os.path.exists(out) or os.path.getsize(out) < 10000:
        log('  requests produced empty file')
        return False
    log(f'  requests done: {fmt(os.path.getsize(out))}')
    log('  Uploading to GDrive...')
    upload_file(out, uploader)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════
def process(url: str, drive, folder_id: str):
    url = clean_url(url.strip())
    if not url or url.startswith('#'):
        return
    hr()
    log(f'URL: {url[:90]}')
    try:
        final_url, fname, size = resolve_url(url)
        if file_exists(drive, folder_id, fname, size):
            log('  Already on GDrive — skipping')
            return
        uploader = StreamUploader(folder_id, fname, size)
        t0 = time.time()
        for fn in [try_aria2c, try_ytdlp, try_curl_cffi, try_requests]:
            for p in Path(TMP).glob(f'{Path(fname).stem}*'):
                try: p.unlink()
                except: pass
            try:
                if fn(final_url, fname, size, uploader):
                    log(f'  Done in {(time.time()-t0)/60:.1f} min')
                    return
            except Exception as e:
                log(f'  Error in {fn.__name__}: {e}')
        log(f'  FAILED — all methods exhausted for: {fname}')
    except Exception as e:
        import traceback; traceback.print_exc()
        log(f'  Fatal: {e}')

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
def main():
    raw = os.environ.get('DOWNLOAD_URLS', '').strip()
    if not raw:
        log('No URLs. Set DOWNLOAD_URLS env var.')
        sys.exit(1)
    urls = [clean_url(u.strip()) for u in re.split(r'[,\n]+', raw)
            if u.strip() and not u.strip().startswith('#')]
    if not urls:
        log('No valid URLs found.')
        sys.exit(1)

    log('=' * 65)
    log(f'  GDrive Downloader — {len(urls)} file(s)')
    log(f'  Folder  : {GDRIVE_FOLDER_ID}')
    log(f'  Method 1: aria2c 16 connections, 1MB splits')
    log(f'  Method 2: yt-dlp + curl_cffi (Cloudflare bypass)')
    log(f'  Method 3: curl_cffi browser TLS')
    log(f'  Method 4: requests stream')
    log(f'  Upload  : rclone (primary) → direct API (fallback)')
    log('=' * 65)

    for key in ('GDRIVE_CLIENT_ID', 'GDRIVE_CLIENT_SECRET', 'GDRIVE_REFRESH_TOKEN'):
        if not os.environ.get(key):
            log(f'ERROR: GitHub secret "{key}" is not set.')
            sys.exit(1)

    log('Connecting to Google Drive...')
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
