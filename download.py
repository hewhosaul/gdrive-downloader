#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║           GDrive Downloader — GitHub Actions                 ║
║                                                              ║
║  Download waterfall (for every URL):                         ║
║    1. yt-dlp extract URL → aria2c 16 connections  [FAST]    ║
║    2. aria2c direct HTTP                          [FAST]    ║
║    3. aria2c Magnet/Torrent (for magnet: links)   [P2P]     ║
║    4. yt-dlp full download (single thread)        [COMPAT]  ║
║    5. curl_cffi (Chrome TLS fingerprint)          [CF]      ║
║    6. requests stream (plain fallback)            [LAST]    ║
║                                                              ║
║  Upload: rclone → Drive (parallel chunks, 150-200 MB/s)     ║
╚══════════════════════════════════════════════════════════════╝
"""

import os, sys, re, time, json, subprocess, tempfile, threading
from pathlib import Path
from urllib.parse import urlparse, unquote

# ── Force unbuffered output — critical for GitHub Actions live logs ──
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
UPLOAD_CHUNK     = 512 * 1024 * 1024   # 512MB upload chunks
DL_CHUNK         = 16  * 1024 * 1024   # 16MB read buffer
ARIA2C_CONNS     = 16                  # parallel connections
LOG_INTERVAL     = 8                   # seconds between progress lines
TMP              = tempfile.mkdtemp(prefix='dl_')
COOKIES_FILE     = f'{TMP}/cookies.txt'

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
# LOGGING — flush=True on every print for live GitHub Actions logs
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
    rem  = (total - done) / (done / elapsed)
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
# RCLONE SETUP — configure rclone on the fly from env vars
# No rclone.conf needed in the repo — all credentials come from
# GitHub Secrets via environment variables
# ══════════════════════════════════════════════════════════════
RCLONE_REMOTE = 'gdrive'
RCLONE_CONFIG  = f'{TMP}/rclone.conf'

def setup_rclone() -> bool:
    """Write rclone.conf from env vars. Returns True if successful."""
    client_id     = os.environ.get('GDRIVE_CLIENT_ID', '')
    client_secret = os.environ.get('GDRIVE_CLIENT_SECRET', '')
    refresh_token = os.environ.get('GDRIVE_REFRESH_TOKEN', '')
    if not all([client_id, client_secret, refresh_token]):
        log('  rclone: missing OAuth credentials in env')
        return False

    # Write minimal rclone config for Google Drive OAuth
    config = f"""[{RCLONE_REMOTE}]
type = drive
client_id = {client_id}
client_secret = {client_secret}
token = {{"access_token":"","token_type":"Bearer","refresh_token":"{refresh_token}","expiry":"2000-01-01T00:00:00Z"}}
scope = drive
root_folder_id = {GDRIVE_FOLDER_ID}
"""
    with open(RCLONE_CONFIG, 'w') as f:
        f.write(config)
    os.chmod(RCLONE_CONFIG, 0o600)
    log('  rclone config written ✓')
    return True

def rclone_upload(path: str, fname: str) -> bool:
    """
    Upload file to GDrive using rclone.
    Uses parallel chunk uploads for higher sustained speed than raw API.
    Falls back gracefully if rclone fails.
    """
    size = os.path.getsize(path)
    log(f'  Uploading {fmt(size)} via rclone...')

    cmd = [
        'rclone', 'copyto',
        path,
        f'{RCLONE_REMOTE}:{fname}',  # copyto preserves exact filename
        '--config', RCLONE_CONFIG,
        '--drive-chunk-size', '256M',          # 256MB chunks per stream
        '--drive-upload-cutoff', '256M',        # use resumable for anything >256MB
        '--transfers', '4',                     # 4 parallel chunk streams
        '--drive-parallel-upload-cutoff', '256M', # parallel chunks within single file
        '--checkers', '1',
        '--retries', '5',
        '--retries-sleep', '5s',
        '--low-level-retries', '10',
        '--stats', f'{LOG_INTERVAL}s',          # progress every N seconds
        '--stats-one-line',
        '--stats-log-level', 'NOTICE',
        '--use-mmap',                           # memory-mapped I/O for speed
        '-v',
    ]

    t0 = time.time()
    env = {
        **os.environ,
        'PYTHONUNBUFFERED': '1',
        'RCLONE_CONFIG':    RCLONE_CONFIG,
    }
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env
    )

    # Stream rclone output live
    last_stats = 0
    for line in proc.stdout:
        line = line.strip()
        if not line: continue
        # rclone stats lines look like:
        # Transferred: 12.345 GiB / 96.52 GiB, 13%, 145.2 MiB/s, ETA 10m5s
        if 'Transferred:' in line or 'ETA' in line or 'ERROR' in line:
            log(f'  ↳ rclone  | {line}')
        elif 'error' in line.lower() or 'failed' in line.lower():
            log(f'  rclone: {line}')

    proc.wait()
    e = time.time() - t0

    if proc.returncode != 0:
        log(f'  rclone failed (code {proc.returncode})')
        return False

    log(f'  ↳ rclone  | done | {fmt(size)} | avg {spd(size/e) if e else "?"}')
    return True

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

def file_size_ok(path: str, min_mb: float = 1.0) -> bool:
    try:
        return os.path.exists(path) and os.path.getsize(path) >= min_mb * 1024 * 1024
    except OSError:
        return False

# ══════════════════════════════════════════════════════════════
# URL RESOLVER — HEAD/GET to follow redirects, get filename+size
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
    m     = re.search(r'[?&]dn=([^&]+)', url)
    fname = sanitize(unquote(m.group(1).replace('+', ' '))) if m else f'torrent_{int(time.time())}'
    log(f'  Magnet : {fname}')
    return fname

# ══════════════════════════════════════════════════════════════
# YT-DLP URL EXTRACTOR
# Runs yt-dlp in extract-only mode to get:
#   - Real CDN download URL
#   - Filename
#   - File size
#   - Cookies (saved to file for aria2c)
# Works for: gofile, Cloudflare sites, streaming sites, DDL hosts
# ══════════════════════════════════════════════════════════════
def ytdlp_extract(url: str) -> dict | None:
    """
    Returns dict with keys: url, filename, filesize, headers, cookies_file
    Returns None if yt-dlp can't extract a direct URL.
    """
    log('  yt-dlp extracting real CDN URL...')

    # Get JSON metadata — filename, url, filesize, http headers
    cmd = [
        'yt-dlp',
        '--no-playlist', '--no-warnings',
        '--dump-json',                     # output metadata as JSON
        '--no-download',                   # don't actually download
        '--user-agent', UA,
        '--no-check-certificate',
        '--cookies', COOKIES_FILE,         # save session cookies
        '--extractor-args', 'generic:impersonate',
        url
    ]
    try:
        env = {**os.environ, 'PYTHONUNBUFFERED': '1'}
        r   = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=90, env=env)
        if r.returncode != 0 or not r.stdout.strip():
            log(f'  yt-dlp extract failed: {r.stderr[-300:].strip()}')
            return None

        # yt-dlp may output multiple JSON objects (playlist) — take last
        lines = [l for l in r.stdout.strip().splitlines() if l.startswith('{')]
        if not lines:
            return None

        info = json.loads(lines[-1])

        # Get the best format URL
        direct_url = None
        filename   = None
        filesize   = 0
        http_hdrs  = {}

        # Try formats list first (for sites with multiple qualities)
        formats = info.get('formats', [])
        if formats:
            # Pick best quality (last format is usually best)
            best = formats[-1]
            direct_url = best.get('url', '')
            filesize   = best.get('filesize') or best.get('filesize_approx') or 0
            http_hdrs  = best.get('http_headers', {})
        
        # Fall back to top-level url
        if not direct_url:
            direct_url = info.get('url', '')
            filesize   = info.get('filesize') or info.get('filesize_approx') or 0
            http_hdrs  = info.get('http_headers', {})

        if not direct_url or not direct_url.startswith('http'):
            log('  yt-dlp: no direct URL in metadata')
            return None

        # Get filename
        filename = (
            info.get('filename') or
            info.get('_filename') or
            info.get('title', '')
        )
        ext = info.get('ext', 'mkv')
        if filename and not Path(filename).suffix:
            filename = f'{filename}.{ext}'
        if not filename:
            filename = f'{info.get("id", "file")}.{ext}'
        filename = sanitize(Path(filename).name)

        log(f'  Extracted: {filename}')
        log(f'  CDN URL  : {direct_url[:80]}')
        log(f'  Size     : {fmt(filesize) if filesize else "unknown"}')

        return {
            'url':          direct_url,
            'filename':     filename,
            'filesize':     filesize,
            'headers':      http_hdrs,
            'cookies_file': COOKIES_FILE if os.path.exists(COOKIES_FILE) else None,
        }

    except json.JSONDecodeError as e:
        log(f'  yt-dlp JSON parse error: {e}')
        return None
    except subprocess.TimeoutExpired:
        log('  yt-dlp extract timed out (90s)')
        return None
    except Exception as e:
        log(f'  yt-dlp extract error: {e}')
        return None

# ══════════════════════════════════════════════════════════════
# PROGRESS MONITOR — background thread, logs every N seconds
# Separate thread so it never blocks the download process.
# This is how we get truly live logs from aria2c in GitHub Actions.
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
                        p     = pct(cur, self.total)
                        e_str = eta_str(cur, self.total, e)
                        log(f'  ↳ {self.label} | {p} | {fmt(cur)} | {spd(cur/e)}{e_str}')
                except OSError:
                    pass
                last = now
            time.sleep(1)

# ══════════════════════════════════════════════════════════════
# ARIA2C RUNNER — shared by multiple methods
# ══════════════════════════════════════════════════════════════
def run_aria2c(url: str, out: str, fname: str, size: int,
               extra_headers: list = None,
               cookies_file: str = None,
               label: str = None) -> bool:
    """
    Run aria2c with 16 connections. Returns True if file downloaded OK.
    extra_headers: list of 'Key: Value' strings
    cookies_file: path to Netscape cookies.txt
    """
    label = label or f'aria2c  {fname[:40]}'
    cmd   = [
        'aria2c', url,
        '--dir', TMP, '--out', fname,
        f'-x{ARIA2C_CONNS}', f'-s{ARIA2C_CONNS}',
        '-k1M', '--min-split-size=1M',
        '--max-tries=5', '--retry-wait=3',
        '--connect-timeout=20', '--timeout=180',
        '--continue=true', '--auto-file-renaming=false',
        '--file-allocation=none', '--allow-overwrite=true',
        '--console-log-level=error', '--summary-interval=0',
        f'--user-agent={UA}',
        '--header=Accept: */*',
        '--header=Accept-Encoding: identity',
        f'--header=Referer: {referer(url)}',
    ]
    if extra_headers:
        for h in extra_headers:
            cmd += [f'--header={h}']
    if cookies_file and os.path.exists(cookies_file):
        cmd += ['--load-cookies', cookies_file]

    mon  = ProgressMonitor(out, size, label).start()
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    proc.wait()
    mon.stop()

    stderr = proc.stderr.read().decode(errors='ignore').strip()
    if not file_size_ok(out):
        if stderr:
            log(f'  aria2c error: {stderr[-400:]}')
        return False
    return True

# ══════════════════════════════════════════════════════════════
# STREAMING UPLOAD — 512MB RAM chunks, resumable Drive API
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
# UNIFIED UPLOAD — rclone first (fast), StreamUploader fallback
# ══════════════════════════════════════════════════════════════
_rclone_ready = None  # cache rclone availability check

def upload_to_drive(path: str, uploader: 'StreamUploader') -> None:
    """
    Try rclone upload first (150-200 MB/s).
    Fall back to StreamUploader (80 MB/s) if rclone fails.
    """
    global _rclone_ready

    # Check rclone availability once
    if _rclone_ready is None:
        result = subprocess.run(['rclone', 'version'],
                                capture_output=True, timeout=10)
        _rclone_ready = result.returncode == 0
        if _rclone_ready:
            _rclone_ready = setup_rclone()
        log(f'  rclone available: {_rclone_ready}')

    if _rclone_ready:
        if rclone_upload(path, uploader.fname):
            return
        log('  rclone failed — falling back to direct API upload')

    # Fallback: original StreamUploader
    uploader.upload_file(path)

# ══════════════════════════════════════════════════════════════
# METHOD 1 — yt-dlp extract URL → aria2c 16 connections
# THE FAST PATH for everything: gofile, Cloudflare, DDL hosts
# yt-dlp resolves the real CDN URL + cookies in ~5 seconds
# aria2c then downloads at full 16-connection speed
# ══════════════════════════════════════════════════════════════
def try_ytdlp_aria2c(url, fname, size, uploader) -> bool:
    log('  [1/6] yt-dlp → aria2c (extract URL + 16 connections)')

    extracted = ytdlp_extract(url)
    if not extracted:
        log('  yt-dlp could not extract direct URL')
        return False

    real_url   = extracted['url']
    real_fname = extracted['filename'] or fname
    real_size  = extracted['filesize'] or size
    cookies    = extracted['cookies_file']

    # Build extra headers from yt-dlp metadata
    extra_headers = []
    for k, v in extracted.get('headers', {}).items():
        if k.lower() not in ('user-agent', 'accept-encoding'):
            extra_headers.append(f'{k}: {v}')

    # Update uploader with real filename if different
    if real_fname and real_fname != fname:
        log(f'  Using extracted filename: {real_fname}')
        uploader.fname = real_fname

    out = f'{TMP}/{real_fname}'

    ok = run_aria2c(
        real_url, out, real_fname, real_size,
        extra_headers=extra_headers,
        cookies_file=cookies,
        label=f'fast    {real_fname[:40]}'
    )

    if not ok:
        log('  aria2c failed on extracted URL')
        return False

    actual_size = os.path.getsize(out)
    log(f'  Download done: {fmt(actual_size)}')
    uploader.total_size = actual_size
    upload_to_drive(out, uploader)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════
# METHOD 2 — aria2c direct HTTP
# For plain servers where yt-dlp extraction isn't needed
# ══════════════════════════════════════════════════════════════
def try_aria2c(url, fname, size, uploader) -> bool:
    log('  [2/6] aria2c direct HTTP — 16 connections')
    out = f'{TMP}/{fname}'
    ok  = run_aria2c(url, out, fname, size,
                     label=f'aria2c  {fname[:40]}')
    if not ok:
        return False
    log(f'  aria2c done: {fmt(os.path.getsize(out))}')
    upload_to_drive(out, uploader)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════
# METHOD 3 — aria2c Magnet/Torrent
# BitTorrent protocol for magnet: links
# ══════════════════════════════════════════════════════════════
def try_magnet(url, fname, size, uploader) -> bool:
    log('  [3/6] aria2c Magnet — BitTorrent, finding peers...')
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

    # Poll until torrent resolves and starts creating a file
    t0 = time.time(); mon = None; last_wait = 0
    while proc.poll() is None:
        candidates = [p for p in Path(TMP).iterdir()
                      if p.is_file() and not p.name.endswith('.aria2')
                      and p.stat().st_size > 0]
        if candidates:
            found = max(candidates, key=lambda p: p.stat().st_size)
            uploader.fname = found.name
            mon = ProgressMonitor(str(found), size,
                                  f'torrent {found.name[:40]}').start()
            log(f'  Resolved: {found.name}')
            break
        now = time.time()
        if now - last_wait >= 30:
            log(f'  Waiting for peers... ({int(now-t0)}s)')
            last_wait = now
        time.sleep(2)

    proc.wait()
    if mon: mon.stop()

    stderr = proc.stderr.read().decode(errors='ignore').strip()
    candidates = sorted(
        [p for p in Path(TMP).iterdir()
         if p.is_file() and not p.name.endswith('.aria2')],
        key=lambda p: p.stat().st_size, reverse=True
    )
    if not candidates or candidates[0].stat().st_size < 1024 * 1024:
        if stderr: log(f'  Magnet error: {stderr[-400:]}')
        return False

    out   = str(candidates[0])
    fname = candidates[0].name
    uploader.fname = fname
    log(f'  Torrent done: {fname} ({fmt(os.path.getsize(out))})')
    upload_to_drive(out, uploader)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════
# METHOD 4 — yt-dlp full download (single thread)
# Fallback when URL extraction works but aria2c fails
# ══════════════════════════════════════════════════════════════
def try_ytdlp(url, fname, size, uploader) -> bool:
    log('  [4/6] yt-dlp full download (single thread)')
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
        '--cookies', COOKIES_FILE,
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
    if not candidates or candidates[0].stat().st_size < 1024 * 1024:
        log(f'  yt-dlp failed (code {proc.returncode})')
        return False
    out = str(candidates[0])
    log(f'  yt-dlp done: {fmt(os.path.getsize(out))}')
    uploader.fname = candidates[0].name
    upload_to_drive(out, uploader)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════
# METHOD 5 — curl_cffi (Chrome TLS fingerprint)
# For Cloudflare-protected sites that block everything else
# ══════════════════════════════════════════════════════════════
def try_curl_cffi(url, fname, size, uploader) -> bool:
    log('  [5/6] curl_cffi (Chrome TLS fingerprint)')
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

    if not file_size_ok(out):
        log('  curl_cffi: file too small')
        return False
    log(f'  curl_cffi done: {fmt(os.path.getsize(out))}')
    upload_to_drive(out, uploader)
    try: os.remove(out)
    except: pass
    return True

# ══════════════════════════════════════════════════════════════
# METHOD 6 — requests stream (last resort)
# ══════════════════════════════════════════════════════════════
def try_requests(url, fname, size, uploader) -> bool:
    log('  [6/6] requests stream (plain HTTP fallback)')
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

        if magnet:
            methods = [try_magnet]
        else:
            # yt-dlp→aria2c is method 1 for ALL urls:
            # handles gofile, cloudflare, DDL, streaming sites
            # aria2c direct is method 2 for plain HTTP servers
            methods = [
                try_ytdlp_aria2c,   # fast path: extract URL + 16 connections
                try_aria2c,         # direct aria2c (plain servers)
                try_ytdlp,          # yt-dlp single thread fallback
                try_curl_cffi,      # chrome TLS fingerprint
                try_requests,       # plain HTTP last resort
            ]

        for fn in methods:
            stem = Path(uploader.fname).stem
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
    log(f'  Method 1: yt-dlp extract URL → aria2c 16 connections')
    log(f'  Method 2: aria2c direct HTTP')
    log(f'  Method 3: aria2c Magnet/Torrent')
    log(f'  Method 4: yt-dlp full download')
    log(f'  Method 5: curl_cffi Chrome TLS')
    log(f'  Method 6: requests stream')
    log(f'  Upload  : 512MB chunks, resumable API')
    log(f'  Logs    : live every {LOG_INTERVAL}s')
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
