#!/usr/bin/env python3
"""
GDrive Downloader — GitHub Actions (SOCKS5 Proxy Optimized)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
SUBFOLDER_NAME   = os.environ.get('FOLDER_NAME', '').strip()

UPLOAD_CHUNK = 256 * 1024 * 1024   
DL_CHUNK     = 16  * 1024 * 1024   
ARIA2C_CONNS = 16
TMP          = tempfile.mkdtemp(prefix='dl_')
PROXY_URL    = "socks5h://127.0.0.1:40000"

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
      'AppleWebKit/537.36 (KHTML, like Gecko) '
      'Chrome/122.0.0.0 Safari/537.36')

COMMON_HEADERS = {
    'User-Agent':      UA,
    'Accept':          '*/*',
    'Accept-Encoding': 'identity',
    'Accept-Language': 'en-US,en;q=0.9',
}

def log(msg): print(msg, flush=True)
def hr():     log('─' * 65)
def fmt(b):   return f'{b/1e9:.2f} GB' if b > 1e9 else f'{b/1e6:.1f} MB'
def spd(b):   return f'{b/1e6:.1f} MB/s'

def sanitize(name: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    return name[:200].strip() or f'file_{int(time.time())}'

def clean_url(u: str) -> str:
    return u.replace('\\?', '?').replace('\\&', '&').replace('\\=', '=')

def referer(url: str) -> str:
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
# OAUTH & FOLDER LOGIC
# ══════════════════════════════════════════════════════════════════
_creds = None
def get_creds() -> Credentials:
    global _creds
    if _creds:
        if _creds.expired: _creds.refresh(GoogleAuthRequest())
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
    if c.expired: c.refresh(GoogleAuthRequest())
    return c.token

def get_drive():
    return build('drive', 'v3', credentials=get_creds(), cache_discovery=False)

def get_or_create_subfolder(drive, parent_id, folder_name):
    log(f"  Checking/Creating Subfolder: '{folder_name}'...")
    safe_name = folder_name.replace("'", "\\'")
    q = f"name='{safe_name}' and '{parent_id}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false"
    res = drive.files().list(q=q, fields='files(id,name)', supportsAllDrives=True, includeItemsFromAllDrives=True).execute()
    if res.get('files'):
        log(f"  Subfolder exists -> {res['files'][0]['id']}")
        return res['files'][0]['id']
    
    meta = {
        'name': folder_name,
        'parents': [parent_id],
        'mimeType': 'application/vnd.google-apps.folder'
    }
    folder = drive.files().create(body=meta, fields='id', supportsAllDrives=True).execute()
    log(f"  Created new subfolder -> {folder['id']}")
    return folder['id']

def file_exists(drive, folder_id, fname, expected_size) -> bool:
    safe_fname = fname.replace("'", "\\'")
    q = f"name='{safe_fname}' and '{folder_id}' in parents and trashed=false"
    res = drive.files().list(
        q=q, fields='files(id,size)',
        supportsAllDrives=True, includeItemsFromAllDrives=True
    ).execute()
    if not res['files']: return False
    ds = int(res['files'][0].get('size', 0))
    return bool(expected_size and ds >= expected_size * 0.99)

# ══════════════════════════════════════════════════════════════════
# RESOLVER
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
            if r.status_code < 400: break
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
# UPLOADER
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
            'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true',
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
                if r.status_code in (200, 201, 308): return
                raise RuntimeError(f'HTTP {r.status_code}: {r.text[:300]}')
            except Exception as e:
                if attempt == 5: raise
                wait = 2 ** attempt
                time.sleep(wait)

    def run_file(self, path: str):
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
                if now - last_log >= 8:
                    e = now - t0
                    pct = f'{uploaded*100//self.total_size}%'
                    log(f'  ↳ {pct} | {fmt(uploaded)} | {spd(uploaded/e)}')
                    last_log = now
        e = time.time() - t0
        log(f'  ↳ done | {fmt(uploaded)} | avg {spd(uploaded/e)}')
        return uploaded

def upload_file(path: str, uploader: StreamUploader):
    uploader.run_file(path)

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

# ══════════════════════════════════════════════════════════════════
# DOWNLOADERS
# ══════════════════════════════════════════════════════════════════
def try_aria2c(url, fname, size, uploader, use_proxy=False) -> bool:
    if use_proxy: return False
    log('  [~] aria2c — 16 connections')
    out = f'{TMP}/{fname}'
    cmd = [
        'aria2c', url, '--dir', TMP, '--out', fname,
        f'-x{ARIA2C_CONNS}', f'-s{ARIA2C_CONNS}',
        '-k1M', '--min-split-size=1M',
        '--max-tries=5', '--retry-wait=3',
        '--connect-timeout=20', '--timeout=120',
        '--continue=true', '--auto-file-renaming=false',
        '--file-allocation=none', '--quiet=true',
        '--allow-overwrite=true',
        f'--user-agent={UA}', '--header=Accept: */*',
        '--header=Accept-Encoding: identity', f'--header=Referer: {referer(url)}',
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    poll_bar(proc, out, size, 'aria2c')
    proc.wait()
    if proc.returncode != 0 or not os.path.exists(out) or os.path.getsize(out) < 10000: return False
    upload_file(out, uploader)
    try: os.remove(out)
    except: pass
    return True

def try_ytdlp(url, fname, size, uploader, use_proxy=False) -> bool:
    log(f'  [~] yt-dlp 16 threads{" (via WARP SOCKS5 Proxy)" if use_proxy else ""}')
    stem     = Path(fname).stem
    out_tmpl = f'{TMP}/{stem}.%(ext)s'
    cmd = [
        'yt-dlp', '--no-playlist', '--no-warnings', '-o', out_tmpl,
        '--user-agent', UA, '--add-header', f'Referer: {referer(url)}',
        '--retries', '5', '--fragment-retries', '5', '--concurrent-fragments', '16',
        '--no-check-certificate', '--extractor-args', 'generic:impersonate',
        '--progress', '--newline',
    ]
    if use_proxy: cmd.extend(['--proxy', PROXY_URL])
    cmd.append(url)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in proc.stdout: pass
    proc.wait()
    candidates = sorted(Path(TMP).glob(f'{stem}.*'), key=lambda p: p.stat().st_size, reverse=True)
    if not candidates or candidates[0].stat().st_size < 10000: return False
    out = str(candidates[0])
    uploader.fname = sanitize(Path(out).name)
    upload_file(out, uploader)
    try: os.remove(out)
    except: pass
    return True

def try_curl_cffi(url, fname, size, uploader, use_proxy=False) -> bool:
    log(f'  [~] curl_cffi TLS impersonate{" (via WARP SOCKS5 Proxy)" if use_proxy else ""}')
    try: from curl_cffi import requests as cffi_req
    except ImportError: return False

    out  = f'{TMP}/{fname}'
    part = out + '.part'
    t0 = time.time(); done = 0; last_log = 0
    px = {"http": PROXY_URL, "https": PROXY_URL} if use_proxy else None

    try:
        r = cffi_req.get(url, stream=True, timeout=120, impersonate='chrome120', headers=COMMON_HEADERS, proxies=px)
        r.raise_for_status()
        with open(part, 'wb') as f:
            for chunk in r.iter_content(chunk_size=DL_CHUNK):
                if chunk:
                    f.write(chunk); done += len(chunk)
                    now = time.time()
                    if now - last_log >= 8:
                        e = now - t0
                        log(f'  ↳ cffi | {done*100//size if size else fmt(done)}% | {fmt(done)} | {spd(done/e)}')
                        last_log = now
        os.rename(part, out)
    except Exception: return False
    if not os.path.exists(out) or os.path.getsize(out) < 10000: return False
    upload_file(out, uploader)
    try: os.remove(out)
    except: pass
    return True

def try_curl(url, fname, size, uploader, use_proxy=False) -> bool:
    log(f'  [~] curl binary fallback{" (via WARP SOCKS5 Proxy)" if use_proxy else ""}')
    out = f'{TMP}/{fname}'
    cmd = [
        'curl', '-L', '-o', out, '-A', UA, '-H', f'Referer: {referer(url)}',
        '--retry', '5', '--retry-connrefused', '--connect-timeout', '20'
    ]
    if use_proxy: cmd.extend(['-x', PROXY_URL])
    cmd.append(url)

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    poll_bar(proc, out, size, 'curl')
    proc.wait()
    if proc.returncode != 0 or not os.path.exists(out) or os.path.getsize(out) < 10000: return False
    upload_file(out, uploader)
    try: os.remove(out)
    except: pass
    return True

def try_requests(url, fname, size, uploader, use_proxy=False) -> bool:
    log(f'  [~] requests module{" (via WARP SOCKS5 Proxy)" if use_proxy else ""}')
    out  = f'{TMP}/{fname}'
    part = out + '.part'
    t0 = time.time(); done = 0; last_log = 0
    px = {"http": PROXY_URL, "https": PROXY_URL} if use_proxy else None

    try:
        with SESSION.get(url, stream=True, timeout=120, proxies=px) as r:
            r.raise_for_status()
            with open(part, 'wb') as f:
                for chunk in r.iter_content(chunk_size=DL_CHUNK):
                    if chunk:
                        f.write(chunk); done += len(chunk)
                        now = time.time()
                        if now - last_log >= 8:
                            e = now - t0
                            log(f'  ↳ stream | {done*100//size if size else fmt(done)}% | {fmt(done)} | {spd(done/e)}')
                            last_log = now
        os.rename(part, out)
    except Exception: return False
    if not os.path.exists(out) or os.path.getsize(out) < 10000: return False
    upload_file(out, uploader)
    try: os.remove(out)
    except: pass
    return True

# ════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ════════════════════════════════════════════════════════════════
def process(url: str, drive, folder_id: str):
    url = clean_url(url.strip())
    if not url or url.startswith('#'): return
    hr()
    log(f'URL: {url[:90]}')
    try:
        final_url, fname, size = resolve_url(url)
        if file_exists(drive, folder_id, fname, size):
            log('  Already on GDrive — skipping')
            return
        uploader = StreamUploader(folder_id, fname, size)
        t0       = time.time()
        
        direct_methods = [try_aria2c, try_ytdlp, try_curl_cffi, try_curl, try_requests]
        proxy_methods  = [try_ytdlp, try_curl, try_curl_cffi, try_requests]

        def _clean():
            for p in Path(TMP).glob(f'{Path(fname).stem}*'):
                try: p.unlink()
                except: pass

        log('  Round 1: Testing direct connection...')
        for fn in direct_methods:
            _clean()
            if fn(final_url, fname, size, uploader, use_proxy=False):
                log(f'  Done in {(time.time()-t0)/60:.1f} min')
                return

        log('\n  ⚠️ All direct methods failed. Azure IP likely blocked (403).')
        log('  Round 2: Retrying download via local WARP SOCKS5 Proxy...')
        for fn in proxy_methods:
            _clean()
            if fn(final_url, fname, size, uploader, use_proxy=True):
                log(f'  Done in {(time.time()-t0)/60:.1f} min')
                return

        log(f'\n  ❌ FAILED — all methods exhausted for: {fname}')
    except Exception as e:
        import traceback; traceback.print_exc()
        log(f'  Fatal: {e}')

def main():
    raw = os.environ.get('DOWNLOAD_URLS', '').strip()
    if not raw: sys.exit(1)
    urls = [clean_url(u.strip()) for u in re.split(r'[,\n]+', raw) if u.strip() and not u.strip().startswith('#')]
    if not urls: sys.exit(1)

    log('=' * 65)
    log(f'  GDrive Downloader')
    if SUBFOLDER_NAME:
        log(f'  Target Subfolder: {SUBFOLDER_NAME}')
    log('=' * 65)

    drive = get_drive()
    
    target_folder_id = GDRIVE_FOLDER_ID
    if SUBFOLDER_NAME:
        target_folder_id = get_or_create_subfolder(drive, GDRIVE_FOLDER_ID, SUBFOLDER_NAME)

    t0 = time.time()
    for i, url in enumerate(urls, 1):
        log(f'\n[{i}/{len(urls)}]')
        process(url, drive, target_folder_id)
    hr()
    log(f'All done in {(time.time()-t0)/60:.1f} min')

if __name__ == '__main__':
    main()
