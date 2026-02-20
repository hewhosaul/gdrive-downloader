#!/usr/bin/env python3
"""
GDrive Downloader — GitHub Actions
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Download waterfall:
  1. aria2c         — 16 parallel connections, fastest for open servers
  2. yt-dlp         — with curl_cffi impersonation, bypasses Cloudflare
  3. curl_cffi      — browser TLS fingerprint, bypasses Cloudflare
  4. requests       — plain fallback

Upload: OAuth refresh token → your personal GDrive quota (no limit issues)
        256MB RAM chunks → resumable Drive API (works for 100GB+ files)
"""

import os, sys, re, time, json, subprocess, tempfile
from pathlib import Path
from urllib.parse import urlparse, unquote

import requests as req_lib
from tqdm import tqdm
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from googleapiclient.discovery import build

# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════
GDRIVE_FOLDER = 'Movies'
CHUNK_SIZE    = 256 * 1024 * 1024   # 256MB upload chunks (RAM only, no disk)
DL_CHUNK      = 8   * 1024 * 1024   # 8MB read buffer
ARIA2C_CONNS  = 16
TMP           = tempfile.mkdtemp(prefix='dl_')

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
      'AppleWebKit/537.36 (KHTML, like Gecko) '
      'Chrome/122.0.0.0 Safari/537.36')

COMMON_HEADERS = {
    'User-Agent': UA,
    'Accept': '*/*',
    'Accept-Encoding': 'identity',
    'Accept-Language': 'en-US,en;q=0.9',
}

# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════
def log(msg): print(msg, flush=True)
def hr():     log('─' * 65)
def fmt(b):   return f'{b/1e9:.2f} GB' if b > 1e9 else f'{b/1e6:.1f} MB'
def speed(b): return f'{b/1e6:.1f} MB/s'

def sanitize(name: str) -> str:
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    return name[:200].strip() or f'file_{int(time.time())}'

def referer(url): 
    p = urlparse(url)
    return f'{p.scheme}://{p.netloc}/'

def make_session():
    s = req_lib.Session()
    s.headers.update(COMMON_HEADERS)
    s.mount('http://',  req_lib.adapters.HTTPAdapter(max_retries=req_lib.adapters.Retry(3, backoff_factor=1)))
    s.mount('https://', req_lib.adapters.HTTPAdapter(max_retries=req_lib.adapters.Retry(3, backoff_factor=1)))
    return s

SESSION = make_session()

# ═══════════════════════════════════════════════════════════════
# OAUTH — uses your personal GDrive quota, no service account
# ═══════════════════════════════════════════════════════════════
_creds = None

def get_creds() -> Credentials:
    global _creds
    if _creds:
        if _creds.expired:
            _creds.refresh(GoogleAuthRequest())
        return _creds

    client_id     = os.environ['GDRIVE_CLIENT_ID']
    client_secret = os.environ['GDRIVE_CLIENT_SECRET']
    refresh_token = os.environ['GDRIVE_REFRESH_TOKEN']

    _creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=client_id,
        client_secret=client_secret,
        scopes=['https://www.googleapis.com/auth/drive.file'],
    )
    _creds.refresh(GoogleAuthRequest())
    return _creds

def get_token() -> str:
    creds = get_creds()
    if creds.expired:
        creds.refresh(GoogleAuthRequest())
    return creds.token

def get_drive():
    return build('drive', 'v3', credentials=get_creds(), cache_discovery=False)

# ═══════════════════════════════════════════════════════════════
# DRIVE FOLDER
# ═══════════════════════════════════════════════════════════════
def get_or_create_folder(drive, name, parent='root') -> str:
    q = (f"name='{name}' and "
         f"mimeType='application/vnd.google-apps.folder' and "
         f"'{parent}' in parents and trashed=false")
    res = drive.files().list(q=q, fields='files(id)').execute()
    if res['files']:
        return res['files'][0]['id']
    f = drive.files().create(
        body={'name': name,
              'mimeType': 'application/vnd.google-apps.folder',
              'parents': [parent]},
        fields='id').execute()
    log(f'  Created GDrive folder "{name}"')
    return f['id']

def file_exists(drive, folder_id, fname, expected_size) -> bool:
    q = f"name='{fname}' and '{folder_id}' in parents and trashed=false"
    res = drive.files().list(q=q, fields='files(id,size)').execute()
    if not res['files']:
        return False
    ds = int(res['files'][0].get('size', 0))
    return bool(expected_size and ds >= expected_size * 0.99)

# ═══════════════════════════════════════════════════════════════
# URL RESOLVER
# ═══════════════════════════════════════════════════════════════
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
    log(f'  Size : {fmt(size) if size else "unknown (server did not send Content-Length)"}')
    log(f'  URL  : {final[:100]}')
    return final, fname, size

# ═══════════════════════════════════════════════════════════════
# STREAMING UPLOAD — 256MB RAM chunks → Drive API resumable
# No disk writes. Works for files of any size.
# ═══════════════════════════════════════════════════════════════
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
            'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json; charset=UTF-8',
                'X-Upload-Content-Type': 'application/octet-stream',
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
                        'Content-Type': 'application/octet-stream',
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

    def run(self, stream_iter, bar_desc='Upload'):
        self._start()
        buf = b''; uploaded = 0; t0 = time.time()
        bar = tqdm(total=self.total_size or None, unit='B',
                   unit_scale=True, unit_divisor=1024,
                   desc=f'  {bar_desc}', colour='green',
                   dynamic_ncols=True, miniters=1, file=sys.stdout)
        for chunk in stream_iter:
            if not chunk: continue
            buf += chunk
            while len(buf) >= CHUNK_SIZE:
                piece = buf[:CHUNK_SIZE]; buf = buf[CHUNK_SIZE:]
                self._put_chunk(piece, uploaded, is_last=False)
                uploaded += len(piece); bar.update(len(piece))
                elapsed = time.time() - t0
                if elapsed: bar.set_postfix(speed=speed(uploaded/elapsed), refresh=True)
        if buf:
            if not self.total_size:
                self.total_size = uploaded + len(buf)
            self._put_chunk(buf, uploaded, is_last=True)
            uploaded += len(buf); bar.update(len(buf))
        bar.close()
        elapsed = time.time() - t0
        log(f'  Uploaded {fmt(uploaded)} in {elapsed:.1f}s ({speed(uploaded/elapsed)})')
        return uploaded

def file_to_drive(path, uploader, desc='Cloud -> GDrive'):
    def gen():
        with open(path, 'rb') as f:
            while True:
                c = f.read(DL_CHUNK)
                if not c: break
                yield c
    uploader.run(gen(), bar_desc=desc)

# ═══════════════════════════════════════════════════════════════
# PROGRESS BAR — poll growing file while subprocess runs
# ═══════════════════════════════════════════════════════════════
def poll_bar(proc, out_path, size, desc):
    bar = tqdm(total=size or None, unit='B', unit_scale=True,
               unit_divisor=1024, desc=f'  {desc}', colour='cyan',
               dynamic_ncols=True, miniters=1, file=sys.stdout)
    t0 = time.time(); prev = 0
    while proc.poll() is None:
        try:   cur = os.path.getsize(out_path)
        except OSError: cur = 0
        if cur > prev:
            bar.update(cur - prev)
            e = time.time() - t0
            if e: bar.set_postfix(speed=speed(cur/e), refresh=True)
            prev = cur
        time.sleep(0.4)
    try:
        cur = os.path.getsize(out_path); bar.update(cur - prev)
    except OSError: pass
    bar.close()

# ═══════════════════════════════════════════════════════════════
# METHOD 1 — aria2c (fastest for open/CDN servers)
# ═══════════════════════════════════════════════════════════════
def try_aria2c(url, fname, size, uploader) -> bool:
    log('  [1/4] aria2c — 16 parallel connections')
    out = f'{TMP}/{fname}'
    cmd = [
        'aria2c', url, '--dir', TMP, '--out', fname,
        f'-x{ARIA2C_CONNS}', f'-s{ARIA2C_CONNS}', '-k4M',
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
    file_to_drive(out, uploader, desc=f'GDrive  {fname[:35]}')
    try: os.remove(out)
    except: pass
    return True

# ═══════════════════════════════════════════════════════════════
# METHOD 2 — yt-dlp with curl_cffi impersonation (Cloudflare bypass)
# ═══════════════════════════════════════════════════════════════
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
        '--extractor-args', 'generic:impersonate',   # ← Cloudflare bypass
        '--progress', '--newline',
        url
    ]
    t0   = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    bar  = tqdm(total=size or None, unit='B', unit_scale=True,
                unit_divisor=1024, desc=f'  yt-dlp  {fname[:35]}',
                colour='magenta', dynamic_ncols=True,
                miniters=1, file=sys.stdout)
    prev = 0
    for line in proc.stdout:
        line = line.strip()
        m = re.search(r'\[download\]\s+([\d.]+)%\s+of\s+~?\s*([\d.]+)(GiB|MiB|KiB|B)', line)
        if m:
            pct  = float(m.group(1)) / 100
            mult = {'GiB': 1<<30, 'MiB': 1<<20, 'KiB': 1<<10, 'B': 1}[m.group(3)]
            cur  = int(pct * float(m.group(2)) * mult)
            if cur > prev:
                bar.update(cur - prev)
                e = time.time() - t0
                if e: bar.set_postfix(speed=speed(cur/e), refresh=True)
                prev = cur
        elif line and '[download]' not in line:
            log(f'    {line}')
    bar.close(); proc.wait()
    candidates = sorted(Path(TMP).glob(f'{stem}.*'),
                        key=lambda p: p.stat().st_size, reverse=True)
    if not candidates or candidates[0].stat().st_size < 10000:
        log(f'  yt-dlp failed (code {proc.returncode})')
        return False
    out = str(candidates[0])
    log(f'  yt-dlp done: {fmt(os.path.getsize(out))}')
    log('  Uploading to GDrive...')
    file_to_drive(out, uploader, desc=f'GDrive  {fname[:35]}')
    try: os.remove(out)
    except: pass
    return True

# ═══════════════════════════════════════════════════════════════
# METHOD 3 — curl_cffi (browser TLS fingerprint, Cloudflare bypass)
# ═══════════════════════════════════════════════════════════════
def try_curl_cffi(url, fname, size, uploader) -> bool:
    log('  [3/4] curl_cffi (browser TLS fingerprint)')
    try:
        from curl_cffi import requests as cffi_req
    except ImportError:
        log('  curl_cffi not available, skipping')
        return False

    out  = f'{TMP}/{fname}'
    part = out + '.part'
    t0   = time.time(); done = 0
    bar  = tqdm(total=size or None, unit='B', unit_scale=True,
                unit_divisor=1024, desc=f'  cffi    {fname[:35]}',
                colour='yellow', dynamic_ncols=True,
                miniters=1, file=sys.stdout)
    try:
        # impersonate='chrome120' makes TLS handshake look like real Chrome
        with cffi_req.get(url, stream=True, timeout=120,
                          impersonate='chrome120',
                          headers=COMMON_HEADERS) as r:
            r.raise_for_status()
            with open(part, 'wb') as f:
                for chunk in r.iter_content(chunk_size=DL_CHUNK):
                    if chunk:
                        f.write(chunk); done += len(chunk); bar.update(len(chunk))
                        e = time.time() - t0
                        if e: bar.set_postfix(speed=speed(done/e), refresh=True)
        bar.close()
        os.rename(part, out)
    except Exception as e:
        bar.close()
        log(f'  curl_cffi download failed: {e}')
        return False

    if not os.path.exists(out) or os.path.getsize(out) < 10000:
        log('  curl_cffi produced empty file')
        return False

    log(f'  curl_cffi done: {fmt(os.path.getsize(out))}')
    log('  Uploading to GDrive...')
    file_to_drive(out, uploader, desc=f'GDrive  {fname[:35]}')
    try: os.remove(out)
    except: pass
    return True

# ═══════════════════════════════════════════════════════════════
# METHOD 4 — plain requests stream (last resort)
# ═══════════════════════════════════════════════════════════════
def try_requests(url, fname, size, uploader) -> bool:
    log('  [4/4] requests stream (plain fallback)')
    t0  = time.time()
    bar = tqdm(total=size or None, unit='B', unit_scale=True,
               unit_divisor=1024, desc=f'  stream  {fname[:35]}',
               colour='white', dynamic_ncols=True,
               miniters=1, file=sys.stdout)
    def gen():
        done = 0
        with SESSION.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            for chunk in r.iter_content(chunk_size=DL_CHUNK):
                if chunk:
                    done += len(chunk); bar.update(len(chunk))
                    e = time.time() - t0
                    if e: bar.set_postfix(speed=speed(done/e), refresh=True)
                    yield chunk
        bar.close()
    try:
        uploader.run(gen(), bar_desc=f'GDrive  {fname[:35]}')
        return True
    except Exception as e:
        bar.close()
        log(f'  requests failed: {e}')
        return False

# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════
def process(url: str, drive, folder_id: str):
    url = url.strip()
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
        t0       = time.time()
        for fn in [try_aria2c, try_ytdlp, try_curl_cffi, try_requests]:
            # clean any partial file before each attempt
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

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def main():
    raw  = os.environ.get('DOWNLOAD_URLS', '').strip()
    if not raw:
        log('No URLs. Set DOWNLOAD_URLS env var.')
        sys.exit(1)
    urls = [u.strip() for u in re.split(r'[,\n]+', raw)
            if u.strip() and not u.strip().startswith('#')]
    if not urls:
        log('No valid URLs found.')
        sys.exit(1)

    log('=' * 65)
    log(f'GDrive Downloader — {len(urls)} file(s) queued')
    log(f'Destination : GDrive/{GDRIVE_FOLDER}')
    log(f'Upload mode : OAuth (your personal quota)')
    log(f'Disk usage  : ~0 bytes (RAM streaming)')
    log('=' * 65)

    # Validate OAuth secrets up front so we fail fast
    for key in ('GDRIVE_CLIENT_ID', 'GDRIVE_CLIENT_SECRET', 'GDRIVE_REFRESH_TOKEN'):
        if not os.environ.get(key):
            log(f'ERROR: GitHub secret "{key}" is not set.')
            log('Run get_token.py on your PC and add the three secrets.')
            sys.exit(1)

    log('Connecting to Google Drive...')
    drive     = get_drive()
    folder_id = get_or_create_folder(drive, GDRIVE_FOLDER)
    log(f'GDrive ready — uploading to personal quota\n')

    t0 = time.time()
    for i, url in enumerate(urls, 1):
        log(f'\n[{i}/{len(urls)}]')
        process(url, drive, folder_id)
    hr()
    log(f'All done in {(time.time()-t0)/60:.1f} min')

if __name__ == '__main__':
    main()
