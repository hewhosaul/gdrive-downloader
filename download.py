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
        
        # Round 1: Fast Direct Array (aria2c first)
        direct_methods = [try_aria2c, try_ytdlp, try_curl_cffi, try_curl, try_requests]
        
        # Round 2: Proxy Array (yt-dlp first for 16 concurrent fragments. aria2c skipped)
        proxy_methods  = [try_ytdlp, try_curl, try_curl_cffi, try_requests]

        def _clean():
            for p in Path(TMP).glob(f'{Path(fname).stem}*'):
                try: p.unlink()
                except: pass

        log('  Round 1: direct connection')
        for fn in direct_methods:
            _clean()
            if fn(final_url, fname, size, uploader, use_proxy=False):
                log(f'  Done in {(time.time()-t0)/60:.1f} min')
                return

        log('  All direct methods failed — activating local WARP SOCKS5 Proxy...')
        log('  Round 2: retrying via proxy (Uploads will remain on fast direct IP)')
        for fn in proxy_methods:
            _clean()
            if fn(final_url, fname, size, uploader, use_proxy=True):
                log(f'  Done in {(time.time()-t0)/60:.1f} min')
                return

        log(f'  FAILED — all methods exhausted for: {fname}')
    except Exception as e:
        import traceback; traceback.print_exc()
        log(f'  Fatal: {e}')
