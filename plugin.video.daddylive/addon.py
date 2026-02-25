# -*- coding: utf-8 -*- 
'''
***********************************************************
*
* @file addon.py
* @package script.module.thecrew
*
* Created on 2024-03-08.
* Copyright 2024 by The Crew. All rights reserved.
*
* @license GNU General Public License, version 3 (GPL-3.0)
*
********************************************************cm*
'''

import re
import os
import sys
import json
import html
import base64
import hashlib
import hmac as _hmac
import requests
import threading
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, unquote, parse_qsl, quote_plus, urlparse, urljoin
from datetime import datetime, timezone
import time
import calendar
import xbmc
import xbmcvfs
import xbmcgui
import xbmcplugin
import xbmcaddon

DADDYLIVE_PROXY_CACHE = {} 

addon_url = sys.argv[0]
addon_handle = int(sys.argv[1])
params = dict(parse_qsl(sys.argv[2][1:]))
addon = xbmcaddon.Addon(id='plugin.video.daddylive')
mode = addon.getSetting('mode')

UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'
FANART = addon.getAddonInfo('fanart')
ICON = addon.getAddonInfo('icon')

_seed_setting = addon.getSetting('seed_baseurl').strip()
SEED_BASEURL = _seed_setting if _seed_setting else 'https://dlhd.link/'
EXTRA_M3U8_URL = 'http://drewlive2423.duckdns.org:8081/DrewLive/MergedPlaylist.m3u8'

RAILWAY_PROXY = "https://maneproxy-production.up.railway.app/proxy"
RAILWAY_API_KEY = "SD5NEo2pGgO976Q0B914q3jyQ31DnbMTUQo0NtYL1eWKsRcp8lGmtr9uFJzGOigHfs46rWhZYK4i78tZvZ6Mh9cbNlWHGDSb1Ti6STqLKj0uSrd7kW77xh1FtsGEMKTc9vLxpdNmcn4tByMxzqPZ44OzmiCQgFlOS7YZhqI7QBJbXLX6UntD95k3gaAYykgMRFLaZDGh1jGZgNiQOik486bosYeaKiC5J4KUs3mnHRyCtJignCjkQXiFhppeGqIp"

CHEVY_PROXY = 'https://chevy.adsfadfds.cfd'
CHEVY_LOOKUP = 'https://chevy.soyspace.cyou'
PLAYER_REFERER = 'https://www.ksohls.ru/'

M3U8_PROXY_PORT = 19876

# EPlayer auth — UA/screen/tz/lang values used for fingerprint computation
_AUTH_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

# Thread-safe state store: channel_key → {auth_token, channel_salt, m3u8_url, fetched_at}
_proxy_lock = threading.Lock()
_channel_creds = {}


def _compute_fingerprint():
    combined = _AUTH_UA + '1920x1080' + 'UTC' + 'en'
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def _compute_pow_nonce(channel_key, channel_salt, key_id, ts):
    hmac_base = _hmac.new(channel_salt.encode(), channel_key.encode(), hashlib.sha256).hexdigest()
    for nonce in range(100000):
        combined = hmac_base + channel_key + key_id + str(ts) + str(nonce)
        h = hashlib.md5(combined.encode()).hexdigest()
        if int(h[:4], 16) < 0x1000:
            return nonce
    return 99999


def _compute_auth_sig(channel_key, channel_salt, key_id, ts, fp):
    msg = f'{channel_key}|{key_id}|{ts}|{fp}'
    return _hmac.new(channel_salt.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]


def _xor_decode(arr, key):
    return ''.join(chr(b ^ key) for b in arr)


def _extract_credential(page, field):
    """Extract a credential value supporting plain string or XOR-encoded formats."""
    # Format 1: field: 'value'
    m = re.search(rf"{field}\s*:\s*'([^']+)'", page)
    if m:
        return m.group(1)
    # Format 2: field: _dec_XXXX(_init_YYYY, key)
    m = re.search(rf"{field}\s*:\s*_dec_\w+\((_init_\w+),\s*(\d+)\)", page)
    if m:
        init_name, key = m.group(1), int(m.group(2))
        arr_m = re.search(rf"{init_name}\s*=\s*\[([^\]]+)\]", page)
        if arr_m:
            arr = list(map(int, arr_m.group(1).split(',')))
            return _xor_decode(arr, key)
    return None


def _fetch_auth_credentials(channel_id):
    """Fetch fresh authToken and channelSalt from the ksohls.ru player page."""
    url = f'https://www.ksohls.ru/premiumtv/daddyhd.php?id={channel_id}'
    for attempt in range(3):
        try:
            r = requests.get(url, headers={
                'User-Agent': _AUTH_UA,
                'Referer': get_active_base(),
            }, timeout=15)
            auth_token = _extract_credential(r.text, 'authToken')
            channel_salt = _extract_credential(r.text, 'channelSalt')
            if auth_token and channel_salt:
                return auth_token, channel_salt
            log(f'[EPlayerAuth] Credentials not found (attempt {attempt+1}/3), page snippet: {r.text[:200]}')
        except Exception as e:
            log(f'[EPlayerAuth] fetch error (attempt {attempt+1}/3): {e}')
        if attempt < 2:
            time.sleep(2)
    return None, None


def _state_file(channel_key):
    return os.path.join(tempfile.gettempdir(), f'daddylive_{channel_key}.json')


def _set_channel_state(channel_key, auth_token, channel_salt, m3u8_url):
    state = {
        'auth_token': auth_token,
        'channel_salt': channel_salt,
        'm3u8_url': m3u8_url,
        'fetched_at': time.time(),
    }
    with _proxy_lock:
        _channel_creds[channel_key] = state
    # Persist to temp file so other plugin processes can read the state
    try:
        with open(_state_file(channel_key), 'w') as f:
            json.dump(state, f)
    except Exception:
        pass


def _get_channel_state(channel_key):
    with _proxy_lock:
        state = _channel_creds.get(channel_key)
    if state:
        return dict(state)
    # Cross-process fallback: read from temp file (written by another plugin process)
    try:
        path = _state_file(channel_key)
        if os.path.exists(path) and (time.time() - os.path.getmtime(path)) < 300:
            with open(path) as f:
                state = json.load(f)
            with _proxy_lock:
                _channel_creds[channel_key] = state
            return dict(state)
    except Exception:
        pass
    return {}


class _EPlayerProxyHandler(BaseHTTPRequestHandler):
    """Local HTTP proxy that:
    - GET /m3u8/<channel_key>  → fetches live m3u8, rewrites key URIs to /key/...
    - GET /key/<channel_key>/<key_id> → computes auth headers, fetches real AES key
    """

    def do_GET(self):
        m = re.match(r'^/m3u8/([^/?]+)', self.path)
        if m:
            self._handle_m3u8(m.group(1))
            return
        m = re.match(r'^/key/([^/]+)/(\d+)', self.path)
        if m:
            self._handle_key(m.group(1), m.group(2))
            return
        m = re.match(r'^/seg/(.+)', self.path)
        if m:
            self._handle_segment(m.group(1))
            return
        m = re.match(r'^/raw/([^/]+)/(.+)', self.path)
        if m:
            self._handle_raw(m.group(1), m.group(2))
            return
        self.send_response(404)
        self.end_headers()

    def _handle_m3u8(self, channel_key):
        state = _get_channel_state(channel_key)
        if not state or not state.get('m3u8_url'):
            # Proxy runs in old process — fetch credentials on demand
            m = re.match(r'^premium(\d+)$', channel_key)
            if m:
                cid = m.group(1)
                log(f'[EPlayerProxy] No state for {channel_key}, fetching credentials for id={cid}')
                auth_token, channel_salt = _fetch_auth_credentials(cid)
                if auth_token and channel_salt:
                    m3u8_url = resolve_stream_url(cid)
                    _set_channel_state(channel_key, auth_token, channel_salt, m3u8_url)
                    state = _get_channel_state(channel_key)
        if not state or not state.get('m3u8_url'):
            self.send_response(503)
            self.end_headers()
            return
        try:
            m3u8_hdrs = {
                'User-Agent': _AUTH_UA,
                'Referer': PLAYER_REFERER,
                'Authorization': f'Bearer {state["auth_token"]}',
                'X-Channel-Key': channel_key,
                'X-User-Agent': _AUTH_UA,
            }
            r = requests.get(state['m3u8_url'], headers=m3u8_hdrs, timeout=10)
            content = r.text
            seq_m = re.search(r'MEDIA-SEQUENCE:(\d+)', content)
            seq = seq_m.group(1) if seq_m else '?'
            log(f'[EPlayerProxy] m3u8 fetched seq={seq} status={r.status_code}')

            port = M3U8_PROXY_PORT

            def _rewrite_key(mo):
                uri = mo.group(1)
                km = re.search(r'/key/[^/]+/(\d+)', uri)
                if km:
                    return f'URI="http://127.0.0.1:{port}/key/{channel_key}/{km.group(1)}"'
                return mo.group(0)

            content = re.sub(r'URI="([^"]+)"', _rewrite_key, content)

            # Rewrite segment URLs so Kodi fetches them via the proxy
            # (segments need Origin/Referer headers that Kodi doesn't send)
            seg_lines = []
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith('#') and (stripped.startswith('https://') or stripped.startswith('http://')):
                    encoded = quote_plus(stripped)
                    seg_lines.append(f'http://127.0.0.1:{port}/seg/{encoded}')
                else:
                    seg_lines.append(line)
            content = '\n'.join(seg_lines)

            body = content.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/vnd.apple.mpegurl')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            log(f'[EPlayerProxy] m3u8 error for {channel_key}: {e}')
            self.send_response(502)
            self.end_headers()

    def _handle_key(self, channel_key, key_id):
        state = _get_channel_state(channel_key)
        if not state or not state.get('channel_salt'):
            # Proxy runs in old process — fetch credentials on demand
            m = re.match(r'^premium(\d+)$', channel_key)
            if m:
                cid = m.group(1)
                auth_token, channel_salt = _fetch_auth_credentials(cid)
                if auth_token and channel_salt:
                    m3u8_url = resolve_stream_url(cid)
                    _set_channel_state(channel_key, auth_token, channel_salt, m3u8_url)
                    state = _get_channel_state(channel_key)
        if not state or not state.get('channel_salt'):
            self.send_response(503)
            self.end_headers()
            return
        try:
            ts = int(time.time())
            fp = _compute_fingerprint()
            nonce = _compute_pow_nonce(channel_key, state['channel_salt'], key_id, ts)
            auth_sig = _compute_auth_sig(channel_key, state['channel_salt'], key_id, ts, fp)
            key_url = f'{CHEVY_LOOKUP}/key/{channel_key}/{key_id}'
            r = requests.get(key_url, headers={
                'User-Agent': _AUTH_UA,
                'Referer': PLAYER_REFERER,
                'Authorization': f'Bearer {state["auth_token"]}',
                'X-Key-Timestamp': str(ts),
                'X-Key-Nonce': str(nonce),
                'X-Key-Path': auth_sig,
                'X-Fingerprint': fp,
            }, timeout=10)
            body = r.content
            log(f'[EPlayerProxy] key {key_id}: {len(body)}B status={r.status_code} nonce={nonce}')
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            log(f'[EPlayerProxy] key error for {channel_key}/{key_id}: {e}')
            self.send_response(502)
            self.end_headers()

    def _handle_raw(self, encoded_origin, encoded_url):
        """Proxy a URL with a specific Origin/Referer.
        - m3u8: rewrites relative segment URLs to absolute and routes them through /raw/
        - segments (.ts): streamed in chunks for low latency
        """
        try:
            origin = unquote(encoded_origin)
            raw_url = unquote(encoded_url)
            referer = origin.rstrip('/') + '/'
            hdrs = {'User-Agent': UA, 'Origin': origin, 'Referer': referer}

            # Decide by URL extension to avoid buffering segments unnecessarily
            is_manifest = '.m3u8' in raw_url.split('?')[0]

            if is_manifest:
                r = requests.get(raw_url, headers=hdrs, timeout=15)
                port = M3U8_PROXY_PORT
                base = raw_url.split('?')[0].rsplit('/', 1)[0] + '/'
                enc_orig = quote_plus(origin)
                seg_lines = []
                for line in r.text.splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith('#'):
                        abs_seg = stripped if stripped.startswith('http') else urljoin(base, stripped)
                        seg_lines.append(f'http://127.0.0.1:{port}/raw/{enc_orig}/{quote_plus(abs_seg)}')
                    else:
                        seg_lines.append(line)
                body = '\n'.join(seg_lines).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/vnd.apple.mpegurl')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                # Segment — stream chunks immediately
                r = requests.get(raw_url, headers=hdrs, timeout=20, stream=True)
                self.send_response(r.status_code)
                ct = r.headers.get('Content-Type', 'video/mp2t')
                self.send_header('Content-Type', ct)
                cl = r.headers.get('Content-Length')
                if cl:
                    self.send_header('Content-Length', cl)
                self.end_headers()
                for chunk in r.iter_content(65536):
                    self.wfile.write(chunk)
        except Exception as e:
            log(f'[EPlayerProxy] raw error: {e}')
            try:
                self.send_response(502)
                self.end_headers()
            except Exception:
                pass

    def _handle_segment(self, encoded_url):
        try:
            seg_url = unquote(encoded_url)
            r = requests.get(seg_url, headers={
                'User-Agent': _AUTH_UA,
                'Referer': PLAYER_REFERER,
                'Origin': 'https://www.ksohls.ru',
            }, timeout=20, stream=True)
            self.send_response(r.status_code)
            ct = r.headers.get('Content-Type', 'video/mp2t')
            self.send_header('Content-Type', ct)
            cl = r.headers.get('Content-Length')
            if cl:
                self.send_header('Content-Length', cl)
            self.end_headers()
            for chunk in r.iter_content(65536):
                self.wfile.write(chunk)
        except Exception as e:
            log(f'[EPlayerProxy] seg error: {e}')
            try:
                self.send_response(502)
                self.end_headers()
            except Exception:
                pass

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


class _M3U8ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        target = unquote(self.path.lstrip('/'))
        try:
            r = requests.get(target, headers={'User-Agent': UA}, timeout=15)
            body = r.content
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()
    def log_message(self, fmt, *args):
        pass

def _ensure_m3u8_proxy():
    try:
        server = HTTPServer(('127.0.0.1', M3U8_PROXY_PORT), _EPlayerProxyHandler)
        t = threading.Thread(target=server.serve_forever)
        t.daemon = True
        t.start()
        log(f'[EPlayerProxy] Started on port {M3U8_PROXY_PORT}')
    except OSError as e:
        if e.errno in (98, 10048):
            log(f'[EPlayerProxy] Already running on port {M3U8_PROXY_PORT}')
        else:
            log(f'[EPlayerProxy] Failed to start: {e}')

EXTRA_CHANNELS_DATA = {} 

CACHE_URLS = [
    "index.php",
    "24-7-channels.php"
]

NO_CACHE_URLS = [
    "watch.php",
    "watchs2watch.php"
]

def log(msg):
    logpath = xbmcvfs.translatePath('special://logpath/')
    filename = 'daddylive.log'
    log_file = os.path.join(logpath, filename)
    try:
        if isinstance(msg, str):
            _msg = f'\n    {msg}'
        else:
            _msg = f'\n    {repr(msg)}'
        if not os.path.exists(log_file):
            with open(log_file, 'w', encoding='utf-8'):
                pass
        with open(log_file, 'a', encoding='utf-8') as f:
            line = '[{} {}]: {}'.format(datetime.now().date(), str(datetime.now().time())[:8], _msg)
            f.write(line.rstrip('\r\n') + '\n')
    except Exception as e:
        try:
            xbmc.log(f'[ Daddylive ] Logging Failure: {e}', 2)
        except:
            pass

def should_cache_url(url: str) -> bool:
    """
    Determine if this URL is cacheable.
    Cache:
        - index.php pages (category, schedule, etc.)
        - 24-7-channels.php
    Do NOT cache:
        - watch.php (stream URLs)
    """
    if 'watch.php' in url:
        return False
    if 'index.php' in url or '24-7-channels.php' in url:
        return True
    return False


CACHE_URLS = [
    "index.php",
    "24-7-channels.php"
]

NO_CACHE_URLS = [
    "watch.php",
    "watchs2watch.php"
]

CACHE_EXPIRY = 12 * 60 * 60 

def _is_error_response(text):
    return not text or text.lstrip().startswith('{')

def fetch_via_proxy(url, method='get', data=None, headers=None, use_cache=True):
    headers = headers or {}
    headers['X-API-Key'] = RAILWAY_API_KEY

    should_cache = should_cache_url(url)

    cached = {}
    if should_cache:
        saved = addon.getSetting('proxy_cache')
        if saved:
            try:
                cached = json.loads(saved)
            except Exception as e:
                log(f"[fetch_via_proxy] Failed to load cache: {e}")
                cached = {}

        if url in cached:
            entry = cached[url]
            if isinstance(entry, dict) and 'data' in entry and 'timestamp' in entry:
                timestamp = entry.get('timestamp', 0)
                cached_data = entry.get('data', '')
                if time.time() - timestamp < CACHE_EXPIRY and not _is_error_response(cached_data):
                    log(f"[fetch_via_proxy] Returning cached data for {url}")
                    return cached_data
            else:
                log(f"[fetch_via_proxy] Old cache format found for {url}, refreshing")

    resp_text = ''
    direct_hdrs = {k: v for k, v in headers.items() if k != 'X-API-Key'}
    for attempt in range(3):
        for verify_ssl in [True, False]:
            try:
                resp_text = requests.get(url, headers=direct_hdrs, timeout=15,
                                         verify=verify_ssl, allow_redirects=True).text
                if not _is_error_response(resp_text):
                    log(f"[fetch_via_proxy] ok attempt={attempt} verify={verify_ssl} for {url}")
                    break
                log(f"[fetch_via_proxy] bad response verify={verify_ssl}: {resp_text[:80]}")
            except Exception as e:
                log(f"[fetch_via_proxy] failed attempt={attempt} verify={verify_ssl} for {url}: {type(e).__name__}: {e}")
        if not _is_error_response(resp_text):
            break
        if attempt < 2:
            time.sleep(2)
    if _is_error_response(resp_text):
        return ''

    if should_cache and not _is_error_response(resp_text):
        cached[url] = {
            'timestamp': int(time.time()),
            'data': resp_text
        }
        try:
            addon.setSetting('proxy_cache', json.dumps(cached))
        except Exception as e:
            log(f"[fetch_via_proxy] Failed to save cache: {e}")

    return resp_text




def normalize_origin(url):
    try:
        u = urlparse(url)
        return f'{u.scheme}://{u.netloc}/'
    except:
        return SEED_BASEURL

def resolve_active_baseurl(seed):
    try:
        _ = fetch_via_proxy(seed, headers={'User-Agent': UA})
        return normalize_origin(seed)
    except Exception as e:
        log(f'Active base resolve failed, using seed. Error: {e}')
        return normalize_origin(seed)

_active_base_cache = None

def get_active_base():
    global _active_base_cache
    if _active_base_cache:
        return _active_base_cache
    base = addon.getSetting('active_baseurl')
    if base:
        # Validate once per process — if unreachable, fall back to seed
        try:
            r = requests.get(base, headers={'User-Agent': UA}, timeout=5,
                             verify=False, allow_redirects=True)
            if r.status_code >= 400:
                raise Exception(f'HTTP {r.status_code}')
        except Exception as e:
            log(f'[get_active_base] {base} invalide ({e}), reset vers seed')
            base = ''
            addon.setSetting('active_baseurl', '')
    if not base:
        base = normalize_origin(SEED_BASEURL)
        addon.setSetting('active_baseurl', base)
    if not base.endswith('/'):
        base += '/'
    _active_base_cache = base
    return base

def set_active_base(new_base: str):
    if not new_base.endswith('/'):
        new_base += '/'
    addon.setSetting('active_baseurl', new_base)

def abs_url(path: str) -> str:
    return urljoin(get_active_base(), path.lstrip('/'))

def get_local_time(utc_time_str):
    if not utc_time_str:
        return ''
    try:
        # Parse manually — datetime.strptime is None in some Kodi/Python envs (_strptime lazy import bug)
        h, m = map(int, utc_time_str.strip().split(':'))
        utc_now = time.gmtime()
        utc_ts = calendar.timegm((utc_now.tm_year, utc_now.tm_mon, utc_now.tm_mday, h, m, 0, 0, 0, 0))
        local = time.localtime(utc_ts)
        use_24h = addon.getSetting('time_format') == '1'
        if use_24h:
            return f'{local.tm_hour:02d}:{local.tm_min:02d}'
        else:
            period = 'AM' if local.tm_hour < 12 else 'PM'
            h12 = local.tm_hour % 12 or 12
            return f'{h12}:{local.tm_min:02d} {period}'
    except Exception as e:
        log(f"Failed to convert time: {e}")
        return utc_time_str or ''


def build_url(query):
    return addon_url + '?' + urlencode(query)

def addDir(title, dir_url, is_folder=True, logo=None, context_menu=None):
    li = xbmcgui.ListItem(title)
    clean_plot = re.sub(r'<[^>]+>', '', title)
    labels = {'title': title, 'plot': clean_plot, 'mediatype': 'video'}
    if getKodiversion() < 20:
        li.setInfo("video", labels)
    else:
        infotag = li.getVideoInfoTag()
        infotag.setMediaType(labels.get("mediatype", "video"))
        infotag.setTitle(labels.get("title", "Daddylive"))
        infotag.setPlot(labels.get("plot", labels.get("title", "Daddylive")))

    logo = logo or ICON
    li.setArt({'thumb': logo, 'poster': logo, 'banner': logo, 'icon': logo, 'fanart': FANART})
    li.setProperty("IsPlayable", 'false' if is_folder else 'true')
    if context_menu:
        li.addContextMenuItems(context_menu)
    xbmcplugin.addDirectoryItem(handle=addon_handle, url=dir_url, listitem=li, isFolder=is_folder)


def closeDir():
    xbmcplugin.endOfDirectory(addon_handle)

def getKodiversion():
    try:
        return int(xbmc.getInfoLabel("System.BuildVersion")[:2])
    except:
        return 18

def Main_Menu():
    menu = [
        ['[B][COLOR gold]LIVE SPORTS SCHEDULE[/COLOR][/B]', 'sched', None],
        ['[B][COLOR gold]LIVE TV CHANNELS[/COLOR][/B]', 'live_tv', None],
        ['[B][COLOR gold]FAVORITE LIVE TV CHANNELS[/COLOR][/B]', 'favorites', None],
        ['[B][COLOR gold]EXTRA CHANNELS / VODS[/COLOR][/B]', 'extra_channels',
         'https://images-ext-1.discordapp.net/external/fUzDq2SD022-veHyDJTHKdYTBzD9371EnrUscXXrf0c/%3Fsize%3D4096/https/cdn.discordapp.com/icons/1373713080206495756/1fe97e658bc7fb0e8b9b6df62259c148.png?format=webp&quality=lossless'],
        ['[B][COLOR gold]SEARCH EVENTS SCHEDULE[/COLOR][/B]', 'search', None],
        ['[B][COLOR gold]SEARCH LIVE TV CHANNELS[/COLOR][/B]', 'search_channels', None],
        ['[B][COLOR gold]REFRESH CATEGORIES[/COLOR][/B]', 'refresh_sched', None],
        ['[B][COLOR gold]SET ACTIVE DOMAIN (AUTO)[/COLOR][/B]', 'resolve_base_now', None],
        ['[B][COLOR red]DIAGNOSTICS[/COLOR][/B]', 'diagnostics', None],
        ['[B][COLOR cyan]DADDYLIVE CHAT[/COLOR][/B]', 'chat', None],
    ]

    for title, mode_name, logo in menu:
        addDir(title, build_url({'mode': 'menu', 'serv_type': mode_name}), True, logo=logo)

    closeDir()


def run_diagnostics():
    def ok(text):
        return f'[COLOR lime][OK][/COLOR] {text}'
    def ko(text):
        return f'[COLOR red][KO][/COLOR] {text}'

    lines = []

    # 1. dlhd.link channels
    url = abs_url('24-7-channels.php')
    lines.append(f'[B]1. Liste des chaines[/B]  ({url})')
    fetched = False
    for verify_ssl in [True, False]:
        try:
            r = requests.get(url, headers={'User-Agent': UA}, timeout=10,
                             verify=verify_ssl, allow_redirects=True)
            cards = len(re.findall(r'class="card"', r.text))
            if cards > 0:
                lines.append(ok(f'HTTP {r.status_code} — {cards} chaines trouvees'))
                fetched = True
                break
            else:
                lines.append(ko(f'HTTP {r.status_code} — 0 chaines (verify={verify_ssl})'))
        except Exception as e:
            lines.append(ko(f'verify={verify_ssl}: {type(e).__name__}: {str(e)[:80]}'))
    if not fetched:
        lines.append(ko('Echec du chargement des chaines'))

    # 2. ksohls.ru credentials
    lines.append('[B]2. Credentials auth[/B]')
    try:
        r2 = requests.get('https://www.ksohls.ru/premiumtv/daddyhd.php?id=51',
                          headers={'User-Agent': UA, 'Referer': get_active_base()},
                          timeout=10, verify=False)
        has_token = 'authToken' in r2.text
        has_salt = 'channelSalt' in r2.text
        if has_token and has_salt:
            lines.append(ok(f'HTTP {r2.status_code} — authToken + channelSalt OK'))
        else:
            lines.append(ko(f'HTTP {r2.status_code} — authToken={has_token} channelSalt={has_salt}'))
    except Exception as e:
        lines.append(ko(f'{type(e).__name__}: {str(e)[:80]}'))

    # 3. CDN m3u8
    lines.append('[B]3. CDN m3u8[/B]')
    segs = []
    try:
        r3 = requests.get('https://chevy.adsfadfds.cfd/proxy/zeko/premium51/mono.css',
                          headers={'User-Agent': UA}, timeout=10, verify=False)
        segs = [l for l in r3.text.splitlines() if l and not l.startswith('#')]
        if r3.status_code == 200 and segs:
            lines.append(ok(f'HTTP {r3.status_code} — {len(segs)} segments'))
        else:
            lines.append(ko(f'HTTP {r3.status_code} — {len(segs)} segments'))
    except Exception as e:
        lines.append(ko(f'{type(e).__name__}: {str(e)[:80]}'))

    # 4. CDN segments
    lines.append('[B]4. CDN segments TS[/B]')
    if segs:
        try:
            r4 = requests.get(segs[-1], headers={
                                  'User-Agent': UA,
                                  'Referer': PLAYER_REFERER,
                                  'Origin': 'https://www.ksohls.ru',
                              }, allow_redirects=True, timeout=10, verify=False)
            ct = r4.headers.get('Content-Type', '')
            is_html = r4.content[:5] in (b'<!DOC', b'<html') or 'text/html' in ct
            if r4.status_code == 200 and len(r4.content) > 1000 and not is_html:
                lines.append(ok(f'HTTP {r4.status_code} — {len(r4.content)} octets — video OK'))
            elif r4.status_code == 200 and is_html:
                lines.append(ko(f'HTTP {r4.status_code} — page HTML ({len(r4.content)}o) — CDN en panne'))
            else:
                lines.append(ko(f'HTTP {r4.status_code} — {len(r4.content)} octets'))
        except Exception as e:
            lines.append(ko(f'{type(e).__name__}: {str(e)[:80]}'))
    else:
        lines.append(ko('Pas de segments a tester'))

    msg = '\n'.join(lines)
    log(f'[Diagnostics]\n{msg}')
    version = addon.getAddonInfo('version')
    xbmcgui.Dialog().textviewer(f'DaddyLive v3 v{version} - Diagnostics', msg)

def getCategTrans():
    schedule_url = abs_url('index.php')
    try:
        html_text = fetch_via_proxy(schedule_url, headers={'User-Agent': UA, 'Referer': get_active_base()})
        log(html_text[:1000])
        m = re.search(r'<div[^>]+class="filters"[^>]*>(.*?)</div>', html_text, re.IGNORECASE | re.DOTALL)
        if not m:
            log("getCategTrans(): filters block not found")
            return []

        block = m.group(1)
        anchors = re.findall(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', block, re.IGNORECASE | re.DOTALL)
        if not anchors:
            log("getCategTrans(): no <a> items in filters block")
            return []

        categs = []
        seen = set()
        for href, text_content in anchors:
            name = html.unescape(re.sub(r'\s+', ' ', text_content)).strip()
            if not name or name.lower() == 'all':
                continue
            if name in seen:
                continue
            seen.add(name)
            categs.append((name, '[]'))

        return categs
    except Exception as e:
        xbmcgui.Dialog().ok("Error", f"Error fetching category data: {e}")
        log(f'index parse fail: url={schedule_url} err={e}')
        return []

def Menu_Trans():
    categs = getCategTrans()
    if not categs:
        return
    for categ_name, _ in categs:
        addDir(categ_name, build_url({'mode': 'showChannels', 'trType': categ_name}))
    closeDir()

def ShowChannels(categ, channels_list):
    for item in channels_list:
        title = item.get('title')
        addDir(title, build_url({'mode': 'trList', 'trType': categ, 'channels': json.dumps(item.get('channels'))}), True)
    closeDir()

def getTransData(categ):
    try:
        url = abs_url('index.php?cat=' + quote_plus(categ))
        html_text = fetch_via_proxy(url, headers={'User-Agent': UA, 'Referer': get_active_base()})
        cut = re.search(r'<h2\s+class="collapsible-header\b', html_text, re.IGNORECASE)
        if cut:
            html_text = html_text[:cut.start()]

        events = re.findall(
            r'<div\s+class="schedule__event">.*?'
            r'<div\s+class="schedule__eventHeader"[^>]*?>\s*'
            r'(?:<[^>]+>)*?'
            r'<span\s+class="schedule__time"[^>]*data-time="([^"]+)"[^>]*>.*?</span>\s*'
            r'<span\s+class="schedule__eventTitle">\s*([^<]+)\s*</span>.*?'
            r'</div>\s*'
            r'<div\s+class="schedule__channels">(.*?)</div>',
            html_text, re.IGNORECASE | re.DOTALL
        )

        trns = []
        for time_str, event_title, channels_block in events:
            event_time_local = get_local_time(time_str.strip())
            title = f'[COLOR gold]{event_time_local}[/COLOR] {html.unescape(event_title.strip())}'

            chans = []
            for href, title_attr, link_text in re.findall(
                r'<a[^>]+href="([^"]+)"[^>]*title="([^"]*)"[^>]*>(.*?)</a>',
                channels_block, re.IGNORECASE | re.DOTALL
            ):
                try:
                    u = urlparse(href)
                    qs = dict(parse_qsl(u.query))
                    cid = qs.get('id') or ''
                except Exception:
                    cid = ''
                name = html.unescape((title_attr or link_text).strip())
                if cid:
                    chans.append({'channel_name': name, 'channel_id': cid})

            if chans:
                trns.append({'title': title, 'channels': chans})

        return trns
    except Exception as e:
        log(f'getTransData error for categ={categ}: {e}')
        return []

def TransList(categ, channels):
    for channel in channels:
        channel_title = html.unescape(channel.get('channel_name'))
        channel_id = str(channel.get('channel_id', '')).strip()
        if not channel_id:
            continue
        addDir(channel_title, build_url({'mode': 'trLinks', 'trData': json.dumps({'channels': [{'channel_name': channel_title, 'channel_id': channel_id}]})}), False)
    closeDir()

def getSource(trData):
    try:
        data = json.loads(unquote(trData))
        channels_data = data.get('channels')
        if channels_data and isinstance(channels_data, list):
            cid = str(channels_data[0].get('channel_id', '')).strip()
            if not cid:
                return
            if '%7C' in cid or '|' in cid:
                url_stream = abs_url('watchs2watch.php?id=' + cid)
            else:
                url_stream = abs_url('watch.php?id=' + cid)
            xbmcplugin.setContent(addon_handle, 'videos')
            PlayStream(url_stream)
    except Exception as e:
        log(f'getSource failed: {e}')

def get_favorites():
    try:
        return json.loads(addon.getSetting('favorites') or '[]')
    except:
        return []

def save_favorites(favs):
    addon.setSetting('favorites', json.dumps(favs))

def toggle_favorite(cid, name):
    favs = get_favorites()
    ids = [f['id'] for f in favs]
    if cid in ids:
        favs = [f for f in favs if f['id'] != cid]
        save_favorites(favs)
        xbmcgui.Dialog().notification('DaddyLive v3', f'Retiré des favoris : {name}', ICON, 2000)
    else:
        favs.append({'id': cid, 'name': name})
        save_favorites(favs)
        xbmcgui.Dialog().notification('DaddyLive v3', f'Ajouté aux favoris : {name}', ICON, 2000)
    xbmc.executebuiltin('Container.Refresh')

def list_favorites():
    favs = get_favorites()
    if not favs:
        xbmcgui.Dialog().notification('DaddyLive v3', 'Aucun favori. Appui long sur une chaîne pour ajouter.', ICON, 3000)
        closeDir()
        return
    fav_ids = {f['id'] for f in favs}
    for fav in favs:
        cid = fav['id']
        name = fav['name']
        ctx = [('Retirer des favoris', 'RunPlugin(%s)' % build_url({'mode': 'toggle_fav', 'cid': cid, 'name': name}))]
        addDir(name, build_url({'mode': 'play', 'url': abs_url('watch.php?id=' + cid)}), False, context_menu=ctx)
    closeDir()

def list_gen():
    chData = channels()
    if not chData:
        xbmcgui.Dialog().notification('DaddyLive v3', 'Impossible de charger les chaînes. Vérifiez votre connexion.', ICON, 5000)
        log('[list_gen] channels() returned empty list')
    fav_ids = {f['id'] for f in get_favorites()}
    for href, name in chData:
        cid_m = re.search(r'id=(\d+)', href)
        cid = cid_m.group(1) if cid_m else ''
        fav_label = '★ Retirer des favoris' if cid in fav_ids else '☆ Ajouter aux favoris'
        ctx = [(fav_label, 'RunPlugin(%s)' % build_url({'mode': 'toggle_fav', 'cid': cid, 'name': name}))] if cid else []
        addDir(name, build_url({'mode': 'play', 'url': abs_url(href)}), False, context_menu=ctx)
    closeDir()

def channels():
    url = abs_url('24-7-channels.php')
    headers = {'Referer': get_active_base(), 'User-Agent': UA}

    try:
        resp = fetch_via_proxy(url, headers=headers)
    except Exception as e:
        log(f"[DADDYLIVE] channels(): request failed: {e}")
        return []

    card_rx = re.compile(
        r'<a\s+class="card"[^>]*?href="(?P<href>[^"]+)"[^>]*?data-title="(?P<data_title>[^"]*)"[^>]*>'
        r'.*?<div\s+class="card__title">\s*(?P<title>.*?)\s*</div>'
        r'.*?ID:\s*(?P<id>\d+)\s*</div>'
        r'.*?</a>',
        re.IGNORECASE | re.DOTALL
    )

    items = []
    for m in card_rx.finditer(resp):
        href_rel = m.group('href').strip()
        title_dom = html.unescape(m.group('title').strip())
        title_attr = html.unescape(m.group('data_title').strip())
        name = title_dom or title_attr

        is_adult = (
            '18+' in name.upper() or
            'XXX' in name.upper() or
            name.strip().startswith('18+')
        )

        if is_adult:
            continue

        name = re.sub(r'^\s*\d+(?=[A-Za-z])', '', name).strip()
        items.append([href_rel, name])

    return items

def show_adult():
    """Return True if adult content is enabled in settings"""
    return addon.getSettingBool('show_adult')

def _probe_hls_url(url):
    """Quick check: returns True if URL responds with valid HLS content."""
    try:
        r = requests.get(url, headers={'User-Agent': UA}, timeout=5, stream=True)
        if r.status_code != 200:
            return False
        chunk = next(r.iter_content(512), b'')
        r.close()
        # HTML page = CDN down; real HLS starts with #EXTM3U
        if chunk[:5] in (b'<!DOC', b'<html', b'<!doc'):
            return False
        if b'#EXTM3U' in chunk:
            return True
        # Some proxies return binary content without #EXTM3U header in first chunk
        return len(chunk) > 0 and b'<' not in chunk[:20]
    except Exception:
        return False


def get_player6_stream(channel_id):
    """Fetch fallback stream URL from Player 6 (tv-bu1.blogspot.com).
    Returns a direct HLS URL or None if unavailable."""
    try:
        blogspot_url = f'https://tv-bu1.blogspot.com/p/e1.html?id={channel_id}a'
        log(f'[Player6] Fetching: {blogspot_url}')
        r = requests.get(blogspot_url, headers={'User-Agent': UA}, timeout=10)
        if r.status_code != 200:
            log(f'[Player6] HTTP {r.status_code}')
            return None
        html_page = r.text

        # Find the iframe src injected for this channel id
        m = re.search(
            r'id\s*===\s*"' + re.escape(str(channel_id)) + r'a"[^<]{0,600}'
            r'<iframe[^>]+src="([^"]+)"',
            html_page, re.DOTALL
        )
        if not m:
            log(f'[Player6] No entry for channel {channel_id}a')
            return None

        iframe_src = m.group(1)
        log(f'[Player6] iframe src: {iframe_src}')

        # Case 1: r-strm.blogspot.com with ?s=<direct_url> parameter
        ms = re.search(r'[?&]s=(https?://[^&"\'>\s]+)', iframe_src)
        if ms:
            stream_url = ms.group(1)
            log(f'[Player6] Direct URL from ?s= param: {stream_url}')
            return stream_url

        # Case 2: hoofoot.ru — JW Player page with file: "..." URL
        if 'hoofoot.ru' in iframe_src:
            r2 = requests.get(iframe_src, headers={'User-Agent': UA}, timeout=8)
            mf = re.search(r'["\']?file["\']?\s*:\s*["\']([^"\']+)["\']', r2.text)
            if mf:
                stream_url = mf.group(1)
                log(f'[Player6] hoofoot.ru stream: {stream_url}')
                return stream_url

        # Case 3: r-strm.blogspot.com sub-page — fetch and extract JW Player or iframe
        if 'r-strm.blogspot.com' in iframe_src:
            r2 = requests.get(iframe_src, headers={'User-Agent': UA}, timeout=8)
            # JW Player file
            mf = re.search(r'["\']?file["\']?\s*:\s*["\']([^"\']+)["\']', r2.text)
            if mf:
                return mf.group(1)
            # Inner iframe with ?s= param
            mi = re.search(r'<iframe[^>]+src="([^"]*[?&]s=https?://[^"]+)"', r2.text)
            if mi:
                ms2 = re.search(r'[?&]s=(https?://[^&"\'>\s]+)', mi.group(1))
                if ms2:
                    return ms2.group(1)

        log(f'[Player6] Could not extract direct URL from {iframe_src}')
        return None

    except Exception as e:
        log(f'[Player6] Error for channel {channel_id}: {e}')
        return None


def get_stream_page_url(channel_id):
    """For channels not in the chevy CDN, extract m3u8 via stellarthread player chain.
    Chain: stream-{id}.php → wikisport.club/court/{fid} → stellarthread.com/wiki.php?live={fid}
    The md5 token in the URL is IP-based, so it will work from Kodi (same IP as this request).
    """
    try:
        watch_url = abs_url(f'watch.php?id={channel_id}')
        stream_url_page = abs_url(f'stream/stream-{channel_id}.php')

        # Step 1: fetch the stream page with the correct Referer
        r = requests.get(stream_url_page, headers={
            'User-Agent': UA,
            'Referer': watch_url,
        }, timeout=12)
        if r.status_code != 200:
            log(f'[StreamPage] stream page HTTP {r.status_code} for id={channel_id}')
            return None

        # Step 2: find wikisport.club iframe src
        mw = re.search(r'src="(https://wikisport\.club/[^"]+)"', r.text)
        if not mw:
            log(f'[StreamPage] no wikisport iframe for id={channel_id}')
            return None
        wikisport_url = mw.group(1)

        # Step 3: fetch wikisport page to get fid
        r2 = requests.get(wikisport_url, headers={
            'User-Agent': UA,
            'Referer': stream_url_page,
        }, timeout=8)
        mf = re.search(r'fid\s*=\s*"([^"]+)"', r2.text)
        if not mf:
            log(f'[StreamPage] no fid in wikisport page')
            return None
        fid = mf.group(1)

        # Step 4: fetch stellarthread wiki.php to get the URL
        stellar_url = f'https://stellarthread.com/wiki.php?player=desktop&live={fid}'
        r3 = requests.get(stellar_url, headers={
            'User-Agent': UA,
            'Referer': wikisport_url,
        }, timeout=8)
        if r3.status_code != 200:
            log(f'[StreamPage] stellarthread HTTP {r3.status_code}')
            return None

        # Step 5: extract URL from char array in ettgHtplrU() function
        m3 = re.search(r'return\(\[(.+?)\]\.join\(', r3.text)
        if not m3:
            log(f'[StreamPage] no char array found in stellarthread page')
            return None
        chars = re.findall(r'"(.*?)"', m3.group(1))
        m3u8_url = ''.join(chars).replace('\\/', '/')

        if 'm3u8' in m3u8_url and m3u8_url.startswith('https://'):
            log(f'[StreamPage] Got URL for channel {channel_id}: {m3u8_url[:70]}')
            return m3u8_url
        return None
    except Exception as e:
        log(f'[StreamPage] Error for channel {channel_id}: {e}')
        return None


def resolve_stream_url(channel_id):
    channel_key = f'premium{channel_id}'
    try:
        resp = requests.get(
            f'{CHEVY_LOOKUP}/server_lookup?channel_id={channel_key}',
            headers={'User-Agent': UA, 'Referer': PLAYER_REFERER},
            timeout=10
        )
        server_key = resp.json().get('server_key', 'zeko')
    except Exception as e:
        log(f'[resolve_stream_url] server_lookup failed: {e}')
        server_key = 'zeko'
    if server_key == 'top1/cdn':
        return f'{CHEVY_PROXY}/proxy/top1/cdn/{channel_key}/mono.css'
    return f'{CHEVY_PROXY}/proxy/{server_key}/{channel_key}/mono.css'

def PlayStream(link):
    try:
        log(f'[PlayStream] Starting: {link}')

        parsed = urlparse(link)
        qs = dict(parse_qsl(parsed.query))
        channel_id = qs.get('id', '').split('|')[0].strip()

        if not channel_id:
            log('[PlayStream] No channel ID found')
            return

        log(f'[PlayStream] Channel ID: {channel_id}')
        channel_key = f'premium{channel_id}'

        # Resolve primary m3u8 URL from DaddyLive CDN
        real_m3u8_url = resolve_stream_url(channel_id)
        log(f'[PlayStream] Primary M3U8 URL: {real_m3u8_url}')

        # Probe primary CDN — if it's down (returns HTML), try Player 6 fallback
        use_player6 = False
        if not _probe_hls_url(real_m3u8_url):
            log('[PlayStream] Primary CDN probe failed, trying Player 6 fallback')
            player6_url = get_player6_stream(channel_id)
            if player6_url:
                log(f'[PlayStream] Player 6 fallback URL: {player6_url}')
                real_m3u8_url = player6_url
                use_player6 = True
            else:
                log('[PlayStream] Player 6 unavailable, trying stream page fallback')
                sp_url = get_stream_page_url(channel_id)
                if sp_url:
                    log(f'[PlayStream] Stream page fallback URL: {sp_url[:70]}')
                    real_m3u8_url = sp_url
                    use_player6 = True
                else:
                    log('[PlayStream] All fallbacks failed, using primary CDN anyway')

        if use_player6:
            # stellarthread/sanwalyaarpya streams require Origin header — proxy via /raw/
            if 'sanwalyaarpya.com' in real_m3u8_url:
                _ensure_m3u8_proxy()
                encoded_origin = quote_plus('https://stellarthread.com')
                encoded_url = quote_plus(real_m3u8_url)
                m3u8_url = f'http://127.0.0.1:{M3U8_PROXY_PORT}/raw/{encoded_origin}/{encoded_url}'
                log(f'[PlayStream] Using raw proxy for stellarthread stream')
            else:
                m3u8_url = real_m3u8_url
            log('[PlayStream] Using Player 6 stream directly')
        else:
            # Fetch fresh auth credentials from the DaddyLive player page
            auth_token, channel_salt = _fetch_auth_credentials(channel_id)
            if auth_token and channel_salt:
                log(f'[PlayStream] Got auth credentials for {channel_key}')
                _set_channel_state(channel_key, auth_token, channel_salt, real_m3u8_url)
                _ensure_m3u8_proxy()
                m3u8_url = f'http://127.0.0.1:{M3U8_PROXY_PORT}/m3u8/{channel_key}'
                log(f'[PlayStream] Using auth proxy: {m3u8_url}')
            else:
                log('[PlayStream] Auth credentials unavailable, falling back to direct URL')
                m3u8_url = real_m3u8_url

        liz = xbmcgui.ListItem(f'Channel {channel_id}', path=m3u8_url)
        liz.setContentLookup(False)
        liz.setProperty('inputstream', 'inputstream.ffmpegdirect')
        liz.setProperty('inputstream.ffmpegdirect.manifest_type', 'hls')
        liz.setProperty('inputstream.ffmpegdirect.is_realtime_stream', 'true')
        liz.setProperty('IsPlayable', 'true')

        xbmcplugin.setResolvedUrl(addon_handle, True, liz)
        log(f'[PlayStream] Stream started ({"Player6" if use_player6 else "primary CDN"})')

    except Exception as e:
        log(f'[PlayStream] Error: {e}')

def Search_Events():
    keyboard = xbmcgui.Dialog().input("Enter search term", type=xbmcgui.INPUT_ALPHANUM)
    if not keyboard or keyboard.strip() == '':
        return
    term = keyboard.lower().strip()

    try:
        html_text = fetch_via_proxy(abs_url('index.php'), headers={'User-Agent': UA, 'Referer': get_active_base()})
        events = re.findall(
            r"<div\s+class=\"schedule__event\">.*?"
            r"<div\s+class=\"schedule__eventHeader\"[^>]*?>\s*"
            r"(?:<[^>]+>)*?"
            r"<span\s+class=\"schedule__time\"[^>]*data-time=\"([^\"]+)\"[^>]*>.*?</span>\s*"
            r"<span\s+class=\"schedule__eventTitle\">\s*([^<]+)\s*</span>.*?"
            r"</div>\s*"
            r"<div\s+class=\"schedule__channels\">(.*?)</div>",
            html_text, re.IGNORECASE | re.DOTALL
        )

        rows = {}
        seen = set()
        for time_str, raw_title, channels_block in events:
            title_clean = html.unescape(raw_title.strip())
            if term not in title_clean.lower():
                continue
            if title_clean in seen:
                continue
            seen.add(title_clean)
            event_time_local = get_local_time(time_str.strip())
            rows[title_clean] = channels_block

        for title, chblock in rows.items():
            links = []
            for href, title_attr, link_text in re.findall(
                r'<a[^>]+href="([^"]+)"[^>]*title="([^"]*)".*?>(.*?)</a>', 
                chblock, re.IGNORECASE | re.DOTALL
            ):
                name = html.unescape(title_attr or link_text)
                links.append({'channel_name': name, 'channel_id': href})
            addDir(title, build_url({'mode': 'trLinks', 'trData': json.dumps({'channels': links})}), False)

        closeDir()
    except Exception as e:
        log(f'Search_Events error: {e}')

def Search_Channels():
    keyboard = xbmcgui.Dialog().input("Enter channel name", type=xbmcgui.INPUT_ALPHANUM)
    if not keyboard or keyboard.strip() == '':
        return
    term = keyboard.lower().strip()
    chData = channels()
    for href, title in chData:
        if term in title.lower():
            addDir(title, build_url({'mode': 'play', 'url': abs_url(href)}), False)
    closeDir()

def load_extra_channels(force_reload=False):
    global EXTRA_CHANNELS_DATA
    CACHE_EXPIRY = 24 * 60 * 60

    saved = addon.getSetting('extra_channels_cache')
    if saved and not force_reload:
        try:
            saved_data = json.loads(saved)
            if time.time() - saved_data.get('timestamp', 0) < CACHE_EXPIRY:
                EXTRA_CHANNELS_DATA = saved_data.get('channels', {})
                if EXTRA_CHANNELS_DATA:
                    return EXTRA_CHANNELS_DATA
        except:
            pass

    try:
        resp = requests.get(EXTRA_M3U8_URL, headers={'User-Agent': UA}, timeout=10).text
    except Exception as e:
        xbmcgui.Dialog().ok("Error", f"Failed to fetch extra channels: {e}")
        return {}

    categories = {}
    lines = resp.splitlines()

    for i, line in enumerate(lines):
        if not line.startswith('#EXTINF:'):
            continue

        title_match = re.search(r',(.+)$', line)
        cat_match = re.search(r'group-title="([^"]+)"', line)
        logo_match = re.search(r'tvg-logo="([^"]+)"', line)

        if not title_match:
            continue

        title = title_match.group(1).strip()
        category = cat_match.group(1).strip() if cat_match else 'Uncategorized'
        logo = logo_match.group(1) if logo_match else ICON

        is_adult = (
            '18+' in category.upper() or
            'XXX' in category.upper() or
            '18+' in title.upper() or
            'XXX' in title.upper()
        )

        if is_adult:
            continue

        stream_url = lines[i + 1].strip() if i + 1 < len(lines) else ''
        if not stream_url:
            continue

        categories.setdefault(category, []).append({
            'title': title,
            'url': stream_url,
            'logo': logo
        })

    EXTRA_CHANNELS_DATA = categories

    addon.setSetting(
        'extra_channels_cache',
        json.dumps({'timestamp': int(time.time()), 'channels': EXTRA_CHANNELS_DATA})
    )

    return EXTRA_CHANNELS_DATA

def ExtraChannels_Main():
    global EXTRA_CHANNELS_DATA
    if not EXTRA_CHANNELS_DATA:
        load_extra_channels() 
        if not EXTRA_CHANNELS_DATA:
            xbmcgui.Dialog().ok("Error", "Extra channels could not be loaded.")
            return

    addDir('[B][COLOR gold]Search Extra Channels / VODs[/COLOR][/B]',
           build_url({'mode': 'extra_search'}), True)

    for cat in sorted(EXTRA_CHANNELS_DATA.keys()):
        is_adult_cat = (
            '18+' in cat.upper() or
            'XXX' in cat.upper()
        )

        if is_adult_cat:
            continue
    
        addDir(cat, build_url({'mode': 'extra_list', 'category': cat}), True, logo="https://images-ext-1.discordapp.net/external/fUzDq2SD022-veHyDJTHKdYTBzD9371EnrUscXXrf0c/%3Fsize%3D4096/https/cdn.discordapp.com/icons/1373713080206495756/1fe97e658bc7fb0e8b9b6df62259c148.png?format=webp&quality=lossless")

    
    closeDir()



def ExtraChannels_Search():
    """
    Open a dialog to search for a channel or VOD in the extra list.
    """
    keyboard = xbmcgui.Dialog().input("Search Extra Channels / VODs", type=xbmcgui.INPUT_ALPHANUM)
    if not keyboard or keyboard.strip() == '':
        return
    search_term = keyboard.strip()
    ExtraChannels_List(None, search_term) 


def ExtraChannels_List(category=None, search=None):
    """
    List ExtraChannels, optionally filtering by category or search term,
    enforcing adult access where needed.
    """
    global EXTRA_CHANNELS_DATA
    if not EXTRA_CHANNELS_DATA:
        load_extra_channels()  
        if not EXTRA_CHANNELS_DATA:
            xbmcgui.Dialog().ok("Error", "Extra channels could not be loaded.")
            return

    items_to_show = []

    for cat, streams in EXTRA_CHANNELS_DATA.items():
        if category and cat != category:
            continue

        is_adult_cat = (
            '18+' in cat.upper() or
            'XXX' in cat.upper()
        )
        if is_adult_cat:
            continue

        for item in streams:
            if category and cat != category:
                continue
            if search and search.lower() not in item['title'].lower():
                continue

            is_adult = (
                '18+' in item['title'].upper() or
                'XXX' in item['title'].upper()
            )
            if is_adult:
                continue

            items_to_show.append({
                'title': item['title'],
                'url': item['url'],
                'logo': item.get('logo', ICON)
            })

    for item in items_to_show:
        addDir(
            item['title'],
            build_url({'mode': 'extra_play', 'url': item['url'], 'logo': item.get('logo', ICON), 'name': item['title']}),
            False,
            logo=item.get('logo', ICON)
        )

    closeDir()


def ExtraChannels_Play(url, name='Extra Channel', logo=ICON):
    """
    Play a channel or VOD from ExtraChannels, enforcing adult access.
    """
    try:

        log(f'[ExtraChannels_Play] Original URL: {url}')

        if 'a1xmedia' in url.lower() or 'a1xs.vip' in url.lower():
            headers = {
                'User-Agent': UA,
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': 'https://a1xs.vip/'
            }
            try:
                response = requests.head(url, headers=headers, allow_redirects=True, timeout=10)
                url = response.url
                log(f'[ExtraChannels_Play] Resolved A1XMedia URL: {url}')
            except Exception as e:
                log(f'[ExtraChannels_Play] Failed to resolve A1XMedia URL, using original: {e}')

        elif 'daddylive' in url.lower() or 'dlhd' in url.lower():
            parsed_url = urlparse(url)
            qs_url = dict(parse_qsl(parsed_url.query))
            channel_id = qs_url.get('id', '').split('|')[0].strip()
            if not channel_id:
                m = re.search(r'(?:id=|premium)(\d+)', url)
                if m:
                    channel_id = m.group(1)
            if channel_id:
                PlayStream(abs_url('watch.php?id=' + channel_id))
                return
            log(f'[ExtraChannels_Play] Could not extract channel ID from: {url}')

        logo = logo or ICON
        liz = xbmcgui.ListItem(name, path=url)
        liz.setArt({'thumb': logo, 'icon': logo, 'fanart': FANART})
        liz.setInfo('video', {'title': name, 'plot': name})

        if '.m3u8' in url.lower():
            liz.setProperty('inputstream', 'inputstream.adaptive')
            liz.setProperty('inputstream.adaptive.manifest_type', 'hls')
            liz.setMimeType('application/vnd.apple.mpegurl')
            log('[ExtraChannels_Play] HLS stream detected')
        elif url.lower().endswith('.mp4'):
            liz.setMimeType('video/mp4')
            log('[ExtraChannels_Play] MP4 stream detected')
        else:
            liz.setMimeType('video')
            log('[ExtraChannels_Play] Generic video stream')

        liz.setProperty('IsPlayable', 'true')
        xbmcplugin.setResolvedUrl(addon_handle, True, liz)
        log(f'[ExtraChannels_Play] Stream started for: {name}')

    except Exception as e:
        log(f'[ExtraChannels_Play] Error: {e}')
        import traceback
        log(f'Traceback: {traceback.format_exc()}')
        xbmcgui.Dialog().notification("Daddylive", "Failed to play channel", ICON, 3000)

def refresh_active_base():
    new_base = resolve_active_baseurl(SEED_BASEURL)
    set_active_base(new_base)
    xbmcgui.Dialog().ok("Daddylive", f"Active base set to:\n{new_base}")
    xbmc.executebuiltin('Container.Refresh')


if not params.get('mode'): 
    load_extra_channels()
    Main_Menu()
else:
    mode = params.get('mode')

    if mode == 'menu':
        servType = params.get('serv_type')
        if servType == 'sched':
            Menu_Trans()
        elif servType == 'live_tv':
            list_gen()
        elif servType == 'favorites':
            list_favorites()
        elif servType == 'extra_channels':
            ExtraChannels_Main()
        elif servType == 'search':
            Search_Events()
        elif servType == 'search_channels':
            Search_Channels()
        elif servType == 'refresh_sched':
            xbmc.executebuiltin('Container.Refresh')
        elif servType == 'diagnostics':
            run_diagnostics()
        elif servType == 'chat':
            import webbrowser
            webbrowser.open('https://daddylivehd.chatango.com/')

    elif mode == 'showChannels':
        transType = params.get('trType')
        channels_list = getTransData(transType)
        ShowChannels(transType, channels_list)

    elif mode == 'trList':
        transType = params.get('trType')
        channels_list = json.loads(params.get('channels'))
        TransList(transType, channels_list)

    elif mode == 'trLinks':
        trData = params.get('trData')
        getSource(trData)

    elif mode == 'play':
        link = params.get('url')
        PlayStream(link)

    elif mode == 'resolve_base_now':
        refresh_active_base()

    elif mode == 'diagnostics':
        run_diagnostics()

    elif mode == 'toggle_fav':
        toggle_favorite(params.get('cid', ''), params.get('name', ''))

    elif mode == 'extra_channels':
        ExtraChannels_Main()

    elif mode == 'extra_search':
        ExtraChannels_Search()

    elif mode == 'extra_list':  
        cat = params.get('category')
        search_term = params.get('search')
        ExtraChannels_List(cat, search_term)

    elif mode == 'extra_play':
        url = params.get('url')
        logo = params.get('logo', ICON)
        name = params.get('name', 'Extra Channel')
        ExtraChannels_Play(url, name=name, logo=logo)

