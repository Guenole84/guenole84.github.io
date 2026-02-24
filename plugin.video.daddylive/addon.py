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
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, unquote, parse_qsl, quote_plus, urlparse, urljoin
from datetime import datetime, timezone
import time
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


def _fetch_auth_credentials(channel_id):
    """Fetch fresh authToken and channelSalt from the ksohls.ru player page."""
    url = f'https://www.ksohls.ru/premiumtv/daddyhd.php?id={channel_id}'
    try:
        r = requests.get(url, headers={
            'User-Agent': _AUTH_UA,
            'Referer': 'https://dlhd.link/',
        }, timeout=15)
        auth_m = re.search(r"authToken\s*:\s*'([^']+)'", r.text)
        salt_m = re.search(r"channelSalt\s*:\s*'([^']+)'", r.text)
        if auth_m and salt_m:
            return auth_m.group(1), salt_m.group(1)
        log('[EPlayerAuth] Credentials not found in player page')
    except Exception as e:
        log(f'[EPlayerAuth] fetch error: {e}')
    return None, None


def _set_channel_state(channel_key, auth_token, channel_salt, m3u8_url):
    with _proxy_lock:
        _channel_creds[channel_key] = {
            'auth_token': auth_token,
            'channel_salt': channel_salt,
            'm3u8_url': m3u8_url,
            'fetched_at': time.time(),
        }


def _get_channel_state(channel_key):
    with _proxy_lock:
        return dict(_channel_creds.get(channel_key, {}))


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
            content = None
            for attempt in range(4):
                r = requests.get(state['m3u8_url'], headers=m3u8_hdrs, timeout=10)
                candidate = r.text
                segs = [l.strip() for l in candidate.splitlines()
                        if l.strip() and not l.startswith('#')]
                if segs:
                    try:
                        sr = requests.head(segs[0], headers={'User-Agent': _AUTH_UA}, timeout=3)
                        seg_ok = sr.status_code == 200
                    except Exception:
                        seg_ok = False
                    seq_m = re.search(r'MEDIA-SEQUENCE:(\d+)', candidate)
                    seq = seq_m.group(1) if seq_m else '?'
                    log(f'[EPlayerProxy] m3u8 attempt={attempt} seq={seq} seg_ok={seg_ok}')
                    if seg_ok:
                        content = candidate
                        break
                if attempt < 3:
                    time.sleep(1)
            if content is None:
                content = r.text  # serve last fetch regardless
                log('[EPlayerProxy] m3u8 all retries had stale segments, serving anyway')

            port = M3U8_PROXY_PORT

            def _rewrite_key(mo):
                uri = mo.group(1)
                km = re.search(r'/key/[^/]+/(\d+)', uri)
                if km:
                    return f'URI="http://127.0.0.1:{port}/key/{channel_key}/{km.group(1)}"'
                return mo.group(0)

            content = re.sub(r'URI="([^"]+)"', _rewrite_key, content)
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
    try:
        if method.lower() == 'get':
            resp = requests.get(RAILWAY_PROXY, headers=headers, params={'url': url}, timeout=15)
        else:
            resp = requests.post(RAILWAY_PROXY, headers=headers, data={'url': url}, timeout=15)
        resp_text = resp.text
    except Exception as e:
        log(f"[fetch_via_proxy] Proxy fetch failed: {url} error={e}")

    if _is_error_response(resp_text):
        log(f"[fetch_via_proxy] Proxy unavailable, trying direct fetch for {url}")
        try:
            direct_hdrs = {k: v for k, v in headers.items() if k != 'X-API-Key'}
            resp_text = requests.get(url, headers=direct_hdrs, timeout=15).text
            log(f"[fetch_via_proxy] Direct fetch succeeded for {url}")
        except Exception as e:
            log(f"[fetch_via_proxy] Direct fetch failed: {url} error={e}")
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

def get_active_base():
    base = addon.getSetting('active_baseurl')
    if not base:
        base = resolve_active_baseurl(SEED_BASEURL)
        addon.setSetting('active_baseurl', base)
    if not base.endswith('/'):
        base += '/'
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
        utc_now = datetime.utcnow()
        event_time_utc = datetime.strptime(utc_time_str, '%H:%M')
        event_time_utc = event_time_utc.replace(year=utc_now.year, month=utc_now.month, day=utc_now.day)
        event_time_utc = event_time_utc.replace(tzinfo=timezone.utc)
        local_time = event_time_utc.astimezone()
        time_format_pref = addon.getSetting('time_format')
        if time_format_pref == '1':
            return local_time.strftime('%H:%M')
        else:
            return local_time.strftime('%I:%M %p').lstrip('0')
    except Exception as e:
        log(f"Failed to convert time: {e}")
        return utc_time_str or ''


def build_url(query):
    return addon_url + '?' + urlencode(query)

def addDir(title, dir_url, is_folder=True, logo=None):
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
        ['[B][COLOR gold]EXTRA CHANNELS / VODS[/COLOR][/B]', 'extra_channels',
         'https://images-ext-1.discordapp.net/external/fUzDq2SD022-veHyDJTHKdYTBzD9371EnrUscXXrf0c/%3Fsize%3D4096/https/cdn.discordapp.com/icons/1373713080206495756/1fe97e658bc7fb0e8b9b6df62259c148.png?format=webp&quality=lossless'],
        ['[B][COLOR gold]SEARCH EVENTS SCHEDULE[/COLOR][/B]', 'search', None],
        ['[B][COLOR gold]SEARCH LIVE TV CHANNELS[/COLOR][/B]', 'search_channels', None],
        ['[B][COLOR gold]REFRESH CATEGORIES[/COLOR][/B]', 'refresh_sched', None],
        ['[B][COLOR gold]SET ACTIVE DOMAIN (AUTO)[/COLOR][/B]', 'resolve_base_now', None],
    ]

    for title, mode_name, logo in menu:
        addDir(title, build_url({'mode': 'menu', 'serv_type': mode_name}), True, logo=logo)

    closeDir()

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

def list_gen():
    chData = channels()
    for c in chData:
        addDir(c[1], build_url({'mode': 'play', 'url': abs_url(c[0])}), False)
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

        # Resolve real m3u8 URL first
        real_m3u8_url = resolve_stream_url(channel_id)
        log(f'[PlayStream] Real M3U8 URL: {real_m3u8_url}')

        # Fetch fresh auth credentials from the player page
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
        log('[PlayStream] Stream started')

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
        elif servType == 'extra_channels':
            ExtraChannels_Main()
        elif servType == 'search':
            Search_Events()
        elif servType == 'search_channels':
            Search_Channels()
        elif servType == 'refresh_sched':
            xbmc.executebuiltin('Container.Refresh')

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

