# -*- coding: utf-8 -*-
"""
IPTV / HLS restream proxy.

Логика работы:
  GET /<key>/            -> тянем исходный плейлист provider[key], переписываем
                             ВСЕ ссылки внутри (сегменты, вложенные m3u8,
                             EXT-X-KEY, EXT-X-MAP, EXT-X-MEDIA и т.п.) так,
                             чтобы они указывали на наш прокси, и отдаём клиенту.

  GET /<key>/res/<token> -> прокси произвольного ресурса (сегмент .ts/.m4s,
                             ключ шифрования, вложенный вариант-плейлист).
                             <token> - это base64url от исходного абсолютного
                             URL. Если это плейлист (по расширению .m3u8/.m3u
                             либо по Content-Type) - он тоже рекурсивно
                             переписывается, иначе байты стримятся как есть.

Управление пользователями не реализуется, как и было указано в задаче.
"""

import asyncio
import base64
import logging
import os
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import web

import config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
log = logging.getLogger('iptv-proxy')

# Порт можно переопределить переменной окружения IPTV_PROXY_PORT - это
# нужно для docker-compose, где порт должен быть ОДНИМ значением сразу
# в трёх местах: bind-порт сервера внутри контейнера, порт, зашитый в
# ссылки, отдаваемые клиентам (host_name:port), и опубликованный наружу
# порт контейнера. Если переменная не задана - используется config.port,
# как и раньше (обычный запуск без Docker).
PORT = int(os.environ.get('IPTV_PROXY_PORT', config.port))

SCHEME = getattr(config, 'scheme', 'http')
USER_AGENT = getattr(config, 'user_agent', 'Mozilla/5.0 (IPTV-Proxy)')
CONNECT_TIMEOUT = getattr(config, 'connect_timeout', 10)
READ_TIMEOUT = getattr(config, 'read_timeout', 30)

CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
}

# Ловим URI="..." внутри тегов #EXT-X-KEY, #EXT-X-MAP, #EXT-X-MEDIA,
# #EXT-X-I-FRAME-STREAM-INF и т.д.
URI_ATTR_RE = re.compile(r'URI="([^"]+)"')

# Теги, которые встречаются ТОЛЬКО в настоящих HLS-плейлистах (медиа- или
# мастер-), но не в обычном M3U-списке каналов (где просто #EXTINF + ссылка
# на ДРУГОЙ .m3u8/поток для каждого канала). Раньше сервер всегда отдавал
# Content-Type: application/vnd.apple.mpegurl - этот тип явно говорит
# плееру "это живой HLS-поток, разбирай как HLS". Для списка каналов это
# неверно: плеер (например VLC) пытается скормить список HLS-демуксеру,
# который ждёт #EXT-X-TARGETDURATION/#EXT-X-STREAM-INF, не находит их и не
# может воспроизвести - хотя HTTP-ответ при этом абсолютно корректен.
HLS_TAG_RE = re.compile(
    r'^#EXT-X-(?:TARGETDURATION|STREAM-INF|MEDIA-SEQUENCE|VERSION|DISCONTINUITY|ENDLIST)\b',
    re.MULTILINE,
)


def playlist_content_type(text: str) -> str:
    """application/vnd.apple.mpegurl - для настоящего HLS (сегменты/варианты),
    audio/x-mpegurl - для обычного M3U-списка каналов (плейлиста ссылок)."""
    if HLS_TAG_RE.search(text):
        return 'application/vnd.apple.mpegurl'
    return 'audio/x-mpegurl'


# --------------------------------------------------------------------------
# Конфигурация провайдеров
# --------------------------------------------------------------------------

def get_provider_entry(key):
    """Возвращает (url, extra_headers) для ключа провайдера или (None, None)."""
    entry = config.provider.get(key)
    if entry is None:
        return None, None
    if isinstance(entry, dict):
        return entry.get('url'), entry.get('headers') or {}
    return entry, {}


# --------------------------------------------------------------------------
# Кодирование/декодирование целевых URL в безопасный для пути токен
# --------------------------------------------------------------------------

def encode_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode('utf-8')).decode('ascii').rstrip('=')


def decode_url(token: str) -> str:
    padding = '=' * (-len(token) % 4)
    return base64.urlsafe_b64decode((token + padding).encode('ascii')).decode('utf-8')


def base_url_of(url: str) -> str:
    """Базовый URL (без имени файла) - для резолва относительных ссылок."""
    parsed = urlparse(url)
    path = parsed.path.rsplit('/', 1)[0] + '/'
    return f'{parsed.scheme}://{parsed.netloc}{path}'


def proxy_root_for(key: str) -> str:
    return f'{SCHEME}://{config.host_name}:{PORT}/{key}'


def make_proxy_url(proxy_root: str, abs_url: str) -> str:
    """Строит ссылку вида {proxy_root}/res/<token>.<ext>."""
    parsed = urlparse(abs_url)
    last_seg = parsed.path.rsplit('/', 1)[-1]
    ext = last_seg.rsplit('.', 1)[-1].lower() if '.' in last_seg else ''
    token = encode_url(abs_url)
    if ext and ext.isalnum() and len(ext) <= 6:
        return f'{proxy_root}/res/{token}.{ext}'
    return f'{proxy_root}/res/{token}'


# --------------------------------------------------------------------------
# Перезапись плейлиста
# --------------------------------------------------------------------------

def rewrite_playlist(text: str, source_url: str, key: str) -> str:
    """Переписывает все ссылки в m3u8 (сегменты, вложенные плейлисты,
    URI="..." атрибуты тегов) на ссылки нашего прокси."""
    base = base_url_of(source_url)
    proxy_root = proxy_root_for(key)

    def repl_attr(m):
        orig = m.group(1)
        abs_u = urljoin(base, orig)
        return f'URI="{make_proxy_url(proxy_root, abs_u)}"'

    out_lines = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip('\r')
        stripped = line.strip()
        if not stripped:
            out_lines.append('')
            continue
        if stripped.startswith('#'):
            line = URI_ATTR_RE.sub(repl_attr, line)
            out_lines.append(line)
        else:
            # Обычная строка без # - это URI сегмента или вложенного плейлиста
            abs_u = urljoin(base, stripped)
            out_lines.append(make_proxy_url(proxy_root, abs_u))
    return '\n'.join(out_lines) + '\n'


# --------------------------------------------------------------------------
# Запрос к провайдеру и отдача клиенту
# --------------------------------------------------------------------------

def build_upstream_headers(request: web.Request, extra: dict) -> dict:
    headers = {'User-Agent': USER_AGENT}
    if extra:
        headers.update(extra)
    rng = request.headers.get('Range')
    if rng:
        headers['Range'] = rng
    return headers


async def fetch_and_respond(request, key, target_url, force_playlist, extra_headers):
    session: aiohttp.ClientSession = request.app['session']
    headers = build_upstream_headers(request, extra_headers)
    timeout = aiohttp.ClientTimeout(
        total=None, sock_connect=CONNECT_TIMEOUT, sock_read=READ_TIMEOUT
    )

    try:
        upstream = await session.get(target_url, headers=headers, timeout=timeout)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        log.warning('Upstream fetch failed for %s: %s', target_url, e)
        return web.Response(status=502, text='Upstream error', headers=CORS_HEADERS)

    async with upstream:
        content_type = upstream.headers.get('Content-Type', '')
        likely_playlist = force_playlist or 'mpegurl' in content_type.lower()

        if likely_playlist:
            # Плейлисты - маленькие файлы (килобайты), поэтому безопасно
            # прочитать начало ответа и убедиться, что это ДЕЙСТВИТЕЛЬНО
            # m3u8 (первая значимая строка должна быть #EXTM3U), а не что-то
            # другое, что провайдер вернул вместо ожидаемого плейлиста.
            try:
                head = await upstream.content.read(1 << 20)  # до 1 МБ на всякий случай
            except Exception as e:
                log.warning('Failed reading response body from %s: %s', target_url, e)
                return web.Response(status=502, text='Upstream error', headers=CORS_HEADERS)

            preview = head.decode('utf-8', errors='replace').lstrip('\ufeff \r\n\t')
            is_real_playlist = preview.startswith('#EXTM3U')

            if is_real_playlist:
                rest = b''
                if not upstream.content.at_eof():
                    rest = await upstream.content.read()
                text = (head + rest).decode('utf-8', errors='replace')

                if upstream.status >= 400:
                    return web.Response(
                        status=upstream.status, text=text or 'Upstream error', headers=CORS_HEADERS
                    )

                rewritten = rewrite_playlist(text, target_url, key)
                resp_headers = dict(CORS_HEADERS)
                resp_headers['Cache-Control'] = 'no-cache'
                return web.Response(
                    text=rewritten,
                    content_type=playlist_content_type(text),
                    charset='utf-8',
                    headers=resp_headers,
                )

            # Провайдер вернул НЕ m3u8 там, где мы его ждали.
            snippet_hex = head[:32].hex()
            log.warning(
                "Ожидался m3u8-плейлист, но ответ на него не похож: url=%s status=%s "
                "content-type=%r content-length=%r первые_байты(hex)=%s",
                target_url, upstream.status, content_type,
                upstream.headers.get('Content-Length'), snippet_hex,
            )

            if force_playlist:
                # Это был запрос корневого плейлиста канала (/<key>/) -
                # отдаём понятную диагностику вместо "мусора", чтобы было
                # ясно, что проблема на стороне провайдера/конфигурации,
                # а не в парсинге.
                diag = (
                    "Провайдер вернул НЕ HLS-плейлист там, где мы его ожидали.\n"
                    f"URL провайдера: {target_url}\n"
                    f"HTTP статус: {upstream.status}\n"
                    f"Content-Type: {content_type or '-'}\n"
                    f"Content-Length: {upstream.headers.get('Content-Length', '-')}\n"
                    f"Первые байты (hex): {snippet_hex}\n\n"
                    "Возможные причины: неверный URL в config.py, провайдер "
                    "требует другой User-Agent/Referer/токен, либо ссылка "
                    "ведёт на редирект/поток напрямую, а не на m3u8."
                )
                return web.Response(status=502, text=diag, headers=CORS_HEADERS)

            # Это был вложенный ресурс с расширением .m3u8/.m3u или
            # Content-Type mpegurl, но по факту это бинарные данные -
            # отдаём как есть, не пытаясь портить их декодированием в текст.
            resp = web.StreamResponse(status=upstream.status)
            for h in ('Content-Type', 'Content-Length', 'Content-Range', 'Accept-Ranges', 'Cache-Control'):
                if h in upstream.headers:
                    resp.headers[h] = upstream.headers[h]
            for k, v in CORS_HEADERS.items():
                resp.headers[k] = v
            await resp.prepare(request)
            await resp.write(head)
            try:
                async for chunk in upstream.content.iter_chunked(65536):
                    await resp.write(chunk)
            except (aiohttp.ClientError, ConnectionResetError):
                pass
            await resp.write_eof()
            return resp

        # Бинарный ресурс (сегмент .ts/.m4s/.aac, ключ шифрования и т.п.)
        # - стримим "на лету", не буферизируя целиком в память.
        resp = web.StreamResponse(status=upstream.status)
        for h in ('Content-Type', 'Content-Length', 'Content-Range', 'Accept-Ranges', 'Cache-Control'):
            if h in upstream.headers:
                resp.headers[h] = upstream.headers[h]
        for k, v in CORS_HEADERS.items():
            resp.headers[k] = v
        await resp.prepare(request)
        try:
            async for chunk in upstream.content.iter_chunked(65536):
                await resp.write(chunk)
        except (aiohttp.ClientError, ConnectionResetError):
            # клиент/провайдер обрубил соединение - это нормально для live
            pass
        await resp.write_eof()
        return resp


# --------------------------------------------------------------------------
# HTTP обработчики
# --------------------------------------------------------------------------

async def _serve_playlist(request: web.Request, key: str):
    target_url, extra_headers = get_provider_entry(key)
    if target_url is None:
        raise web.HTTPNotFound(text='Unknown provider key: %s' % key)
    return await fetch_and_respond(
        request, key, target_url, force_playlist=True, extra_headers=extra_headers
    )


async def handler_playlist(request: web.Request):
    return await _serve_playlist(request, request.match_info['key'])


async def handler_playlist_ext(request: web.Request):
    """Алиасы /<key>.m3u8, /<key>.m3u, /<key>/playlist.m3u8 - отдают тот же
    плейлист, что и /<key>/. Некоторые IPTV-приложения на Smart TV (в т.ч.
    Samsung Tizen: Smart IPTV, SS IPTV) жёстко требуют, чтобы адрес плейлиста
    заканчивался расширением .m3u/.m3u8, и не принимают адрес без него."""
    return await _serve_playlist(request, request.match_info['key'])


async def handler_resource(request: web.Request):
    key = request.match_info['key']
    if key not in config.provider:
        raise web.HTTPNotFound(text='Unknown provider key: %s' % key)
    _, extra_headers = get_provider_entry(key)

    raw = request.match_info['token']
    if '.' in raw:
        token, ext = raw.rsplit('.', 1)
    else:
        token, ext = raw, ''

    try:
        target_url = decode_url(token)
    except Exception:
        raise web.HTTPBadRequest(text='Malformed resource token')

    force_playlist = ext.lower() in ('m3u8', 'm3u')
    return await fetch_and_respond(
        request, key, target_url, force_playlist=force_playlist, extra_headers=extra_headers
    )


async def handler_redirect_to_slash(request: web.Request):
    key = request.match_info['key']
    raise web.HTTPFound(f'/{key}/')


async def handler_options(request: web.Request):
    return web.Response(status=204, headers=CORS_HEADERS)


async def handler_index(request: web.Request):
    """Небольшая служебная страница со списком доступных каналов."""
    lines = ['IPTV proxy is running.\n\nAvailable channels:\n']
    for k in config.provider:
        lines.append(f'  http://{config.host_name}:{PORT}/{k}/')
    return web.Response(text='\n'.join(lines), content_type='text/plain')


# --------------------------------------------------------------------------
# Приложение
# --------------------------------------------------------------------------

async def on_startup(app):
    app['session'] = aiohttp.ClientSession()
    log.info('IPTV proxy started on 0.0.0.0:%s', PORT)
    for k in config.provider:
        log.info("  channel '%s' -> %s://%s:%s/%s/", k, SCHEME, config.host_name, PORT, k)


async def on_cleanup(app):
    await app['session'].close()


def create_app() -> web.Application:
    if not getattr(config, 'provider', None):
        raise RuntimeError('config.provider is empty - nothing to serve')

    app = web.Application()
    app.router.add_route('OPTIONS', '/{tail:.*}', handler_options)
    app.router.add_get('/', handler_index)
    # Алиасы с расширением - должны быть зарегистрированы РАНЬШЕ общего
    # '/{key}', иначе тот перехватит их первым (например, ключ 'one.m3u8').
    app.router.add_get('/{key}.m3u8', handler_playlist_ext)
    app.router.add_get('/{key}.m3u', handler_playlist_ext)
    app.router.add_get('/{key}/playlist.m3u8', handler_playlist_ext)
    app.router.add_get('/{key}', handler_redirect_to_slash)
    app.router.add_get('/{key}/', handler_playlist)
    app.router.add_get('/{key}/res/{token}', handler_resource)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == '__main__':
    web.run_app(create_app(), host='0.0.0.0', port=PORT)
