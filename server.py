# -*- coding: utf-8 -*-
"""
IPTV / HLS restream proxy.

Логика работы:
  GET /<key>/            -> тянем исходный плейлист provider[key], переписываем
                             ВСЕ ссылки внутри (сегменты, вложенные m3u8,
                             EXT-X-KEY, EXT-X-MAP, EXT-X-MEDIA и т.п.) так,
                             чтобы они указывали на наш прокси, и отдаём клиенту.

  GET /<key>/res/<sig>/<token>
                          -> прокси произвольного ресурса (сегмент .ts/.m4s,
                             ключ шифрования, вложенный вариант-плейлист).
                             <token> - это base64url от исходного абсолютного
                             URL, <sig> - HMAC-подпись пары (<key>, URL), без
                             верной подписи запрос отклоняется (иначе прокси
                             можно было бы натравить на произвольный URL).
                             Если это плейлист (по расширению .m3u8/.m3u
                             либо по Content-Type) - он тоже рекурсивно
                             переписывается, иначе байты стримятся как есть.

Управление пользователями не реализуется, как и было указано в задаче.
"""

import asyncio
import base64
import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import ssl
import time
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import web
from aiohttp.abc import AbstractAccessLogger

import config
import providers_store

# Уровень логов из окружения (.env): INFO по умолчанию, DEBUG - в т.ч.
# строка access-лога на КАЖДЫЙ запрос (см. DebugAccessLogger ниже).
LOG_LEVEL = (os.environ.get('LOG_LEVEL') or 'INFO').upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
log = logging.getLogger('iptv-proxy')


class DebugAccessLogger(AbstractAccessLogger):
    """Access-лог aiohttp на уровне DEBUG вместо INFO. Строка пишется на
    каждый запрос, включая каждый сегмент .ts - на INFO это забивало лог.
    Значимые события (несуществующие ключи, админка, ошибки провайдера)
    пишутся отдельно, на WARNING. Referer/User-Agent через %r - в них может
    быть что угодно от клиента, в т.ч. переводы строк."""

    @property
    def enabled(self) -> bool:
        # aiohttp >= 3.10 не вызывает log() вовсе, если False.
        return self.logger.isEnabledFor(logging.DEBUG)

    def log(self, request, response, time):
        self.logger.debug(
            '%s "%s %s HTTP/%d.%d" %s %s %.3fs referer=%r ua=%r',
            request.remote, request.method, request.path_qs,
            request.version.major, request.version.minor,
            response.status, response.body_length, time,
            request.headers.get('Referer'), request.headers.get('User-Agent'),
        )

# Порт можно переопределить переменной окружения IPTV_PROXY_PORT - это
# нужно для docker-compose, где порт должен быть ОДНИМ значением сразу
# в трёх местах: bind-порт сервера внутри контейнера, порт, зашитый в
# ссылки, отдаваемые клиентам (host_name:port), и опубликованный наружу
# порт контейнера. Если переменная не задана - используется config.port,
# как и раньше (обычный запуск без Docker).
PORT = int(os.environ.get('IPTV_PROXY_PORT', config.port))

# Аналогично для host_name - тот же паттерн "одно значение из .env",
# удобно, когда домен/IP меняется в зависимости от окружения (staging/prod,
# смена хостинга и т.п.) без правки config.py на сервере.
# "or" вместо второго аргумента os.environ.get() - принципиально: в
# docker-compose переменная передаётся всегда (см. environment: в
# docker-compose.yml), и если в .env она не задана, внутрь контейнера
# попадёт ПУСТАЯ СТРОКА, а не отсутствующая переменная - .get(key, default)
# в этом случае вернул бы '', а не откатился на config.host_name.
HOST_NAME = os.environ.get('IPTV_PROXY_HOST_NAME') or config.host_name

# Базовая защита /admin/ - HTTP Basic Auth, без системы пользователей:
# один логин/пароль из окружения (.env). Если ADMIN_PASSWORD не задан -
# /admin/ ВЫКЛЮЧЕН (404), а не открыт без пароля (см. warning в on_startup).
ADMIN_USER = os.environ.get('ADMIN_USER') or 'admin'
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD') or ''

# Адрес панели управления: http://<host>:<port>/<ADMIN_PATH>/. Нестандартное
# значение прячет панель от сканеров, которые перебирают /admin/. Один
# сегмент пути (без "/"), он же зарезервирован - провайдера с таким ключом
# создать нельзя (его адреса перекрыла бы панель).
ADMIN_PATH = (os.environ.get('ADMIN_PATH') or 'admin').strip('/')
if not re.match(r'^[A-Za-z0-9_-]+$', ADMIN_PATH):
    raise SystemExit(
        f'ADMIN_PATH={ADMIN_PATH!r}: допустимы только латинские буквы, цифры, "-" и "_" '
        '(один сегмент пути, например ADMIN_PATH=panel-x7Gk2q)'
    )
ADMIN_PREFIX = f'/{ADMIN_PATH}'

# Доверять заголовкам nginx: IP клиента из X-Forwarded-For (последний адрес -
# тот, что дописал наш nginx), адрес для ссылок из X-Forwarded-Proto/Host
# (см. public_origin). Включать ТОЛЬКО если прокси доступен исключительно
# через nginx: при прямом доступе заголовки подделываются клиентом, и
# блокировку перебора пароля можно обойти. Без nginx/выключено - IP
# соединения и адрес из конфигурации.
TRUST_X_FORWARDED_FOR = getattr(config, 'trust_x_forwarded_for', False)

# Защита /admin/ от перебора пароля: после AUTH_MAX_FAILURES неверных
# попыток с одного IP за AUTH_WINDOW секунд этот IP получает 429 на
# AUTH_BLOCK секунд (даже с верным паролем).
AUTH_MAX_FAILURES = 10
AUTH_WINDOW = 600
AUTH_BLOCK = 900

SCHEME = getattr(config, 'scheme', 'http')
USER_AGENT = getattr(config, 'user_agent', 'Mozilla/5.0 (IPTV-Proxy)')
CONNECT_TIMEOUT = getattr(config, 'connect_timeout', 10)
READ_TIMEOUT = getattr(config, 'read_timeout', 30)

# SSL для провайдеров с verify_ssl=false (галочка "Не проверять SSL" в
# панели): сертификат не проверяется (самоподписанный, просроченный, на
# другой домен) и допускаются устаревшие TLS 1.0/1.1 и слабые шифры, которые
# OpenSSL 3 по умолчанию отвергает. Трафик по-прежнему шифруется, но
# подлинность сервера провайдера не проверяется.
INSECURE_SSL = ssl.create_default_context()
INSECURE_SSL.check_hostname = False
INSECURE_SSL.verify_mode = ssl.CERT_NONE
INSECURE_SSL.minimum_version = ssl.TLSVersion.TLSv1
INSECURE_SSL.set_ciphers('DEFAULT:@SECLEVEL=0')
INSECURE_SSL.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0)

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
#
# Список провайдеров больше не хранится в config.py - он живёт в
# providers_store (data/providers.json) и управляется через /admin/ или
# прямой правкой этого файла. config.py используется только один раз, как
# начальные данные при самом первом запуске (см. providers_store.load()).
# --------------------------------------------------------------------------

def get_provider_entry(key):
    """Возвращает (url, extra_headers) для ключа провайдера или (None, None)."""
    return providers_store.get(key)


def client_ip(request: web.Request) -> str:
    if TRUST_X_FORWARDED_FOR:
        forwarded = request.headers.get('X-Forwarded-For', '')
        last = forwarded.rsplit(',', 1)[-1].strip()
        if last:
            return last
    return request.remote or '-'


def client_desc(request: web.Request) -> str:
    """Кто обратился - для логов. Значения через %r: в них может быть что
    угодно от клиента, в т.ч. переводы строк (подделка строк лога)."""
    return 'ip=%s forwarded-for=%r ua=%r' % (
        request.remote, request.headers.get('X-Forwarded-For'),
        request.headers.get('User-Agent'),
    )


def require_provider(request: web.Request, key: str):
    """(url, extra_headers) для ключа; для несуществующего ключа - warning
    в лог и 404 без подробностей (не подтверждаем, какие ключи есть)."""
    url, extra_headers = get_provider_entry(key)
    if url is None:
        log.warning(
            'Обращение к несуществующему ключу %r: %s %r %s',
            key, request.method, request.path_qs, client_desc(request),
        )
        raise web.HTTPNotFound()
    return url, extra_headers


# --------------------------------------------------------------------------
# Кодирование/декодирование целевых URL в безопасный для пути токен
# --------------------------------------------------------------------------

def encode_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode('utf-8')).decode('ascii').rstrip('=')


def decode_url(token: str) -> str:
    padding = '=' * (-len(token) % 4)
    return base64.urlsafe_b64decode((token + padding).encode('ascii')).decode('utf-8')


# --------------------------------------------------------------------------
# Подпись ссылок /res/
#
# Без подписи /<key>/res/<token> можно было бы вызвать с base64 ЛЮБОГО URL
# и заставить прокси сходить куда угодно (в т.ч. во внутреннюю сеть), да
# ещё и с доп. заголовками провайдера. Поэтому каждая ссылка, которую
# прокси вписывает в плейлист, подписывается HMAC от (ключ провайдера, URL),
# а handler_resource принимает только ссылки с верной подписью.
#
# Секрет генерируется один раз и хранится в data/secret.key - он ОБЯЗАН
# переживать перезапуски: при смене секрета все ранее выданные ссылки
# (в т.ч. закэшированные IPTV-приложениями списки каналов) перестают
# работать до перезагрузки плейлиста в приложении.
# --------------------------------------------------------------------------

SECRET_FILE = os.path.join(providers_store.DATA_DIR, 'secret.key')
SIG_BYTES = 16

_signing_key = b''


def load_signing_key():
    global _signing_key
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, 'r', encoding='ascii') as f:
            _signing_key = bytes.fromhex(f.read().strip())
        return
    _signing_key = secrets.token_bytes(32)
    os.makedirs(providers_store.DATA_DIR, exist_ok=True)
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii') as f:
        f.write(_signing_key.hex())
    log.info('Создан новый секрет подписи ссылок: %s', SECRET_FILE)


def sign_url(key: str, url: str) -> str:
    msg = f'{key}\n{url}'.encode('utf-8')
    digest = hmac.new(_signing_key, msg, hashlib.sha256).digest()[:SIG_BYTES]
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')


def signature_ok(key: str, url: str, sig: str) -> bool:
    return hmac.compare_digest(sign_url(key, url), sig)


def base_url_of(url: str) -> str:
    """Базовый URL (без имени файла) - для резолва относительных ссылок."""
    parsed = urlparse(url)
    path = parsed.path.rsplit('/', 1)[0] + '/'
    return f'{parsed.scheme}://{parsed.netloc}{path}'


HOST_HEADER_RE = re.compile(r'^(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$')


def public_origin(request: web.Request) -> str:
    """Адрес прокси для ссылок в плейлисте: <схема>://<хост>[:<порт>].

    За nginx (trust_x_forwarded_for) - тот адрес, по которому клиент
    реально пришёл: схема из X-Forwarded-Proto, хост и порт из Host. Тогда
    http-клиент получает http-ссылки, https-клиент - https, и все запросы
    идут через nginx, а не напрямую на порт прокси. Иначе (и если заголовки
    странные) - из конфигурации: scheme, host_name, port."""
    if TRUST_X_FORWARDED_FOR:
        proto = request.headers.get('X-Forwarded-Proto', '').split(',', 1)[0].strip().lower()
        host = request.headers.get('Host', '').strip()
        if proto in ('http', 'https') and HOST_HEADER_RE.match(host):
            return f'{proto}://{host}'
    return f'{SCHEME}://{HOST_NAME}:{PORT}'


def make_proxy_url(origin: str, key: str, abs_url: str) -> str:
    """Строит ссылку вида {origin}/{key}/res/<sig>/<token>.<ext>."""
    parsed = urlparse(abs_url)
    last_seg = parsed.path.rsplit('/', 1)[-1]
    ext = last_seg.rsplit('.', 1)[-1].lower() if '.' in last_seg else ''
    token = encode_url(abs_url)
    prefix = f'{origin}/{key}/res/{sign_url(key, abs_url)}'
    if ext and ext.isalnum() and len(ext) <= 6:
        return f'{prefix}/{token}.{ext}'
    return f'{prefix}/{token}'


# --------------------------------------------------------------------------
# Перезапись плейлиста
# --------------------------------------------------------------------------

def rewrite_playlist(text: str, source_url: str, key: str, origin: str) -> str:
    """Переписывает все ссылки в m3u8 (сегменты, вложенные плейлисты,
    URI="..." атрибуты тегов) на ссылки нашего прокси."""
    base = base_url_of(source_url)

    def repl_attr(m):
        orig = m.group(1)
        abs_u = urljoin(base, orig)
        return f'URI="{make_proxy_url(origin, key, abs_u)}"'

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
            out_lines.append(make_proxy_url(origin, key, abs_u))
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

    ssl_ctx = True if providers_store.verify_ssl(key) else INSECURE_SSL

    try:
        upstream = await session.get(target_url, headers=headers, timeout=timeout, ssl=ssl_ctx)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        log.warning('Upstream fetch failed for %s: %s', target_url, e)
        if isinstance(e, aiohttp.ClientSSLError):
            log.warning("Ошибка SSL у провайдера %r - если провайдеру нельзя исправить "
                        "сертификат/TLS, включите для него \"Не проверять SSL\" в панели", key)
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

                # База для относительных ссылок - адрес, откуда плейлист
                # реально пришёл: aiohttp сам проходит редиректы, и после
                # редиректа на CDN/https сегменты лежат рядом с конечным
                # URL, а не с запрошенным.
                rewritten = rewrite_playlist(text, str(upstream.url), key, public_origin(request))
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
    target_url, extra_headers = require_provider(request, key)
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
    _, extra_headers = require_provider(request, key)

    raw = request.match_info['token']
    if '.' in raw:
        token, ext = raw.rsplit('.', 1)
    else:
        token, ext = raw, ''

    try:
        target_url = decode_url(token)
    except Exception:
        raise web.HTTPBadRequest(text='Malformed resource token')

    if not signature_ok(key, target_url, request.match_info['sig']):
        raise web.HTTPForbidden(text='Invalid resource signature')

    force_playlist = ext.lower() in ('m3u8', 'm3u')
    return await fetch_and_respond(
        request, key, target_url, force_playlist=force_playlist, extra_headers=extra_headers
    )


async def handler_resource_unsigned(request: web.Request):
    """Ссылки старого формата /<key>/res/<token> (до подписи) - их могли
    закэшировать IPTV-приложения, отвечаем понятной причиной вместо 405."""
    require_provider(request, request.match_info['key'])
    raise web.HTTPForbidden(text='Unsigned resource link: reload the playlist')


async def handler_redirect_to_slash(request: web.Request):
    key = request.match_info['key']
    require_provider(request, key)
    raise web.HTTPFound(f'/{key}/')


async def handler_not_found(request: web.Request):
    """Любой другой путь /<key>/... - 404. Для несуществующего ключа ещё и
    warning в лог (через require_provider); /<ADMIN_PATH>/... не логируем
    как "несуществующий ключ" - это панель управления, а не провайдер."""
    key = request.match_info['key']
    if key != ADMIN_PATH:
        require_provider(request, key)
    raise web.HTTPNotFound()


async def handler_admin_redirect_to_slash(request: web.Request):
    raise web.HTTPFound(f'{ADMIN_PREFIX}/')


async def handler_options(request: web.Request):
    return web.Response(status=204, headers=CORS_HEADERS)


async def handler_index(request: web.Request):
    """Корень ничего не раскрывает (ни список каналов, ни адрес панели) -
    иначе любой, кто наткнулся на порт, сразу видит все ключи провайдеров.
    Роут нужен явно: без него GET / получил бы 405 от OPTIONS catch-all."""
    raise web.HTTPForbidden()


# --------------------------------------------------------------------------
# Веб-интерфейс управления провайдерами (/<ADMIN_PATH>/, по умолчанию /admin/)
#
# Закрыт Basic Auth (см. admin_auth_middleware). Изменения применяются сразу
# же (пишутся в data/providers.json через providers_store).
# --------------------------------------------------------------------------

KEY_RE = re.compile(r'^[A-Za-z0-9_-]+$')


def _validate_key(key: str):
    if not key:
        return 'Ключ обязателен'
    if not KEY_RE.match(key):
        return 'Ключ может содержать только латинские буквы, цифры, "-" и "_"'
    if key == ADMIN_PATH:
        return f'Ключ "{key}" зарезервирован, выберите другой'
    return None


def _validate_url(url: str):
    if not url:
        return 'URL обязателен'
    if not (url.startswith('http://') or url.startswith('https://')):
        return 'URL должен начинаться с http:// или https://'
    return None


def _parse_headers(text: str):
    """Построчный разбор 'Имя: значение' -> (dict, error)."""
    headers = {}
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if ':' not in line:
            return None, f'Строка {i} заголовков не в формате "Имя: значение": {line!r}'
        name, value = line.split(':', 1)
        name = name.strip()
        value = value.strip()
        if not name:
            return None, f'Строка {i}: пустое имя заголовка'
        headers[name] = value
    return headers, None


def _headers_to_text(headers: dict) -> str:
    return '\n'.join(f'{k}: {v}' for k, v in (headers or {}).items())


def render_admin_page(providers, message=None, error=None,
                       form_key='', form_url='', form_headers_text='',
                       form_verify_ssl=True, original_key=''):
    """original_key - ключ редактируемой записи; пусто - форма добавления."""
    e = html.escape
    edit_mode = bool(original_key)
    rows = []
    for key in sorted(providers):
        entry = providers[key]
        n_headers = len(entry['headers'])
        headers_note = f'{n_headers} доп. заголовок(ов)' if n_headers else '-'
        ssl_note = '' if entry['verify_ssl'] else '<p class="hint">SSL не проверяется</p>'
        rows.append(f'''
        <tr>
          <td><code>{e(key)}</code></td>
          <td class="url-cell"><code>{e(entry['url'])}</code>{ssl_note}</td>
          <td>{headers_note}</td>
          <td class="actions">
            <a href="/{e(key)}/" target="_blank">Открыть</a>
            <a href="{e(ADMIN_PREFIX)}/edit/{e(key)}">Изменить</a>
            <form method="post" action="{e(ADMIN_PREFIX)}/delete/{e(key)}" class="inline">
              <button type="submit" class="danger">Удалить</button>
            </form>
          </td>
        </tr>''')

    rows_html = ''.join(rows) if rows else '<tr><td colspan="4"><em>Провайдеров пока нет</em></td></tr>'
    message_html = f'<p class="msg ok">{e(message)}</p>' if message else ''
    error_html = f'<p class="msg err">{e(error)}</p>' if error else ''
    form_title = 'Изменить провайдера' if edit_mode else 'Добавить провайдера'
    key_field = (
        f'<input type="text" id="key" name="key" value="{e(form_key)}" placeholder="one"'
        ' required pattern="[A-Za-z0-9_-]+">'
        '<button type="button" onclick="generateKey()">Сгенерировать</button>'
    )
    original_key_field = (
        f'<input type="hidden" name="original_key" value="{e(original_key)}">'
        '<p class="hint">При смене ключа старый адрес канала перестанет работать -'
        ' в IPTV-приложениях нужно будет указать новый.</p>'
        if edit_mode else ''
    )
    cancel_link = f'<a href="{e(ADMIN_PREFIX)}/">Отмена</a>' if edit_mode else ''

    return f'''<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>IPTV proxy - провайдеры</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2em auto; padding: 0 1em; color: #222; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2em; }}
  th, td {{ border: 1px solid #ccc; padding: 0.5em; text-align: left; vertical-align: top; }}
  .url-cell {{ max-width: 320px; overflow-wrap: anywhere; }}
  .actions a, .actions button {{ margin-right: 0.5em; }}
  form.inline {{ display: inline; }}
  button.danger {{ color: #b00020; }}
  label {{ display: block; margin-top: 0.75em; }}
  label.checkbox {{ font-weight: normal; }}
  input[type=text], textarea {{ width: 100%; box-sizing: border-box; padding: 0.4em; }}
  .key-row {{ display: flex; gap: 0.5em; }}
  .key-row input {{ flex: 1; font-family: monospace; }}
  .hint {{ margin: 0.3em 0 0; font-size: 0.9em; color: #666; }}
  textarea {{ height: 4em; font-family: monospace; }}
  .msg {{ padding: 0.6em 1em; border-radius: 4px; }}
  .msg.ok {{ background: #e6ffed; border: 1px solid #4caf50; }}
  .msg.err {{ background: #ffe8e8; border: 1px solid #d32f2f; }}
  code {{ word-break: break-all; }}
</style>
</head>
<body>
<h1>IPTV proxy - провайдеры</h1>
{message_html}{error_html}
<table>
  <thead><tr><th>Ключ</th><th>URL</th><th>Заголовки</th><th>Действия</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>

<h2>{form_title}</h2>
<form method="post" action="{e(ADMIN_PREFIX)}/save">
  <label for="key">Ключ (используется в адресе /&lt;ключ&gt;/)</label>
  <div class="key-row">{key_field}</div>
  {original_key_field}
  <label>URL плейлиста провайдера
    <input type="text" name="url" value="{e(form_url)}" placeholder="https://provide.one/list.m3u8" required>
  </label>
  <label class="checkbox"><input type="checkbox" name="insecure_ssl" value="1"{'' if form_verify_ssl else ' checked'}>
    Не проверять SSL-сертификат провайдера</label>
  <p class="hint">Только если провайдер отдаёт https с самоподписанным/просроченным
    сертификатом или устаревшим TLS и в логе ошибки SSL. Подлинность сервера
    провайдера при этом не проверяется.</p>
  <details>
    <summary>Дополнительные заголовки (опционально)</summary>
    <label>По одному заголовку на строку, формат "Имя: значение"
      <textarea name="headers">{e(form_headers_text)}</textarea>
    </label>
  </details>
  <p><button type="submit">Сохранить</button> {cancel_link}</p>
</form>
<script>
function generateKey() {{
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = '';
  while (key.length < 12) {{
    for (const b of crypto.getRandomValues(new Uint8Array(16))) {{
      // 248 = 62 * 4: байты >= 248 отбрасываем, иначе первые символы
      // алфавита выпадали бы чаще остальных.
      if (b < 248 && key.length < 12) key += alphabet[b % 62];
    }}
  }}
  document.getElementById('key').value = key;
}}
</script>
</body>
</html>
'''


async def handler_admin_index(request: web.Request):
    msg = request.query.get('msg')
    message = {'saved': 'Сохранено', 'deleted': 'Удалено'}.get(msg)
    body = render_admin_page(providers_store.list_all(), message=message)
    return web.Response(text=body, content_type='text/html')


async def handler_admin_edit(request: web.Request):
    key = request.match_info['key']
    url, headers = providers_store.get(key)
    if url is None:
        raise web.HTTPNotFound(text='Unknown provider key: %s' % key)
    body = render_admin_page(
        providers_store.list_all(),
        form_key=key, form_url=url, form_headers_text=_headers_to_text(headers),
        form_verify_ssl=providers_store.verify_ssl(key), original_key=key,
    )
    return web.Response(text=body, content_type='text/html')


async def handler_admin_save(request: web.Request):
    data = await request.post()
    key = (data.get('key') or '').strip()
    url = (data.get('url') or '').strip()
    headers_text = data.get('headers') or ''
    verify_ssl = not data.get('insecure_ssl')
    # Есть original_key - это форма редактирования (ключ мог поменяться),
    # нет - форма добавления.
    original_key = (data.get('original_key') or '').strip()

    existing = providers_store.list_all()
    if original_key and original_key not in existing:
        error = f'Провайдер "{original_key}" не найден - возможно, его уже удалили'
        original_key = ''
    elif key != original_key and key in existing:
        # И при добавлении, и при переименовании: не затираем молча
        # чужую запись с таким же ключом.
        error = f'Ключ "{key}" уже занят другим провайдером'
    else:
        # Неизменённый ключ не перепроверяем: правка URL записи со
        # "старым" ключом (например, из config.py) не должна блокироваться.
        error = _validate_key(key) if not original_key or key != original_key else None
    headers, headers_error = _parse_headers(headers_text)
    error = error or _validate_url(url) or headers_error

    if error:
        body = render_admin_page(
            existing, error=error,
            form_key=key, form_url=url, form_headers_text=headers_text,
            form_verify_ssl=verify_ssl, original_key=original_key,
        )
        return web.Response(text=body, content_type='text/html', status=400)

    # Значения заголовков не логируем - там бывают токены провайдера.
    if not original_key:
        await providers_store.save(key, url, headers, verify_ssl)
        log.warning('Админка: добавлен провайдер %r url=%r заголовки=%r verify_ssl=%s %s',
                    key, url, sorted(headers), verify_ssl, client_desc(request))
    elif key != original_key:
        old_url = existing[original_key]['url']
        await providers_store.rename(original_key, key, url, headers, verify_ssl)
        log.warning('Админка: переименован провайдер %r -> %r url=%r (было %r) заголовки=%r '
                    'verify_ssl=%s %s', original_key, key, url, old_url, sorted(headers),
                    verify_ssl, client_desc(request))
    else:
        old_url = existing[key]['url']
        await providers_store.save(key, url, headers, verify_ssl)
        log.warning('Админка: изменён провайдер %r url=%r (было %r) заголовки=%r verify_ssl=%s %s',
                    key, url, old_url, sorted(headers), verify_ssl, client_desc(request))
    raise web.HTTPSeeOther(f'{ADMIN_PREFIX}/?msg=saved')


async def handler_admin_delete(request: web.Request):
    key = request.match_info['key']
    old_url, _ = providers_store.get(key)
    await providers_store.delete(key)
    if old_url is not None:
        log.warning('Админка: удалён провайдер %r url=%r %s', key, old_url, client_desc(request))
    raise web.HTTPSeeOther(f'{ADMIN_PREFIX}/?msg=deleted')


def _basic_auth_user(request: web.Request):
    """(user, ok) из заголовка Authorization; (None, False) - если его нет."""
    auth_header = request.headers.get('Authorization', '')
    scheme, _, encoded = auth_header.partition(' ')
    if scheme != 'Basic' or not encoded:
        return None, False
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except Exception:
        return '', False
    user, _, password = decoded.partition(b':')
    # Сравниваем БАЙТЫ: hmac.compare_digest на str падает с TypeError на
    # не-ASCII символах (кириллический пароль давал 500). Оба сравнения
    # выполняются всегда - без короткого замыкания по неверному логину.
    # compare_digest - сравнение за постоянное время (без утечки через тайминг).
    user_ok = hmac.compare_digest(user, ADMIN_USER.encode('utf-8'))
    password_ok = hmac.compare_digest(password, ADMIN_PASSWORD.encode('utf-8'))
    return user.decode('utf-8', errors='replace'), user_ok and password_ok


# ip -> [неудачных попыток в текущем окне, начало окна, заблокирован до]
_auth_failures = {}


def _auth_blocked_for(ip: str, now: float) -> int:
    """Сколько секунд ещё действует блокировка IP (0 - не заблокирован)."""
    state = _auth_failures.get(ip)
    if state and state[2] > now:
        return int(state[2] - now) + 1
    return 0


def _register_auth_failure(ip: str, now: float) -> bool:
    """Учитывает неудачную попытку; True - если IP только что заблокирован."""
    if len(_auth_failures) > 10000:
        # Не даём словарю расти бесконечно при переборе с множества IP.
        for stale_ip in [i for i, s in _auth_failures.items()
                         if s[2] <= now and now - s[1] > AUTH_WINDOW]:
            del _auth_failures[stale_ip]
    state = _auth_failures.get(ip)
    if state is None or now - state[1] > AUTH_WINDOW:
        state = _auth_failures[ip] = [0, now, 0.0]
    state[0] += 1
    if state[0] >= AUTH_MAX_FAILURES:
        state[0], state[1], state[2] = 0, now, now + AUTH_BLOCK
        return True
    return False


def _same_origin(request: web.Request) -> bool:
    """POST в панель принимаем только со страниц самого прокси (защита от
    CSRF: Basic Auth браузер подставляет в запрос с ЛЮБОГО сайта). Браузеры
    всегда шлют Origin на POST; Referer - запасной вариант."""
    source = request.headers.get('Origin') or request.headers.get('Referer')
    if not source or source == 'null':
        return False
    netloc = urlparse(source).netloc.lower()
    allowed = {request.host.lower(), HOST_NAME.lower(), f'{HOST_NAME}:{PORT}'.lower()}
    return netloc in allowed


@web.middleware
async def admin_auth_middleware(request: web.Request, handler):
    """HTTP Basic Auth на /<ADMIN_PATH>/* - без системы пользователей, один
    общий логин/пароль из .env (ADMIN_USER/ADMIN_PASSWORD). Если
    ADMIN_PASSWORD не задан, панель выключена (404)."""
    if request.path != ADMIN_PREFIX and not request.path.startswith(ADMIN_PREFIX + '/'):
        return await handler(request)
    if not ADMIN_PASSWORD:
        raise web.HTTPNotFound()

    ip = client_ip(request)
    now = time.monotonic()
    blocked_for = _auth_blocked_for(ip, now)
    if blocked_for:
        return web.Response(status=429, text='Too Many Requests',
                            headers={'Retry-After': str(blocked_for)})

    user, ok = _basic_auth_user(request)
    if not ok:
        # Запрос вовсе без логина - обычный первый заход браузера (он в
        # ответ на 401 покажет окно входа), такое попыткой не считаем.
        if user is not None:
            log.warning('Админка: неверный логин/пароль (логин %r): %s %r %s',
                        user, request.method, request.path_qs, client_desc(request))
            if _register_auth_failure(ip, now):
                log.warning('Админка: IP %s заблокирован на %d с после %d неверных попыток',
                            ip, AUTH_BLOCK, AUTH_MAX_FAILURES)
        return web.Response(
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="iptv-proxy admin", charset="UTF-8"'},
            text='Unauthorized',
        )
    _auth_failures.pop(ip, None)

    if request.method == 'POST' and not _same_origin(request):
        log.warning('Админка: отклонён POST с чужого сайта (CSRF?) origin=%r referer=%r: %r %s',
                    request.headers.get('Origin'), request.headers.get('Referer'),
                    request.path_qs, client_desc(request))
        raise web.HTTPForbidden(text='Cross-site request rejected')
    return await handler(request)


# --------------------------------------------------------------------------
# Приложение
# --------------------------------------------------------------------------

async def on_startup(app):
    app['session'] = aiohttp.ClientSession()
    providers_store.load(seed_from=getattr(config, 'provider', None))
    load_signing_key()
    log.info('IPTV proxy started on 0.0.0.0:%s', PORT)
    providers = providers_store.list_all()
    if not providers:
        log.warning("Провайдеров нет - добавьте через http://%s:%s%s/", HOST_NAME, PORT, ADMIN_PREFIX)
    for k in providers:
        log.info("  channel '%s' -> %s://%s:%s/%s/", k, SCHEME, HOST_NAME, PORT, k)
    if ADMIN_PATH in providers:
        log.warning("Провайдер с ключом %r недоступен: этот адрес занят панелью управления "
                    "(ADMIN_PATH). Переименуйте провайдера в панели или смените ADMIN_PATH",
                    ADMIN_PATH)
    if not ADMIN_PASSWORD:
        log.warning("ADMIN_PASSWORD не задан - панель управления %s/ ВЫКЛЮЧЕНА (404). "
                    "Задайте ADMIN_PASSWORD в .env, чтобы управлять провайдерами", ADMIN_PREFIX)
    else:
        log.info("Панель управления: %s://%s:%s%s/", SCHEME, HOST_NAME, PORT, ADMIN_PREFIX)


async def on_cleanup(app):
    await app['session'].close()


def create_app() -> web.Application:
    app = web.Application(middlewares=[admin_auth_middleware])
    app.router.add_route('OPTIONS', '/{tail:.*}', handler_options)
    app.router.add_get('/', handler_index)
    # Роуты панели и алиасы с расширением - должны быть зарегистрированы
    # РАНЬШЕ общего '/{key}', иначе тот перехватит их первым (например,
    # ключ ADMIN_PATH или 'one.m3u8'). ADMIN_PATH поэтому же зарезервирован
    # как имя ключа провайдера (см. _validate_key).
    app.router.add_get(ADMIN_PREFIX, handler_admin_redirect_to_slash)
    app.router.add_get(f'{ADMIN_PREFIX}/', handler_admin_index)
    app.router.add_get(f'{ADMIN_PREFIX}/edit/{{key}}', handler_admin_edit)
    app.router.add_post(f'{ADMIN_PREFIX}/save', handler_admin_save)
    app.router.add_post(f'{ADMIN_PREFIX}/delete/{{key}}', handler_admin_delete)
    app.router.add_get('/{key}.m3u8', handler_playlist_ext)
    app.router.add_get('/{key}.m3u', handler_playlist_ext)
    app.router.add_get('/{key}/playlist.m3u8', handler_playlist_ext)
    app.router.add_get('/{key}', handler_redirect_to_slash)
    app.router.add_get('/{key}/', handler_playlist)
    app.router.add_get('/{key}/res/{sig}/{token}', handler_resource)
    app.router.add_get('/{key}/res/{token}', handler_resource_unsigned)
    # Последним - всё, что не совпало выше (иначе было бы 405 от OPTIONS).
    app.router.add_get('/{key}/{tail:.*}', handler_not_found)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


if __name__ == '__main__':
    web.run_app(create_app(), host='0.0.0.0', port=PORT,
                access_log_class=DebugAccessLogger)
