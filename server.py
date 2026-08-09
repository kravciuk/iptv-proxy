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
import html
import logging
import os
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import web

import config
import providers_store

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
#
# Список провайдеров больше не хранится в config.py - он живёт в
# providers_store (data/providers.json) и управляется через /admin/ или
# прямой правкой этого файла. config.py используется только один раз, как
# начальные данные при самом первом запуске (см. providers_store.load()).
# --------------------------------------------------------------------------

def get_provider_entry(key):
    """Возвращает (url, extra_headers) для ключа провайдера или (None, None)."""
    return providers_store.get(key)


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
    _, extra_headers = get_provider_entry(key)
    if extra_headers is None:
        raise web.HTTPNotFound(text='Unknown provider key: %s' % key)

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
    for k in providers_store.list_all():
        lines.append(f'  http://{config.host_name}:{PORT}/{k}/')
    lines.append(f'\nУправление провайдерами: http://{config.host_name}:{PORT}/admin/')
    return web.Response(text='\n'.join(lines), content_type='text/plain')


# --------------------------------------------------------------------------
# Веб-интерфейс управления провайдерами (/admin/)
#
# Без авторизации - как и весь сервис по условию задачи. Любой, кто может
# достучаться до порта прокси, может смотреть/добавлять/менять/удалять
# провайдеров через эту страницу. Изменения применяются сразу же (пишутся
# в data/providers.json через providers_store).
# --------------------------------------------------------------------------

KEY_RE = re.compile(r'^[A-Za-z0-9_-]+$')


def _validate_key(key: str):
    if not key:
        return 'Ключ обязателен'
    if not KEY_RE.match(key):
        return 'Ключ может содержать только латинские буквы, цифры, "-" и "_"'
    if key in providers_store.RESERVED_KEYS:
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
                       edit_mode=False):
    e = html.escape
    rows = []
    for key in sorted(providers):
        entry = providers[key]
        n_headers = len(entry['headers'])
        headers_note = f'{n_headers} доп. заголовок(ов)' if n_headers else '-'
        rows.append(f'''
        <tr>
          <td><code>{e(key)}</code></td>
          <td class="url-cell"><code>{e(entry['url'])}</code></td>
          <td>{headers_note}</td>
          <td class="actions">
            <a href="/{e(key)}/" target="_blank">Открыть</a>
            <a href="/admin/edit/{e(key)}">Изменить</a>
            <form method="post" action="/admin/delete/{e(key)}" class="inline">
              <button type="submit" class="danger">Удалить</button>
            </form>
          </td>
        </tr>''')

    rows_html = ''.join(rows) if rows else '<tr><td colspan="4"><em>Провайдеров пока нет</em></td></tr>'
    message_html = f'<p class="msg ok">{e(message)}</p>' if message else ''
    error_html = f'<p class="msg err">{e(error)}</p>' if error else ''
    form_title = 'Изменить провайдера' if edit_mode else 'Добавить провайдера'
    key_field = (
        f'<input type="text" name="key" value="{e(form_key)}" readonly>'
        if edit_mode else
        '<input type="text" name="key" placeholder="one" required pattern="[A-Za-z0-9_-]+">'
    )
    cancel_link = '<a href="/admin/">Отмена</a>' if edit_mode else ''

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
  input[type=text], textarea {{ width: 100%; box-sizing: border-box; padding: 0.4em; }}
  textarea {{ height: 4em; font-family: monospace; }}
  .msg {{ padding: 0.6em 1em; border-radius: 4px; }}
  .msg.ok {{ background: #e6ffed; border: 1px solid #4caf50; }}
  .msg.err {{ background: #ffe8e8; border: 1px solid #d32f2f; }}
  code {{ word-break: break-all; }}
</style>
</head>
<body>
<h1>IPTV proxy - провайдеры</h1>
<p><em>Без авторизации: любой, кто откроет эту страницу, может добавлять,
менять и удалять провайдеров.</em></p>
{message_html}{error_html}
<table>
  <thead><tr><th>Ключ</th><th>URL</th><th>Заголовки</th><th>Действия</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>

<h2>{form_title}</h2>
<form method="post" action="/admin/save">
  <label>Ключ (используется в адресе /&lt;ключ&gt;/)
    {key_field}
  </label>
  <label>URL плейлиста провайдера
    <input type="text" name="url" value="{e(form_url)}" placeholder="https://provide.one/list.m3u8" required>
  </label>
  <details>
    <summary>Дополнительные заголовки (опционально)</summary>
    <label>По одному заголовку на строку, формат "Имя: значение"
      <textarea name="headers">{e(form_headers_text)}</textarea>
    </label>
  </details>
  <p><button type="submit">Сохранить</button> {cancel_link}</p>
</form>
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
        edit_mode=True,
    )
    return web.Response(text=body, content_type='text/html')


async def handler_admin_save(request: web.Request):
    data = await request.post()
    key = (data.get('key') or '').strip()
    url = (data.get('url') or '').strip()
    headers_text = data.get('headers') or ''

    key_error = _validate_key(key)
    url_error = _validate_url(url)
    headers, headers_error = _parse_headers(headers_text)
    error = key_error or url_error or headers_error

    if error:
        edit_mode = key in providers_store.list_all()
        body = render_admin_page(
            providers_store.list_all(), error=error,
            form_key=key, form_url=url, form_headers_text=headers_text,
            edit_mode=edit_mode,
        )
        return web.Response(text=body, content_type='text/html', status=400)

    await providers_store.save(key, url, headers)
    raise web.HTTPSeeOther('/admin/?msg=saved')


async def handler_admin_delete(request: web.Request):
    key = request.match_info['key']
    await providers_store.delete(key)
    raise web.HTTPSeeOther('/admin/?msg=deleted')


# --------------------------------------------------------------------------
# Приложение
# --------------------------------------------------------------------------

async def on_startup(app):
    app['session'] = aiohttp.ClientSession()
    providers_store.load(seed_from=getattr(config, 'provider', None))
    log.info('IPTV proxy started on 0.0.0.0:%s', PORT)
    providers = providers_store.list_all()
    if not providers:
        log.warning("Провайдеров нет - добавьте через http://%s:%s/admin/", config.host_name, PORT)
    for k in providers:
        log.info("  channel '%s' -> %s://%s:%s/%s/", k, SCHEME, config.host_name, PORT, k)


async def on_cleanup(app):
    await app['session'].close()


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_route('OPTIONS', '/{tail:.*}', handler_options)
    app.router.add_get('/', handler_index)
    # Роуты /admin/* и алиасы с расширением - должны быть зарегистрированы
    # РАНЬШЕ общего '/{key}', иначе тот перехватит их первым (например,
    # ключ 'admin' или 'one.m3u8'). 'admin' поэтому же зарезервирован как
    # имя ключа провайдера (см. providers_store.RESERVED_KEYS).
    app.router.add_get('/admin/', handler_admin_index)
    app.router.add_get('/admin/edit/{key}', handler_admin_edit)
    app.router.add_post('/admin/save', handler_admin_save)
    app.router.add_post('/admin/delete/{key}', handler_admin_delete)
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
