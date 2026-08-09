# -*- coding: utf-8 -*-
"""
Хранилище провайдеров плейлистов.

Раньше provider = {...} жил только в config.py и менялся правкой файла +
перезапуском процесса. Теперь это отдельный JSON-файл на диске
(data/providers.json), которым можно управлять как через веб-интерфейс
(/admin/, мгновенно), так и вручную (правка файла, применяется после
перезапуска - как раньше config.py).

Формат файла: {"<key>": {"url": "...", "headers": {...}}, ...}
"""

import asyncio
import json
import logging
import os

log = logging.getLogger('iptv-proxy')

DATA_DIR = os.environ.get('IPTV_PROXY_DATA_DIR', 'data')
DATA_FILE = os.path.join(DATA_DIR, 'providers.json')

# Ключ 'admin' зарезервирован под веб-интерфейс управления - провайдер с
# таким именем создать нельзя (см. валидацию в server.py).
RESERVED_KEYS = {'admin'}

PROVIDERS = {}
_lock = asyncio.Lock()


def _normalize(entry):
    """Приводит запись провайдера (строка-URL либо dict) к единому виду
    {"url": ..., "headers": {...}}."""
    if isinstance(entry, dict):
        return {'url': entry.get('url', ''), 'headers': dict(entry.get('headers') or {})}
    return {'url': entry, 'headers': {}}


def _read_from_disk():
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        raw = json.load(f)
    return {key: _normalize(entry) for key, entry in raw.items()}


def _write_to_disk(data):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp_path = DATA_FILE + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, DATA_FILE)


def load(seed_from=None):
    """Вызывается один раз при старте. Если providers.json уже существует -
    грузит его. Если нет - сидирует из seed_from (обычно config.provider),
    сохраняет на диск и логирует перенос, чтобы существующие деплойменты
    не потеряли уже настроенных провайдеров."""
    global PROVIDERS
    if os.path.exists(DATA_FILE):
        PROVIDERS = _read_from_disk()
        log.info("Providers loaded from %s (%d записей)", DATA_FILE, len(PROVIDERS))
        return

    seeded = {key: _normalize(entry) for key, entry in (seed_from or {}).items()}
    PROVIDERS = seeded
    _write_to_disk(PROVIDERS)
    if seeded:
        log.info(
            "%s не найден - перенесены провайдеры из config.py (%d записей) в %s",
            DATA_FILE, len(seeded), DATA_FILE,
        )
    else:
        log.info("%s не найден - создан пустой файл провайдеров", DATA_FILE)


def get(key):
    """Возвращает (url, headers) для ключа провайдера или (None, None)."""
    entry = PROVIDERS.get(key)
    if entry is None:
        return None, None
    return entry['url'], entry['headers']


def list_all():
    """dict {key: {"url":..., "headers":...}} - для рендера /admin/."""
    return dict(PROVIDERS)


async def save(key, url, headers):
    async with _lock:
        PROVIDERS[key] = {'url': url, 'headers': dict(headers or {})}
        _write_to_disk(PROVIDERS)


async def delete(key):
    async with _lock:
        PROVIDERS.pop(key, None)
        _write_to_disk(PROVIDERS)
