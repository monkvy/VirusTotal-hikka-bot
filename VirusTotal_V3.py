# Author TG: @monkvy
# Version: v3.0.0
# Telegram Channel: https://t.me/codex_modules
# Telegram Chat: https://t.me/CodexCommunityChat
# https://github.com/monkvy/VirusTotal-hikka-bot

import asyncio
import logging
import os
import tempfile
import re
import base64
import hashlib
import time
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field

import aiohttp

from .. import loader, utils

logger = logging.getLogger(__name__)

@dataclass
class ScanStats:
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0

    @property
    def total(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected

@dataclass
class HistoryEntry:
    item_id: str
    timestamp: datetime
    scan_type: str
    name: Optional[str] = None
    url: Optional[str] = None
    as_owner: Optional[str] = None
    country_code: Optional[str] = None
    stats: ScanStats = field(default_factory=ScanStats)
    raw_result: dict = field(default_factory=dict)

class VTAPIClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._session: Optional[aiohttp.ClientSession] = None
        self._retries = 3

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(headers={'x-apikey': self.api_key})
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _request(self, method: str, url: str, **kwargs) -> Optional[Dict]:
        for attempt in range(self._retries):
            try:
                session = await self._get_session()
                async with session.request(method, url, **kwargs) as resp:
                    if resp.status == 429:
                        wait = int(resp.headers.get('Retry-After', 60))
                        await asyncio.sleep(wait)
                        continue
                    if resp.status == 200:
                        return await resp.json()
                    return None
            except (aiohttp.ClientConnectorError, asyncio.TimeoutError):
                if attempt == self._retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)
        return None

    async def upload_file(self, file_path: str) -> Optional[str]:
        with open(file_path, 'rb') as f:
            data = aiohttp.FormData()
            data.add_field('file', f, filename=os.path.basename(file_path))
            result = await self._request('POST', 'https://www.virustotal.com/api/v3/files', data=data)
            return result.get('data', {}).get('id') if result else None

    async def get_analysis(self, analysis_id: str) -> Optional[Dict]:
        return await self._request('GET', f'https://www.virustotal.com/api/v3/analyses/{analysis_id}')

    async def get_file_report(self, file_hash: str) -> Optional[Dict]:
        return await self._request('GET', f'https://www.virustotal.com/api/v3/files/{file_hash}')

    async def get_url_report(self, url_id: str) -> Optional[Dict]:
        return await self._request('GET', f'https://www.virustotal.com/api/v3/urls/{url_id}')

    async def scan_url(self, url: str) -> Optional[Dict]:
        data = aiohttp.FormData()
        data.add_field('url', url)
        result = await self._request('POST', 'https://www.virustotal.com/api/v3/urls', data=data)
        return result

    async def get_ip_report(self, ip: str) -> Optional[Dict]:
        return await self._request('GET', f'https://www.virustotal.com/api/v3/ip_addresses/{ip}')

class HistoryManager:
    def __init__(self, db, max_items: int = 10):
        self._db = db
        self.max_items = max_items
        self._entries: List[HistoryEntry] = []
        self._load()

    def _load(self):
        data = self._db.get(__name__, 'history', [])
        for item in data:
            try:
                entry = HistoryEntry(
                    item_id=item['item_id'],
                    timestamp=datetime.fromisoformat(item['timestamp']),
                    scan_type=item['scan_type'],
                    name=item.get('name'),
                    url=item.get('url'),
                    as_owner=item.get('as_owner'),
                    country_code=item.get('country_code'),
                    stats=ScanStats(**item.get('stats', {})),
                    raw_result=item.get('raw_result', {})
                )
                self._entries.append(entry)
            except:
                continue

    def _save(self):
        data = []
        for entry in self._entries:
            data.append({
                'item_id': entry.item_id,
                'timestamp': entry.timestamp.isoformat(),
                'scan_type': entry.scan_type,
                'name': entry.name,
                'url': entry.url,
                'as_owner': entry.as_owner,
                'country_code': entry.country_code,
                'stats': {
                    'malicious': entry.stats.malicious,
                    'suspicious': entry.stats.suspicious,
                    'harmless': entry.stats.harmless,
                    'undetected': entry.stats.undetected
                },
                'raw_result': entry.raw_result
            })
        self._db.set(__name__, 'history', data)

    def _trim(self):
        if len(self._entries) > self.max_items:
            self._entries = self._entries[:self.max_items]

    def add(self, entry: HistoryEntry):
        self._entries.insert(0, entry)
        self._trim()
        self._save()

    def clear(self):
        self._entries.clear()
        self._save()

    def get_all(self) -> List[HistoryEntry]:
        return self._entries.copy()

    def get_page(self, page: int, per_page: int) -> List[HistoryEntry]:
        start = (page - 1) * per_page
        return self._entries[start:start + per_page]

    @property
    def total_pages(self, per_page: int) -> int:
        return (len(self._entries) + per_page - 1) // per_page

    def find_by_hash(self, hash_part: str) -> List[HistoryEntry]:
        hash_part = hash_part.lower()
        return [e for e in self._entries if hash_part in e.item_id.lower()]

    def set_max_items(self, max_items: int):
        self.max_items = max_items
        self._trim()
        self._save()

class UIFormatter:
    def __init__(self, lang: str = 'ru'):
        self.lang = lang
        self._premium_emojis = self._build_emojis(premium=True)
        self._normal_emojis = self._build_emojis(premium=False)

    def _build_emojis(self, premium: bool):
        if premium:
            return {
                'file': '<emoji document_id=5433653135799228968>📁</emoji>',
                'url': '<emoji document_id=5271604874419647061>🔗</emoji>',
                'size': '<emoji document_id=5784891605601225888>📦</emoji>',
                'time': '<emoji document_id=5382194935057372936>⏱️</emoji>',
                'engines': '<emoji document_id=5195033767969839232>🚀</emoji>',
                'scans': '<emoji document_id=5444965061749644170>👥</emoji>',
                'progress': '<emoji document_id=5386367538735104399>⏳</emoji>',
                'refresh': '<emoji document_id=5818740758257077530>🔄</emoji>',
                'stats': '<emoji document_id=5231200819986047254>📊</emoji>',
                'shield': '<emoji document_id=5251203410396458957>🛡</emoji>',
                'check': '<emoji document_id=5231012545799666522>🔍</emoji>',
                'success': '<emoji document_id=5206607081334906820>✅️</emoji>',
                'error': '<emoji document_id=5210952531676504517>❌️</emoji>',
                'warning': '<emoji document_id=5447644880824181073>⚠️</emoji>',
                'danger': '<emoji document_id=5260293700088511294>⛔️</emoji>',
                'skull': '<emoji document_id=5370842086658546991>☠️</emoji>',
                'history': '<emoji document_id=5197269100878907942>📋</emoji>',
                'pages': '<emoji document_id=5253742260054409879>📄</emoji>',
                'hash': '<emoji document_id=5343824560523322473>🔢</emoji>',
                'upload': '<emoji document_id=5433614747381538714>📤</emoji>',
                'globe': '<emoji document_id=5447410659077661506>🌐</emoji>',
                'chart': '<emoji document_id=5244837092042750681>📈</emoji>',
                'forbidden': '<emoji document_id=5240241223632954241>🚫</emoji>',
                'trash': '<emoji document_id=5445267414562389170>🗑</emoji>',
                'history_empty': '<emoji document_id=5352896944496728039>📭</emoji>',
                'downloading': '<emoji document_id=5433653135799228968>📥</emoji>',
                'waiting': '<emoji document_id=5386367538735104399>⏳</emoji>',
                'timeout': '<emoji document_id=5382194935057372936>⏰</emoji>',
                'left_arrow': '⬅️',
                'right_arrow': '➡️',
                'back_arrow': '↩️',
                'flag_ru': '🇷🇺',
                'flag_gb': '🇬🇧',
                'link': '🔗',
                'cancel': '🚫'
            }
        else:
            return {
                'file': '📁',
                'url': '🔗',
                'size': '📦',
                'time': '⏱️',
                'engines': '🚀',
                'scans': '👥',
                'progress': '⏳',
                'refresh': '🔄',
                'stats': '📊',
                'shield': '🛡',
                'check': '🔍',
                'success': '✅',
                'error': '❌',
                'warning': '⚠️',
                'danger': '⛔',
                'skull': '☠️',
                'history': '📋',
                'pages': '📄',
                'hash': '🔢',
                'upload': '📤',
                'globe': '🌐',
                'chart': '📈',
                'forbidden': '🚫',
                'trash': '🗑',
                'history_empty': '📭',
                'downloading': '📥',
                'waiting': '⏳',
                'timeout': '⏰',
                'left_arrow': '⬅️',
                'right_arrow': '➡️',
                'back_arrow': '↩️',
                'flag_ru': '🇷🇺',
                'flag_gb': '🇬🇧',
                'link': '🔗',
                'cancel': '🚫'
            }

    def emoji(self, name: str, premium: bool = True) -> str:
        if premium:
            return self._premium_emojis.get(name, '')
        else:
            return self._normal_emojis.get(name, '')

    def country_flag(self, country_code: str) -> str:
        if not country_code or len(country_code) != 2:
            return '🏳️'
        base = 127462
        code1 = base + (ord(country_code[0].upper()) - ord('A'))
        code2 = base + (ord(country_code[1].upper()) - ord('A'))
        return chr(code1) + chr(code2)

    def format_size(self, size_bytes: int) -> str:
        units = ['B', 'KB', 'MB', 'GB']
        ru_units = ['Б', 'КБ', 'МБ', 'ГБ']
        size = size_bytes
        unit_index = 0
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        if self.lang == 'ru':
            return f"{size:.1f} {ru_units[unit_index]}" if unit_index > 0 else f"{size:.0f} {ru_units[0]}"
        else:
            return f"{size:.1f} {units[unit_index]}" if unit_index > 0 else f"{size:.0f} {units[0]}"

    def format_time(self, seconds: int) -> str:
        if seconds < 60:
            return f"{seconds} {'сек' if self.lang == 'ru' else 'sec'}"
        else:
            minutes = seconds // 60
            remaining = seconds % 60
            if remaining == 0:
                return f"{minutes} {'мин' if self.lang == 'ru' else 'min'}"
            return f"{minutes} {'мин' if self.lang == 'ru' else 'min'} {remaining} {'сек' if self.lang == 'ru' else 'sec'}"

    def get_status_emoji(self, stats: ScanStats) -> Tuple[str, str]:
        if stats.malicious > 0:
            ratio = stats.malicious / stats.total if stats.total > 0 else 0
            if ratio < 0.02:
                return self.emoji('success'), 'likely_safe'
            elif ratio < 0.05:
                return self.emoji('warning'), 'suspicious'
            elif ratio < 0.15:
                return self.emoji('danger'), 'dangerous'
            else:
                return self.emoji('skull'), 'very_dangerous'
        elif stats.suspicious > 0:
            return self.emoji('warning'), 'suspicious'
        else:
            return self.emoji('success'), 'clean'

    def format_stats_block(self, stats: ScanStats) -> str:
        total = stats.total or 1
        mal_pct = round(stats.malicious / total * 100, 1)
        susp_pct = round(stats.suspicious / total * 100, 1)
        harm_pct = round(stats.harmless / total * 100, 1)
        und_pct = round(stats.undetected / total * 100, 1)
        return (
            f"<blockquote>🚫<code>{stats.malicious}/{total} ({mal_pct}%)│{'Вредоносные' if self.lang == 'ru' else 'Malicious'}</code>\n"
            f"⚠️<code>{stats.suspicious}/{total} ({susp_pct}%)│{'Подозрительные' if self.lang == 'ru' else 'Suspicious'}</code>\n"
            f"{self.emoji('success')}<code>{stats.harmless}/{total} ({harm_pct}%)│{'Безвредные' if self.lang == 'ru' else 'Harmless'}</code>\n"
            f"👁️<code>{stats.undetected}/{total} ({und_pct}%)│{'Не обнаружено' if self.lang == 'ru' else 'Undetected'}</code></blockquote>"
        )

class InlineHandlers:
    def __init__(self, module):
        self.module = module

    async def history_callback(self, call, page_num: int = 1, return_id: Optional[int] = None):
        await self.module._show_history_page(call, page_num, return_id)

    async def clear_confirm_callback(self, call):
        if not self.module.history.get_all():
            await call.answer(f"{self.module.ui.emoji('history_empty')} {'История пуста' if self.module.lang == 'ru' else 'History empty'}", show_alert=True)
            return
        warning_line = ('⚠️ Вы уверены, что хотите очистить всю историю?\nЭто действие нельзя отменить.'
                        if self.module.lang == 'ru'
                        else '⚠️ Are you sure you want to clear all history?\nThis action cannot be undone.')
        text = (
            f"<b>{self.module.ui.emoji('warning')} {'Подтверждение очистки' if self.module.lang == 'ru' else 'Confirm clear'}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"{warning_line}\n"
            f"<b>{'Записей' if self.module.lang == 'ru' else 'Entries'}: {len(self.module.history.get_all())}</b>"
        )
        buttons = [[
            {"text": f"{self.module.ui.emoji('success', premium=False)} {'Да, очистить' if self.module.lang == 'ru' else 'Yes, clear'}", "callback": self.module._clear_history_callback},
            {"text": self.module.get_string('cancel'), "callback": self.cancel_clear_callback}
        ]]
        await call.edit(text=text, reply_markup=buttons)

    async def cancel_clear_callback(self, call):
        await self.module._show_history_page(call, 1, None)

    async def return_to_results_callback(self, call, message_id: int):
        data = self.module._db.get(__name__, f"result_{message_id}")
        if not data:
            await call.answer(f"{self.module.ui.emoji('error')} {'Результат устарел' if self.module.lang == 'ru' else 'Result expired'}", show_alert=True)
            await call.delete()
            return
        buttons = [
            [{"text": f"{self.module.ui.emoji('link', premium=False)} {self.module.get_string('view_report')}", "url": data['vt_url']}],
            [{"text": f"{self.module.ui.emoji('history', premium=False)} {'История' if self.module.lang == 'ru' else 'History'}", "callback": self.history_callback, "args": (1, message_id)}]
        ]
        await call.edit(text=data['text'], reply_markup=buttons)

    async def change_language_callback(self, call, lang: str):
        self.module.config['language'] = lang
        self.module.lang = lang
        self.module.ui.lang = lang
        await call.answer(f"{self.module.ui.emoji('success')} {'Язык изменен' if lang == 'ru' else 'Language changed'}")
        await call.edit(text=f"<b>{self.module.ui.emoji('success')} {'Язык изменен на Русский' if lang == 'ru' else 'Language changed to English'}</b>", reply_markup=None)

STRINGS = {
    'ru': {
        'name': 'VirusTotal',
        'no_file': 'Ответьте на файл',
        'no_url': 'Укажите ссылку после команды',
        'invalid_url': 'Неверный формат ссылки',
        'downloading': 'Скачиваю файл...',
        'uploading': 'Загружаю на VirusTotal...',
        'scanning_url': 'Сканирую ссылку...',
        'waiting': 'Жду анализа...',
        'no_key': 'Укажите API ключ в конфиге',
        'error': 'Ошибка при сканировании',
        'size_limit': 'Файл больше 32МБ',
        'timeout': 'Таймаут сканирования',
        'view_report': 'Полный отчёт',
        'checking_cache': 'Проверка кэша...',
        'getting_results': 'Получаю результаты...',
        'upload_error': 'Ошибка загрузки',
        'scan_error': 'Ошибка сканирования',
        'download_error': 'Не удалось скачать файл: {error}',
        'results_title': 'Результаты сканирования VirusTotal',
        'history_title': 'История сканирований VirusTotal',
        'history_empty': 'История сканирований пуста',
        'history_cleared': 'История очищена',
        'history_entries': 'Всего записей',
        'clear_history': 'Очистить',
        'hash_check': 'Проверить по хешу',
        'invalid_history_limit': '❌ Должно быть целым числом от 1 до 30',
        'history_limit_set': '✅ Лимит истории установлен на',
        'history_settings': 'Настройки истории',
        'current_limit': 'Текущий лимит',
        'entries': 'записей',
        'delete_entry': 'Удалить запись',
        'entry_deleted': '✅ Запись удалена',
        'cancel': 'Отмена',
        'confirm_clear': 'Подтвердить очистку',
        'clear_all_history': 'Очистить всю историю',
        'clear_history_confirm': '⚠️ Вы уверены, что хотите очистить всю историю?\nЭто действие нельзя отменить.',
        'scan_details': 'Детали сканирования',
        'prev_page': 'Назад',
        'next_page': 'Вперед',
        'page_info': 'Страница',
        'refresh': 'Обновить',
        'first_page': 'Первая',
        'last_page': 'Последняя',
        'back_to_results': 'Обратно',
        'file': 'Файл',
        'url': 'Ссылка',
        'hash': 'Хеш',
        'domain': 'Домен',
        'scans': 'сканирований',
        'engines': 'движков',
        'clean': 'чистый',
        'dangerous': 'опасный',
        'very_dangerous': 'очень опасный',
        'suspicious': 'подозрительный',
        'likely_safe': 'вероятно безопасный',
        'high_risk': 'высокий риск',
        'low_risk': 'низкий риск',
        'threats': 'Угроз',
        'detected': 'обнаружено',
        'status': 'Статус',
        'safe': 'безопасно',
        'results': 'Результаты',
        'malicious': 'Вредоносные',
        'harmless': 'Безвредные',
        'undetected': 'Не обнаружено',
        'specify_hash': 'Укажите хеш файла (SHA256 или MD5)',
        'hash_not_found': 'Неверный формат хеша. Используйте SHA256 (64 символа) или MD5 (32 символа)',
        'search_results': 'Найдено {count} записей с хешем {hash}:',
        'and_more': '... и еще {count} записей',
        'use_full_hash': 'Используйте полный хеш для проверки:\n<code>.vthash [полный_хеш]</code>',
        'current_language': 'Текущий язык',
        'available_languages': 'Доступные языки',
        'russian': 'Русский (по умолчанию)',
        'english': 'Английский',
        'current_setting': 'Текущая настройка',
        'yes_clear': 'Да, очистить',
        'deleted_entries': 'Удалено записей',
        'checking_hash': 'Проверка хеша...',
        'searching_report': 'Поиск отчета по {type} хешу...',
        'not_found': 'Не найден'
    },
    'en': {
        'name': 'VirusTotal',
        'no_file': 'Reply to a file',
        'no_url': 'Specify URL after command',
        'invalid_url': 'Invalid URL format',
        'downloading': 'Downloading file...',
        'uploading': 'Uploading to VirusTotal...',
        'scanning_url': 'Scanning URL...',
        'waiting': 'Waiting for analysis',
        'no_key': 'Set API key in config',
        'error': 'Error during scanning',
        'size_limit': 'File is larger than 32MB',
        'timeout': 'Scan timeout',
        'view_report': 'Full report',
        'checking_cache': 'Checking cache...',
        'getting_results': 'Getting results...',
        'upload_error': 'Upload error',
        'scan_error': 'Scan error',
        'download_error': 'Failed to download file: {error}',
        'results_title': 'VirusTotal Scan Results',
        'history_title': 'VirusTotal Scan History',
        'history_empty': 'Scan history is empty',
        'history_cleared': 'History cleared',
        'history_entries': 'Total entries',
        'clear_history': 'Clear',
        'hash_check': 'Check by hash',
        'invalid_history_limit': '❌ Must be integer between 1 and 30',
        'history_limit_set': '✅ History limit set to',
        'history_settings': 'History settings',
        'current_limit': 'Current limit',
        'entries': 'entries',
        'delete_entry': 'Delete entry',
        'entry_deleted': '✅ Entry deleted',
        'cancel': 'Cancel',
        'confirm_clear': 'Confirm clear',
        'clear_all_history': 'Clear all history',
        'clear_history_confirm': '⚠️ Are you sure you want to clear all history?\nThis action cannot be undone.',
        'scan_details': 'Scan details',
        'prev_page': 'Back',
        'next_page': 'Forward',
        'page_info': 'Page',
        'refresh': 'Refresh',
        'first_page': 'First',
        'last_page': 'Last',
        'back_to_results': 'Back',
        'file': 'File',
        'url': 'URL',
        'hash': 'Hash',
        'domain': 'Domain',
        'scans': 'scans',
        'engines': 'engines',
        'clean': 'clean',
        'dangerous': 'dangerous',
        'very_dangerous': 'very dangerous',
        'suspicious': 'suspicious',
        'likely_safe': 'likely safe',
        'high_risk': 'high risk',
        'low_risk': 'low risk',
        'threats': 'Threats',
        'detected': 'detected',
        'status': 'Status',
        'safe': 'safe',
        'results': 'Results',
        'malicious': 'Malicious',
        'harmless': 'Harmless',
        'undetected': 'Undetected',
        'specify_hash': 'Specify file hash (SHA256 or MD5)',
        'hash_not_found': 'Invalid hash format. Use SHA256 (64 chars) or MD5 (32 chars)',
        'search_results': 'Found {count} entries with hash {hash}:',
        'and_more': '... and {count} more entries',
        'use_full_hash': 'Use full hash for check:\n<code>.vthash [full_hash]</code>',
        'current_language': 'Current language',
        'available_languages': 'Available languages',
        'russian': 'Russian (default)',
        'english': 'English',
        'current_setting': 'Current setting',
        'yes_clear': 'Yes, clear',
        'deleted_entries': 'Deleted entries',
        'checking_hash': 'Checking hash...',
        'searching_report': 'Searching report by {type} hash...',
        'not_found': 'Not found'
    }
}

@loader.tds
class VirusTotalMod(loader.Module):
    def __init__(self):
        self.config = loader.ModuleConfig(
            loader.ConfigValue(
                'api_key',
                None,
                'VirusTotal API key',
                validator=loader.validators.Hidden()
            ),
            loader.ConfigValue(
                'max_wait_time',
                300,
                'Maximum wait time in seconds',
                validator=loader.validators.Integer(minimum=60, maximum=600)
            ),
            loader.ConfigValue(
                'poll_interval',
                10,
                'Polling interval in seconds',
                validator=loader.validators.Integer(minimum=5, maximum=30)
            ),
            loader.ConfigValue(
                'save_history',
                True,
                'Save scan history',
                validator=loader.validators.Boolean()
            ),
            loader.ConfigValue(
                'max_history_items',
                10,
                'Maximum history entries',
                validator=loader.validators.Integer(minimum=1, maximum=30)
            ),
            loader.ConfigValue(
                'language',
                'ru',
                'Language (ru/en)',
                validator=loader.validators.Choice(['ru', 'en'])
            ),
            loader.ConfigValue(
                'cleanup_interval',
                3600,
                'Interval in seconds to clean old results',
                validator=loader.validators.Integer(minimum=300, maximum=86400)
            )
        )
        self.api: Optional[VTAPIClient] = None
        self.history: Optional[HistoryManager] = None
        self.ui: Optional[UIFormatter] = None
        self._inline_handlers: Optional[InlineHandlers] = None
        self.lang = 'ru'
        self.MAX_SIZE = 32 * 1024 * 1024
        self._cleanup_task: Optional[asyncio.Task] = None

    strings = {'name': 'VirusTotal'}

    async def client_ready(self, client, db):
        self._client = client
        self._db = db
        self.lang = self.config['language']
        if self.config['api_key']:
            self.api = VTAPIClient(self.config['api_key'])
        self.history = HistoryManager(db, self.config['max_history_items'])
        self.ui = UIFormatter(self.lang)
        self._inline_handlers = InlineHandlers(self)
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def on_unload(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()
        if self.api:
            await self.api.close()

    async def _cleanup_loop(self):
        interval = self.config['cleanup_interval']
        while True:
            await asyncio.sleep(interval)
            keys = self._db.get(__name__, {}).keys()
            for key in keys:
                if key.startswith('result_'):
                    self._db.set(__name__, key, None)

    def get_string(self, key: str, **kwargs) -> str:
        text = STRINGS[self.lang].get(key, STRINGS['ru'].get(key, key))
        if kwargs:
            try:
                return text.format(**kwargs)
            except:
                return text
        return text

    def _is_valid_ip(self, string: str) -> bool:
        try:
            ipaddress.ip_address(string)
            return True
        except ValueError:
            return False

    def _validate_url(self, url: str) -> Optional[str]:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        try:
            result = urlparse(url)
            if all([result.scheme, result.netloc]):
                return url
        except:
            pass
        return None

    def _calculate_hash(self, file_path: str) -> str:
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha.update(block)
        return sha.hexdigest()

    def _extract_stats(self, data: Dict, scan_type: str) -> ScanStats:
        stats = ScanStats()
        attrs = data.get('data', {}).get('attributes', {})
        if scan_type == 'file':
            last_stats = attrs.get('last_analysis_stats', {})
            stats.malicious = last_stats.get('malicious', 0)
            stats.suspicious = last_stats.get('suspicious', 0)
            stats.harmless = last_stats.get('harmless', 0)
            stats.undetected = last_stats.get('undetected', 0)
        else:
            results = attrs.get('last_analysis_results', {})
            for res in results.values():
                cat = res.get('category', '')
                if cat == 'malicious':
                    stats.malicious += 1
                elif cat == 'suspicious':
                    stats.suspicious += 1
                elif cat == 'harmless':
                    stats.harmless += 1
                else:
                    stats.undetected += 1
        return stats

    async def _poll_analysis_loop(self, analysis_id: str) -> Optional[Dict]:
        while True:
            result = await self.api.get_analysis(analysis_id)
            if result and result.get('data', {}).get('attributes', {}).get('status') == 'completed':
                return result
            await asyncio.sleep(self.config['poll_interval'])

    async def _poll_analysis(self, analysis_id: str, msg, msg_id: int) -> Optional[Dict]:
        try:
            result = await asyncio.wait_for(
                self._poll_analysis_loop(analysis_id),
                timeout=self.config['max_wait_time']
            )
            return result
        except asyncio.TimeoutError:
            return None

    async def _show_results(self, msg, item_id: str, data: Dict, scan_type: str, name: Optional[str] = None, url: Optional[str] = None, scan_time: int = 0, file_size: int = 0):
        stats = self._extract_stats(data, 'url' if scan_type in ['url', 'ip'] else scan_type)
        status_emoji, status_key = self.ui.get_status_emoji(stats)
        total = stats.total
        safety = round((stats.harmless + stats.undetected) / total * 100, 1) if total > 0 else 0
        
        popularity = data.get('data', {}).get('attributes', {}).get('times_submitted', 0)

        if scan_type == 'file':
            display_name = name or f"{self.get_string('hash')}: {item_id[:16]}..."
            info = (
                f"• {self.ui.emoji('file')} <b>{self.get_string('file')}:</b> <code>{display_name}</code>\n"
                f"• {self.ui.emoji('size')} <code>{self.ui.format_size(file_size) if file_size else ''}</code>\n"
                f"• {self.ui.emoji('time')} <code>{self.ui.format_time(scan_time)}</code>\n"
                f"• {self.ui.emoji('engines')} <code>{total} {self.get_string('engines')}</code>\n"
                f"• {self.ui.emoji('scans')} <code>{popularity} {self.get_string('scans')}</code>"
            )
            vt_url = f"https://www.virustotal.com/gui/file/{item_id}"
        elif scan_type == 'ip':
            country_code = data.get('data', {}).get('attributes', {}).get('country', '')
            flag = self.ui.country_flag(country_code)
            asn = data.get('data', {}).get('attributes', {}).get('asn', '')
            as_owner = data.get('data', {}).get('attributes', {}).get('as_owner', '')
            as_text = f"{asn} ({as_owner})" if as_owner else asn
            info = (
                f"• {self.ui.emoji('globe')} <b>IP-адрес:</b> <code>{url}</code>\n"
                f"• {flag} <b>Страна:</b> <code>{country_code or 'Неизвестно'}</code>\n"
                f"• {self.ui.emoji('stats')} <b>ASN:</b> <code>{as_text}</code>\n"
                f"• {self.ui.emoji('time')} <code>{self.ui.format_time(scan_time)}</code>\n"
                f"• {self.ui.emoji('engines')} <code>{total} {self.get_string('engines')}</code>"
            )
            vt_url = f"https://www.virustotal.com/gui/ip-address/{item_id}"
        else:
            domain = urlparse(url).netloc if url else ''
            info = (
                f"• {self.ui.emoji('url')} <b>{self.get_string('url')}:</b> <code>{url[:40] + '...' if url and len(url) > 40 else url}</code>\n"
                f"• {self.ui.emoji('globe')} <b>{self.get_string('domain')}:</b> <code>{domain}</code>\n"
                f"• {self.ui.emoji('time')} <code>{self.ui.format_time(scan_time)}</code>\n"
                f"• {self.ui.emoji('engines')} <code>{total} {self.get_string('engines')}</code>\n"
                f"• {self.ui.emoji('scans')} <code>{popularity} {self.get_string('scans')}</code>"
            )
            vt_url = f"https://www.virustotal.com/gui/url/{item_id}"

        text = (
            f"<b>{self.ui.emoji('shield')} {self.get_string('results_title')}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{info}\n\n"
            f"{status_emoji} <b>{self.get_string('status')}:</b> <code>{self.get_string(status_key)} ({safety}% {self.get_string('safe')})</code>\n"
            f"{status_emoji} <b>{self.get_string('threats')}:</b> <code>{stats.malicious} {self.get_string('detected')}</code>\n\n"
            f"<b>{self.ui.emoji('chart')} {self.get_string('results')}:</b>\n"
            f"{self.ui.format_stats_block(stats)}"
        )

        if self.config['save_history']:
            if scan_type == 'ip':
                as_owner = data.get('data', {}).get('attributes', {}).get('as_owner', '')
                country_code = data.get('data', {}).get('attributes', {}).get('country', '')
                entry = HistoryEntry(
                    item_id=item_id,
                    timestamp=datetime.now(timezone.utc),
                    scan_type=scan_type,
                    name=url,
                    url=url,
                    as_owner=as_owner,
                    country_code=country_code,
                    stats=stats,
                    raw_result=data
                )
            else:
                entry = HistoryEntry(
                    item_id=item_id,
                    timestamp=datetime.now(timezone.utc),
                    scan_type=scan_type,
                    name=name,
                    url=url,
                    stats=stats,
                    raw_result=data
                )
            self.history.add(entry)

        message_id = msg.id if hasattr(msg, 'id') else id(msg)
        self._db.set(__name__, f"result_{message_id}", {'text': text, 'vt_url': vt_url})

        buttons = [
            [{"text": f"{self.ui.emoji('link', premium=False)} {self.get_string('view_report')}", "url": vt_url}],
            [{"text": f"{self.ui.emoji('history', premium=False)} {'История' if self.lang == 'ru' else 'History'}", "callback": self._inline_handlers.history_callback, "args": (1, message_id)}]
        ]

        await self.inline.form(text=text, message=msg, reply_markup=buttons, ttl=300)

    async def _show_history_page(self, message, page: int = 1, return_id: Optional[int] = None):
        per_page = 5
        
        if not self.history.get_all():
            text = f"{self.ui.emoji('history_empty')} <b>{self.get_string('history_empty')}</b>"
            if hasattr(message, 'edit'):
                await message.edit(text=text, reply_markup=None)
            else:
                await utils.answer(message, text)
            return

        total = len(self.history.get_all())
        total_pages = (total + per_page - 1) // per_page

        if page < 1:
            page = 1
        elif page > total_pages:
            page = total_pages

        entries = self.history.get_page(page, per_page)

        lines = [
            f"<b>{self.ui.emoji('history')} {self.get_string('history_title')}</b>",
            f"━━━━━━━━━━━━━━━━━━━━━━\n",
            f"<b>{self.ui.emoji('pages')} {'Записи' if self.lang == 'ru' else 'Entries'} {(page-1)*per_page+1}-{min(page*per_page, total)} из {total}</b>\n"
        ]

        for i, e in enumerate(entries, (page-1)*per_page+1):
            dt_str = e.timestamp.strftime("%H:%M %d.%m UTC")
            status_emoji, _ = self.ui.get_status_emoji(e.stats)

            if e.scan_type == 'file':
                name = e.name or 'Unknown'
                if len(name) > 25:
                    name = name[:22] + '...'
                block_lines = [
                    f"<b>{i}.</b> {self.ui.emoji('file')} <b>{name}</b>",
                    f"   {self.ui.emoji('hash')} <code>{e.item_id}</code>",
                    f"   {self.ui.emoji('time')} <code>{dt_str}</code>",
                    f"   {status_emoji} <code>{e.stats.malicious}/{e.stats.total}</code>"
                ]
                lines.append(f"<blockquote>{chr(10).join(block_lines)}</blockquote>")
            
            elif e.scan_type == 'ip':
                flag = self.ui.country_flag(e.country_code) if e.country_code else '🏳️'
                display_name = e.as_owner if e.as_owner else e.name or 'Unknown'
                block_lines = [
                    f"<b>{i}.</b> {flag} <b>{display_name}</b>",
                    f"   {self.ui.emoji('url')} <code>{e.url or e.name}</code>",
                    f"   {self.ui.emoji('time')} <code>{dt_str}</code>",
                    f"   {status_emoji} <code>{e.stats.malicious}/{e.stats.total}</code>"
                ]
                lines.append(f"<blockquote>{chr(10).join(block_lines)}</blockquote>")
            
            else:
                url = e.url or 'Unknown'
                domain = urlparse(url).netloc if url else ''
                block_lines = [
                    f"<b>{i}.</b> {self.ui.emoji('globe')} <b>{domain}</b>",
                    f"   {self.ui.emoji('url')} <code>{url}</code>",
                    f"   {self.ui.emoji('time')} <code>{dt_str}</code>",
                    f"   {status_emoji} <code>{e.stats.malicious}/{e.stats.total}</code>"
                ]
                lines.append(f"<blockquote>{chr(10).join(block_lines)}</blockquote>")

        lines.append(f"\n<b>{self.get_string('history_entries')}: {total}/{self.config['max_history_items']}</b>")
        text = '\n'.join(lines)

        buttons = []
        nav_row = []
        if page > 1:
            nav_row.append({"text": f"{self.ui.emoji('left_arrow', premium=False)} {self.get_string('prev_page')}", "callback": self._inline_handlers.history_callback, "args": (page-1, return_id)})
        if page < total_pages:
            nav_row.append({"text": f"{self.get_string('next_page')} {self.ui.emoji('right_arrow', premium=False)}", "callback": self._inline_handlers.history_callback, "args": (page+1, return_id)})
        if nav_row:
            buttons.append(nav_row)

        action_row = [
            {"text": f"{self.ui.emoji('trash', premium=False)} {self.get_string('clear_history')}", "callback": self._inline_handlers.clear_confirm_callback},
            {"text": f"{self.ui.emoji('refresh', premium=False)} {self.get_string('refresh')}", "callback": self._inline_handlers.history_callback, "args": (page, return_id)}
        ]
        if return_id:
            action_row.append({"text": f"{self.ui.emoji('back_arrow', premium=False)} {self.get_string('back_to_results')}", "callback": self._inline_handlers.return_to_results_callback, "args": (return_id,)})
        buttons.append(action_row)

        if hasattr(message, 'edit'):
            await message.edit(text=text, reply_markup=buttons)
        else:
            await self.inline.form(text=text, message=message, reply_markup=buttons, ttl=300)

    async def _clear_history_callback(self, call):
        count = len(self.history.get_all())
        self.history.clear()
        text = (
            f"<b>{self.ui.emoji('trash')} {self.get_string('history_cleared')}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"<b>{self.ui.emoji('success')} {self.get_string('deleted_entries')}: {count}</b>"
        )
        buttons = [[{"text": f"{self.ui.emoji('history', premium=False)} {'История' if self.lang == 'ru' else 'History'}", "callback": self._inline_handlers.history_callback, "args": (1, None)}]]
        await call.edit(text=text, reply_markup=buttons)

    @loader.command(ru_doc="[файл/ссылка/IP] - просканировать файл, ссылку или IP-адрес", en_doc="[file/url/IP] - scan file, URL or IP address")
    async def vt(self, message):
        if not self.api:
            return await utils.answer(message, f"{self.ui.emoji('forbidden')} <b>{self.get_string('no_key')}</b>")
        
        reply = await message.get_reply_message()
        if reply and reply.document:
            msg = await utils.answer(message, f"<b>{self.ui.emoji('downloading')} {self.get_string('downloading')}</b>")
            msg_id = id(msg)
            start = time.time()
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, reply.file.name or 'file.bin')
                try:
                    await reply.download_media(path)
                except Exception as e:
                    await msg.edit(f"<b>{self.ui.emoji('error')} {self.get_string('download_error', error=str(e))}</b>")
                    return
                size = os.path.getsize(path)
                if size > self.MAX_SIZE:
                    await msg.edit(f"<b>{self.ui.emoji('forbidden')} {self.get_string('size_limit')}</b>")
                    return
                file_hash = self._calculate_hash(path)
                await msg.edit(f"<b>{self.ui.emoji('check')} {self.get_string('checking_cache')}</b>")
                existing = await self.api.get_file_report(file_hash)
                if existing:
                    await self._show_results(msg, file_hash, existing, 'file', name=reply.file.name, scan_time=int(time.time()-start), file_size=size)
                    return
                await msg.edit(f"<b>{self.ui.emoji('upload')} {self.get_string('uploading')}</b>")
                analysis_id = await self.api.upload_file(path)
                if not analysis_id:
                    await msg.edit(f"<b>{self.ui.emoji('error')} {self.get_string('upload_error')}</b>")
                    return
                await msg.edit(f"<b>{self.ui.emoji('waiting')} {self.get_string('waiting')}</b>")
                poll_result = await self._poll_analysis(analysis_id, msg, msg_id)
                if not poll_result:
                    await msg.edit(f"<b>{self.ui.emoji('timeout')} {self.get_string('timeout')}</b>")
                    return
                final = await self.api.get_file_report(file_hash)
                await self._show_results(msg, file_hash, final or poll_result, 'file', name=reply.file.name, scan_time=int(time.time()-start), file_size=size)
            return

        url = None
        args = utils.get_args_raw(message)
        if args:
            url = args.strip()
        if not url:
            if reply and reply.text:
                found = re.findall(r'https?://[^\s"\'<>]+', reply.text)
                if found:
                    url = found[0]
            if not url and message.text:
                found = re.findall(r'https?://[^\s"\'<>]+', message.text)
                if found:
                    url = found[0]
        if not url:
            return await utils.answer(message, f"{self.ui.emoji('forbidden')} <b>{self.get_string('no_url')}</b>")
        
        url = url.split('"')[0].split('>')[0].split('<')[0]

        if self._is_valid_ip(url):
            msg = await utils.answer(message, f"<b>{self.ui.emoji('globe')} Проверяю IP {url}...</b>")
            msg_id = id(msg)
            start = time.time()
            report = await self.api.get_ip_report(url)
            if report:
                await self._show_results(msg, url, report, 'ip', url=url, scan_time=int(time.time()-start))
            else:
                await msg.edit(f"<b>{self.ui.emoji('not_found')} {self.get_string('not_found')}</b>")
            return

        validated_url = self._validate_url(url)
        if not validated_url:
            return await utils.answer(message, f"{self.ui.emoji('error')} <b>{self.get_string('invalid_url')}</b>")
        
        url = validated_url

        msg = await utils.answer(message, f"<b>{self.ui.emoji('url')} {self.get_string('scanning_url')}</b>")
        msg_id = id(msg)
        start = time.time()
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        await msg.edit(f"<b>{self.ui.emoji('check')} {self.get_string('checking_cache')}</b>")
        existing = await self.api.get_url_report(url_id)
        if existing:
            await self._show_results(msg, url_id, existing, 'url', url=url, scan_time=int(time.time()-start))
            return
        await msg.edit(f"<b>{self.ui.emoji('waiting')} {self.get_string('waiting')}</b>")
        scan = await self.api.scan_url(url)
        if not scan:
            await msg.edit(f"<b>{self.ui.emoji('error')} {self.get_string('scan_error')}</b>")
            return
        analysis_id = scan.get('data', {}).get('id')
        if not analysis_id:
            await msg.edit(f"<b>{self.ui.emoji('error')} {self.get_string('scan_error')}</b>")
            return
        poll_result = await self._poll_analysis(analysis_id, msg, msg_id)
        if not poll_result:
            await msg.edit(f"<b>{self.ui.emoji('timeout')} {self.get_string('timeout')}</b>")
            return
        final = await self.api.get_url_report(url_id)
        await self._show_results(msg, url_id, final or poll_result, 'url', url=url, scan_time=int(time.time()-start))

    @loader.command(ru_doc="[хеш] - проверить по хешу", en_doc="[hash] - check by hash")
    async def vthash(self, message):
        if not self.api:
            return await utils.answer(message, f"{self.ui.emoji('forbidden')} <b>{self.get_string('no_key')}</b>")

        args = utils.get_args_raw(message)
        if not args:
            return await utils.answer(message, f"{self.ui.emoji('error')} <b>{self.get_string('specify_hash')}</b>")

        file_hash = args.strip().lower()

        if re.match(r'^[a-f0-9]{64}$', file_hash):
            hash_type = 'SHA256'
        elif re.match(r'^[a-f0-9]{32}$', file_hash):
            hash_type = 'MD5'
        else:
            found = self.history.find_by_hash(file_hash)
            if found:
                lines = [
                    f"<b>{self.ui.emoji('check')} {self.get_string('history_search')}</b>\n<code>━━━━━━━━━━━━━━━━━━━━━━</code>\n\n"
                    f"{self.get_string('search_results', count=len(found), hash=file_hash)}\n"
                ]
                for i, e in enumerate(found[:5], 1):
                    dt_str = e.timestamp.strftime("%H:%M %d.%m UTC")
                    if e.scan_type == 'ip' and e.as_owner:
                        flag = self.ui.country_flag(e.country_code) if e.country_code else '🏳️'
                        name = f"{flag} {e.as_owner}"
                    else:
                        name = e.name or e.url or 'Unknown'
                    lines.append(f"{i}. {self.ui.emoji('file') if e.scan_type=='file' else self.ui.emoji('url')} {name[:30]}")
                    lines.append(f"   {self.ui.emoji('time')} {dt_str}\n")
                if len(found) > 5:
                    lines.append(self.get_string('and_more', count=len(found)-5))
                lines.append(self.get_string('use_full_hash'))
                return await self.inline.form(
                    text='\n'.join(lines),
                    message=message,
                    reply_markup=[[{
                        "text": f"{self.ui.emoji('history', premium=False)} {'История' if self.lang=='ru' else 'History'}",
                        "callback": self._inline_handlers.history_callback,
                        "args": (1, None)
                    }]],
                    ttl=60
                )
            return await utils.answer(message, f"{self.ui.emoji('error')} <b>{self.get_string('hash_not_found')}</b>")

        msg = await utils.answer(message, f"<b>{self.ui.emoji('hash')} {self.get_string('checking_hash')}</b>")
        msg_id = id(msg)
        start = time.time()

        await msg.edit(f"<b>{self.ui.emoji('check')} {self.get_string('searching_report', type=hash_type)}</b>")
        report = await self.api.get_file_report(file_hash)

        if report:
            await self._show_results(msg, file_hash, report, 'file', name=f"{self.get_string('hash')}: {file_hash[:16]}...", scan_time=int(time.time()-start))
        else:
            await msg.edit(f"<b>{self.ui.emoji('not_found')} {self.get_string('not_found')}</b>")

    @loader.command(ru_doc="[страница] - показать историю", en_doc="[page] - show history")
    async def vthistory(self, message):
        if not self.history.get_all():
            return await utils.answer(message, f"{self.ui.emoji('history_empty')} <b>{self.get_string('history_empty')}</b>")

        try:
            page = int(utils.get_args_raw(message) or 1)
        except:
            page = 1

        await self._show_history_page(message, page)

    @loader.command(ru_doc=" - очистить историю", en_doc=" - clear history")
    async def vtclear(self, message):
        count = len(self.history.get_all())
        if count == 0:
            return await utils.answer(message, f"{self.ui.emoji('history_empty')} <b>{self.get_string('history_empty')}</b>")

        self.history.clear()
        await utils.answer(message, f"{self.ui.emoji('trash')} <b>{self.get_string('history_cleared')}</b>. {self.ui.emoji('success')} <b>{self.get_string('deleted_entries')}: {count}</b>")

    @loader.command(ru_doc=" - сменить язык", en_doc=" - change language")
    async def vtlang(self, message):
        args = utils.get_args_raw(message)

        if not args:
            text = (
                f"<b>{self.ui.emoji('globe')} {self.get_string('current_language')}: {'Русский' if self.lang=='ru' else 'English'}</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"<b>{self.get_string('available_languages')}:</b>\n"
                f"• <code>.vtlang ru</code> - {self.get_string('russian')}\n"
                f"• <code>.vtlang en</code> - {self.get_string('english')}\n\n"
                f"<b>{self.get_string('current_setting')}:</b>\n"
                f"language: {self.config['language']}"
            )
            await self.inline.form(
                text=text,
                message=message,
                reply_markup=[[
                    {"text": f"{self.ui.emoji('flag_ru', premium=False)} Русский", "callback": self._inline_handlers.change_language_callback, "args": ("ru",)},
                    {"text": f"{self.ui.emoji('flag_gb', premium=False)} English", "callback": self._inline_handlers.change_language_callback, "args": ("en",)}
                ]],
                ttl=60
            )
            return

        lang = args.strip().lower()
        if lang in ('ru', 'en'):
            self.config['language'] = lang
            self.lang = lang
            self.ui.lang = lang
            await utils.answer(message, f"{self.ui.emoji('success')} <b>{'Язык изменен на Русский' if lang=='ru' else 'Language changed to English'}</b>")
        else:
            await utils.answer(message, f"{self.ui.emoji('error')} <b>{'Неверный язык. Используйте: ru или en' if self.lang=='ru' else 'Invalid language. Use: ru or en'}</b>")
