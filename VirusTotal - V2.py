# Author TG: @monkvy
# Version: 2.0.3
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
from datetime import datetime, timezone
from urllib.parse import urlparse

import aiohttp

from .. import loader, utils

logger = logging.getLogger(__name__)

@loader.tds
class VirusTotalMod(loader.Module):
    strings = {
        "name": "VirusTotal",
    }

    strings_ru = {
        "no_file": "<b>Ответьте на файл</b>",
        "no_url": "<b>Укажите ссылку после команды</b>",
        "invalid_url": "<b>Неверный формат ссылки</b>",
        "downloading": "Скачиваю файл...",
        "uploading": "Загружаю на VirusTotal...",
        "scanning_url": "Сканирую ссылку...",
        "scanning": "Сканирование начато",
        "waiting": "Жду анализа...",
        "no_key": "<b>Укажите API ключ в конфиге</b>",
        "error": "Ошибка при сканировании",
        "size_limit": "<b>Файл больше 32МБ</b>",
        "timeout": "Таймаут сканирования (слишком долгое ожидание)",
        "view_report": "Полный отчёт",
        "analysis_timeout": "Анализ занимает больше времени, чем ожидалось",
        "file_too_large": "<b>Файл слишком большой</b>",
        "api_limit": "Лимит API исчерпан",
        "checking_report": "Проверяю существующий отчет...",
        "scan_started": "Сканирование начато",
        "file_not_found": "<b>Файл не найден</b>",
        "rate_limit": "<b>Превышен лимит запросов. Подождите 60 секунд</b>",
        "getting_results": "Получаю результаты...",
        "please_wait": "Пожалуйста, подождите...",
        "history_empty": "История сканирований пуста",
        "history_cleared": "История очищена",
        "history_entries": "Всего записей",
        "history_max": "максимум",
        "clear_history": "Очистить",
        "hash_check": "Проверить по хешу",
        "history_search": "Поиск в истории",
        "invalid_history_limit": "❌ Должно быть целым числом в промежутке от 1 до 30",
        "history_limit_set": "✅ Лимит истории установлен на",
        "history_settings": "Настройки истории",
        "current_limit": "Текущий лимит",
        "entries": "записей",
        "set_history_limit": "Установить лимит истории",
        "delete_entry": "Удалить запись",
        "entry_deleted": "✅ Запись удалена",
        "cancel": "Отмена",
        "confirm_clear": "Подтвердить очистку",
        "clear_all_history": "Очистить всю историю",
        "clear_history_confirm": "⚠️ Вы уверены, что хотите очистить всю историю?\nЭто действие нельзя отменить.",
        "scan_details": "Детали сканирования",
        "prev_page": "Назад",
        "next_page": "Вперед",
        "page_info": "Страница",
        "refresh": "Обновить",
        "first_page": "Первая",
        "last_page": "Последняя",
        "back_to_results": "Обратно",
        "file": "Файл",
        "url": "Ссылка",
        "hash": "Хеш",
        "domain": "Домен",
        "scans": "сканирований",
        "engines": "движков",
        "clean": "чистый",
        "dangerous": "опасный",
        "very_dangerous": "очень опасный",
        "suspicious": "подозрительный",
        "likely_safe": "вероятно безопасный",
        "high_risk": "высокий риск",
        "low_risk": "низкий риск",
        "threats": "Угроз",
        "detected": "обнаружено",
        "status": "Статус",
        "safe": "безопасно",
        "results": "Результаты",
        "malicious": "Вредоносные",
        "harmless": "Безвредные",
        "undetected": "Не обнаружено",
        "uploading_file": "Загрузка файла...",
        "checking_cache": "Проверка кэша...",
        "completing": "Завершение...",
        "error_title": "Ошибка",
        "timeout_title": "Таймаут",
        "not_found": "Не найден",
        "report_not_found": "Отчет не найден. Файл не был сканирован ранее.",
        "hash_not_found": "Неверный формат хеша. Используйте SHA256 (64 символа) или MD5 (32 символа)",
        "specify_hash": "Укажите хеш файла (SHA256 или MD5)",
        "search_results": "Найдено {count} записей с хешем {hash}:",
        "and_more": "... и еще {count} записей",
        "use_full_hash": "Используйте полный хеш для проверки:\n<code>.vthash [полный_хеш]</code>",
        "current_language": "Текущий язык",
        "available_languages": "Доступные языки",
        "russian": "Русский (по умолчанию)",
        "english": "Английский",
        "current_setting": "Текущая настройка",
        "yes_clear": "Да, очистить",
        "deleted_entries": "Удалено записей",
        "file_by_hash": "По хешу",
        "by_hash": "По хешу {type}",
        "checking_hash": "Проверка хеша...",
        "searching_report": "Поиск отчета по {type} хешу...",
        "upload_error": "Ошибка загрузки",
        "scan_error": "Ошибка сканирования",
        "scan_title": "Сканирование VirusTotal",
        "results_title": "Результаты сканирования VirusTotal",
        "history_title": "История сканирований VirusTotal",
    }

    strings_en = {
        "no_file": "<b>Reply to a file</b>",
        "no_url": "<b>Specify URL after command</b>",
        "invalid_url": "<b>Invalid URL format</b>",
        "downloading": "Downloading file...",
        "uploading": "Uploading to VirusTotal...",
        "scanning_url": "Scanning URL...",
        "scanning": "Scan started",
        "waiting": "Waiting for analysis",
        "no_key": "<b>Set API key in config</b>",
        "error": "Error during scanning",
        "size_limit": "<b>File is larger than 32MB</b>",
        "timeout": "Scan timeout (waiting too long)",
        "view_report": "Full report",
        "analysis_timeout": "Analysis takes longer than expected",
        "file_too_large": "<b>File is too large</b>",
        "api_limit": "API limit exceeded",
        "checking_report": "Checking existing report...",
        "scan_started": "Scan started",
        "file_not_found": "<b>File not found</b>",
        "rate_limit": "<b>Rate limit exceeded. Wait 60 seconds</b>",
        "getting_results": "Getting results...",
        "please_wait": "Please wait...",
        "history_empty": "Scan history is empty",
        "history_cleared": "History cleared",
        "history_entries": "Total entries",
        "history_max": "maximum",
        "clear_history": "Clear",
        "hash_check": "Check by hash",
        "history_search": "History search",
        "invalid_history_limit": "❌ Must be integer between 1 and 30",
        "history_limit_set": "✅ History limit set to",
        "history_settings": "History settings",
        "current_limit": "Current limit",
        "entries": "entries",
        "set_history_limit": "Set history limit",
        "delete_entry": "Delete entry",
        "entry_deleted": "✅ Entry deleted",
        "cancel": "Cancel",
        "confirm_clear": "Confirm clear",
        "clear_all_history": "Clear all history",
        "clear_history_confirm": "⚠️ Are you sure you want to clear all history?\nThis action cannot be undone.",
        "scan_details": "Scan details",
        "prev_page": "Back",
        "next_page": "Forward",
        "page_info": "Page",
        "refresh": "Refresh",
        "first_page": "First",
        "last_page": "Last",
        "back_to_results": "Back",
        "file": "File",
        "url": "URL",
        "hash": "Hash",
        "domain": "Domain",
        "scans": "scans",
        "engines": "engines",
        "clean": "clean",
        "dangerous": "dangerous",
        "very_dangerous": "very dangerous",
        "suspicious": "suspicious",
        "likely_safe": "likely safe",
        "high_risk": "high risk",
        "low_risk": "low risk",
        "threats": "Threats",
        "detected": "detected",
        "status": "Status",
        "safe": "safe",
        "results": "Results",
        "malicious": "Malicious",
        "harmless": "Harmless",
        "undetected": "Undetected",
        "uploading_file": "Uploading file...",
        "checking_cache": "Checking cache...",
        "completing": "Completing...",
        "error_title": "Error",
        "timeout_title": "Timeout",
        "not_found": "Not found",
        "report_not_found": "Report not found. File hasn't been scanned before.",
        "hash_not_found": "Invalid hash format. Use SHA256 (64 chars) or MD5 (32 chars)",
        "specify_hash": "Specify file hash (SHA256 or MD5)",
        "search_results": "Found {count} entries with hash {hash}:",
        "and_more": "... and {count} more entries",
        "use_full_hash": "Use full hash for check:\n<code>.vthash [full_hash]</code>",
        "current_language": "Current language",
        "available_languages": "Available languages",
        "russian": "Russian (default)",
        "english": "English",
        "current_setting": "Current setting",
        "yes_clear": "Yes, clear",
        "deleted_entries": "Deleted entries",
        "file_by_hash": "By hash",
        "by_hash": "By hash {type}",
        "checking_hash": "Checking hash...",
        "searching_report": "Searching report by {type} hash...",
        "upload_error": "Upload error",
        "scan_error": "Scan error",
        "scan_title": "VirusTotal Scanning",
        "results_title": "VirusTotal Scan Results",
        "history_title": "VirusTotal Scan History",
    }

    LOW_RISK_THRESHOLD = 0.02
    MEDIUM_RISK_THRESHOLD = 0.05
    HIGH_RISK_THRESHOLD = 0.15

    def __init__(self):
        self.config = loader.ModuleConfig(
            loader.ConfigValue(
                "api_key",
                None,
                "VirusTotal API key from https://virustotal.com",
                validator=loader.validators.Hidden(),
            ),
            loader.ConfigValue(
                "max_wait_time",
                300,
                "Maximum wait time in seconds",
                validator=loader.validators.Integer(minimum=60, maximum=600),
            ),
            loader.ConfigValue(
                "poll_interval",
                10,
                "Polling interval in seconds",
                validator=loader.validators.Integer(minimum=5, maximum=30),
            ),
            loader.ConfigValue(
                "save_history",
                True,
                "Save scan history",
                validator=loader.validators.Boolean(),
            ),
            loader.ConfigValue(
                "max_history_items",
                10,
                "Maximum number of entries in history",
                validator=loader.validators.Integer(minimum=1, maximum=10),
            ),
            loader.ConfigValue(
                "history_items_per_page",
                5,
                "Number of entries per page",
                validator=loader.validators.Integer(minimum=3, maximum=10),
            ),
            loader.ConfigValue(
                "language",
                "ru",
                "Language (ru/en)",
                validator=loader.validators.Choice(["ru", "en"]),
            ),
        )
        self.session = None
        self.MAX_SIZE = 32 * 1024 * 1024
        self.last_message_content = {}
        self.scan_history = {}
        self._current_language = None
        self._inline_msgs = {}

    async def client_ready(self, client, db):
        self._client = client
        self._db = db
        
        if self.config["save_history"]:
            self.scan_history = self._db.get(__name__, "scan_history", {})
        
        self._current_language = self.config["language"]

    def get_string(self, key, **kwargs):
        lang_dict = self.strings_ru if self._current_language == 'ru' else self.strings_en
        text = lang_dict.get(key, key)
        
        if kwargs:
            return text.format(**kwargs)
        return text

    def _get_premium_emoji(self, name):
        emojis = {
            'file': "<emoji document_id=5433653135799228968>📁</emoji>",
            'url': "<emoji document_id=5271604874419647061>🔗</emoji>",
            'size': "<emoji document_id=5784891605601225888>📦</emoji>",
            'time': "<emoji document_id=5382194935057372936>⏱️</emoji>",
            'engines': "<emoji document_id=5195033767969839232>🚀</emoji>",
            'scans': "<emoji document_id=5444965061749644170>👥</emoji>",
            'progress': "<emoji document_id=5386367538735104399>⏳</emoji>",
            'refresh': "<emoji document_id=5818740758257077530>🔄</emoji>",
            'stats': "<emoji document_id=5231200819986047254>📊</emoji>",
            'shield': "<emoji document_id=5251203410396458957>🛡</emoji>",
            'check': "<emoji document_id=5231012545799666522>🔍</emoji>",
            'success': "<emoji document_id=5206607081334906820>✅️</emoji>",
            'error': "<emoji document_id=5210952531676504517>❌️</emoji>",
            'warning': "<emoji document_id=5447644880824181073>⚠️</emoji>",
            'danger': "<emoji document_id=5260293700088511294>⛔️</emoji>",
            'skull': "<emoji document_id=5370842086658546991>☠️</emoji>",
            'history': "<emoji document_id=5197269100878907942>📋</emoji>",
            'pages': "<emoji document_id=5253742260054409879>📄</emoji>",
            'hash': "<emoji document_id=5343824560523322473>🔢</emoji>",
            'upload': "<emoji document_id=5433614747381538714>📤</emoji>",
            'globe': "<emoji document_id=5447410659077661506>🌐</emoji>",
            'chart': "<emoji document_id=5244837092042750681>📈</emoji>",
            'forbidden': "<emoji document_id=5240241223632954241>🚫</emoji>",
            'trash': "<emoji document_id=5445267414562389170>🗑</emoji>",
            'history_empty': "<emoji document_id=5352896944496728039>📭</emoji>",
            'downloading': "<emoji document_id=5433653135799228968>📥</emoji>",
            'waiting': "<emoji document_id=5386367538735104399>⏳</emoji>",
            'timeout': "<emoji document_id=5382194935057372936>⏰</emoji>",
        }
        return emojis.get(name, "")

    def _get_normal_emoji(self, name):
        emojis = {
            'file': "📁",
            'url': "🔗",
            'size': "📦",
            'time': "⏱️",
            'engines': "🚀",
            'scans': "👥",
            'progress': "⏳",
            'refresh': "🔄",
            'stats': "📊",
            'shield': "🛡",
            'check': "🔍",
            'success': "✅",
            'error': "❌",
            'warning': "⚠️",
            'danger': "⛔",
            'skull': "☠️",
            'history': "📋",
            'pages': "📄",
            'hash': "🔢",
            'upload': "📤",
            'globe': "🌐",
            'chart': "📈",
            'forbidden': "🚫",
            'trash': "🗑",
            'history_empty': "📭",
            'left_arrow': "⬅️",
            'right_arrow': "➡️",
            'link': "🔗",
            'flag_ru': "🇷🇺",
            'flag_gb': "🇬🇧",
            'back_arrow': "↩️",
            'cancel': "🚫",
            'downloading': "📥",
            'waiting': "⏳",
            'timeout': "⏰",
        }
        return emojis.get(name, "")

    async def on_unload(self):
        if self.config["save_history"]:
            self._db.set(__name__, "scan_history", self.scan_history)
        
        if self.session and not self.session.closed:
            await self.session.close()

    def _get_session(self):
        if not self.session or self.session.closed:
            headers = {"x-apikey": self.config["api_key"]}
            self.session = aiohttp.ClientSession(headers=headers)
        return self.session

    def _validate_url(self, url):
        return bool(re.match(r'^https?://[^\s/$.?#].[^\s]*$', url, re.IGNORECASE))

    def _calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _format_size(self, size_bytes):
        units = ['B', 'KB', 'MB', 'GB']
        ru_units = ['Б', 'КБ', 'МБ', 'ГБ']
        
        size = size_bytes
        unit_index = 0
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        if self._current_language == 'ru':
            return f"{size:.1f} {ru_units[unit_index]}" if unit_index > 0 else f"{size:.0f} {ru_units[0]}"
        else:
            return f"{size:.1f} {units[unit_index]}" if unit_index > 0 else f"{size:.0f} {units[0]}"

    def _format_time(self, seconds):
        if seconds < 60:
            return f"{seconds} {'сек' if self._current_language == 'ru' else 'sec'}"
        else:
            minutes = seconds // 60
            remaining_seconds = seconds % 60
            if remaining_seconds == 0:
                return f"{minutes} {'мин' if self._current_language == 'ru' else 'min'}"
            return f"{minutes} {'мин' if self._current_language == 'ru' else 'min'} {remaining_seconds} {'сек' if self._current_language == 'ru' else 'sec'}"

    def _get_history_status(self, malicious, suspicious, total):
        premium_warning = self._get_premium_emoji('warning')
        premium_danger = self._get_premium_emoji('danger')
        premium_skull = self._get_premium_emoji('skull')
        premium_success = self._get_premium_emoji('success')
        
        if malicious > 0:
            detection_ratio = malicious / total if total > 0 else 0
            
            if detection_ratio < self.LOW_RISK_THRESHOLD:
                return premium_warning, f"{premium_warning} <code>{malicious}/{total} ({self.get_string('low_risk')})</code>"
            elif detection_ratio < self.MEDIUM_RISK_THRESHOLD:
                return premium_warning, f"{premium_warning} <code>{malicious}/{total} ({self.get_string('suspicious')})</code>"
            elif detection_ratio < self.HIGH_RISK_THRESHOLD:
                return premium_danger, f"{premium_danger} <code>{malicious}/{total} ({self.get_string('dangerous')})</code>"
            else:
                return premium_skull, f"{premium_skull} <code>{malicious}/{total} ({self.get_string('high_risk')})</code>"
        elif suspicious > 0:
            return premium_warning, f"{premium_warning} <code>{suspicious}/{total} {self.get_string('suspicious')}</code>"
        else:
            return premium_success, f"{premium_success} <code>{total} {self.get_string('engines')}</code>"

    def _save_to_history(self, item_id, result, scan_type, name=None, url=None, stats=None):
        if not self.config["save_history"]:
            return
            
        try:
            if scan_type == "file":
                data = result.get("data", {})
                attributes = data.get("attributes", {})
                last_stats = attributes.get("last_analysis_stats", {})
            else:
                data = result.get("data", {})
                attributes = data.get("attributes", {})
                last_analysis_results = attributes.get("last_analysis_results", {}) or {}
                
                malicious = suspicious = harmless = undetected = 0
                
                for engine_result in last_analysis_results.values():
                    category = engine_result.get("category", "")
                    if category == "malicious":
                        malicious += 1
                    elif category == "suspicious":
                        suspicious += 1
                    elif category == "harmless":
                        harmless += 1
                    elif category == "undetected":
                        undetected += 1
                
                last_stats = {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total": len(last_analysis_results)
                }
            
            if stats:
                last_stats = stats
            
            self.scan_history[item_id] = {
                'timestamp': time.time(),
                'result': result,
                'type': scan_type,
                'name': name,
                'url': url,
                'stats': last_stats
            }
            
            max_items = self.config["max_history_items"]
            if len(self.scan_history) > max_items:
                oldest_items = sorted(self.scan_history.items(), key=lambda x: x[1]['timestamp'])
                for old_id, _ in oldest_items[:len(self.scan_history) - max_items]:
                    del self.scan_history[old_id]
            
            self._db.set(__name__, "scan_history", self.scan_history)
        except Exception:
            pass

    async def _safe_edit(self, msg, text, msg_id=None):
        try:
            if msg_id is None:
                msg_id = id(msg)
            
            if msg_id in self.last_message_content and self.last_message_content[msg_id] == text:
                return msg
            
            await msg.edit(text)
            self.last_message_content[msg_id] = text
            return msg
        except Exception:
            return msg

    async def _poll_analysis(self, session, analysis_id, msg, start_time, msg_id, filename=None, url=None, file_size=None, scan_type="file"):
        poll_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        max_wait_time = self.config["max_wait_time"]
        poll_interval = self.config["poll_interval"]
        max_attempts = max_wait_time // poll_interval
        
        for attempt in range(max_attempts):
            try:
                async with session.get(poll_url) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get("data", {}).get("attributes", {}).get("status") == "completed":
                            return data
                await asyncio.sleep(poll_interval)
            except Exception:
                await asyncio.sleep(poll_interval)
        
        return None

    async def _check_existing_report(self, session, file_hash):
        try:
            async with session.get(f"https://www.virustotal.com/api/v3/files/{file_hash}") as response:
                return await response.json() if response.status == 200 else None
        except:
            return None

    async def _upload_file(self, session, path):
        try:
            with open(path, "rb") as f:
                form = aiohttp.FormData()
                form.add_field("file", f, filename=os.path.basename(path))

                async with session.post("https://www.virustotal.com/api/v3/files", data=form) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("data", {}).get("id")
        except Exception:
            pass
        return None

    async def _get_file_report(self, session, file_hash):
        try:
            async with session.get(f"https://www.virustotal.com/api/v3/files/{file_hash}") as response:
                return await response.json() if response.status == 200 else None
        except:
            return None

    async def _get_url_report(self, session, url_encoded):
        try:
            async with session.get(f"https://www.virustotal.com/api/v3/urls/{url_encoded}") as response:
                return await response.json() if response.status == 200 else None
        except:
            return None

    async def _scan_url(self, session, url):
        try:
            url_encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            async with session.get(f"https://www.virustotal.com/api/v3/urls/{url_encoded}") as response:
                if response.status == 200:
                    return {"type": "existing", "id": url_encoded}
            
            form = aiohttp.FormData()
            form.add_field("url", url)
            
            async with session.post("https://www.virustotal.com/api/v3/urls", data=form) as response:
                if response.status == 200:
                    data = await response.json()
                    return {"type": "new", "id": data.get("data", {}).get("id")}
                elif response.status == 429:
                    return {"type": "error", "error": "rate_limit"}
                else:
                    return {"type": "error", "error": f"http_{response.status}"}
        except Exception as e:
            logger.error(f"Error scanning URL: {e}")
            return {"type": "error", "error": str(e)}

    async def _show_results(self, message, item_id, result, scan_type, original_url=None, original_filename=None, scan_time=0, file_size=0, progress_msg=None):
        try:
            malicious = suspicious = harmless = undetected = popularity = 0
            
            data = result.get("data", {})
            attributes = data.get("attributes", {})
            
            if scan_type == "file":
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)
                popularity = attributes.get("times_submitted", 0)
                
                last_results = attributes.get("last_analysis_results", {})
                if last_results:
                    harmless = undetected = malicious = suspicious = 0
                    for res in last_results.values():
                        cat = res.get("category", "")
                        if cat == "malicious":
                            malicious += 1
                        elif cat == "suspicious":
                            suspicious += 1
                        elif cat == "harmless":
                            harmless += 1
                        elif cat == "undetected":
                            undetected += 1
            else:
                popularity = attributes.get("times_submitted", 0)
                last_results = attributes.get("last_analysis_results", {}) or {}
                
                for res in last_results.values():
                    cat = res.get("category", "")
                    if cat == "malicious":
                        malicious += 1
                    elif cat == "suspicious":
                        suspicious += 1
                    elif cat == "harmless":
                        harmless += 1
                    elif cat == "undetected":
                        undetected += 1
            
            total_engines = malicious + suspicious + undetected + harmless
            malicious_percent = round((malicious / total_engines * 100), 1) if total_engines > 0 else 0
            suspicious_percent = round((suspicious / total_engines * 100), 1) if total_engines > 0 else 0
            harmless_percent = round((harmless / total_engines * 100), 1) if total_engines > 0 else 0
            undetected_percent = round((undetected / total_engines * 100), 1) if total_engines > 0 else 0
            safety_percent = round(((harmless + undetected) / total_engines * 100), 1) if total_engines > 0 else 0
            
            if malicious > 0:
                detection_ratio = malicious / total_engines if total_engines > 0 else 0
                if detection_ratio < self.LOW_RISK_THRESHOLD and safety_percent > 97:
                    status_text = self.get_string('likely_safe')
                    status_emoji = self._get_premium_emoji('success')
                    threats_emoji = self._get_premium_emoji('warning')
                elif detection_ratio < self.MEDIUM_RISK_THRESHOLD and safety_percent > 90:
                    status_text = self.get_string('suspicious')
                    status_emoji = self._get_premium_emoji('warning')
                    threats_emoji = self._get_premium_emoji('warning')
                elif detection_ratio < self.HIGH_RISK_THRESHOLD:
                    status_text = self.get_string('dangerous')
                    status_emoji = self._get_premium_emoji('danger')
                    threats_emoji = self._get_premium_emoji('danger')
                else:
                    status_text = self.get_string('very_dangerous')
                    status_emoji = self._get_premium_emoji('skull')
                    threats_emoji = self._get_premium_emoji('skull')
            elif suspicious > 0:
                status_text = self.get_string('suspicious')
                status_emoji = self._get_premium_emoji('warning')
                threats_emoji = self._get_premium_emoji('warning')
            else:
                status_text = self.get_string('clean')
                status_emoji = self._get_premium_emoji('success')
                threats_emoji = self._get_premium_emoji('success')
            
            if scan_type == "file":
                vt_url = f"https://www.virustotal.com/gui/file/{item_id}"
                filename_display = f"{original_filename[:27]}..." if original_filename and len(original_filename) > 30 else (original_filename or f"{self.get_string('hash')}: {item_id[:16]}...")
                
                scan_info_lines = [
                    f"• {self._get_premium_emoji('file')} <b>{self.get_string('file')}:</b> <code>{filename_display}</code>"
                ]
                if file_size > 0:
                    scan_info_lines.append(f"• {self._get_premium_emoji('size')} <code>{self._format_size(file_size)}</code>")
                scan_info_lines.extend([
                    f"• {self._get_premium_emoji('time')} <code>{self._format_time(scan_time)}</code>",
                    f"• {self._get_premium_emoji('engines')} <code>{total_engines} {self.get_string('engines')}</code>",
                    f"• {self._get_premium_emoji('scans')} <code>{popularity} {self.get_string('scans')}</code>"
                ])
                scan_info = "\n".join(scan_info_lines)
            else:
                url_encoded = base64.urlsafe_b64encode(original_url.encode()).decode().strip("=") if original_url else item_id
                vt_url = f"https://www.virustotal.com/gui/url/{url_encoded}"
                
                try:
                    domain = urlparse(original_url).netloc if original_url else ''
                    if not domain:
                        domain = self.get_string('domain')
                except:
                    domain = ''
                
                url_display = f"{original_url[:37]}..." if original_url and len(original_url) > 40 else (original_url or '')
                
                scan_info = "\n".join([
                    f"• {self._get_premium_emoji('url')} <b>{self.get_string('url')}:</b> <code>{url_display}</code>",
                    f"• {self._get_premium_emoji('globe')} <b>{self.get_string('domain')}:</b> <code>{domain}</code>",
                    f"• {self._get_premium_emoji('time')} <code>{self._format_time(scan_time)}</code>",
                    f"• {self._get_premium_emoji('engines')} <code>{total_engines} {self.get_string('engines')}</code>",
                    f"• {self._get_premium_emoji('scans')} <code>{popularity} {self.get_string('scans')}</code>"
                ])

            text = "\n".join([
                f"<b>{self._get_premium_emoji('shield')} {self.get_string('results_title')}</b>",
                f"━━━━━━━━━━━━━━━━━━━━━━",
                f"{scan_info}",
                "",
                f"{status_emoji} <b>{self.get_string('status')}:</b> <code>{status_text} ({safety_percent}% {self.get_string('safe')})</code>",
                f"{threats_emoji} <b>{self.get_string('threats')}:</b> <code>{malicious} {self.get_string('detected')}</code>",
                "",
                f"<b>{self._get_premium_emoji('chart')} {self.get_string('results')}:</b>",
                f"<blockquote>🚫<code>{malicious}/{total_engines} ({malicious_percent}%)│{self.get_string('malicious')}</code>\n⚠️<code>{suspicious}/{total_engines} ({suspicious_percent}%)│{self.get_string('suspicious')}</code>\n{self._get_premium_emoji('success')}<code>{harmless}/{total_engines} ({harmless_percent}%)│{self.get_string('harmless')}</code>\n👁️<code>{undetected}/{total_engines} ({undetected_percent}%)│{self.get_string('undetected')}</code></blockquote>"
            ])

            self._save_to_history(
                item_id=item_id,
                result=result,
                scan_type=scan_type,
                name=original_filename if scan_type == "file" else None,
                url=original_url if scan_type == "url" else None,
                stats={
                    'malicious': malicious, 
                    'suspicious': suspicious, 
                    'harmless': harmless, 
                    'undetected': undetected, 
                    'total': total_engines
                }
            )

            if progress_msg:
                try:
                    await progress_msg.delete()
                except:
                    pass

            message_id = message.id
            return_data = {
                'item_id': item_id,
                'result': result,
                'scan_type': scan_type,
                'original_url': original_url,
                'original_filename': original_filename,
                'scan_time': scan_time,
                'file_size': file_size,
                'text': text,
                'vt_url': vt_url
            }
            self._db.set(__name__, f"result_{message_id}", return_data)

            await self.inline.form(
                text=text,
                message=message,
                reply_markup=[
                    [{"text": f"{self._get_normal_emoji('link')} {self.get_string('view_report')}", "url": vt_url}],
                    [{"text": f"{self._get_normal_emoji('history')} {'История' if self._current_language == 'ru' else 'History'}", 
                      "callback": self._history_from_results_callback, "args": (1, message_id)}],
                ],
                ttl=300,
            )
        except Exception as e:
            error_text = f"{self._get_premium_emoji('error')} {self.get_string('error')}: {str(e)}"
            await utils.answer(message, error_text)

    async def _show_history_page(self, message, page_num=1, return_message_id=None):
        if not self.scan_history:
            if hasattr(message, 'edit') and callable(getattr(message, 'edit')):
                text = f"{self._get_premium_emoji('history_empty')} <b>{self.get_string('history_empty')}</b>"
                await message.edit(text=text, reply_markup=None)
                if hasattr(message, 'answer'):
                    await message.answer(f"{self._get_normal_emoji('history_empty')} {self.get_string('history_empty')}")
            else:
                await utils.answer(message, f"{self._get_premium_emoji('history_empty')} <b>{self.get_string('history_empty')}</b>")
            return
        
        sorted_history = sorted(self.scan_history.items(), key=lambda x: x[1]['timestamp'], reverse=True)
        items_per_page = self.config["history_items_per_page"]
        total_items = len(sorted_history)
        total_pages = (total_items + items_per_page - 1) // items_per_page
        
        if page_num > total_pages:
            if hasattr(message, 'answer'):
                await message.answer(f"{self._get_normal_emoji('warning')} Страницы {page_num} не существует. Показана последняя страница.")
            page_num = total_pages
        elif page_num < 1:
            page_num = 1
        
        current_page = page_num
        
        start_idx = (current_page - 1) * items_per_page
        page_items = sorted_history[start_idx:start_idx + items_per_page]
        
        text_lines = [
            f"<b>{self._get_premium_emoji('history')} {self.get_string('history_title')}</b>",
            f"━━━━━━━━━━━━━━━━━━━━━━",
            "",
            f"<b>{self._get_premium_emoji('pages')} {'Записи' if self._current_language == 'ru' else 'Entries'} {start_idx + 1}-{min(start_idx + items_per_page, total_items)} из {total_items}</b>",
            ""
        ]
        
        for i, (item_id, data) in enumerate(page_items, start_idx + 1):
            dt = datetime.fromtimestamp(data['timestamp'], timezone.utc)
            timestamp = dt.strftime("%H:%M %d.%m UTC")
            
            if data['type'] == 'file':
                icon = self._get_premium_emoji('file')
                name = data.get('name', 'Неизвестный файл' if self._current_language == 'ru' else 'Unknown file')
                if len(name) > 25:
                    name = name[:22] + "..."
                
                block_content = f"<b>{i}.</b> {icon} <b>{name}</b>\n   {self._get_premium_emoji('hash')} <code>{item_id}</code>\n   {self._get_premium_emoji('time')} <code>{timestamp}</code>"
                
                stats = data.get('stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = stats.get('total', 0)
                
                _, status_text = self._get_history_status(malicious, suspicious, total)
                block_content += f"\n   {status_text}"
                
                text_lines.append(f"<blockquote>{block_content}</blockquote>")
            else:
                icon = self._get_premium_emoji('globe')
                url = data.get('url', 'Неизвестная ссылка' if self._current_language == 'ru' else 'Unknown URL')
                try:
                    parsed = urlparse(url)
                    domain = parsed.netloc or url[:20] + "..."
                except:
                    domain = url[:20] + "..." if len(url) > 20 else url
                
                url_display = url[:37] + "..." if len(url) > 40 else url
                
                block_content = f"<b>{i}.</b> {icon} <b>{domain} ({self.get_string('url')})</b>\n    {self._get_premium_emoji('url')} <code>{url_display}</code>\n   {self._get_premium_emoji('time')} <code>{timestamp}</code>"
                
                stats = data.get('stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = stats.get('total', 0)
                
                _, status_text = self._get_history_status(malicious, suspicious, total)
                block_content += f"\n   {status_text}"
                
                text_lines.append(f"<blockquote>{block_content}</blockquote>")
        
        text_lines.append("")
        text_lines.append(f"<b>{self.get_string('history_entries')}: {total_items}/{self.config['max_history_items']}</b>")
        
        text = "\n".join(text_lines)
        
        buttons = []
        
        if total_pages > 1:
            row = []
            if current_page > 1:
                row.append({
                    "text": f"{self._get_normal_emoji('left_arrow')} {self.get_string('prev_page')}",
                    "callback": self._history_callback,
                    "args": (current_page - 1, return_message_id)
                })
            if current_page < total_pages:
                row.append({
                    "text": f"{self.get_string('next_page')} {self._get_normal_emoji('right_arrow')}",
                    "callback": self._history_callback,
                    "args": (current_page + 1, return_message_id)
                })
            if row:
                buttons.append(row)
        
        row2 = [
            {
                "text": f"{self._get_normal_emoji('trash')} {self.get_string('clear_history')}",
                "callback": self._clear_history_confirm_callback
            },
            {
                "text": f"{self._get_normal_emoji('refresh')} {self.get_string('refresh')}",
                "callback": self._history_callback,
                "args": (current_page, return_message_id)
            }
        ]
        
        if return_message_id:
            row2.append({
                "text": f"{self._get_normal_emoji('back_arrow')} {self.get_string('back_to_results')}",
                "callback": self._return_to_results_callback,
                "args": (return_message_id,)
            })
        
        buttons.append(row2)
        
        if hasattr(message, 'edit') and callable(getattr(message, 'edit')):
            try:
                await message.edit(text=text, reply_markup=buttons)
                if hasattr(message, 'answer'):
                    await message.answer(f"{self._get_normal_emoji('pages')} {'Страница' if self._current_language == 'ru' else 'Page'} {current_page}")
            except TypeError:
                await self.inline.form(
                    text=text,
                    message=message,
                    reply_markup=buttons,
                    ttl=300
                )
        else:
            await self.inline.form(
                text=text,
                message=message,
                reply_markup=buttons,
                ttl=300
            )

    async def _history_callback(self, call, page_num=1, return_message_id=None):
        await self._show_history_page(call, page_num, return_message_id)

    async def _history_from_results_callback(self, call, page_num=1, return_message_id=None):
        await self._show_history_page(call, page_num, return_message_id)

    async def _return_to_results_callback(self, call, message_id):
        return_data = self._db.get(__name__, f"result_{message_id}", None)
        
        if not return_data:
            await call.answer(
                f"{self._get_normal_emoji('error')} {'Результаты больше не доступны' if self._current_language == 'ru' else 'Results no longer available'}", 
                show_alert=True
            )
            await call.delete()
            return
        
        buttons = [
            [{"text": f"{self._get_normal_emoji('link')} {self.get_string('view_report')}", "url": return_data['vt_url']}],
            [{
                "text": f"{self._get_normal_emoji('history')} {'История' if self._current_language == 'ru' else 'History'}", 
                "callback": self._history_from_results_callback, 
                "args": (1, message_id)
            }],
        ]
        
        try:
            await call.edit(text=return_data['text'], reply_markup=buttons)
            await call.answer(f"{self._get_normal_emoji('back_arrow')} {self.get_string('back_to_results')}")
        except Exception:
            await call.answer(f"{self._get_normal_emoji('error')} {self.get_string('error')}", show_alert=True)

    async def _clear_history_confirm_callback(self, call):
        if not self.scan_history:
            await call.answer(f"{self._get_normal_emoji('history_empty')} {self.get_string('history_empty')}", show_alert=True)
            return
        
        text = "\n".join([
            f"<b>{self._get_premium_emoji('warning')} {self.get_string('confirm_clear')}</b>",
            f"━━━━━━━━━━━━━━━━━━━━━━",
            "",
            f"{self.get_string('clear_history_confirm')}",
            f"<b>{self.get_string('history_entries')}: {len(self.scan_history)}</b>",
            "",
            f"{self._get_premium_emoji('warning')} {'Это действие нельзя отменить!' if self._current_language == 'ru' else 'This action cannot be undone!'}"
        ])
        
        buttons = [[
            {"text": f"{self._get_normal_emoji('success')} {self.get_string('yes_clear')}", "callback": self._clear_history_callback},
            {"text": self.get_string('cancel'), "callback": self._cancel_clear_history_callback}
        ]]
        
        try:
            await call.edit(text=text, reply_markup=buttons)
            await call.answer(f"{self._get_normal_emoji('warning')} {self.get_string('confirm_clear')}")
        except Exception:
            await call.answer(f"{self._get_normal_emoji('error')} {self.get_string('error')}", show_alert=True)

    async def _cancel_clear_history_callback(self, call):
        await self._history_callback(call, 1, None)
        await call.answer(f"{self._get_normal_emoji('cancel')} {'Отменено' if self._current_language == 'ru' else 'Cancelled'}")

    async def _clear_history_callback(self, call):
        count = len(self.scan_history)
        self.scan_history.clear()
        
        if self.config["save_history"]:
            self._db.set(__name__, "scan_history", {})
        
        text = "\n".join([
            f"<b>{self._get_premium_emoji('trash')} {self.get_string('history_cleared')}</b>",
            f"━━━━━━━━━━━━━━━━━━━━━━",
            "",
            f"<b>{self._get_premium_emoji('success')} {self.get_string('deleted_entries')}: {count}</b>",
            "",
            f"<i>{self._get_premium_emoji('history_empty')} {self.get_string('history_empty')}</i>"
        ])
        
        buttons = [[{
            "text": f"{self._get_normal_emoji('history')} {'История' if self._current_language == 'ru' else 'History'}", 
            "callback": self._history_callback, 
            "args": (1, None)
        }]]
        
        try:
            await call.edit(text=text, reply_markup=buttons)
            await call.answer(f"{self._get_normal_emoji('success')} {self.get_string('deleted_entries')}: {count}")
        except Exception:
            await call.answer(f"{self._get_normal_emoji('error')} {self.get_string('error')}", show_alert=True)

    async def _change_language_callback(self, call, lang):
        self.config['language'] = lang
        self._current_language = lang
        await call.answer(f"{self._get_normal_emoji('success')} {'Язык изменен на Русский' if lang == 'ru' else 'Language changed to English'}")
        await call.edit(
            text=f"<b>{self._get_premium_emoji('success')} {'Язык изменен на Русский' if lang == 'ru' else 'Language changed to English'}</b>", 
            reply_markup=None
        )

    async def _handle_scan_common(self, message, scan_type, **kwargs):
        api_key = self.config["api_key"]
        if not api_key:
            return await utils.answer(message, f"{self._get_premium_emoji('forbidden')} <b>{self.get_string('no_key')}</b>")
        
        msg = None
        try:
            start_time = time.time()
            
            if scan_type == "file":
                reply = await message.get_reply_message()
                if not reply or not reply.document:
                    return await utils.answer(message, f"{self._get_premium_emoji('forbidden')} <b>{self.get_string('no_file')}</b>")
                
                filename = reply.file.name or "file.bin"
                
                msg = await utils.answer(message, f"<b>{self._get_premium_emoji('downloading')} {self.get_string('downloading')}</b>")
                msg_id = id(msg)
                
                session = self._get_session()
                
                with tempfile.TemporaryDirectory() as tmpdir:
                    file_path = os.path.join(tmpdir, filename)
                    await reply.download_media(file_path)
                    
                    file_size = os.path.getsize(file_path)
                    if file_size > self.MAX_SIZE:
                        await self._safe_edit(msg, f"<b>{self._get_premium_emoji('forbidden')} {self.get_string('size_limit')}</b>", msg_id)
                        return
                    
                    file_hash = self._calculate_file_hash(file_path)
                    
                    await self._safe_edit(msg, f"<b>{self._get_premium_emoji('check')} {self.get_string('checking_cache')}</b>", msg_id)
                    
                    existing_report = await self._check_existing_report(session, file_hash)
                    if existing_report:
                        await self._safe_edit(msg, f"<b>{self._get_premium_emoji('stats')} {self.get_string('getting_results')}</b>", msg_id)
                        await asyncio.sleep(1)
                        await self._show_results(
                            msg, 
                            file_hash, 
                            existing_report, 
                            "file", 
                            original_filename=filename, 
                            scan_time=int(time.time() - start_time), 
                            file_size=file_size
                        )
                        return
                    
                    await self._safe_edit(msg, f"<b>{self._get_premium_emoji('upload')} {self.get_string('uploading')}</b>", msg_id)
                    
                    upload_result = await self._upload_file(session, file_path)
                    if not upload_result:
                        await self._safe_edit(msg, f"<b>{self._get_premium_emoji('error')} {self.get_string('upload_error')}</b>", msg_id)
                        return
                    
                    await self._safe_edit(msg, f"<b>{self._get_premium_emoji('waiting')} {self.get_string('waiting')}</b>", msg_id)
                    
                    result = await self._poll_analysis(
                        session, 
                        upload_result, 
                        msg, 
                        start_time, 
                        msg_id, 
                        filename=filename, 
                        file_size=file_size, 
                        scan_type="file"
                    )
                    
                    if result:
                        await self._safe_edit(msg, f"<b>{self._get_premium_emoji('stats')} {self.get_string('getting_results')}</b>", msg_id)
                        
                        final_report = await self._get_file_report(session, file_hash)
                        await self._show_results(
                            msg, 
                            file_hash, 
                            final_report or result, 
                            "file", 
                            original_filename=filename, 
                            scan_time=int(time.time() - start_time), 
                            file_size=file_size
                        )
                    else:
                        await self._safe_edit(msg, f"<b>{self._get_premium_emoji('timeout')} {self.get_string('timeout')}</b>", msg_id)
                        
            elif scan_type == "url":
                url = kwargs.get('url')
                if not url:
                    args = utils.get_args_raw(message)
                    if not args:
                        return await utils.answer(message, f"{self._get_premium_emoji('forbidden')} <b>{self.get_string('no_url')}</b>")
                    url = args.strip()
                
                if not self._validate_url(url):
                    return await utils.answer(message, f"{self._get_premium_emoji('error')} <b>{self.get_string('invalid_url')}</b>")
                
                msg = await utils.answer(message, f"<b>{self._get_premium_emoji('url')} {self.get_string('scanning_url')}</b>")
                msg_id = id(msg)
                
                session = self._get_session()
                url_encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                
                await self._safe_edit(msg, f"<b>{self._get_premium_emoji('check')} {self.get_string('checking_cache')}</b>", msg_id)
                
                scan_result = await self._scan_url(session, url)
                
                if not scan_result or scan_result.get("type") == "error":
                    await self._safe_edit(msg, f"<b>{self._get_premium_emoji('error')} {self.get_string('scan_error')}</b>", msg_id)
                    return
                
                if scan_result["type"] == "existing":
                    existing_report = await self._get_url_report(session, scan_result["id"])
                    if existing_report:
                        await self._safe_edit(msg, f"<b>{self._get_premium_emoji('stats')} {self.get_string('getting_results')}</b>", msg_id)
                        await asyncio.sleep(1)
                        await self._show_results(
                            msg, 
                            url_encoded, 
                            existing_report, 
                            "url", 
                            original_url=url, 
                            scan_time=int(time.time() - start_time)
                        )
                        return
                    else:
                        scan_result = {"type": "new", "id": scan_result["id"]}
                
                if scan_result["type"] == "new":
                    await self._safe_edit(msg, f"<b>{self._get_premium_emoji('waiting')} {self.get_string('waiting')}</b>", msg_id)
                    
                    result = await self._poll_analysis(
                        session, 
                        scan_result["id"], 
                        msg, 
                        start_time, 
                        msg_id, 
                        url=url, 
                        scan_type="url"
                    )
                    
                    if result:
                        await self._safe_edit(msg, f"<b>{self._get_premium_emoji('stats')} {self.get_string('getting_results')}</b>", msg_id)
                        
                        final_report = await self._get_url_report(session, url_encoded)
                        if final_report:
                            await self._show_results(
                                msg, 
                                url_encoded, 
                                final_report, 
                                "url", 
                                original_url=url, 
                                scan_time=int(time.time() - start_time)
                            )
                        else:
                            await self._safe_edit(msg, f"<b>{self._get_premium_emoji('timeout')} {self.get_string('timeout')}</b>", msg_id)
                    else:
                        await self._safe_edit(msg, f"<b>{self._get_premium_emoji('timeout')} {self.get_string('timeout')}</b>", msg_id)
        
        except Exception as e:
            elapsed = int(time.time() - start_time) if 'start_time' in locals() else 0
            error_text = f"<b>{self._get_premium_emoji('error')} {self.get_string('error')}: {str(e)[:100]} ({self._format_time(elapsed)})</b>"
            if msg:
                await self._safe_edit(msg, error_text, msg_id)
            else:
                await utils.answer(message, error_text)

    @loader.command(ru_doc="[ответ] - просканировать файл через VirusTotal", en_doc="[reply] - scan file with VirusTotal")
    async def vt(self, message):
        await self._handle_scan_common(message, "file")

    @loader.command(ru_doc="[ссылка] - просканировать ссылку через VirusTotal", en_doc="[url] - scan URL with VirusTotal")
    async def vtl(self, message):
        api_key = self.config["api_key"]
        if not api_key:
            return await utils.answer(message, f"{self._get_premium_emoji('forbidden')} <b>{self.get_string('no_key')}</b>")
        
        url = None
        args = utils.get_args_raw(message)
        if args:
            url = args.strip()
        
        if not url:
            reply = await message.get_reply_message()
            if reply:
                if reply.entities:
                    for entity in reply.entities:
                        if hasattr(entity, 'url') and entity.url:
                            url = entity.url
                            break
                
                if not url and reply.text:
                    import re
                    urls = re.findall(r'https?://[^\s"\'<>]+', reply.text)
                    if urls:
                        url = urls[0]
                        url = re.sub(r'[<>"].*$', '', url)
        
        if not url:
            return await utils.answer(message, f"{self._get_premium_emoji('forbidden')} <b>{self.get_string('no_url')}</b>")
        
        url = url.split('"')[0].split('>')[0].split('<')[0]
        
        if not self._validate_url(url):
            return await utils.answer(message, f"{self._get_premium_emoji('error')} <b>{self.get_string('invalid_url')}</b>")
        
        await self._handle_scan_common(message, "url", url=url)

    @loader.command(ru_doc="[хеш] - проверить файл по хешу (SHA256/MD5)", en_doc="[hash] - check file by hash (SHA256/MD5)")
    async def vthash(self, message):
        api_key = self.config["api_key"]
        if not api_key:
            return await utils.answer(message, f"{self._get_premium_emoji('forbidden')} <b>{self.get_string('no_key')}</b>")

        args = utils.get_args_raw(message)
        if not args:
            return await utils.answer(message, f"{self._get_premium_emoji('error')} <b>{self.get_string('specify_hash')}</b>")
        
        file_hash = args.strip().lower()
        
        if re.match(r'^[a-f0-9]{64}$', file_hash):
            hash_type = "SHA256"
            display_hash = file_hash[:16] + "..."
        elif re.match(r'^[a-f0-9]{32}$', file_hash):
            hash_type = "MD5"
            display_hash = file_hash[:16] + "..."
        else:
            found = [(i, d) for i, d in self.scan_history.items() if file_hash in i.lower()]
            if found:
                text_lines = [
                    f"<b>{self._get_premium_emoji('check')} {self.get_string('history_search')}</b>",
                    f"<code>━━━━━━━━━━━━━━━━━━━━━━</code>",
                    "",
                    self.get_string('search_results', count=len(found), hash=file_hash),
                    ""
                ]
                
                for i, (item_id, data) in enumerate(found[:5], 1):
                    dt = datetime.fromtimestamp(data['timestamp'], timezone.utc)
                    timestamp = dt.strftime("%H:%M %d.%m UTC")
                    icon = self._get_premium_emoji('file') if data['type'] == 'file' else self._get_premium_emoji('url')
                    name = data.get('name', data.get('url', ''))[:30]
                    text_lines.append(f"{i}. {icon} {name}")
                    text_lines.append(f"   {self._get_premium_emoji('time')} {timestamp}")
                    text_lines.append("")
                
                if len(found) > 5:
                    text_lines.append(self.get_string('and_more', count=len(found) - 5))
                    text_lines.append("")
                text_lines.append(self.get_string('use_full_hash'))
                
                text = "\n".join(text_lines)
                
                return await self.inline.form(
                    text=text,
                    message=message,
                    reply_markup=[[{
                        "text": f"{self._get_normal_emoji('history')} {'История' if self._current_language == 'ru' else 'History'}", 
                        "callback": self._history_callback, 
                        "args": (1, None)
                    }]],
                    ttl=60
                )
            else:
                return await utils.answer(message, f"{self._get_premium_emoji('error')} <b>{self.get_string('hash_not_found')}</b>")

        msg = None
        try:
            start_time = time.time()
            
            msg = await utils.answer(message, f"<b>{self._get_premium_emoji('hash')} {self.get_string('checking_hash')}</b>")
            msg_id = id(msg)
            
            session = self._get_session()
            
            await self._safe_edit(msg, f"<b>{self._get_premium_emoji('check')} {self.get_string('searching_report', type=hash_type)}</b>", msg_id)
            
            existing_report = await self._check_existing_report(session, file_hash)
            
            if existing_report:
                await self._safe_edit(msg, f"<b>{self._get_premium_emoji('stats')} {self.get_string('getting_results')}</b>", msg_id)
                await asyncio.sleep(1)
                await self._show_results(
                    msg, 
                    file_hash, 
                    existing_report, 
                    "file", 
                    original_filename=f"{self.get_string('hash')}: {display_hash}", 
                    scan_time=int(time.time() - start_time)
                )
            else:
                await self._safe_edit(msg, f"<b>{self._get_premium_emoji('not_found')} {self.get_string('not_found')}</b>", msg_id)
                
        except Exception as e:
            elapsed = int(time.time() - start_time)
            error_text = f"<b>{self._get_premium_emoji('error')} {self.get_string('error')}: {str(e)[:100]} ({self._format_time(elapsed)})</b>"
            if msg:
                await self._safe_edit(msg, error_text, msg_id)
            else:
                await utils.answer(message, error_text)

    @loader.command(ru_doc="[страница] - показать историю сканирований", en_doc="[page] - show scan history")
    async def vthistory(self, message):
        if not self.scan_history:
            return await utils.answer(
                message, 
                f"{self._get_premium_emoji('history_empty')} <b>{self.get_string('history_empty')}</b>"
            )
        
        try:
            page_num = int(utils.get_args_raw(message) or 1)
        except ValueError:
            page_num = 1
        
        total_items = len(self.scan_history)
        items_per_page = self.config["history_items_per_page"]
        total_pages = (total_items + items_per_page - 1) // items_per_page
        
        if page_num < 1:
            page_num = 1
        elif page_num > total_pages:
            await utils.answer(message, f"{self._get_premium_emoji('warning')} <b>Страницы {page_num} не существует. Показана последняя страница.</b>")
            page_num = total_pages
        
        await self._show_history_page(message, page_num)

    @loader.command(ru_doc=" - очистить историю сканирований", en_doc=" - clear scan history")
    async def vtclear(self, message):
        if not self.scan_history:
            return await utils.answer(
                message, 
                f"{self._get_premium_emoji('history_empty')} <b>{self.get_string('history_empty')}</b>"
            )
        
        count = len(self.scan_history)
        self.scan_history.clear()
        
        if self.config["save_history"]:
            self._db.set(__name__, "scan_history", {})
        
        await utils.answer(
            message, 
            f"{self._get_premium_emoji('trash')} <b>{self.get_string('history_cleared')}</b>. {self._get_premium_emoji('success')} <b>{self.get_string('deleted_entries')}</b>: {count}"
        )

    @loader.command(ru_doc=" - сменить язык интерфейса", en_doc=" - change interface language")
    async def vtlang(self, message):
        args = utils.get_args_raw(message)
        
        if not args:
            current_lang = "Русский" if self._current_language == 'ru' else "English"
            
            text = "\n".join([
                f"<b>{self._get_premium_emoji('globe')} {self.get_string('current_language')}: {current_lang}</b>",
                f"━━━━━━━━━━━━━━━━━━━━━━",
                "",
                f"<b>{self.get_string('available_languages')}:</b>",
                f"• <code>.vtlang ru</code> - {self.get_string('russian')}",
                f"• <code>.vtlang en</code> - {self.get_string('english')}",
                "",
                f"<b>{self.get_string('current_setting')}:</b>",
                f"language: {self.config['language']}"
            ])
            
            await self.inline.form(
                text=text,
                message=message,
                reply_markup=[[
                    {"text": f"{self._get_normal_emoji('flag_ru')} Русский", "callback": self._change_language_callback, "args": ("ru",)},
                    {"text": f"{self._get_normal_emoji('flag_gb')} English", "callback": self._change_language_callback, "args": ("en",)}
                ]],
                ttl=60
            )
            return
        
        lang = args.strip().lower()
        if lang in ['ru', 'en']:
            self.config['language'] = lang
            self._current_language = lang
            await utils.answer(
                message, 
                f"{self._get_premium_emoji('success')} <b>{'Язык изменен на Русский' if lang == 'ru' else 'Language changed to English'}</b>"
            )
        else:
            await utils.answer(
                message, 
                f"{self._get_premium_emoji('error')} <b>{'Неверный язык. Используйте: ru или en' if self._current_language == 'ru' else 'Invalid language. Use: ru or en'}</b>"
    )
