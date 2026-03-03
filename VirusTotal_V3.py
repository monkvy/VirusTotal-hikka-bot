#  This file is part of Codex modules
#  Copyright (c) 2026 Codex
#  This software is released under the MIT License.
#  https://opensource.org/licenses/MIT

__version__ = (3, 0, 0)  # v3.0

# meta developer: @monkvy

#░█████╗░░█████╗░██████╗░███████╗██╗░░██╗
#██╔══██╗██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝
#██║░░╚═╝██║░░██║██║░░██║█████╗░░░╚███╔╝░
#██║░░██╗██║░░██║██║░░██║██╔══╝░░░██╔██╗░
#╚█████╔╝╚█████╔╝██████╔╝███████╗██╔╝╚██╗
#░╚════╝░░╚════╝░╚═════╝░╚══════╝╚═╝░░╚═╝

import asyncio,re,base64,hashlib,time,ipaddress,random,logging
from datetime import datetime,timezone
from urllib.parse import urlparse
from typing import Optional,Dict,Tuple,List
from dataclasses import dataclass,field
import aiohttp
from .. import loader,utils

MAX_FILE_SIZE=32*1024*1024
HISTORY_PER_PAGE=5
logger=logging.getLogger(__name__)

class VirusTotalError(Exception):pass
class QuotaExceededError(VirusTotalError):pass
class InvalidKeyError(VirusTotalError):pass
class RateLimitError(VirusTotalError):pass
class NotFoundError(VirusTotalError):pass

@dataclass
class ScanStats:
    malicious:int=0
    suspicious:int=0
    harmless:int=0
    undetected:int=0
    @property
    def total(self)->int:
        return self.malicious+self.suspicious+self.harmless+self.undetected

@dataclass
class HistoryEntry:
    item_id:str
    timestamp:datetime
    scan_type:str
    name:Optional[str]=None
    url:Optional[str]=None
    as_owner:Optional[str]=None
    country_code:Optional[str]=None
    stats:ScanStats=field(default_factory=ScanStats)
    raw_result:dict=field(default_factory=dict)

@loader.tds
class VirusTotalMod(loader.Module):
    strings={
        "name":"VirusTotal",
        "no_url":"Specify URL, IP or file",
        "invalid_url":"Invalid URL format",
        "downloading":"Downloading file...",
        "uploading":"Uploading to VirusTotal...",
        "scanning_url":"Scanning URL...",
        "waiting":"Waiting for analysis",
        "no_key":"Set API key(s) in config",
        "error":"Error: {}",
        "size_limit":"File is larger than 32MB",
        "timeout":"Scan timeout",
        "view_report":"Full report",
        "checking_cache":"Checking cache...",
        "getting_results":"Getting results...",
        "upload_error":"Upload error",
        "scan_error":"Scan error",
        "download_error":"Failed to download file: {}",
        "results_title":"VirusTotal Scan Results",
        "history_title":"VirusTotal Scan History",
        "history_empty":"Scan history is empty",
        "history_cleared":"History cleared",
        "history_entries":"Total entries",
        "clear_history":"Clear",
        "hash_check":"Check by hash",
        "cancel":"Cancel",
        "confirm_clear":"Confirm clear",
        "clear_history_confirm":"⚠️ Are you sure you want to clear all history?\nThis action cannot be undone.",
        "prev_page":"Back",
        "next_page":"Forward",
        "refresh":"Refresh",
        "back_to_results":"Back",
        "file":"File",
        "url":"URL",
        "hash":"Hash",
        "domain":"Domain",
        "scans":"scans",
        "engines":"engines",
        "clean":"clean",
        "dangerous":"dangerous",
        "very_dangerous":"very dangerous",
        "suspicious":"suspicious",
        "likely_safe":"likely safe",
        "high_risk":"high risk",
        "low_risk":"low risk",
        "threats":"Threats",
        "detected":"detected",
        "status":"Status",
        "safe":"safe",
        "results":"Results",
        "malicious":"Malicious",
        "harmless":"Harmless",
        "undetected":"Undetected",
        "specify_hash":"Specify file hash (SHA256 or MD5)",
        "hash_not_found":"Invalid hash format",
        "search_results":"Found {} entries with hash {}:",
        "and_more":"... and {} more entries",
        "use_full_hash":"Use full hash for check",
        "checking_hash":"Checking hash...",
        "searching_report":"Searching report by {} hash...",
        "not_found":"Not found",
        "unknown":"Unknown",
        "country":"Country",
        "asn":"ASN",
        "ip_address":"IP-address",
        "checking":"Checking",
        "of":"of",
        "history":"History",
        "yes_clear":"Yes, clear",
        "deleted_entries":"Deleted entries",
        "bytes":"B",
        "kb":"KB",
        "mb":"MB",
        "gb":"GB",
        "sec":"sec",
        "min":"min",
        "entries":"Entries",
        "quota_error":"{} VirusTotal daily quota exceeded. Try again tomorrow or add more API keys",
        "invalid_key_error":"{} Invalid API key. Check your key(s) in config: <code>.cfg VirusTotal api_keys</code>",
        "rate_limit_error":"{} Too many requests. Please wait {{}} seconds",
        "not_found_error":"{} Resource not found in VirusTotal database",
        "server_error":"{} VirusTotal server error ({{}}). Try again later",
        "network_error":"{} Network error: {{}}",
        "all_keys_exhausted":"{} All API keys have exhausted their quotas. Add new keys to config",
    }
    
    strings_ru={
        "name":"VirusTotal",
        "no_url":"Укажите ссылку, айпи или файл",
        "invalid_url":"Неверный формат ссылки",
        "downloading":"Скачиваю файл...",
        "uploading":"Загружаю на VirusTotal...",
        "scanning_url":"Сканирую ссылку...",
        "waiting":"Жду анализа...",
        "no_key":"Укажите API ключ(и) в конфиге",
        "error":"Ошибка: {}",
        "size_limit":"Файл больше 32МБ",
        "timeout":"Таймаут сканирования",
        "view_report":"Полный отчёт",
        "checking_cache":"Проверка кэша...",
        "getting_results":"Получаю результаты...",
        "upload_error":"Ошибка загрузки",
        "scan_error":"Ошибка сканирования",
        "download_error":"Не удалось скачать файл: {}",
        "results_title":"Результаты сканирования VirusTotal",
        "history_title":"История сканирований VirusTotal",
        "history_empty":"История сканирований пуста",
        "history_cleared":"История очищена",
        "history_entries":"Всего записей",
        "clear_history":"Очистить",
        "hash_check":"Проверить по хешу",
        "cancel":"Отмена",
        "confirm_clear":"Подтвердить очистку",
        "clear_history_confirm":"⚠️ Вы уверены, что хотите очистить всю историю?\nЭто действие нельзя отменить.",
        "prev_page":"Назад",
        "next_page":"Вперед",
        "refresh":"Обновить",
        "back_to_results":"Обратно",
        "file":"Файл",
        "url":"Ссылка",
        "hash":"Хеш",
        "domain":"Домен",
        "scans":"сканирований",
        "engines":"движков",
        "clean":"чистый",
        "dangerous":"опасный",
        "very_dangerous":"очень опасный",
        "suspicious":"подозрительный",
        "likely_safe":"вероятно безопасный",
        "high_risk":"высокий риск",
        "low_risk":"низкий риск",
        "threats":"Угроз",
        "detected":"обнаружено",
        "status":"Статус",
        "safe":"безопасно",
        "results":"Результаты",
        "malicious":"Вредоносные",
        "harmless":"Безвредные",
        "undetected":"Не обнаружено",
        "specify_hash":"Укажите хеш файла (SHA256 или MD5)",
        "hash_not_found":"Неверный формат хеша",
        "search_results":"Найдено {} записей с хешем {}:",
        "and_more":"... и еще {} записей",
        "use_full_hash":"Используйте полный хеш",
        "checking_hash":"Проверка хеша...",
        "searching_report":"Поиск отчета по {} хешу...",
        "not_found":"Не найден",
        "unknown":"Неизвестно",
        "country":"Страна",
        "asn":"ASN",
        "ip_address":"IP-адрес",
        "checking":"Проверяю",
        "of":"из",
        "history":"История",
        "yes_clear":"Да, очистить",
        "deleted_entries":"Удалено записей",
        "bytes":"Б",
        "kb":"КБ",
        "mb":"МБ",
        "gb":"ГБ",
        "sec":"сек",
        "min":"мин",
        "entries":"Записи",
        "quota_error":"{} Превышен дневной лимит запросов VirusTotal. Попробуйте завтра или добавьте ещё API ключей",
        "invalid_key_error":"{} Неверный API ключ. Проверьте ключ(и) в конфиге: <code>.cfg VirusTotal api_keys</code>",
        "rate_limit_error":"{} Слишком много запросов. Подождите {{}} секунд",
        "not_found_error":"{} Ресурс не найден в базе VirusTotal",
        "server_error":"{} Ошибка сервера VirusTotal ({{}}). Попробуйте позже",
        "network_error":"{} Сетевая ошибка: {{}}",
        "all_keys_exhausted":"{} Все API ключи исчерпали лимиты. Добавьте новые ключи в конфиг",
    }

    def __init__(self):
        self.config=loader.ModuleConfig(
            loader.ConfigValue('api_keys','','VirusTotal API keys (comma-separated)',validator=loader.validators.Hidden()),
            loader.ConfigValue('max_wait_time',300,'Maximum wait time',validator=loader.validators.Integer(minimum=60,maximum=600)),
            loader.ConfigValue('poll_interval',10,'Polling interval',validator=loader.validators.Integer(minimum=5,maximum=10)),
            loader.ConfigValue('save_history',True,'Save scan history',validator=loader.validators.Boolean()),
            loader.ConfigValue('max_history_items',10,'Max history entries',validator=loader.validators.Integer(minimum=1,maximum=10)),
            loader.ConfigValue('cleanup_interval',3600,'Cleanup interval',validator=loader.validators.Integer(minimum=300,maximum=86400))
        )
        self.history=[]
        self._session=None
        self._cleanup_task=None
        self._result_cache={}
        self._cache_ttl=300
        self.api_keys=[]
        self.key_status={}
        self.current_key_index=0
        self.key_lock=asyncio.Lock()
        self._timeout=aiohttp.ClientTimeout(total=30)
        self._connector=aiohttp.TCPConnector(limit=20)

    def _emoji(self,name:str,premium:bool=True)->str:
        emojis={
            'file':('<emoji document_id=5915834902074364776>☁️</emoji>','☁️'),
            'url':('<emoji document_id=5271604874419647061>🔗</emoji>','🔗'),
            'size':('<emoji document_id=5784891605601225888>📦</emoji>','📦'),
            'time':('<emoji document_id=5382194935057372936>⏱️</emoji>','⏱️'),
            'engines':('<emoji document_id=5195033767969839232>🚀</emoji>','🚀'),
            'scans':('<emoji document_id=5444965061749644170>👥</emoji>','👥'),
            'progress':('<emoji document_id=5386367538735104399>⏳</emoji>','⏳'),
            'refresh':('<emoji document_id=5818740758257077530>🔄</emoji>','🔄'),
            'stats':('<emoji document_id=5231200819986047254>📊</emoji>','📊'),
            'shield':('<emoji document_id=5251203410396458957>🛡</emoji>','🛡'),
            'check':('<emoji document_id=5231012545799666522>🔍</emoji>','🔍'),
            'success':('<emoji document_id=5206607081334906820>✅️</emoji>','✅'),
            'error':('<emoji document_id=5210952531676504517>❌️</emoji>','❌'),
            'warning':('<emoji document_id=5447644880824181073>⚠️</emoji>','⚠️'),
            'danger':('<emoji document_id=5260293700088511294>⛔️</emoji>','⛔'),
            'skull':('<emoji document_id=5370842086658546991>☠️</emoji>','☠️'),
            'history':('<emoji document_id=5197269100878907942>📋</emoji>','📋'),
            'pages':('<emoji document_id=5253742260054409879>📄</emoji>','📄'),
            'hash':('<emoji document_id=5343824560523322473>🔢</emoji>','🔢'),
            'upload':('<emoji document_id=5406745015365943482>⬇️</emoji>','⬇️'),
            'globe':('<emoji document_id=5447410659077661506>🌐</emoji>','🌐'),
            'chart':('<emoji document_id=5244837092042750681>📈</emoji>','📈'),
            'forbidden':('<emoji document_id=5240241223632954241>🚫</emoji>','🚫'),
            'trash':('<emoji document_id=5445267414562389170>🗑</emoji>','🗑'),
            'history_empty':('<emoji document_id=5253742260054409879>✉️</emoji>','✉️'),
            'downloading':('<emoji document_id=5433653135799228968>📥</emoji>','📥'),
            'waiting':('<emoji document_id=5386367538735104399>⏳</emoji>','⏳'),
            'timeout':('<emoji document_id=5382194935057372936>⏰</emoji>','⏰'),
            'not_found':('<emoji document_id=5235750010691271995>❓</emoji>','❓'),
            'left_arrow':('⬅️','⬅️'),
            'right_arrow':('➡️','➡️'),
            'back_arrow':('↩️','↩️'),
            'link':('🔗','🔗'),
            'cancel':('🚫','🚫'),
            'server':('<emoji document_id=5341715473882955310>⚙️</emoji>','⚙️'),
            'quota':('<emoji document_id=5206492775075295242>💔</emoji>','💔'),
            'exhausted':('<emoji document_id=5274099962655816924>❗️</emoji>','❗️'),
        }
        return emojis[name][0] if premium else emojis[name][1]

    def _country_flag(self,country_code:str)->str:
        if not country_code or len(country_code)!=2:return '🏳️'
        base=127462
        return chr(base+(ord(country_code[0].upper())-ord('A')))+chr(base+(ord(country_code[1].upper())-ord('A')))

    def _format_size(self,size:int)->str:
        units=[self.strings('bytes'),self.strings('kb'),self.strings('mb'),self.strings('gb')]
        idx=0
        while size>=1024 and idx<len(units)-1:
            size/=1024
            idx+=1
        return f"{size:.1f} {units[idx]}" if idx>0 else f"{size:.0f} {units[0]}"

    def _format_time(self,seconds:int)->str:
        if seconds<60:return f"{seconds} {self.strings('sec')}"
        m,s=divmod(seconds,60)
        return f"{m} {self.strings('min')} {s} {self.strings('sec')}" if s else f"{m} {self.strings('min')}"

    def _get_status(self,stats:ScanStats)->Tuple[str,str]:
        if stats.malicious==0 and stats.suspicious==0:
            return self._emoji('success'),'clean'
        ratio=stats.malicious/stats.total if stats.total>0 else 0
        thresholds=[(0.02,'likely_safe','success'),(0.05,'suspicious','warning'),(0.15,'dangerous','danger')]
        for limit,key,emoji in thresholds:
            if ratio<limit:return self._emoji(emoji),key
        return self._emoji('skull'),'very_dangerous'

    def _get_lang(self)->str:
        try:return self._db.get("hikka.inline","lang","en")
        except:return "en"

    async def _get_next_key(self)->Optional[str]:
        async with self.key_lock:
            if not self.api_keys:return None
            start=self.current_key_index
            for i in range(len(self.api_keys)):
                idx=(start+i)%len(self.api_keys)
                key=self.api_keys[idx]
                if self.key_status.get(key,True):
                    self.current_key_index=(idx+1)%len(self.api_keys)
                    return key
            self.key_status.clear()
            self.current_key_index=0
            return self.api_keys[0] if self.api_keys else None

    async def _mark_key_bad(self,key:str):
        async with self.key_lock:
            self.key_status[key]=False
            logger.warning(f"Key {key[:8]}... marked as bad")

    _error_map={
        InvalidKeyError:('shield','invalid_key_error'),
        QuotaExceededError:('quota','quota_error'),
        RateLimitError:('progress','rate_limit_error'),
        NotFoundError:('check','not_found_error'),
    }

    async def _handle_error(self,e:Exception,context:str="")->str:
        logger.exception(f"VirusTotal error in {context}: {e}")
        if isinstance(e,asyncio.TimeoutError):return self.strings("timeout")
        if isinstance(e,aiohttp.ClientResponseError):
            if e.status==403:return f"{self._emoji('shield')} {self.strings('invalid_key_error').format(self._emoji('shield'))}"
            if e.status==429:return f"{self._emoji('progress')} {self.strings('rate_limit_error').format(self._emoji('progress'),e.headers.get('Retry-After','60'))}"
            if e.status==404:return f"{self._emoji('check')} {self.strings('not_found_error').format(self._emoji('check'))}"
            if e.status>=500:return f"{self._emoji('server')} {self.strings('server_error').format(self._emoji('server'),e.status)}"
        if isinstance(e,aiohttp.ClientError):return f"{self._emoji('globe')} {self.strings('network_error').format(self._emoji('globe'),str(e))}"
        for err,(emoji,key) in self._error_map.items():
            if isinstance(e,err):return f"{self._emoji(emoji)} {self.strings(key).format(self._emoji(emoji))}"
        if isinstance(e,VirusTotalError):return f"{self._emoji('exhausted')} {self.strings('all_keys_exhausted').format(self._emoji('exhausted'))}"
        return self.strings("error").format(str(e))

    async def _check_api_response(self,data:dict)->Optional[Exception]:
        if not data or 'error' not in data:return None
        m=data['error'].get('message','').lower()
        if 'quota' in m or 'exceeded' in m:return QuotaExceededError(m)
        if 'key' in m:return InvalidKeyError(m)
        if 'rate' in m or 'too many' in m:return RateLimitError(m)
        if 'not found' in m:return NotFoundError(m)
        return VirusTotalError(m)

    async def _request(self,method:str,url:str,**kwargs)->Optional[Dict]:
        if not self._session or self._session.closed:
            self._session=aiohttp.ClientSession(timeout=self._timeout,connector=self._connector)
        max_attempts,base_delay,max_delay=3,2,60
        last_error=None
        for attempt in range(max_attempts):
            api_key=await self._get_next_key()
            if not api_key:raise VirusTotalError("No API keys available")
            req_kwargs={**kwargs,"headers":{**kwargs.get("headers",{}),"x-apikey":api_key}}
            try:
                async with self._session.request(method,url,**req_kwargs) as resp:
                    if resp.status==429:
                        delay=int(resp.headers.get('Retry-After',min(base_delay*2**attempt,max_delay)))
                        await self._mark_key_bad(api_key)
                        await asyncio.sleep(delay)
                        continue
                    if resp.status==403:
                        await self._mark_key_bad(api_key)
                        raise InvalidKeyError(f"Invalid API key: {api_key[:8]}...")
                    try:data=await resp.json()
                    except:data=None
                    if data:
                        error=await self._check_api_response(data)
                        if error:
                            if isinstance(error,(InvalidKeyError,QuotaExceededError)):await self._mark_key_bad(api_key)
                            raise error
                    if resp.status!=200:
                        if resp.status>=500 and attempt<max_attempts-1:
                            await asyncio.sleep(min(base_delay*2**attempt,max_delay))
                            continue
                        return None
                    return data
            except (aiohttp.ClientError,asyncio.TimeoutError) as e:
                last_error=e
                if attempt==max_attempts-1:break
                await asyncio.sleep(min(base_delay*2**attempt,max_delay))
            except (InvalidKeyError,QuotaExceededError) as e:
                last_error=e
                continue
            except Exception as e:
                last_error=e
                break
        if isinstance(last_error, (InvalidKeyError, QuotaExceededError)):
            raise VirusTotalError("All API keys exhausted") from last_error
        elif last_error:
            raise last_error
        raise VirusTotalError("All API keys exhausted")

    async def upload_file(self,filename:str,file_bytes:bytes)->Optional[str]:
        data=aiohttp.FormData()
        data.add_field('file',file_bytes,filename=filename)
        try:
            r=await self._request('POST','https://www.virustotal.com/api/v3/files',data=data)
            return r.get('data',{}).get('id') if r else None
        except Exception as e:logger.error(f"Upload failed: {e}");return None

    async def get_analysis(self,analysis_id:str)->Optional[Dict]:
        try:return await self._request('GET',f'https://www.virustotal.com/api/v3/analyses/{analysis_id}')
        except Exception as e:logger.error(f"Get analysis failed: {e}");return None

    async def get_file_report(self,file_hash:str)->Optional[Dict]:
        try:return await self._request('GET',f'https://www.virustotal.com/api/v3/files/{file_hash}')
        except Exception as e:logger.error(f"Get file report failed: {e}");return None

    async def get_url_report(self,url_id:str)->Optional[Dict]:
        try:return await self._request('GET',f'https://www.virustotal.com/api/v3/urls/{url_id}')
        except Exception as e:logger.error(f"Get URL report failed: {e}");return None

    async def scan_url(self,url:str)->Optional[Dict]:
        data=aiohttp.FormData()
        data.add_field('url',url)
        try:return await self._request('POST','https://www.virustotal.com/api/v3/urls',data=data)
        except Exception as e:logger.error(f"Scan URL failed: {e}");return None

    async def get_ip_report(self,ip:str)->Optional[Dict]:
        try:return await self._request('GET',f'https://www.virustotal.com/api/v3/ip_addresses/{ip}')
        except Exception as e:logger.error(f"Get IP report failed: {e}");return None

    def _is_valid_ip(self,s:str)->bool:
        try:ipaddress.ip_address(s);return True
        except ValueError:return False

    def _validate_url(self,url:str)->Optional[str]:
        if not url.startswith(('http://','https://')):
            url='https://'+url
        try:
            r=urlparse(url)
            if r.scheme in ('http','https') and r.netloc:
                return url
        except:pass
        return None

    def _extract_stats(self,data:Dict,scan_type:str)->ScanStats:
        stats=ScanStats()
        attrs=data.get('data',{}).get('attributes',{})
        last_stats=attrs.get('last_analysis_stats',{})
        if last_stats:
            stats.malicious=last_stats.get('malicious',0)
            stats.suspicious=last_stats.get('suspicious',0)
            stats.harmless=last_stats.get('harmless',0)
            stats.undetected=last_stats.get('undetected',0)
        else:
            for r in attrs.get('last_analysis_results',{}).values():
                cat=r.get('category','')
                if cat=='malicious':stats.malicious+=1
                elif cat=='suspicious':stats.suspicious+=1
                elif cat=='harmless':stats.harmless+=1
                else:stats.undetected+=1
        return stats

    async def _poll_analysis(self,analysis_id:str)->Optional[Dict]:
        try:return await asyncio.wait_for(self._poll_loop(analysis_id),timeout=self.config['max_wait_time'])
        except asyncio.TimeoutError:return None

    async def _poll_loop(self,analysis_id:str)->Optional[Dict]:
        for d in[2,3,5,8,13,21]:
            r=await self.get_analysis(analysis_id)
            if r and r.get('data',{}).get('attributes',{}).get('status')=='completed':return r
            await asyncio.sleep(d)
        attempts=0
        while attempts<30:
            r=await self.get_analysis(analysis_id)
            if not r:return None
            if r.get('data',{}).get('attributes',{}).get('status')=='completed':return r
            await asyncio.sleep(self.config['poll_interval'])
            attempts+=1
        return None

    def _format_result_info(self,scan_type:str,item_id:str,data:dict,**kwargs)->Tuple[str,str,ScanStats]:
        stats=self._extract_stats(data,'url' if scan_type in['url','ip'] else scan_type)
        t=stats.total
        pop=data.get('data',{}).get('attributes',{}).get('times_submitted',0)
        st=kwargs.get('scan_time',0)
        url=kwargs.get('url','')
        if scan_type=='file':
            is_hash=kwargs.get('is_hash',False)
            name=kwargs.get('name') or f"{self.strings('hash')}: {item_id[:16]}..."
            sz=kwargs.get('file_size',0)
            lbl=self.strings('hash') if is_hash else self.strings('file')
            info=[f"• {self._emoji('file')} <b>{lbl}:</b> <code>{name}</code>"]
            if sz:info.append(f"• {self._emoji('size')} <code>{self._format_size(sz)}</code>")
            info+=[f"• {self._emoji('time')} <code>{self._format_time(st)}</code>",f"• {self._emoji('engines')} <code>{t} {self.strings('engines')}</code>",f"• {self._emoji('scans')} <code>{pop} {self.strings('scans')}</code>"]
            vt_url=f"https://www.virustotal.com/gui/file/{item_id}"
        elif scan_type=='ip':
            a=data.get('data',{}).get('attributes',{})
            cc=a.get('country','')
            ao=a.get('as_owner','')
            asn=a.get('asn','')
            info=[f"• {self._emoji('globe')} <b>{self.strings('ip_address')}:</b> <code>{url}</code>",f"• {self._country_flag(cc)} <b>{self.strings('country')}:</b> <code>{cc or self.strings('unknown')}</code>"]
            if ao:info.append(f"• {self._emoji('stats')} <b>{self.strings('asn')}:</b> <code>{asn} ({ao})</code>")
            else:info.append(f"• {self._emoji('stats')} <b>{self.strings('asn')}:</b> <code>{asn or self.strings('unknown')}</code>")
            info+=[f"• {self._emoji('time')} <code>{self._format_time(st)}</code>",f"• {self._emoji('engines')} <code>{t} {self.strings('engines')}</code>"]
            vt_url=f"https://www.virustotal.com/gui/ip-address/{item_id}"
        else:
            d=urlparse(url).netloc
            info=[f"• {self._emoji('url')} <b>{self.strings('url')}:</b> <code>{url[:40]+'...' if len(url)>40 else url}</code>",f"• {self._emoji('globe')} <b>{self.strings('domain')}:</b> <code>{d}</code>",f"• {self._emoji('time')} <code>{self._format_time(st)}</code>",f"• {self._emoji('engines')} <code>{t} {self.strings('engines')}</code>",f"• {self._emoji('scans')} <code>{pop} {self.strings('scans')}</code>"]
            vt_url=f"https://www.virustotal.com/gui/url/{item_id}"
        return "\n".join(info),vt_url,stats

    def _result_buttons(self,vt_url:str,msg_id:int):
        return[[{"text":f"{self._emoji('link',False)} {self.strings('view_report')}","url":vt_url}],[{"text":f"{self._emoji('history',False)} {self.strings('history')}","callback":self._history_cb,"args":(1,msg_id)}]]

    def _save_to_history(self,entry:HistoryEntry):
        if not self.config['save_history']:return
        self.history.insert(0,entry)
        if len(self.history)>self.config['max_history_items']:self.history=self.history[:self.config['max_history_items']]
        self._db.set(__name__,'history',[{'item_id':e.item_id,'timestamp':e.timestamp.isoformat(),'scan_type':e.scan_type,'name':e.name,'url':e.url,'as_owner':e.as_owner,'country_code':e.country_code,'stats':{'malicious':e.stats.malicious,'suspicious':e.stats.suspicious,'harmless':e.stats.harmless,'undetected':e.stats.undetected},'raw_result':e.raw_result} for e in self.history])

    def _load_history(self):
        self.history=[]
        for i in self._db.get(__name__,'history',[]):
            try:self.history.append(HistoryEntry(item_id=i['item_id'],timestamp=datetime.fromisoformat(i['timestamp']),scan_type=i['scan_type'],name=i.get('name'),url=i.get('url'),as_owner=i.get('as_owner'),country_code=i.get('country_code'),stats=ScanStats(**i.get('stats',{})),raw_result=i.get('raw_result',{})))
            except Exception as e:logger.warning(f"Failed to load history entry: {e}")

    async def client_ready(self,client,db):
        self._client=client
        self._db=db
        self.api_keys=[k.strip() for k in self.config['api_keys'].split(',') if k.strip()] if self.config['api_keys'] else []
        if self.api_keys:logger.info(f"Loaded {len(self.api_keys)} API key(s)")
        else:logger.warning("No API keys loaded from config!")
        self.key_status.clear()
        self._load_history()
        self._cleanup_task=asyncio.create_task(self._cleanup_loop())

    async def on_unload(self):
        if self._cleanup_task:self._cleanup_task.cancel()
        if self._session and not self._session.closed:await self._session.close()
        self._result_cache.clear()

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(self.config['cleanup_interval'])
            t=time.time()
            expired=[k for k,(_,_,ts) in self._result_cache.items() if t-ts>self._cache_ttl]
            for k in expired:
                self._result_cache.pop(k,None)
            for k in list((self._db.get(__name__) or {}).keys()):
                if k.startswith('result_'):
                    data=self._db.get(__name__,k)
                    if data and isinstance(data,dict) and 'timestamp' in data:
                        if t-data['timestamp']>self._cache_ttl:
                            self._db.set(__name__,k,None)
                    else:
                        self._db.set(__name__,k,None)

    async def _show_results(self,msg,item_id:str,data:dict,scan_type:str,**kwargs):
        try:
            info,vt_url,stats=self._format_result_info(scan_type,item_id,data,**kwargs)
            se,sk=self._get_status(stats)
            total=stats.total or 1
            safe=round((stats.harmless+stats.undetected)/total*100,1)
            if self.config['save_history']:
                if scan_type=='ip':
                    e=HistoryEntry(item_id=item_id,timestamp=datetime.now(timezone.utc),scan_type=scan_type,name=kwargs.get('url'),url=kwargs.get('url'),as_owner=data.get('data',{}).get('attributes',{}).get('as_owner'),country_code=data.get('data',{}).get('attributes',{}).get('country'),stats=stats,raw_result=data)
                else:
                    hn=kwargs.get('history_name') or kwargs.get('name') or f"{self.strings('hash')}: {item_id[:16]}..."
                    e=HistoryEntry(item_id=item_id,timestamp=datetime.now(timezone.utc),scan_type=scan_type,name=hn,url=kwargs.get('url'),stats=stats,raw_result=data)
                self._save_to_history(e)
            t=(f"<b>{self._emoji('shield')} {self.strings('results_title')}</b>\n━━━━━━━━━━━━━━━━━━━\n{info}\n\n"
               f"{se} <b>{self.strings('status')}:</b> <code>{self.strings(sk)} ({safe}% {self.strings('safe')})</code>\n"
               f"{se} <b>{self.strings('threats')}:</b> <code>{stats.malicious} {self.strings('detected')}</code>\n\n"
               f"<b>{self._emoji('chart')} {self.strings('results')}:</b>\n"
               f"<blockquote>🚫<code>{stats.malicious}/{stats.total} ({round(stats.malicious/total*100,1)}%)│{self.strings('malicious')}</code>\n"
               f"⚠️<code>{stats.suspicious}/{stats.total} ({round(stats.suspicious/total*100,1)}%)│{self.strings('suspicious')}</code>\n"
               f"{self._emoji('success')}<code>{stats.harmless}/{stats.total} ({round(stats.harmless/total*100,1)}%)│{self.strings('harmless')}</code>\n"
               f"👁️<code>{stats.undetected}/{stats.total} ({round(stats.undetected/total*100,1)}%)│{self.strings('undetected')}</code></blockquote>")
            mid=msg.id if hasattr(msg,'id') else id(msg)
            self._result_cache[mid]=(t,vt_url,time.time())
            self._db.set(__name__,f"result_{mid}",{'text':t,'vt_url':vt_url,'timestamp':time.time()})
            await self.inline.form(text=t,message=msg,reply_markup=self._result_buttons(vt_url,mid),ttl=300)
        except Exception as e:
            await utils.answer(msg,await self._handle_error(e,"show_results"))

    async def _history_cb(self,call,page:int=1,return_id:Optional[int]=None):
        if not self.history:
            t=f"{self._emoji('history_empty')} <b>{self.strings('history_empty')}</b>"
            if hasattr(call,'inline_message_id'):await call.edit(text=t,reply_markup=None)
            else:await call.edit(text=t)
            return
        t=len(self.history)
        p=(t+HISTORY_PER_PAGE-1)//HISTORY_PER_PAGE
        page=max(1,min(page,p))
        s=(page-1)*HISTORY_PER_PAGE
        e=self.history[s:s+HISTORY_PER_PAGE]
        l=[f"<b>{self._emoji('history')} {self.strings('history_title')}</b>","━━━━━━━━━━━━━━━━━━━",f"<b>{self._emoji('pages')} {self.strings('entries')} {s+1}-{min(s+HISTORY_PER_PAGE,t)} {self.strings('of')} {t}</b>"]
        for i,en in enumerate(e,s+1):
            dt=en.timestamp.strftime("%H:%M %d.%m UTC")
            se,_=self._get_status(en.stats)
            if en.scan_type=='file':
                n=(en.name or self.strings('unknown'))[:25]+('...' if en.name and len(en.name)>25 else '')
                b=f"<b>{i}.</b> {self._emoji('file')} <b>{n}</b>\n   {self._emoji('hash')} <code>{en.item_id}</code>\n   {self._emoji('time')} <code>{dt}</code>\n   {se} <code>{en.stats.malicious}/{en.stats.total}</code>"
            elif en.scan_type=='ip':
                fg=self._country_flag(en.country_code) if en.country_code else '🏳️'
                n=en.as_owner or en.name or self.strings('unknown')
                b=f"<b>{i}.</b> {fg} <b>{n}</b>\n   {self._emoji('url')} <code>{en.url or en.name}</code>\n   {self._emoji('time')} <code>{dt}</code>\n   {se} <code>{en.stats.malicious}/{en.stats.total}</code>"
            else:
                d=urlparse(en.url or '').netloc or ''
                b=f"<b>{i}.</b> {self._emoji('globe')} <b>{d}</b>\n   {self._emoji('url')} <code>{en.url or self.strings('unknown')}</code>\n   {self._emoji('time')} <code>{dt}</code>\n   {se} <code>{en.stats.malicious}/{en.stats.total}</code>"
            l.append(f"<blockquote>{b}</blockquote>")
        l.append(f"\n<b>{self.strings('history_entries')}: {t}/{self.config['max_history_items']}</b>")
        txt='\n'.join(l)
        btns=[]
        nav=[]
        if page>1:nav.append({"text":f"{self._emoji('left_arrow',False)} {self.strings('prev_page')}","callback":self._history_cb,"args":(page-1,return_id)})
        if page<p:nav.append({"text":f"{self.strings('next_page')} {self._emoji('right_arrow',False)}","callback":self._history_cb,"args":(page+1,return_id)})
        if nav:btns.append(nav)
        a=[{"text":f"{self._emoji('trash',False)} {self.strings('clear_history')}","callback":self._clear_confirm_cb},{"text":f"{self._emoji('refresh',False)} {self.strings('refresh')}","callback":self._history_cb,"args":(page,return_id)}]
        if return_id:a.append({"text":f"{self._emoji('back_arrow',False)} {self.strings('back_to_results')}","callback":self._return_cb,"args":(return_id,)})
        btns.append(a)
        if hasattr(call,'inline_message_id'):await call.edit(text=txt,reply_markup=btns)
        else:await self.inline.form(text=txt,message=call,reply_markup=btns,ttl=300)

    async def _clear_confirm_cb(self,call):
        if not self.history:return await call.answer(self.strings('history_empty'),show_alert=True)
        t=f"<b>{self._emoji('warning')} {self.strings('confirm_clear')}</b>\n━━━━━━━━━━━━━━━━━━━\n\n{self.strings('clear_history_confirm')}\n<b>{self.strings('entries')}: {len(self.history)}</b>"
        await call.edit(text=t,reply_markup=[[{"text":f"{self._emoji('success',False)} {self.strings('yes_clear')}","callback":self._clear_cb},{"text":self.strings('cancel'),"callback":self._cancel_cb}]])

    async def _clear_cb(self,call):
        c=len(self.history)
        self.history.clear()
        self._db.set(__name__,'history',[])
        await call.edit(text=f"<b>{self._emoji('success')} {self.strings('history_cleared')}! {self.strings('deleted_entries')}: {c}</b>",reply_markup=None)

    async def _cancel_cb(self,call):await self._history_cb(call,1)

    async def _return_cb(self,call,msg_id:int):
        if msg_id in self._result_cache:
            t,vu,ts=self._result_cache[msg_id]
            if time.time()-ts<self._cache_ttl:return await call.edit(text=t,reply_markup=self._result_buttons(vu,msg_id))
        d=self._db.get(__name__,f"result_{msg_id}")
        if not d:return await call.answer(self.strings('error').format('Result expired'),show_alert=True) or await call.delete()
        self._result_cache[msg_id]=(d['text'],d['vt_url'],time.time())
        await call.edit(text=d['text'],reply_markup=self._result_buttons(d['vt_url'],msg_id))

    @loader.command(ru_doc="[файл/ссылка/айпи] - просканировать",en_doc="[file/url/IP] - scan")
    async def vt(self,message):
        if not self.api_keys:return await utils.answer(message,f"{self._emoji('forbidden')} <b>{self.strings('no_key')}</b>")
        r=await message.get_reply_message()
        if r and r.document:
            m=await utils.answer(message,f"<b>{self._emoji('downloading')} {self.strings('downloading')}</b>")
            s=time.time()
            try:
                fb=await r.download_media(bytes)
                sz=len(fb)
                if sz>MAX_FILE_SIZE:return await m.edit(f"<b>{self._emoji('forbidden')} {self.strings('size_limit')}</b>")
                fh=hashlib.sha256(fb).hexdigest()
                await m.edit(f"<b>{self._emoji('check')} {self.strings('checking_cache')}</b>")
                try:
                    if ex:=await self.get_file_report(fh):return await self._show_results(m,fh,ex,'file',name=r.file.name,scan_time=int(time.time()-s),file_size=sz,is_hash=False)
                except Exception as e:
                    et=await self._handle_error(e,"check_cache")
                    return await m.edit(et)
                await m.edit(f"<b>{self._emoji('upload')} {self.strings('uploading')}</b>")
                try:aid=await self.upload_file(r.file.name or 'file.bin',fb)
                except Exception as e:
                    et=await self._handle_error(e,"upload")
                    return await m.edit(et)
                if not aid:return await m.edit(f"<b>{self._emoji('error')} {self.strings('upload_error')}</b>")
                await m.edit(f"<b>{self._emoji('waiting')} {self.strings('waiting')}</b>")
                try:pr=await self._poll_analysis(aid)
                except Exception as e:
                    et=await self._handle_error(e,"poll")
                    return await m.edit(et)
                if not pr:return await m.edit(f"<b>{self._emoji('timeout')} {self.strings('timeout')}</b>")
                try:fn=await self.get_file_report(fh)
                except Exception as e:
                    et=await self._handle_error(e,"final_report")
                    return await m.edit(et)
                await self._show_results(m,fh,fn or pr,'file',name=r.file.name,scan_time=int(time.time()-s),file_size=sz,is_hash=False)
            except Exception as e:
                et=await self._handle_error(e,"file_processing")
                return await m.edit(et)
            return
        t=None
        a=utils.get_args_raw(message)
        if a:t=a.strip()
        if not t and r and r.text:
            f=re.findall(r'https?://[^\s"\'<>]+',r.text)
            t=f[0] if f else None
        if not t:return await utils.answer(message,f"{self._emoji('forbidden')} <b>{self.strings('no_url')}</b>")
        t=t.split('"')[0].split('>')[0].split('<')[0]
        if self._is_valid_ip(t):
            m=await utils.answer(message,f"<b>{self._emoji('globe')} {self.strings('checking')} IP {t}...</b>")
            s=time.time()
            try:rp=await self.get_ip_report(t)
            except Exception as e:
                et=await self._handle_error(e,"ip_report")
                return await m.edit(et)
            if rp:await self._show_results(m,t,rp,'ip',url=t,scan_time=int(time.time()-s))
            else:await m.edit(f"<b>{self._emoji('not_found')} {self.strings('not_found')}</b>")
            return
        u=self._validate_url(t)
        if not u:return await utils.answer(message,f"{self._emoji('error')} <b>{self.strings('invalid_url')}</b>")
        m=await utils.answer(message,f"<b>{self._emoji('url')} {self.strings('scanning_url')}</b>")
        s=time.time()
        uid=base64.urlsafe_b64encode(u.encode()).decode().strip('=')
        await m.edit(f"<b>{self._emoji('check')} {self.strings('checking_cache')}</b>")
        try:
            if ex:=await self.get_url_report(uid):return await self._show_results(m,uid,ex,'url',url=u,scan_time=int(time.time()-s))
        except Exception as e:
            et=await self._handle_error(e,"url_check")
            return await m.edit(et)
        await m.edit(f"<b>{self._emoji('waiting')} {self.strings('waiting')}</b>")
        try:sc=await self.scan_url(u)
        except Exception as e:
            et=await self._handle_error(e,"url_scan")
            return await m.edit(et)
        if not sc or not (aid:=sc.get('data',{}).get('id')):return await m.edit(f"<b>{self._emoji('error')} {self.strings('scan_error')}</b>")
        try:pr=await self._poll_analysis(aid)
        except Exception as e:
            et=await self._handle_error(e,"url_poll")
            return await m.edit(et)
        if not pr:return await m.edit(f"<b>{self._emoji('timeout')} {self.strings('timeout')}</b>")
        try:fn=await self.get_url_report(uid)
        except Exception as e:
            et=await self._handle_error(e,"url_final")
            return await m.edit(et)
        await self._show_results(m,uid,fn or pr,'url',url=u,scan_time=int(time.time()-s))

    @loader.command(ru_doc="[хеш] - проверить по хешу",en_doc="[hash] - check by hash")
    async def vthash(self,message):
        if not self.api_keys:return await utils.answer(message,f"{self._emoji('forbidden')} <b>{self.strings('no_key')}</b>")
        a=utils.get_args_raw(message)
        if not a:return await utils.answer(message,f"{self._emoji('error')} <b>{self.strings('specify_hash')}</b>")
        fh=a.strip().lower()
        ht='SHA256' if re.match(r'^[a-f0-9]{64}$',fh) else 'MD5' if re.match(r'^[a-f0-9]{32}$',fh) else None
        if not ht:
            fd=[e for e in self.history if fh in e.item_id.lower()]
            if fd:
                l=[f"<b>{self._emoji('check')} {self.strings('hash_check')}</b>\n<code>━━━━━━━━━━━━━━━━━━━</code>\n\n{self.strings('search_results').format(len(fd),fh)}\n"]
                for e in fd[:5]:
                    dt=e.timestamp.strftime("%H:%M %d.%m UTC")
                    if e.scan_type=='ip' and e.as_owner:
                        fl=self._country_flag(e.country_code) if e.country_code else '🏳️'
                        n=f"{fl} {e.as_owner}"
                    else:n=e.name or e.url or self.strings('unknown')
                    l.append(f"• {self._emoji('file') if e.scan_type=='file' else self._emoji('url')} {n[:30]}")
                    l.append(f"  {self._emoji('time')} {dt}")
                if len(fd)>5:l.append(self.strings('and_more').format(len(fd)-5))
                l.append(f"\n{self.strings('use_full_hash')}")
                return await self.inline.form(text='\n'.join(l),message=message,reply_markup=[[{"text":f"{self._emoji('history',False)} {self.strings('history')}","callback":self._history_cb}]],ttl=60)
            return await utils.answer(message,f"{self._emoji('error')} <b>{self.strings('hash_not_found')}</b>")
        m=await utils.answer(message,f"<b>{self._emoji('hash')} {self.strings('checking_hash')}</b>")
        s=time.time()
        await m.edit(f"<b>{self._emoji('check')} {self.strings('searching_report').format(ht)}</b>")
        try:r=await self.get_file_report(fh)
        except Exception as e:
            et=await self._handle_error(e,"hash_report")
            return await m.edit(et)
        if r:
            sz=r.get('data',{}).get('attributes',{}).get('size',0)
            fn=None
            try:fn=r.get('data',{}).get('attributes',{}).get('meaningful_name')
            except:pass
            dn=fh[:16]+"..."
            hn=fn or f"{self.strings('hash')}: {fh[:16]}..."
            await self._show_results(m,fh,r,'file',name=dn,history_name=hn,scan_time=int(time.time()-s),file_size=sz,is_hash=True)
        else:await m.edit(f"<b>{self._emoji('not_found')} {self.strings('not_found')}</b>")

    @loader.command(ru_doc="[страница] - показать историю",en_doc="[page] - show history")
    async def vthistory(self,message):
        p=1
        try:p=int(utils.get_args_raw(message) or 1)
        except:pass
        await self._history_cb(message,p)

    @loader.command(ru_doc=" - очистить историю",en_doc=" - clear history")
    async def vtclear(self,message):
        if not self.history:return await utils.answer(message,f"{self._emoji('history_empty')} <b>{self.strings('history_empty')}</b>")
        c=len(self.history)
        self.history.clear()
        self._db.set(__name__,'history',[])
        await utils.answer(message,f"{self._emoji('trash')} <b>{self.strings('history_cleared')}</b>. {self._emoji('success')} <b>{self.strings('deleted_entries')}: {c}</b>")
