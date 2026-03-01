# VirusTotal Hikka Bot
Author: @monkvy  
Version: 3.0.0

## 📥 Installation
```
.dlm https://raw.githubusercontent.com/monkvy/VirusTotal-hikka-bot/refs/heads/main/VirusTotal_V3.py
```

## 💻 Commands
```
.vt <file/url/ip> — scan a file (reply), URL or IP address (autodetect)
.vthash <hash> — check by hash (SHA256 / MD5)
.vthistory — show scan history
.vtclear — clear history
.vtlang <ru/en> — change language
```

## ⚙️ Config
```
api_key — VirusTotal API key (required)
max_wait_time — max wait time in seconds (default: 300)
poll_interval — check interval in seconds (default: 10)
save_history — save scan history (default: True)
max_history_items — max history entries (default: 10)
language — interface language (ru/en)
cleanup_interval — clean old results every N seconds (default: 3600)
```

## 📊 Understanding Results
🚫 Malicious — dangerous  
⚠️ Suspicious — potentially unsafe  
✅ Harmless — safe  
👁️ Undetected — no detection  

0–2 detections — low risk  
3–5 — medium risk  
6–10 — high risk  
10+ — critical risk  

## 🔑 Getting an API Key
1. Register at https://www.virustotal.com  
2. Go to your profile settings  
3. Copy your API key  
4. Paste it into the module config  

## 🔄 What’s New in v3.0.0
• .vt command unified – scan files, links, IPs in one go.    
• IP scanning added – country flag and AS owner visible in results & history.     
• Links auto‑https enabled.     
• Automatic cleanup of old data (default: 1 hour)    
• Refined architecture – more stable and easier to maintain.     

## 📞 Support
For any questions: TG @monkvy
