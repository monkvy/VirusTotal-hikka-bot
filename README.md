# VirusTotal Hikka Bot

Author: @monkvy  
Version: 3.0.0

## 📥 Installation

```
.dlm https://raw.githubusercontent.com/monkvy/VirusTotal-hikka-bot/refs/heads/main/VirusTotal%20-%20V2.py
```

## 💻 Commands

```
.vt — scan a file (reply to a file)
.vtl <url> — scan a URL
.vthash <hash> — check by hash (SHA256 / MD5)
.vthistory — scan history
.vtclear — clear history
.vtlang ru/en — change language
```

## ⚙️ Config

```
api_key — VirusTotal API key (required)
max_wait_time — maximum wait time (300 sec)
poll_interval — check interval (10 sec)
save_history — save history (True)
max_history_items — maximum history entries (10)
language — interface language (ru/en)
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
• IP scanning added – visible in results & history.      
• Links auto‑https enabled.     
• Automatic cleanup of old data (default: 1 hour).      
• Refined architecture – more stable and easier to maintain.     

## 📞 Support

For any questions: TG @monkvy
