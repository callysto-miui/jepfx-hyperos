# HyperOS Bootloader Unlocker - Web Version with Auto Login

A web-based automated tool for requesting Xiaomi/HyperOS bootloader unlocks with automatic token extraction.

## ⚠️ Disclaimer

This tool is for educational purposes only. Using it may violate Xiaomi's Terms of Service. Use at your own risk.

## 🚀 Features

- **Auto Login**: Opens Xiaomi login page and extracts token automatically
- **Manual Token**: Traditional cookie paste method still available
- **Token Verification**: Check account status before starting
- **Automated Timing**: Waits until Beijing midnight (00:00 UTC+8)
- **Real-time Logs**: Live log stream
- **Countdown Timer**: Visual countdown to target time
- **Background Processing**: Runs on server, close browser after starting

## 📋 Prerequisites

- Python 3.11+
- Render account (free tier + UptimeRobot)
- UptimeRobot account (free) to keep service awake

## 🛠️ Deployment

### 1. Push to GitHub

Upload all files to a GitHub repository:
```
.
├── app.py
├── miunlock_aes.py
├── requirements.txt
├── render.yaml
└── templates/
    └── index.html
```

### 2. Deploy on Render

**Option A: Dashboard**
1. Go to [render.com](https://render.com)
2. New + → Web Service
3. Connect your GitHub repo
4. Configure:
   - Runtime: Python 3
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn -w 1 -b 0.0.0.0:10000 app:app`
   - Plan: Free

**Option B: Blueprint**
1. Push `render.yaml` to repo
2. New + → Blueprint
3. Connect repo

### 3. Setup UptimeRobot

1. Go to [uptimerobot.com](https://uptimerobot.com)
2. Add Monitor → HTTP(s)
3. URL: Your Render app URL
4. Interval: 5 minutes
5. This prevents Render free tier from sleeping

## 🔐 How to Use Auto Login

### Method 1: Auto Login (Recommended)

1. Open your deployed app
2. Click **"Open Xiaomi Login Page"** button
3. Login with your Xiaomi account in the popup
4. After login, you'll be redirected to a callback URL
5. **Copy the entire URL** from the address bar
6. Paste it in the text box
7. Click **"Extract Token"**
8. Click **"Verify Token"** to check status
9. Click **"Start Unlock Process"**
10. Close browser - it runs on server!

### Method 2: Manual Token

1. Go to Xiaomi Account login page manually
2. Login and open DevTools (F12)
3. Application → Cookies → find `new_bbs_serviceToken`
4. Copy the value
5. Switch to "Manual Token" tab in the app
6. Paste and verify
7. Start unlock process

## ⚙️ Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Phase Shift | 1400ms | Time offset before midnight |
| Login Method | Auto | Auto or Manual token input |

## 🔴 Important Notes

1. **Free Tier**: 750 hours/month. With 24/7 uptime = ~720 hours. Tight but works.
2. **Cookie Expiry**: Tokens expire. Refresh if you get "Expired Cookie" error.
3. **Account Requirements**:
   - Account older than 30 days
   - Not blocked from requesting
   - Has available quota
4. **Security**: Token stored in memory only, not persisted.

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| "Expired Cookie" | Get fresh token via login |
| "Blocked" | Wait until shown date |
| "Quota Reached" | Wait until next month |
| App sleeping | Check UptimeRobot config |
| Token extraction fails | Use Manual Token method |

## 📝 File Structure

```
.
├── app.py              # Flask backend + unlock logic
├── miunlock_aes.py     # AES crypto module
├── requirements.txt    # Dependencies
├── render.yaml         # Render config
└── templates/
    └── index.html      # Web interface
```

## 📄 License

Educational purposes only. Use responsibly.
