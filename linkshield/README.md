# 🛡️ LinkShield — Phishing URL Detector (Flask)

A Python/Flask port of the LinkShield phishing URL analyzer. Detects fake login pages and phishing websites before you enter your credentials.

## 📁 Project Structure

```
linkshield/
├── app.py                  # Flask web server (routes)
├── phishing_analyzer.py    # Core URL analysis engine
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── templates/
    └── index.html          # Full frontend (HTML + CSS + JS)
```

## 🚀 Getting Started

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the app

```bash
python app.py
```

### 3. Open in browser

Visit: [http://localhost:5000](http://localhost:5000)

## 🔍 What It Checks

| Check | Description |
|-------|-------------|
| HTTPS Security | Verifies encrypted connection |
| Brand Impersonation | Detects fake google/paypal/etc domains |
| IP Address Usage | Flags raw IP addresses (phishing red flag) |
| Suspicious TLD | Checks for .tk, .ml, .xyz and other abused TLDs |
| Subdomain Abuse | Detects excessive subdomain nesting |
| Suspicious Characters | Homograph attacks, special chars |
| Phishing Keywords | login, verify, secure, password, etc. |
| URL Length | Abnormally long URLs |
| Port Analysis | Unusual port numbers |
| URL Obfuscation | Defanged URLs like hxxps://, http$ |

## 🧠 How Risk Score Works

- Each check has a **weight** (8–30 points)
- `danger` = full weight, `warning` = half weight, `safe` = 0
- Score = (danger points / total weight) × 100
- **< 25** → Legitimate ✅
- **25–49** → Suspicious ⚠️
- **≥ 50** → Phishing ❌

## 🛠️ Tech Stack

- **Backend**: Python 3, Flask
- **Frontend**: Vanilla HTML + CSS + JavaScript (no frameworks)
- **Fonts**: Space Grotesk, Fira Code (Google Fonts)
- **Theme**: Dark mode, red accent

## 📄 License

MIT — Free to use and modify.
