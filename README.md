# 🛡️ VulnScanAI

**A Python-based Web Vulnerability Scanner with SQLMap Integration**

VulnScanAI is a powerful and extensible tool for detecting common web vulnerabilities such as SQL Injection, XSS, SSRF, IDOR, and Open Redirects. Designed for ethical hackers, penetration testers, and security researchers, it combines automated scanning with a user-friendly GUI and detailed reporting.

---

## 🌟 Features

- 🔍 **Vulnerability Detection**:
  - SQL Injection (via SQLMap)
  - Cross-Site Scripting (XSS)
  - Server-Side Request Forgery (SSRF)
  - Insecure Direct Object References (IDOR)
  - Open Redirects
- 🖥️ **GUI Application** (Tkinter)
- 🔐 **Supports Authentication** (Cookies, Headers, POST Data)
- 📊 **Detailed JSON Reports** with severity, evidence, and timestamps
- 🧪 **Extensible Architecture** for adding new checks

---

## 📦 Installation

### Prerequisites

- Python 3.8+
- Git

### Clone the Repo

```bash
git clone https://github.com/yourusername/VulnScanAI.git
cd VulnScanAI
```

### Install Dependencies

```bash
pip install requests beautifulsoup4
```

### Download SQLMap

```bash
git clone https://github.com/sqlmapproject/sqlmap.git
```

---

## ▶️ Usage

Run the scanner:

```bash
python3 vuln_scanner.py
```

### GUI Fields

| Field         | Description                          |
|---------------|--------------------------------------|
| Target URL    | URL to scan                          |
| Cookies       | Session cookies (optional)           |
| Headers       | Custom headers (optional)            |
| POST Data     | Form data for POST requests (optional) |

Click **Start Scan** to begin.

---

## 📄 Sample Report (JSON)

```json
[
  {
    "type": "SQL Injection",
    "url": "http://testphp.vulnweb.com/artists.php?artist=1",
    "method": "GET",
    "severity": "High",
    "timestamp": "2025-04-05T14:22:31Z",
    "evidence": "Parameter 'artist' appears to be injectable",
    "tool": "SQLMap",
    "vulnerable": true
  }
]
```

---

## 🧠 Future Enhancements

- Export to PDF/HTML
- CVSS Scoring
- Proxy/Tor Support
- Browser Extension Version
- Dockerized Deployment

---

## ⚠️ Disclaimer

This tool is for **educational and authorized testing purposes only**. Unauthorized scanning of websites is illegal and unethical. Always obtain explicit permission before testing.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🧑‍💻 Contributing

Contributions are welcome! Fork the repo and submit a pull request.

---
