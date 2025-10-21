# Chrome Cookie Security Analyzer

Real-time monitoring and comprehensive security analysis for Chrome browser cookies.

![Python](https://img.shields.io/badge/python-3.7%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

## Features

- 🔍 **Full Cookie Scan** - Analyze all existing cookies with security scoring
- 🎯 **Real-Time Monitor** - Watch for new cookies as they're created
- 📊 **Security Scoring** - Rate cookies from 0-100 based on security best practices
- 🚨 **Risk Detection** - Identify LOW, MEDIUM, HIGH, and CRITICAL risk cookies
- 💾 **JSON Export** - Save detailed reports for further analysis

## What It Checks

- ✅ **Secure flag** - Should be sent over HTTPS only
- ✅ **HttpOnly flag** - Protected from JavaScript access (XSS protection)
- ✅ **SameSite attribute** - CSRF protection (None/Lax/Strict)
- ✅ **Expiration time** - How long cookies persist
- ✅ **Domain scope** - Which sites can access the cookie

## Download

### Option 1: Pre-built Executable (Easiest)

Download from [Releases](https://github.com/yourusername/cookie-analyzer/releases):

- **macOS**: `CookieAnalyzer-v1.0-macOS.dmg`

### Option 2: Run from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/cookie-analyzer.git
cd cookie-analyzer

# Install dependencies
pip install -r requirements.txt

# Run
python cookie_analyzer_crossplatform.py
```

## Quick Start

### macOS
```bash
# 1. Download and extract
# 2. Double-click INSTALL.command
# 3. Double-click "Run Cookie Analyzer.command"
```

## Requirements

- **Python 3.7+** (for source installation)
- **Google Chrome** installed and used at least once

## Building from Source

### Create Standalone Executable

**macOS:**
```bash
pip install pyinstaller
pyinstaller --onefile --windowed \
  --name "Cookie Analyzer" \
  --add-data "cookie_database_watcher_crossplatform.py:." \
  cookie_analyzer_crossplatform.py
```

## 📝 To-Do / Future Features

- [ ] Support for Firefox cookies
- [ ] Support for Edge cookies
- [ ] Support for Brave cookies
- [ ] Cookie deletion feature
- [ ] Browser extension version
- [ ] Export to CSV format
- [ ] Scheduled scans
- [ ] Cookie comparison over time

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Disclaimer**: This tool is for educational and security analysis purposes. Always respect privacy and terms of service.
