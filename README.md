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
- ✅ **Expiration time** - How long cookies persist
- ✅ **Domain scope** - Which sites can access the cookie

## Download

### Option 1: Download Latest Release
https://github.com/neff-jordan/Cookie_Tool/releases/tag/v1.0.0 

### Option 2: Run from Source

```bash
# Clone the repository
gh repo clone yourusername/Cookie_Tool
cd Cookie_Tool

# Install dependencies
pip3 install -r requirements.txt

# Run
python3 chrome_cookie_extractor.py
```

### Option 3: Create Standalone Executable

**macOS:**
```bash
# Clone the repository
gh repo clone yourusername/Cookie_Tool
cd Cookie_Tool

# Install dependencies
pip3 install -r requirements.txt

# Make executable
pip install pyinstaller
pyinstaller --onefile --windowed --name "Cookie Analyzer" chrome_cookie_extractor.py
```

## Requirements

- **Python 3.7+** (for source installation)
- **Google Chrome** installed and used at least once


## 📝 To-Do / Future Features

- [ ] Cookie deletion feature
- [ ] Browser extension version
- [ ] Export to CSV format
- [ ] Scheduled scans

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Disclaimer**: This tool is for educational and security analysis purposes. Always respect privacy and terms of service.
