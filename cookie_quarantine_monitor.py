"""
Cookie Quarantine Monitor 

Author: Jordan Neff 
Date: 2025-11-04
Description: monitoring with instant quarantine and user decision for risky cookies.
Works on macOS, Windows, and Linux.
"""

import os
import sys
import sqlite3
import shutil
import subprocess
import time
import json
import threading
import platform
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac
from typing import Dict, List, Tuple, Set, Optional
import queue

# Try to import watchdog, but make it optional
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("⚠️  Warning: watchdog not installed. File watching disabled (polling only).")
    print("   Install with: pip install watchdog")


class PlatformDetector:
    """Detects OS and provides platform-specific paths and methods."""
    
    def __init__(self):
        self.os_type = platform.system()
        self.browser_paths = self._get_browser_paths()
        
    def _get_browser_paths(self) -> Dict[str, Dict[str, str]]:
        """Get browser cookie database paths for different OSes."""
        home = os.path.expanduser("~")
        
        if self.os_type == "Darwin":  # macOS
            return {
                "chrome": {
                    "cookies": f"{home}/Library/Application Support/Google/Chrome/Default/Cookies",
                    "name": "Google Chrome"
                },
                "edge": {
                    "cookies": f"{home}/Library/Application Support/Microsoft Edge/Default/Cookies",
                    "name": "Microsoft Edge"
                },
                "brave": {
                    "cookies": f"{home}/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
                    "name": "Brave"
                }
            }
        elif self.os_type == "Windows":
            appdata = os.environ.get('LOCALAPPDATA', f"{home}\\AppData\\Local")
            return {
                "chrome": {
                    "cookies": f"{appdata}\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
                    "name": "Google Chrome"
                },
                "edge": {
                    "cookies": f"{appdata}\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies",
                    "name": "Microsoft Edge"
                },
                "brave": {
                    "cookies": f"{appdata}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies",
                    "name": "Brave"
                }
            }
        elif self.os_type == "Linux":
            return {
                "chrome": {
                    "cookies": f"{home}/.config/google-chrome/Default/Cookies",
                    "name": "Google Chrome"
                },
                "chromium": {
                    "cookies": f"{home}/.config/chromium/Default/Cookies",
                    "name": "Chromium"
                },
                "brave": {
                    "cookies": f"{home}/.config/BraveSoftware/Brave-Browser/Default/Cookies",
                    "name": "Brave"
                }
            }
        else:
            return {}
    
    def detect_browser(self) -> Tuple[Optional[str], Optional[str]]:
        """Detect which browser is installed and return its cookie path."""
        for browser, info in self.browser_paths.items():
            cookie_path = info["cookies"]
            if os.path.exists(cookie_path):
                return cookie_path, info["name"]
        return None, None
    
    def get_encryption_key_mac(self) -> bytes:
        """Get encryption key from macOS Keychain."""
        try:
            process = subprocess.Popen(
                ["security", "find-generic-password", "-wa", "Chrome"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            password, err = process.communicate()
            if process.returncode != 0:
                # Try alternative names
                for name in ["Chromium", "Microsoft Edge", "Brave"]:
                    process = subprocess.Popen(
                        ["security", "find-generic-password", "-wa", name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    password, err = process.communicate()
                    if process.returncode == 0:
                        break
                else:
                    raise Exception("Failed to get browser password from Keychain")
            
            password = password.strip()
            salt = b"saltysalt"
            length = 16
            iterations = 1003
            return pbkdf2_hmac("sha1", password, salt, iterations, dklen=length)
        except Exception as e:
            raise Exception(f"macOS Keychain access failed: {e}")
    
    def get_encryption_key_windows(self) -> bytes:
        """Get encryption key from Windows DPAPI."""
        try:
            import win32crypt
            
            # Try to find Local State file
            appdata = os.environ.get('LOCALAPPDATA')
            local_state_paths = [
                f"{appdata}\\Google\\Chrome\\User Data\\Local State",
                f"{appdata}\\Microsoft\\Edge\\User Data\\Local State",
                f"{appdata}\\BraveSoftware\\Brave-Browser\\User Data\\Local State"
            ]
            
            for path in local_state_paths:
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        local_state = json.load(f)
                    
                    encrypted_key = local_state['os_crypt']['encrypted_key']
                    import base64
                    encrypted_key = base64.b64decode(encrypted_key)
                    encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
                    
                    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            
            raise Exception("Could not find Local State file")
        except ImportError:
            raise Exception("win32crypt not available. Install with: pip install pywin32")
        except Exception as e:
            raise Exception(f"Windows DPAPI access failed: {e}")
    
    def get_encryption_key_linux(self) -> bytes:
        """Get encryption key for Linux (uses default password)."""
        # Linux Chrome uses a default password
        password = b'peanuts'
        salt = b'saltysalt'
        length = 16
        iterations = 1
        return pbkdf2_hmac("sha1", password, salt, iterations, dklen=length)
    
    def get_encryption_key(self) -> bytes:
        """Get encryption key based on platform."""
        if self.os_type == "Darwin":
            return self.get_encryption_key_mac()
        elif self.os_type == "Windows":
            return self.get_encryption_key_windows()
        elif self.os_type == "Linux":
            return self.get_encryption_key_linux()
        else:
            raise Exception(f"Unsupported OS: {self.os_type}")


class QuarantineDecision:
    """Represents a quarantine decision for a cookie."""
    ALLOW = "allow"
    BLOCK = "block"
    PENDING = "pending"


class CookieQuarantineManager:
    """Manages quarantined cookies and user decisions."""
    
    def __init__(self):
        self.quarantine_log = []
        self.blocked_cookies = []
        self.allowed_cookies = []
        self.auto_block_critical = False
        self.auto_allow_safe = False
        
    def add_to_quarantine(self, cookie_analysis: Dict) -> str:
        """Add a cookie to quarantine and return decision."""
        cookie_analysis['quarantine_time'] = datetime.now().isoformat()
        cookie_analysis['decision'] = QuarantineDecision.PENDING
        
        self.quarantine_log.append(cookie_analysis)
        
        # Auto-decisions based on risk level
        if self.auto_block_critical and cookie_analysis['risk_level'] == 'CRITICAL':
            return QuarantineDecision.BLOCK
        elif self.auto_allow_safe and cookie_analysis['risk_level'] == 'LOW':
            return QuarantineDecision.ALLOW
        
        return QuarantineDecision.PENDING
    
    def record_decision(self, cookie_analysis: Dict, decision: str):
        """Record user's decision about a quarantined cookie."""
        cookie_analysis['decision'] = decision
        cookie_analysis['decision_time'] = datetime.now().isoformat()
        
        if decision == QuarantineDecision.BLOCK:
            self.blocked_cookies.append(cookie_analysis)
        else:
            self.allowed_cookies.append(cookie_analysis)
    
    def save_quarantine_log(self, filename="quarantine_log.json"):
        """Save quarantine log to file."""
        with open(filename, 'w') as f:
            json.dump({
                'quarantine_log': self.quarantine_log,
                'blocked_cookies': self.blocked_cookies,
                'allowed_cookies': self.allowed_cookies,
                'stats': {
                    'total_quarantined': len(self.quarantine_log),
                    'blocked': len(self.blocked_cookies),
                    'allowed': len(self.allowed_cookies)
                }
            }, f, indent=2)


if WATCHDOG_AVAILABLE:
    class CookieDatabaseWatcher(FileSystemEventHandler):
        """Watches browser's cookie database for changes."""
        
        def __init__(self, callback):
            self.callback = callback
            self.last_modified = time.time()
            self.debounce_seconds = 0.1
            
        def on_modified(self, event):
            """Called when the cookie database is modified."""
            if 'Cookies' in event.src_path or 'cookies' in event.src_path.lower():
                current_time = time.time()
                if current_time - self.last_modified > self.debounce_seconds:
                    self.last_modified = current_time
                    self.callback()


class QuarantineCookieMonitor:
    """Cross-platform cookie quarantine monitor."""
    
    def __init__(self, poll_interval=1, interactive_mode=True):
        self.platform = PlatformDetector()
        self.db_path, self.browser_name = self.platform.detect_browser()
        
        if not self.db_path:
            raise Exception(f"No supported browser found on {self.platform.os_type}")
        
        self.temp_db = "Cookies_quarantine.db"
        self.known_cookie_ids = set()
        self.encryption_key = None
        self.poll_interval = poll_interval
        self.initial_cookie_count = 0
        self.interactive_mode = interactive_mode
        
        # Quarantine system
        self.quarantine_manager = CookieQuarantineManager()
        self.decision_queue = queue.Queue()
        self.pending_decisions = {}
        
        # Thread safety
        self.db_lock = threading.Lock()
        
        print(f"✅ Detected: {self.browser_name}")
        print(f"📂 Cookie database: {self.db_path}")
        print(f"💻 Operating System: {self.platform.os_type}")
        
    def get_encryption_key(self):
        """Get encryption key for the current platform."""
        if self.encryption_key:
            return self.encryption_key
        
        try:
            self.encryption_key = self.platform.get_encryption_key()
            return self.encryption_key
        except Exception as e:
            print(f"⚠️  Warning: Could not get encryption key: {e}")
            print(f"   Encrypted cookies cannot be decrypted.")
            return None
    
    def decrypt_data(self, encrypted_value, key):
        """Decrypt AES-GCM encrypted browser cookies (cross-platform)."""
        if not key:
            return "[encrypted - no key available]"
        
        try:
            # Chrome/Chromium v10/v11 encryption
            if encrypted_value.startswith(b'v10') or encrypted_value.startswith(b'v11'):
                iv = encrypted_value[3:15]
                ciphertext = encrypted_value[15:-16]
                tag = encrypted_value[-16:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted_bytes.decode('utf-8')
            # Windows DPAPI encrypted
            elif self.platform.os_type == "Windows" and encrypted_value.startswith(b'\x01\x00\x00\x00'):
                try:
                    import win32crypt
                    return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8')
                except:
                    pass
            
            # Try plain decode as fallback
            return encrypted_value.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"[decryption_failed: {str(e)}]"
    
    def get_chrome_datetime(self, chromedate):
        """Convert Chrome timestamp to readable datetime."""
        if chromedate != 86400000000 and chromedate:
            try:
                return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
            except:
                return None
        return None
    
    def calculate_security_score(self, cookie: Dict) -> Tuple[int, List[str]]:
        """Calculate security score for a cookie (0-100)."""
        score = 100
        issues = []
        
        if cookie.get('is_secure', 0) == 0:
            score -= 30
            issues.append("❌ Missing 'Secure' flag - can be sent over HTTP")
        
        if cookie.get('is_httponly', 0) == 0:
            score -= 25
            issues.append("⚠️  Missing 'HttpOnly' flag - vulnerable to XSS")
        
        same_site = cookie.get('samesite', -1)
        if same_site == -1 or same_site == 0:
            score -= 20
            issues.append("⚠️  SameSite=None - vulnerable to CSRF")
        elif same_site == 1:
            score -= 5
            issues.append("ℹ️  SameSite=Lax - partial CSRF protection")
        
        expires = cookie.get('expires_utc')
        if expires:
            expiry_date = self.get_chrome_datetime(expires)
            if expiry_date:
                days_until_expiry = (expiry_date - datetime.now()).days
                if days_until_expiry > 365:
                    score -= 15
                    issues.append(f"⚠️  Long expiration: {days_until_expiry} days")
        
        domain = cookie.get('host_key', '')
        if domain.startswith('.'):
            score -= 5
            issues.append(f"ℹ️  Broad domain scope: {domain}")
        
        return max(0, score), issues
    
    def get_risk_level(self, score: int) -> str:
        """Determine risk level based on score."""
        if score >= 80:
            return "LOW"
        elif score >= 60:
            return "MEDIUM"
        elif score >= 40:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def delete_cookie(self, cookie_id: str, host_key: str, name: str) -> bool:
        """Delete a cookie from browser's database."""
        try:
            db = sqlite3.connect(self.db_path)
            cursor = db.cursor()
            
            cursor.execute("""
                DELETE FROM cookies 
                WHERE host_key = ? AND name = ?
            """, (host_key, name))
            
            db.commit()
            deleted = cursor.rowcount > 0
            db.close()
            
            return deleted
        except Exception as e:
            print(f"   ⚠️  Could not delete cookie: {e}")
            print(f"   💡 TIP: Close {self.browser_name} to allow cookie deletion")
            return False
    
    def prompt_user_decision(self, analysis: Dict) -> str:
        """Prompt user for decision on a quarantined cookie."""
        cookie_id = f"{analysis['domain']}:{analysis['name']}"
        
        print("\n" + "🔔" * 35)
        print("⚠️  QUARANTINE ALERT - USER DECISION REQUIRED")
        print("🔔" * 35)
        
        self._print_cookie_alert(analysis)
        
        print("\n📋 WHAT WOULD YOU LIKE TO DO?")
        print("-" * 70)
        print("1. ✅ ALLOW - Keep this cookie (accept the risk)")
        print("2. 🗑️  BLOCK - Delete this cookie immediately")
        print("3. ℹ️  INFO - Show more details")
        print("4. ⏭️  SKIP - Decide later (cookie stays for now)")
        print("-" * 70)
        
        while True:
            try:
                choice = input("\n👉 Your decision (1-4): ").strip()
                
                if choice == "1":
                    print("✅ Cookie ALLOWED")
                    return QuarantineDecision.ALLOW
                elif choice == "2":
                    print(f"🗑️  Attempting to DELETE cookie from {self.browser_name}...")
                    if self.delete_cookie(cookie_id, analysis['domain'], analysis['name']):
                        print("✅ Cookie DELETED successfully!")
                        return QuarantineDecision.BLOCK
                    else:
                        print(f"⚠️  Could not delete cookie ({self.browser_name} might be running)")
                        print("   Cookie will remain but is logged as BLOCKED")
                        return QuarantineDecision.BLOCK
                elif choice == "3":
                    self._print_detailed_info(analysis)
                    continue
                elif choice == "4":
                    print("⏭️  Decision skipped - cookie remains for now")
                    return QuarantineDecision.ALLOW
                else:
                    print("❌ Invalid choice. Please enter 1-4.")
            except KeyboardInterrupt:
                print("\n⏭️  Decision interrupted - cookie remains")
                return QuarantineDecision.ALLOW
    
    def _print_cookie_alert(self, analysis: Dict):
        """Print quarantine alert for a cookie."""
        risk_emoji = {
            "LOW": "✅",
            "MEDIUM": "⚠️ ",
            "HIGH": "🚨",
            "CRITICAL": "💀"
        }
        
        print(f"\n🆕 NEW COOKIE DETECTED")
        print(f"   Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"   Domain: {analysis['domain']}")
        print(f"   Name: {analysis['name']}")
        print(f"   Security Score: {analysis['score']}/100")
        print(f"   Risk Level: {risk_emoji[analysis['risk_level']]} {analysis['risk_level']}")
        
        if analysis['issues']:
            print(f"\n   ⚠️  Security Issues:")
            for issue in analysis['issues']:
                print(f"      {issue}")
    
    def _print_detailed_info(self, analysis: Dict):
        """Print detailed information about a cookie."""
        print("\n" + "=" * 70)
        print("📊 DETAILED COOKIE INFORMATION")
        print("=" * 70)
        print(f"Domain: {analysis['domain']}")
        print(f"Name: {analysis['name']}")
        print(f"Value: {analysis['value']}")
        print(f"Secure: {analysis['secure']}")
        print(f"HttpOnly: {analysis['httpOnly']}")
        print(f"SameSite: {analysis['sameSite']}")
        print(f"Security Score: {analysis['score']}/100")
        print(f"Risk Level: {analysis['risk_level']}")
        
        if analysis['issues']:
            print(f"\nSecurity Issues:")
            for issue in analysis['issues']:
                print(f"  {issue}")
        
        print("\n💡 RECOMMENDATIONS:")
        if analysis['score'] >= 80:
            print("  ✅ This cookie appears safe to keep")
        elif analysis['score'] >= 60:
            print("  ⚠️  This cookie has moderate risk - consider your trust in this site")
        elif analysis['score'] >= 40:
            print("  🚨 This cookie is risky - recommend blocking unless you trust the site")
        else:
            print("  💀 This cookie is highly unsafe - strongly recommend blocking")
        print("=" * 70)
    
    def analyze_new_cookies(self, source=""):
        """Check for NEW cookies and quarantine risky ones."""
        with self.db_lock:
            try:
                if os.path.exists(self.temp_db):
                    os.remove(self.temp_db)
                shutil.copyfile(self.db_path, self.temp_db)
            except Exception as e:
                return
            
            db = sqlite3.connect(self.temp_db)
            db.text_factory = lambda b: b.decode(errors="ignore")
            cursor = db.cursor()
            
            cursor.execute("""
            SELECT host_key, name, value, creation_utc, last_access_utc, 
                   expires_utc, encrypted_value, is_secure, is_httponly, samesite
            FROM cookies
            """)
            
            key = self.get_encryption_key()
            new_cookies = []
            
            for row in cursor.fetchall():
                host_key, name, value, creation_utc, last_access_utc, expires_utc, \
                encrypted_value, is_secure, is_httponly, samesite = row
                
                cookie_id = f"{host_key}:{name}"
                
                if cookie_id in self.known_cookie_ids:
                    continue
                
                self.known_cookie_ids.add(cookie_id)
                
                # Decrypt value
                if not value and encrypted_value:
                    decrypted_value = self.decrypt_data(encrypted_value, key)
                else:
                    decrypted_value = value
                
                # Build cookie dict
                cookie_data = {
                    'host_key': host_key,
                    'name': name,
                    'value': decrypted_value,
                    'creation_utc': creation_utc,
                    'last_access_utc': last_access_utc,
                    'expires_utc': expires_utc,
                    'is_secure': is_secure,
                    'is_httponly': is_httponly,
                    'samesite': samesite
                }
                
                score, issues = self.calculate_security_score(cookie_data)
                risk_level = self.get_risk_level(score)
                
                analysis = {
                    'timestamp': datetime.now().isoformat(),
                    'domain': host_key,
                    'name': name,
                    'value': decrypted_value[:50] + '...' if len(decrypted_value) > 50 else decrypted_value,
                    'score': score,
                    'risk_level': risk_level,
                    'issues': issues,
                    'secure': bool(is_secure),
                    'httpOnly': bool(is_httponly),
                    'sameSite': ['None', 'Lax', 'Strict'][samesite] if samesite in [0,1,2] else 'None',
                    'cookie_id': cookie_id
                }
                
                new_cookies.append(analysis)
            
            db.close()
            
            # Process new cookies through quarantine
            for analysis in new_cookies:
                self.process_quarantine(analysis)
    
    def process_quarantine(self, analysis: Dict):
        """Process a cookie through the quarantine system."""
        initial_decision = self.quarantine_manager.add_to_quarantine(analysis)
        
        if initial_decision == QuarantineDecision.ALLOW:
            print(f"\n✅ AUTO-ALLOWED: {analysis['domain']} - {analysis['name']} (Low Risk)")
            self.quarantine_manager.record_decision(analysis, QuarantineDecision.ALLOW)
            
        elif initial_decision == QuarantineDecision.BLOCK:
            print(f"\n🗑️  AUTO-BLOCKED: {analysis['domain']} - {analysis['name']} (Critical Risk)")
            self.delete_cookie(analysis['cookie_id'], analysis['domain'], analysis['name'])
            self.quarantine_manager.record_decision(analysis, QuarantineDecision.BLOCK)
            
        else:
            if self.interactive_mode and analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                decision = self.prompt_user_decision(analysis)
                self.quarantine_manager.record_decision(analysis, decision)
            else:
                print(f"\n📝 LOGGED: {analysis['domain']} - {analysis['name']} " +
                      f"(Score: {analysis['score']}, Risk: {analysis['risk_level']})")
                self.quarantine_manager.record_decision(analysis, QuarantineDecision.ALLOW)
    
    def initial_scan(self):
        """Count existing cookies but don't analyze them - just mark as known."""
        print("🔍 Performing initial scan of existing cookies...")
        try:
            shutil.copyfile(self.db_path, self.temp_db)
            db = sqlite3.connect(self.temp_db)
            db.text_factory = lambda b: b.decode(errors="ignore")
            cursor = db.cursor()
            
            cursor.execute("SELECT host_key, name FROM cookies")
            
            for host_key, name in cursor.fetchall():
                cookie_id = f"{host_key}:{name}"
                self.known_cookie_ids.add(cookie_id)
            
            db.close()
            
            self.initial_cookie_count = len(self.known_cookie_ids)
            
            print(f"✅ Found {self.initial_cookie_count} existing cookies")
            print(f"🛡️  Quarantine system active - monitoring for NEW cookies")
        except Exception as e:
            print(f"⚠️  Initial scan failed: {e}")
    
    def polling_worker(self, stop_event):
        """Worker thread that polls the database periodically."""
        while not stop_event.is_set():
            time.sleep(self.poll_interval)
            self.analyze_new_cookies(source="POLL")
    
    def start_monitoring(self, duration=None, auto_block_critical=False, auto_allow_safe=False):
        """Start monitoring browser's cookie database with quarantine."""
        print("\n" + "="*70)
        print(f"🛡️  COOKIE QUARANTINE MONITOR - {self.browser_name}")
        print("="*70)
        print("🔒 Mode: Active Quarantine with User Decisions")
        print(f"💻 Platform: {self.platform.os_type}")
        print(f"⚡ Detection: {self.poll_interval}s polling", end="")
        if WATCHDOG_AVAILABLE:
            print(" + instant file watch")
        else:
            print(" (file watch unavailable)")
        print(f"🎯 Interactive Mode: {self.interactive_mode}")
        print(f"🚫 Auto-block CRITICAL: {auto_block_critical}")
        print(f"✅ Auto-allow SAFE: {auto_allow_safe}")
        
        self.quarantine_manager.auto_block_critical = auto_block_critical
        self.quarantine_manager.auto_allow_safe = auto_allow_safe
        
        if duration:
            print(f"⏱️  Will run for {duration} seconds")
        else:
            print("⏱️  Running indefinitely (Press Ctrl+C to stop)")
        print("="*70 + "\n")
        
        self.initial_scan()
        
        # Set up file watcher if available
        observer = None
        if WATCHDOG_AVAILABLE:
            browser_dir = os.path.dirname(self.db_path)
            event_handler = CookieDatabaseWatcher(lambda: self.analyze_new_cookies(source="WATCH"))
            observer = Observer()
            observer.schedule(event_handler, browser_dir, recursive=False)
            observer.start()
        
        # Start polling thread
        stop_event = threading.Event()
        poll_thread = threading.Thread(target=self.polling_worker, args=(stop_event,), daemon=True)
        poll_thread.start()
        
        try:
            start_time = time.time()
            while True:
                time.sleep(1)
                if duration and (time.time() - start_time) >= duration:
                    break
        except KeyboardInterrupt:
            print("\n\n⏹️  Stopping quarantine monitor...")
        finally:
            stop_event.set()
            if observer:
                observer.stop()
                observer.join()
            poll_thread.join(timeout=2)
            self._print_summary()
            self.quarantine_manager.save_quarantine_log()
    
    def _print_summary(self):
        """Print monitoring summary."""
        manager = self.quarantine_manager
        
        print("\n" + "=" * 70)
        print("📈 QUARANTINE SESSION SUMMARY")
        print("=" * 70)
        print(f"Browser: {self.browser_name}")
        print(f"Platform: {self.platform.os_type}")
        print(f"Initial Cookie Count: {self.initial_cookie_count}")
        print(f"Final Cookie Count: {len(self.known_cookie_ids)}")
        print(f"New Cookies Detected: {len(manager.quarantine_log)}")
        print(f"\n🛡️  Quarantine Actions:")
        print(f"  ✅ Allowed: {len(manager.allowed_cookies)}")
        print(f"  🗑️  Blocked: {len(manager.blocked_cookies)}")
        
        if manager.quarantine_log:
            risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            for cookie in manager.quarantine_log:
                risk_counts[cookie['risk_level']] += 1
            
            print(f"\n📊 Risk Distribution:")
            print(f"  ✅ Safe (Low):        {risk_counts['LOW']}")
            print(f"  ⚠️  Moderate (Medium): {risk_counts['MEDIUM']}")
            print(f"  🚨 Unsafe (High):     {risk_counts['HIGH']}")
            print(f"  💀 Critical:          {risk_counts['CRITICAL']}")
        
        print("=" * 70)
        print("💾 Quarantine log saved to: quarantine_log.json")


def main():
    """Start the quarantine cookie monitor."""
    print("\n🛡️  CROSS-PLATFORM COOKIE QUARANTINE MONITOR")
    print("=" * 70)
    print("Supports: macOS, Windows, and Linux")
    print("Browsers: Chrome, Edge, Brave, Chromium")
    print("=" * 70)
    
    try:
        # Try to detect system
        platform_detector = PlatformDetector()
        db_path, browser_name = platform_detector.detect_browser()
        
        if not db_path:
            print("\n❌ No supported browser found!")
            print(f"   OS: {platform_detector.os_type}")
            print("\n   Supported browsers:")
            for browser, info in platform_detector.browser_paths.items():
                print(f"   - {info['name']}: {info['cookies']}")
            sys.exit(1)
        
        print(f"\n✅ Detected: {browser_name}")
        print(f"📂 Cookie database: {db_path}")
        
    except Exception as e:
        print(f"\n❌ Error during initialization: {e}")
        sys.exit(1)
    
    print("\nThis monitor will:")
    print("  • Detect new cookies in real-time")
    print("  • Analyze their security")
    print("  • Ask you to ALLOW or BLOCK risky cookies")
    print(f"  • Delete blocked cookies from {browser_name}")
    print("=" * 70)
    
    # Configuration
    try:
        auto_block = input("\n🚫 Auto-block CRITICAL risk cookies? (y/n, default=n): ").strip().lower() == 'y'
        auto_allow = input("✅ Auto-allow LOW risk cookies? (y/n, default=n): ").strip().lower() == 'y'
    except:
        auto_block = False
        auto_allow = False
    
    try:
        monitor = QuarantineCookieMonitor(
            poll_interval=1,
            interactive_mode=True
        )
        
        monitor.start_monitoring(
            auto_block_critical=auto_block,
            auto_allow_safe=auto_allow
        )
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()