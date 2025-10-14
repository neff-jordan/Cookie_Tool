"""
Background Cookie Database Watcher - NEW COOKIES ONLY VERSION
Continuously monitors Chrome's cookie database for NEW cookies only

Author: Jordan Neff
Date: 2025-10-08
Description: Watches Chrome's cookie database file for changes and analyzes
only NEW cookies (when count goes from 2000 -> 2001+), ignoring existing ones.
"""

import os
import sqlite3
import shutil
import subprocess
import time
import json
import threading
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac
from typing import Dict, List, Tuple, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class CookieDatabaseWatcher(FileSystemEventHandler):
    """Watches Chrome's cookie database for changes."""
    
    def __init__(self, callback):
        self.callback = callback
        self.last_modified = time.time()
        self.debounce_seconds = 1
        
    def on_modified(self, event):
        """Called when the cookie database is modified."""
        if event.src_path.endswith('Cookies'):
            current_time = time.time()
            if current_time - self.last_modified > self.debounce_seconds:
                self.last_modified = current_time
                print(f"🔔 File system change detected at {datetime.now().strftime('%H:%M:%S')}")
                self.callback()


class BackgroundCookieMonitor:
    """Monitors Chrome browsing activity for NEW cookies only."""
    
    def __init__(self, poll_interval=5):
        self.db_path = os.path.expanduser(
            "~/Library/Application Support/Google/Chrome/Default/Cookies"
        )
        self.temp_db = "Cookies_monitor.db"
        self.known_cookie_ids = set()  # Just track IDs, not values
        self.security_log = []
        self.encryption_key = None
        self.poll_interval = poll_interval
        self.last_db_size = 0
        self.last_db_mtime = 0
        self.initial_cookie_count = 0
        
    def get_encryption_key(self):
        """Get AES encryption key from macOS Keychain."""
        if self.encryption_key:
            return self.encryption_key
            
        process = subprocess.Popen(
            ["security", "find-generic-password", "-wa", "Chrome"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        password, err = process.communicate()
        if process.returncode != 0:
            raise Exception("Failed to get Chrome password from Keychain")
        password = password.strip()

        salt = b"saltysalt"
        length = 16
        iterations = 1003
        self.encryption_key = pbkdf2_hmac("sha1", password, salt, iterations, dklen=length)
        return self.encryption_key
    
    def decrypt_data(self, encrypted_value, key):
        """Decrypt AES-GCM encrypted Chrome cookies."""
        try:
            if encrypted_value.startswith(b'v10') or encrypted_value.startswith(b'v11'):
                iv = encrypted_value[3:15]
                ciphertext = encrypted_value[15:-16]
                tag = encrypted_value[-16:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted_bytes.decode('utf-8')
            else:
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
    
    def check_database_changed(self) -> bool:
        """Check if database file has changed since last check."""
        try:
            stat = os.stat(self.db_path)
            size = stat.st_size
            mtime = stat.st_mtime
            
            changed = (size != self.last_db_size or mtime != self.last_db_mtime)
            
            self.last_db_size = size
            self.last_db_mtime = mtime
            
            return changed
        except Exception:
            return False
    
    def analyze_new_cookies(self, source=""):
        """Check for NEW cookies only (when count increases beyond initial scan)."""
        try:
            if os.path.exists(self.temp_db):
                os.remove(self.temp_db)
            shutil.copyfile(self.db_path, self.temp_db)
        except Exception as e:
            print(f"⚠️  Could not copy database: {e}")
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
        new_cookie_count = 0
        
        for row in cursor.fetchall():
            host_key, name, value, creation_utc, last_access_utc, expires_utc, \
            encrypted_value, is_secure, is_httponly, samesite = row
            
            cookie_id = f"{host_key}:{name}"
            
            # Skip if we've already seen this cookie ID
            if cookie_id in self.known_cookie_ids:
                continue
            
            # This is a NEW cookie!
            self.known_cookie_ids.add(cookie_id)
            new_cookie_count += 1
            
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
                'cookie_number': len(self.known_cookie_ids)
            }
            
            self.security_log.append(analysis)
            self._print_cookie_alert(analysis, source)
        
        db.close()
        
        if new_cookie_count > 0:
            total_now = len(self.known_cookie_ids)
            if source:
                print(f"   [{source}] Detected {new_cookie_count} NEW cookie(s)")
                print(f"   📊 Total cookies: {self.initial_cookie_count} -> {total_now}\n")
    
    def _print_cookie_alert(self, analysis: Dict, source=""):
        """Print alert for a detected NEW cookie."""
        risk_emoji = {
            "LOW": "✅",
            "MEDIUM": "⚠️ ",
            "HIGH": "🚨",
            "CRITICAL": "💀"
        }
        
        source_tag = f" via {source}" if source else ""
        
        print("=" * 70)
        print(f"🆕 {risk_emoji[analysis['risk_level']]} NEW COOKIE DETECTED{source_tag}")
        print(f"   Cookie #{analysis['cookie_number']} (was {self.initial_cookie_count})")
        print(f"   Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"   Domain: {analysis['domain']}")
        print(f"   Name: {analysis['name']}")
        print(f"   Value: {analysis['value']}")
        print(f"   Security Score: {analysis['score']}/100 ({analysis['risk_level']} RISK)")
        print(f"   Secure: {analysis['secure']} | HttpOnly: {analysis['httpOnly']} | SameSite: {analysis['sameSite']}")
        
        if analysis['issues']:
            print(f"\n   Security Issues:")
            for issue in analysis['issues']:
                print(f"      {issue}")
        
        if analysis['score'] >= 80:
            print(f"\n   ✅ VERDICT: This cookie is SAFE")
        elif analysis['score'] >= 60:
            print(f"\n   ⚠️  VERDICT: This cookie has MODERATE risk")
        else:
            print(f"\n   🚨 VERDICT: This cookie is UNSAFE - consider deleting!")
        
        print("=" * 70)
    
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
            
            # Initialize change detection
            stat = os.stat(self.db_path)
            self.last_db_size = stat.st_size
            self.last_db_mtime = stat.st_mtime
            
            print(f"✅ Found {self.initial_cookie_count} existing cookies")
            print(f"📊 Database size: {self.last_db_size:,} bytes")
            print(f"👀 Now watching for NEW cookies (#{self.initial_cookie_count + 1}+)")
        except Exception as e:
            print(f"⚠️  Initial scan failed: {e}")
    
    def polling_worker(self, stop_event):
        """Worker thread that polls the database periodically."""
        print(f"🔄 Polling thread started (checking every {self.poll_interval}s)")
        
        while not stop_event.is_set():
            time.sleep(self.poll_interval)
            
            if self.check_database_changed():
                print(f"🔔 Database change detected via polling at {datetime.now().strftime('%H:%M:%S')}")
                self.analyze_new_cookies(source="POLL")
    
    def start_monitoring(self, duration=None):
        """Start monitoring Chrome's cookie database for NEW cookies only."""
        print("\n" + "="*70)
        print("🚀 BACKGROUND COOKIE MONITOR - NEW COOKIES ONLY")
        print("="*70)
        print("📡 Using HYBRID monitoring (file watching + polling)")
        print(f"🔄 Polling interval: {self.poll_interval} seconds")
        print("🎯 Mode: NEW cookies only (no analysis of existing cookies)")
        print("🌐 Visit any website in Chrome to see real-time cookie analysis")
        if duration:
            print(f"⏱️  Will run for {duration} seconds")
        else:
            print("⏱️  Running indefinitely (Press Ctrl+C to stop)")
        print("="*70 + "\n")
        
        self.initial_scan()
        
        # Set up file watcher
        chrome_dir = os.path.dirname(self.db_path)
        event_handler = CookieDatabaseWatcher(lambda: self.analyze_new_cookies(source="FILE WATCH"))
        observer = Observer()
        observer.schedule(event_handler, chrome_dir, recursive=False)
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
            print("\n\n⏹️  Stopping monitor...")
        finally:
            stop_event.set()
            observer.stop()
            observer.join()
            poll_thread.join(timeout=2)
            self._print_summary()
            self.save_log()
    
    def _print_summary(self):
        """Print monitoring summary."""
        if not self.security_log:
            print("\n📭 No new cookies detected during monitoring period.")
            print(f"   Total cookies remained at: {self.initial_cookie_count}")
            return
        
        risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        total_score = 0
        
        for cookie in self.security_log:
            risk_counts[cookie['risk_level']] += 1
            total_score += cookie['score']
        
        avg_score = total_score / len(self.security_log)
        
        print("\n" + "=" * 70)
        print("📈 MONITORING SUMMARY")
        print("=" * 70)
        print(f"Initial Cookie Count: {self.initial_cookie_count}")
        print(f"Final Cookie Count: {len(self.known_cookie_ids)}")
        print(f"New Cookies Detected: {len(self.security_log)}")
        print(f"Average Security Score: {avg_score:.1f}/100")
        print(f"\nRisk Distribution:")
        print(f"  ✅ Safe (Low Risk):        {risk_counts['LOW']}")
        print(f"  ⚠️  Moderate (Medium Risk): {risk_counts['MEDIUM']}")
        print(f"  🚨 Unsafe (High Risk):     {risk_counts['HIGH']}")
        print(f"  💀 Unsafe (Critical Risk): {risk_counts['CRITICAL']}")
        print("=" * 70)
    
    def save_log(self, filename="new_cookies_log.json"):
        """Save monitoring log to file."""
        if self.security_log:
            with open(filename, 'w') as f:
                json.dump(self.security_log, f, indent=2)
            print(f"\n💾 Security log saved to: {filename}")


def main():
    """Start the background cookie monitor for NEW cookies only."""
    monitor = BackgroundCookieMonitor(poll_interval=3)
    
    # Run indefinitely (or set duration in seconds)
    monitor.start_monitoring()


if __name__ == "__main__":
    main()