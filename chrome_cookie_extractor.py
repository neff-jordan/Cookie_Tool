"""
Cookie Analyzer - Main Control Script

Author: Jordan Neff
Date: 2025-10-14
Description: Main interface that orchestrates cookie scanning and monitoring
"""

import os
import sys
import sqlite3
import shutil
import subprocess
import json
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac
from typing import Dict, List, Tuple

# Import the monitoring class (assuming it's in cookie_monitor.py)
try:
    from cookie_database_watcher import BackgroundCookieMonitor
except ImportError:
    print("⚠️  Warning: cookie_database_watcher.py not found in current directory")
    BackgroundCookieMonitor = None


class CookieAnalyzer:
    """Main class for analyzing all existing Chrome cookies."""
    
    def __init__(self):
        self.db_path = os.path.expanduser(
            "~/Library/Application Support/Google/Chrome/Default/Cookies"
        )
        self.temp_db = "Cookies_analysis.db"
        self.encryption_key = None
        
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
            issues.append("❌ Missing 'Secure' flag")
        
        if cookie.get('is_httponly', 0) == 0:
            score -= 25
            issues.append("⚠️  Missing 'HttpOnly' flag")
        
        same_site = cookie.get('samesite', -1)
        if same_site == -1 or same_site == 0:
            score -= 20
            issues.append("⚠️  SameSite=None")
        elif same_site == 1:
            score -= 5
            issues.append("ℹ️  SameSite=Lax")
        
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
            issues.append(f"ℹ️  Broad domain scope")
        
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
    
    def scan_all_cookies(self, show_details=True, export_file=None):
        """Scan and analyze all existing cookies in Chrome."""
        print("\n" + "="*70)
        print("🔍 SCANNING ALL EXISTING COOKIES")
        print("="*70)
        
        try:
            if os.path.exists(self.temp_db):
                os.remove(self.temp_db)
            shutil.copyfile(self.db_path, self.temp_db)
        except Exception as e:
            print(f"❌ Error: Could not access cookie database: {e}")
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
        
        cookies_data = []
        risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        total_score = 0
        
        print("📊 Analyzing cookies...\n")
        
        for row in cursor.fetchall():
            host_key, name, value, creation_utc, last_access_utc, expires_utc, \
            encrypted_value, is_secure, is_httponly, samesite = row
            
            # Decrypt value
            if not value and encrypted_value:
                decrypted_value = self.decrypt_data(encrypted_value, key)
            else:
                decrypted_value = value
            
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
            
            risk_counts[risk_level] += 1
            total_score += score
            
            cookie_analysis = {
                'domain': host_key,
                'name': name,
                'value': decrypted_value[:50] + '...' if len(decrypted_value) > 50 else decrypted_value,
                'score': score,
                'risk_level': risk_level,
                'issues': issues,
                'secure': bool(is_secure),
                'httpOnly': bool(is_httponly),
                'sameSite': ['None', 'Lax', 'Strict'][samesite] if samesite in [0,1,2] else 'None',
                'created': str(self.get_chrome_datetime(creation_utc)),
                'expires': str(self.get_chrome_datetime(expires_utc))
            }
            
            cookies_data.append(cookie_analysis)
            
            if show_details and risk_level in ["HIGH", "CRITICAL"]:
                self._print_cookie_detail(cookie_analysis)
        
        db.close()
        
        # Print summary
        total_cookies = len(cookies_data)
        avg_score = total_score / total_cookies if total_cookies > 0 else 0
        
        print("\n" + "="*70)
        print("📈 SCAN SUMMARY")
        print("="*70)
        print(f"Total Cookies: {total_cookies}")
        print(f"Average Security Score: {avg_score:.1f}/100")
        print(f"\nRisk Distribution:")
        print(f"  ✅ Low Risk:      {risk_counts['LOW']} ({risk_counts['LOW']/total_cookies*100:.1f}%)")
        print(f"  ⚠️  Medium Risk:   {risk_counts['MEDIUM']} ({risk_counts['MEDIUM']/total_cookies*100:.1f}%)")
        print(f"  🚨 High Risk:     {risk_counts['HIGH']} ({risk_counts['HIGH']/total_cookies*100:.1f}%)")
        print(f"  💀 Critical Risk: {risk_counts['CRITICAL']} ({risk_counts['CRITICAL']/total_cookies*100:.1f}%)")
        print("="*70)
        
        # Export if requested
        if export_file:
            self._export_results(cookies_data, export_file)
        
        return cookies_data
    
    def _print_cookie_detail(self, cookie: Dict):
        """Print detailed information about a cookie."""
        risk_emoji = {"LOW": "✅", "MEDIUM": "⚠️ ", "HIGH": "🚨", "CRITICAL": "💀"}
        
        print(f"\n{risk_emoji[cookie['risk_level']]} {cookie['risk_level']} RISK COOKIE")
        print(f"   Domain: {cookie['domain']}")
        print(f"   Name: {cookie['name']}")
        print(f"   Score: {cookie['score']}/100")
        if cookie['issues']:
            print(f"   Issues:")
            for issue in cookie['issues']:
                print(f"      {issue}")
        print("-" * 70)
    
    def _export_results(self, cookies_data: List[Dict], filename: str):
        """Export scan results to JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump({
                    'scan_date': datetime.now().isoformat(),
                    'total_cookies': len(cookies_data),
                    'cookies': cookies_data
                }, f, indent=2)
            print(f"\n💾 Results exported to: {filename}")
        except Exception as e:
            print(f"\n⚠️  Failed to export results: {e}")


def print_banner():
    """Print application banner."""
    print("\n" + "="*70)
    print("🍪 CHROME COOKIE SECURITY ANALYZER")
    print("   Real-time monitoring & comprehensive security analysis")
    print("="*70)


def print_menu():
    """Print main menu options."""
    print("\n📋 MAIN MENU")
    print("-" * 70)
    print("1. 🔍 Scan All Existing Cookies (Full Report)")
    print("2. 📊 Scan All Cookies (Summary Only)")
    print("3. 🎯 Start Real-Time Cookie Monitor (New Cookies Only)")
    print("4. 💾 Export Full Cookie Report to JSON")
    print("5. 📈 View Cookie Statistics")
    print("6. ❌ Exit")
    print("-" * 70)


def main():
    """Main application entry point."""
    print_banner()
    
    analyzer = CookieAnalyzer()
    
    while True:
        print_menu()
        
        try:
            choice = input("\n👉 Enter your choice (1-6): ").strip()
            
            if choice == "1":
                # Full scan with details
                print("\n🔍 Starting full cookie scan...")
                print("   This will show detailed info for HIGH and CRITICAL risk cookies")
                input("\nPress Enter to continue...")
                analyzer.scan_all_cookies(show_details=True)
                input("\n\nPress Enter to return to menu...")
                
            elif choice == "2":
                # Summary only
                print("\n📊 Starting quick scan (summary only)...")
                input("\nPress Enter to continue...")
                analyzer.scan_all_cookies(show_details=False)
                input("\n\nPress Enter to return to menu...")
                
            elif choice == "3":
                # Start real-time monitor
                if BackgroundCookieMonitor is None:
                    print("\n❌ Error: cookie_database_watcher.py not found!")
                    print("   Make sure the file is in the same directory.")
                    input("\nPress Enter to return to menu...")
                    continue
                
                print("\n🎯 Starting Real-Time Cookie Monitor")
                print("   This will monitor for NEW cookies only")
                print("   Press Ctrl+C to stop monitoring\n")
                
                try:
                    duration_input = input("   Run for how many seconds? (leave blank for indefinite): ").strip()
                    duration = int(duration_input) if duration_input else None
                except ValueError:
                    duration = None
                
                monitor = BackgroundCookieMonitor(poll_interval=3)
                
                try:
                    monitor.start_monitoring(duration=duration)
                except KeyboardInterrupt:
                    print("\n\n⏹️  Monitor stopped by user")
                
                input("\n\nPress Enter to return to menu...")
                
            elif choice == "4":
                # Export to JSON
                print("\n💾 Export Cookie Report")
                filename = input("   Enter filename (default: cookie_report.json): ").strip()
                if not filename:
                    filename = "cookie_report.json"
                if not filename.endswith('.json'):
                    filename += '.json'
                
                print(f"\n   Scanning and exporting to {filename}...")
                analyzer.scan_all_cookies(show_details=False, export_file=filename)
                input("\n\nPress Enter to return to menu...")
                
            elif choice == "5":
                # Quick stats
                print("\n📈 Gathering cookie statistics...")
                cookies = analyzer.scan_all_cookies(show_details=False)
                
                if cookies:
                    domains = set(c['domain'] for c in cookies)
                    secure_count = sum(1 for c in cookies if c['secure'])
                    httponly_count = sum(1 for c in cookies if c['httpOnly'])
                    
                    print(f"\n📊 Additional Statistics:")
                    print(f"   Unique Domains: {len(domains)}")
                    print(f"   Secure Flag Set: {secure_count} ({secure_count/len(cookies)*100:.1f}%)")
                    print(f"   HttpOnly Flag Set: {httponly_count} ({httponly_count/len(cookies)*100:.1f}%)")
                
                input("\n\nPress Enter to return to menu...")
                
            elif choice == "6":
                # Exit
                print("\n👋 Thanks for using Cookie Security Analyzer!")
                print("   Stay safe online! 🔒\n")
                sys.exit(0)
                
            else:
                print("\n⚠️  Invalid choice. Please enter a number between 1-6.")
                input("Press Enter to continue...")
                
        except KeyboardInterrupt:
            print("\n\n👋 Exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ An error occurred: {e}")
            input("\nPress Enter to return to menu...")


if __name__ == "__main__":
    main()
