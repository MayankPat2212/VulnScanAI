import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import requests
from bs4 import BeautifulSoup
import urllib.parse
import json
from datetime import datetime
import threading

# -----------------------------
# Vulnerability Scanner Class
# -----------------------------
class WebVulnScannerApp:
    def add_vuln(self, vuln_type, url, method="GET", severity="Medium", evidence="", tool=None):
        self.report.append({
            "type": vuln_type,
            "url": url,
            "method": method,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "evidence": evidence,
            "tool": tool,
            "vulnerable": True
        })
    
    def __init__(self, root):
        self.root = root
        self.root.title("Web Vulnerability Scanner")
        self.root.geometry("700x600")

        self.create_widgets()
        self.report = []
    
    def check_ssrf(self, url, cookies, headers):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:22"
        ]

        for key in params:
            for payload in ssrf_payloads:
                new_params = params.copy()
                new_params[key] = payload
                query = urllib.parse.urlencode(new_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

                try:
                    res = requests.get(
                        test_url,
                        cookies=dict(item.split("=") for item in cookies.split("; ")) if cookies else {},
                        headers=dict(item.split(": ") for item in headers.split("; ")) if headers else {},
                        timeout=5
                    )
                    if "metadata" in res.text or "root" in res.text or res.elapsed.total_seconds() > 4:
                        self.log(f"[VULN] Possible SSRF detected: {test_url}")
                        self.add_vuln(
                            vuln_type="SSRF",
                            url=test_url,
                            method="GET",
                            severity="High",
                            evidence=f"Response time: {res.elapsed.total_seconds()}s"
                        )
                except Exception as e:
                    self.log(f"[ERROR] SSRF check failed: {e}")
                    
    def check_idor(self, url, cookies, headers):
        import re
        match = re.search(r"/(\d+)/", url)
        if not match:
            return

        current_id = match.group(1)
        test_id = str(int(current_id) + 1)
        test_url = url.replace(current_id, test_id)

        try:
            original_res = requests.get(
                url,
                cookies=dict(item.split("=") for item in cookies.split("; ")) if cookies else {},
                headers=dict(item.split(": ") for item in headers.split("; ")) if headers else {}
            )
            test_res = requests.get(
                test_url,
                cookies=dict(item.split("=") for item in cookies.split("; ")) if cookies else {},
                headers=dict(item.split(": ") for item in headers.split("; ")) if headers else {}
            )

            if abs(len(original_res.text) - len(test_res.text)) < 100 and test_res.status_code == 200:
                self.log(f"[VULN] Possible IDOR detected: {test_url}")
                self.add_vuln(
                    vuln_type="IDOR",
                    url=test_url,
                    method="GET",
                    severity="High",
                    evidence="Similar response size to original user"
                )
        except Exception as e:
            self.log(f"[ERROR] IDOR check failed: {e}")
            
    def create_widgets(self):
        # URL Input
        tk.Label(self.root, text="Target URL:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.url_entry = tk.Entry(self.root, width=60)
        self.url_entry.grid(row=0, column=1, padx=10, pady=5)

        # Cookies
        tk.Label(self.root, text="Cookies (optional):").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.cookies_entry = tk.Entry(self.root, width=60)
        self.cookies_entry.grid(row=1, column=1, padx=10, pady=5)

        # Headers
        tk.Label(self.root, text="Headers (optional):").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.headers_entry = tk.Entry(self.root, width=60)
        self.headers_entry.grid(row=2, column=1, padx=10, pady=5)

        # POST Data
        tk.Label(self.root, text="POST Data (optional):").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.post_data_entry = tk.Entry(self.root, width=60)
        self.post_data_entry.grid(row=3, column=1, padx=10, pady=5)

        # Scan Button
        self.scan_button = tk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=4, column=1, pady=10)

        # Output Area
        self.output_area = scrolledtext.ScrolledText(self.root, width=80, height=20)
        self.output_area.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        # Save Report Button
        self.save_button = tk.Button(self.root, text="Save Report", command=self.save_report)
        self.save_button.grid(row=6, column=1, pady=10)

    def log(self, message):
        self.output_area.insert(tk.END, f"[LOG] {message}\n")
        self.output_area.see(tk.END)

    def start_scan(self):
        self.report = []
        self.output_area.delete(1.0, tk.END)
        threading.Thread(target=self.run_scan).start()

    def run_scan(self):
        url = self.url_entry.get()
        cookies = self.cookies_entry.get()
        headers = self.headers_entry.get()
        post_data = self.post_data_entry.get()
        # Run SSRF and IDOR checks
        self.check_ssrf(url, cookies, headers)
        self.check_idor(url, cookies, headers)

        if not url:
            messagebox.showerror("Error", "Please enter a target URL.")
            return

        self.log(f"Scanning: {url}")

        # Run SQLMap
        self.run_sqlmap(url, cookies, headers, post_data)

        # Run XSS and Redirect checks
        self.check_xss(url, cookies, headers)
        self.check_open_redirect(url, cookies, headers)

        self.log("Scan complete.")

    def run_sqlmap(self, url, cookies, headers, post_data):
        cmd = [
            "python3", "sqlmap/sqlmap.py",
            "-u", url,
            "--batch",
            "--level=3",
            "--risk=2",
            "--output-dir=sqlmap_output"
        ]

        if cookies:
            cmd.extend(["--cookie", cookies])
        if headers:
            cmd.extend(["--headers", headers])
        if post_data:
            cmd.extend(["--data", post_data])

        self.log("Running SQLMap...")
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if "parameter appears to be injectable" in result.stdout:
                self.log("[VULN] SQL Injection detected by SQLMap.")
                self.add_vuln(
                    vuln_type="SQL Injection",
                    url=url,
                    method="POST" if post_data else "GET",
                    severity="High",
                    evidence="Parameter appears to be injectable",
                    tool="SQLMap"
                )
            else:
                self.log("No SQLi detected by SQLMap.")
        except Exception as e:
            self.log(f"[ERROR] SQLMap failed: {e}")
            
    def check_xss(self, url, cookies, headers):
        payloads = ["<script>alert(1)</script>", "javascript:alert(1)"]
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                res = requests.get(
                    test_url,
                    cookies=dict(item.split("=") for item in cookies.split("; ")) if cookies else {},
                    headers=dict(item.split(": ") for item in headers.split("; ")) if headers else {}
                )
                if payload in res.text:
                    self.log(f"[VULN] XSS detected: {test_url}")
                    self.add_vuln(
                        vuln_type="XSS",
                        url=test_url,
                        method="GET",
                        severity="Medium",
                        evidence=payload
                    )
            except Exception as e:
                self.log(f"[ERROR] XSS check failed: {e}")

    def check_open_redirect(self, url, cookies, headers):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        payload = "http://evil.com"
        for key in params:
            new_params = params.copy()
            new_params[key] = payload
            query = urllib.parse.urlencode(new_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
            try:
                res = requests.get(
                    test_url,
                    cookies=dict(item.split("=") for item in cookies.split("; ")) if cookies else {},
                    headers=dict(item.split(": ") for item in headers.split("; ")) if headers else {},
                    allow_redirects=False
                )
                if res.status_code in [301, 302] and "Location" in res.headers:
                    loc = res.headers["Location"]
                    if payload in loc:
                        self.log(f"[VULN] Open Redirect detected: {test_url}")
                        self.add_vuln(
                            vuln_type="Open Redirect",
                            url=test_url,
                            method="GET",
                            severity="Medium",
                            evidence=f"Redirects to {loc}"
                        )
            except Exception as e:
                self.log(f"[ERROR] Redirect check failed: {e}")

    def save_report(self):
        if not self.report:
            messagebox.showinfo("Info", "No vulnerabilities to save.")
            return

        with open("vulnerability_report.json", "w") as f:
            json.dump(self.report, f, indent=4)
        messagebox.showinfo("Saved", "Report saved as vulnerability_report.json")

# -----------------------------
# Launch App
# -----------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = WebVulnScannerApp(root)
    root.mainloop()