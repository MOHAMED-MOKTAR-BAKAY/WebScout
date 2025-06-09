import requests
import socket
import re
from urllib.parse import urljoin
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import track

console = Console()

# === Supported Languages ===
LANGUAGES = {
    "ar": {
        "banner": """
██████╗ ██╗   ██╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗ 
██╔══██╗╚██╗ ██╔╝██╔════╝██╔═══██╗████╗  ██║██╔════╝ 
██████╔╝ ╚████╔╝ ██║     ██║   ██║██╔██╗ ██║██║  ███╗
██╔══██╗  ╚██╔╝  ██║     ██║   ██║██║╚██╗██║██║   ██║
██████╔╝   ██║   ══╝     ╚██████╔╝██║ ╚████║╚██████╔╝
╚═════╝    ╚═╝           ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ 

                By: Mohamed Moktar BAKAY
""",
        "select_lang": "اختر لغة / Choose Language / Choisissez la langue:",
        "lang_options": {
            "1": "العربية",
            "2": "English",
            "3": "Français"
        },
        "enter_target": "🌐 أدخل رابط الموقع المستهدف (مثال: https://example.com):  ",
        "start_scan": "🚀 بدء التحليل على: ",
        "subdomain_scan": "🔍 جارٍ فحص السب دومينات...",
        "dir_brute": "📁 جارٍ كسر الدلائل...",
        "results_done": "✅ اكتمل الفحص!",
        "save_prompt": "هل تريد حفظ النتائج في ملف؟ (y/n): ",
        "saving": "📄 يتم حفظ التقرير...",
        "exit_msg": "[+] تم الخروج من الأداة."
    },
    "en": {
        "banner": """
██████╗ ██╗   ██╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗ 
██╔══██╗╚██╗ ██╔╝██╔════╝██╔═══██╗████╗  ██║██╔════╝ 
██████╔╝ ╚████╔╝ ██║     ██║   ██║██╔██╗ ██║██║  ███╗
██╔══██╗  ╚██╔╝  ██║     ██║   ██║██║╚██╗██║██║   ██║
██████╔╝   ██║   ══╝     ╚██████╔╝██║ ╚████║╚██████╔╝
╚═════╝    ╚═╝           ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ 

                By: Mohamed Moktar BAKAY
""",
        "select_lang": "Choose Language / Select your language:",
        "lang_options": {
            "1": "English",
            "2": "Arabic",
            "3": "French"
        },
        "enter_target": "🌐 Enter Target URL (e.g., https://example.com):  ",
        "start_scan": "🚀 Starting reconnaissance on: ",
        "subdomain_scan": "🔍 Scanning Subdomains...",
        "dir_brute": "📁 Brute Forcing Directories...",
        "results_done": "✅ Recon and Scan Completed!",
        "save_prompt": "Do you want to save the results to a file? (y/n): ",
        "saving": "📄 Saving report...",
        "exit_msg": "[+] Exiting WebScout..."
    },
    "fr": {
        "banner": """
██████╗ ██╗   ██╗ ██████╗ ██████╗ ███╗   ██╗ ██████╗ 
██╔══██╗╚██╗ ██╔╝██╔════╝██╔═══██╗████╗  ██║██╔════╝ 
██████╔╝ ╚████╔╝ ██║     ██║   ██║██╔██╗ ██║██║  ███╗
██╔══██╗  ╚██╔╝  ██║     ██║   ██║██║╚██╗██║██║   ██║
██████╔╝   ██║   ══╝     ╚██████╔╝██║ ╚████║╚██████╔╝
╚═════╝    ╚═╝           ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ 

                By: Mohamed Moktar BAKAY
""",
        "select_lang": "Choisissez votre langue / Choose your language:",
        "lang_options": {
            "1": "Français",
            "2": "Anglais",
            "3": "Arabe"
        },
        "enter_target": "🌐 Entrez l'URL cible (exemple : https://example.com)  : ",
        "start_scan": "🚀 Démarrage de l'analyse sur : ",
        "subdomain_scan": "🔍 Analyse des sous-domaines...",
        "dir_brute": "📁 Force brute des répertoires...",
        "results_done": "✅ Analyse terminée !",
        "save_prompt": "Voulez-vous enregistrer les résultats ? (o/n) : ",
        "saving": "📄 Enregistrement du rapport...",
        "exit_msg": "[+] Fermeture de l'outil."
    }
}

# === Banner ===
def show_banner(lang):
    console.print(Panel(LANGUAGES[lang]["banner"], style="bold blue"))

# === Input Target ===
def get_target(lang):
    target = input(LANGUAGES[lang]["enter_target"]).strip()
    if not target.startswith(('http://', 'https://')): 
        target = 'https://'  + target
    return target

# === Basic Info Gathering ===
def get_basic_info(url, lang):
    try:
        res = requests.get(url, timeout=10, headers={"User-Agent": "WebScout"})
        title = re.search(r"<title.*?>(.*?)</title>", res.text, re.IGNORECASE)
        server = res.headers.get('Server')
        powered_by = res.headers.get('X-Powered-By')
        cookies = res.cookies.get_dict()
        content_type = res.headers.get('Content-Type')
        status_code = res.status_code
        ip = socket.gethostbyname(res.url.split('/')[2])

        return {
            "URL": res.url,
            "IP Address": ip,
            "Status Code": status_code,
            "Title": title.group(1) if title else "غير موجود",
            "Server": server or "غير موجود",
            "Powered By": powered_by or "غير موجود",
            "Cookies": cookies,
            "Content Type": content_type or "غير موجود"
        }
    except Exception as e:
        console.print(f"[red][-] خطأ أثناء جمع المعلومات الأساسية: {str(e)}")
        return {}

# === DNS Lookup ===
def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return {"Domain": domain, "IP": ip}
    except:
        return {"Domain": domain, "IP": "خطأ"}

# === Subdomains Scan ===
def scan_subdomains(domain, lang):
    subdomains = ['www', 'admin', 'dev', 'test', 'ftp', 'mail', 'blog']
    found = []
    for sub in track(subdomains, description=LANGUAGES[lang]["subdomain_scan"]):
        target = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(target)
            found.append({target: ip})
        except:
            continue
    return found

# === Directory Bruteforce ===
def dir_bruteforce(url, lang):
    common_dirs = ['admin', 'login', 'wp-admin', 'backup', 'api', 'config', '.git', '.env']
    found = []
    for d in track(common_dirs, description=LANGUAGES[lang]["dir_brute"]):
        target = urljoin(url, d)
        try:
            res = requests.get(target, timeout=5, headers={"User-Agent": "WebScout"})
            if res.status_code == 200:
                found.append({target: res.status_code})
        except:
            continue
    return found

# === Robots.txt Checker ===
def check_robots(url):
    robots_url = urljoin(url, "/robots.txt")
    try:
        res = requests.get(robots_url, timeout=5, headers={"User-Agent": "WebScout"})
        if res.status_code == 200:
            lines = res.text.splitlines()
            allowed = [line for line in lines if line.lower().startswith("allow:")]
            disallowed = [line for line in lines if line.lower().startswith("disallow:")]
            return {"robots.txt": {"content": res.text, "allowed": allowed, "disallowed": disallowed}}
        return {}
    except:
        return {}

# === Check if Domain is Free ===
def check_free_domain(domain):
    free_domains = ["tk", "ml", "ga", "cf", "gq"]
    tld = domain.split('.')[-1]
    return {"Free Domain TLD": tld in free_domains}

# === Detect CMS ===
def detect_cms(url):
    cms_patterns = {
        "WordPress": "/wp-login.php",
        "Joomla": "/administrator/",
        "Drupal": "/core/",
        "Magento": "/skin/frontend/",
        "Shopify": "shopify",
        "Squarespace": "squarespace",
        "Blogger / Blogspot": "blogspot.com"
    }

    detected = []
    for name, path in cms_patterns.items():
        if path.startswith("/"):
            full_url = urljoin(url, path)
            try:
                res = requests.head(full_url, timeout=5, headers={"User-Agent": "WebScout"})
                if res.status_code < 400:
                    detected.append(name)
            except:
                pass
        else:
            try:
                res = requests.get(url, timeout=5, headers={"User-Agent": "WebScout"})
                if path.lower() in res.text.lower():
                    detected.append(name)
            except:
                pass
    return {"Detected CMS": detected or "Not Detected"}

# === OS Detection based on Server Headers ===
def detect_os(server_header):
    os_guess = "غير معروف"
    if server_header:
        if "Apache" in server_header and "Ubuntu" in server_header:
            os_guess = "لينكس (Ubuntu)"
        elif "Apache" in server_header and "CentOS" in server_header:
            os_guess = "لينكس (CentOS)"
        elif "Microsoft" in server_header or "IIS" in server_header:
            os_guess = "ويندوز سيرفر"
        elif "nginx" in server_header:
            os_guess = "لينكس (NGINX)"
    return {"Operating System Guess": os_guess}

# === XSS Detection ===
def xss_check(url, lang):
    payloads = ["<script>alert(1)</script>", "'><img src=x onerror=alert(1)>"]
    vulns = []
    parsed = url.split('?')
    if len(parsed) > 1:
        params = parsed[1].split('&')
        for p in params:
            key = p.split('=')[0]
            for payload in payloads:
                test_url = url.replace(f"{key}={p.split('=')[1]}", f"{key}={payload}")
                try:
                    res = requests.get(test_url, timeout=5, headers={"User-Agent": "WebScout"})
                    if payload in res.text:
                        vulns.append({test_url: "ثغرة XSS مكتشفة"})
                except:
                    continue
    return vulns

# === SQLi Detection ===
def sqli_check(url, lang):
    payloads = ["'", "\"", "';", "--", "' OR '1'='1"]
    vulns = []
    parsed = url.split('?')
    if len(parsed) > 1:
        params = parsed[1].split('&')
        for p in params:
            key = p.split('=')[0]
            for payload in payloads:
                test_url = url.replace(f"{key}={p.split('=')[1]}", f"{key}={payload}")
                try:
                    res = requests.get(test_url, timeout=5, headers={"User-Agent": "WebScout"})
                    errors = [
                        "you have an error in your sql syntax",
                        "mysql_fetch_assoc",
                        "sql syntax",
                        "supplied argument is not a valid mysql",
                        "Warning: mysql"
                    ]
                    if any(err in res.text.lower() for err in errors):
                        vulns.append({test_url: "ثغرة SQLi مكتشفة"})
                except:
                    continue
    return vulns

# === Clickjacking Protection ===
def clickjacking_check(url, lang):
    try:
        res = requests.get(url, timeout=5, headers={"User-Agent": "WebScout"})
        if 'X-Frame-Options' not in res.headers:
            return {"Clickjacking Vulnerable": True}
        return {"Clickjacking Protected": True}
    except:
        return {}

# === Print All Results to Screen ===
def print_results(data, lang):
    console.print("\n📊 [bold green]نتائج الفحص:[/bold green]\n")
    for key, val in data.items():
        console.print(f"\n[bold cyan]==> {key}[/bold cyan]")
        if isinstance(val, dict):
            for k, v in val.items():
                console.print(f" • {k}: {v}")
        elif isinstance(val, list):
            for item in val:
                console.print(f" • {item}")

# === Export Results to File ===
def export_results(data, lang):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename_json = f"report_{timestamp}.json"
    with open(filename_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    console.print(f"\n📄 تم حفظ التقرير في: {filename_json}")

# === Main Execution ===
def main():
    # Choose Language
    print(LANGUAGES["ar"]["select_lang"])
    for k, v in LANGUAGES["ar"]["lang_options"].items():
        print(f"{k}. {v}")
    choice = input("اختيارك: ").strip()
    lang = {"1": "ar", "2": "en", "3": "fr"}.get(choice, "ar")

    show_banner(lang)
    target = get_target(lang)
    domain = target.split("//")[-1].split("/")[0]

    console.print(f"\n{LANGUAGES[lang]['start_scan']}{target}", style="bold green")

    basic_info = get_basic_info(target, lang)
    server_header = basic_info.get("Server", "")

    results = {
        "Basic Info": basic_info,
        "DNS Info": dns_lookup(domain),
        "Subdomains": scan_subdomains(domain, lang),
        "Directories": dir_bruteforce(target, lang),
        "Robots.txt": check_robots(target),
        "Free Domain Check": check_free_domain(domain),
        "CMS Detection": detect_cms(target),
        "Operating System": detect_os(server_header),
        "XSS Vulnerabilities": xss_check(target, lang),
        "SQL Injection": sqli_check(target, lang),
        "Clickjacking": clickjacking_check(target, lang)
    }

    console.print(f"\n{LANGUAGES[lang]['results_done']}", style="bold green")
    print_results(results, lang)

    save = input(LANGUAGES[lang]["save_prompt"]).lower()
    if save in ['y', 'yes', 'o']:
        export_results(results, lang)

if __name__ == "__main__":
    main()