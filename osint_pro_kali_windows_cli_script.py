#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT-Pro — 100% OSINT cross‑platform (Kali Linux & Windows)
Author: ChatGPT

Features (passive OSINT):
  1) Username checker across popular platforms
  2) IP intelligence (geo, ISP) via ip-api.com
  3) Domain OSINT: WHOIS + DNS + SSL cert summary
  4) Email OSINT: MX lookup + Gravatar check + (optional HIBP via env var)
  5) Phone OSINT: region, carrier, timezone (phonenumbers)
  6) Image EXIF + GPS extraction (Pillow)
  7) PDF metadata (PyPDF2)
  8) GitHub user OSINT (public API)
  9) MAC vendor lookup (api.macvendors.com)

Notes:
- Strictly passive collection. No intrusive scanning.
- Some providers rate‑limit; be mindful when running large checks.
- Optional HIBP support if environment variable HIBP_API_KEY is set.

Dependencies (install once):
  pip install --upgrade colorama rich requests dnspython pillow phonenumbers python-whois PyPDF2 beautifulsoup4

Run:
  python osint_pro.py
"""

import os
import re
import sys
import ssl
import json
import time
import math
import socket
import hashlib
import datetime as dt
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third‑party
try:
    import requests
    from colorama import init as colorama_init, Fore, Style
except Exception as e:  # pragma: no cover
    print("Missing base deps. Run:\n  pip install colorama requests\n", file=sys.stderr)
    raise

# Optional
try:
    from rich.console import Console
    from rich.table import Table
    from rich.markdown import Markdown
    RICH = True
    console = Console()
except Exception:
    RICH = False

try:
    import dns.resolver
except Exception:
    dns = None

try:
    from PIL import Image, ExifTags
except Exception:
    Image = None
    ExifTags = None

try:
    import phonenumbers
    from phonenumbers import geocoder as phone_geocoder, carrier as phone_carrier, timezone as phone_timezone
except Exception:
    phonenumbers = None

try:
    import whois
except Exception:
    whois = None

try:
    from PyPDF2 import PdfReader
except Exception:
    PdfReader = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

USER_AGENT = "Mozilla/5.0 (OSINT-Pro; +https://example.local)"
TIMEOUT = 10
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "").strip()

colorama_init(autoreset=True)

BANNER = (
    "\n" +
    Fore.MAGENTA + Style.BRIGHT +
    "██░ ██▓██   ██▓▓█████▄  ██▀███   ▄▄▄      \n"+
    "▓██░ ██▒▒██  ██▒▒██▀ ██▌▓██ ▒ ██▒▒████▄    \n"+
    "▒██▀▀██░ ▒██ ██░░██   █▌▓██ ░▄█ ▒▒██  ▀█▄  \n"+
    "░▓█ ░██  ░ ▐██▓░░▓█▄   ▌▒██▀▀█▄  ░██▄▄▄▄██ \n"+
    "░▓█▒░██▓ ░ ██▒▓░░▒████▓ ░██▓ ▒██▒ ▓█   ▓██▒\n"+
    " ▒ ░░▒░▒  ██▒▒▒  ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░\n"+
    " ▒ ░▒░ ░▓██ ░▒░  ░ ▒  ▒   ░▒ ░ ▒░  ▒   ▒▒ ░\n"+
    " ░  ░░ ░▒ ▒ ░░   ░ ░  ░   ░░   ░   ░   ▒   \n"+
    " ░  ░  ░░ ░        ░       ░           ░  ░\n"+
    "        ░ ░      ░                         \n"+
    Style.RESET_ALL
)

MENU = f"""
{Fore.CYAN}{Style.BRIGHT}OSINT‑Pro — Main Menu{Style.RESET_ALL}
  1) Username checker
  2) IP intelligence (ip-api)
  3) Domain OSINT (WHOIS + DNS + SSL)
  4) Email OSINT (MX + Gravatar [+HIBP opt])
  5) Phone OSINT
  6) Image EXIF + GPS
  7) PDF metadata
  8) GitHub user OSINT
  9) MAC vendor lookup
  0) Exit
"""

SITE_TEMPLATES = {
    "500px": "https://500px.com/p/{u}",
    "AUR": "https://aur.archlinux.org/account/{u}",
    "AO3": "https://archiveofourown.org/users/{u}",
    "ArtStation": "https://www.artstation.com/{u}",
    "Bandcamp": "https://{u}.bandcamp.com",
    "Behance": "https://www.behance.net/{u}",
    "Bitbucket": "https://bitbucket.org/{u}/",
    "Bluesky": "https://bsky.app/profile/{u}",
    "BuyMeACoffee": "https://www.buymeacoffee.com/{u}",
    "CodePen": "https://codepen.io/{u}",
    "Codeberg": "https://codeberg.org/{u}",
    "Codeforces": "https://codeforces.com/profile/{u}",
    "Dailymotion": "https://www.dailymotion.com/{u}",
    "Dev.to": "https://dev.to/{u}",
    "Docker Hub": "https://hub.docker.com/u/{u}",
    "Dribbble": "https://dribbble.com/{u}",
    "Facebook": "https://www.facebook.com/{u}",
    "Flickr": "https://www.flickr.com/people/{u}/",
    "Foursquare": "https://foursquare.com/{u}",
    "Gab": "https://gab.com/{u}",
    "Gitee": "https://gitee.com/{u}",
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}",
    "HackerOne": "https://hackerone.com/{u}",
    "HackerRank": "https://www.hackerrank.com/profile/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "Kaggle": "https://www.kaggle.com/{u}",
    "Keybase": "https://keybase.io/{u}",
    "Ko-fi": "https://ko-fi.com/{u}",
    "Last.fm": "https://www.last.fm/user/{u}",
    "LeetCode": "https://leetcode.com/{u}/",
    "Lobsters": "https://lobste.rs/u/{u}",
    "Medium": "https://medium.com/@{u}",
    "Mixcloud": "https://www.mixcloud.com/{u}/",
    "MyAnimeList": "https://myanimelist.net/profile/{u}",
    "NPM": "https://www.npmjs.com/~{u}",
    "Observable": "https://observablehq.com/@{u}",
    "Packagist": "https://packagist.org/users/{u}",
    "Patreon": "https://www.patreon.com/{u}",
    "PayPal.me": "https://www.paypal.me/{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
    "ProductHunt": "https://www.producthunt.com/@{u}",
    "PyPI": "https://pypi.org/user/{u}/",
    "Quora": "https://www.quora.com/profile/{u}",
    "Reddit": "https://www.reddit.com/user/{u}/",
    "Replit": "https://replit.com/@{u}",
    "Scratch": "https://scratch.mit.edu/users/{u}/",
    "Snapchat": "https://www.snapchat.com/add/{u}",
    "SourceForge": "https://sourceforge.net/u/{u}/",
    "SourceHut": "https://sr.ht/~{u}",
    "SoundCloud": "https://soundcloud.com/{u}",
    "Spotify": "https://open.spotify.com/user/{u}",
    "StackBlitz": "https://stackblitz.com/@{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "Telegram": "https://t.me/{u}",
    "Threads": "https://www.threads.net/@{u}",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Tumblr": "https://{u}.tumblr.com",
    "Twitter/X": "https://x.com/{u}",
    "TryHackMe": "https://tryhackme.com/p/{u}",
    "Vimeo": "https://vimeo.com/{u}",
    "VK": "https://vk.com/{u}",
    "YouTube": "https://www.youtube.com/@{u}"
}


def safe_get(url: str, allow_redirects=True, stream=False):
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=allow_redirects, stream=stream)
        return r
    except Exception as e:
        return None


def print_heading(text: str):
    if RICH:
        console.rule(f"[bold cyan]{text}")
    else:
        print(Fore.CYAN + Style.BRIGHT + f"\n=== {text} ===" + Style.RESET_ALL)


# 1) USERNAME CHECKER

def check_one_site(site, tpl, username):
    url = tpl.format(u=username)
    r = safe_get(url)
    if r is None:
        return site, url, False, "net err"
    # Heuristic: 200 OK implies likely exists, 404/410 not
    exists = (r.status_code == 200)
    note = f"HTTP {r.status_code}"
    # Some platforms return 302 to profile (count as exists)
    if r.status_code in (301, 302, 303, 307, 308):
        exists = True
        note = f"Redirect {r.status_code}"
    # Simple content check for known 404 phrases
    if r.status_code == 200 and r.text:
        not_found_patterns = ["not found", "page isn’t available", "couldn’t find this", "user not found"]
        if any(pat.lower() in r.text.lower() for pat in not_found_patterns):
            exists = False
            note = "200 + nf text"
    return site, url, exists, note


def username_checker():
    username = input(Fore.YELLOW + "Enter username: " + Style.RESET_ALL).strip()
    if not username:
        return
    print_heading(f"Username reconnaissance — {username}")

    rows = []
    with ThreadPoolExecutor(max_workers=min(24, len(SITE_TEMPLATES))) as ex:
        futures = [ex.submit(check_one_site, s, t, username) for s, t in SITE_TEMPLATES.items()]
        for fut in as_completed(futures):
            site, url, exists, note = fut.result()
            rows.append((site, url, exists, note))

    rows.sort(key=lambda x: (not x[2], x[0].lower()))  # show found first

    if RICH:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Site", style="bold")
        table.add_column("Exists?")
        table.add_column("URL")
        table.add_column("Notes")
        for site, url, exists, note in rows:
            mark = "✅" if exists else "❌"
            table.add_row(site, mark, url, note)
        console.print(table)
    else:
        for site, url, exists, note in rows:
            mark = (Fore.GREEN + "[OK]" if exists else Fore.RED + "[NO]") + Style.RESET_ALL
            print(f"{mark} {site:12s} -> {url}  ({note})")

    print()


# 2) IP INTELLIGENCE

def ip_intel():
    ip = input(Fore.YELLOW + "Enter IP (or leave blank for your public IP): " + Style.RESET_ALL).strip()
    url = f"http://ip-api.com/json/{ip if ip else ''}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query,timezone"
    print_heading("IP intelligence (ip-api.com)")
    r = safe_get(url)
    if not r:
        print(Fore.RED + "Network error." + Style.RESET_ALL)
        return
    data = r.json()
    if data.get("status") != "success":
        print(Fore.RED + f"Error: {data.get('message')}" + Style.RESET_ALL)
        return
    if RICH:
        table = Table(show_header=False)
        for k in ["query","country","regionName","city","lat","lon","timezone","isp","org","as"]:
            table.add_row(f"[bold]{k}", str(data.get(k)))
        console.print(table)
    else:
        for k,v in data.items():
            print(f"- {k}: {v}")


# 3) DOMAIN OSINT

def dns_lookup(domain):
    results = {}
    if dns is None:
        return results
    resolver = dns.resolver.Resolver()
    for rtype in ["A","AAAA","MX","NS","TXT"]:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=5)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            results[rtype] = []
    return results


def ssl_summary(domain, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # Extract fields
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                notBefore = cert.get('notBefore')
                notAfter = cert.get('notAfter')
                san = []
                for typ, val in cert.get('subjectAltName', []):
                    if typ.lower() == 'dns':
                        san.append(val)
                return {
                    'subject_CN': subject.get('commonName'),
                    'issuer_CN': issuer.get('commonName'),
                    'not_before': notBefore,
                    'not_after': notAfter,
                    'alt_names': san[:10]
                }
    except Exception:
        return {}


def domain_osint():
    domain = input(Fore.YELLOW + "Enter domain (example.com): " + Style.RESET_ALL).strip().lower()
    if not domain:
        return
    print_heading(f"Domain OSINT — {domain}")

    # WHOIS
    who = None
    if whois:
        try:
            who = whois.whois(domain)
        except Exception:
            who = None

    # DNS
    dns_res = dns_lookup(domain)

    # SSL
    ssl_info = ssl_summary(domain)

    if RICH:
        if who is not None:
            console.print(Markdown("**WHOIS (key fields)**"))
            wtable = Table(show_header=False)
            keyz = ["domain_name","registrar","creation_date","expiration_date","name_servers","org","country","emails"]
            for k in keyz:
                val = getattr(who, k, None) if not isinstance(who, dict) else who.get(k)
                wtable.add_row(k, str(val))
            console.print(wtable)
        else:
            console.print("[yellow]WHOIS module not available or query failed.[/]")

        console.print(Markdown("**DNS records**"))
        dtable = Table(show_header=True, header_style="bold magenta")
        dtable.add_column("Type"); dtable.add_column("Values")
        for t, vals in dns_res.items():
            dtable.add_row(t, "\n".join(vals) if vals else "—")
        console.print(dtable)

        console.print(Markdown("**SSL certificate (summary)**"))
        stable = Table(show_header=False)
        for k,v in ssl_info.items():
            stable.add_row(k, str(v))
        console.print(stable)
    else:
        print("WHOIS:", who if who else "(not available)")
        print("DNS:")
        for t, vals in dns_res.items():
            print(f"  {t}: {', '.join(vals) if vals else '—'}")
        print("SSL:", ssl_info if ssl_info else "(no TLS info)")


# 4) EMAIL OSINT

def has_mx(domain):
    if dns is None:
        return None
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        return [str(r.exchange).rstrip('.') for r in answers]
    except Exception:
        return []


def gravatar_exists(email):
    email_norm = email.strip().lower()
    h = hashlib.md5(email_norm.encode('utf-8')).hexdigest()
    url = f"https://www.gravatar.com/avatar/{h}?d=404&s=80"
    r = safe_get(url, allow_redirects=False)
    if not r:
        return False, url
    return r.status_code == 200, url


def hibp_breaches(email):
    if not HIBP_API_KEY:
        return None
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}?truncateResponse=false"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": USER_AGENT,
    }
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return []
        else:
            return {"error": f"HTTP {r.status_code}"}
    except Exception:
        return {"error": "network"}


def email_osint():
    email = input(Fore.YELLOW + "Enter email: " + Style.RESET_ALL).strip()
    if not email or "@" not in email:
        print(Fore.RED + "Invalid email." + Style.RESET_ALL)
        return
    print_heading(f"Email OSINT — {email}")

    domain = email.split("@",1)[1]
    mx = has_mx(domain)
    has_g, g_url = gravatar_exists(email)
    breaches = hibp_breaches(email)

    if RICH:
        table = Table(show_header=False)
        table.add_row("Domain", domain)
        table.add_row("MX records", ", ".join(mx) if mx else ("(none)" if mx == [] else "(dns module missing)"))
        table.add_row("Gravatar", "✅ exists" if has_g else "❌ none")
        table.add_row("Gravatar URL", g_url)
        if breaches is None:
            table.add_row("Breaches", "(set HIBP_API_KEY env var to enable)")
        elif isinstance(breaches, list):
            table.add_row("Breaches count", str(len(breaches)))
        else:
            table.add_row("Breaches", json.dumps(breaches))
        console.print(table)
        if isinstance(breaches, list) and breaches:
            btab = Table(title="Breaches (HIBP)", header_style="bold magenta")
            btab.add_column("Name"); btab.add_column("Domain"); btab.add_column("BreachDate"); btab.add_column("PwnCount")
            for b in breaches[:20]:
                btab.add_row(str(b.get('Name')), str(b.get('Domain')), str(b.get('BreachDate')), str(b.get('PwnCount')))
            console.print(btab)
    else:
        print(f"- Domain: {domain}")
        print(f"- MX: {', '.join(mx) if mx else '(none or dns missing)'}")
        print(f"- Gravatar: {'yes' if has_g else 'no'} -> {g_url}")
        print(f"- Breaches: {'disabled' if breaches is None else breaches}")


# 5) PHONE OSINT

def phone_osint():
    if phonenumbers is None:
        print(Fore.YELLOW + "Install 'phonenumbers' to use this module." + Style.RESET_ALL)
        return
    raw = input(Fore.YELLOW + "Enter phone (with country code, e.g., +33612345678): " + Style.RESET_ALL).strip()
    try:
        num = phonenumbers.parse(raw, None)
    except Exception:
        print(Fore.RED + "Could not parse number." + Style.RESET_ALL)
        return
    valid = phonenumbers.is_valid_number(num)
    region = phone_geocoder.description_for_number(num, "en")
    carrier = phone_carrier.name_for_number(num, "en")
    tzs = phone_timezone.time_zones_for_number(num)
    if RICH:
        table = Table(show_header=False)
        table.add_row("Valid", "✅" if valid else "❌")
        table.add_row("E164", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164))
        table.add_row("Region", region)
        table.add_row("Carrier", carrier)
        table.add_row("Timezones", ", ".join(tzs))
        console.print(table)
    else:
        print(f"- valid: {valid}")
        print(f"- region: {region}\n- carrier: {carrier}\n- tz: {', '.join(tzs)}")


# 6) IMAGE EXIF + GPS

def _convert_gps_to_decimal(value, ref):
    # value is a tuple of (deg, min, sec) with each an IFDRational
    try:
        d = float(value[0]) + float(value[1]) / 60.0 + float(value[2]) / 3600.0
        if ref in ['S', 'W']:
            d = -d
        return d
    except Exception:
        return None


def image_exif():
    if Image is None:
        print(Fore.YELLOW + "Install 'Pillow' to use this module." + Style.RESET_ALL)
        return
    path = input(Fore.YELLOW + "Path to image: " + Style.RESET_ALL).strip('"')
    if not os.path.isfile(path):
        print(Fore.RED + "File not found." + Style.RESET_ALL)
        return
    img = Image.open(path)
    exif = img._getexif()
    if not exif:
        print(Fore.YELLOW + "No EXIF metadata found." + Style.RESET_ALL)
        return
    label = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
    gps = label.get('GPSInfo')
    lat = lon = None
    if gps:
        gps_parsed = {}
        for k, v in gps.items():
            name = ExifTags.GPSTAGS.get(k, k)
            gps_parsed[name] = v
        if 'GPSLatitude' in gps_parsed and 'GPSLatitudeRef' in gps_parsed:
            lat = _convert_gps_to_decimal(gps_parsed['GPSLatitude'], gps_parsed['GPSLatitudeRef'])
        if 'GPSLongitude' in gps_parsed and 'GPSLongitudeRef' in gps_parsed:
            lon = _convert_gps_to_decimal(gps_parsed['GPSLongitude'], gps_parsed['GPSLongitudeRef'])
    # Print summary
    if RICH:
        table = Table(show_header=False)
        for key in ["Make","Model","DateTimeOriginal","Software","ExifImageWidth","ExifImageHeight"]:
            if key in label:
                table.add_row(key, str(label[key]))
        if lat is not None and lon is not None:
            table.add_row("GPS", f"{lat:.6f}, {lon:.6f}")
            table.add_row("Map", f"https://maps.google.com/?q={lat},{lon}")
        console.print(table)
    else:
        keys = ["Make","Model","DateTimeOriginal","Software","ExifImageWidth","ExifImageHeight"]
        for k in keys:
            if k in label:
                print(f"- {k}: {label[k]}")
        if lat is not None and lon is not None:
            print(f"- GPS: {lat:.6f}, {lon:.6f}")
            print(f"- Map: https://maps.google.com/?q={lat},{lon}")


# 7) PDF METADATA

def pdf_metadata():
    if PdfReader is None:
        print(Fore.YELLOW + "Install 'PyPDF2' to use this module." + Style.RESET_ALL)
        return
    path = input(Fore.YELLOW + "Path to PDF: " + Style.RESET_ALL).strip('"')
    if not os.path.isfile(path):
        print(Fore.RED + "File not found." + Style.RESET_ALL)
        return
    try:
        reader = PdfReader(path)
        info = reader.metadata
        n_pages = len(reader.pages)
        if RICH:
            table = Table(show_header=False)
            table.add_row("Pages", str(n_pages))
            if info:
                for k, v in info.items():
                    table.add_row(str(k), str(v))
            console.print(table)
        else:
            print(f"- pages: {n_pages}")
            print(f"- metadata: {info}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)


# 8) GITHUB OSINT

def github_user():
    user = input(Fore.YELLOW + "GitHub username: " + Style.RESET_ALL).strip()
    if not user:
        return
    print_heading(f"GitHub OSINT — {user}")
    r = safe_get(f"https://api.github.com/users/{user}")
    if not r or r.status_code != 200:
        print(Fore.RED + f"HTTP {r.status_code if r else 'net err'}" + Style.RESET_ALL)
        return
    data = r.json()
    repos_r = safe_get(f"https://api.github.com/users/{user}/repos?sort=pushed&per_page=5")
    repos = repos_r.json() if repos_r and repos_r.status_code == 200 else []
    if RICH:
        table = Table(show_header=False)
        for k in ["name","company","blog","location","email","bio","public_repos","followers","following","created_at"]:
            table.add_row(k, str(data.get(k)))
        console.print(table)
        if repos:
            rtab = Table(title="Recent repos", header_style="bold magenta")
            rtab.add_column("Name"); rtab.add_column("Desc"); rtab.add_column("Pushed at")
            for rp in repos:
                rtab.add_row(rp.get('name'), str(rp.get('description')), rp.get('pushed_at'))
            console.print(rtab)
    else:
        for k,v in data.items():
            if k in ("name","company","blog","location","email","bio","public_repos","followers","following","created_at"):
                print(f"- {k}: {v}")
        if repos:
            print("Recent repos:")
            for rp in repos:
                print("  -", rp.get('name'), rp.get('pushed_at'))


# 9) MAC VENDOR LOOKUP

def mac_vendor():
    mac = input(Fore.YELLOW + "MAC address (e.g., 44:38:39:ff:ef:57): " + Style.RESET_ALL).strip()
    mac = mac.replace('-', ':')
    if not re.match(r"^[0-9A-Fa-f:]{11,17}$", mac):
        print(Fore.RED + "Invalid MAC format." + Style.RESET_ALL)
        return
    r = safe_get(f"https://api.macvendors.com/{mac}")
    if r and r.status_code == 200:
        print(Fore.GREEN + f"Vendor: {r.text}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + f"No vendor found (HTTP {r.status_code if r else 'err'})." + Style.RESET_ALL)


ACTIONS = {
    '1': username_checker,
    '2': ip_intel,
    '3': domain_osint,
    '4': email_osint,
    '5': phone_osint,
    '6': image_exif,
    '7': pdf_metadata,
    '8': github_user,
    '9': mac_vendor,
}


def main():
    os.system('')  # enable ANSI on Windows 10+
    print(BANNER)
    print(Fore.CYAN + Style.BRIGHT + "Welcome to OSINT‑Pro (Kali & Windows)." + Style.RESET_ALL)
    while True:
        print(MENU)
        choice = input(Fore.GREEN + "Select> " + Style.RESET_ALL).strip()
        if choice == '0':
            print(Fore.CYAN + "Bye!" + Style.RESET_ALL)
            return
        action = ACTIONS.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                print("\n(Interrupted)\n")
            except Exception as e:
                print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "Invalid choice." + Style.RESET_ALL)
        input(Fore.MAGENTA + "\nPress Enter to continue…" + Style.RESET_ALL)


if __name__ == '__main__':
    main()
