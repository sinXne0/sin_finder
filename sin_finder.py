#!/usr/bin/env python3
"""
Single-file OSINT CLI with interactive prompts and no API keys required.
Cross-platform, text output with optional JSON and basic PDF export.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.3.0"
TOOL_NAME = "Sin Finder"
USER_AGENT = "sin-finder/0.3 (python urllib)"
GLOBALS = {"timeout": 12, "no_network": False}


def now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def prompt(msg: str, default: str | None = None) -> str:
    if default:
        msg = f"{msg} [{default}] "
    else:
        msg = f"{msg} "
    value = input(msg).strip()
    return value if value else (default or "")


def prompt_yes_no(msg: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    value = input(f"{msg} ({suffix}) ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes")


def http_get(url: str, headers: dict | None = None, timeout: int | None = None) -> tuple[int, bytes]:
    if GLOBALS.get("no_network"):
        raise urllib.error.URLError("network disabled")
    if timeout is None:
        timeout = GLOBALS.get("timeout", 12)
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(32768)
        return resp.getcode(), data


def http_get_json(url: str, headers: dict | None = None, timeout: int | None = None) -> dict | list | None:
    try:
        code, data = http_get(url, headers=headers, timeout=timeout)
        if code and 200 <= code < 300:
            return json.loads(data.decode("utf-8", "ignore"))
    except (urllib.error.URLError, json.JSONDecodeError):
        return None
    return None


def safe_url_exists(url: str) -> dict:
    result = {"url": url, "status": None, "ok": False, "note": ""}
    try:
        code, _ = http_get(url, timeout=10)
        result["status"] = code
        result["ok"] = 200 <= code < 400
    except urllib.error.HTTPError as exc:
        result["status"] = exc.code
        result["ok"] = exc.code in (200, 301, 302, 307, 308)
    except urllib.error.URLError as exc:
        result["note"] = str(exc.reason)
    return result


def normalize_username(username: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "", username.strip())


def username_search(username: str, check_live: bool = True) -> dict:
    username = normalize_username(username)
    sites = {
        "GitHub": f"https://github.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Bitbucket": f"https://bitbucket.org/{username}/",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Facebook": f"https://www.facebook.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Medium": f"https://medium.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "StackOverflow": f"https://stackoverflow.com/users/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "Dev.to": f"https://dev.to/{username}",
        "HackerNews": f"https://news.ycombinator.com/user?id={username}",
        "Kaggle": f"https://www.kaggle.com/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
    }
    results = {"input": username, "profiles": []}
    for name, url in sites.items():
        item = {"site": name, "url": url}
        if check_live:
            item.update(safe_url_exists(url))
        results["profiles"].append(item)
    return results


def parse_email(email: str) -> dict:
    email = email.strip()
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return {
        "input": email,
        "valid_syntax": bool(re.match(pattern, email)),
        "local": email.split("@")[0] if "@" in email else "",
        "domain": email.split("@")[1] if "@" in email else "",
    }


def whois_rdap_domain(domain: str) -> dict | None:
    url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
    return http_get_json(url)


def dns_google_query(name: str, qtype: str) -> dict | None:
    params = urllib.parse.urlencode({"name": name, "type": qtype})
    url = f"https://dns.google/resolve?{params}"
    return http_get_json(url)


def nslookup_mx(domain: str) -> list[str]:
    if not shutil_which("nslookup"):
        return []
    try:
        out = subprocess.check_output(
            ["nslookup", "-type=mx", domain],
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []
    mx = []
    for line in out.splitlines():
        if "mail exchanger" in line.lower():
            parts = line.split("=")
            if len(parts) > 1:
                mx.append(parts[-1].strip())
    return mx


def email_lookup(email: str) -> dict:
    info = parse_email(email)
    domain = info["domain"]
    results = {"parsed": info, "dns": {}, "rdap": None}
    if domain:
        results["dns"]["A"] = dns_google_query(domain, "A")
        results["dns"]["AAAA"] = dns_google_query(domain, "AAAA")
        results["dns"]["CNAME"] = dns_google_query(domain, "CNAME")
        results["dns"]["MX"] = dns_google_query(domain, "MX")
        results["dns"]["NS"] = dns_google_query(domain, "NS")
        results["dns"]["SOA"] = dns_google_query(domain, "SOA")
        results["dns"]["CAA"] = dns_google_query(domain, "CAA")
        results["dns"]["TXT"] = dns_google_query(domain, "TXT")
        results["dns"]["DMARC"] = dns_google_query(f"_dmarc.{domain}", "TXT")
        results["dns"]["MX_nslookup"] = nslookup_mx(domain)
        results["rdap"] = whois_rdap_domain(domain)
        results["domain_intel"] = domain_intel(domain)
    return results


def phone_lookup(phone: str) -> dict:
    raw = phone.strip()
    digits = re.sub(r"\D", "", raw)
    e164 = f"+{digits}" if raw.startswith("+") else ""
    return {
        "input": raw,
        "digits": digits,
        "e164_guess": e164,
        "length": len(digits),
        "note": "No external lookups without API keys; validate with carrier tools if needed.",
    }


def rdap_ip(ip: str) -> dict | None:
    url = f"https://rdap.org/ip/{urllib.parse.quote(ip)}"
    data = http_get_json(url)
    if data:
        return data
    url = f"https://rdap.arin.net/registry/ip/{urllib.parse.quote(ip)}"
    return http_get_json(url)


def ipinfo(ip: str) -> dict | None:
    url = f"https://ipinfo.io/{urllib.parse.quote(ip)}/json"
    return http_get_json(url)


def ip_api(ip: str) -> dict | None:
    url = f"https://ip-api.com/json/{urllib.parse.quote(ip)}"
    return http_get_json(url)


def shodan_internetdb(ip: str) -> dict | None:
    url = f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}"
    return http_get_json(url)


def ip_intel(ip: str) -> dict:
    return {
        "rdap": rdap_ip(ip),
        "ipinfo": ipinfo(ip),
        "ip_api": ip_api(ip),
        "ipwhois": ipwhois_app(ip),
        "threatfox": threatfox_search(ip),
        "shodan_internetdb": shodan_internetdb(ip),
    }


def xposedornot_breach(email: str) -> dict | None:
    url = f"https://api.xposedornot.com/v1/check-email/{urllib.parse.quote(email)}"
    return http_get_json(url)


def breach_check(email: str) -> dict:
    return {
        "xposedornot": xposedornot_breach(email),
        "note": "HIBP requires an API key; XposedOrNot is a free/no-key fallback.",
    }


def domain_intel(domain: str) -> dict:
    return {
        "rdap": whois_rdap_domain(domain),
        "dns_A": dns_google_query(domain, "A"),
        "dns_AAAA": dns_google_query(domain, "AAAA"),
        "dns_CNAME": dns_google_query(domain, "CNAME"),
        "dns_MX": dns_google_query(domain, "MX"),
        "dns_NS": dns_google_query(domain, "NS"),
        "dns_SOA": dns_google_query(domain, "SOA"),
        "dns_SRV": dns_google_query(domain, "SRV"),
        "dns_CAA": dns_google_query(domain, "CAA"),
        "dns_TXT": dns_google_query(domain, "TXT"),
        "dns_DMARC": dns_google_query(f"_dmarc.{domain}", "TXT"),
        "crtsh": crtsh_search(domain),
        "urlscan": urlscan_search(domain),
        "hackertarget_hostsearch": hackertarget_hostsearch(domain),
        "wayback": wayback_cdx(domain),
    }


def social_discovery(query: str) -> dict:
    q = urllib.parse.quote(query)
    return {
        "query": query,
        "search_links": {
            "Google": f"https://www.google.com/search?q={q}",
            "DuckDuckGo": f"https://duckduckgo.com/?q={q}",
            "Bing": f"https://www.bing.com/search?q={q}",
            "Yandex": f"https://yandex.com/search/?text={q}",
        },
    }


def metadata_extract(path: str) -> dict:
    info = {"path": path, "exists": False}
    if not os.path.exists(path):
        return info
    info["exists"] = True
    stat = os.stat(path)
    info["size"] = stat.st_size
    info["mtime"] = dt.datetime.utcfromtimestamp(stat.st_mtime).isoformat() + "Z"
    info["sha256"] = file_hash(path, "sha256")
    info["sha1"] = file_hash(path, "sha1")
    info["md5"] = file_hash(path, "md5")
    if shutil_which("exiftool"):
        info["exiftool"] = run_exiftool(path)
    return info


def file_hash(path: str, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def run_exiftool(path: str) -> str:
    try:
        out = subprocess.check_output(["exiftool", path], text=True, timeout=15)
        return out.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def shutil_which(cmd: str) -> str | None:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(p, cmd)
        if os.name == "nt":
            for ext in (".exe", ".bat", ".cmd"):
                if os.path.isfile(candidate + ext):
                    return candidate + ext
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def write_simple_pdf(text: str, out_path: str) -> None:
    lines = []
    for line in text.splitlines():
        if not line:
            lines.append("")
        else:
            lines.extend(textwrap.wrap(line, width=90))

    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    content_lines = ["BT", "/F1 10 Tf", "12 TL", "40 800 Td"]
    for idx, line in enumerate(lines):
        if idx > 0:
            content_lines.append("T*")
        content_lines.append(f"({esc(line)}) Tj")
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("ascii", "ignore")

    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Contents 5 0 R /Resources << /Font << /F1 4 0 R >> >> >>"
    )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream")

    xref_positions = []
    out = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
    for i, obj in enumerate(objects, start=1):
        xref_positions.append(sum(len(chunk) for chunk in out))
        out.append(f"{i} 0 obj\n".encode("ascii") + obj + b"\nendobj\n")
    xref_start = sum(len(chunk) for chunk in out)
    xref = ["xref", f"0 {len(objects)+1}", "0000000000 65535 f "]
    for pos in xref_positions:
        xref.append(f"{pos:010d} 00000 n ")
    out.append(("\n".join(xref) + "\n").encode("ascii"))
    trailer = f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n"
    out.append(trailer.encode("ascii"))

    with open(out_path, "wb") as f:
        f.write(b"".join(out))


def render_results_text(results: dict) -> str:
    return json.dumps(results, indent=2, ensure_ascii=True)


def ipwhois_app(ip: str) -> dict | None:
    url = f"https://ipwhois.app/json/{urllib.parse.quote(ip)}"
    return http_get_json(url)


def threatfox_search(ip: str) -> dict | None:
    url = f"https://threatfox.abuse.ch/export/json/ip/{urllib.parse.quote(ip)}"
    return http_get_json(url)


def crtsh_search(domain: str) -> dict | list | None:
    url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    data = http_get_json(url)
    if isinstance(data, list):
        return data[:50]
    return data


def urlscan_search(domain: str) -> dict | None:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(domain)}"
    return http_get_json(url)


def hackertarget_hostsearch(domain: str) -> dict:
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
    try:
        code, data = http_get(url)
        text = data.decode("utf-8", "ignore")
        return {"status": code, "raw": text[:10000]}
    except urllib.error.URLError as exc:
        return {"status": None, "raw": "", "error": str(exc.reason)}


def wayback_cdx(domain: str) -> dict | None:
    url = (
        "https://web.archive.org/cdx/search/cdx?"
        f"url=*.{urllib.parse.quote(domain)}/*&output=json&fl=timestamp,original&limit=50"
    )
    return http_get_json(url)


def flatten_for_csv(results: dict) -> list[dict]:
    rows = []
    for item in results.get("items", []):
        for key, value in item.items():
            rows.append(
                {
                    "section": key,
                    "value": json.dumps(value, ensure_ascii=True),
                }
            )
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sin Finder OSINT CLI (interactive prompts, no API keys)."
    )
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout seconds")
    parser.add_argument("--no-network", action="store_true", help="Skip network lookups")
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Default output directory for JSON/CSV/PDF",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    GLOBALS["timeout"] = args.timeout
    GLOBALS["no_network"] = args.no_network
    output_dir = args.output_dir

    print(f"{TOOL_NAME} v{VERSION}")
    print("No API keys required. Network lookups may fail if offline.")
    print("")

    results = {"generated_at": now_iso(), "items": []}

    tasks = [
        "Username search",
        "Email lookup",
        "Phone lookup",
        "Domain/WHOIS/DNS",
        "IP intel",
        "Breach check (email)",
        "Social discovery links",
        "Metadata extraction (file)",
    ]
    for i, task in enumerate(tasks, start=1):
        print(f"{i}. {task}")
    print("")
    selection = prompt("Select tasks (comma separated numbers, or 'all')", "all")

    if selection.lower() == "all":
        chosen = set(range(1, len(tasks) + 1))
    else:
        chosen = set()
        for part in selection.split(","):
            part = part.strip()
            if part.isdigit():
                chosen.add(int(part))

    if 1 in chosen:
        username = prompt("Username")
        check_live = prompt_yes_no("Check live profile URLs", True)
        results["items"].append({"username_search": username_search(username, check_live)})
    if 2 in chosen:
        email = prompt("Email")
        results["items"].append({"email_lookup": email_lookup(email)})
    if 3 in chosen:
        phone = prompt("Phone number")
        results["items"].append({"phone_lookup": phone_lookup(phone)})
    if 4 in chosen:
        domain = prompt("Domain")
        results["items"].append({"domain_intel": domain_intel(domain)})
    if 5 in chosen:
        ip = prompt("IP address")
        results["items"].append({"ip_intel": ip_intel(ip)})
    if 6 in chosen:
        email = prompt("Email for breach check")
        results["items"].append({"breach_check": breach_check(email)})
    if 7 in chosen:
        query = prompt("Search query (name, username, email)")
        results["items"].append({"social_discovery": social_discovery(query)})
    if 8 in chosen:
        path = prompt("File path")
        results["items"].append({"metadata_extract": metadata_extract(path)})

    output_text = render_results_text(results)
    print("")
    print(output_text)

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    if prompt_yes_no("Save JSON output", True):
        out_path = prompt("JSON path", os.path.join(output_dir, "osint_output.json"))
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(output_text + "\n")
        print(f"Wrote {out_path}")

    if prompt_yes_no("Save CSV output", False):
        csv_path = prompt("CSV path", os.path.join(output_dir, "osint_output.csv"))
        rows = flatten_for_csv(results)
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["section", "value"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote {csv_path}")

    if prompt_yes_no("Save PDF output", False):
        pdf_path = prompt("PDF path", os.path.join(output_dir, "osint_output.pdf"))
        try:
            write_simple_pdf(output_text, pdf_path)
            print(f"Wrote {pdf_path}")
        except OSError as exc:
            print(f"Failed to write PDF: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
