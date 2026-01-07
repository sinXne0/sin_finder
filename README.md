# sin_finder
Single-file OSINT CLI with interactive prompts. No API keys required. Cross-platform.

<img width="1536" height="1024" alt="sinfinder" src="https://github.com/user-attachments/assets/73e4b38d-c649-4eee-92f3-cd816a7a886c" />


## Features
- Username search across popular platforms
- Email lookup with DNS/WHOIS and domain intel
- Phone number parsing (no external lookups without keys)
- Domain/WHOIS/DNS enrichment
- IP intel (RDAP + free sources)
- Breach check via XposedOrNot
- Social discovery search links
- File metadata extraction with hashes (+ exiftool if installed)
- Output to JSON, CSV, and PDF

## Quick start
```
python3 sin_finder.py
```

## Options
```
python3 sin_finder.py --timeout 20 --output-dir results
python3 sin_finder.py --no-network
```

## Free sources used
- RDAP: https://rdap.org
- Google DNS-over-HTTPS: https://dns.google/resolve
- IP info: https://ipinfo.io
- IP-API: https://ip-api.com
- IPWhois: https://ipwhois.app
- Shodan InternetDB: https://internetdb.shodan.io
- ThreatFox: https://threatfox.abuse.ch
- crt.sh: https://crt.sh
- urlscan: https://urlscan.io
- HackerTarget hostsearch: https://api.hackertarget.com
- Wayback CDX: https://web.archive.org
- XposedOrNot: https://xposedornot.com

## Notes
- This tool does not use API keys; network calls may be rate limited.
- Use responsibly and comply with applicable laws and terms.
