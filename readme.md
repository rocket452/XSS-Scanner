# XSS Scanner (Authorized Testing Only)

This project provides a lightweight CLI tool to:

1. Discover subdomains for a target domain.
2. Crawl likely attack surfaces (query-parameter URLs and HTML forms).
3. Test common reflected-XSS payloads.

> ⚠️ **Legal notice:** only scan systems you own or have explicit written permission to test.

## Features

- Passive subdomain discovery via certificate transparency (`crt.sh`).
- Lightweight active subdomain guessing (common host prefixes).
- DNS resolution filter to keep only live hosts.
- HTML link collection restricted to the target domain.
- Detection of potentially vulnerable reflected input vectors:
  - Query parameters.
  - Form inputs (GET/POST).
- CLI controls for timeout, crawl depth, and scan pacing.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 xss_scanner.py example.com --timeout 8 --max-links 30 --delay 0.1
```

### Output

The scanner prints:

- Resolved subdomains.
- Crawled URLs.
- Potential reflected-XSS findings including URL, vector, payload, and evidence.

## Important limitations

- Reflection does not always mean exploitable XSS (context-aware validation and manual verification are required).
- JavaScript-heavy sites may hide endpoints this crawler cannot discover.
- WAF/rate limiting may affect discovery and scan coverage.
- Payload list is intentionally small and should be expanded carefully for deeper assessments.
