# XSS Scanner (Authorized Testing Only)

This project provides a lightweight CLI tool to:

1. Discover subdomains for a target domain.
2. Crawl likely attack surfaces (query-parameter URLs and HTML forms).
3. Intelligently detect reflected and breakout-oriented XSS behavior.

> ⚠️ **Legal notice:** only scan systems you own or have explicit written permission to test.

## Features

- Passive subdomain discovery via certificate transparency (`crt.sh`).
- Lightweight active subdomain guessing (common host prefixes).
- DNS resolution filter to keep only live hosts.
- HTML link collection restricted to the target domain.
- Detection workflow for potential XSS vectors:
  - Probe-based reflection detection with a unique marker.
  - Context inference for reflected input (`script`, attribute, tag, and HTML text contexts).
  - Context-specific breakout payload selection instead of one-size-fits-all payload blasting.
  - Query parameter and form field testing (GET/POST).
- Deduped findings with context-aware evidence notes.
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
- Potential XSS findings including URL, vector, payload, and context-aware evidence.

## Important limitations

- Reflection and breakout signals do not always prove exploitability; manual verification is still required.
- JavaScript-heavy sites may hide endpoints this crawler cannot discover.
- WAF/rate limiting may affect discovery and scan coverage.
- Context detection is heuristic-based and may produce false positives/false negatives.
