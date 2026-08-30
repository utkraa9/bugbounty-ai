import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests


USER_AGENT = "BugBountyAI-Recon/0.3"
REQUEST_TIMEOUT = 10
MAX_BODY_SAMPLE = 500_000
MAX_DISCOVERED_LINKS = 50

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

COMMON_RESOURCES = [
    "/robots.txt",
    "/.well-known/security.txt",
]


def normalize_target(asset: str) -> str:
    """Normalize an authorized asset into a requestable URL."""

    asset = asset.strip()

    if not asset:
        raise ValueError("Target is empty")

    if not asset.startswith(("http://", "https://")):
        asset = "https://" + asset

    parsed = urlparse(asset)

    if not parsed.hostname:
        raise ValueError("Invalid target")

    return asset.rstrip("/")


def collect_security_headers(headers: dict) -> dict:
    """Return security headers and whether each one is present."""

    values = {
        header: headers.get(header)
        for header in SECURITY_HEADERS
    }

    return {
        "values": values,
        "present": [
            header for header, value in values.items()
            if value is not None
        ],
        "missing": [
            header for header, value in values.items()
            if value is None
        ],
    }


def collect_cookie_metadata(headers: dict) -> list:
    """
    Inspect Set-Cookie metadata without collecting cookie values.

    Cookie values are intentionally omitted from recon output.
    """

    raw_cookies = headers.get("Set-Cookie")

    if not raw_cookies:
        return []

    # Requests may combine multiple Set-Cookie values differently
    # depending on the server. This parser is intentionally conservative.
    cookie_entries = []

    for raw in re.split(r", (?=[^;,=]+=[^;,]+)", raw_cookies):
        first_part = raw.split(";", 1)[0].strip()
        name = first_part.split("=", 1)[0].strip()

        if not name:
            continue

        attributes = {
            "secure": False,
            "httponly": False,
            "samesite": None,
            "path": None,
            "domain": None,
        }

        for part in raw.split(";")[1:]:
            item = part.strip()
            lower = item.lower()

            if lower == "secure":
                attributes["secure"] = True
            elif lower == "httponly":
                attributes["httponly"] = True
            elif lower.startswith("samesite="):
                attributes["samesite"] = item.split("=", 1)[1]
            elif lower.startswith("path="):
                attributes["path"] = item.split("=", 1)[1]
            elif lower.startswith("domain="):
                attributes["domain"] = item.split("=", 1)[1]

        cookie_entries.append({
            "name": name,
            "attributes": attributes,
        })

    return cookie_entries


def collect_page_metadata(response: requests.Response) -> dict:
    """
    Collect basic HTML metadata without executing JavaScript.
    """

    content_type = response.headers.get("Content-Type", "")

    if "text/html" not in content_type.lower():
        return {
            "title": None,
            "html_detected": False,
            "forms": [],
            "same_origin_links": [],
            "scripts": 0,
        }

    body = response.text[:MAX_BODY_SAMPLE]
    lower_body = body.lower()

    title = None
    title_start = lower_body.find("<title>")

    if title_start != -1:
        title_start += len("<title>")
        title_end = lower_body.find("</title>", title_start)

        if title_end != -1:
            title = body[title_start:title_end].strip()

    # Lightweight, non-executing form metadata.
    forms = []
    for match in re.finditer(r"<form\b([^>]*)>", body, re.IGNORECASE):
        attrs = match.group(1)

        action_match = re.search(
            r'\baction\s*=\s*["\']([^"\']+)["\']',
            attrs,
            re.IGNORECASE,
        )
        method_match = re.search(
            r'\bmethod\s*=\s*["\']([^"\']+)["\']',
            attrs,
            re.IGNORECASE,
        )

        forms.append({
            "action": action_match.group(1) if action_match else None,
            "method": (
                method_match.group(1).upper()
                if method_match
                else "GET"
            ),
        })

    # Extract links but do not request them. This gives the AI
    # useful discovery evidence without turning recon into a crawler.
    links = []
    base_url = response.url

    for match in re.finditer(
        r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\']',
        body,
        re.IGNORECASE,
    ):
        href = match.group(1).strip()

        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)

        if parsed.scheme not in ("http", "https"):
            continue

        links.append(absolute)

        if len(links) >= MAX_DISCOVERED_LINKS:
            break

    same_origin = []
    origin = urlparse(base_url).netloc.lower()

    for link in links:
        if urlparse(link).netloc.lower() == origin:
            if link not in same_origin:
                same_origin.append(link)

    script_count = len(
        re.findall(r"<script\b", body, re.IGNORECASE)
    )

    return {
        "title": title,
        "html_detected": True,
        "forms": forms,
        "same_origin_links": same_origin,
        "scripts": script_count,
    }


def fingerprint_technology(headers: dict, page_metadata: dict) -> list:
    """
    Make conservative technology observations from passive evidence.

    This does not claim an exact version unless the server explicitly
    exposes it.
    """

    signals = []

    server = headers.get("Server")
    powered_by = headers.get("X-Powered-By")

    if server:
        signals.append({
            "source": "Server header",
            "value": server,
        })

    if powered_by:
        signals.append({
            "source": "X-Powered-By header",
            "value": powered_by,
        })

    title = page_metadata.get("title")
    if title:
        signals.append({
            "source": "HTML title",
            "value": title,
        })

    return signals


def check_common_resource(
    session: requests.Session,
    base_url: str,
    path: str
) -> dict:
    """
    Check a very small set of standard resources.
    """

    url = urljoin(base_url + "/", path.lstrip("/"))

    try:
        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        return {
            "path": path,
            "url": response.url,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type"),
            "content_length": response.headers.get("Content-Length"),
        }

    except requests.RequestException as exc:
        return {
            "path": path,
            "url": url,
            "status_code": None,
            "error": str(exc),
        }


def collect_http_metadata(asset: str) -> dict:
    """
    V2.2 limited authorized reconnaissance.

    Collects passive DNS and HTTP metadata, security-header state,
    cookie metadata, redirect information, basic HTML discovery,
    technology signals, and standard-resource status.

    It does not execute JavaScript, brute-force paths, exploit
    vulnerabilities, submit forms, or perform intrusive scanning.
    """

    target = normalize_target(asset)
    parsed = urlparse(target)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid target")

    # ---------- DNS ----------
    try:
        ip_addresses = sorted({
            result[4][0]
            for result in socket.getaddrinfo(
                hostname,
                None,
                type=socket.SOCK_STREAM,
            )
        })
    except socket.gaierror:
        ip_addresses = []

    # ---------- HTTP session ----------
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    })

    try:
        response = session.get(
            target,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        headers = dict(response.headers)

        # ---------- Redirect chain ----------
        redirect_chain = [
            {
                "status_code": redirect.status_code,
                "url": redirect.url,
                "location": redirect.headers.get("Location"),
            }
            for redirect in response.history
        ]

        # ---------- Security headers ----------
        security_headers = collect_security_headers(headers)

        # ---------- Page metadata ----------
        page_metadata = collect_page_metadata(response)

        # ---------- Technology signals ----------
        technology_signals = fingerprint_technology(
            headers,
            page_metadata,
        )

        # ---------- Cookie metadata ----------
        cookie_metadata = collect_cookie_metadata(headers)

        # ---------- Standard resources ----------
        resources = {
            path.lstrip("/").replace("/", "_"): check_common_resource(
                session,
                response.url,
                path,
            )
            for path in COMMON_RESOURCES
        }

        # ---------- Selected response headers ----------
        selected_headers = {
            "Server": headers.get("Server"),
            "Content-Type": headers.get("Content-Type"),
            "Content-Length": headers.get("Content-Length"),
            "Location": headers.get("Location"),
            "Cache-Control": headers.get("Cache-Control"),
            "ETag": headers.get("ETag"),
            "Last-Modified": headers.get("Last-Modified"),
            "X-Powered-By": headers.get("X-Powered-By"),
            "Access-Control-Allow-Origin": headers.get(
                "Access-Control-Allow-Origin"
            ),
            "Access-Control-Allow-Credentials": headers.get(
                "Access-Control-Allow-Credentials"
            ),
        }

        return {
            "target": asset,
            "normalized_target": target,
            "final_url": response.url,
            "status_code": response.status_code,
            "reason": response.reason,
            "ip_addresses": ip_addresses,
            "response_time_ms": round(
                response.elapsed.total_seconds() * 1000,
                2,
            ),
            "selected_headers": selected_headers,
            "security_headers": security_headers,
            "cookie_metadata": cookie_metadata,
            "redirect_chain": redirect_chain,
            "page_metadata": page_metadata,
            "technology_signals": technology_signals,
            "standard_resources": resources,
            "collected_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }

    except requests.RequestException as exc:
        return {
            "target": asset,
            "normalized_target": target,
            "url": target,
            "status_code": None,
            "ip_addresses": ip_addresses,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "collected_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }
