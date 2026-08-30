import socket
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone

import requests


USER_AGENT = "BugBountyAI-Recon/0.2"


def normalize_target(asset: str) -> str:
    asset = asset.strip()

    if not asset.startswith(("http://", "https://")):
        asset = "https://" + asset

    return asset.rstrip("/")


def collect_security_headers(headers: dict) -> dict:
    """
    Extract commonly useful security-related HTTP headers.
    """

    interesting_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy"
    ]

    return {
        header: headers.get(header)
        for header in interesting_headers
    }


def collect_page_metadata(response: requests.Response) -> dict:
    """
    Collect basic page metadata without executing JavaScript
    or performing intrusive crawling.
    """

    content_type = response.headers.get("Content-Type", "")

    if "text/html" not in content_type.lower():
        return {
            "title": None,
            "html_detected": False
        }

    body = response.text[:500000]

    title = None

    lower_body = body.lower()

    title_start = lower_body.find("<title>")

    if title_start != -1:
        title_start += len("<title>")
        title_end = lower_body.find("</title>", title_start)

        if title_end != -1:
            title = body[title_start:title_end].strip()

    return {
        "title": title,
        "html_detected": True
    }


def check_common_resource(
    session: requests.Session,
    base_url: str,
    path: str
) -> dict:
    """
    Check a small set of standard web resources.
    """

    url = urljoin(base_url + "/", path.lstrip("/"))

    try:
        response = session.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        return {
            "path": path,
            "url": response.url,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type"),
            "content_length": response.headers.get("Content-Length")
        }

    except requests.RequestException as exc:

        return {
            "path": path,
            "url": url,
            "status_code": None,
            "error": str(exc)
        }


def collect_http_metadata(asset: str) -> dict:
    """
    Recon v2.

    Collects limited, non-destructive HTTP information from
    an authorized target.

    No vulnerability exploitation or intrusive scanning.
    """

    target = normalize_target(asset)

    parsed = urlparse(target)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid target")

    # ---------- DNS ----------

    try:
        ip_addresses = sorted(
            {
                result[4][0]
                for result in socket.getaddrinfo(
                    hostname,
                    None,
                    type=socket.SOCK_STREAM
                )
            }
        )

    except socket.gaierror:
        ip_addresses = []


    # ---------- HTTP Session ----------

    session = requests.Session()

    session.headers.update({
        "User-Agent": USER_AGENT
    })


    try:

        response = session.get(
            target,
            timeout=10,
            allow_redirects=True
        )

        headers = dict(response.headers)

        # ---------- Redirect Information ----------

        redirect_chain = []

        for redirect in response.history:

            redirect_chain.append({
                "status_code": redirect.status_code,
                "url": redirect.url,
                "location": redirect.headers.get("Location")
            })


        # ---------- Security Headers ----------

        security_headers = collect_security_headers(
            headers
        )


        # ---------- Page Metadata ----------

        page_metadata = collect_page_metadata(
            response
        )


        # ---------- Standard Resources ----------

        resources = {
            "robots_txt": check_common_resource(
                session,
                response.url,
                "/robots.txt"
            ),
            "security_txt": check_common_resource(
                session,
                response.url,
                "/.well-known/security.txt"
            )
        }


        # ---------- Response Headers ----------

        selected_headers = {
            "Server": headers.get("Server"),
            "Content-Type": headers.get("Content-Type"),
            "Content-Length": headers.get("Content-Length"),
            "Location": headers.get("Location"),
            "Cache-Control": headers.get("Cache-Control"),
            "ETag": headers.get("ETag"),
            "Last-Modified": headers.get("Last-Modified")
        }


        return {
            "target": asset,
            "final_url": response.url,
            "status_code": response.status_code,
            "ip_addresses": ip_addresses,
            "selected_headers": selected_headers,
            "security_headers": security_headers,
            "redirect_chain": redirect_chain,
            "page_metadata": page_metadata,
            "standard_resources": resources,
            "collected_at": datetime.now(
                timezone.utc
            ).isoformat()
        }


    except requests.RequestException as exc:

        return {
            "target": asset,
            "url": target,
            "status_code": None,
            "ip_addresses": ip_addresses,
            "error": str(exc),
            "collected_at": datetime.now(
                timezone.utc
            ).isoformat()
        }