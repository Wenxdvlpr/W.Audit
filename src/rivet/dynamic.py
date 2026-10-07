from __future__ import annotations

import ipaddress
import http.client
import socket
import ssl
from urllib.parse import urlsplit

from .model import Check, Finding

METADATA_ADDRESSES = {ipaddress.ip_address(value) for value in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16")}


def _blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    value = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
    return value.is_link_local or value.is_multicast or value.is_unspecified or value.is_reserved or value in METADATA_ADDRESSES


def _target(url: str, allowed_hosts: tuple[str, ...]) -> tuple[object, str, ipaddress.IPv4Address | ipaddress.IPv6Address]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("dynamic target must be an HTTP(S) URL without userinfo or fragment")
    host = parsed.hostname.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    local = host == "localhost" or address is not None and address.is_loopback
    if not local and host not in {x.lower().rstrip(".") for x in allowed_hosts}:
        raise ValueError("target host is not loopback or explicitly allowed")
    if local:
        resolved = {address} if address is not None else {ipaddress.ip_address("127.0.0.1")}
    else:
        if address is None:
            try:
                resolved = {ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)}
            except (OSError, ValueError) as exc:
                raise ValueError("target hostname could not be safely resolved") from exc
        else:
            resolved = {address}
        if not resolved or any(_blocked(ip) for ip in resolved):
            raise ValueError("target resolves to a blocked address")
        if any(ip.is_private for ip in resolved) and host not in {x.lower().rstrip(".") for x in allowed_hosts}:
            raise ValueError("private target requires an explicit allowlist entry")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("invalid target port")
    return parsed, host, sorted(resolved, key=str)[0]


def validate_target(url: str, allowed_hosts: tuple[str, ...]) -> str:
    return _target(url, allowed_hosts)[1]


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str):
        super().__init__(host, port, timeout=5)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str):
        super().__init__(host, port, timeout=5, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def check_headers(url: str, allowed_hosts: tuple[str, ...]) -> tuple[list[Finding], list[Check]]:
    parsed, host, address = _target(url, allowed_hosts)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connection = _PinnedHTTPS(host, port, str(address)) if parsed.scheme == "https" else _PinnedHTTP(host, port, str(address))
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    host_header = f"[{host}]" if ":" in host else host
    if parsed.port:
        host_header += f":{port}"
    try:
        connection.request("HEAD", path, headers={"Host": host_header, "User-Agent": "W.Audit/0.4.0b1 safe-baseline"})
        response = connection.getresponse()
        if 300 <= response.status < 400:
            return [], [Check("Dynamic HTTP", "SKIPPED", "W.Audit HEAD", "redirect blocked")]
        if response.status >= 400:
            raise RuntimeError(f"HEAD request failed with HTTP {response.status}")
        headers = response.headers
    except (OSError, TimeoutError, ssl.SSLError, http.client.HTTPException) as exc:
        raise RuntimeError("HEAD request failed") from exc
    finally:
        connection.close()
    findings = []
    if not headers.get("X-Content-Type-Options", "").lower() == "nosniff":
        findings.append(Finding("http/missing-nosniff", "X-Content-Type-Options is not nosniff", "LOW", "HIGH", "HTTP headers", url, 1, "HEAD response lacks nosniff", "Browsers may MIME-sniff some responses.", "Set X-Content-Type-Options: nosniff.", "Repeat HEAD request and check the response header.", "W.Audit HEAD", "CWE-693", "CONDITIONAL", "NEEDS_MANUAL_REVIEW"))
    if headers.get("Access-Control-Allow-Origin") == "*" and headers.get("Access-Control-Allow-Credentials", "").lower() == "true":
        findings.append(Finding("http/cors-wildcard-credentials", "CORS combines wildcard origin and credentials", "MEDIUM", "MEDIUM", "CORS", url, 1, "HEAD response advertises wildcard origin and credentials", "Browser behavior and actual cross-origin exposure require review.", "Use a narrow origin allowlist and verify credential behavior.", "Test cross-origin requests from an untrusted origin.", "W.Audit HEAD", "CWE-942", "CONDITIONAL", "NEEDS_MANUAL_REVIEW"))
    return findings, [Check("Dynamic HTTP", "CHECKED", "W.Audit HEAD", "One bounded HEAD request; no redirects")]
