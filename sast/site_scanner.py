"""Passive, bounded website inspection with SSRF protections."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import urllib.error
import urllib.parse
import urllib.request


MAX_BODY = 600_000
USER_AGENT = "Sentinela-SAST/0.2 passive-security-check"


class SiteScanError(ValueError):
    pass


def validate_public_url(value: str) -> str:
    value = value.strip()
    if len(value) > 2048:
        raise SiteScanError("URL muito longa.")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SiteScanError("Use uma URL pública começando com http:// ou https://.")
    if parsed.username or parsed.password or parsed.fragment:
        raise SiteScanError("A URL não pode conter credenciais ou fragmento.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise SiteScanError("Porta inválida.") from exc
    if port and port not in {80, 443}:
        raise SiteScanError("Somente portas web 80 e 443 são permitidas.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise SiteScanError("Não foi possível resolver o endereço do site.") from exc
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise SiteScanError("Endereços locais, privados ou reservados não podem ser analisados.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


class SafeRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = validate_public_url(urllib.parse.urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, target)


def fetch_site(url: str) -> tuple[str, str, dict[str, str]]:
    url = validate_public_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"})
    try:
        with urllib.request.build_opener(SafeRedirects).open(request, timeout=12) as response:
            final_url = validate_public_url(response.geturl())
            content_type = response.headers.get_content_type()
            if content_type not in {"text/html", "application/xhtml+xml"}:
                raise SiteScanError("A URL precisa retornar uma página HTML.")
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise SiteScanError("A página excede o limite de 600 KB.")
            charset = response.headers.get_content_charset() or "utf-8"
            return final_url, body.decode(charset, errors="replace"), {key.lower(): value for key, value in response.headers.items()}
    except SiteScanError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SiteScanError("Não foi possível acessar o site público.") from exc


def _finding(rule: str, severity: str, cwe: str, title: str, remediation: str, url: str, line: int = 1, trace: list[str] | None = None):
    raw = f"{rule}:{url}:{line}:{title}"
    return {
        "rule": rule, "severity": severity, "cwe": cwe, "title": title,
        "remediation": remediation, "file": url, "line": line, "column": 1,
        "confidence": "HIGH", "trace": trace or ["Resposta HTTP e HTML da página pública"],
        "engine": "passive-web", "fingerprint": hashlib.sha256(raw.encode()).hexdigest()[:24],
        "context": "Inspeção passiva; nenhum payload foi executado contra o site.",
    }


def scan_site(url: str) -> dict:
    final_url, html, headers = fetch_site(url)
    lower = html.lower()
    findings = []
    if urllib.parse.urlsplit(final_url).scheme != "https":
        findings.append(_finding("W001", "HIGH", "CWE-319", "Site sem HTTPS", "Publique o site apenas por HTTPS e redirecione HTTP para HTTPS.", final_url))
    elif "strict-transport-security" not in headers:
        findings.append(_finding("W002", "MEDIUM", "CWE-319", "HSTS ausente", "Adicione Strict-Transport-Security após confirmar que todo o site funciona em HTTPS.", final_url))
    csp = headers.get("content-security-policy", "")
    if not csp:
        findings.append(_finding("W003", "MEDIUM", "CWE-693", "Content Security Policy ausente", "Defina uma CSP restritiva e evite unsafe-inline/unsafe-eval.", final_url))
    if "x-content-type-options" not in headers:
        findings.append(_finding("W004", "LOW", "CWE-693", "Proteção MIME ausente", "Envie X-Content-Type-Options: nosniff.", final_url))
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        findings.append(_finding("W005", "MEDIUM", "CWE-1021", "Proteção contra clickjacking ausente", "Use frame-ancestors na CSP ou X-Frame-Options.", final_url))
    if "referrer-policy" not in headers:
        findings.append(_finding("W006", "LOW", "CWE-200", "Referrer Policy ausente", "Defina uma Referrer-Policy adequada aos dados da aplicação.", final_url))
    for match in re.finditer(r"<(?:script|img|iframe|link|form)[^>]+(?:src|href|action)\s*=\s*['\"]http://", html, re.I):
        line = html.count("\n", 0, match.start()) + 1
        findings.append(_finding("W007", "MEDIUM", "CWE-319", "Conteúdo misto ou envio inseguro", "Troque recursos e ações HTTP por HTTPS.", final_url, line))
        break
    if re.search(r"<input[^>]+type\s*=\s*['\"]password['\"]", html, re.I) and urllib.parse.urlsplit(final_url).scheme != "https":
        findings.append(_finding("W008", "HIGH", "CWE-523", "Senha transmitida sem HTTPS", "Nunca aceite credenciais em uma página HTTP.", final_url))
    dangerous = [(r"\beval\s*\(", "eval() no JavaScript", "CWE-95"), (r"document\.write\s*\(", "document.write() no JavaScript", "CWE-79"), (r"\.innerHTML\s*=", "Atribuição a innerHTML", "CWE-79")]
    for pattern, title, cwe in dangerous:
        match = re.search(pattern, html, re.I)
        if match:
            line = html.count("\n", 0, match.start()) + 1
            findings.append(_finding("W009", "HIGH", cwe, title, "Use APIs seguras de DOM e nunca interprete entrada não confiável como código ou HTML.", final_url, line, ["Padrão localizado no HTML/JavaScript retornado"]))
    return {"gate": "BLOCKED" if any(item["severity"] in {"HIGH", "CRITICAL"} for item in findings) else "PASSED", "findings": findings, "errors": [], "files_scanned": 1, "target": final_url, "scan_type": "website"}
