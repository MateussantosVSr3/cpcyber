"""Conservative cross-language security rules for non-Python source files."""
from __future__ import annotations

import hashlib
import re

SUPPORTED = {".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".go", ".cs", ".rb"}

RULES = [
    ("M001", "HIGH", "CWE-798", "Possível segredo hardcoded", r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"][^'\"\r\n]{8,}['\"]", "Use um gerenciador de segredos ou variável de ambiente e faça rotação do valor."),
    ("M002", "HIGH", "CWE-95", "Execução dinâmica de código", r"(?i)(?:\beval\s*\(|\bnew\s+Function\s*\(|ScriptEngine[^\n]*\.eval\s*\()", "Remova a avaliação dinâmica e use parsing explícito com validação de tipos."),
    ("M003", "HIGH", "CWE-78", "Execução de comando do sistema", r"(?i)(?:child_process\s*\.\s*exec\s*\(|\b(?:shell_exec|system|passthru)\s*\(|Runtime\.getRuntime\(\)\.exec\s*\(|Process\.Start\s*\(|\bexec\s*\([^\n]*\+|`[^`]*(?:\$\{|#\{))", "Evite shells, use argumentos separados e valide entradas por allowlist."),
    ("M004", "HIGH", "CWE-89", "SQL construído dinamicamente", r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)[^\r\n]{0,180}(?:\+|\$\{|#\{|\.\s*\$)", "Use consultas parametrizadas e mantenha dados separados do comando SQL."),
    ("M005", "MEDIUM", "CWE-327", "Hash criptográfico fraco", r"(?i)(?:\bmd5\s*\(|\bsha1\s*\(|MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1))", "Use SHA-256/512 para integridade ou Argon2/bcrypt/scrypt para senhas."),
    ("M006", "MEDIUM", "CWE-295", "Validação TLS desabilitada", r"(?i)(?:rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*false|ServerCertificateValidationCallback[^\n]*=>\s*true)", "Mantenha a validação de certificados habilitada e instale a cadeia de confiança correta."),
    ("M007", "HIGH", "CWE-79", "HTML não confiável em sink de DOM", r"(?i)(?:\.innerHTML\s*=|dangerouslySetInnerHTML\s*=|document\.write\s*\()", "Use textContent/APIs seguras de DOM e sanitização contextual quando HTML for inevitável."),
]


def _redact(line: str) -> str:
    return re.sub(r"(['\"])(?:(?!\1).)*\1", r"\1<literal oculto>\1", line)[:300]


def scan_multilang(files: dict[str, str]) -> list[dict]:
    findings = []
    for name, source in files.items():
        for rule, severity, cwe, title, pattern, remediation in RULES:
            for match in re.finditer(pattern, source):
                line = source.count("\n", 0, match.start()) + 1
                raw = f"{rule}:{name}:{line}:{match.group(0)[:80]}"
                findings.append({
                    "rule": rule, "severity": severity, "cwe": cwe, "title": title,
                    "remediation": remediation, "file": name, "line": line, "column": match.start() - source.rfind("\n", 0, match.start()),
                    "confidence": "MEDIUM", "trace": [f"L{line}: padrão de segurança localizado"],
                    "engine": "multilang-pattern", "fingerprint": hashlib.sha256(raw.encode()).hexdigest()[:24],
                    "context": _redact(source.splitlines()[line - 1] if source.splitlines() else ""),
                })
                break
    return findings
