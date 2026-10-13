import argparse
import json
import sys
from pathlib import Path
from sast.engine import scan, gate

EXCLUDED = {".git", ".venv", "venv", "node_modules", "__pycache__"}


def sarif(result):
    rules = {f["rule"]: f for f in result["findings"]}
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "Sentinela SAST", "version": "0.1.0", "rules": [
            {"id": r, "shortDescription": {"text": f["title"]}, "properties": {"tags": ["security", f["cwe"]]}} for r, f in rules.items()]}},
        "invocations": [{"executionSuccessful": not result["errors"]}],
        "results": [{"ruleId": f["rule"], "level": "error" if f["severity"] in {"HIGH", "CRITICAL"} else "warning",
            "message": {"text": f["title"] + ". " + f["remediation"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]}, "region": {"startLine": f["line"], "startColumn": f["column"]}}}],
            "partialFingerprints": {"primaryLocationLineHash": f["fingerprint"]}} for f in result["findings"]]
    }]}


def main():
    parser = argparse.ArgumentParser(description="Sentinela Python SAST — nunca executa código analisado")
    parser.add_argument("path")
    parser.add_argument("--output")
    parser.add_argument("--format", choices=["json", "sarif"], default="json")
    parser.add_argument("--threshold", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH")
    args = parser.parse_args()
    root = Path(args.path)
    paths = sorted(root.rglob("*.py")) if root.is_dir() else [root]
    files, errors = {}, []
    for path in paths:
        if any(part in EXCLUDED for part in path.parts):
            continue
        relative = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            if path.is_symlink() or path.suffix != ".py" or path.stat().st_size > 100_000:
                raise ValueError("Arquivo não suportado, symlink ou maior que 100 KB")
            if root.is_dir() and not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("Arquivo fora do diretório autorizado")
            files[relative] = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append({"file": relative, "message": str(exc)})
    result = scan(files)
    if not files:
        errors.append({"file": str(root), "message": "Nenhum arquivo Python analisável."})
    result["errors"].extend(errors)
    result["gate"] = gate(result["findings"], result["errors"], args.threshold)
    output = json.dumps(sarif(result) if args.format == "sarif" else result, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)
    print(f"Security Gate: {result['gate']} | {len(files)} arquivos | {len(result['findings'])} achados", file=sys.stderr)
    return 2 if result["gate"] == "ERROR" else 1 if result["gate"] == "BLOCKED" else 0

if __name__ == "__main__":
    raise SystemExit(main())
