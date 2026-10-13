from pathlib import PurePosixPath

from sast.engine import scan as scan_python
from sast.multilang import scan_multilang


def scan(files: dict[str, str]) -> dict:
    python_files = {name: source for name, source in files.items() if PurePosixPath(name).suffix.lower() == ".py"}
    other_files = {name: source for name, source in files.items() if name not in python_files}
    py_result = scan_python(python_files) if python_files else {"findings": [], "errors": [], "gate": "PASSED", "files_scanned": 0}
    findings = py_result["findings"] + scan_multilang(other_files)
    errors = py_result["errors"]
    gate = "ERROR" if py_result["gate"] == "ERROR" else "BLOCKED" if any(item["severity"] in {"HIGH", "CRITICAL"} for item in findings) else "PASSED"
    return {"findings": findings, "errors": errors, "gate": gate, "files_scanned": len(files), "scan_type": "code"}
