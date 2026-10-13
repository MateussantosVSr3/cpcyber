import os
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import PurePosixPath, Path
from typing import Annotated

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, field_validator
from sast import ai, storage
from sast.jobs import process


class Submission(BaseModel):
    project: str = Field(min_length=1, max_length=80)
    files: dict[str, str] = Field(min_length=1, max_length=100)

    @field_validator("files")
    @classmethod
    def validate_files(cls, files):
        total = 0
        for name, source in files.items():
            p = PurePosixPath(name)
            allowed = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".go", ".cs", ".rb"}
            if p.suffix.lower() not in allowed or p.is_absolute() or ".." in p.parts or "\\" in name or ":" in name or len(name) > 200:
                raise ValueError("Envie arquivos Python, JavaScript, TypeScript, Java, PHP, Go, C# ou Ruby.")
            size = len(source.encode("utf-8"))
            if size > 100_000:
                raise ValueError("Limite de 100 KB por arquivo.")
            total += size
        if total > 1_000_000:
            raise ValueError("Limite de 1 MB por análise.")
        return files


class SiteSubmission(BaseModel):
    project: str = Field(min_length=1, max_length=80)
    url: str = Field(min_length=8, max_length=2048)


@asynccontextmanager
async def lifespan(app):
    storage.init()
    yield


app = FastAPI(title="Sentinela SAST", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "testserver", "api", "3.149.250.106"],
)


@app.middleware("http")
async def local_boundary(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            return JSONResponse({"detail": "Origem não autorizada."}, status_code=403)
        if request.method != "GET" and request.headers.get("x-sast-client") != "dashboard":
            return JSONResponse({"detail": "Cabeçalho X-SAST-Client obrigatório."}, status_code=403)
        # Bound body before JSON validation, including chunked requests.
        if request.method in {"POST", "PUT", "PATCH"}:
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 2_000_000:
                    return JSONResponse({"detail": "Payload muito grande."}, status_code=413)
            request._body = bytes(body)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scans", status_code=202)
def submit(payload: Submission, background: BackgroundTasks):
    scan_id = storage.create(payload.project, payload.files)
    if os.getenv("REDIS_URL"):
        from sast.jobs import scan_task
        try:
            scan_task.apply_async(args=[scan_id], task_id=scan_id, retry=False)
        except Exception:
            storage.finish(scan_id, {"gate": "ERROR", "findings": [], "errors": [{"message": "Fila indisponível."}]}, "FAILED")
            raise HTTPException(503, "Fila indisponível. Tente novamente.")
    else:
        background.add_task(process, scan_id)
    return {"id": scan_id, "status": "QUEUED"}


@app.post("/api/site-scans", status_code=202)
def submit_site(payload: SiteSubmission, background: BackgroundTasks):
    from sast.site_scanner import SiteScanError, validate_public_url
    try:
        url = validate_public_url(payload.url)
    except SiteScanError as exc:
        raise HTTPException(422, str(exc)) from exc
    scan_id = storage.create(payload.project, {"__site_url__": url})
    if os.getenv("REDIS_URL"):
        from sast.jobs import scan_task
        try:
            scan_task.apply_async(args=[scan_id], task_id=scan_id, retry=False)
        except Exception:
            storage.finish(scan_id, {"gate": "ERROR", "findings": [], "errors": [{"message": "Fila indisponível."}]}, "FAILED")
            raise HTTPException(503, "Fila indisponível. Tente novamente.")
    else:
        background.add_task(process, scan_id)
    return {"id": scan_id, "status": "QUEUED"}


@app.get("/api/scans")
def scans():
    return storage.recent()


@app.get("/api/scans/{scan_id}")
def detail(scan_id: str):
    item = storage.get(scan_id)
    if item is None:
        raise HTTPException(404, "Análise não encontrada.")
    return item


@app.get("/api/metrics")
def metrics(project: str | None = None):
    items = [s for s in storage.recent() if (project is None or s["project"] == project) and s["status"] == "COMPLETED"]
    latest = {}
    for item in items:
        latest.setdefault(item["project"], item)
    findings = [f for s in latest.values() for f in s["result"].get("findings", [])]
    return {"severity": dict(Counter(f["severity"] for f in findings)),
        "critical_files": Counter(f["file"] for f in findings if f["severity"] in {"HIGH", "CRITICAL"}).most_common(5),
        "trend": [{"project": s["project"], "created": s["created"], "count": len(s["result"].get("findings", [])),
            "gate": s["result"].get("gate", "PENDING"), "scan_type": s["result"].get("scan_type", "code")} for s in reversed(items)],
        "projects": len(latest), "scans": len(items)}


def call_ai(route, payload=None):
    try:
        return ai.bridge(route, payload)
    except Exception:
        raise HTTPException(503, "Serviço Codex indisponível. Verifique o container e a configuração.")


@app.get("/api/codex/account")
def account():
    return call_ai("/account")


@app.post("/api/codex/login")
def login():
    return call_ai("/login", {})


@app.post("/api/codex/logout")
def logout():
    return call_ai("/logout", {})


@app.post("/api/scans/{scan_id}/review/{fingerprint}")
def review(scan_id: str, fingerprint: str):
    item = detail(scan_id)
    finding = next((f for f in item["result"].get("findings", []) if f["fingerprint"] == fingerprint), None)
    if finding is None:
        raise HTTPException(404, "Vulnerabilidade não encontrada.")
    try:
        result = ai.review({key: value for key, value in finding.items() if key != "ai"})
    except Exception:
        raise HTTPException(503, "Não foi possível obter a revisão. Confira o login e os limites da conta.")
    finding["ai"] = result
    storage.save_result(scan_id, item["result"])
    return result


@app.post("/api/scans/{scan_id}/ai-report")
def ai_report(scan_id: str):
    item = detail(scan_id)
    findings = item["result"].get("findings", [])
    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    severity = max((f.get("severity", "LOW") for f in findings), key=lambda value: severity_order.get(value, 0), default="LOW")
    context = "\n".join(f"{f['severity']} {f['rule']} {f['cwe']}: {f['title']} — {f['remediation']}" for f in findings)[:14000]
    payload = {"rule": "EXECUTIVE-REPORT", "severity": severity, "cwe": "N/A", "title": f"Relatório executivo do projeto {item['project']}",
        "remediation": "Priorize ações práticas e explique o risco de negócio em português.", "file": item["result"].get("target", item["project"]),
        "line": 1, "column": 1, "confidence": "HIGH", "trace": [f"Gate {item['result'].get('gate')}; {len(findings)} achados"],
        "engine": "report", "fingerprint": scan_id[:24], "context": context or "Nenhum achado pelas regras executadas; destaque as limitações desta conclusão."}
    try:
        review = ai.review(payload)
    except Exception:
        raise HTTPException(503, "Não foi possível gerar o relatório com Codex. Confira login e limites da conta.")
    item["result"]["ai_report"] = {"provider": "codex", "summary": review["explanation"], "priorities": review["remediation"], "action_plan": review["corrected_code"]}
    storage.save_result(scan_id, item["result"])
    return item["result"]["ai_report"]


@app.get("/api/scans/{scan_id}/report.pdf")
def pdf_report(scan_id: str):
    from sast.pdf_report import build_pdf
    item = detail(scan_id)
    stream = build_pdf(item)
    return StreamingResponse(stream, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="null-sentry-{scan_id}.pdf"'})


WEB = Path(__file__).resolve().parent.parent / "web"
app.mount("/static", StaticFiles(directory=WEB), name="static")


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")
