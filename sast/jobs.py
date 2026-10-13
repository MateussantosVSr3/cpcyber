import os
from sast import storage
from sast.engine import scan
from sast.site_scanner import scan_site


def process(scan_id):
    item = storage.get(scan_id, include_source=True)
    if not item or item["status"] == "COMPLETED":
        return
    storage.status(scan_id, "RUNNING")
    try:
        site_url = item["files"].get("__site_url__")
        result = scan_site(site_url) if site_url else scan(item["files"])
        storage.finish(scan_id, result)
    except Exception:
        storage.finish(scan_id, {"gate": "ERROR", "findings": [], "errors": [{"message": "Falha no processamento; execute nova análise."}]}, "FAILED")

if os.getenv("REDIS_URL"):
    from celery import Celery
    celery_app = Celery("sast", broker=os.environ["REDIS_URL"])
    celery_app.conf.update(task_serializer="json", accept_content=["json"], worker_prefetch_multiplier=1,
        task_acks_late=True, task_reject_on_worker_lost=True, task_soft_time_limit=100, task_time_limit=120,
        broker_connection_retry_on_startup=True)
    scan_task = celery_app.task(name="sast.scan")(process)
