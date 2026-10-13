import json
import os
from urllib.request import Request, urlopen


def bridge(route, payload=None, timeout=20):
    token = os.getenv("BRIDGE_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError("Configure BRIDGE_TOKEN para conectar o serviço Codex.")
    req = Request(os.getenv("CODEX_BRIDGE_URL", "http://127.0.0.1:8090") + route,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    with urlopen(req, timeout=timeout) as response:
        return json.load(response)


def review(finding):
    # Source literals and credentials are deliberately not sent to the model.
    return bridge("/review", {"finding": finding}, timeout=200)
