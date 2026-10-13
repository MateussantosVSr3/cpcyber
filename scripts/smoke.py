"""Checks the real queue/DB stack; never authenticates to Codex in CI."""
import json
import time
from urllib.request import Request, urlopen


def request(path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request("http://127.0.0.1:8000" + path, data=data,
        headers={"Content-Type": "application/json", "X-SAST-Client": "dashboard"})
    with urlopen(req, timeout=10) as response:
        return json.load(response)


for source, expected in [('eval(input())', 'BLOCKED'), ('x = 1', 'PASSED')]:
    scan = request('/api/scans', {'project': 'CI smoke', 'files': {'test.py': source}})
    for attempt in range(30):
        item = request('/api/scans/' + scan['id'])
        if item['status'] in {'COMPLETED', 'FAILED'}:
            break
        time.sleep(1)
    if item['status'] != 'COMPLETED' or item['result']['gate'] != expected:
        raise SystemExit('Smoke test failed: ' + json.dumps(item))
print('Smoke test HTTP: passed (confira o modo de execução do servidor)')
