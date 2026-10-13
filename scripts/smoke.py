"""Checks the real queue/DB stack; never authenticates to Codex in CI."""
import json
import os
import time
from urllib.request import Request, urlopen
from sast import auth

session = auth.issue_session()


def request(path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(os.getenv("SAST_BASE_URL", "http://127.0.0.1:8000") + path, data=data,
        headers={"Content-Type": "application/json", "X-SAST-Client": "dashboard", "Cookie": auth.COOKIE + '=' + session})
    with urlopen(req, timeout=10) as response:
        return json.load(response)


if not os.getenv('DATABASE_URL', '').startswith('postgresql://') or not os.getenv('REDIS_URL'):
    raise SystemExit('Execute este smoke dentro do container API com PostgreSQL e Redis configurados.')

from sast import storage
from sast.jobs import celery_app
import redis

assert redis.Redis.from_url(os.environ['REDIS_URL']).ping(), 'Redis indisponível'
assert celery_app.control.ping(timeout=10), 'Nenhum worker respondeu'

for source, expected in [('eval(input())', 'BLOCKED'), ('x = 1', 'PASSED')]:
    scan = request('/api/scans', {'project': 'CI smoke', 'files': {'test.py': source}})
    for attempt in range(30):
        item = request('/api/scans/' + scan['id'])
        if item['status'] in {'COMPLETED', 'FAILED'}:
            break
        time.sleep(1)
    if item['status'] != 'COMPLETED' or item['result']['gate'] != expected:
        raise SystemExit('Smoke test failed: ' + json.dumps(item))
    persisted = storage.get(scan['id'], include_source=True)
    assert persisted['result']['gate'] == expected and persisted['files'] == {}
print('Smoke: HTTP, PostgreSQL, Redis, Celery, remoção do fonte e gates BLOCKED/PASSED confirmados.')
auth.revoke(session)
