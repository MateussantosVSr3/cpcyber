"""Exercise the real authenticated HTTP/queue/database stack in the API container."""
import json
import os
import time
from urllib.request import Request, urlopen

from sast import auth, storage


def main():
    if not os.getenv('DATABASE_URL', '').startswith('postgresql://') or not os.getenv('REDIS_URL'):
        raise SystemExit('Execute este smoke dentro do container API com PostgreSQL e Redis configurados.')
    from sast.jobs import celery_app
    import redis

    if not redis.Redis.from_url(os.environ['REDIS_URL']).ping():
        raise SystemExit('Redis indisponível')
    for attempt in range(15):
        if celery_app.control.ping(timeout=2):
            break
        time.sleep(1)
    else:
        raise SystemExit('Nenhum worker respondeu após aguardar a inicialização.')
    session = auth.issue_session()
    created = []

    def request(path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = Request(os.getenv('SAST_BASE_URL', 'http://127.0.0.1:8000') + path, data=data,
            headers={'Content-Type': 'application/json', 'X-SAST-Client': 'dashboard', 'Cookie': auth.COOKIE + '=' + session})
        with urlopen(req, timeout=10) as response:
            return json.load(response)

    try:
        for source, expected in [('eval(input())', 'BLOCKED'), ('x = 1', 'PASSED')]:
            scan = request('/api/scans', {'project': 'CI smoke', 'files': {'test.py': source}})
            created.append(scan['id'])
            for attempt in range(30):
                item = request('/api/scans/' + scan['id'])
                if item['status'] in {'COMPLETED', 'FAILED'}:
                    break
                time.sleep(1)
            if item['status'] != 'COMPLETED' or item['result']['gate'] != expected:
                raise SystemExit('Smoke test failed: ' + json.dumps(item))
            persisted = storage.get(scan['id'], include_source=True)
            if persisted['result']['gate'] != expected or persisted['files'] != {}:
                raise SystemExit('Persistência ou remoção do fonte falhou.')
        print('Smoke: HTTP, PostgreSQL, Redis, Celery, remoção do fonte e gates BLOCKED/PASSED confirmados.')
    finally:
        auth.revoke(session)
        with storage.connection() as conn:
            for identity in created:
                storage.run(conn, 'DELETE FROM scans WHERE id = ? AND project = ?', (identity, 'CI smoke'))


if __name__ == '__main__':
    main()
