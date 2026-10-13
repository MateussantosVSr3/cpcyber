"""Bounded queue exercise. Run inside API; deletes only its own synthetic jobs."""
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen
from uuid import uuid4

from sast import auth, storage
from sast.jobs import celery_app


def main():
    session = auth.issue_session()
    created = []
    project = 'QA queue ' + uuid4().hex[:12]

    def request(path, payload=None):
        req = Request('http://127.0.0.1:8000' + path,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={'Content-Type': 'application/json', 'X-SAST-Client': 'dashboard', 'Cookie': auth.COOKIE + '=' + session})
        with urlopen(req, timeout=20) as response:
            return json.load(response)

    def submit(index):
        start = time.monotonic()
        vulnerable = index % 2 == 0
        source = 'eval(user);' if vulnerable else 'console.log("ok");'
        scan = request('/api/scans', {'project': project, 'files': {'sample.js': source}})
        created.append(scan['id'])
        for _ in range(120):
            item = request('/api/scans/' + scan['id'])
            if item['status'] in {'COMPLETED', 'FAILED'}:
                expected = 'BLOCKED' if vulnerable else 'PASSED'
                if item['status'] != 'COMPLETED' or item['result']['gate'] != expected:
                    raise RuntimeError('Resultado de fila incorreto')
                return time.monotonic() - start
            time.sleep(.25)
        raise RuntimeError('Timeout aguardando fila')

    started = time.monotonic()
    try:
        expected_workers = int(os.getenv('LOAD_EXPECT_WORKERS', '1'))
        for _ in range(20):
            workers = celery_app.control.ping(timeout=2)
            if len(workers) >= expected_workers:
                break
            time.sleep(1)
        else:
            raise RuntimeError(f'Esperados {expected_workers} workers, responderam {len(workers)}')
        with ThreadPoolExecutor(max_workers=4) as pool:
            times = sorted(pool.map(submit, range(12)))
        report = {'requests': len(times), 'concurrent_clients': 4, 'workers_online': len(workers),
            'duration_seconds': round(time.monotonic() - started, 3), 'p95_seconds': round(times[-1], 3),
            'passed': len(times), 'scope': 'Teste funcional limitado de fila, não benchmark de capacidade máxima'}
        print(json.dumps(report, indent=2))
    finally:
        auth.revoke(session)
        with storage.connection() as conn:
            for scan_id in created:
                storage.run(conn, 'DELETE FROM scans WHERE id = ? AND project = ?', (scan_id, project))


if __name__ == '__main__':
    main()
