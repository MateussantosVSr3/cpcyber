"""Comparable trends: same project and scan type, never unrelated projects."""
from collections import Counter


def summarize(items):
    latest, previous, trend = {}, {}, []
    for item in items:
        kind = item['result'].get('scan_type', 'code')
        latest.setdefault((item['project'], kind), item)
    findings = [finding for item in latest.values() for finding in item['result'].get('findings', [])]
    for item in reversed(items):
        result = item['result']
        kind = result.get('scan_type', 'code')
        key = (item['project'], kind)
        counts = Counter(f['severity'] for f in result.get('findings', []))
        count = sum(counts.values())
        last = previous.get(key)
        trend.append({'project': item['project'], 'created': item['created'], 'count': count,
                      'severity': dict(counts), 'delta': count - last if last is not None else None,
                      'gate': result.get('gate', 'PENDING'), 'scan_type': kind})
        previous[key] = count
    critical = Counter((item['project'], f['file']) for item in latest.values()
                       for f in item['result'].get('findings', []) if f['severity'] in {'HIGH', 'CRITICAL'})
    return {'severity': dict(Counter(f['severity'] for f in findings)),
            'critical_files': [(f'{project} / {file}', count) for (project, file), count in critical.most_common(5)],
            'trend': trend, 'projects': len({key[0] for key in latest}), 'scans': len(items)}
