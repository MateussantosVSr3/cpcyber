"""Reproducible labeled evaluation by (rule, line), without executing samples."""
import argparse
import json
import platform
import time
from collections import Counter
from pathlib import Path

from sast.scanner import scan


def scores(counts):
    tp, fp, fn = (counts[key] for key in ('tp', 'fp', 'fn'))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {**dict(counts), 'precision': precision, 'recall': recall, 'f1': f1}


def evaluate():
    corpus = json.loads(Path('benchmarks/corpus.json').read_text(encoding='utf-8'))
    total = Counter(tp=0, fp=0, fn=0)
    languages, cases = {}, []
    start = time.perf_counter()
    for case in corpus['cases']:
        result = scan({case['file']: case['source']})
        actual = {(f['rule'], f['line']) for f in result['findings']}
        expected = {tuple(item) for item in case['expected']}
        counts = Counter(tp=len(actual & expected), fp=len(actual - expected), fn=len(expected - actual))
        total.update(counts)
        language = Path(case['file']).suffix
        languages.setdefault(language, Counter(tp=0, fp=0, fn=0)).update(counts)
        cases.append({'id': case['id'], 'gate': result['gate'], **dict(counts),
                      'missed': sorted(expected - actual), 'unexpected': sorted(actual - expected), 'errors': result['errors']})
    return {'corpus': corpus['description'], 'python': platform.python_version(), 'cases_count': len(cases),
            'elapsed_seconds': round(time.perf_counter() - start, 4), 'aggregate': scores(total),
            'by_extension': {key: scores(value) for key, value in languages.items()}, 'cases': cases}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='reports/benchmark.json')
    args = parser.parse_args()
    result = evaluate()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({key: result[key] for key in ('cases_count', 'elapsed_seconds', 'aggregate')}, indent=2))
    # Known false negatives stay visible; fail regressions without pretending perfect coverage.
    if any(case['errors'] for case in result['cases']) or result['aggregate']['fp'] > 0 or result['aggregate']['fn'] > 2:
        raise SystemExit('Regressão no corpus: consulte o relatório por caso.')


if __name__ == '__main__':
    main()
