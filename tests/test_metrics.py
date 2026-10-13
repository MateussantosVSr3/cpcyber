import unittest
from sast.metrics import summarize


def item(project, count, kind='code'):
    return {'project': project, 'created': '2026-10-13', 'result': {'scan_type': kind, 'gate': 'PASSED',
            'findings': [{'severity': 'HIGH', 'file': 'main.py'} for _ in range(count)]}}


class MetricsTests(unittest.TestCase):
    def test_delta_compares_same_project_and_type(self):
        result = summarize([item('A', 1), item('B', 9), item('A', 5, 'website'), item('A', 3)])
        self.assertEqual([x['delta'] for x in result['trend']], [None, None, None, -2])
        self.assertEqual(result['severity'], {'HIGH': 15})

    def test_files_are_separated_by_project(self):
        result = summarize([item('A', 1), item('B', 2)])
        self.assertEqual(result['critical_files'], [('B / main.py', 2), ('A / main.py', 1)])
