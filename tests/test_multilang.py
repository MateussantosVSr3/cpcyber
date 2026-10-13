import unittest

from sast.scanner import scan


class MultilangTests(unittest.TestCase):
    def test_mixed_project_uses_both_engines(self):
        result = scan({"main.py": "eval(input())", "app.ts": "target.innerHTML = userInput;"})
        self.assertEqual(result["gate"], "BLOCKED")
        self.assertEqual({item["engine"] for item in result["findings"]}, {"python-ast", "tree-sitter:typescript"})
        self.assertEqual(result["files_scanned"], 2)

    def test_detects_cross_language_rules(self):
        result = scan({
            "app.js": "const api_key = '123456789-secret'; eval(userInput);",
            "Main.java": 'class Main { void f(String command) { Runtime.getRuntime().exec(command); } }',
            "server.go": 'package main\nvar config = tls.Config{InsecureSkipVerify: true}',
        })
        self.assertEqual(result["gate"], "BLOCKED")
        self.assertTrue({"M001", "M002", "M003", "M006"}.issubset({item["rule"] for item in result["findings"]}))

    def test_safe_multilang_passes(self):
        result = scan({"app.js": "node.textContent = message;", "Main.java": 'class Main { void f() { System.out.println("ok"); } }'})
        self.assertEqual(result["gate"], "PASSED")
        self.assertEqual(result["findings"], [])

    def test_comments_and_strings_are_not_calls(self):
        result = scan({'a.js': '// eval(input);\nconst text = "system(command)";',
                       'a.rb': '# system(cmd)\ntext = "eval(user)"'})
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['gate'], 'PASSED')

    def test_invalid_syntax_fails_closed(self):
        for name in ['a.js', 'a.ts', 'A.java', 'a.go', 'a.cs', 'a.rb']:
            with self.subTest(name=name):
                result = scan({name: 'function {'})
                self.assertEqual(result['gate'], 'ERROR')
                self.assertTrue(result['errors'])

    def test_all_occurrences_and_redaction(self):
        result = scan({'a.js': 'eval("demo-literal-123");\neval(user);'})
        self.assertEqual(len(result['findings']), 2)
        self.assertNotIn('demo-literal-123', str(result['findings']))

    def test_parameterized_sql_passes(self):
        self.assertEqual(scan({'a.js': 'db.query("SELECT * FROM users WHERE id = ?", [id]);'})['gate'], 'PASSED')

    def test_dynamic_sql_blocks(self):
        self.assertEqual(scan({'a.js': 'db.query("SELECT * FROM users WHERE id = " + id);'})['gate'], 'BLOCKED')


if __name__ == "__main__":
    unittest.main()
