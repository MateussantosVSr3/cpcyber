import unittest

from sast.scanner import scan


class MultilangTests(unittest.TestCase):
    def test_mixed_project_uses_both_engines(self):
        result = scan({"main.py": "eval(input())", "app.ts": "target.innerHTML = userInput;"})
        self.assertEqual(result["gate"], "BLOCKED")
        self.assertEqual({item["engine"] for item in result["findings"]}, {"python-ast", "multilang-pattern"})
        self.assertEqual(result["files_scanned"], 2)

    def test_detects_cross_language_rules(self):
        result = scan({
            "app.js": "const api_key = '123456789-secret'; eval(userInput);",
            "Main.java": 'Runtime.getRuntime().exec(command);',
            "server.go": 'tls.Config{InsecureSkipVerify: true}',
        })
        self.assertEqual(result["gate"], "BLOCKED")
        self.assertTrue({"M001", "M002", "M003", "M006"}.issubset({item["rule"] for item in result["findings"]}))

    def test_safe_multilang_passes(self):
        result = scan({"app.js": "node.textContent = message;", "Main.java": "System.out.println(\"ok\");"})
        self.assertEqual(result["gate"], "PASSED")
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
