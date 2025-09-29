import unittest
from app import score_url

class TestScoreURL(unittest.TestCase):
    def test_sqli(self):
        r = score_url("/index.php?id=1 OR 1=1")
        self.assertIn("SQL Injection", r["findings"])

    def test_xss(self):
        r = score_url("/search?q=<script>alert(1)</script>")
        self.assertIn("Cross Site Scripting (XSS)", r["findings"])

    def test_traversal(self):
        r = score_url("/view.php?file=../../etc/passwd")
        self.assertIn("Directory Traversal", r["findings"])

    def test_clean(self):
        r = score_url("/home")
        self.assertEqual(len(r["findings"]), 0)

if __name__ == "__main__":
    unittest.main()
