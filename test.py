import subprocess
from unittest import TestCase
from unittest import main as unittest_main


class BankTest(TestCase):
    def test_bank_executable_output(self):
        result = subprocess.run(
            ["./bank.py"],
            capture_output=True,
            text=True
        )
        with open("README.md", "r") as f:
            readme_content = f.read()
        self.assertEqual(result.stdout[-2:], "\n\n")
        self.assertIn(result.stdout[:-1], readme_content)


if __name__ == "__main__":
    unittest_main()
