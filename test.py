import subprocess
from pathlib import Path
from unittest import TestCase
from unittest import main as unittest_main

from bank import BankException, Config


class ReadmeTest(TestCase):
    def test_bank_executable_output(self):
        result = subprocess.run(["./bank.py"], capture_output=True, text=True)
        with Path("README.md").open() as f:
            readme_content = f.read()
        self.assertEqual(result.stdout[-2:], "\n\n")
        self.assertIn(result.stdout[:-1], readme_content)


class ConfigValidationTest(TestCase):
    """Test Config class validation and error messages"""

    def test_missing_certificates_field(self):
        """Should raise error when certificates field is missing"""
        with self.assertRaises(BankException) as ctx:
            Config('{"accounts": []}')
        self.assertEqual(str(ctx.exception), "Missing 'certificates' field in config")

    def test_missing_accounts_field(self):
        """Should raise error when accounts field is missing"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {"qonto": "abc123"}}')
        self.assertEqual(str(ctx.exception), "Missing 'accounts' field in config")

    def test_missing_qonto_certificate(self):
        """Should raise error when qonto certificate is missing"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {}, "accounts": []}')
        self.assertEqual(str(ctx.exception), "Missing 'certificates.qonto' field in config")

    def test_certificate_wrong_type(self):
        """Should raise error when certificate is not a string"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {"qonto": 123}, "accounts": []}')
        self.assertEqual(str(ctx.exception), "Certificate must be a string, got int")

    def test_certificate_invalid_length(self):
        """Should raise error when certificate is not 64 characters"""
        config_str = (
            '{"certificates": {"qonto": "abc"}, "accounts": [{"id": "x", "secret_key": "y", "local_store_path": "z"}]}'
        )
        with self.assertRaises(BankException) as ctx:
            Config(config_str)
        self.assertEqual(str(ctx.exception), "Certificate must be 64 hex characters, got 3")

    def test_certificate_invalid_characters(self):
        """Should raise error when certificate contains non-hex characters"""
        with self.assertRaises(BankException) as ctx:
            Config(
                '{"certificates": {"qonto": "'
                + "G" * 64
                + '"}, "accounts": [{"id": "x", "secret_key": "y", "local_store_path": "z"}]}'
            )
        self.assertEqual(str(ctx.exception), "Certificate must contain only hexadecimal characters (0-9, a-f)")

    def test_accounts_wrong_type(self):
        """Should raise error when accounts is not a list"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {"qonto": "' + "a" * 64 + '"}, "accounts": "not-a-list"}')
        self.assertEqual(str(ctx.exception), "'accounts' must be a list, got str")

    def test_accounts_empty_list(self):
        """Should raise error when accounts list is empty"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {"qonto": "' + "a" * 64 + '"}, "accounts": []}')
        self.assertEqual(str(ctx.exception), "'accounts' list cannot be empty")

    def test_account_missing_id(self):
        """Should raise error when account is missing id field"""
        with self.assertRaises(BankException) as ctx:
            Config(
                '{"certificates": {"qonto": "'
                + "a" * 64
                + '"}, "accounts": [{"secret_key": "y", "local_store_path": "z"}]}'
            )
        self.assertEqual(str(ctx.exception), "Missing 'id' in account #1")

    def test_account_missing_secret_key(self):
        """Should raise error when account is missing secret_key field"""
        with self.assertRaises(BankException) as ctx:
            Config(
                '{"certificates": {"qonto": "' + "a" * 64 + '"}, "accounts": [{"id": "x", "local_store_path": "z"}]}'
            )
        self.assertEqual(str(ctx.exception), "Missing 'secret_key' in account #1")

    def test_account_missing_local_store_path(self):
        """Should raise error when account is missing local_store_path field"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {"qonto": "' + "a" * 64 + '"}, "accounts": [{"id": "x", "secret_key": "y"}]}')
        self.assertEqual(str(ctx.exception), "Missing 'local_store_path' in account #1")

    def test_multiple_accounts_not_supported(self):
        """Should raise error when multiple accounts are configured"""
        cert = "a" * 64
        config_str = (
            f'{{"certificates": {{"qonto": "{cert}"}}, '
            '"accounts": ['
            '{"id": "x", "secret_key": "y", "local_store_path": "z"}, '
            '{"id": "x2", "secret_key": "y2", "local_store_path": "z2"}'
            "]}"
        )
        with self.assertRaises(BankException) as ctx:
            Config(config_str)
        self.assertEqual(str(ctx.exception), "Only single account supported, found 2 in config")


if __name__ == "__main__":
    unittest_main()
