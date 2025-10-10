import subprocess
from pathlib import Path
from unittest import TestCase
from unittest import main as unittest_main

from bank import BankException, Config, parse_date_params


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


class DateParsingTest(TestCase):
    """Test date parameter parsing"""

    def test_date_equals(self):
        """Should parse date=2024 to full year range"""
        result = parse_date_params(["date=2024"])
        self.assertEqual(result.emitted_at_from, "2024-01-01T00:00:00Z")
        self.assertEqual(result.emitted_at_to, "2024-12-31T23:59:59Z")

    def test_date_greater_than_or_equal(self):
        """Should parse date>=2024 to start from 2024"""
        result = parse_date_params(["date>=2024"])
        self.assertEqual(result.emitted_at_from, "2024-01-01T00:00:00Z")
        self.assertIsNone(result.emitted_at_to)

    def test_date_greater_than(self):
        """Should parse date>2024 to start from 2025"""
        result = parse_date_params(["date>2024"])
        self.assertEqual(result.emitted_at_from, "2025-01-01T00:00:00Z")
        self.assertIsNone(result.emitted_at_to)

    def test_date_less_than_or_equal(self):
        """Should parse date<=2024 to end at 2024"""
        result = parse_date_params(["date<=2024"])
        self.assertIsNone(result.emitted_at_from)
        self.assertEqual(result.emitted_at_to, "2024-12-31T23:59:59Z")

    def test_date_less_than(self):
        """Should parse date<2024 to end at 2023"""
        result = parse_date_params(["date<2024"])
        self.assertIsNone(result.emitted_at_from)
        self.assertEqual(result.emitted_at_to, "2023-12-31T23:59:59Z")

    def test_date_range(self):
        """Should parse date range with >= and <"""
        result = parse_date_params(["date>=2023", "date<2025"])
        self.assertEqual(result.emitted_at_from, "2023-01-01T00:00:00Z")
        self.assertEqual(result.emitted_at_to, "2024-12-31T23:59:59Z")

    def test_date_range_with_different_operators(self):
        """Should parse date range with > and <="""
        result = parse_date_params(["date>2022", "date<=2024"])
        self.assertEqual(result.emitted_at_from, "2023-01-01T00:00:00Z")
        self.assertEqual(result.emitted_at_to, "2024-12-31T23:59:59Z")

    def test_no_date_params(self):
        """Should return empty filter when no date params"""
        result = parse_date_params(["no-invoice", "other-param"])
        self.assertIsNone(result.emitted_at_from)
        self.assertIsNone(result.emitted_at_to)

    def test_invalid_year_format_not_digits(self):
        """Should raise error for non-digit year"""
        with self.assertRaises(BankException) as ctx:
            parse_date_params(["date=abcd"])
        self.assertEqual(str(ctx.exception), "Year must be 4 digits, got: abcd")

    def test_invalid_year_format_wrong_length(self):
        """Should raise error for wrong length year"""
        with self.assertRaises(BankException) as ctx:
            parse_date_params(["date=24"])
        self.assertEqual(str(ctx.exception), "Year must be 4 digits, got: 24")

    def test_too_many_date_params(self):
        """Should raise error for more than 2 date params"""
        with self.assertRaises(BankException) as ctx:
            parse_date_params(["date>=2023", "date<2025", "date=2024"])
        self.assertEqual(str(ctx.exception), "Maximum 2 date parameters allowed")

    def test_cannot_combine_equals_with_others(self):
        """Should raise error when combining date= with other operators"""
        with self.assertRaises(BankException) as ctx:
            parse_date_params(["date=2024", "date>=2023"])
        # date= sets both from and to, so date>= tries to set from again
        self.assertEqual(str(ctx.exception), "Cannot specify multiple 'from' date parameters")

    def test_multiple_from_dates(self):
        """Should raise error for multiple 'from' parameters"""
        with self.assertRaises(BankException) as ctx:
            parse_date_params(["date>=2023", "date>=2024"])
        self.assertEqual(str(ctx.exception), "Cannot specify multiple 'from' date parameters")

    def test_multiple_to_dates(self):
        """Should raise error for multiple 'to' parameters"""
        with self.assertRaises(BankException) as ctx:
            parse_date_params(["date<=2024", "date<2025"])
        self.assertEqual(str(ctx.exception), "Cannot specify multiple 'to' date parameters")

    def test_invalid_range(self):
        """Should raise error when from date is after to date"""
        with self.assertRaises(BankException) as ctx:
            parse_date_params(["date>=2025", "date<=2023"])
        self.assertEqual(str(ctx.exception), "Invalid date range: 'from' date must be before 'to' date")

    def test_invalid_parameter_format(self):
        """Should raise error for invalid parameter format"""
        with self.assertRaises(BankException) as ctx:
            parse_date_params(["date:2024"])
        self.assertEqual(str(ctx.exception), "Invalid date parameter format: date:2024")


if __name__ == "__main__":
    unittest_main()
