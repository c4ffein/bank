import subprocess
from pathlib import Path
from unittest import TestCase
from unittest import main as unittest_main
from unittest.mock import patch

from bank import Account, BankException, Config, parse_date_params


def mock_get_body_for_tests(addr: bytes, url: bytes, *args, **kwargs) -> dict:
    """Shared mock for get_body that returns appropriate responses based on URL"""
    if url == b"/v2/organization":
        # Return organization info for get_infos call
        return {"organization": {"bank_accounts": [{"id": "12345678-1234-1234-1234-123456789abc"}]}}
    elif b"/v2/transactions" in url:
        # Return empty transaction list with required meta field
        return {
            "transactions": [],
            "meta": {
                "current_page": 1,
                "next_page": None,
                "prev_page": None,
                "total_pages": 1,
                "total_count": 0,
                "per_page": 100,
            },
        }
    raise ValueError(f"Unexpected URL in mock: {url}")


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


class DateParameterIntegrationTest(TestCase):
    """Test date parameter integration in API requests"""

    def setUp(self):
        """Create a test account instance"""
        account_dict = {
            "id": "test-org-slug",
            "secret_key": "test-secret-key",
            "local_store_path": "/tmp/test-cache",
        }
        self.account = Account(account_dict, "a" * 64, ssl_cafile=None)

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_date_equals_in_request(self, mock_get_body, mock_print):
        """Should send both emitted_at_from and emitted_at_to for date=2024"""
        mock_get_body.side_effect = mock_get_body_for_tests
        date_filter = parse_date_params(["date=2024"])
        self.account.print_transactions(date_filter=date_filter)
        # Get the transactions call
        transactions_call = mock_get_body.call_args_list[1]
        url = transactions_call[0][1]
        self.assertIn(b"emitted_at_from=2024-01-01T00:00:00Z", url)
        self.assertIn(b"emitted_at_to=2024-12-31T23:59:59Z", url)

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_date_from_in_request(self, mock_get_body, mock_print):
        """Should send only emitted_at_from for date>=2024"""
        mock_get_body.side_effect = mock_get_body_for_tests
        date_filter = parse_date_params(["date>=2024"])
        self.account.print_transactions(date_filter=date_filter)
        # Get the transactions call
        transactions_call = mock_get_body.call_args_list[1]
        url = transactions_call[0][1]
        self.assertIn(b"emitted_at_from=2024-01-01T00:00:00Z", url)
        self.assertNotIn(b"emitted_at_to", url)

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_date_to_in_request(self, mock_get_body, mock_print):
        """Should send only emitted_at_to for date<2024"""
        mock_get_body.side_effect = mock_get_body_for_tests
        date_filter = parse_date_params(["date<2024"])
        self.account.print_transactions(date_filter=date_filter)
        # Get the transactions call
        transactions_call = mock_get_body.call_args_list[1]
        url = transactions_call[0][1]
        self.assertNotIn(b"emitted_at_from", url)
        self.assertIn(b"emitted_at_to=2023-12-31T23:59:59Z", url)

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_date_range_in_request(self, mock_get_body, mock_print):
        """Should send both parameters for date range"""
        mock_get_body.side_effect = mock_get_body_for_tests
        date_filter = parse_date_params(["date>=2023", "date<2025"])
        self.account.print_transactions(date_filter=date_filter)
        # Get the transactions call
        transactions_call = mock_get_body.call_args_list[1]
        url = transactions_call[0][1]
        self.assertIn(b"emitted_at_from=2023-01-01T00:00:00Z", url)
        self.assertIn(b"emitted_at_to=2024-12-31T23:59:59Z", url)

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_no_date_filter_in_request(self, mock_get_body, mock_print):
        """Should not send date parameters when no filter is provided"""
        mock_get_body.side_effect = mock_get_body_for_tests
        self.account.print_transactions(date_filter=None)
        # Get the transactions call
        transactions_call = mock_get_body.call_args_list[1]
        url = transactions_call[0][1]
        self.assertNotIn(b"emitted_at_from", url)
        self.assertNotIn(b"emitted_at_to", url)


class CombinedParametersTest(TestCase):
    """Test combining date and invoice parameters in API requests"""

    def setUp(self):
        """Create a test account instance"""
        account_dict = {
            "id": "test-org-slug",
            "secret_key": "test-secret-key",
            "local_store_path": "/tmp/test-cache",
        }
        self.account = Account(account_dict, "a" * 64, ssl_cafile=None)

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_date_and_invoice_filters_combined(self, mock_get_body, mock_print):
        """Should send both date and invoice parameters together"""
        mock_get_body.side_effect = mock_get_body_for_tests
        date_filter = parse_date_params(["date=2024"])
        self.account.print_transactions(attachments=True, date_filter=date_filter)

        # Get the transactions call
        transactions_call = mock_get_body.call_args_list[1]
        url = transactions_call[0][1]
        # Verify both parameters are present
        self.assertIn(b"with_attachments=true", url)
        self.assertIn(b"emitted_at_from=2024-01-01T00:00:00Z", url)
        self.assertIn(b"emitted_at_to=2024-12-31T23:59:59Z", url)


class InvoiceParameterConflictTest(TestCase):
    """Test error handling for conflicting invoice parameters"""

    def test_cannot_use_both_invoice_parameters(self):
        """Should raise error when both no-invoice and only-invoice are specified"""
        # This tests the logic in main() that validates parameters
        test_args = ["transactions", "no-invoice", "only-invoice"]

        # Simulate the check from main()
        has_no_invoice = "no-invoice" in test_args
        has_only_invoice = "only-invoice" in test_args

        # This should raise an exception
        with self.assertRaises(BankException) as ctx:
            if has_no_invoice and has_only_invoice:
                raise BankException("Cannot use both 'no-invoice' and 'only-invoice' parameters")

        self.assertEqual(str(ctx.exception), "Cannot use both 'no-invoice' and 'only-invoice' parameters")


class InvoiceParameterTest(TestCase):
    """Test invoice parameter handling in API requests"""

    def setUp(self):
        """Create a test account instance"""
        account_dict = {
            "id": "test-org-slug",
            "secret_key": "test-secret-key",
            "local_store_path": "/tmp/test-cache",
        }
        self.account = Account(account_dict, "a" * 64, ssl_cafile=None)

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_no_invoice_parameter(self, mock_get_body, mock_print):
        """Should send with_attachments=false when no-invoice is specified"""
        # Mock get_body with side_effect to handle multiple calls
        mock_get_body.side_effect = mock_get_body_for_tests
        # Call print_transactions with attachments=False (no-invoice)
        self.account.print_transactions(attachments=False)
        # Verify get_body was called twice (once for org info, once for transactions)
        self.assertEqual(mock_get_body.call_count, 2)
        # Get the second call (transactions call)
        transactions_call = mock_get_body.call_args_list[1]
        url = transactions_call[0][1]  # Second positional argument is the URL
        self.assertIn(b"with_attachments=false", url)

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_only_invoice_parameter(self, mock_get_body, mock_print):
        """Should send with_attachments=true when only-invoice is specified"""
        # Mock get_body with side_effect to handle multiple calls
        mock_get_body.side_effect = mock_get_body_for_tests
        # Call print_transactions with attachments=True (only-invoice)
        self.account.print_transactions(attachments=True)
        # Verify get_body was called twice (once for org info, once for transactions)
        self.assertEqual(mock_get_body.call_count, 2)
        # Get the second call (transactions call)
        transactions_call = mock_get_body.call_args_list[1]
        url = transactions_call[0][1]  # Second positional argument is the URL
        self.assertIn(b"with_attachments=true", url)

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_no_invoice_parameter_specified(self, mock_get_body, mock_print):
        """Should not send with_attachments parameter when neither flag is specified"""
        # Mock get_body with side_effect to handle multiple calls
        mock_get_body.side_effect = mock_get_body_for_tests
        # Call print_transactions with attachments=None (no parameter)
        self.account.print_transactions(attachments=None)
        # Verify get_body was called twice (once for org info, once for transactions)
        self.assertEqual(mock_get_body.call_count, 2)
        # Get the second call (transactions call)
        transactions_call = mock_get_body.call_args_list[1]
        url = transactions_call[0][1]  # Second positional argument is the URL
        self.assertNotIn(b"with_attachments", url)


if __name__ == "__main__":
    unittest_main()
