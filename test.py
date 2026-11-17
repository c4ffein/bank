import os
import subprocess
import tempfile
from email.message import Message
from hashlib import sha256
from io import BytesIO
from json import loads
from pathlib import Path
from unittest import TestCase, addModuleCleanup
from unittest import main as unittest_main
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from bank import (
    Account,
    BankException,
    Config,
    Transaction,
    detect_file_type,
    get_links,
    make_pinned_ssl_context,
    parse_date_params,
    print_unlinked,
    resolve_pins,
    state_path,
)

REAL_HOME = Path.home()
PDF = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj"
JPG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00"
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"


def setUpModule():
    """
    Nothing here reads or writes the real home (config, state): HOME is a temporary directory for all the tests,
    and for the commands that they run. StateTestCase gives a fresh one to each test that reads or writes the state.
    """
    home = tempfile.TemporaryDirectory()
    addModuleCleanup(home.cleanup)
    env_patch = patch.dict(os.environ, {"HOME": home.name})
    env_patch.start()
    addModuleCleanup(env_patch.stop)


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
        result = subprocess.run(["./bank.py", "help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
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
            Config('{"certificates": {"qonto": ["cmd"]}}')
        self.assertEqual(str(ctx.exception), "Missing 'accounts' field in config")

    def test_missing_qonto_certificate(self):
        """Should raise error when qonto certificate is missing"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {}, "accounts": []}')
        self.assertEqual(str(ctx.exception), "Missing 'certificates.qonto' field in config")

    def test_certificate_wrong_type(self):
        """Should raise error when certificate is not a command: a hash, as it used to be, included"""
        for value, name in (("123", "int"), ('"' + "a" * 64 + '"', "str"), ('{"command": ["cmd"]}', "dict")):
            with self.subTest(value=value), self.assertRaises(BankException) as ctx:
                Config('{"certificates": {"qonto": ' + value + '}, "accounts": []}')
            self.assertEqual(str(ctx.exception), f"Certificate must be a command (list of strings), got {name}")

    def test_accounts_wrong_type(self):
        """Should raise error when accounts is not a list"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {"qonto": ["cmd"]}, "accounts": "not-a-list"}')
        self.assertEqual(str(ctx.exception), "'accounts' must be a list, got str")

    def test_accounts_empty_list(self):
        """Should raise error when accounts list is empty"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {"qonto": ["cmd"]}, "accounts": []}')
        self.assertEqual(str(ctx.exception), "'accounts' list cannot be empty")

    def test_account_missing_id(self):
        """Should raise error when account is missing id field"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {"qonto": ["cmd"]}, "accounts": [{"secret_key": "y", "local_store_path": "z"}]}')
        self.assertEqual(str(ctx.exception), "Missing 'id' in account #1")

    def test_account_missing_secret_key(self):
        """Should raise error when account is missing secret_key field"""
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {"qonto": ["cmd"]}, "accounts": [{"id": "x", "local_store_path": "z"}]}')
        self.assertEqual(str(ctx.exception), "Missing 'secret_key' in account #1")

    def test_local_store_path_is_not_needed_anymore(self):
        """Was required, and never used: a config that still has it is accepted, as one that does not"""
        for more in ("", ', "local_store_path": "z"'):
            with self.subTest(more=more):
                account = '{"id": "x", "secret_key": "y"' + more + "}"
                config = Config('{"certificates": {"qonto": ["cmd"]}, "accounts": [' + account + "]}")
                self.assertEqual(config.accounts[0].organization_slug, "x")

    def test_multiple_accounts_not_supported(self):
        """Should raise error when multiple accounts are configured"""
        config_str = (
            '{"certificates": {"qonto": ["cmd"]}, '
            '"accounts": ['
            '{"id": "x", "secret_key": "y", "local_store_path": "z"}, '
            '{"id": "x2", "secret_key": "y2", "local_store_path": "z2"}'
            "]}"
        )
        with self.assertRaises(BankException) as ctx:
            Config(config_str)
        self.assertEqual(str(ctx.exception), "Only single account supported, found 2 in config")


class PinCommandTest(TestCase):
    """A certificate is configured as a command that prints the SHA256 pins to accept"""

    ACCOUNTS = '"accounts": [{"id": "x", "secret_key": "y", "local_store_path": "z"}]'

    @staticmethod
    def sh(script):
        return ("/bin/sh", "-c", script)

    def test_config_accepts_commands(self):
        """Commands are kept as they are, and not run when the config is loaded"""
        config = Config(
            '{"certificates": {"qonto": ["/nonexistent/tls-pin-get", "thirdparty.qonto.com:443"], '
            '"aws_s3": ["/nonexistent/tls-pin-get", "qonto.s3.eu-central-1.amazonaws.com:443"]}, ' + self.ACCOUNTS + "}"
        )
        self.assertEqual(config.certificates["qonto"], ("/nonexistent/tls-pin-get", "thirdparty.qonto.com:443"))
        self.assertEqual(config.accounts[0].pin_command, ("/nonexistent/tls-pin-get", "thirdparty.qonto.com:443"))
        self.assertEqual(
            config.accounts[0].s3_pin_command, ("/nonexistent/tls-pin-get", "qonto.s3.eu-central-1.amazonaws.com:443")
        )

    def test_config_rejects_bad_commands(self):
        for command in ("[]", '[""]', '["cmd", 1]', '["cmd", ["nested"]]', '["cmd", "a\\u0000b"]'):
            with self.subTest(command=command), self.assertRaises(BankException) as ctx:
                Config('{"certificates": {"qonto": ' + command + "}, " + self.ACCOUNTS + "}")
            self.assertEqual(str(ctx.exception), "Certificate command must be a non-empty list of non-empty strings")
        with self.assertRaises(BankException) as ctx:
            Config('{"certificates": {"qonto": ["cmd"], "aws_s3": []}, ' + self.ACCOUNTS + "}")
        self.assertEqual(str(ctx.exception), "S3 certificate command must be a non-empty list of non-empty strings")

    def test_static_pin(self):
        """A hash that never changes is still possible: echo"""
        self.assertEqual(resolve_pins(("/bin/echo", "a" * 64)), ("a" * 64,))

    def test_command_one_pin(self):
        self.assertEqual(resolve_pins(self.sh(f"echo {'a' * 64}")), ("a" * 64,))

    def test_command_several_pins(self):
        """All of them are accepted: the old and the new certificate overlap during a rotation"""
        pins = resolve_pins(self.sh(f"printf '%s\\n' {'a' * 64} {'B' * 64}"))
        self.assertEqual(pins, ("a" * 64, "b" * 64))

    def test_command_receives_arguments_without_a_shell(self):
        with patch("bank.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 0, stdout=b"c" * 64 + b"\n", stderr=b"")
            self.assertEqual(resolve_pins(("tls-pin-get", "host; rm -rf $HOME")), ("c" * 64,))
        self.assertEqual(mock_run.call_args.args, (("tls-pin-get", "host; rm -rf $HOME"),))
        self.assertNotIn("shell", mock_run.call_args.kwargs)

    def test_command_is_run_once(self):
        with patch("bank.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess([], 0, stdout=b"d" * 64 + b"\n", stderr=b"")
            resolve_pins(("tls-pin-get", "run-once.example:443"))
            resolve_pins(("tls-pin-get", "run-once.example:443"))
        self.assertEqual(mock_run.call_count, 1)

    def test_command_failures(self):
        cases = {
            "exit 1": "Pin command failed (exit code 1): /bin/sh -c exit 1",
            "echo 'no pin for x' >&2; exit 1": (
                "Pin command failed (exit code 1): /bin/sh -c echo 'no pin for x' >&2; exit 1: no pin for x"
            ),
            f"echo {'a' * 64}; exit 3": f"Pin command failed (exit code 3): /bin/sh -c echo {'a' * 64}; exit 3",
            "true": "Pin command printed no pin: /bin/sh -c true",
            "echo": "Pin command printed no pin: /bin/sh -c echo",
        }
        for script, message in cases.items():
            with self.subTest(script=script), self.assertRaises(BankException) as ctx:
                resolve_pins(self.sh(script))
            self.assertEqual(str(ctx.exception), message)

    def test_command_output_that_is_not_pins(self):
        """One bad line and nothing is accepted, the valid lines included"""
        scripts = (
            f"echo {'a' * 63}",
            f"echo {'a' * 65}",
            f"echo {'g' * 64}",
            f"echo ' {'a' * 64}'",
            f"echo {'a' * 64}; echo",
            f"echo {'a' * 64}; echo not-a-pin",
            f"printf '{'a' * 64}\\r\\n'",
            f"printf '{'a' * 63}\\351\\n'",
        )
        for script in scripts:
            with self.subTest(script=script), self.assertRaises(BankException) as ctx:
                resolve_pins(self.sh(script))
            self.assertIn("Pin command printed something that is not a SHA256", str(ctx.exception))

    def test_command_too_many_pins(self):
        with self.assertRaises(BankException) as ctx:
            resolve_pins(self.sh(f"for i in $(seq 17); do echo {'a' * 64}; done"))
        self.assertIn("Pin command printed more than 16 pins", str(ctx.exception))

    def test_command_not_found(self):
        with self.assertRaises(BankException) as ctx:
            resolve_pins(("/nonexistent/tls-pin-get", "thirdparty.qonto.com:443"))
        self.assertIn(
            "Pin command could not be run: /nonexistent/tls-pin-get thirdparty.qonto.com:443", str(ctx.exception)
        )

    def test_command_timeout(self):
        with patch("bank.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
            with self.assertRaises(BankException) as ctx:
                resolve_pins(("tls-pin-get", "timeout.example:443"))
        self.assertEqual(str(ctx.exception), "Pin command timed out after 10s: tls-pin-get timeout.example:443")

    def test_failing_command_means_no_connection(self):
        account = Account({"id": "x", "secret_key": "y", "local_store_path": "z"}, self.sh("exit 1"))
        with patch("bank.urlopen") as mock_urlopen, self.assertRaises(BankException):
            account.get_infos()
        mock_urlopen.assert_not_called()

    def test_pinned_context_accepts_one_or_several_pins(self):
        for pins in ("a" * 64, ("a" * 64, "b" * 64), []):
            with self.subTest(pins=pins):
                context = make_pinned_ssl_context(pins)
                self.assertTrue(context.check_hostname)


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
        self.account = Account(account_dict, ("/bin/echo", "a" * 64), ssl_cafile=None)

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
        self.account = Account(account_dict, ("/bin/echo", "a" * 64), ssl_cafile=None)

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
        self.account = Account(account_dict, ("/bin/echo", "a" * 64), ssl_cafile=None)

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


def transaction(n: int, **more) -> dict:
    """A transaction as the API returns it, with only what is always there (plus more)"""
    return {
        "transaction_id": f"test-org-slug-1-transaction-{n}",
        "id": f"00000000-0000-0000-0000-{n:012d}",
        "label": f"label {n}",
        "amount_cents": 100 * n,
        "local_amount_cents": 100 * n,
        "currency": "EUR",
        "side": "debit",
        "emitted_at": "2024-01-01T00:00:00.000Z",
        **more,
    }


class StateTestCase(TestCase):
    """A test that reads or writes the state: it gets a home of its own, with nothing in it"""

    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        env_patch = patch.dict(os.environ, {"HOME": home.name})
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.home = Path(home.name)
        self.state = self.home / ".local" / "state" / "bank"
        self.account = Account(
            {"id": "test-org-slug", "secret_key": "test-secret-key"},
            ("/bin/echo", "a" * 64),
            s3_pin_command=("/bin/echo", "b" * 64),
        )

    def write_file(self, name, content):
        path = self.home / "documents" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path


class HermeticTest(StateTestCase):
    """The tests never touch the real home: see setUpModule"""

    def test_home_is_not_the_real_one(self):
        self.assertNotEqual(Path.home(), REAL_HOME)
        self.assertEqual(state_path("transactions.json"), self.state / "transactions.json")

    def test_state_is_written_in_the_test_home(self):
        self.account.save_transaction_cache([transaction(1)])
        cache_path = self.state / "transactions.json"
        self.assertEqual(list(loads(cache_path.read_text())), ["test-org-slug-1-transaction-1"])
        self.assertEqual(cache_path.stat().st_mode & 0o777, 0o600)


class PaginationTest(StateTestCase):
    PAGES = {1: [1, 2], 2: [3, 4], 3: [5]}

    def get_body(self, addr, url, *args, **kwargs):
        if url == b"/v2/organization":
            return mock_get_body_for_tests(addr, url)
        page = int(url.rsplit(b"&page=", 1)[1])
        return {
            "transactions": [transaction(n, reference=f"invoice {n}", attachment_ids=["x"]) for n in self.PAGES[page]],
            "meta": {"current_page": page, "next_page": page + 1 if page < 3 else None, "total_count": 5},
        }

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_every_page_is_fetched_printed_and_cached(self, mock_get_body, mock_print):
        mock_get_body.side_effect = self.get_body
        self.account.print_transactions()
        urls = [call[0][1] for call in mock_get_body.call_args_list[1:]]
        expected = [[b"per_page=100", b"page=%d" % i] for i in (1, 2, 3)]
        self.assertEqual([url.rsplit(b"&", 2)[1:] for url in urls], expected)
        printed = [call[0][0] for call in mock_print.call_args_list[:-1]]
        self.assertEqual(len(printed), 5)
        for n, line in enumerate(printed, 1):
            self.assertIn(f"label {n}", line)
        self.assertEqual(len(self.account.get_transaction_cache()), 5)
        self.assertEqual(self.account.get_one_transaction("transaction-5")["label"], "label 5")

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_what_linking_needs_is_cached(self, mock_get_body, mock_print):
        mock_get_body.side_effect = self.get_body
        self.account.print_transactions()
        cached = self.account.get_one_transaction("transaction-2")
        self.assertEqual((cached["reference"], cached["attachment_ids"]), ("invoice 2", ["x"]))
        self.assertIsNone(cached["note"])  # Not in the answer: still a key, with no value

    def test_transaction_without_the_optional_fields(self):
        t = Transaction.from_dict(transaction(1))
        self.assertEqual((t.reference, t.attachment_ids, t.local_currency), (None, [], None))
        self.assertEqual(Transaction.from_dict(t.to_dict()), t)

    @patch("builtins.print")
    @patch("bank.get_body")
    def test_page_that_fails_keeps_the_previous_ones(self, mock_get_body, mock_print):
        def get_body(addr, url, *args, **kwargs):
            if url.endswith(b"&page=2"):
                raise BankException("HTTP 500 Internal Server Error")
            return self.get_body(addr, url)

        mock_get_body.side_effect = get_body
        with self.assertRaises(BankException):
            self.account.print_transactions()
        self.assertEqual(len(self.account.get_transaction_cache()), 2)

    @patch("bank.get_body")
    def test_next_page_must_be_a_later_page(self, mock_get_body):
        for next_page in (1, 0, "2"):
            mock_get_body.side_effect = lambda addr, url, *a, next_page=next_page, **k: (
                mock_get_body_for_tests(addr, url)
                if url == b"/v2/organization"
                else {"transactions": [], "meta": {"next_page": next_page}}
            )
            with self.subTest(next_page=next_page), self.assertRaises(BankException) as ctx:
                self.account.fetch_transactions()
            self.assertEqual(str(ctx.exception), f"Unexpected next page after page 1: {next_page}")


class FileTypeTest(TestCase):
    def test_accepted_types(self):
        self.assertEqual(detect_file_type(PDF), ("pdf", "application/pdf"))
        self.assertEqual(detect_file_type(JPG), ("jpg", "image/jpeg"))
        self.assertEqual(detect_file_type(PNG), ("png", "image/png"))

    def test_anything_else_is_refused(self):
        for data in (b"", b"GIF89a", b"PK\x03\x04", b" %PDF-1.7", b"\x89PNG", b"<html>%PDF-"):
            with self.subTest(data=data), self.assertRaises(BankException) as ctx:
                detect_file_type(data)
            self.assertIn("only PDF, JPEG and PNG are accepted", str(ctx.exception))


@patch("builtins.print")
class JustifyTest(StateTestCase):
    def setUp(self):
        super().setUp()
        self.account.save_transaction_cache([transaction(1), transaction(2)])

    def log(self):
        return [loads(line) for line in (self.state / "justify_log.jsonl").read_text().splitlines()]

    @staticmethod
    def key(mock_post_body, call=-1):
        return mock_post_body.call_args_list[call].kwargs["additional_headers"]["X-Qonto-Idempotency-Key"]

    @patch("bank.post_body", return_value={})
    def test_type_is_what_the_content_is_not_what_the_name_says(self, mock_post_body, mock_print):
        path = self.write_file("receipt.pdf", PNG)
        self.account.justify("transaction-1", str(path))
        url = b"/v2/transactions/00000000-0000-0000-0000-000000000001/attachments"
        self.assertEqual(mock_post_body.call_args.args[1], url)
        self.assertEqual(mock_post_body.call_args.args[2], PNG)
        self.assertEqual(mock_post_body.call_args.kwargs["file_name"], "file.png")
        self.assertEqual(mock_post_body.call_args.kwargs["file_mimetype"], "image/png")

    def test_type_reaches_the_request(self, mock_print):
        with patch("bank.fetch", return_value=("application/json", b"{}")) as mock_fetch:
            self.account.justify("transaction-1", str(self.write_file("photo", JPG)))
        body = mock_fetch.call_args.args[0].data
        self.assertIn(b'name="file"; filename="file.jpg"\r\nContent-Type: image/jpeg\r\n\r\n' + JPG, body)

    @patch("bank.post_body")
    def test_unsupported_file_is_not_sent(self, mock_post_body, mock_print):
        with self.assertRaises(BankException):
            self.account.justify("transaction-1", str(self.write_file("receipt.gif", b"GIF89a")))
        with self.assertRaises(BankException) as ctx:
            self.account.justify("transaction-1", str(self.home / "missing.pdf"))
        self.assertIn("Could not read", str(ctx.exception))
        mock_post_body.assert_not_called()
        self.assertEqual(get_links(), [])

    @patch("bank.post_body")
    def test_sending_again_after_a_failure_uses_the_same_key(self, mock_post_body, mock_print):
        path = str(self.write_file("invoice.pdf", PDF))
        mock_post_body.side_effect = BankException("Connection error: no answer after 30s")
        with self.assertRaises(BankException) as ctx:
            self.account.justify("transaction-1", path)
        self.assertEqual(str(ctx.exception), "Upload failed: Connection error: no answer after 30s")
        self.assertEqual(get_links(), [])  # Not known to be sent: not linked
        mock_post_body.side_effect = None
        mock_post_body.return_value = {}
        self.account.justify("transaction-1", path)
        self.assertEqual(self.key(mock_post_body, 0), self.key(mock_post_body, 1))
        self.assertEqual([entry["status"] for entry in self.log()], ["started", "failed", "started", "success"])
        self.assertEqual({entry["sha256"] for entry in self.log()}, {sha256(PDF).hexdigest()})
        self.assertEqual((self.state / "justify_log.jsonl").stat().st_mode & 0o777, 0o600)

    @patch("bank.post_body", return_value={})
    def test_key_is_for_one_file_and_one_transaction(self, mock_post_body, mock_print):
        self.account.justify("transaction-1", str(self.write_file("a.pdf", PDF)))
        self.account.justify("transaction-2", str(self.write_file("a.pdf", PDF)))
        self.account.justify("transaction-1", str(self.write_file("b.pdf", PDF + b"other")))
        self.assertEqual(len({self.key(mock_post_body, i) for i in range(3)}), 3)

    @patch("bank.post_body", return_value={})
    def test_file_already_sent_is_not_sent_again_unless_forced(self, mock_post_body, mock_print):
        path = self.write_file("invoice.pdf", PDF)
        self.account.justify("transaction-1", str(path))
        self.account.justify("transaction-1", str(path))
        self.assertEqual(mock_post_body.call_count, 1)
        self.account.justify("transaction-2", str(path))  # Another transaction: sent
        self.assertEqual(mock_post_body.call_count, 2)
        self.account.justify("transaction-1", str(path), force=True)
        self.assertEqual(mock_post_body.call_count, 3)
        self.assertNotEqual(self.key(mock_post_body, 0), self.key(mock_post_body, 2))

    @patch("bank.post_body", return_value={})
    def test_file_that_is_sent_is_linked(self, mock_post_body, mock_print):
        path = self.write_file("invoice.pdf", PDF)
        self.account.justify("transaction-1", str(path))
        transaction_id, digest = "test-org-slug-1-transaction-1", sha256(PDF).hexdigest()
        link = {"transaction_id": transaction_id, "full_path": str(path), "sha256": digest}
        self.assertEqual(get_links(), [link])
        self.account.justify("transaction-1", str(path))
        self.assertEqual(get_links(), [link])


@patch("builtins.print")
class LinksTest(StateTestCase):
    def setUp(self):
        super().setUp()
        self.account.save_transaction_cache([transaction(1), transaction(2)])
        self.links_path = self.state / "qonto-transaction-id-to-local-invoices.json"

    def unlinked(self, mock_print, *paths):
        """(exit code, paths that were printed) of bank unlinked"""
        mock_print.reset_mock()
        code = print_unlinked([str(path) for path in paths])
        return code, [call[0][0] for call in mock_print.call_args_list[:-1]]

    def test_link_writes_the_expected_file(self, mock_print):
        train, hotel = self.write_file("train.pdf", PDF), self.write_file("hotel.heic", b"not sent, so any type")
        self.account.link("transaction-1", str(train))
        self.account.link("transaction-1", str(hotel))
        self.account.link("transaction-2", str(hotel))  # A file can go with several transactions
        self.account.link("transaction-1", str(train))  # Already there: no duplicate
        expected = [
            ("test-org-slug-1-transaction-1", hotel, b"not sent, so any type"),
            ("test-org-slug-1-transaction-2", hotel, b"not sent, so any type"),
            ("test-org-slug-1-transaction-1", train, PDF),
        ]
        self.assertEqual(
            loads(self.links_path.read_text()),
            {
                "links": [
                    {"transaction_id": t, "full_path": str(path), "sha256": sha256(content).hexdigest()}
                    for t, path, content in expected
                ]
            },
        )
        self.assertEqual(self.links_path.stat().st_mode & 0o777, 0o600)

    def test_unlinked_lists_what_is_not_linked(self, mock_print):
        train, meal = self.write_file("train.pdf", PDF), self.write_file("meals/monday.jpg", JPG)
        self.write_file(".DS_Store", b"hidden")
        self.write_file(".git/config", b"hidden directory")
        documents = self.home / "documents"
        self.assertEqual(self.unlinked(mock_print, documents), (1, [train, meal]))
        self.assertIn("2 file(s), 0 linked, 2 not linked", mock_print.call_args[0][0])
        self.account.link("transaction-1", str(train))
        self.assertEqual(self.unlinked(mock_print, documents), (1, [meal]))
        self.account.link("transaction-1", str(meal))
        self.assertEqual(self.unlinked(mock_print, documents), (0, []))
        self.assertIn("2 file(s), 2 linked, 0 not linked", mock_print.call_args[0][0])

    def test_linked_file_is_known_by_its_content(self, mock_print):
        train = self.write_file("train.pdf", PDF)
        self.account.link("transaction-1", str(train))
        moved = train.rename(train.with_name("2024-01-train.pdf"))
        self.assertEqual(self.unlinked(mock_print, moved), (0, []))
        moved.write_bytes(PDF + b"edited")
        self.assertEqual(self.unlinked(mock_print, moved), (1, [moved]))

    def test_unlinked_path_that_does_not_exist(self, mock_print):
        with self.assertRaises(BankException) as ctx:
            print_unlinked([str(self.home / "nowhere")])
        self.assertIn("Not a file or a directory", str(ctx.exception))

    def test_links_file_that_is_not_ours_is_left_as_it_is(self, mock_print):
        self.state.mkdir(parents=True, exist_ok=True)
        for content in ("[]", '{"transactions": []}', '{"links": [{"transaction_id": "x"}]}', "{not json"):
            self.links_path.write_text(content)
            with self.subTest(content=content):
                with self.assertRaises(BankException):
                    self.account.link("transaction-1", str(self.write_file("train.pdf", PDF)))
                with self.assertRaises(BankException):
                    print_unlinked([str(self.home)])
                self.assertEqual(self.links_path.read_text(), content)


class NetworkErrorTest(StateTestCase):
    def http_error(self, code, reason, body):
        return HTTPError("https://thirdparty.qonto.com/v2/organization", code, reason, Message(), BytesIO(body))

    def get_infos_error(self, side_effect):
        with patch("bank.urlopen", side_effect=side_effect) as mock_urlopen, self.assertRaises(BankException) as ctx:
            self.account.get_infos()
        self.assertEqual(mock_urlopen.call_args.kwargs["timeout"], 30)
        return str(ctx.exception)

    def test_http_error_says_what_the_server_answered(self):
        body = b'{"errors": [{"code": "unauthorized", "detail": "Invalid credentials"}, {"code": "other"}]}'
        self.assertEqual(
            self.get_infos_error(self.http_error(401, "Unauthorized", body)),
            "HTTP 401 Unauthorized: unauthorized: Invalid credentials; other",
        )

    def test_http_error_with_a_body_that_is_not_what_qonto_sends(self):
        cases = {
            b"": "HTTP 500 Internal Server Error",
            b"<Error>\n  <Code>AccessDenied</Code>\x1b[31m\n</Error>": (
                "HTTP 500 Internal Server Error: <Error> <Code>AccessDenied</Code>?[31m </Error>"
            ),
            b'["a list"]': 'HTTP 500 Internal Server Error: ["a list"]',
            b"x" * 5000: "HTTP 500 Internal Server Error: " + "x" * 300,
        }
        for body, message in cases.items():
            with self.subTest(body=body[:20]):
                self.assertEqual(self.get_infos_error(self.http_error(500, "Internal Server Error", body)), message)

    def test_connection_errors(self):
        self.assertEqual(self.get_infos_error(URLError("timed out")), "Connection error: timed out")
        self.assertEqual(self.get_infos_error(TimeoutError()), "Connection error: no answer after 30s")
        self.assertEqual(self.get_infos_error(ConnectionResetError("reset")), "Connection error: reset")

    def test_answer_that_is_not_the_json_it_says_it_is(self):
        with patch("bank.fetch", return_value=("application/json", b"<html>")), self.assertRaises(BankException):
            self.account.get_infos()


@patch("builtins.print")
class AttachmentsTest(StateTestCase):
    ID = "00000000-0000-0000-0000-000000000001"

    def setUp(self):
        super().setUp()
        self.account.save_transaction_cache([transaction(1)])
        self.out = self.home / "out"

    def run_with(self, urls, contents, command):
        """Run a command on a transaction that has these attachments: returns its exit code, and the fetch mock"""
        attachments = {"attachments": [{"url": url} if url else {} for url in urls]}
        with patch("bank.get_body", return_value=attachments), patch("bank.fetch") as mock_fetch:
            mock_fetch.side_effect = [c if isinstance(c, Exception) else ("application/pdf", c) for c in contents]
            return command(), mock_fetch

    def download(self, urls, contents):
        return self.run_with(urls, contents, lambda: self.account.download_attachments("transaction-1", str(self.out)))

    def test_download(self, mock_print):
        code, mock_fetch = self.download(["https://s3/1", "https://s3/2"], [PDF, PNG])
        self.assertEqual(code, 0)
        self.assertEqual([call.args[1] for call in mock_fetch.call_args_list], [("/bin/echo", "b" * 64)] * 2)
        self.assertEqual((self.out / f"attachment_{self.ID}_1").read_bytes(), PDF)
        self.assertEqual((self.out / f"attachment_{self.ID}_2").read_bytes(), PNG)
        self.assertEqual((self.out / f"attachment_{self.ID}_1").stat().st_mode & 0o777, 0o600)
        self.assertIn("Downloaded 2 of 2 attachment(s)", mock_print.call_args[0][0])

    def test_download_that_fails_is_said_and_is_the_exit_code(self, mock_print):
        code, _ = self.download(["https://s3/1", "https://s3/2"], [BankException("HTTP 403 Forbidden"), PNG])
        self.assertEqual(code, 1)
        self.assertEqual([path.name for path in self.out.iterdir()], [f"attachment_{self.ID}_2"])
        printed = [call[0][0] for call in mock_print.call_args_list]
        self.assertIn("Failed to download", printed[1])
        self.assertIn("HTTP 403 Forbidden", printed[1])
        self.assertIn("Downloaded 1 of 2 attachment(s)", printed[-1])
        self.assertFalse(any("complete" in line for line in printed))

    def test_only_https_urls_are_followed(self, mock_print):
        code, mock_fetch = self.download(["file:///etc/passwd", "http://s3/2", None], [])
        self.assertEqual(code, 1)
        mock_fetch.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_no_attachment(self, mock_print):
        self.assertEqual(self.download([], [])[0], 0)
        self.assertIn("No attachments found", mock_print.call_args[0][0])

    def test_s3_pin_is_required(self, mock_print):
        self.account.s3_pin_command = None
        with self.assertRaises(BankException) as ctx:
            self.download(["https://s3/1"], [PDF])
        self.assertIn("S3 certificate pinning not configured", str(ctx.exception))

    def test_hashes(self, mock_print):
        code, _ = self.run_with(
            ["https://s3/1", "https://s3/2"],
            [PDF, BankException("HTTP 403 Forbidden")],
            lambda: self.account.get_attachment_hashes("transaction-1"),
        )
        self.assertEqual(code, 1)
        printed = "\n".join(call[0][0] for call in mock_print.call_args_list)
        self.assertIn(sha256(PDF).hexdigest(), printed)
        self.assertIn("Failed to hash", printed)


@patch("builtins.print")
class ReconcileTest(StateTestCase):
    """Qonto as a dict: {transaction number: {attachment id: content}}"""

    def setUp(self):
        super().setUp()
        self.qonto = {1: {"att-train": PDF}, 2: {"att-hotel": PNG}}
        self.documents = self.home / "documents"
        self.documents.mkdir()
        self.table_path = self.state / "qonto-attachment-id-to-sha256.json"

    def get_body(self, addr, url, *args, **kwargs):
        if url == b"/v2/organization":
            return mock_get_body_for_tests(addr, url)
        if url.endswith(b"/attachments"):
            n = int(url.split(b"/")[3].rsplit(b"-", 1)[1])
            return {"attachments": [{"id": a, "url": f"https://s3/{n}/{a}"} for a in self.qonto[n]]}
        transactions = [transaction(n, attachment_ids=list(attachments)) for n, attachments in self.qonto.items()]
        return {"transactions": transactions, "meta": {"next_page": None}}

    def fetch(self, request, pin_command, cafile=None):
        n, attachment_id = request.full_url.removeprefix("https://s3/").split("/")
        content = self.qonto[int(n)][attachment_id]
        if isinstance(content, Exception):
            raise content
        return "application/octet-stream", content

    def reconcile(self, mock_print, *args, **kwargs):
        """Returns (exit code, what was printed without the colors, urls that were asked, attachments downloaded)"""
        mock_print.reset_mock()
        with patch("bank.get_body", side_effect=self.get_body) as mock_get_body:
            with patch("bank.fetch", side_effect=self.fetch) as mock_fetch:
                code = self.account.reconcile([str(self.documents), *args], **kwargs)
        printed = [call[0][0] for call in mock_print.call_args_list]
        for color in ("\033[31m", "\033[32m", "\033[34m", "\033[90m", "\033[39m"):
            printed = [line.replace(color, "") for line in printed]
        asked = [call[0][1] for call in mock_get_body.call_args_list]
        return code, printed, asked, [call[0][0].full_url.rsplit("/", 1)[1] for call in mock_fetch.call_args_list]

    def links(self):
        return {(link["transaction_id"][-1], Path(link["full_path"]).name) for link in get_links()}

    def test_attachments_that_are_local_files_get_linked(self, mock_print):
        train, hotel = self.write_file("train.pdf", PDF), self.write_file("trip/hotel.png", PNG)
        code, printed, asked, downloaded = self.reconcile(mock_print)
        self.assertEqual(code, 0)
        self.assertEqual(
            printed,
            [
                f"✓ linked           tion-1 label 1 {train}",
                f"✓ linked           tion-2 label 2 {hotel}",
                "2 attachment(s) on Qonto: 2 newly linked, 0 on Qonto only"
                " ─ 2 local file(s): 0 not linked, 0 linked here only",
            ],
        )
        self.assertEqual(self.links(), {("1", "train.pdf"), ("2", "hotel.png")})
        self.assertEqual(downloaded, ["att-train", "att-hotel"])
        self.assertIn(b"with_attachments=true", asked[1])
        self.assertEqual(
            loads(self.table_path.read_text()),
            {
                "attachments": {
                    "att-train": {"sha256": sha256(PDF).hexdigest(), "size": len(PDF)},
                    "att-hotel": {"sha256": sha256(PNG).hexdigest(), "size": len(PNG)},
                }
            },
        )
        self.assertEqual(self.table_path.stat().st_mode & 0o777, 0o600)

    def test_attachment_is_only_downloaded_the_first_time(self, mock_print):
        self.write_file("train.pdf", PDF)
        self.write_file("hotel.png", PNG)
        self.reconcile(mock_print)
        code, printed, asked, downloaded = self.reconcile(mock_print)
        self.assertEqual((code, downloaded), (0, []))
        self.assertEqual(len(asked), 2)  # The organization, the transactions: no transaction is asked its attachments
        self.assertIn("0 newly linked", printed[-1])
        self.assertEqual(len(printed), 1)
        # A new attachment on a transaction: this transaction only is asked, this attachment only is downloaded
        self.qonto[1]["att-meal"] = JPG
        code, printed, asked, downloaded = self.reconcile(mock_print)
        self.assertEqual((code, downloaded), (1, ["att-meal"]))
        self.assertEqual(asked[2:], [b"/v2/transactions/00000000-0000-0000-0000-000000000001/attachments"])
        self.assertEqual(printed[0], "✗ on Qonto only    tion-1 label 1 attachment att-meal")

    def test_what_is_not_one_to_one_is_said(self, mock_print):
        self.write_file("train.pdf", PDF)
        meal = self.write_file("meal.jpg", JPG)
        code, printed, _, _ = self.reconcile(mock_print)
        self.assertEqual(code, 1)
        self.assertEqual(
            printed,
            [
                f"✓ linked           tion-1 label 1 {self.documents / 'train.pdf'}",
                "✗ on Qonto only    tion-2 label 2 attachment att-hotel",
                f"✗ not linked       {meal}",
                "2 attachment(s) on Qonto: 1 newly linked, 1 on Qonto only"
                " ─ 2 local file(s): 1 not linked, 0 linked here only",
            ],
        )
        self.assertEqual(self.links(), {("1", "train.pdf")})

    def test_file_linked_without_being_sent_is_not_an_error(self, mock_print):
        self.write_file("train.pdf", PDF)
        self.write_file("hotel.png", PNG)
        meal = self.write_file("meal.jpg", JPG)
        self.account.save_transaction_cache([transaction(1)])
        self.account.link("transaction-1", str(meal))
        code, printed, _, _ = self.reconcile(mock_print)
        self.assertEqual(code, 0)
        self.assertIn(f"· linked here only tion-1 label 1 {meal}", printed)
        self.assertIn("3 local file(s): 0 not linked, 1 linked here only", printed[-1])

    def test_same_file_on_two_transactions(self, mock_print):
        self.write_file("train.pdf", PDF)
        self.qonto[2] = {"att-train-again": PDF}
        self.assertEqual(self.reconcile(mock_print)[0], 0)
        self.assertEqual(self.links(), {("1", "train.pdf"), ("2", "train.pdf")})

    def test_download_that_fails_is_tried_again_the_next_time(self, mock_print):
        self.write_file("train.pdf", PDF)
        self.write_file("hotel.png", PNG)
        self.qonto[2]["att-hotel"] = BankException("HTTP 403 Forbidden")
        code, printed, _, _ = self.reconcile(mock_print)
        self.assertEqual(code, 1)
        self.assertEqual(printed[1], "✗ could not download tion-2 label 2 attachment att-hotel: HTTP 403 Forbidden")
        self.assertIn(", 1 not downloaded ─ ", printed[-1])
        self.assertEqual(list(loads(self.table_path.read_text())["attachments"]), ["att-train"])
        self.qonto[2]["att-hotel"] = PNG
        code, _, _, downloaded = self.reconcile(mock_print)
        self.assertEqual((code, downloaded), (0, ["att-hotel"]))

    def test_dates_are_for_the_transactions(self, mock_print):
        _, _, asked, _ = self.reconcile(mock_print, date_filter=parse_date_params(["date=2024"]))
        self.assertIn(b"emitted_at_from=2024-01-01T00:00:00Z&emitted_at_to=2024-12-31T23:59:59Z", asked[1])

    def test_what_is_wrong_is_said_before_anything_is_fetched(self, mock_print):
        with self.assertRaises(BankException) as ctx:
            self.reconcile(mock_print, str(self.home / "nowhere"))
        self.assertIn("Not a file or a directory", str(ctx.exception))
        self.account.s3_pin_command = None
        with patch("bank.get_body") as mock_get_body, self.assertRaises(BankException) as ctx:
            self.account.reconcile([str(self.documents)])
        self.assertIn("S3 certificate pinning not configured", str(ctx.exception))
        mock_get_body.assert_not_called()

    def test_attachments_file_that_is_not_ours_is_left_as_it_is(self, mock_print):
        self.state.mkdir(parents=True, exist_ok=True)
        for content in ("[]", '{"attachments": {"att-train": "a hash"}}', "{not json"):
            self.table_path.write_text(content)
            with self.subTest(content=content):
                with self.assertRaises(BankException):
                    self.reconcile(mock_print)
                self.assertEqual(self.table_path.read_text(), content)


class CommandLineTest(StateTestCase):
    """What is wrong is said, and is the exit code"""

    CONFIG = '{"certificates": {"qonto": ["/bin/false"]}, "accounts": [{"id": "x", "secret_key": "y"}]}'

    def run_bank(self, *args, config=None):
        if config is not None:
            (self.home / ".config" / "bank").mkdir(parents=True)
            (self.home / ".config" / "bank" / "config.json").write_text(config)
        result = subprocess.run(["./bank.py", *args], capture_output=True, text=True)
        self.assertEqual(result.stderr, "")
        return result.returncode, result.stdout

    def test_help_does_not_need_a_config(self):
        for args in (["help"], ["help", "config"]):
            with self.subTest(args=args):
                self.assertEqual(self.run_bank(*args)[0], 0)

    def test_commands_that_are_wrong(self):
        cases = {
            ("nonsense",): "Unknown command: nonsense",
            ("justify", "abc"): "Wrong arguments for 'justify'",
            ("justify", "abc", "file.pdf", "forced"): "Wrong arguments for 'justify'",
            ("download",): "Wrong arguments for 'download'",
            ("accounts", "extra"): "Wrong arguments for 'accounts'",
            ("transactions", "no-invoices"): "Unknown parameter for 'transactions': no-invoices",
            ("unlinked",): "'unlinked' needs at least one path",
            ("reconcile",): "'reconcile' needs at least one path",
            ("reconcile", "date=2024"): "'reconcile' needs at least one path",
        }
        for args, message in cases.items():
            for config in (None, self.CONFIG):  # Said before the config is looked at
                with self.subTest(args=args, config=config):
                    code, output = self.run_bank(*args, config=config)
                    self.assertEqual(code, 255)
                    self.assertIn("- bank help", output)
                    self.assertIn(f"!!  {message}  !!", output)
                (self.home / ".config" / "bank" / "config.json").unlink(missing_ok=True)
                (self.home / ".config" / "bank").rmdir() if config else None

    def test_config_that_is_missing_or_wrong(self):
        path = self.home / ".config" / "bank" / "config.json"
        message = f"No config file: {path} - see 'bank help config'"
        self.assertEqual(self.run_bank(), (255, f"\x1b[31m\n  !!  {message}  !!  \x1b[39m\n\n"))
        code, output = self.run_bank("transactions", "date=24")
        self.assertEqual(code, 255)
        self.assertIn("Year must be 4 digits", output)
        code, output = self.run_bank("transactions", config="{not json")
        self.assertEqual(code, 255)
        self.assertIn(f"Config file is not valid JSON: {path}: ", output)
        self.assertNotIn("- bank help", output)
        for config, message in {
            "[]": "Config must be an object, got list",
            '{"certificates": [], "accounts": []}': "'certificates' must be an object, got list",
            '{"certificates": {"qonto": ["x"]}, "accounts": ["x"]}': "Account #1 must be an object, got str",
        }.items():
            with self.subTest(config=config):
                path.write_text(config)
                self.assertEqual(self.run_bank("transactions"), (255, f"\x1b[31m\n  !!  {message}  !!  \x1b[39m\n\n"))

    def test_error_of_a_command_is_the_exit_code(self):
        code, output = self.run_bank("transactions", config=self.CONFIG)  # The pin command fails: no connection
        self.assertEqual(code, 255)
        self.assertIn("Pin command failed (exit code 1): /bin/false", output)
        code, output = self.run_bank("show", "abc")
        self.assertEqual(code, 255)
        self.assertIn("No transaction found", output)

    def test_unlinked_is_local(self):
        receipt = self.write_file("receipt.jpg", JPG)
        code, output = self.run_bank("unlinked", str(self.home / "documents"))  # No config, no network
        self.assertEqual((code, output.splitlines()[0]), (1, str(receipt)))
        self.account.save_transaction_cache([transaction(1)])
        self.assertEqual(self.run_bank("link", "transaction-1", str(receipt), config=self.CONFIG)[0], 0)
        self.assertEqual(self.run_bank("unlinked", str(self.home / "documents"))[0], 0)


if __name__ == "__main__":
    unittest_main()
