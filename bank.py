#!/usr/bin/env python

"""
bank - KISS banking Client
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
"""

import fcntl
import mimetypes
import os
from binascii import hexlify
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from io import BytesIO
from itertools import chain
from json import dumps, loads
from pathlib import Path
from pprint import pprint as pp
from ssl import (
    CERT_NONE,
    CERT_REQUIRED,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    Purpose,
    SSLCertVerificationError,
    SSLContext,
    SSLSocket,
    _ASN1Object,
    _ssl,
)
from sys import argv, exit
from sys import flags as sys_flags
from urllib.request import Request, urlopen
from uuid import uuid4

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])
COLOR_LEN = 4


TITLE = "bank - KISS banking client"


class MultiPartForm:
    """
    Simple multipart/form-data encoder for file uploads.
    Original code can be found at https://github.com/c4ffein/python-snippets
    """

    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = hexlify(os.urandom(16))

    def add_field(self, name, value):
        self.form_fields.append((name, value))

    def add_file(self, field_name, file_name, file_handle, mimetype=None):
        body = file_handle.read()
        mimetype = (mimetypes.guess_type(file_name)[0] or "application/octet-stream") if mimetype is None else mimetype
        self.files.append((field_name, file_name, mimetype, body))

    def __bytes__(self):
        part_boundary = b"--" + self.boundary
        gen_disposition = lambda name: f'Content-Disposition: form-data; name="{name}"'.encode(encoding="ascii")
        gen_file = lambda field, file: gen_disposition(field) + f'; filename="{file}"'.encode(encoding="ascii")
        gen_content_type = lambda content_type: f"Content-Type: {content_type}".encode(encoding="ascii")
        forms_to_add = ([part_boundary, gen_disposition(name), b"", value] for name, value in self.form_fields)
        files_to_add = (
            [part_boundary, gen_file(field_name, file_name), gen_content_type(content_type), b"", body]
            for field_name, file_name, content_type, body in self.files
        )
        return b"\r\n".join([*chain(*(chain(forms_to_add, files_to_add))), b"--" + self.boundary + b"--", b""])


def make_pinned_ssl_context(pinned_sha_256, cafile=None, capath=None, cadata=None):
    """
    Returns an instance of a subclass of SSLContext that uses a subclass of SSLSocket
    that actually verifies the sha256 of the certificate during the TLS handshake
    Tested with `python-version: [3.8, 3.9, 3.10, 3.11, 3.12, 3.13]`
    Original code can be found at https://github.com/c4ffein/python-snippets
    """

    class PinnedSSLSocket(SSLSocket):
        def check_pinned_cert(self):
            der_cert_bin = self.getpeercert(True)
            if sha256(der_cert_bin).hexdigest() != pinned_sha_256:
                raise SSLCertVerificationError("Incorrect certificate checksum")

        def do_handshake(self, *args, **kwargs):
            r = super().do_handshake(*args, **kwargs)
            self.check_pinned_cert()
            return r

    class PinnedSSLContext(SSLContext):
        sslsocket_class = PinnedSSLSocket

    def create_pinned_default_context(purpose=Purpose.SERVER_AUTH):
        if not isinstance(purpose, _ASN1Object):
            raise TypeError(purpose)
        if purpose == Purpose.SERVER_AUTH:  # Verify certs and host name in client mode
            context = PinnedSSLContext(PROTOCOL_TLS_CLIENT)
            context.verify_mode, context.check_hostname = CERT_REQUIRED, True
        elif purpose == Purpose.CLIENT_AUTH:
            context = PinnedSSLContext(PROTOCOL_TLS_SERVER)
        else:
            raise ValueError(purpose)
        context.verify_flags |= _ssl.VERIFY_X509_STRICT
        if cafile or capath or cadata:
            context.load_verify_locations(cafile, capath, cadata)
        elif context.verify_mode != CERT_NONE:
            context.load_default_certs(purpose)  # Try loading default system root CA certificates, may fail silently
        if hasattr(context, "keylog_filename"):  # OpenSSL 1.1.1 keylog file
            keylogfile = os.environ.get("SSLKEYLOGFILE")
            if keylogfile and not sys_flags.ignore_environment:
                context.keylog_filename = keylogfile
        return context

    return create_pinned_default_context()


class BankException(Exception):
    pass


@dataclass
class Transaction:
    """
    Represents a single transaction from the Qonto API.

    Amount fields explanation:
    - amount_cents: Transaction amount in account currency (EUR for Qonto)
    - local_amount_cents: Transaction amount in foreign currency (if applicable)
    - currency: Account currency (always EUR for Qonto)
    - local_currency: Foreign currency (e.g., USD for international purchases)
    """

    transaction_id: str
    id: str
    label: str
    amount_cents: int  # Account currency (EUR)
    local_amount_cents: int  # Foreign currency (if different)
    currency: str  # Account currency
    local_currency: str | None  # Foreign currency (None if same as account currency)
    side: str  # "debit" or "credit"
    emitted_at: str

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        """Create Transaction from API response dict"""
        return cls(
            transaction_id=data["transaction_id"],
            id=data["id"],
            label=data["label"],
            amount_cents=data["amount_cents"],
            local_amount_cents=data["local_amount_cents"],
            currency=data["currency"],
            local_currency=data.get("local_currency"),  # Optional for domestic transactions
            side=data["side"],
            emitted_at=data["emitted_at"],
        )

    def to_dict(self) -> dict:
        """Convert back to dict for caching"""
        return {
            "transaction_id": self.transaction_id,
            "id": self.id,
            "label": self.label,
            "amount_cents": self.amount_cents,
            "local_amount_cents": self.local_amount_cents,
            "currency": self.currency,
            "local_currency": self.local_currency,
            "side": self.side,
            "emitted_at": self.emitted_at,
        }


@dataclass
class BankAccount:
    """Represents a bank account from organization info"""

    id: str

    @classmethod
    def from_dict(cls, data: dict) -> "BankAccount":
        return cls(id=data["id"])


@dataclass
class Organization:
    """Represents organization info from the API"""

    bank_accounts: list[BankAccount]

    @classmethod
    def from_dict(cls, data: dict) -> "Organization":
        return cls(bank_accounts=[BankAccount.from_dict(ba) for ba in data["bank_accounts"]])


@dataclass
class OrganizationResponse:
    """Response from /v2/organization endpoint"""

    organization: Organization

    @classmethod
    def from_dict(cls, data: dict) -> "OrganizationResponse":
        return cls(organization=Organization.from_dict(data["organization"]))


@dataclass
class TransactionsResponse:
    """Response from /v2/transactions endpoint"""

    transactions: list[Transaction]
    meta: dict

    @classmethod
    def from_dict(cls, data: dict) -> "TransactionsResponse":
        return cls(
            transactions=[Transaction.from_dict(t) for t in data["transactions"]],
            meta=data["meta"],
        )


@dataclass
class DateFilter:
    """Parsed date filter parameters for API queries"""

    emitted_at_from: str | None = None
    emitted_at_to: str | None = None


def parse_date_params(args: list[str]) -> DateFilter:
    """
    Parse date filter parameters from command line arguments.

    Supported formats (phase 1 - year only):
    - date=2024       → full year 2024
    - date>=2024      → from 2024 onwards
    - date>2024       → from 2025 onwards
    - date<=2024      → until end of 2024
    - date<2024       → until end of 2023
    - date>=2023 date<2025  → range

    Returns DateFilter with emitted_at_from/to in ISO 8601 format for API.
    """
    date_params = [arg for arg in args if arg.startswith("date")]

    if len(date_params) > 2:
        raise BankException("Maximum 2 date parameters allowed")

    filter_obj = DateFilter()

    for param in date_params:
        # Parse operator and value - check specific prefixes
        if param.startswith("date>="):
            op, value = ">=", param[6:]  # len("date>=") = 6
        elif param.startswith("date<="):
            op, value = "<=", param[6:]  # len("date<=") = 6
        elif param.startswith("date>"):
            op, value = ">", param[5:]  # len("date>") = 5
        elif param.startswith("date<"):
            op, value = "<", param[5:]  # len("date<") = 5
        elif param.startswith("date="):
            op, value = "=", param[5:]  # len("date=") = 5
        else:
            raise BankException(f"Invalid date parameter format: {param}")

        # Validate year format (4 digits)
        if not value.isdigit() or len(value) != 4:
            raise BankException(f"Year must be 4 digits, got: {value}")

        year = int(value)

        # Convert to ISO 8601 timestamps
        if op == "=":
            # Full year
            if filter_obj.emitted_at_from or filter_obj.emitted_at_to:
                raise BankException("Cannot combine date= with other date operators")
            filter_obj.emitted_at_from = f"{year}-01-01T00:00:00Z"
            filter_obj.emitted_at_to = f"{year}-12-31T23:59:59Z"
        elif op == ">=":
            if filter_obj.emitted_at_from:
                raise BankException("Cannot specify multiple 'from' date parameters")
            filter_obj.emitted_at_from = f"{year}-01-01T00:00:00Z"
        elif op == ">":
            if filter_obj.emitted_at_from:
                raise BankException("Cannot specify multiple 'from' date parameters")
            filter_obj.emitted_at_from = f"{year + 1}-01-01T00:00:00Z"
        elif op == "<=":
            if filter_obj.emitted_at_to:
                raise BankException("Cannot specify multiple 'to' date parameters")
            filter_obj.emitted_at_to = f"{year}-12-31T23:59:59Z"
        elif op == "<":
            if filter_obj.emitted_at_to:
                raise BankException("Cannot specify multiple 'to' date parameters")
            filter_obj.emitted_at_to = f"{year - 1}-12-31T23:59:59Z"

    # Validate range if both from and to are specified
    if filter_obj.emitted_at_from and filter_obj.emitted_at_to:
        if filter_obj.emitted_at_from > filter_obj.emitted_at_to:
            raise BankException("Invalid date range: 'from' date must be before 'to' date")

    return filter_obj


def get_body(addr, url, cert_checksum, user_agent=None, authorization=None, json=None, cafile=None):
    """
    Fetch data from API endpoint.

    Args:
        json: If True, parse as JSON. If False, return raw bytes.
              If None (default), auto-detect from Content-Type header.
    """
    context = make_pinned_ssl_context(cert_checksum, cafile=cafile)
    headers = {
        "User-Agent": "",  # Otherwise would send default User-Agent, that does fail
        **({"Authorization": str(authorization)[2:-1]} if authorization is not None else {}),
    }
    r = urlopen(Request("https://" + (addr + url).decode(), None, headers=headers), context=context)
    # Auto-detect JSON from Content-Type header if not explicitly specified
    if json is None:
        content_type = r.headers.get("Content-Type", "")
        json = "application/json" in content_type
    return loads(r.read()) if json else r.read()


def post_body(
    addr,
    url,
    file_bytes,
    cert_checksum,
    user_agent=None,
    authorization=None,
    json=None,
    additional_headers=None,
    cafile=None,
):
    """
    POST data to API endpoint (typically for file uploads).

    Args:
        json: If True, parse as JSON. If False, return raw bytes.
              If None (default), auto-detect from Content-Type header.
    """
    context = make_pinned_ssl_context(cert_checksum, cafile=cafile)
    form = MultiPartForm()
    form.add_file("file", "file.pdf", file_handle=BytesIO(file_bytes))
    body = bytes(form)
    headers = {
        "User-Agent": "",  # Otherwise would send default User-Agent, that does fail
        "Content-Type": f"multipart/form-data; boundary={form.boundary.decode()}",  # Needed for file upload
        **({"Authorization": str(authorization)[2:-1]} if authorization is not None else {}),
        **(additional_headers or {}),
    }
    request = Request("https://" + (addr + url).decode(), body, headers=headers)
    r = urlopen(request, context=context)
    # Auto-detect JSON from Content-Type header if not explicitly specified
    if json is None:
        content_type = r.headers.get("Content-Type", "")
        json = "application/json" in content_type
    return loads(r.read()) if json else r.read()


def usage(wrong_config=False, wrong_command=False, wrong_arg_len=False):
    output_lines = [
        TITLE,
        "─" * len(TITLE),
        "- bank help                         ==> show this help",
        "  + config                          ==> helps you with the configuration file",
        "─" * len(TITLE),
        "- bank                              ==> gives accounts infos",
        "- bank transactions                 ==> list transactions for first account",
        "  + no-invoice                      ==> only show transactions without an invoice",
        "  + only-invoice                    ==> only show transactions with an invoice",
        "  + use-original-currency           ==> show amounts in foreign currency (when applicable)",
        "  + date=2024                       ==> transactions from year 2024",
        "  + date>=2024                      ==> transactions from 2024 onwards",
        "  + date<2024                       ==> transactions before 2024",
        "  + date>=2023 date<2025            ==> transactions in range",
        "- bank j       end_of_id file_path  ==> add a file to a transaction by the end of its id",
        "- bank justify end_of_id file_path  ==> add a file to a transaction by the end of its id",
        "─" * len(TITLE),
        "Only working with Qonto for now, for my specific use-cases",
    ]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


def help_config():
    output_lines = [
        TITLE,
        "─" * len(TITLE),
        "Configuration",
        "─" * len(TITLE),
        "",
        f"{Color.PURP.value}Config file location:{Color.WHITE.value}",
        "  ~/.config/bank/config.json",
        "",
        f"{Color.PURP.value}Example configuration:{Color.WHITE.value}",
        "  {",
        '    "accounts": [',
        "      {",
        '        "id": "organization-slug",',
        '        "secret_key": "your_secret_key_here",',
        '        "local_store_path": "optional_path"',
        "      }",
        "    ],",
        '    "certificates": {',
        '      "qonto": "sha256_hash_of_der_certificate"',
        "    },",
        f"    {Color.DIM.value}# Optional:{Color.WHITE.value}",
        '    "ssl_cafile": "/path/to/ca-bundle.crt"',
        "  }",
        "",
        f"{Color.PURP.value}Required fields:{Color.WHITE.value}",
        "  • accounts[].id          - Organization slug from banking provider",
        "  • accounts[].secret_key  - API secret key",
        "  • certificates.qonto     - SHA256 hash of DER cert (64 hex chars)",
        "",
        f"{Color.PURP.value}Optional fields:{Color.WHITE.value}",
        "  • ssl_cafile             - Path to system CA bundle",
        "                             (e.g., /etc/ssl/certs/ca-certificates.crt)",
        "                             Provides defense-in-depth with cert pinning",
        "",
        f"{Color.PURP.value}Cache location:{Color.WHITE.value}",
        "  ~/.local/state/bank/transactions.json",
        "  (XDG-compliant, file-locked for safe concurrent access)",
        "",
        f"{Color.PURP.value}Limitations:{Color.WHITE.value}",
        "  • Only single account supported (multi-account planned for future)",
        "",
        "─" * len(TITLE),
    ]
    print("\n" + "\n".join(output_lines) + "\n")
    return 0


class Account:
    """
    Represents a banking account with methods to interact with the Qonto API.

    Handles transaction retrieval, caching, attachment uploads, and account information display.
    Uses certificate pinning for secure API communication.
    """

    def __init__(self, account_dict, cert_checksum, ssl_cafile=None):
        """
        Initialize an Account instance.

        Args:
            account_dict: Dict containing 'id', 'secret_key', and 'local_store_path'
            cert_checksum: SHA256 hash of the pinned certificate
            ssl_cafile: Optional path to CA bundle file for additional TLS verification
        """
        self.endpoint = b"thirdparty.qonto.com"
        account_keys = ["id", "secret_key", "local_store_path"]
        self.organization_slug, self.secret_key, self.local_store_path = (account_dict[k] for k in account_keys)
        self.account_infos = None
        self.cert_checksum = cert_checksum
        self.ssl_cafile = ssl_cafile

    @property
    def auth_str(self):
        """Generate authorization string for API requests."""
        return str.encode(f"{self.organization_slug}:{self.secret_key}")

    def get_infos(self):
        """Fetch and store organization information from the API."""
        response_dict = get_body(
            self.endpoint, b"/v2/organization", self.cert_checksum, authorization=self.auth_str, cafile=self.ssl_cafile
        )
        self.account_infos = OrganizationResponse.from_dict(response_dict)

    def _subinfos_str(self, infos, level, last_key):
        starter = " " * level * 2
        starter += Color.GREEN.value if level == 0 else Color.PURP.value if level % 2 else Color.RED.value
        if isinstance(infos, dict):
            return "".join(f"\n{starter}{k}{self._subinfos_str(v, level + 1, k)}" for k, v in infos.items())
        if isinstance(infos, list):
            return "".join(f"\n{starter}#{i}{self._subinfos_str(v, level + 1, i)}" for i, v in enumerate(infos))
        return f" {Color.DIM.value}{'─' * (34 - level * 2 - len(str(last_key)))}{Color.WHITE.value} {infos}"

    def print_infos(self):
        self.get_infos()
        # Convert back to dict for pretty printing (could improve this later)
        response_dict = get_body(
            self.endpoint, b"/v2/organization", self.cert_checksum, authorization=self.auth_str, cafile=self.ssl_cafile
        )
        print(f"{TITLE}\n{'─' * len(TITLE)}{self._subinfos_str(response_dict, 0, None)}")

    def _read_cache_unlocked(self):
        """Read cache without acquiring lock - caller must hold lock"""
        cache_path = Path.home() / ".local" / "state" / "bank" / "transactions.json"
        try:
            with cache_path.open() as f:
                return loads(f.read())
        except FileNotFoundError:
            return {}

    def get_transaction_cache(self):
        cache_path = Path.home() / ".local" / "state" / "bank" / "transactions.json"
        lock_path = cache_path.with_suffix(".lock")

        try:
            with lock_path.open("a") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
                try:
                    return self._read_cache_unlocked()
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        except FileNotFoundError:
            return {}

    def save_transaction_cache(self, obtained_transactions):
        cache_path = Path.home() / ".local" / "state" / "bank" / "transactions.json"
        lock_path = cache_path.with_suffix(".lock")
        cache_path.parent.mkdir(parents=True, exist_ok=True)

        # Use separate lock file + atomic write for crash safety
        with lock_path.open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                # Read existing cache while already holding exclusive lock
                existing = self._read_cache_unlocked()

                # Merge data
                new_cache = {**existing, **{t["transaction_id"]: t for t in obtained_transactions}}

                # Atomic write via temp file
                temp_path = cache_path.with_suffix(".tmp")
                with temp_path.open("w") as f:
                    f.write(dumps(new_cache))
                    f.flush()
                    os.fsync(f.fileno())  # Force to disk before rename

                # Atomic rename - either old or new file exists, never partial
                temp_path.rename(cache_path)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def get_full_transactions(self, partial_id):
        return [v for k, v in self.get_transaction_cache().items() if k.endswith(partial_id)]

    def get_one_transaction(self, partial_id):
        transactions = self.get_full_transactions(partial_id)
        if len(transactions) != 1:
            raise BankException("More than one transaction found" if len(transactions) else "No transaction found")
        return transactions[0]

    def show(self, partial_id):
        pp(self.get_one_transaction(partial_id))

    def show_attachments(self, transaction_id):
        url = b"/v2/transactions/" + transaction_id.encode() + b"/attachments"
        pp(get_body(self.endpoint, url, self.cert_checksum, authorization=self.auth_str, cafile=self.ssl_cafile))

    def _log_justify_attempt(self, transaction_id, idempotency_key, file_size, status, error=None):
        """Log justify attempt to file for recovery"""
        log_path = Path.home() / ".local" / "state" / "bank" / "justify_log.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "transaction_id": transaction_id,
            "idempotency_key": idempotency_key,
            "file_size": file_size,
            "status": status,  # "started", "success", "failed"
        }
        if error:
            log_entry["error"] = str(error)

        with log_path.open("a") as f:
            f.write(dumps(log_entry) + "\n")

    def justify(self, partial_id, file):
        transaction = self.get_one_transaction(partial_id)
        transaction_id = transaction["id"]
        idempo = str(uuid4())
        file_size = len(file)

        # Log the attempt before making the request
        self._log_justify_attempt(transaction_id, idempo, file_size, "started")

        print(f"{Color.DIM.value}Transaction ID: {Color.WHITE.value}{transaction_id}")
        print(f"{Color.DIM.value}Idempotency key: {Color.PURP.value}{idempo}{Color.WHITE.value}")
        print(f"{Color.DIM.value}File size: {Color.WHITE.value}{file_size} bytes")
        print(f"{Color.DIM.value}Uploading...{Color.WHITE.value}")

        try:
            r = post_body(
                self.endpoint,
                b"/v2/transactions/" + transaction_id.encode() + b"/attachments",
                file,
                self.cert_checksum,
                authorization=self.auth_str,
                additional_headers={"X-Qonto-Idempotency-Key": idempo},
                cafile=self.ssl_cafile,
            )
        except Exception as e:
            self._log_justify_attempt(transaction_id, idempo, file_size, "failed", error=str(e))
            raise BankException(f"Upload failed: {e}") from e

        # Validate response
        if r != {}:
            self._log_justify_attempt(transaction_id, idempo, file_size, "failed", error=f"Unexpected response: {r}")
            raise BankException(f"Unexpected API response: {r}")

        self._log_justify_attempt(transaction_id, idempo, file_size, "success")
        print(f"{Color.GREEN.value}✓ Attachment uploaded successfully{Color.WHITE.value}")
        print(f"{Color.DIM.value}Log: ~/.local/state/bank/justify_log.jsonl{Color.WHITE.value}")

    def print_transactions(
        self,
        attachments: bool | None = None,
        date_filter: DateFilter | None = None,
        use_original_currency: bool = False,
    ) -> None:
        """
        Fetch and display transactions with optional filtering.

        Args:
            attachments: If True, show only transactions with attachments (only-invoice).
                         If False, show only transactions without attachments (no-invoice).
                         If None, show all transactions.
            date_filter: Optional DateFilter to filter transactions by emission date.
            use_original_currency: If True, show amounts in foreign currency (when applicable).
                                   If False (default), show amounts in account currency (EUR).
        """
        self.get_infos()
        account_id = str.encode(self.account_infos.organization.bank_accounts[0].id)
        # Validate account_id is a valid UUID format (36 chars: 8-4-4-4-12 with hyphens)
        if len(account_id) != 36 or not all(chr(c) in "0123456789abcdef-" for c in account_id):
            raise BankException(f"Invalid account ID format: expected UUID, got {account_id.decode()}")
        # Build query parameters
        query_params = []
        if attachments is not None:
            query_params.append(b"with_attachments=" + (b"true" if attachments else b"false"))
        if date_filter:
            if date_filter.emitted_at_from:
                query_params.append(b"emitted_at_from=" + date_filter.emitted_at_from.encode())
            if date_filter.emitted_at_to:
                query_params.append(b"emitted_at_to=" + date_filter.emitted_at_to.encode())
        query_string = b"&".join(query_params)
        if query_string:
            query_string += b"&"
        url = b"/v2/transactions?" + query_string + b"bank_account_id="
        response_dict = get_body(
            self.endpoint, url + account_id, self.cert_checksum, authorization=self.auth_str, cafile=self.ssl_cafile
        )
        ts = TransactionsResponse.from_dict(response_dict)
        # Save transactions to cache (convert to dicts)
        self.save_transaction_cache([t.to_dict() for t in ts.transactions])
        for t in ts.transactions:
            short_transaction_id = f" {t.transaction_id[-6:]} "
            label = f"{Color.WHITE.value} {t.label}{Color.DIM.value} "
            # Choose which currency to display
            if use_original_currency and t.local_currency and t.local_currency != t.currency:
                money = t.local_amount_cents
                currency_code = t.local_currency
            else:
                money = t.amount_cents
                currency_code = t.currency
            money_str = Color.RED.value if t.side == "debit" else Color.GREEN.value
            sign = "-" if t.side == "debit" else "+"
            money_str += f" {sign}{money // 100},{str(money % 100).zfill(2)} {currency_code} "
            emitted_at = f" {t.emitted_at[:10]}"
            print(
                f"{Color.DIM.value}─"
                f"{Color.PURP.value}{short_transaction_id}"
                f"{Color.DIM.value}─"
                f"{label.ljust(60 + COLOR_LEN * 2, '─')}"
                f"{money_str.rjust(20 + COLOR_LEN, '─')}"
                f"{Color.DIM.value}─"
                f"{Color.PURP.value}{emitted_at}"
            )
        meta_gen = (f"{Color.PURP.value}{k}{Color.DIM.value}={Color.WHITE.value}{v}" for k, v in ts.meta.items())
        print("", f"{Color.DIM.value} ─ ".join(meta_gen))


class Config:
    def __init__(self, input_str):
        json = loads(input_str)
        # Validate required top-level fields
        if "certificates" not in json:
            raise BankException("Missing 'certificates' field in config")
        if "accounts" not in json:
            raise BankException("Missing 'accounts' field in config")
        # Validate certificates
        if "qonto" not in json["certificates"]:
            raise BankException("Missing 'certificates.qonto' field in config")
        qonto_cert = json["certificates"]["qonto"]
        if not isinstance(qonto_cert, str):
            raise BankException(f"Certificate must be a string, got {type(qonto_cert).__name__}")
        qonto_cert = qonto_cert.lower()
        if len(qonto_cert) != 64:
            raise BankException(f"Certificate must be 64 hex characters, got {len(qonto_cert)}")
        if any(c not in "0123456789abcdef" for c in qonto_cert):
            raise BankException("Certificate must contain only hexadecimal characters (0-9, a-f)")
        self.certificates = {"qonto": qonto_cert}
        # Optional: system CA bundle path for better TLS validation (in addition to cert pinning)
        self.ssl_cafile = json.get("ssl_cafile")
        # Validate accounts
        if not isinstance(json["accounts"], list):
            raise BankException(f"'accounts' must be a list, got {type(json['accounts']).__name__}")
        if len(json["accounts"]) == 0:
            raise BankException("'accounts' list cannot be empty")
        # Validate each account has required fields
        for i, account in enumerate(json["accounts"]):
            for field in ["id", "secret_key", "local_store_path"]:
                if field not in account:
                    raise BankException(f"Missing '{field}' in account #{i + 1}")
        self.accounts = [Account(a, self.certificates["qonto"], ssl_cafile=self.ssl_cafile) for a in json["accounts"]]
        # Currently only single account is supported
        if len(self.accounts) != 1:
            raise BankException(f"Only single account supported, found {len(self.accounts)} in config")


def main():
    # Check for help command before loading config
    if len(argv) >= 2 and argv[1] == "help":
        if len(argv) == 3 and argv[2] == "config":
            return help_config()
        return usage()

    try:
        with (Path.home() / ".config" / "bank" / "config.json").open() as f:
            config = Config(f.read())
    except Exception:
        return usage(wrong_config=True)
    if len(argv) < 2 or argv[1] == "accounts":
        return config.accounts[0].print_infos()
    if argv[1] == "transactions":
        # Parse parameters
        has_no_invoice = "no-invoice" in argv[2:]
        has_only_invoice = "only-invoice" in argv[2:]
        if has_no_invoice and has_only_invoice:
            raise BankException("Cannot use both 'no-invoice' and 'only-invoice' parameters")
        attachments = False if has_no_invoice else (True if has_only_invoice else None)
        use_original_currency = "use-original-currency" in argv[2:]
        date_filter = parse_date_params(argv[2:])
        return config.accounts[0].print_transactions(
            attachments=attachments,
            date_filter=date_filter if date_filter.emitted_at_from or date_filter.emitted_at_to else None,
            use_original_currency=use_original_currency,
        )
    if argv[1] == "show":
        if len(argv) != 3:
            return usage()
        return config.accounts[0].show(argv[2])
    if argv[1] == "show-attachments":
        if len(argv) != 3:
            return usage()
        return config.accounts[0].show_attachments(argv[2])
    if argv[1] == "justify" or argv[1] == "j":
        if len(argv) != 4:
            return usage()
        with Path(argv[3]).open("rb") as f:
            file = f.read()
        return config.accounts[0].justify(argv[2], file)
    return usage()


if __name__ == "__main__":
    try:
        main()
    except BankException as e:
        print(f"{Color.RED.value}\n  !!  {e}  !!  \n")
        exit(-1)
    except Exception:
        raise
