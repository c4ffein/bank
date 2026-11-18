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
import subprocess
import tempfile
from binascii import hexlify
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from functools import cache
from hashlib import file_digest, sha256
from io import BytesIO
from itertools import chain
from json import JSONDecodeError, dumps, loads
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
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import NAMESPACE_URL, uuid4, uuid5

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])
COLOR_LEN = 4


TITLE = "bank - KISS banking client"

HEX_CHARS = frozenset("0123456789abcdef")
PIN_COMMAND_TIMEOUT = 10  # seconds
PIN_COMMAND_MAX_PINS = 16  # the old and the new certificate overlap during a rotation: a few, never many
REQUEST_TIMEOUT = 30  # seconds, for each blocking network operation (connecting, then each read)
HTTP_ERROR_BODY_MAX = 4096  # bytes read from an error response, to say what the server answered
PER_PAGE = 100  # transactions per page: the most Qonto accepts
LINKS_FILE = "qonto-transaction-id-to-local-invoices.json"
ATTACHMENTS_FILE = "qonto-attachment-id-to-sha256.json"
# What Qonto accepts as an attachment, recognised by the first bytes of the file: (magic number, extension, mimetype)
FILE_TYPES = (
    (b"%PDF-", "pdf", "application/pdf"),
    (b"\xff\xd8\xff", "jpg", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
)


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
    pinned_sha_256 is a hex digest, or several of them: any is accepted (certificates overlap during a rotation)
    Tested with `python-version: [3.8, 3.9, 3.10, 3.11, 3.12, 3.13]`
    Original code can be found at https://github.com/c4ffein/python-snippets
    """

    pinned = frozenset((pinned_sha_256,) if isinstance(pinned_sha_256, str) else pinned_sha_256)

    class PinnedSSLSocket(SSLSocket):
        def check_pinned_cert(self):
            der_cert_bin = self.getpeercert(True)
            if sha256(der_cert_bin).hexdigest() not in pinned:
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


def detect_file_type(data: bytes) -> tuple[str, str]:
    """
    (extension, mimetype) of a file that Qonto accepts as an attachment, from its first bytes: its name is not trusted.
    Raises BankException for anything that is not a PDF, a JPEG or a PNG.
    """
    for magic, extension, mimetype in FILE_TYPES:
        if data.startswith(magic):
            return extension, mimetype
    raise BankException("Unsupported file type: only PDF, JPEG and PNG are accepted (checked on the first bytes)")


def read_local_file(file_path: str) -> tuple[Path, bytes]:
    """A local file, as (absolute path, content)"""
    path = Path(file_path).resolve()
    try:
        return path, path.read_bytes()
    except OSError as e:
        raise BankException(f"Could not read {file_path}: {e}") from e


def state_path(name: str) -> Path:
    """A file of the state directory - resolved at each call, so that nothing outlives a change of HOME"""
    return Path.home() / ".local" / "state" / "bank" / name


@contextmanager
def state_lock(path: Path, exclusive: bool):
    """Hold the lock file that goes with a state file: shared to read it, exclusive to rewrite it"""
    with path.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def read_json(path: Path, default):
    """Read a state file, or default when there is none yet - the caller must hold its lock"""
    try:
        with path.open() as f:
            return loads(f.read())
    except FileNotFoundError:
        return default
    except ValueError as e:
        raise BankException(f"State file is not valid JSON: {path}") from e


def read_state(path: Path, default):
    """Read a state file under its shared lock, or default when there is none yet"""
    try:
        with state_lock(path, exclusive=False):
            return read_json(path, default)
    except FileNotFoundError:  # No state directory yet: the lock file could not be created
        return default


def fsync_directory(path: Path) -> None:
    """Force a directory to disk: what makes a file that was created or renamed in it survive a crash"""
    dir_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def write_json_atomic(path: Path, data) -> None:
    """Rewrite a state file - the caller must hold its exclusive lock"""
    # Atomic write via temp file, created 0o600 up front (financial data must not be world-readable)
    temp_path = path.with_suffix(".tmp")
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(dumps(data))
        f.flush()
        os.fsync(f.fileno())  # force file contents to disk before the swap
    # Atomic replace - readers see either the whole old or whole new file, never partial
    temp_path.replace(path)
    # fsync the directory too, so the rename itself survives a crash (not just the file contents)
    fsync_directory(path.parent)


def check_transaction_cache(data, path: Path) -> dict[str, dict]:
    """The content of the transactions cache - a BankException when it is not what save_transaction_cache writes"""
    if not isinstance(data, dict) or not all(isinstance(transaction, dict) for transaction in data.values()):
        raise BankException(f"Transactions cache is not what is expected: {path}")
    return data


def check_links(data, path: Path) -> list[dict]:
    """The content of the links file, as a list of links - a BankException when it is not what add_link writes"""
    links = data.get("links") if isinstance(data, dict) else None
    keys = ("transaction_id", "full_path", "sha256")
    if not isinstance(links, list) or not all(
        isinstance(link, dict) and all(isinstance(link.get(key), str) for key in keys) for link in links
    ):
        raise BankException(f"Links file is not what is expected: {path}")
    return links


def get_links() -> list[dict]:
    """Every link between a transaction and a local file: {"transaction_id", "full_path", "sha256"}"""
    path = state_path(LINKS_FILE)
    return check_links(read_state(path, {"links": []}), path)


def add_link(transaction_id: str, file_path: Path, digest: str) -> bool:
    """
    Link a local file to a transaction. A file is its SHA256: the path only says where it was when it was linked.
    Returns False when this file was already linked to this transaction: the path is then refreshed.
    """
    path = state_path(LINKS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    new = {"transaction_id": transaction_id, "full_path": str(file_path), "sha256": digest}
    with state_lock(path, exclusive=True):
        links = check_links(read_json(path, {"links": []}), path)
        others = [link for link in links if (link["transaction_id"], link["sha256"]) != (transaction_id, digest)]
        write_json_atomic(path, {"links": [*others, new]})
    return len(others) == len(links)


def check_known_attachments(data, path: Path) -> dict[str, dict]:
    """The content of the attachments file - a BankException when it is not what add_known_attachment writes"""
    attachments = data.get("attachments") if isinstance(data, dict) else None
    if not isinstance(attachments, dict) or not all(
        isinstance(entry, dict) and isinstance(entry.get("sha256"), str) and isinstance(entry.get("size"), int)
        for entry in attachments.values()
    ):
        raise BankException(f"Attachments file is not what is expected: {path}")
    return attachments


def get_known_attachments() -> dict[str, dict]:
    """
    The attachments of Qonto that were already downloaded once, by their id: {"sha256", "size"}.
    Qonto gives an id to an attachment, not its hash: this is what avoids downloading it again to know it.
    """
    path = state_path(ATTACHMENTS_FILE)
    return check_known_attachments(read_state(path, {"attachments": {}}), path)


def add_known_attachment(attachment_id: str, content: bytes) -> dict:
    """Remember what an attachment of Qonto is: returns its entry, see get_known_attachments"""
    path = state_path(ATTACHMENTS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"sha256": sha256(content).hexdigest(), "size": len(content)}
    with state_lock(path, exclusive=True):
        attachments = check_known_attachments(read_json(path, {"attachments": {}}), path)
        write_json_atomic(path, {"attachments": {**attachments, attachment_id: entry}})
    return entry


def local_files(paths: list[str]):
    """The files under the given paths: directories are walked, hidden files and hidden directories are skipped"""
    for path in map(Path, paths):
        if path.is_file():
            yield path
        elif path.is_dir():
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for file in sorted(files):
                    if not file.startswith(".") and (Path(root) / file).is_file():
                        yield Path(root) / file
        else:
            raise BankException(f"Not a file or a directory: {path}")


def local_file_hashes(paths: list[str]):
    """(path, SHA256) of each of the files under the given paths: see local_files"""
    for path in local_files(paths):
        try:
            with path.open("rb") as f:
                yield path, file_digest(f, "sha256").hexdigest()
        except OSError as e:
            raise BankException(f"Could not read {path}: {e}") from e


def print_unlinked(paths: list[str]) -> int:
    """
    Print the local files that are not linked to any transaction: the ones that still have to be dealt with.
    Files are compared by SHA256, so that a linked file can be renamed or moved. Returns 1 when some are not linked.
    """
    linked = {link["sha256"] for link in get_links()}
    total = unlinked = 0
    for path, digest in local_file_hashes(paths):
        total += 1
        if digest not in linked:
            unlinked += 1
            print(path)
    color = Color.RED.value if unlinked else Color.GREEN.value
    print(f"{color}{total} file(s), {total - unlinked} linked, {unlinked} not linked{Color.WHITE.value}")
    return 1 if unlinked else 0


def validate_pin_command(value, label):
    """
    A configured certificate is a command, as a list (an argv), that prints the SHA256s to accept: see resolve_pins.
    Returned as a tuple (hashable: resolve_pins caches on it).
    """
    if not isinstance(value, list):
        raise BankException(f"{label} must be a command (list of strings), got {type(value).__name__}")
    if not value or not all(isinstance(arg, str) and arg and "\0" not in arg for arg in value):
        raise BankException(f"{label} command must be a non-empty list of non-empty strings")
    return tuple(value)


@cache
def resolve_pins(command):
    """
    The SHA256 pins to accept for a certificate, as a tuple: what its configured command (an argv tuple) prints.
    It is run as it is, without a shell, once per run, when a connection needs it. What is expected is what
    tls-pin-get (https://github.com/c4ffein/crypto) does: exit code 0, and one SHA256 per line on stdout.
    Anything else (a failure, no pin, a line that is not a SHA256) is an error: no connection is made.
    """
    shown = " ".join(command)
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=PIN_COMMAND_TIMEOUT)
    except subprocess.TimeoutExpired as e:
        raise BankException(f"Pin command timed out after {PIN_COMMAND_TIMEOUT}s: {shown}") from e
    except (OSError, ValueError) as e:
        raise BankException(f"Pin command could not be run: {shown}: {e}") from e
    if result.returncode != 0:
        detail = " ".join(result.stderr.decode(errors="replace").split())[:200]
        detail = "".join(c if c.isprintable() else "?" for c in detail)
        raise BankException(f"Pin command failed (exit code {result.returncode}): {shown}{detail and ': ' + detail}")
    try:
        pins = tuple(line.lower() for line in result.stdout.decode("ascii").removesuffix("\n").split("\n"))
    except UnicodeDecodeError as e:
        raise BankException(f"Pin command printed something that is not a SHA256: {shown}") from e
    if pins == ("",):
        raise BankException(f"Pin command printed no pin: {shown}")
    if len(pins) > PIN_COMMAND_MAX_PINS:
        raise BankException(f"Pin command printed more than {PIN_COMMAND_MAX_PINS} pins: {shown}")
    if any(len(pin) != 64 or any(c not in HEX_CHARS for c in pin) for pin in pins):
        raise BankException(f"Pin command printed something that is not a SHA256: {shown}")
    return pins


def currency_symbol(code: str) -> str:
    """Convert currency code to symbol. Returns '?' for unknown currencies."""
    symbols = {
        "EUR": "€",
        "USD": "$",
    }
    return symbols.get(code, "?")


def validate_uuid(uuid_string: str) -> None:
    """
    Validate that a string is a properly formatted UUID.

    Raises BankException if invalid.
    """
    if len(uuid_string) != 36:
        raise BankException(f"Invalid UUID format: expected 36 characters, got {len(uuid_string)}")
    if not all(c in "0123456789abcdef-" for c in uuid_string.lower()):
        raise BankException("Invalid UUID format: contains invalid characters")
    # UUID format: 8-4-4-4-12 with hyphens
    parts = uuid_string.split("-")
    if len(parts) != 5 or [len(p) for p in parts] != [8, 4, 4, 4, 12]:
        raise BankException(f"Invalid UUID format: expected 8-4-4-4-12 format, got {uuid_string}")


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
    # What follows is not shown, but cached: what a transaction can be matched to a document or a client with
    settled_at: str | None = None
    status: str | None = None
    operation_type: str | None = None  # "card", "transfer", "income"...
    clean_counterparty_name: str | None = None
    reference: str | None = None  # Free text of a transfer: where an invoice number usually is
    note: str | None = None
    card_last_digits: str | None = None
    attachment_ids: list[str] = field(default_factory=list)  # Up to 5 per transaction

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
            settled_at=data.get("settled_at"),
            status=data.get("status"),
            operation_type=data.get("operation_type"),
            clean_counterparty_name=data.get("clean_counterparty_name"),
            reference=data.get("reference"),
            note=data.get("note"),
            card_last_digits=data.get("card_last_digits"),
            attachment_ids=list(data.get("attachment_ids") or []),
        )

    def to_dict(self) -> dict:
        """Convert back to dict for caching"""
        return asdict(self)


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


def describe_http_error(error: HTTPError) -> str:
    """What the server answered, on one line: the status, then what its body says went wrong"""
    try:
        raw = error.read(HTTP_ERROR_BODY_MAX)
    except OSError:
        raw = b""
    try:  # Qonto: {"errors": [{"code": ..., "detail": ...}]}
        detail = "; ".join(": ".join(str(e[k]) for k in ("code", "detail") if e.get(k)) for e in loads(raw)["errors"])
    except (ValueError, KeyError, TypeError, AttributeError):
        detail = raw.decode(errors="replace")  # Anything else (S3 answers in XML) is shown as it is
    detail = "".join(c if c.isprintable() else "?" for c in " ".join(detail.split()))[:300]
    return f"HTTP {error.code} {error.reason}" + (f": {detail}" if detail else "")


def fetch(request, pin_command, cafile=None) -> tuple[str, bytes]:
    """
    Send a request over a pinned TLS connection: returns (content type, body).
    Whatever goes wrong is raised as a BankException that says what, the answer of the server included.
    """
    try:
        context = make_pinned_ssl_context(resolve_pins(pin_command), cafile=cafile)
        with urlopen(request, context=context, timeout=REQUEST_TIMEOUT) as response:
            return response.headers.get("Content-Type", ""), response.read()
    except SSLCertVerificationError as e:
        raise BankException(f"SSL certificate error: {e}") from e
    except HTTPError as e:  # The server answered, with an error status: not a connection error
        raise BankException(describe_http_error(e)) from e
    except URLError as e:
        raise BankException(f"Connection error: {e.reason}") from e
    except TimeoutError as e:  # While reading the answer: a timeout while connecting is a URLError
        raise BankException(f"Connection error: no answer after {REQUEST_TIMEOUT}s") from e
    except OSError as e:
        raise BankException(f"Connection error: {e}") from e


def request_body(
    method,
    addr,
    url,
    pin_command,
    file_bytes=None,
    file_name="file.pdf",
    file_mimetype=None,
    user_agent=None,
    authorization=None,
    json=None,
    additional_headers=None,
    cafile=None,
):
    """
    Send an HTTP request to an API endpoint.

    Args:
        method: "GET" or "POST".
        file_bytes: If not None, sent as a multipart/form-data file, named file_name, of type file_mimetype
                    (guessed from file_name if None).
        json: If True, parse as JSON. If False, return raw bytes.
              If None (default), auto-detect from Content-Type header.
    """
    headers = {
        "User-Agent": "",  # Otherwise would send default User-Agent, that does fail
        **({"Authorization": str(authorization)[2:-1]} if authorization is not None else {}),
        **(additional_headers or {}),
    }
    body = None
    if file_bytes is not None:
        form = MultiPartForm()
        form.add_file("file", file_name, file_handle=BytesIO(file_bytes), mimetype=file_mimetype)
        body = bytes(form)
        headers["Content-Type"] = f"multipart/form-data; boundary={form.boundary.decode()}"
    request = Request("https://" + (addr + url).decode(), body, headers=headers, method=method)
    content_type, content = fetch(request, pin_command, cafile=cafile)
    # Auto-detect JSON from Content-Type header if not explicitly specified
    if json is None:
        json = "application/json" in content_type
    if not json:
        return content
    try:
        return loads(content)
    except ValueError as e:
        raise BankException("Unexpected answer: announced as JSON, but is not") from e


def get_body(addr, url, pin_command, user_agent=None, authorization=None, json=None, cafile=None):
    return request_body(
        "GET", addr, url, pin_command, user_agent=user_agent, authorization=authorization, json=json, cafile=cafile
    )


def post_body(
    addr,
    url,
    file_bytes,
    pin_command,
    file_name="file.pdf",
    file_mimetype=None,
    user_agent=None,
    authorization=None,
    json=None,
    additional_headers=None,
    cafile=None,
):
    return request_body(
        "POST",
        addr,
        url,
        pin_command,
        file_bytes=file_bytes,
        file_name=file_name,
        file_mimetype=file_mimetype,
        user_agent=user_agent,
        authorization=authorization,
        json=json,
        additional_headers=additional_headers,
        cafile=cafile,
    )


def usage(error=None):
    """Print the usage, then what was wrong with the command if anything was: returns the exit code"""
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
        "- bank j        end_of_id file_path ==> send a pdf/jpg/png to a transaction by the end of its id, and link it",
        "- bank justify  end_of_id file_path ==> send a pdf/jpg/png to a transaction by the end of its id, and link it",
        "  + force                           ==> send it again, when it was already sent to this transaction",
        "- bank link     end_of_id file_path ==> link a local file to a transaction, without sending it",
        "- bank unlinked path [path ...]     ==> list the local files that are not linked to any transaction",
        "- bank reconcile path [path ...]    ==> compare the attachments on Qonto with local files: link what matches,",
        "                                        list what is on Qonto only, and the local files that are not linked",
        "  + date=2024 ...                   ==> only the transactions of these dates, as for transactions",
        "- bank d        end_of_id [out_dir] ==> download attachments for a transaction",
        "- bank download end_of_id [out_dir] ==> download attachments for a transaction",
        "- bank hash     end_of_id           ==> show SHA256 hashes of attachments",
        "- bank sha256   end_of_id           ==> show SHA256 hashes of attachments",
        "─" * len(TITLE),
        "Only working with Qonto for now, for my specific use-cases",
    ]
    print("\n" + "\n".join(output_lines) + "\n")
    if error is None:
        return 0
    print(f"{Color.RED.value}  !!  {error}  !!  {Color.WHITE.value}\n")
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
        '        "secret_key": "your_secret_key_here"',
        "      }",
        "    ],",
        '    "certificates": {',
        '      "qonto": ["/home/you/.local/bin/tls-pin-get", "thirdparty.qonto.com:443"],',
        '      "aws_s3": ["/home/you/.local/bin/tls-pin-get", "qonto.s3.eu-central-1.amazonaws.com:443"]',
        "    },",
        f"    {Color.DIM.value}# Optional:{Color.WHITE.value}",
        '    "ssl_cafile": "/path/to/ca-bundle.crt"',
        "  }",
        "",
        f"{Color.PURP.value}Required fields:{Color.WHITE.value}",
        "  • accounts[].id          - Organization slug from banking provider",
        "  • accounts[].secret_key  - API secret key",
        "  • certificates.qonto     - Command that prints the SHA256 hashes of the Qonto API",
        "                             DER certs to accept (see below)",
        "",
        f"{Color.PURP.value}Optional fields:{Color.WHITE.value}",
        "  • certificates.aws_s3    - Same, for AWS S3",
        "                             (REQUIRED for download/hash commands)",
        "  • ssl_cafile             - Path to system CA bundle",
        "                             (e.g., /etc/ssl/certs/ca-certificates.crt)",
        "                             Provides defense-in-depth with cert pinning",
        "",
        f"{Color.PURP.value}Certificate commands:{Color.WHITE.value}",
        "  A certificate is not a hash but a command that prints some, as a list: full path, then",
        "  arguments. The example is tls-pin-get, from https://github.com/c4ffein/crypto",
        "  • Run as it is (no shell, no ~), when a connection needs it, once per run",
        "  • Must exit with 0 and print SHA256 hashes, one per line: any of them is accepted",
        "  • No connection when it fails, prints nothing, or prints anything else",
        "  • Whoever can edit the config file can run commands as you: keep it 0600",
        '  • A hash that never changes: ["/bin/echo", "sha256_hash_of_the_der_certificate"]',
        "",
        f"{Color.PURP.value}State location:{Color.WHITE.value}",
        "  ~/.local/state/bank/",
        "  (XDG-compliant, file-locked for safe concurrent access)",
        "  • transactions.json      - Cache of the transactions that were listed",
        "                             (can be deleted: list them again)",
        f"  • {LINKS_FILE}",
        "                           - Which local file goes with which transaction",
        "                             (the only copy of it: files are known by SHA256,",
        "                             the path is where they were when they were linked)",
        "  • justify_log.jsonl      - What was sent to which transaction, and when",
        f"  • {ATTACHMENTS_FILE}",
        "                           - SHA256 of the attachments of Qonto, by their id",
        "                             (can be deleted: reconcile downloads them again)",
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

    def __init__(self, account_dict, pin_command, s3_pin_command=None, ssl_cafile=None):
        """
        Initialize an Account instance.

        Args:
            account_dict: Dict containing 'id' and 'secret_key'
            pin_command: Command (argv tuple) that prints the pinned SHA256s for Qonto API, see resolve_pins
            s3_pin_command: Same, for AWS S3
            ssl_cafile: Optional path to CA bundle file for additional TLS verification
        """
        self.endpoint = b"thirdparty.qonto.com"
        self.organization_slug, self.secret_key = account_dict["id"], account_dict["secret_key"]
        self.account_infos = None
        self.pin_command = pin_command
        self.s3_pin_command = s3_pin_command
        self.ssl_cafile = ssl_cafile

    @property
    def auth_str(self):
        """Generate authorization string for API requests."""
        return str.encode(f"{self.organization_slug}:{self.secret_key}")

    def _get(self, url):
        """GET an API endpoint, as this account"""
        return get_body(self.endpoint, url, self.pin_command, authorization=self.auth_str, cafile=self.ssl_cafile)

    def get_infos(self):
        """Fetch and store organization information from the API."""
        self.account_infos = OrganizationResponse.from_dict(self._get(b"/v2/organization"))

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
        response_dict = self._get(b"/v2/organization")
        print(f"{TITLE}\n{'─' * len(TITLE)}{self._subinfos_str(response_dict, 0, None)}")

    def get_transaction_cache(self):
        cache_path = state_path("transactions.json")
        return check_transaction_cache(read_state(cache_path, {}), cache_path)

    def save_transaction_cache(self, obtained_transactions):
        cache_path = state_path("transactions.json")
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        # Separate lock file + atomic write for crash safety - the existing cache is read under the same lock
        with state_lock(cache_path, exclusive=True):
            existing = check_transaction_cache(read_json(cache_path, {}), cache_path)
            write_json_atomic(cache_path, {**existing, **{t["transaction_id"]: t for t in obtained_transactions}})

    def get_full_transactions(self, partial_id):
        return [v for k, v in self.get_transaction_cache().items() if k.endswith(partial_id)]

    def get_one_transaction(self, partial_id):
        transactions = self.get_full_transactions(partial_id)
        if len(transactions) != 1:
            raise BankException("More than one transaction found" if len(transactions) else "No transaction found")
        return transactions[0]

    def show(self, partial_id):
        pp(self.get_one_transaction(partial_id))

    def get_attachments(self, transaction_id):
        """What the API lists as the attachments of a transaction, by its id (the UUID)"""
        validate_uuid(transaction_id)
        return self._get(b"/v2/transactions/" + transaction_id.encode() + b"/attachments").get("attachments", [])

    def show_attachments(self, partial_id):
        pp(self.get_attachments(self.get_one_transaction(partial_id)["id"]))

    def require_s3_pin(self):
        """Attachments are downloaded from S3, with certificate pinning as well: said before anything is done"""
        if not self.s3_pin_command:
            raise BankException(
                "S3 certificate pinning not configured. Add 'aws_s3' certificate to config. "
                "See 'bank help config' for details."
            )

    def download_attachment(self, attachment) -> bytes:
        """The content of an attachment, as the API lists it: from its pre-signed S3 URL, nothing but https"""
        download_url = attachment.get("url") if isinstance(attachment, dict) else None
        if not isinstance(download_url, str) or not download_url.startswith("https://"):
            raise BankException("No download URL")
        return fetch(Request(download_url), self.s3_pin_command, cafile=self.ssl_cafile)[1]

    def iter_attachments(self, partial_id):
        """
        Download the attachments of a transaction: yields (index, how many there are, file name, content).
        The content is a BankException when this attachment could not be downloaded: the others still are.
        File names are ours: the ones that the API provides are not trusted.
        """
        transaction_id = self.get_one_transaction(partial_id)["id"]
        attachments = self.get_attachments(transaction_id)
        if not attachments:
            print(f"{Color.DIM.value}No attachments found for transaction {transaction_id[-6:]}{Color.WHITE.value}")
            return
        self.require_s3_pin()
        DIM, WHITE = Color.DIM.value, Color.WHITE.value
        print(f"{DIM}Found {len(attachments)} attachment(s) for transaction {transaction_id[-6:]}{WHITE}")
        for i, attachment in enumerate(attachments, 1):
            try:
                content = self.download_attachment(attachment)
            except BankException as e:
                content = e
            yield i, len(attachments), f"attachment_{transaction_id}_{i}", content

    def download_attachments(self, partial_id, output_dir=None):
        """
        Download all attachments for a transaction. Returns the exit code: 1 when some could not be downloaded.

        Args:
            partial_id: Partial transaction ID to match
            output_dir: Directory to save files (default: current directory)
        """
        output_dir = Path.cwd() if output_dir is None else Path(output_dir)
        RED, GREEN, DIM, WHITE = Color.RED.value, Color.GREEN.value, Color.DIM.value, Color.WHITE.value
        total = failed = 0
        for i, total, file_name, content in self.iter_attachments(partial_id):
            output_path = output_dir / file_name
            try:
                if isinstance(content, BankException):
                    raise content
                output_dir.mkdir(parents=True, exist_ok=True)
                # Save to disk atomically - temp file in same dir + rename, kept 0o600 (financial documents)
                temp_fd, temp_name = tempfile.mkstemp(dir=output_dir, prefix=f".{file_name}.")
                temp_path = Path(temp_name)
                try:
                    try:
                        os.write(temp_fd, content)
                    finally:
                        os.close(temp_fd)
                    temp_path.replace(output_path)  # Atomic rename - either old or new file exists, never partial
                except BaseException:
                    try:
                        temp_path.unlink()
                    except OSError:
                        pass
                    raise
            except (BankException, OSError) as e:
                failed += 1
                print(f"{RED}✗ [{i}/{total}] Failed to download {file_name}: {e}{WHITE}")
                continue
            print(f"{GREEN}✓ {DIM}[{i}/{total}] {WHITE}{output_path} {DIM}({len(content) / 1024:.1f} KB){WHITE}")
        if total:
            print(f"{RED if failed else GREEN}Downloaded {total - failed} of {total} attachment(s){WHITE}")
        return 1 if failed else 0

    def get_attachment_hashes(self, partial_id):
        """
        Download and display SHA256 hashes of all attachments for a transaction.
        Returns the exit code: 1 when some could not be downloaded.

        Args:
            partial_id: Partial transaction ID to match
        """
        failed = 0
        for i, _total, file_name, content in self.iter_attachments(partial_id):
            if isinstance(content, BankException):
                failed += 1
                print(f"\n{Color.RED.value}[{i}] ✗ Failed to hash {file_name}: {content}{Color.WHITE.value}")
                continue
            print(f"\n{Color.PURP.value}[{i}] {Color.WHITE.value}{file_name}")
            print(f"{Color.DIM.value}    Size: {Color.WHITE.value}{len(content) / 1024:.1f} KB")
            print(f"{Color.DIM.value}    SHA256: {Color.GREEN.value}{sha256(content).hexdigest()}{Color.WHITE.value}")
        return 1 if failed else 0

    def get_remote_hashes(self, transaction_id) -> set[str]:
        """
        SHA256 of each of the attachments that a transaction has on Qonto right now, by its id (the UUID).
        As reconcile does, an attachment is only downloaded the first time that its id is seen.
        """
        known = get_known_attachments()
        hashes = set()
        for attachment in self.get_attachments(transaction_id):
            attachment_id = attachment.get("id") if isinstance(attachment, dict) else None
            if not isinstance(attachment_id, str):
                raise BankException("No attachment id")
            if attachment_id not in known:
                self.require_s3_pin()
                known[attachment_id] = add_known_attachment(attachment_id, self.download_attachment(attachment))
            hashes.add(known[attachment_id]["sha256"])
        return hashes

    def _log_justify_attempt(self, transaction_id, idempotency_key, file_size, digest, status, error=None):
        """Log justify attempt to file: for recovery, and to know what was already sent (see _justify_sent_at)"""
        log_path = state_path("justify_log.jsonl")
        log_path.parent.mkdir(parents=True, exist_ok=True)

        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "transaction_id": transaction_id,
            "idempotency_key": idempotency_key,
            "file_size": file_size,
            "sha256": digest,
            "status": status,  # "started", "success", "failed"
        }
        if error:
            log_entry["error"] = str(error)

        # Append-only, created 0o600 up front. On disk before going on: "started" has to be there before the request
        fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(dumps(log_entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        fsync_directory(log_path.parent)  # The log itself, the first time

    def _justify_successes(self):
        """The entries of the log that are a success, oldest first - none when there is no log"""
        try:
            lines = state_path("justify_log.jsonl").read_text().splitlines()
        except FileNotFoundError:
            return
        for line in lines:
            try:
                entry = loads(line)
            except ValueError:  # A line that a crash cut short: not a success
                continue
            if isinstance(entry, dict) and entry.get("status") == "success":
                yield entry

    def _justify_sent_at(self, transaction_id, digest):
        """When this file was successfully sent to this transaction, as the log has it - None when it never was"""
        sent_at = None
        for entry in self._justify_successes():
            if (entry.get("transaction_id"), entry.get("sha256")) == (transaction_id, digest):
                sent_at = entry.get("timestamp")  # The last time
        return sent_at

    def link(self, partial_id, file_path):
        """Link a local file to a transaction, without sending anything: see add_link"""
        transaction = self.get_one_transaction(partial_id)
        path, file = read_local_file(file_path)
        digest = sha256(file).hexdigest()
        added = add_link(transaction["transaction_id"], path, digest)
        DIM, WHITE = Color.DIM.value, Color.WHITE.value
        print(f"{DIM}Transaction: {WHITE}{transaction['transaction_id']}")
        print(f"{DIM}SHA256: {WHITE}{digest}")
        print(f"{Color.GREEN.value}✓ {'Linked' if added else 'Was already linked'}: {WHITE}{path}")

    def justify(self, partial_id, file_path, force=False):
        """
        Send a local file (PDF, JPEG or PNG) to a transaction as an attachment, then link it: see add_link.
        A file is not sent again, unless force, when the log says that it was already sent to this transaction,
        or when the transaction already has it on Qonto: what an answer that was lost, or another machine, left there.
        """
        transaction = self.get_one_transaction(partial_id)
        transaction_id = transaction["id"]
        validate_uuid(transaction_id)
        path, file = read_local_file(file_path)
        extension, mimetype = detect_file_type(file)
        file_size, digest = len(file), sha256(file).hexdigest()

        sent_at = self._justify_sent_at(transaction_id, digest)
        if sent_at and not force:
            add_link(transaction["transaction_id"], path, digest)
            print(f"{Color.GREEN.value}✓ Already sent to this transaction{Color.WHITE.value} ({sent_at}): nothing sent")
            print(f"{Color.DIM.value}Add 'force' to send it again{Color.WHITE.value}")
            return

        if not force:
            # The log only knows the answers that were received: Qonto is asked what the transaction really has
            try:
                already_there = digest in self.get_remote_hashes(transaction_id)
            except BankException as e:
                raise BankException(
                    f"Could not check what this transaction already has, nothing sent: {e} (add 'force' to send anyway)"
                ) from e
            if already_there:
                add_link(transaction["transaction_id"], path, digest)
                print(f"{Color.GREEN.value}✓ Already on this transaction{Color.WHITE.value}: nothing sent, linked")
                print(f"{Color.DIM.value}Add 'force' to send it again{Color.WHITE.value}")
                return

        # Same transaction and same file: same key. Qonto answers a key that it has seen in the last 30 minutes
        # without doing anything again, so that sending again after a lost answer cannot attach the file twice.
        # Past these 30 minutes, the check above is what prevents it. force is a new key: always a new attachment.
        idempo = str(uuid4() if force else uuid5(NAMESPACE_URL, f"bank:justify:{transaction_id}:{digest}"))

        # Log the attempt before making the request
        self._log_justify_attempt(transaction_id, idempo, file_size, digest, "started")

        print(f"{Color.DIM.value}Transaction ID: {Color.WHITE.value}{transaction_id}")
        print(f"{Color.DIM.value}Idempotency key: {Color.PURP.value}{idempo}{Color.WHITE.value}")
        print(f"{Color.DIM.value}File: {Color.WHITE.value}{mimetype}, {file_size} bytes")
        print(f"{Color.DIM.value}SHA256: {Color.WHITE.value}{digest}")
        print(f"{Color.DIM.value}Uploading...{Color.WHITE.value}")

        try:
            r = post_body(
                self.endpoint,
                b"/v2/transactions/" + transaction_id.encode() + b"/attachments",
                file,
                self.pin_command,
                file_name=f"file.{extension}",
                file_mimetype=mimetype,
                authorization=self.auth_str,
                additional_headers={"X-Qonto-Idempotency-Key": idempo},
                cafile=self.ssl_cafile,
            )
        except Exception as e:
            self._log_justify_attempt(transaction_id, idempo, file_size, digest, "failed", error=str(e))
            raise BankException(f"Upload failed: {e}") from e

        # Validate response
        if r != {}:
            error = f"Unexpected response: {r}"
            self._log_justify_attempt(transaction_id, idempo, file_size, digest, "failed", error=error)
            raise BankException(f"Unexpected API response: {r}")

        self._log_justify_attempt(transaction_id, idempo, file_size, digest, "success")
        add_link(transaction["transaction_id"], path, digest)
        print(f"{Color.GREEN.value}✓ Attachment uploaded successfully, and linked{Color.WHITE.value}")
        print(f"{Color.DIM.value}Log: ~/.local/state/bank/justify_log.jsonl{Color.WHITE.value}")

    def reconcile(self, paths: list[str], date_filter: DateFilter | None = None) -> int:
        """
        Compare the attachments that the transactions have on Qonto with the local files under paths, by SHA256.
        - An attachment that is one of the local files: this file is linked to the transaction, if it was not
        - An attachment that is none of them is said: it is on Qonto only
        - A local file that is linked to no transaction is said: as unlinked does
        - A local file that the log says was sent to a transaction that does not have it anymore is said: it is gone
          from Qonto. A file that was only linked (bank link) is not: it never was there
        Returns 1 when one of the last three happens, or when an attachment could not be downloaded.

        Qonto gives no hash, but an id for each attachment: an attachment is only downloaded the first time that
        its id is seen (see get_known_attachments), and a transaction is only asked for its attachments when it
        has some that are not known yet. The transactions without any attachment are only fetched when a file
        that was sent may be linked to one of them.
        """
        RED, GREEN, DIM, WHITE = Color.RED.value, Color.GREEN.value, Color.DIM.value, Color.WHITE.value
        local_hashes = list(local_file_hashes(paths))  # First: a wrong path is said before anything is fetched
        local = {}
        for path, digest in local_hashes:
            local.setdefault(digest, path.resolve())
        self.require_s3_pin()
        transactions, _ = self.fetch_transactions(attachments=True, date_filter=date_filter)
        known = get_known_attachments()
        linked = {(link["transaction_id"], link["sha256"]) for link in get_links()}
        on_qonto = set()  # (transaction_id, sha256) of every attachment
        new_links = remote_only = failed = 0
        for t in transactions:
            short = f"{Color.PURP.value}{t.transaction_id[-6:]}{WHITE} {t.label}"
            attachment_ids = t.attachment_ids
            if not attachment_ids or any(attachment_id not in known for attachment_id in attachment_ids):
                attachment_ids = []
                for attachment in self.get_attachments(t.id):
                    attachment_id = attachment.get("id") if isinstance(attachment, dict) else None
                    try:
                        if not isinstance(attachment_id, str):
                            raise BankException("No attachment id")
                        if attachment_id not in known:
                            known[attachment_id] = add_known_attachment(
                                attachment_id, self.download_attachment(attachment)
                            )
                    except BankException as e:
                        failed += 1
                        print(f"{RED}✗ could not download {WHITE}{short}{DIM} attachment {attachment_id}: {e}{WHITE}")
                        continue
                    attachment_ids.append(attachment_id)
            for attachment_id in attachment_ids:
                digest = known[attachment_id]["sha256"]
                on_qonto.add((t.transaction_id, digest))
                if digest not in local:
                    remote_only += 1
                    print(f"{RED}✗ on Qonto only    {WHITE}{short}{DIM} attachment {attachment_id}{WHITE}")
                elif (t.transaction_id, digest) not in linked:
                    add_link(t.transaction_id, local[digest], digest)
                    linked.add((t.transaction_id, digest))
                    new_links += 1
                    print(f"{GREEN}✓ linked           {WHITE}{short}{DIM} {local[digest]}{WHITE}")
        # The other way: local files, against the links
        fetched = {t.transaction_id: t for t in transactions}
        linked_hashes = {digest for _, digest in linked}
        local_only = unlinked = gone = 0
        here_only = sorted(link for link in linked - on_qonto if link[1] in local)
        # The log has the id of a transaction, a link has its transaction_id: the transaction says which goes with which
        sent = {(entry.get("transaction_id"), entry.get("sha256")) for entry in self._justify_successes()}
        sent_hashes = {digest for _, digest in sent}
        without_attachments = {}
        if any(transaction_id not in fetched and digest in sent_hashes for transaction_id, digest in here_only):
            others, _ = self.fetch_transactions(attachments=False, date_filter=date_filter)
            without_attachments = {t.transaction_id: t for t in others}
        for transaction_id, digest in here_only:
            t = fetched.get(transaction_id) or without_attachments.get(transaction_id)
            if t is None:  # Not a transaction of these dates
                continue
            short = f"{Color.PURP.value}{t.transaction_id[-6:]}{WHITE} {t.label}"
            if (t.id, digest) in sent:  # It was there: someone removed it
                gone += 1
                print(f"{RED}✗ gone from Qonto  {WHITE}{short}{DIM} {local[digest]}{WHITE}")
            elif transaction_id in fetched:  # Linked without being sent (bank link): not an error
                local_only += 1
                print(f"{DIM}· linked here only {WHITE}{short}{DIM} {local[digest]}{WHITE}")
        for path, digest in local_hashes:
            if digest not in linked_hashes:
                unlinked += 1
                print(f"{RED}✗ not linked       {WHITE}{path}")
        problems = remote_only + unlinked + failed + gone
        print(
            f"{RED if problems else GREEN}"
            f"{len(on_qonto)} attachment(s) on Qonto: {new_links} newly linked, {remote_only} on Qonto only"
            f"{f', {failed} not downloaded' if failed else ''}"
            f" ─ {len(local_hashes)} local file(s): {unlinked} not linked, {local_only} linked here only"
            f"{f', {gone} gone from Qonto' if gone else ''}{WHITE}"
        )
        return 1 if problems else 0

    def fetch_transactions(
        self, attachments: bool | None = None, date_filter: DateFilter | None = None
    ) -> tuple[list[Transaction], dict]:
        """
        Fetch the transactions of the first account, page after page until the last one, and cache them.
        Returns them with the meta of the last page. See print_transactions for the filters.
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
        query_params += [b"bank_account_id=" + account_id, b"per_page=" + str(PER_PAGE).encode()]
        url = b"/v2/transactions?" + b"&".join(query_params) + b"&page="
        transactions, page = [], 1
        while page is not None:
            response = TransactionsResponse.from_dict(self._get(url + str(page).encode()))
            # Cached page by page (as dicts): what was fetched is kept if a later page fails
            self.save_transaction_cache([t.to_dict() for t in response.transactions])
            transactions += response.transactions
            next_page = response.meta.get("next_page")
            if next_page is not None and (not isinstance(next_page, int) or next_page <= page):
                raise BankException(f"Unexpected next page after page {page}: {next_page}")
            page = next_page
        return transactions, response.meta

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
        transactions, meta = self.fetch_transactions(attachments=attachments, date_filter=date_filter)
        for t in transactions:
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
            symbol = currency_symbol(currency_code)
            money_str += f" {sign}{money // 100},{str(money % 100).zfill(2)} {symbol} "
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
        meta_gen = (f"{Color.PURP.value}{k}{Color.DIM.value}={Color.WHITE.value}{v}" for k, v in meta.items())
        print("", f"{Color.DIM.value} ─ ".join(meta_gen))


class Config:
    def __init__(self, input_str):
        json = loads(input_str)
        if not isinstance(json, dict):
            raise BankException(f"Config must be an object, got {type(json).__name__}")
        # Validate required top-level fields
        if "certificates" not in json:
            raise BankException("Missing 'certificates' field in config")
        if "accounts" not in json:
            raise BankException("Missing 'accounts' field in config")
        # Validate certificates
        if not isinstance(json["certificates"], dict):
            raise BankException(f"'certificates' must be an object, got {type(json['certificates']).__name__}")
        if "qonto" not in json["certificates"]:
            raise BankException("Missing 'certificates.qonto' field in config")
        qonto_cert = validate_pin_command(json["certificates"]["qonto"], "Certificate")
        # Optional: AWS S3 certificate for attachment downloads
        s3_cert = json["certificates"].get("aws_s3")
        if s3_cert is not None:
            s3_cert = validate_pin_command(s3_cert, "S3 certificate")
        self.certificates = {"qonto": qonto_cert, "aws_s3": s3_cert}
        # Optional: system CA bundle path for better TLS validation (in addition to cert pinning)
        self.ssl_cafile = json.get("ssl_cafile")
        # Validate accounts
        if not isinstance(json["accounts"], list):
            raise BankException(f"'accounts' must be a list, got {type(json['accounts']).__name__}")
        if len(json["accounts"]) == 0:
            raise BankException("'accounts' list cannot be empty")
        # Validate each account has required fields ('local_store_path' was one: still accepted, and ignored)
        for i, account in enumerate(json["accounts"]):
            if not isinstance(account, dict):
                raise BankException(f"Account #{i + 1} must be an object, got {type(account).__name__}")
            for field_name in ["id", "secret_key"]:
                if field_name not in account:
                    raise BankException(f"Missing '{field_name}' in account #{i + 1}")
        self.accounts = [
            Account(
                a, self.certificates["qonto"], s3_pin_command=self.certificates["aws_s3"], ssl_cafile=self.ssl_cafile
            )
            for a in json["accounts"]
        ]
        # Currently only single account is supported
        if len(self.accounts) != 1:
            raise BankException(f"Only single account supported, found {len(self.accounts)} in config")


def load_config():
    """The config, from its file: whatever is wrong with it is a BankException that says what"""
    path = Path.home() / ".config" / "bank" / "config.json"
    try:
        content = path.read_text()
    except FileNotFoundError as e:
        raise BankException(f"No config file: {path} - see 'bank help config'") from e
    except (OSError, UnicodeDecodeError) as e:
        raise BankException(f"Config file could not be read: {path}: {e}") from e
    try:
        return Config(content)
    except JSONDecodeError as e:
        raise BankException(f"Config file is not valid JSON: {path}: {e}") from e


# How many arguments each command accepts ('transactions', 'unlinked' and 'reconcile' have their own rules)
ARG_COUNTS = {
    "accounts": (0,),
    "show": (1,),
    "show-attachments": (1,),
    "justify": (2, 3),
    "j": (2, 3),
    "link": (2,),
    "download": (1, 2),
    "d": (1, 2),
    "sha256": (1,),
    "hash": (1,),
}
TRANSACTIONS_PARAMETERS = ("no-invoice", "only-invoice", "use-original-currency")


def main():
    """Run the command, and return the exit code. What is wrong with the command is said before anything is done"""
    command, args = (argv[1], argv[2:]) if len(argv) >= 2 else ("accounts", [])
    if command == "help":
        return help_config() if args == ["config"] else usage()
    if command == "unlinked":  # Local only: neither the config nor the network
        return print_unlinked(args) if args else usage("'unlinked' needs at least one path")
    if command == "transactions":
        unknown = [arg for arg in args if arg not in TRANSACTIONS_PARAMETERS and not arg.startswith("date")]
        if unknown:
            return usage(f"Unknown parameter for 'transactions': {unknown[0]}")
        has_no_invoice = "no-invoice" in args
        has_only_invoice = "only-invoice" in args
        if has_no_invoice and has_only_invoice:
            raise BankException("Cannot use both 'no-invoice' and 'only-invoice' parameters")
        attachments = False if has_no_invoice else (True if has_only_invoice else None)
        date_filter = parse_date_params(args)
    elif command == "reconcile":
        paths = [arg for arg in args if not arg.startswith("date")]
        if not paths:
            return usage("'reconcile' needs at least one path")
        date_filter = parse_date_params(args)
    elif command not in ARG_COUNTS:
        return usage(f"Unknown command: {command}")
    elif len(args) not in ARG_COUNTS[command] or (command in ("justify", "j") and args[2:] not in ([], ["force"])):
        return usage(f"Wrong arguments for '{command}'")

    account = load_config().accounts[0]
    if command == "accounts":
        return account.print_infos()
    if command == "transactions":
        return account.print_transactions(
            attachments=attachments,
            date_filter=date_filter if date_filter.emitted_at_from or date_filter.emitted_at_to else None,
            use_original_currency="use-original-currency" in args,
        )
    if command == "reconcile":
        return account.reconcile(paths, date_filter=date_filter)
    if command == "show":
        return account.show(args[0])
    if command == "show-attachments":
        return account.show_attachments(args[0])
    if command in ("justify", "j"):
        return account.justify(args[0], args[1], force=args[2:] == ["force"])
    if command == "link":
        return account.link(args[0], args[1])
    if command in ("download", "d"):
        return account.download_attachments(args[0], args[1] if len(args) == 2 else None)
    return account.get_attachment_hashes(args[0])  # sha256, hash


if __name__ == "__main__":
    try:
        exit(main() or 0)
    except BankException as e:
        print(f"{Color.RED.value}\n  !!  {e}  !!  {Color.WHITE.value}\n")
        exit(-1)
