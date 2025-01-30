#!/usr/bin/env python

"""
bank - KISS banking Client
MIT License - Copyright (c) 2025 c4ffein
WARNING: I don't recommand using this as-is. This a PoC, and usable by me because I know what I want to do with it.
- You can use it if you feel that you can edit the code yourself and you can live with my future breaking changes.
TODOs and possible improvements:
- clean code obviously
- use classes to deserialize http responses
- cleaner certificate pinning: instead of rewriting http, implement certificate-pinning through a custom sslcontext
  - then, you can just pass this sslcontext to regular libs... not sure it's the way to go though
- Let select a specific account instead of the first one - in the account list from the config
- Let select a specific account instead of the first one - in the account list from the selected remote account
- Shows money in euros and not foreign currency
"""

import mimetypes
import socket
import ssl
from binascii import hexlify
from enum import Enum
from hashlib import sha256
from http.client import HTTPResponse
from io import BytesIO, StringIO
from itertools import chain
from json import dumps, loads
from pathlib import Path
from pprint import pprint as pp
from urllib.request import urlopen, Request
from uuid import uuid4
from ssl import Purpose, SSLContext, SSLSocket, _ASN1Object, PROTOCOL_TLS_CLIENT, CERT_REQUIRED, _ssl, CERT_NONE
from sys import argv
import os


colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])
COLOR_LEN = 4


class MultiPartForm(object):
    def __init__(self):
        self.form_fields = []
        self.files = []
        self.boundary = hexlify(os.urandom(16))

    def add_field(self, name, value):
        self.form_fields.append((name, value))

    def add_file(self, fieldname, filename, file_handle, mimetype=None):
        body = file_handle.read()
        mimetype = (mimetypes.guess_type(filename)[0] or "application/octet-stream") if mimetype is None else mimetypes
        self.files.append((fieldname, filename, mimetype, body))

    def __bytes__(self):
        part_boundary = b"--" + self.boundary
        gen_content_disposition = lambda field_name, file_name: (
            f'Content-Disposition: form-data; name="{field_name}"; filename="{file_name}"'.encode(encoding="ascii")
        )
        gen_content_type = lambda content_type: f"Content-Type: {content_type}".encode(encoding="ascii")
        forms_to_add = (
            [part_boundary, f'Content-Disposition: form-data; name="{name}"'.encode(encoding="ascii"), b"", value]
            for name, value in self.form_fields
        )
        files_to_add = (
            [part_boundary, gen_content_disposition(field_name, file_name), gen_content_type(content_type), b"", body]
            for field_name, file_name, content_type, body in self.files
        )
        return b"\r\n".join([*chain(*(chain(forms_to_add, files_to_add))), b"--" + self.boundary + b"--", b""])


# TODO : UT to ensure the checks are called for any python version
# TODO : UT to ensure those works if we create 2 contexts with 2 different certificatesa
# TODO : UT to ensure check is called if already opened socket gets wrapped
# TODO : UT to ensure check is called if connecting on new socket
# TODO : Ensure called with correct params, so that regular verif, and so getpeercert is enough
def make_pinned_ssl_context(pinned_sha_256):

    class PinnedSSLSocket(SSLSocket):
        def check_pinned_cert(self):
            der_cert_bin = self.getpeercert(True)
            if sha256(der_cert_bin).hexdigest() != pinned_sha_256:  # TODO : Check this is enough
                raise Exception("Incorrect certificate checksum")  # TODO : Better

        def connect(self, addr):  # Needed for when the context creates a new connection
            r = super().connect(addr)
            self.check_pinned_cert()
            return r

        def connect_ex(self, addr):  # Needed for when the context creates a new connection
            r = super().connect_ex(addr)
            self.check_pinned_cert()
            return r

    class PinnedSSLContext(SSLContext):
        sslsocket_class = PinnedSSLSocket

        def wrap_socket(  # Needed for when we wrap an exising socket
            self,
            sock,
            server_side=False,
            do_handshake_on_connect=True,
            suppress_ragged_eofs=True,
            server_hostname=None,
            session=None
        ):
            ws = super().wrap_socket(
                sock,
                server_side=server_side,
                do_handshake_on_connect=do_handshake_on_connect,
                suppress_ragged_eofs=suppress_ragged_eofs,
                server_hostname=server_hostname,
                session=session
            )
            ws.check_pinned_cert()
            return ws

    def create_pinned_default_context(purpose=Purpose.SERVER_AUTH, *, cafile=None, capath=None, cadata=None):
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
            context.load_default_certs(purpose)  # Try loading default system root CA certificates, this may fail silently.
        if hasattr(context, "keylog_filename"):  # OpenSSL 1.1.1 keylog file
            keylogfile = os.environ.get("SSLKEYLOGFILE")
            if keylogfile and not sys.flags.ignore_environment:
                context.keylog_filename = keylogfile
        return context

    return create_pinned_default_context()



def get_body(addr, url, cert_checksum, user_agent=None, authorization=None, json=True):
    context = make_pinned_ssl_context(cert_checksum)
    headers = {
        "User-Agent": "",  # Otherwise would send default User-Agent, that does fail
        **({"Authorization": str(authorization)[2:-1]} if authorization is not None else {}),
    }
    r = urlopen(Request("https://" + (addr+url).decode(), None, headers=headers), context=context)
    return loads(r.read()) if json else r.read()  # TODO : json is not a param, populate if type?..

def post_body(addr, url, file_bytes, cert_checksum, user_agent=None, authorization=None, json=True, additional_headers=None):
    context = make_pinned_ssl_context(cert_checksum)
    form = MultiPartForm()
    form.add_file("file", "file.pdf", file_handle=BytesIO(file_bytes))
    body = bytes(form)
    headers = {
        "User-Agent": "",  # Otherwise would send default User-Agent, that does fail
        "Content-Type": f"multipart/form-data; boundary={form.boundary.decode()}",  # Needed for file upload
        #"X-Qonto-Idempotency-Key": str(uuid4()),  # TODO : param this
        **({"Authorization": str(authorization)[2:-1]} if authorization is not None else {}),
        **(additional_headers or {}),
    }
    request = Request("https://" + (addr+url).decode(), body, headers=headers)
    r = urlopen(request, context=context)  # TODO: data doesnt work?
    return loads(r.read()) if json else r.read()  # TODO : json is not a param, populate if type?..

def usage(wrong_config=False, wrong_command=False, wrong_arg_len=False):
    output_lines = [
        "bank - KISS banking client"
        # TODO
        "==========================",
        """~/.config/bank/config.json => {"accounts": [ACCOUNT_INFOS, ...], "certificates": {"qonto": "..."]}"""
        "  - ACCOUNT_INFOS = {",
        '    "id": "name-XXXX"',
        '    "secret_key": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"',
        '    "local_store_path": "XX"',
        "  - certificates = sha256sum of der_cert_bin",
        "=======================",
        "- bank                   ==> list all",
        "=======================",
        "This should help you get files TODO",
    ]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


class Account:
    def __init__(self, account_dict, cert_checksum):
        self.endpoint = b"thirdparty.qonto.com"
        account_keys = ["id", "secret_key", "local_store_path"]
        self.organization_slug, self.secret_key, self.local_store_path = (account_dict[k] for k in account_keys)
        self.account_infos = None
        self.cert_checksum = cert_checksum

    @property
    def auth_str(self):
        return str.encode(f"{self.organization_slug}:{self.secret_key}")

    def get_infos(self):
        self.account_infos = get_body(
            self.endpoint, b"/v2/organization", self.cert_checksum, authorization=self.auth_str
        )

    def print_infos(self):
        self.get_infos()
        pp(self.account_infos)

    def get_transaction_cache(self):
        # TODO: Parameterize - no need to lock if clean overwrite
        try:
            with (Path.home() / ".config" / "bank" / "DIRTYCACHE.json").open() as f:
                return loads(f.read())
        except Exception:
            return {}

    def save_transaction_cache(self, obtained_transactions):
        # TODO: Parameterize / lock / better overwrite
        new_cache = {**self.get_transaction_cache(), **{t["transaction_id"]: t for t in obtained_transactions}}
        with (Path.home() / ".config" / "bank" / "DIRTYCACHE.json").open("w") as f:
            f.write(dumps(new_cache))

    def get_full_transactions(self, partial_id):
        return [v for k, v in self.get_transaction_cache().items() if k.endswith(partial_id)]

    def get_one_transaction(self, partial_id):
        transactions = self.get_full_transactions(partial_id)
        if len(transactions) == 0:
            raise Exception("No transaction found")  # TODO: Better
        if len(transactions) > 1:
            raise Exception("More than one transaction found")  # TODO: Better
        return transactions[0]

    def show(self, partial_id):
        pp(self.get_one_transaction(partial_id))

    def show_attachments(self, transaction_id):
        url = b"/v2/transactions/"+transaction_id.encode()+b"/attachments"
        pp(get_body(self.endpoint, url, self.cert_checksum, authorization=self.auth_str))

    def justify(self, partial_id, file):
        transaction = self.get_one_transaction(partial_id)
        idempo = str(uuid4())
        print(f"Idempotent id: {idempo}")
        try:
            r = post_body(
                self.endpoint, b"/v2/transactions/"+transaction["id"].encode()+b"/attachments",
                file, self.cert_checksum, authorization=self.auth_str,
                additional_headers={"X-Qonto-Idempotency-Key": idempo}  # TODO : consume this
            )
        except Exception as e:
            import pdb; pdb.set_trace()
            raise
        assert r == {}  # TODO Better
        # TODO NOW USE IDEMPOTENCY, CLEAN CODE, SHOW ID

    def print_transactions(self, attachments=None):
        self.get_infos()
        account_id = str.encode(self.account_infos["organization"]["bank_accounts"][0]["id"])
        assert len(account_id) == 36 and all(chr(c) in "0123456789abcdef-" for c in account_id)  # TODO real exception
        with_attachments_query = (
            b"with_attachments=" + (b"true" if attachments else b"false") + b"&"
            if attachments is not None
            else b""
        )
        url = b"/v2/transactions?" + with_attachments_query + b"bank_account_id="
        ts = get_body(self.endpoint, url + account_id, self.cert_checksum, authorization=self.auth_str)
        self.save_transaction_cache(ts["transactions"])
        for t in ts["transactions"]:
            short_transaction_id = f" {t['transaction_id'][-6:]} "
            label = f"{Color.WHITE.value} {t['label']}{Color.DIM.value} "
            money = int(t["local_amount_cents"])
            money_str = Color.RED.value if t["side"] == "debit" else Color.GREEN.value
            money_str += f" {'-' if t['side'] == 'debit' else '+'}{money // 100},{str(money % 100).zfill(2)} "
            emitted_at = f" {t['emitted_at'][:10]}"
            print(
                f"{Color.DIM.value}-"
                f"{Color.PURP.value}{short_transaction_id}"
                f"{Color.DIM.value}-"
                f"{label.ljust(60 + COLOR_LEN * 2, '-')}"
                f"{money_str.rjust(16 + COLOR_LEN, '-')}"
                f"{Color.DIM.value}-"
                f"{Color.PURP.value}{emitted_at}"
            )  # TODO : local_amount vs amount?
        meta_gen = (f"{Color.PURP.value}{k}{Color.DIM.value}={Color.WHITE.value}{v}" for k, v in ts["meta"].items())
        print("", f"{Color.DIM.value} - ".join(meta_gen))

    def find_transaction(self, partial_id):
        pass  # TODO : Only accept partal_id from previously shown ids


class Config:
    def __init__(self, input_str):
        json = loads(input_str)
        self.certificates = {"qonto": json["certificates"].get("qonto").lower()}
        if any(
            (c is not None and (not isinstance(c, str) or len(c) != 64 or any(v not in "0123456789abcdef" for v in c)))
            for c in self.certificates.values()
        ):
            raise Exception  # TODO Better
        self.accounts = [Account(a, self.certificates["qonto"]) for a in json["accounts"]]


def consume_subparameters(allowed_parameters, parameters):
    unknown_parameters = [
        parameter
        for parameter in parameters
        if not any(parameter.startswith(p) for p in allowed_parameters)
    ]
    r = {}


def main():
    try:
        with (Path.home() / ".config" / "bank" / "config.json").open() as f:
            config = Config(f.read())
    except Exception:
        return usage(wrong_config=True)
    if len(argv) < 2 or argv[1] == "accounts":
        return config.accounts[0].print_infos()
    if argv[1] == "transactions":
        if "no-invoice" in argv[2:]:
            return config.accounts[0].print_transactions(attachments=False)  # TODO: Better obviously
        return config.accounts[0].print_transactions()
        # TODO: parameters to limit year, show missing invoices only
        # TODO: year<2024 / year<=2024 / year=2024 etc
        # TODO: missing=True / missing=true / missing=y
    if argv[1] == "show":
        if len(argv) != 3:
            return usage()
        return config.accounts[0].show(argv[2])
    if argv[1] == "show-attachments":
        if len(argv) != 3:
            return usage()
        return config.accounts[0].show_attachments(argv[2])
    if argv[1] == "justify":
        if len(argv) != 4:
            return usage()
        with open(argv[3], "rb") as f:
            file = f.read()
        return config.accounts[0].justify(argv[2], file)
    return usage()


if __name__ == "__main__":
    main()
