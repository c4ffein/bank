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
"""

import socket
import ssl
from enum import Enum
from hashlib import sha256
from http.client import HTTPResponse
from json import dumps, loads
from pathlib import Path
from pprint import pprint as pp
from sys import argv

colors = {"RED": "31", "GREEN": "32", "PURP": "34", "DIM": "90", "WHITE": "39"}
Color = Enum("Color", [(k, f"\033[{v}m") for k, v in colors.items()])
COLOR_LEN = 4


def custom_socket(addr, url, cert_checksum):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    wrapped_socket = ssl.create_default_context().wrap_socket(sock, server_hostname=addr)
    try:
        wrapped_socket.connect((addr, 443))
    except Exception:
        return None  # TODO : Better handling
    der_cert_bin = wrapped_socket.getpeercert(True)
    if sha256(der_cert_bin).hexdigest() != cert_checksum:  # TODO : Check this is enough
        raise Exception("Incorrect certificate checksum")
    return wrapped_socket


def get(addr, url, cert_checksum, user_agent=None, authorization=None, json=False):
    sock = custom_socket(addr, url, cert_checksum)
    if sock is None:
        raise Exception("Unable to open socket")  # TODO : Better
    request_header = b"GET " + url + b" HTTP/1.0\r\nHost: " + addr
    request_header += b"\r\nUser-Agent: " + user_agent if user_agent else b""
    request_header += b"\r\nAuthorization: " + authorization if authorization else b""
    request_header += b"\r\n\r\n"
    sock.send(request_header)
    response = HTTPResponse(sock)
    response.begin()
    if json:
        pass  # TODO : Parse the Content-Type and decode depending of charset.
        # TODO : Don't try to implement this. See the top TODO for what to implement instead of this. Unless...
        # if response.getheader("Content-Type") != "application/json; charset=utf-8":
        #    raise Exception("Content-Type isn't application/json; charset=utf-8")
        # if response.getheader("Content-Type") != "application/json":
        #    raise Exception("Content-Type isn't application/json")
    body = response.read()
    sock.close()
    return response, body


def get_body(addr, url, cert_checksum, user_agent=None, authorization=None, json=True):
    r = get(addr, url, cert_checksum, user_agent=user_agent, authorization=authorization, json=json)[1]
    return loads(r) if json else r


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

    def justify(self, partial_id, file):
        pp(self.get_one_transaction(partial_id))  # TODO: Actually justify here

    def print_transactions(self, attachments=None):
        self.get_infos()
        account_id = str.encode(self.account_infos["organization"]["bank_accounts"][0]["id"])
        assert len(account_id) == 36 and all(chr(c) in "0123456789abcdef-" for c in account_id)  # TODO real exception
        with_attachments_query = (
            b"with_attachments=" + (b"true" if attachments else b"false") + b"&"
            if attachments
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
    if argv[1] == "justify":
        if len(argv) != 4:
            return usage()
        return config.accounts[0].justify(argv[2], None)  # TODO : set an invoice
    return usage()


if __name__ == "__main__":
    main()
