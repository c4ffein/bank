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
"""

import socket
import ssl
from enum import Enum
from hashlib import sha256
from http.client import HTTPResponse
from json import loads
from pathlib import Path
from pprint import pprint as pp

Color = Enum("Color", [("RED", "\033[31m"), ("GREEN", "\033[32m"), ("DIM", "\033[34m"), ("WHITE", "\033[39m")])
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
        "=======================",
        "- bank                   ==> list all",
        "=======================",
        "This should help you get files TODO",
    ]
    print("\n" + "\n".join(output_lines) + "\n")
    return -1


class Account:
    def __init__(self, account_dict):
        # TODO : cert_checksum in config, passed directly in __init__ through intermediary, use in methods
        self.endpoint = b"thirdparty.qonto.com"
        account_keys = ["id", "secret_key", "local_store_path"]
        self.organization_slug, self.secret_key, self.local_store_path = (account_dict[k] for k in account_keys)
        self.account_infos = None

    @property
    def auth_str(self):
        return str.encode(f"{self.organization_slug}:{self.secret_key}")

    def get_infos(self, cert_checksum):
        self.account_infos = get_body(self.endpoint, b"/v2/organization", cert_checksum, authorization=self.auth_str)

    def print_infos(self, cert_checksum):
        pp(self.account_infos)

    def print_transactions(self, cert_checksum):
        self.get_infos(cert_checksum)
        account_id = str.encode(self.account_infos["organization"]["bank_accounts"][0]["id"])
        assert len(account_id) == 36 and all(chr(c) in "0123456789abcdef-" for c in account_id)
        url = b"/v2/transactions?bank_account_id="
        ts = get_body(self.endpoint, url + account_id, cert_checksum, authorization=self.auth_str)
        for t in ts["transactions"]:
            label = f"{Color.WHITE.value}{t['label']}{Color.DIM.value} "
            money = int(t["local_amount_cents"])
            money_str = Color.RED.value if t["side"] == "debit" else Color.GREEN.value
            money_str += f" {'-' if t['side'] == 'debit' else '+'}{money // 100},{str(money % 100).zfill(2)}"
            print(
                f"{Color.DIM.value}- {label.ljust(60 + COLOR_LEN * 2, '-')}{money_str.rjust(11 + COLOR_LEN, '-')}"
            )  # TODO : local_amount vs amount?
        pp(ts["transactions"][0])
        pp(ts["meta"])  # TODO : Handle this, show all year through iteration, param to set min/max page?..


class Config:
    def __init__(self, input_str):
        json = loads(input_str)
        self.certificates = {"qonto": json["certificates"].get("qonto")}
        if any((c is not None and (not isinstance(c, str) and len(c) != 64)) for c in self.certificates):
            raise Exception
        self.accounts = [Account(a) for a in json["accounts"]]


def main():
    try:
        with (Path.home() / ".config" / "bank" / "config.json").open() as f:
            config = Config(f.read())
    except Exception:
        return usage(wrong_config=True)
    # TODO : parameterize next 2 lines
    # config.accounts[0].print_infos(config.certificates["qonto"])
    config.accounts[0].print_transactions(config.certificates["qonto"])
    # TODO : set an invoice
    # TODO : parameters to limit year, show missing invoices only
    # TODO : show date of transaction


if __name__ == "__main__":
    main()
