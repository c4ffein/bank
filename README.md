# bank
KISS banking Client

## WARNING
**I don't recommand using this as-is.** This a PoC, usable by me because I know what I want to do with it.

## Help
```
bank - KISS banking client
==========================
~/.config/bank/config.json => {"accounts": [ACCOUNT_INFOS, ...], "certificates": {"qonto": "..."]}  - ACCOUNT_INFOS = {
    "id": "name-XXXX"
    "secret_key": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    "local_store_path": "XX"
  - certificates = sha256sum of der_cert_bin
=======================
- bank                              ==> gives accounts infos
- bank transactions                 ==> list transactions for first account
  + no-invoice                      ==> only show transactions without an invoice
- bank justify end_of_id file_path  ==> add a file to a transaction by the end of its id
=======================
This should help you get files TODO
```
