# bank
KISS banking Client

## WARNING
**I don't recommand using this as-is.** This a PoC, usable by me because I know what I want to do with it.

## Help
```
bank - KISS banking client
──────────────────────────
- bank help                         ==> show this help
  + config                          ==> helps you with the configuration file
──────────────────────────
- bank                              ==> gives accounts infos
- bank transactions                 ==> list transactions for first account
  + no-invoice                      ==> only show transactions without an invoice
- bank j       end_of_id file_path  ==> add a file to a transaction by the end of its id
- bank justify end_of_id file_path  ==> add a file to a transaction by the end of its id
──────────────────────────
Only working with Qonto for now, for my specific use-cases
```
