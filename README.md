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
  + only-invoice                    ==> only show transactions with an invoice
  + use-original-currency           ==> show amounts in foreign currency (when applicable)
  + date=2024                       ==> transactions from year 2024
  + date>=2024                      ==> transactions from 2024 onwards
  + date<2024                       ==> transactions before 2024
  + date>=2023 date<2025            ==> transactions in range
- bank j        end_of_id file_path ==> add a file to a transaction by the end of its id
- bank justify  end_of_id file_path ==> add a file to a transaction by the end of its id
- bank d        end_of_id [out_dir] ==> download attachments for a transaction
- bank download end_of_id [out_dir] ==> download attachments for a transaction
- bank hash     end_of_id           ==> show SHA256 hashes of attachments
- bank sha256   end_of_id           ==> show SHA256 hashes of attachments
──────────────────────────
Only working with Qonto for now, for my specific use-cases
```
