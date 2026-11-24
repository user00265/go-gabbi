# Test configurations

TrustedQSL configuration files used by the config tests. They are test data
only and are not part of the library. See `NOTICE` for their license.

| File | Version | Source | Fetched | Size | sha256 |
|---|---|---|---|---|---|
| `config-11.34.tq6` | 11.34 | `https://lotw.arrl.org/lotw/config.tq6`, unchanged (gzip, `<tqsldata>` wrapper) | 2026-11-24 | 67,225 bytes | `43984e315bdbfc8e0d4a6db3fa42d5626f4fc0cc57d9926cf05b919dca160ba2` |
| `config-11.35.xml` | 11.35 | TrustedQSL `src/config.xml` at HEAD `9b30153` (2.8.8), byte-identical to Debian `trustedqsl` 2.8.7-1 | 2026-11-24 | 480,545 bytes | `5a0747d35f5788f8b14757be2fc2f1ce7d0857bd0c0c4def0a30aef72d2f3538` |

`config-11.34.tq6` decompresses to 480,178 bytes with sha256
`5d7561f8c3862fce89f34f0c8a85736bc33a6e13743b04eb22951b2d138e149a`.

The only content difference between the two is that 11.35 adds the satellite
`RS95S`. The live file also orders its sections differently.

Never edit these files to make a test pass. Replace them with a fresh copy
from the same source and update this table.
