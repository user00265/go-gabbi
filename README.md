# go-gabbi

go-gabbi implements the TrustedQSL / GAbbI signing and certificate formats used by ARRL's Logbook of The World (LoTW).

This project is independent and is not affiliated with or endorsed by ARRL.

go-gabbi is a pure-Go library. It loads a TrustedQSL `.p12` callsign
certificate and signs QSO records into the GAbbI text that a `.tq8` file
holds. It has no binary, reads no files and makes no network calls. Your
application owns the streams, the keys, the duplicate store and the
configuration.

## Install

```sh
go get github.com/user00265/go-gabbi
```

## Configuration

Signing needs the TrustedQSL configuration (`config.xml`, which LoTW
publishes as `config.tq6`). The library embeds no configuration and has no
download function. Nothing works until you pass it one, so fetching and
storing it is your application's job:

1. On startup, load the stored config, if you have one, and pass it to
   `ParseConfig`.
2. Periodically, and whenever no config is stored, GET
   `https://lotw.arrl.org/lotw/config_xml_version`. The body is one line:
   `config.xml: Version <major>.<minor>`. The server's cache lifetime is 14
   days, which makes a sensible polling interval.
3. If no config is stored, or the online version is newer, GET
   `https://lotw.arrl.org/lotw/config.tq6`, store the bytes unchanged, and
   pass them to `ParseConfig`.
4. Keep the previous config until the new one parses without error.
5. Always verify TLS. The file carries no signature, so HTTPS is its only
   protection.
6. If `ParseConfig` returns `ErrConfigOutdated` (the config is older than
   the minimum supported version, 11.34), download it again. If LoTW itself
   is serving an older file, report that and do not sign.

## Usage

A short sketch with error handling left out. The runnable examples in the
package documentation (`ExampleSign_all` and others) show it in full. The
API is still settling:

```go
cfg, err := gabbi.ParseConfig(bytes.NewReader(storedConfig))
cred, _, err := gabbi.LoadPKCS12(p12Bytes, "")
creds := []gabbi.Credential{cred}

st := gabbi.Station{
	Call:       "KF0TST",
	DXCC:       291,
	GridSquare: "EM10dh",
	Fields:     map[string]string{"US_STATE": "TX", "US_COUNTY": "Travis"},
}
qsos := []gabbi.QSO{{Call: "W1AW", Band: "20M", Mode: "SSB", Freq: "14.250",
	Time: time.Date(2026, 11, 1, 15, 30, 0, 0, time.UTC)}}

zw := gzip.NewWriter(out) // a .tq8 is the GAbbI text, gzipped
report, err := gabbi.Sign(ctx, zw, cfg, creds, st, slices.Values(qsos),
	gabbi.SignOptions{Action: gabbi.Compliant, Dupes: store})
if err == nil {
	err = zw.Close()
}
// Commit the store's transaction only if report.Commit is true.
```

Check every error in real code. Errors wrap sentinels such as
`ErrInvalidQSO` and `ErrDateRange` (use `errors.Is`), and per-QSO problems
arrive as `*QSOError` (use `errors.As`).

## License

MIT. See `LICENSE`. Third-party notices are in `NOTICE`.
