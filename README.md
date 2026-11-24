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

An illustrative sketch. It is not compiled, and the API is still settling:

```go
cfg, err := gabbi.ParseConfig(bytes.NewReader(storedConfig))
cert, key, _, err := gabbi.LoadPKCS12(p12Bytes, "")
creds := []gabbi.Credential{{Cert: cert, Signer: key}}

zw := gzip.NewWriter(out) // a .tq8 is the GAbbI text, gzipped
report, err := gabbi.Sign(ctx, zw, cfg, creds, station, qsos,
	gabbi.SignOptions{Action: gabbi.Compliant, Now: time.Now()})
if err == nil {
	err = zw.Close()
}
```

Check every error in real code. Errors wrap sentinels such as
`ErrInvalidQSO` and `ErrDateRange` (use `errors.Is`), and per-QSO problems
arrive as `*QSOError` (use `errors.As`).

## License

MIT. See `LICENSE`. Third-party notices are in `NOTICE`.
