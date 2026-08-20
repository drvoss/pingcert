# pingcert

**한국어 문서: [README.ko.md](README.ko.md)**

`pingcert` is a line-oriented network diagnostic CLI for DNS, destination
reachability, route tracing, TCP connectivity, TLS negotiation, and certificate
policy. Its text output fits incident logs, while versioned JSON and NDJSON
output can be consumed by automation.

> Only diagnose systems and networks you own or are authorized to test. Redact
> hostnames, IP addresses, and certificate details before sharing output.

## Why pingcert

`ping` cannot tell whether a failure is DNS, TCP, TLS, or certificate related,
and many networks block ICMP. `pingcert check` runs the application-relevant
checks and treats ping/trace failures as warnings when TCP, TLS, and certificate
validation succeed.

Use the focused subcommands when you need only one part of the diagnosis:

- `check`: DNS + TCP/TLS/certificate + concurrent ping and trace
- `cert`: DNS + TCP/TLS/certificate
- `ping`: DNS + destination ping
- `trace`: DNS + route trace

## Build

Requires Go 1.26.6 or newer and uses only the Go standard library. The patch
minimum includes security fixes in TLS and certificate parsing paths.

Install directly:

```sh
go install github.com/drvoss/pingcert@latest
```

Or build from a local clone:

```sh
go test ./...
go build -o pingcert .
```

On Windows, use `go build -o pingcert.exe .`.

## Quick start

```sh
pingcert example.com
pingcert check example.com:443
pingcert cert --warn-before 720h example.com
pingcert ping -4 --count 4 example.com
pingcert trace --max-hops 20 example.com
pingcert --format json --no-trace example.com
pingcert cert --format ndjson --server-name example.com 192.0.2.10
```

Targets may be a hostname, `host:port`, an IPv6 literal, or an HTTPS URL. The
default port is 443. Run `pingcert --help` for the complete flag list.

## Output

- `text`: human-readable streaming output
- `json`: one schema-versioned report written at the end
- `ndjson`: schema-versioned events written as each stage completes

The command-based ping/traceroute backend is always labelled
`backend=command degraded=true`. An unresponsive intermediate hop does not by
itself prove filtering or forwarding loss.

## Certificate policy

The default warning threshold is 30 days (`720h`). Use `--warn-before` to
change it and `--fail-before` to make near-expiry a failure. Certificate checks
include the verified chain, hostname, validity window, issuer, subject, and
SHA-256 fingerprint. Use `--server-name` when connecting to an IP address that
serves a named TLS virtual host.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Required checks passed; warnings may still be present |
| `1` | Target, TLS, or certificate policy failure |
| `2` | Invalid arguments |
| `3` | Local backend or output failure |
| `130` | Interrupted by the user |

In `check` mode, DNS, TCP, TLS, and certificate validation are required. Ping
and trace failures are reported as warnings because ICMP is commonly blocked.

## Platform notes and limitations

- Ping and traceroute invoke platform commands (`ping`, `tracert`, or
  `traceroute`), so detail and permissions depend on the OS.
- Locale-aware fixtures cover common English and Korean Windows ping output,
  but every localized OS variant has not been tested.
- The whole run defaults to a 10-second deadline; large hop/count values can be
  cut short unless `--overall-timeout` is raised.
- This is a diagnostic snapshot, not a monitoring daemon or a load tester.
- JSON schema version `1` is pre-1.0 and can evolve in a future release.

## Development

```sh
gofmt -w .
go vet ./...
go test ./...
```

Tests use local data and generated certificates; they do not require the public
network. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
