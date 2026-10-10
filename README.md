# iping

Find the fastest IPs in a range. iping probes every address in a CIDR range (or a file of ranges) in random order, times the TCP connect, TLS handshake, or QUIC handshake, and reports the 10 fastest hosts by minimum RTT. All responsive hosts are saved to a CSV file.

## Install

```sh
go install github.com/PeronGH/iping@latest
```

## Usage

```
iping tcp <cidr|file> [flags]   # TCP connect time (default port 80)
iping tls <cidr|file> [flags]   # TCP connect + TLS handshake (default port 443)
```

The target is a CIDR, a single IP, or a file with one CIDR or IP per line (blank lines and `#` comments are ignored). Overlapping ranges are merged.

| Flag | Default | Description |
| --- | --- | --- |
| `-p, --port` | 80 / 443 | Port to connect to |
| `-c, --count` | 4 | Attempts per IP |
| `-W, --timeout` | 2s | Timeout per attempt |
| `-w, --workers` | 1024 | Concurrent workers |
| `-o, --output` | `<target>-<protocol>.csv` | CSV file for responsive hosts; `/dev/null` disables it |

`tls` only:

| Flag | Default | Description |
| --- | --- | --- |
| `--sni` | none | Server name to send; the certificate is verified against it |
| `-k, --insecure` | off | Skip certificate verification when `--sni` is set |
| `--quic` | off | QUIC handshake over UDP instead of TCP+TLS (one round trip fewer) |
| `--alpn` | none, `h3` with `--quic` | ALPN protocols to offer |

Without `--sni`, no SNI is sent and certificates are not verified.

## Example

```sh
iping tls 104.16.16.0/24 --sni cloudflare.com --quic
```

This prints the 10 fastest hosts and overall statistics, and saves every responsive host to `104.16.16.0_24-quic.csv` with the columns `ip,sent,received,loss_pct,min_ms,avg_ms,max_ms`.
