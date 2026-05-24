## Yet another SIP003 plugin for shadowsocks, based on [v2ray](https://github.com/v2fly/v2ray-core)

[![CircleCI](https://circleci.com/gh/shadowsocks/v2ray-plugin.svg?style=shield)](https://circleci.com/gh/shadowsocks/v2ray-plugin)
[![Releases](https://img.shields.io/github/downloads/shadowsocks/v2ray-plugin/total.svg)](https://github.com/shadowsocks/v2ray-plugin/releases)
[![Language: Go](https://img.shields.io/badge/go-1.13+-blue.svg)](https://github.com/shadowsocks/v2ray-plugin/search?l=go)
[![Go Report Card](https://goreportcard.com/badge/github.com/shadowsocks/v2ray-plugin)](https://goreportcard.com/report/github.com/shadowsocks/v2ray-plugin)
[![License](https://img.shields.io/github/license/shadowsocks/v2ray-plugin.svg)](LICENSE)

## Build

* `go build`
* Alternatively, you can grab the latest nightly from Circle CI by logging into Circle CI or adding `#artifacts` at the end of URL like such: https://circleci.com/gh/shadowsocks/v2ray-plugin/20#artifacts

## Usage

See command line args for advanced usages.

### Shadowsocks over websocket (HTTP)

Warning: HTTP only provides a moderate (but lightweight) traffic obfuscation. Cautious users should refrain from using this mode.

On your server

```sh
ss-server -c config.json -p 80 --plugin v2ray-plugin --plugin-opts "server"
```

On your client

```sh
ss-local -c config.json -p 80 --plugin v2ray-plugin
```

### Shadowsocks over websocket (HTTPS)

On your server

```sh
ss-server -c config.json -p 443 --plugin v2ray-plugin --plugin-opts "server;tls;host=mydomain.me"
```

On your client

```sh
ss-local -c config.json -p 443 --plugin v2ray-plugin --plugin-opts "tls;host=mydomain.me"
```

### Shadowsocks over quic

On your server

```sh
ss-server -c config.json -p 443 --plugin v2ray-plugin --plugin-opts "server;mode=quic;host=mydomain.me"
```

On your client

```sh
ss-local -c config.json -p 443 --plugin v2ray-plugin --plugin-opts "mode=quic;host=mydomain.me"
```

### SIP003U UDP forwarding

SIP003U support is split between shadowsocks-libev and this plugin:

* shadowsocks-libev `--plugin-mode` decides whether UDP relay traffic is routed through the plugin port.
* v2ray-plugin `udpMode` decides whether this plugin starts its native UDP relay and which UDP transport it uses.

The TCP transport still follows `mode`. Enabling UDP forwarding does not change an existing TCP deployment unless both `mode=websocket` and `udpMode=websocket` are used on the server, where the plugin owns the public WebSocket listener and routes TCP and UDP by path.

#### UDP over QUIC Datagram

On your server

```sh
ss-server -c config.json -p 443 -u --plugin v2ray-plugin --plugin-mode tcp_and_udp --plugin-opts "server;tls;host=mydomain.me;udpMode=quic"
```

On your client

```sh
ss-local -c config.json -p 443 -u --plugin v2ray-plugin --plugin-mode tcp_and_udp --plugin-opts "tls;host=mydomain.me;udpMode=quic"
```

To keep TCP on WebSocket while sending UDP through QUIC Datagram, leave `mode` unset or set it to `websocket`:

```sh
ss-server -c config.json -p 443 -u --plugin v2ray-plugin --plugin-mode tcp_and_udp --plugin-opts "server;tls;host=mydomain.me;mode=websocket;udpMode=quic"
ss-local -c config.json -p 443 -u --plugin v2ray-plugin --plugin-mode tcp_and_udp --plugin-opts "tls;host=mydomain.me;mode=websocket;udpMode=quic"
```

#### UDP over WebSocket

Use `udpMode=websocket` when UDP traffic also needs to pass through an HTTP/WebSocket proxy path, for example a regular Cloudflare proxied hostname. The TCP WebSocket path remains controlled by `path`; the UDP WebSocket path is controlled by `udpPath` and defaults to `/ray-udp`.

On your server

```sh
ss-server -c config.json -p 443 -u --plugin v2ray-plugin --plugin-mode tcp_and_udp --plugin-opts "server;tls;host=mydomain.me;mode=websocket;path=/ray;udpMode=websocket;udpPath=/ray-udp"
```

On your client

```sh
ss-local -c config.json -p 443 -u --plugin v2ray-plugin --plugin-mode tcp_and_udp --plugin-opts "tls;host=mydomain.me;mode=websocket;path=/ray;udpMode=websocket;udpPath=/ray-udp"
```

In this mode the server-side plugin listens on the public TCP port, accepts `/ray-udp` itself, and reverse-proxies the normal TCP WebSocket path to an internal loopback v2ray-core listener. `path` and `udpPath` must both start with `/`, must not contain `?` or `#`, and must be different.

`udpMode=websocket` can also be combined with `mode=quic`. In that layout, TCP relay traffic uses v2ray-core QUIC on UDP while UDP relay traffic uses the plugin's WebSocket listener on TCP. Because TCP and UDP sockets are separate, the same numeric port can be reused without the public WebSocket reverse-proxy layer.

Each encrypted Shadowsocks UDP packet is sent as one WebSocket binary message. The plugin preserves packet boundaries and keeps Shadowsocks UDP payloads opaque; it does not parse, decrypt, modify, coalesce, or fragment UDP payloads.

`udpTimeout` controls the plugin's own UDP flow table and defaults to 30 seconds:

```sh
ss-local -c config.json -p 443 -u --plugin v2ray-plugin --plugin-mode tcp_and_udp --plugin-opts "tls;host=mydomain.me;udpMode=quic;udpTimeout=60"
```

This timeout is separate from shadowsocks-libev's internal UDP relay timeout. The implementation does not add separate UDP local or remote port options and does not fragment oversized UDP datagrams; oversized packets are dropped and logged. Certificate options are shared with the TCP TLS path, so certificate mismatch errors usually mean `host`, `cert`, `certRaw`, or `key` differs between client and server. If TCP works but UDP bypasses the plugin, check that shadowsocks-libev was started with `--plugin-mode tcp_and_udp` or another UDP-capable plugin mode.

`udpMode=quic` uses QUIC Datagram and needs end-to-end UDP reachability to the plugin. It will not work through a regular Cloudflare orange-cloud HTTP proxy because Cloudflare terminates QUIC/HTTP3 at the edge and speaks HTTP to the origin. `udpMode=websocket` is Cloudflare-compatible, but it carries UDP packets over a reliable WebSocket/TCP stream, so packet loss can cause head-of-line blocking.

### Issue a cert for TLS and QUIC

`v2ray-plugin` will look for TLS certificates signed by [acme.sh](https://github.com/acmesh-official/acme.sh) by default.
Here's some sample commands for issuing a certificate using CloudFlare.
You can find commands for issuing certificates for other DNS providers at acme.sh.

```sh
curl https://get.acme.sh | sh
~/.acme.sh/acme.sh --issue --dns dns_cf -d mydomain.me
```

Alternatively, you can specify path to your certificates using option `cert` and `key`.

### Use `certRaw` to pass certificate

Instead of using `cert` to pass the certificate file, `certRaw` could be used to pass in PEM format certificate, that is the content between `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` without the line breaks.
