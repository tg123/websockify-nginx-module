# End-to-end tests

A modern, self-contained end-to-end test suite for the websockify nginx module.
It builds nginx with the module, starts a real TCP echo upstream (a stand-in for
a websockify backend such as a VNC server), and drives the public endpoint with a
standards-compliant WebSocket client ([`ws`](https://github.com/websockets/ws)).

## What is covered

- `binary` subprotocol round trips raw payloads
- `base64` subprotocol decodes client frames and re-encodes upstream data
- `binary` is preferred when the client offers both subprotocols
- large payloads stream through the proxy intact
- a connection with no supported subprotocol is rejected
- a dead upstream tears the WebSocket connection down instead of echoing data

## Running locally

You need Node.js 18+ and a C toolchain (gcc, make, PCRE/zlib/OpenSSL headers).

```bash
cd e2e
npm install

# Build nginx with the module and capture the binary path.
export NGINX_BIN="$(./build-nginx.sh)"

npm test
```

To test against an nginx you have already built with the module, skip
`build-nginx.sh` and point `NGINX_BIN` at your binary:

```bash
NGINX_BIN=/path/to/nginx npm test
```

You can choose the nginx version that `build-nginx.sh` compiles:

```bash
NGINX_VERSION=1.27.3 ./build-nginx.sh
```

## Continuous integration

`.github/workflows/e2e.yml` runs this suite on every push and pull request across
several nginx versions.
