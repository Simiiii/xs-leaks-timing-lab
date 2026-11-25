# Modern Web Timing Attacks & XS-Leaks (Local Docker Demo)

An interactive, single-container lab demonstrating how cross-site timing attacks and XS-Leaks infer whether a user is logged in. It covers the 2015 Service Worker cache timing attack (*"The Clock is Still Ticking"*, Van Goethem et al., CCS 2015), a modern `SameSite=Lax` popup bypass, and the browser defenses that stop them.

## Architecture

A single Docker container runs two independent Flask apps: **Victim** (`http://victim.localhost:8001`) and **Attacker** (`http://attacker.localhost:8002`).

Both `*.localhost` hostnames resolve to loopback automatically, while modern browsers treat them as separate cross-site yet trustworthy origins—allowing Service Workers and `SameSite=None; Secure` cookies over HTTP.

## What This Demonstrates
- **Victim (`http://victim.localhost:8001`):** Serves a 2 MB JS subresource (`/private-group/asset.js`, for Demo A — passes modern ORB while staying opaque to `no-cors` fetches) and an HTML page with 3 hidden iframes (`/private-group`, for Demo B) when logged in, vs. 2 kB / 0 iframes when logged out, both with `Cache-Control: no-store` and live toggles for cookie policies, random server delays, and modern security headers.
- **Attacker (`http://attacker.localhost:8002`):** Runs two cross-site probes against the victim:
  1. **2015 Service Worker Timing vs. Classic Timing:** Shows that random server delays break classic network timing, while post-download Service Worker Cache API timing still reveals response size (and ignores `Cache-Control: no-store`). Includes a run-history table for side-by-side comparison.
  2. **2026 `SameSite=Lax` Bypass (`window.open`):** Shows that modern default cookies stop background subrequest leaks, but top-level navigations still carry `SameSite=Lax` cookies unless blocked by `Cross-Origin-Opener-Policy: same-origin` (COOP), `Sec-Fetch-Site`, or `SameSite=Strict`.

## Quick Start

Run the published image directly from GitHub Container Registry (supports `amd64` and `arm64`, no local build required):

```bash
docker run --rm -p 8001:8001 -p 8002:8002 ghcr.io/simiiii/xs-leaks-timing-lab:latest
```

Open both URLs in a **normal Chromium/Chrome window** (avoid Incognito, which blocks third-party cookies by default):

- Victim dashboard: `http://victim.localhost:8001`
- Attacker page: `http://attacker.localhost:8002`

### Optional: Local HTTPS (`mkcert`)
HTTPS is optional (plain HTTP works in Chromium on `*.localhost`). If you prefer HTTPS, generate a local cert once and mount `./certs` — `run.py` enables TLS automatically when `/certs/cert.pem` and `/certs/key.pem` are present:

```bash
brew install mkcert && mkcert -install
mkdir -p certs
mkcert -cert-file certs/cert.pem -key-file certs/key.pem victim.localhost attacker.localhost
docker run --rm -p 8001:8001 -p 8002:8002 -v "$PWD/certs:/certs:ro" ghcr.io/simiiii/xs-leaks-timing-lab:latest
```

## 1-Minute Presentation Flow

1. **Show the 2015 leak:** Keep `SameSite=None`. Run **Demo A** while Logged Out, then Log In and run it again. Note the jump in Service Worker cache time in the comparison table.
2. **Break classic defenses:** Turn **Random Server Delay ON**. Re-run **Demo A** to show Classic Network timing gets noisy while Service Worker timing stays unaffected.
3. **Apply modern defaults:** Switch to `SameSite=Lax` (or `Sec-Fetch-Site Block`). Re-run **Demo A** to show the 2015 leak is closed.
4. **Show "Still Ticking" (2026):** With `SameSite=Lax` active, run **Demo B**. The popup leaks your login state via `popup.length`.
5. **Close the final gap:** Enable `COOP: same-origin` (or `SameSite=Strict`) and re-run **Demo B** to show the leak is stopped.

## Development (Build Locally)

To modify the lab and build the Docker image locally:

```bash
docker build -t web-timing-demo .
docker run --rm -p 8001:8001 -p 8002:8002 web-timing-demo
```

### Hot Reload
Hot reload is **off by default**. To edit Python, templates, JS, or CSS without rebuilding the Docker image, mount the repo and set `RELOAD=1`:

```bash
docker run --rm -p 8001:8001 -p 8002:8002 -e RELOAD=1 -v "$PWD:/app" web-timing-demo
```

Saving any `.py` file restarts the servers automatically; template/static changes apply on browser refresh. (Add `-v "$PWD/certs:/certs:ro"` if developing over HTTPS.)

### Running Tests
```bash
docker build -t web-timing-demo .
docker run --rm web-timing-demo pytest -v
```
