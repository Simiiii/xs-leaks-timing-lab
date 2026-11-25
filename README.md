# Modern Web Timing Attacks & XS-Leaks (Local Docker Demo)

Single-container lab accompanying *"The Clock is Still Ticking: Timing Attacks in the Modern Web"* (Van Goethem et al., CCS 2015) and modern 2026 browser defenses.

## Architecture

Both origins run inside a single Docker container via `run.py`, separated into independent Flask applications (`victim` on port `8001` and `attacker` on port `8002`) with Jinja2 templates, static JS/CSS assets, a root-scoped Service Worker (`/sw.js`), thread-safe lab state, and graceful `SIGTERM` shutdown.

`victim.localhost` and `attacker.localhost` resolve to loopback automatically (RFC 6761) with no `/etc/hosts` edits, while Chromium treats them as separate cross-site yet potentially trustworthy origins (allowing both Service Workers and `SameSite=None; Secure` cookies over HTTP).

## What This Demonstrates
- **Victim (`http://victim.localhost:8001`):** Serves a 2 MB JS subresource (`/private-group/asset.js`, for Demo A — passes modern ORB while staying opaque to `no-cors` fetches) and an HTML page with 3 hidden iframes (`/private-group`, for Demo B) when logged in, vs. 2 kB / 0 iframes when logged out, both with `Cache-Control: no-store` and live toggles for cookie policies, random server delays, and modern security headers.
- **Attacker (`http://attacker.localhost:8002`):** Runs two cross-site probes against the victim:
  1. **2015 Service Worker Timing vs. Classic Timing:** Shows that random server delays break classic network timing, while post-download Service Worker Cache API timing still reveals response size (and ignores `Cache-Control: no-store`). Includes a run-history table for side-by-side comparison.
  2. **2026 `SameSite=Lax` Bypass (`window.open`):** Shows that modern default cookies stop background subrequest leaks, but top-level navigations still carry `SameSite=Lax` cookies unless blocked by `Cross-Origin-Opener-Policy: same-origin` (COOP), `Sec-Fetch-Site`, or `SameSite=Strict`.

## Quick Start (Docker)
```bash
docker build -t web-timing-demo .
docker run --rm -p 8001:8001 -p 8002:8002 web-timing-demo
```

Open both URLs in a **normal Chromium/Chrome window** (avoid Incognito, which blocks third-party cookies by default):

- Victim dashboard: `http://victim.localhost:8001`
- Attacker page: `http://attacker.localhost:8002`

## Optional: Local HTTPS (`mkcert`)
HTTPS is optional (plain HTTP works in Chromium on `*.localhost`). If you prefer HTTPS, generate a local cert once and mount `./certs` — `run.py` enables TLS automatically when `/certs/cert.pem` and `/certs/key.pem` are present:

```bash
brew install mkcert && mkcert -install
mkdir -p certs
mkcert -cert-file certs/cert.pem -key-file certs/key.pem victim.localhost attacker.localhost
docker run --rm -p 8001:8001 -p 8002:8002 -v "$PWD/certs:/certs:ro" web-timing-demo
```

## Development (Hot Reload)
Hot reload is **off by default**. To edit Python, templates, JS, or CSS without rebuilding the Docker image, mount the repo and set `RELOAD=1`:

```bash
docker run --rm -p 8001:8001 -p 8002:8002 -e RELOAD=1 -v "$PWD:/app" web-timing-demo
```

Saving any `.py` file restarts the servers automatically; template/static changes apply on browser refresh. (Add `-v "$PWD/certs:/certs:ro"` if developing over HTTPS.)

## Running Tests
```bash
docker run --rm web-timing-demo pytest -v
```

## 1-Minute Presentation Flow

1. **Show the 2015 leak:** Keep `SameSite=None`. Run **Demo A** while Logged Out, then Log In and run it again. Note the jump in Service Worker cache time in the comparison table.
2. **Break classic defenses:** Turn **Random Server Delay ON**. Re-run **Demo A** to show Classic Network timing gets noisy while Service Worker timing stays unaffected.
3. **Apply modern defaults:** Switch to `SameSite=Lax` (or `Sec-Fetch-Site Block`). Re-run **Demo A** to show the 2015 leak is closed.
4. **Show "Still Ticking" (2026):** With `SameSite=Lax` active, run **Demo B**. The popup leaks your login state via `popup.length`.
5. **Close the final gap:** Enable `COOP: same-origin` (or `SameSite=Strict`) and re-run **Demo B** to show the leak is stopped.
