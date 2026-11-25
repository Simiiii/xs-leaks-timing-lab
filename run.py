from __future__ import annotations

import os
import signal
import ssl
import threading
from pathlib import Path

from werkzeug._reloader import run_with_reloader
from werkzeug.serving import make_server

from attacker.app import create_app as create_attacker_app
from victim.app import create_app as create_victim_app


def _build_ssl_context() -> ssl.SSLContext | None:
    cert_path = Path(os.environ.get("TLS_CERT", "/certs/cert.pem"))
    key_path = Path(os.environ.get("TLS_KEY", "/certs/key.pem"))
    if cert_path.is_file() and key_path.is_file():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        return ctx
    return None


def serve() -> None:
    victim_port = int(os.environ.get("VICTIM_PORT", "8001"))
    attacker_port = int(os.environ.get("ATTACKER_PORT", "8002"))
    ssl_context = _build_ssl_context()
    scheme = "https" if ssl_context else "http"

    victim_origin = os.environ.get("VICTIM_ORIGIN", f"{scheme}://victim.localhost:{victim_port}")
    attacker_origin = os.environ.get("ATTACKER_ORIGIN", f"{scheme}://attacker.localhost:{attacker_port}")

    victim_app = create_victim_app(victim_origin=victim_origin, attacker_origin=attacker_origin)
    attacker_app = create_attacker_app(victim_origin=victim_origin, attacker_origin=attacker_origin)

    victim_server = make_server(
        "0.0.0.0", victim_port, victim_app, threaded=True, ssl_context=ssl_context
    )
    attacker_server = make_server(
        "0.0.0.0", attacker_port, attacker_app, threaded=True, ssl_context=ssl_context
    )

    stop_event = threading.Event()

    def handle_signal(signum, _frame):
        if not stop_event.is_set():
            stop_event.set()
            print(f"\nReceived signal {signum}, shutting down...")
            threading.Thread(target=victim_server.shutdown, daemon=True).start()
            threading.Thread(target=attacker_server.shutdown, daemon=True).start()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

    print(f"Victim running at   {victim_origin}")
    print(f"Attacker running at {attacker_origin}")

    t_victim = threading.Thread(target=victim_server.serve_forever, name="victim", daemon=True)
    t_attacker = threading.Thread(target=attacker_server.serve_forever, name="attacker", daemon=True)
    t_victim.start()
    t_attacker.start()

    t_victim.join()
    t_attacker.join()
    victim_server.server_close()
    attacker_server.server_close()


def main() -> None:
    if os.environ.get("RELOAD", "").lower() in {"1", "true", "on"}:
        run_with_reloader(serve, reloader_type="stat")
    else:
        serve()


if __name__ == "__main__":
    main()
