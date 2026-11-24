from __future__ import annotations

import os
import signal
import threading

from werkzeug.serving import make_server

from attacker.app import create_app as create_attacker_app
from victim.app import create_app as create_victim_app


def main() -> None:
    victim_port = int(os.environ.get("VICTIM_PORT", "8001"))
    attacker_port = int(os.environ.get("ATTACKER_PORT", "8002"))
    victim_origin = os.environ.get("VICTIM_ORIGIN", f"http://victim.localhost:{victim_port}")
    attacker_origin = os.environ.get("ATTACKER_ORIGIN", f"http://attacker.localhost:{attacker_port}")

    victim_app = create_victim_app(victim_origin=victim_origin, attacker_origin=attacker_origin)
    attacker_app = create_attacker_app(victim_origin=victim_origin, attacker_origin=attacker_origin)

    victim_server = make_server("0.0.0.0", victim_port, victim_app, threaded=True)
    attacker_server = make_server("0.0.0.0", attacker_port, attacker_app, threaded=True)

    stop_event = threading.Event()

    def handle_signal(signum, _frame):
        if not stop_event.is_set():
            stop_event.set()
            print(f"\nReceived signal {signum}, shutting down...")
            threading.Thread(target=victim_server.shutdown, daemon=True).start()
            threading.Thread(target=attacker_server.shutdown, daemon=True).start()

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


if __name__ == "__main__":
    main()
