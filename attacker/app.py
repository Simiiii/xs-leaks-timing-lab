from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, make_response, render_template, send_from_directory

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(
    *,
    victim_origin: str | None = None,
    attacker_origin: str | None = None,
) -> Flask:
    app = Flask(__name__)

    app.config["VICTIM_ORIGIN"] = victim_origin or os.environ.get(
        "VICTIM_ORIGIN", "http://victim.localhost:8001"
    )
    app.config["ATTACKER_ORIGIN"] = attacker_origin or os.environ.get(
        "ATTACKER_ORIGIN", "http://attacker.localhost:8002"
    )

    @app.get("/")
    def index():
        resp = make_response(
            render_template(
                "index.html",
                victim_origin=app.config["VICTIM_ORIGIN"],
                attacker_origin=app.config["ATTACKER_ORIGIN"],
            )
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/sw.js")
    def service_worker():
        resp = make_response(
            send_from_directory(
                STATIC_DIR,
                "sw.js",
                mimetype="application/javascript",
            )
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    return app
