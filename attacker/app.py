from __future__ import annotations

from pathlib import Path

from flask import Flask, make_response, render_template, send_from_directory

from config import configure_dev_reload, resolve_origins

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(
    *,
    victim_origin: str | None = None,
    attacker_origin: str | None = None,
) -> Flask:
    app = Flask(__name__)
    configure_dev_reload(app)

    resolved_victim, resolved_attacker = resolve_origins(
        victim_origin=victim_origin,
        attacker_origin=attacker_origin,
    )
    app.config["VICTIM_ORIGIN"] = resolved_victim
    app.config["ATTACKER_ORIGIN"] = resolved_attacker

    def _render_demo(template_name: str, active_tab: str):
        resp = make_response(
            render_template(
                template_name,
                victim_origin=app.config["VICTIM_ORIGIN"],
                attacker_origin=app.config["ATTACKER_ORIGIN"],
                active_tab=active_tab,
            )
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/")
    @app.get("/demo-a")
    def index():
        return _render_demo("demo_a.html", "demo-a")

    @app.get("/demo-b")
    def demo_b():
        return _render_demo("demo_b.html", "demo-b")

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
