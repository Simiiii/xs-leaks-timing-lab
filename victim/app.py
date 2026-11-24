from __future__ import annotations

import os
import random
import threading
import time
from dataclasses import asdict, dataclass

from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for

PADDING_500KB = "A" * 500_000
PADDING_2KB = "B" * 2_000

VALID_COOKIE_MODES = {"none", "lax", "strict"}
VALID_DEFENSES = {"off", "sec-fetch", "coop"}


@dataclass
class LabState:
    cookie_mode: str = "none"   # "none" (2015/opt-out), "lax" (default), "strict"
    random_delay: bool = False  # True = 150-450ms random server delay
    defense: str = "off"        # "off", "sec-fetch", "coop"


class StateStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = LabState()

    def snapshot(self) -> LabState:
        with self._lock:
            return LabState(**asdict(self._state))

    def update(
        self,
        *,
        cookie_mode: str | None = None,
        random_delay: bool | None = None,
        defense: str | None = None,
    ) -> LabState:
        with self._lock:
            if cookie_mode in VALID_COOKIE_MODES:
                self._state.cookie_mode = cookie_mode
            if random_delay is not None:
                self._state.random_delay = random_delay
            if defense in VALID_DEFENSES:
                self._state.defense = defense
            return LabState(**asdict(self._state))


def _set_session_cookie(response, value: str, cookie_mode: str, max_age: int = 3600) -> None:
    samesite_map = {"none": "None", "lax": "Lax", "strict": "Strict"}
    response.set_cookie(
        "session",
        value,
        max_age=max_age,
        path="/",
        samesite=samesite_map[cookie_mode],
        secure=(cookie_mode == "none"),
    )


def create_app(
    *,
    victim_origin: str | None = None,
    attacker_origin: str | None = None,
) -> Flask:
    app = Flask(__name__)
    store = StateStore()

    app.config["VICTIM_ORIGIN"] = victim_origin or os.environ.get(
        "VICTIM_ORIGIN", "http://victim.localhost:8001"
    )
    app.config["ATTACKER_ORIGIN"] = attacker_origin or os.environ.get(
        "ATTACKER_ORIGIN", "http://attacker.localhost:8002"
    )
    app.extensions["state_store"] = store

    def is_logged_in() -> bool:
        return request.cookies.get("session") == "authenticated"

    @app.get("/")
    def dashboard():
        state = store.snapshot()
        resp = make_response(
            render_template(
                "dashboard.html",
                logged_in=is_logged_in(),
                state=state,
                victim_origin=app.config["VICTIM_ORIGIN"],
                attacker_origin=app.config["ATTACKER_ORIGIN"],
            )
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/api/state")
    def api_state():
        state = store.snapshot()
        return jsonify({"logged_in": is_logged_in(), **asdict(state)})

    @app.post("/login")
    def login():
        state = store.snapshot()
        resp = make_response(redirect(url_for("dashboard")))
        _set_session_cookie(resp, "authenticated", state.cookie_mode)
        return resp

    @app.post("/logout")
    def logout():
        state = store.snapshot()
        resp = make_response(redirect(url_for("dashboard")))
        _set_session_cookie(resp, "deleted", state.cookie_mode, max_age=0)
        return resp

    @app.post("/config")
    def config():
        cookie_mode = request.form.get("cookie_mode")
        delay_raw = request.form.get("random_delay")
        defense = request.form.get("defense")

        random_delay = None
        if delay_raw is not None:
            random_delay = delay_raw in {"1", "true", "on"}

        state = store.update(
            cookie_mode=cookie_mode,
            random_delay=random_delay,
            defense=defense,
        )

        resp = make_response(redirect(url_for("dashboard")))
        if is_logged_in():
            _set_session_cookie(resp, "authenticated", state.cookie_mode)
        return resp

    @app.get("/private-group")
    def private_group():
        state = store.snapshot()
        if state.random_delay:
            time.sleep(random.uniform(0.15, 0.45))

        sec_fetch_site = request.headers.get("Sec-Fetch-Site", "")
        if state.defense == "sec-fetch" and sec_fetch_site == "cross-site":
            resp = make_response(
                render_template("blocked.html", padding=PADDING_2KB),
                403,
            )
        elif is_logged_in():
            resp = make_response(
                render_template("private_member.html", padding=PADDING_500KB),
                200,
            )
        else:
            resp = make_response(
                render_template("private_denied.html", padding=PADDING_2KB),
                200,
            )

        resp.headers["Cache-Control"] = "no-store"
        if state.defense == "coop":
            resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        return resp

    return app
