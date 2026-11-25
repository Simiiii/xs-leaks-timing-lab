from __future__ import annotations

import random
import secrets
import threading
import time
from dataclasses import asdict, dataclass

from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for

from config import configure_dev_reload, resolve_origins
from victim.posture import build_posture

PADDING_2MB = "A" * 2_000_000
PADDING_2KB = "B" * 2_000

VALID_COOKIE_MODES = {"none", "lax", "strict"}


@dataclass
class LabState:
    cookie_mode: str = "none"   # "none" (2015/opt-out), "lax" (default), "strict"
    sec_fetch: bool = False     # True = reject Sec-Fetch-Site: cross-site (Demo A & B)
    random_delay: bool = False  # True = 50-250ms random server delay (Demo A)
    coop: bool = False          # True = Cross-Origin-Opener-Policy: same-origin (Demo B)


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
        sec_fetch: bool | None = None,
        random_delay: bool | None = None,
        coop: bool | None = None,
    ) -> LabState:
        with self._lock:
            if cookie_mode in VALID_COOKIE_MODES:
                self._state.cookie_mode = cookie_mode
            if sec_fetch is not None:
                self._state.sec_fetch = sec_fetch
            if random_delay is not None:
                self._state.random_delay = random_delay
            if coop is not None:
                self._state.coop = coop
            return LabState(**asdict(self._state))


def _parse_bool(raw: str | None) -> bool | None:
    if raw is None:
        return None
    return raw in {"1", "true", "on"}


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
    configure_dev_reload(app)
    store = StateStore()
    session_token = secrets.token_hex(16)

    resolved_victim, resolved_attacker = resolve_origins(
        victim_origin=victim_origin,
        attacker_origin=attacker_origin,
    )
    app.config["VICTIM_ORIGIN"] = resolved_victim
    app.config["ATTACKER_ORIGIN"] = resolved_attacker
    app.extensions["state_store"] = store

    def is_logged_in() -> bool:
        return request.cookies.get("session") == session_token

    def _render_demo(template_name: str, active_tab: str):
        state = store.snapshot()
        logged_in = is_logged_in()
        resp = make_response(
            render_template(
                template_name,
                logged_in=logged_in,
                state=state,
                posture=build_posture(logged_in, state, active_tab),
                victim_origin=app.config["VICTIM_ORIGIN"],
                attacker_origin=app.config["ATTACKER_ORIGIN"],
                active_tab=active_tab,
            )
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def _redirect_target() -> str:
        if request.form.get("tab") == "demo-b":
            return url_for("demo_b")
        return url_for("dashboard")

    @app.get("/")
    @app.get("/demo-a")
    def dashboard():
        return _render_demo("demo_a.html", "demo-a")

    @app.get("/demo-b")
    def demo_b():
        return _render_demo("demo_b.html", "demo-b")

    @app.get("/api/state")
    def api_state():
        state = store.snapshot()
        return jsonify({"logged_in": is_logged_in(), **asdict(state)})

    @app.post("/login")
    def login():
        state = store.snapshot()
        resp = make_response(redirect(_redirect_target()))
        _set_session_cookie(resp, session_token, state.cookie_mode)
        return resp

    @app.post("/logout")
    def logout():
        state = store.snapshot()
        resp = make_response(redirect(_redirect_target()))
        _set_session_cookie(resp, "deleted", state.cookie_mode, max_age=0)
        return resp

    @app.post("/config")
    def config():
        state = store.update(
            cookie_mode=request.form.get("cookie_mode"),
            sec_fetch=_parse_bool(request.form.get("sec_fetch")),
            random_delay=_parse_bool(request.form.get("random_delay")),
            coop=_parse_bool(request.form.get("coop")),
        )

        resp = make_response(redirect(_redirect_target()))
        if is_logged_in():
            _set_session_cookie(resp, session_token, state.cookie_mode)
        return resp

    def _resolve_private_access(state: LabState) -> tuple[str, int]:
        sec_fetch_site = request.headers.get("Sec-Fetch-Site", "")
        if state.sec_fetch and sec_fetch_site == "cross-site":
            return "blocked", 403
        if is_logged_in():
            return "member", 200
        return "denied", 200

    @app.get("/private-group")
    def private_group():
        state = store.snapshot()
        outcome, status = _resolve_private_access(state)
        templates = {
            "blocked": "blocked.html",
            "member": "private_member.html",
            "denied": "private_denied.html",
        }
        resp = make_response(
            render_template(templates[outcome], padding=PADDING_2KB),
            status,
        )
        resp.headers["Cache-Control"] = "no-store"
        if state.coop:
            resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        return resp

    @app.get("/private-group/asset.js")
    def private_group_asset():
        state = store.snapshot()
        if state.random_delay:
            time.sleep(random.uniform(0.05, 0.25))

        outcome, status = _resolve_private_access(state)
        payloads = {
            "blocked": ("blocked", PADDING_2KB),
            "member": ("member asset", PADDING_2MB),
            "denied": ("denied", PADDING_2KB),
        }
        label, padding = payloads[outcome]
        resp = make_response(f"/* {label}: {padding} */\n", status)
        resp.headers["Content-Type"] = "application/javascript; charset=utf-8"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    return app
