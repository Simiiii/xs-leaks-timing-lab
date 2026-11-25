from __future__ import annotations

import os
import random
import secrets
import threading
import time
from dataclasses import asdict, dataclass

from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for

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
    if os.environ.get("RELOAD", "").lower() in {"1", "true", "on"}:
        app.config["TEMPLATES_AUTO_RELOAD"] = True
        app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    store = StateStore()
    session_token = secrets.token_hex(16)

    app.config["VICTIM_ORIGIN"] = victim_origin or os.environ.get(
        "VICTIM_ORIGIN", "http://victim.localhost:8001"
    )
    app.config["ATTACKER_ORIGIN"] = attacker_origin or os.environ.get(
        "ATTACKER_ORIGIN", "http://attacker.localhost:8002"
    )
    app.extensions["state_store"] = store

    def is_logged_in() -> bool:
        return request.cookies.get("session") == session_token

    def _build_posture(logged_in: bool, state: LabState, active_tab: str) -> dict[str, object]:
        is_demo_b = active_tab == "demo-b"
        endpoint = "/private-group" if is_demo_b else "/private-group/asset.js"
        status = "403 Forbidden" if state.sec_fetch else "200 OK"
        cookie_attr = (
            "SameSite=None; Secure"
            if state.cookie_mode == "none"
            else f"SameSite={state.cookie_mode.capitalize()}"
        )

        level = "exposed"
        verdict = "EXPOSED"
        cookie_blocked = False
        cookie_bypassed = False

        if not logged_in:
            level = "neutral"
            verdict = "LOGGED OUT"
        elif not is_demo_b:
            cookie_blocked = state.cookie_mode in {"lax", "strict"}
            if cookie_blocked or state.sec_fetch:
                level = "blocked"
                verdict = "MITIGATED"
            elif state.random_delay:
                level = "bypassed"
                verdict = "BYPASSED (SW TIMING)"
        else:
            cookie_blocked = state.cookie_mode == "strict"
            cookie_bypassed = state.cookie_mode == "lax"
            if cookie_blocked or state.sec_fetch or state.coop:
                level = "blocked"
                verdict = "MITIGATED"
            elif cookie_bypassed:
                level = "bypassed"
                verdict = "BYPASSED (SAMESITE=LAX)"

        leak_active = logged_in and not cookie_blocked and not state.sec_fetch
        if state.sec_fetch:
            observed = "403 Blocked (2 kB)"
        elif not is_demo_b:
            observed = "2 MB JS asset" if leak_active else "2 kB JS stub"
        else:
            observed = "3 hidden iframes" if leak_active else "0 iframes"

        return {
            "endpoint": endpoint,
            "status": status,
            "cookie_attr": cookie_attr,
            "level": level,
            "verdict": verdict,
            "cookie_blocked": cookie_blocked,
            "cookie_bypassed": cookie_bypassed,
            "observed": observed,
        }

    def _render_demo(template_name: str, active_tab: str):
        state = store.snapshot()
        logged_in = is_logged_in()
        resp = make_response(
            render_template(
                template_name,
                logged_in=logged_in,
                state=state,
                posture=_build_posture(logged_in, state, active_tab),
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

    def _parse_bool(raw: str | None) -> bool | None:
        if raw is None:
            return None
        return raw in {"1", "true", "on"}

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

    @app.get("/private-group")
    def private_group():
        state = store.snapshot()
        sec_fetch_site = request.headers.get("Sec-Fetch-Site", "")
        if state.sec_fetch and sec_fetch_site == "cross-site":
            resp = make_response(
                render_template("blocked.html", padding=PADDING_2KB),
                403,
            )
        elif is_logged_in():
            resp = make_response(
                render_template("private_member.html", padding=PADDING_2KB),
                200,
            )
        else:
            resp = make_response(
                render_template("private_denied.html", padding=PADDING_2KB),
                200,
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

        sec_fetch_site = request.headers.get("Sec-Fetch-Site", "")
        if state.sec_fetch and sec_fetch_site == "cross-site":
            body = f"/* blocked: {PADDING_2KB} */\n"
            status = 403
        elif is_logged_in():
            body = f"/* member asset: {PADDING_2MB} */\n"
            status = 200
        else:
            body = f"/* denied: {PADDING_2KB} */\n"
            status = 200

        resp = make_response(body, status)
        resp.headers["Content-Type"] = "application/javascript; charset=utf-8"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    return app
