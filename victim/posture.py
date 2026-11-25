from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from victim.app import LabState


def build_posture(logged_in: bool, state: LabState, active_tab: str) -> dict[str, object]:
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
