from __future__ import annotations

import pytest

from attacker.app import create_app as create_attacker_app
from config import DEFAULT_ATTACKER_ORIGIN, DEFAULT_VICTIM_ORIGIN
from victim.app import create_app as create_victim_app


@pytest.fixture
def victim_client():
    app = create_victim_app(
        victim_origin=DEFAULT_VICTIM_ORIGIN,
        attacker_origin=DEFAULT_ATTACKER_ORIGIN,
    )
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def attacker_client():
    app = create_attacker_app(
        victim_origin=DEFAULT_VICTIM_ORIGIN,
        attacker_origin=DEFAULT_ATTACKER_ORIGIN,
    )
    app.config["TESTING"] = True
    return app.test_client()


def test_victim_dashboard_and_state(victim_client):
    resp = victim_client.get("/")
    assert resp.status_code == 200
    assert DEFAULT_VICTIM_ORIGIN.encode() in resp.data
    assert DEFAULT_ATTACKER_ORIGIN.encode() in resp.data
    assert resp.headers["Cache-Control"] == "no-store"
    assert b'name="random_delay"' in resp.data
    assert b'name="coop"' not in resp.data
    assert b'href="/demo-b"' in resp.data

    demo_a = victim_client.get("/demo-a")
    assert demo_a.status_code == 200
    assert b'name="random_delay"' in demo_a.data
    assert b'name="coop"' not in demo_a.data

    demo_b = victim_client.get("/demo-b")
    assert demo_b.status_code == 200
    assert demo_b.headers["Cache-Control"] == "no-store"
    assert b'name="coop"' in demo_b.data
    assert b'name="random_delay"' not in demo_b.data
    assert b'href="/demo-a"' in demo_b.data

    login_b = victim_client.post("/login", data={"tab": "demo-b"})
    assert login_b.status_code == 302
    assert login_b.headers["Location"].endswith("/demo-b")

    cfg_b = victim_client.post("/config", data={"tab": "demo-b", "coop": "1"})
    assert cfg_b.status_code == 302
    assert cfg_b.headers["Location"].endswith("/demo-b")

    logout_b = victim_client.post("/logout", data={"tab": "demo-b"})
    assert logout_b.status_code == 302
    assert logout_b.headers["Location"].endswith("/demo-b")

    victim_client.post("/config", data={"coop": "0"})
    state = victim_client.get("/api/state").get_json()
    assert state == {
        "logged_in": False,
        "cookie_mode": "none",
        "sec_fetch": False,
        "random_delay": False,
        "coop": False,
    }


def test_private_group_payload_size_logged_out_vs_in(victim_client):
    out_resp = victim_client.get("/private-group")
    assert out_resp.status_code == 200
    assert out_resp.headers["Cache-Control"] == "no-store"
    assert len(out_resp.data) < 5_000
    assert out_resp.data.count(b"<iframe") == 0

    login_resp = victim_client.post("/login")
    assert login_resp.status_code == 302
    set_cookie = login_resp.headers.get("Set-Cookie", "")
    assert "session=" in set_cookie
    assert "SameSite=None" in set_cookie
    assert "Secure" in set_cookie

    in_resp = victim_client.get("/private-group")
    assert in_resp.status_code == 200
    assert in_resp.data.count(b"<iframe") == 3

    asset_in = victim_client.get("/private-group/asset.js")
    assert asset_in.status_code == 200
    assert "javascript" in asset_in.content_type
    assert asset_in.headers["Cache-Control"] == "no-store"
    assert len(asset_in.data) > 2_000_000

    logout_resp = victim_client.post("/logout")
    assert logout_resp.status_code == 302
    assert len(victim_client.get("/private-group").data) < 5_000
    assert len(victim_client.get("/private-group/asset.js").data) < 5_000


def test_cookie_mode_reissues_cookie_when_logged_in(victim_client):
    victim_client.post("/login")

    lax_resp = victim_client.post("/config", data={"cookie_mode": "lax"})
    assert lax_resp.status_code == 302
    lax_cookie = lax_resp.headers.get("Set-Cookie", "")
    assert "SameSite=Lax" in lax_cookie
    assert "Secure" not in lax_cookie

    strict_resp = victim_client.post("/config", data={"cookie_mode": "strict"})
    assert "SameSite=Strict" in strict_resp.headers.get("Set-Cookie", "")


def test_sec_fetch_site_defense(victim_client):
    victim_client.post("/login")
    victim_client.post("/config", data={"sec_fetch": "1"})

    blocked = victim_client.get("/private-group", headers={"Sec-Fetch-Site": "cross-site"})
    assert blocked.status_code == 403
    assert len(blocked.data) < 5_000

    blocked_asset = victim_client.get("/private-group/asset.js", headers={"Sec-Fetch-Site": "cross-site"})
    assert blocked_asset.status_code == 403
    assert len(blocked_asset.data) < 5_000

    same_origin = victim_client.get("/private-group", headers={"Sec-Fetch-Site": "same-origin"})
    assert same_origin.status_code == 200
    assert same_origin.data.count(b"<iframe") == 3

    same_origin_asset = victim_client.get(
        "/private-group/asset.js", headers={"Sec-Fetch-Site": "same-origin"}
    )
    assert same_origin_asset.status_code == 200
    assert len(same_origin_asset.data) > 2_000_000


def test_coop_defense_header(victim_client):
    victim_client.post("/config", data={"coop": "1"})
    resp = victim_client.get("/private-group")
    assert resp.status_code == 200
    assert resp.headers.get("Cross-Origin-Opener-Policy") == "same-origin"


def test_attacker_demo_pages_and_service_worker(attacker_client):
    expected_victim_attr = f'data-victim-origin="{DEFAULT_VICTIM_ORIGIN}"'.encode()

    index = attacker_client.get("/")
    assert index.status_code == 200
    assert index.headers["Cache-Control"] == "no-store"
    assert expected_victim_attr in index.data
    assert b"/static/attacker.js" in index.data
    assert b'id="runTimingBtn"' in index.data
    assert b'id="runPopupBtn"' not in index.data
    assert b'href="/demo-b"' in index.data

    demo_a = attacker_client.get("/demo-a")
    assert demo_a.status_code == 200
    assert demo_a.headers["Cache-Control"] == "no-store"
    assert b'id="runTimingBtn"' in demo_a.data
    assert b'id="runPopupBtn"' not in demo_a.data

    demo_b = attacker_client.get("/demo-b")
    assert demo_b.status_code == 200
    assert demo_b.headers["Cache-Control"] == "no-store"
    assert expected_victim_attr in demo_b.data
    assert b"/static/attacker.js" in demo_b.data
    assert b'id="runPopupBtn"' in demo_b.data
    assert b'id="runTimingBtn"' not in demo_b.data
    assert b'href="/demo-a"' in demo_b.data

    sw = attacker_client.get("/sw.js")
    assert sw.status_code == 200
    assert "javascript" in sw.content_type
    assert sw.headers["Cache-Control"] == "no-store"
    assert b"caches.open('timing-demo')" in sw.data
