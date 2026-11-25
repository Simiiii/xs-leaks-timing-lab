from __future__ import annotations

import pytest

from attacker.app import create_app as create_attacker_app
from victim.app import create_app as create_victim_app


@pytest.fixture
def victim_client():
    app = create_victim_app(
        victim_origin="http://victim.localhost:8001",
        attacker_origin="http://attacker.localhost:8002",
    )
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def attacker_client():
    app = create_attacker_app(
        victim_origin="http://victim.localhost:8001",
        attacker_origin="http://attacker.localhost:8002",
    )
    app.config["TESTING"] = True
    return app.test_client()


def test_victim_dashboard_and_state(victim_client):
    resp = victim_client.get("/")
    assert resp.status_code == 200
    assert b"http://victim.localhost:8001" in resp.data
    assert b"http://attacker.localhost:8002" in resp.data
    assert resp.headers["Cache-Control"] == "no-store"

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
    assert "session=authenticated" in set_cookie
    assert "SameSite=None" in set_cookie
    assert "Secure" in set_cookie

    in_resp = victim_client.get("/private-group")
    assert in_resp.status_code == 200
    assert len(in_resp.data) > 500_000
    assert in_resp.data.count(b"<iframe") == 3

    logout_resp = victim_client.post("/logout")
    assert logout_resp.status_code == 302
    assert len(victim_client.get("/private-group").data) < 5_000


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

    same_origin = victim_client.get("/private-group", headers={"Sec-Fetch-Site": "same-origin"})
    assert same_origin.status_code == 200
    assert len(same_origin.data) > 500_000


def test_coop_defense_header(victim_client):
    victim_client.post("/config", data={"coop": "1"})
    resp = victim_client.get("/private-group")
    assert resp.status_code == 200
    assert resp.headers.get("Cross-Origin-Opener-Policy") == "same-origin"


def test_attacker_index_and_service_worker(attacker_client):
    index = attacker_client.get("/")
    assert index.status_code == 200
    assert b'data-victim-origin="http://victim.localhost:8001"' in index.data
    assert b"/static/attacker.js" in index.data

    sw = attacker_client.get("/sw.js")
    assert sw.status_code == 200
    assert "javascript" in sw.content_type
    assert sw.headers["Cache-Control"] == "no-store"
    assert b"caches.open('timing-demo')" in sw.data
