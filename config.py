from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask

VICTIM_HOST = "victim.localhost"
ATTACKER_HOST = "attacker.localhost"
DEFAULT_VICTIM_PORT = 8001
DEFAULT_ATTACKER_PORT = 8002


def build_origin(host: str, port: int, scheme: str = "http") -> str:
    return f"{scheme}://{host}:{port}"


DEFAULT_VICTIM_ORIGIN = build_origin(VICTIM_HOST, DEFAULT_VICTIM_PORT)
DEFAULT_ATTACKER_ORIGIN = build_origin(ATTACKER_HOST, DEFAULT_ATTACKER_PORT)


def resolve_origins(
    *,
    victim_origin: str | None = None,
    attacker_origin: str | None = None,
    scheme: str = "http",
    victim_port: int = DEFAULT_VICTIM_PORT,
    attacker_port: int = DEFAULT_ATTACKER_PORT,
) -> tuple[str, str]:
    victim = victim_origin or os.environ.get(
        "VICTIM_ORIGIN", build_origin(VICTIM_HOST, victim_port, scheme)
    )
    attacker = attacker_origin or os.environ.get(
        "ATTACKER_ORIGIN", build_origin(ATTACKER_HOST, attacker_port, scheme)
    )
    return victim, attacker


def is_reload_enabled() -> bool:
    return os.environ.get("RELOAD", "").lower() in {"1", "true", "on"}


def configure_dev_reload(app: Flask) -> None:
    if is_reload_enabled():
        app.config["TEMPLATES_AUTO_RELOAD"] = True
        app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
