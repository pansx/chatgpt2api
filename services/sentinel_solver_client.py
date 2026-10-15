"""Client for the sentinel solver service (`sentinel_solver/`).

Since 2026-10-14 chatgpt.com only accepts a Turnstile token that was computed
inside a real chatgpt.com page. A pure-Python or Node emulation of the challenge
is rejected, and an incomplete handshake does not surface as 403: the
conversation endpoint answers a disguised `404 {"detail": "Model not found"}`.
The solver keeps a headless Chromium on that page and computes the token for us.

The JSON browser route forwards account Authorization to the trusted solver.
Conversation prompts and streaming responses continue to use the main service.
"""

from __future__ import annotations

import threading
import time

from curl_cffi import requests

from services.config import config
from utils.log import logger

SOLVER_TIMEOUT_SECONDS = 20
# Solving waits on the page's own module, which can take a moment on a cold page.
SOLVER_SOLVE_TIMEOUT_SECONDS = 60
USER_AGENT_CACHE_SECONDS = 600
# A failed health probe is cached briefly too, so a solver that is down does not
# get probed once per request.
USER_AGENT_FAILURE_CACHE_SECONDS = 30

_user_agent_lock = threading.Lock()
_user_agent_cache: dict[str, object] = {"url": "", "value": "", "expires_at": 0.0}


class SentinelSolverError(RuntimeError):
    """The solver is unconfigured or could not produce a Turnstile token."""


def _solver_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if config.sentinel_solver_key:
        headers["Authorization"] = f"Bearer {config.sentinel_solver_key}"
    return headers


def solver_user_agent() -> str:
    """User agent of the page that computes the Turnstile token, or "" when unset.

    The requirements/proof tokens embed the UA, and it has to match the browser
    environment that solved the challenge; otherwise the conversation endpoint
    answers `404 {"detail": "Model not found"}`.
    """
    base_url = config.sentinel_solver_url
    if not base_url:
        return ""
    with _user_agent_lock:
        now = time.monotonic()
        if _user_agent_cache["url"] == base_url and now < float(_user_agent_cache["expires_at"]):
            return str(_user_agent_cache["value"])
        value = ""
        try:
            response = requests.get(
                f"{base_url}/health",
                headers=_solver_headers(),
                timeout=SOLVER_TIMEOUT_SECONDS,
            )
            if response.status_code == 200:
                value = str((response.json() or {}).get("user_agent") or "")
        except Exception as exc:  # noqa: BLE001
            logger.warning({"event": "sentinel_solver_health_error", "error": str(exc)})
        ttl = USER_AGENT_CACHE_SECONDS if value else USER_AGENT_FAILURE_CACHE_SECONDS
        _user_agent_cache.update(url=base_url, value=value, expires_at=now + ttl)
        return value


def solve_turnstile(dx: str, p: str, requirements: dict | None = None, proxy: str = "") -> str:
    """Solve the Turnstile challenge.

    `dx` comes from the prepare response and `p` is the requirements token we sent.
    `requirements` is the whole prepare response — passing it lets the solver call
    the page's own turnstile module instead of emulating the challenge, which is
    the only thing that currently produces an accepted token. It is pure challenge
    material: no account token, cookie or user prompt is involved.

    Fails closed: without a solved token the conversation request would come back
    as a disguised 404 and burn the whole retry budget, so an unsolvable challenge
    is raised here instead.
    """
    base_url = config.sentinel_solver_url
    if not base_url:
        raise SentinelSolverError(
            "sentinel solver is not configured (CHATGPT2API_SENTINEL_SOLVER_URL / config.json sentinel_solver_url)"
        )
    body: dict[str, object] = {"dx": dx, "p": p}
    if requirements:
        body["requirements"] = requirements
    if proxy:
        body["proxy"] = proxy
    try:
        response = requests.post(
            f"{base_url}/v1/turnstile",
            headers=_solver_headers(),
            json=body,
            timeout=SOLVER_SOLVE_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning({"event": "sentinel_solver_error", "error": str(exc)})
        raise SentinelSolverError(f"sentinel solver request failed: {exc}") from exc

    if response.status_code != 200:
        logger.warning({
            "event": "sentinel_solver_failed",
            "status": response.status_code,
            "body": str(response.text or "")[:200],
        })
        raise SentinelSolverError(
            f"sentinel solver returned HTTP {response.status_code}: {str(response.text or '')[:200]}"
        )

    token = str((response.json() or {}).get("token") or "")
    if not token:
        raise SentinelSolverError("sentinel solver returned an empty turnstile token")
    return token


def browser_request(method: str, url: str, headers: dict[str, str] | None = None, body: str = "", proxy: str = "") -> dict:
    """Run a JSON request through the solver's real Chromium page."""
    base_url = config.sentinel_solver_url
    if not base_url:
        raise SentinelSolverError("sentinel solver is not configured")
    try:
        response = requests.post(
            f"{base_url}/v1/request", headers=_solver_headers(),
            json={"method": method, "url": url, "headers": headers or {}, "body": body, **({"proxy": proxy} if proxy else {})},
            timeout=SOLVER_SOLVE_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001
        raise SentinelSolverError(f"sentinel browser request failed: {exc}") from exc
    if response.status_code != 200:
        raise SentinelSolverError(f"sentinel browser request returned HTTP {response.status_code}")
    try:
        data = response.json()
        if (not isinstance(data, dict) or type(data.get("status")) is not int
                or not 0 <= data["status"] <= 599 or not isinstance(data.get("headers"), dict)
                or not isinstance(data.get("text"), str)):
            raise ValueError("invalid browser response")
        return data
    except (TypeError, ValueError) as exc:
        raise SentinelSolverError("invalid sentinel browser response") from exc
