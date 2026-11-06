"""Shared politeness policy for every Yahoo Finance call in this app.

Yahoo rate limits by IP and blocks aggressively, so all quote traffic goes through
one throttle: calls are spaced apart, each request may spend only a bounded number of
lookups, and a 429 puts the whole process into cooldown instead of hammering back.
"""

import threading
import time
from functools import wraps

MIN_CALL_SPACING_SECONDS = 0.35
MAX_LOOKUPS_PER_REQUEST = 40
COOLDOWN_SECONDS = 120

_lock = threading.Lock()
_state = {"calls": 0, "last_call_at": 0.0, "cooldown_until": 0.0}


class YahooBudgetExceeded(Exception):
    """This request has spent its Yahoo lookups, or Yahoo is cooling down."""


def begin_request_budget():
    """Reset the per-request lookup budget. Call at the top of each API request."""
    with _lock:
        _state["calls"] = 0
        _state["last_call_at"] = 0.0


def budget(function):
    """Decorator giving one request its own lookup allowance."""
    @wraps(function)
    def decorator(*args, **kwargs):
        begin_request_budget()
        return function(*args, **kwargs)
    return decorator


def acquire_call_slot():
    """Space this call from the previous one and charge it to the request budget."""
    with _lock:
        now = time.monotonic()
        if now < _state["cooldown_until"]:
            raise YahooBudgetExceeded(
                f"Yahoo is cooling down; retry in {int(_state['cooldown_until'] - now)}s."
            )
        if _state["calls"] >= MAX_LOOKUPS_PER_REQUEST:
            raise YahooBudgetExceeded(
                f"Lookup limit of {MAX_LOOKUPS_PER_REQUEST} symbols reached for this request."
            )
        if _state["last_call_at"]:
            wait = MIN_CALL_SPACING_SECONDS - (now - _state["last_call_at"])
            if wait > 0:
                time.sleep(wait)
        _state["calls"] += 1
        _state["last_call_at"] = time.monotonic()


def note_rate_limited(exc=None):
    """Record that Yahoo rate limited us, starting a process-wide cooldown."""
    with _lock:
        _state["cooldown_until"] = time.monotonic() + COOLDOWN_SECONDS


def is_rate_limit_error(exc):
    """True when an exception from yfinance looks like rate limiting (429/403)."""
    return getattr(exc, "code", None) in (429, 403)
