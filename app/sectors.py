"""Sector labels for symbols, cached on disk.

Yahoo's ``Ticker.info`` is the only source of a free per-symbol sector here, and it is
rate limited, so every lookup goes through this module plus app.yahoo_rate_limit:
results (including "no sector") are persisted, calls are spaced apart, and one request
can only spend a bounded number of lookups. A cold cache costs seconds; warm cache is
free.

Sectors are stored exactly as Yahoo reports them - eleven values, no invented buckets.
A symbol Yahoo cannot resolve gets ``None``, which the frontend shows as Unclassified
rather than dropping from the chart.
"""

import json
import os
import threading
import time

import yfinance as yf

from app import yahoo_rate_limit as yahoo

CACHE_PATH = os.path.join(os.path.dirname(__file__), "cache", "sectors.json")

# Quote data changes slowly; a delisted symbol rarely comes back, so negatives can be
# held longer than positives without hiding real changes.
POSITIVE_TTL_SECONDS = 30 * 24 * 60 * 60
NEGATIVE_TTL_SECONDS = 7 * 24 * 60 * 60

_cache_lock = threading.Lock()


def _load_cache():
    if not os.path.exists(CACHE_PATH):
        return {}
    try:
        with open(CACHE_PATH, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    tmp_path = f"{CACHE_PATH}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(cache, handle, indent=1, sort_keys=True)
    os.replace(tmp_path, CACHE_PATH)


def _is_fresh(entry, now):
    if not isinstance(entry, dict):
        return False
    ttl = POSITIVE_TTL_SECONDS if entry.get("sector") else NEGATIVE_TTL_SECONDS
    return now - entry.get("fetched_at", 0) < ttl


def _record(symbol, sector, source):
    with _cache_lock:
        cache = _load_cache()
        cache[symbol] = {"sector": sector, "source": source, "fetched_at": time.time()}
        _save_cache(cache)


def _fetch_sector(symbol):
    """One Yahoo call for a symbol's sector. Returns the sector string or None."""
    yahoo.acquire_call_slot()
    try:
        info = yf.Ticker(symbol).info
    except Exception as exc:
        if yahoo.is_rate_limit_error(exc):
            yahoo.note_rate_limited()
            raise
        return None

    sector = info.get("sector")
    # A bare response with no identity is Yahoo shrugging (delisted, renamed), not a
    # real sector; treating it as one would label dead symbols as investable sectors.
    if info.get("quoteType") in ("NONE", None) and not info.get("longName"):
        return None
    if not isinstance(sector, str) or not sector.strip():
        return None
    return sector.strip()


def get_sector(symbol):
    """Sector for one symbol from cache, fetching from Yahoo only when needed.

    ``None`` means unclassified: Yahoo has no quote, or the request ran out of lookup
    budget. Ordinary misses never raise.
    """
    symbol = symbol.upper()
    now = time.time()
    with _cache_lock:
        entry = _load_cache().get(symbol)
    if _is_fresh(entry, now):
        return entry["sector"]

    try:
        sector = _fetch_sector(symbol)
    except yahoo.YahooBudgetExceeded:
        # Budget spent: answer unclassified without caching, so the next request gets
        # its own chance to resolve this symbol.
        return None
    except Exception:
        return None

    _record(symbol, sector, "yahoo")
    return sector


def get_sectors(symbols):
    """Symbol -> sector for many symbols. Unclassified symbols map to None."""
    yahoo.begin_request_budget()
    return {symbol.upper(): get_sector(symbol) for symbol in symbols}


def cache_stats():
    """Counts of cached entries, for the build script's summary line."""
    cache = _load_cache()
    labeled = sum(1 for e in cache.values() if isinstance(e, dict) and e.get("sector"))
    return {"entries": len(cache), "labeled": labeled, "unclassified": len(cache) - labeled}
