"""SEC EDGAR company universe: ticker -> canonical name, exchange, CIK.

The SEC publishes the full registered-company ticker list as one static JSON file,
which is what lets this app cover any listed symbol instead of a hand-maintained
list. Requests are polite by construction: one small file, cached on disk for a day,
with the User-Agent EDGAR asks for.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request

UNIVERSE_URL = "https://www.sec.gov/files/company_tickers_exchange.json"
# EDGAR's published ceiling is 10 requests per second; stay well under it.
REQUEST_SPACING_SECONDS = 0.25
CACHE_TTL_SECONDS = 24 * 60 * 60
# EDGAR rejects requests without an identifying User-Agent (a bare browser UA gets a 403),
# and asks for a reachable contact address. Override with SEC_USER_AGENT to use your own.
USER_AGENT = os.environ.get(
    "SEC_USER_AGENT", "StockSim portfolio charts (contact: hutzz@example.com)")

CACHE_DIR = os.path.join(os.path.dirname(__file__), "cache")
UNIVERSE_CACHE = os.path.join(CACHE_DIR, "sec_universe.json")

_last_request_at = 0.0

# Corporate suffixes carry no identifying information, and the two sources spell the
# same company differently ("Marsh & McLennan Companies Inc." vs
# 'MARSH & MCLENNAN COMPANIES, INC.'), so both sides are reduced to the stem.
_NAME_SUFFIXES = {
    "inc", "incorporated", "corp", "corporation", "co", "company", "companies",
    "ltd", "limited", "plc", "llc", "lp", "sa", "nv", "ag", "bv", "new", "the",
}


class UniverseUnavailable(Exception):
    """The SEC ticker file could not be fetched or parsed."""


def _throttle():
    global _last_request_at
    wait = REQUEST_SPACING_SECONDS - (time.monotonic() - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.monotonic()


def _get_json(url, ttl_seconds=CACHE_TTL_SECONDS, cache_path=None):
    if cache_path and os.path.exists(cache_path):
        try:
            with open(cache_path, encoding="utf-8") as handle:
                cached = json.load(handle)
            if time.time() - cached.get("fetched_at", 0) < ttl_seconds:
                return cached["data"]
        except (json.JSONDecodeError, OSError):
            pass

    _throttle()
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            if response.headers.get("Content-Encoding") == "gzip":
                import gzip

                raw = gzip.decompress(raw)
            data = json.loads(raw)
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
        raise UniverseUnavailable(f"Could not load SEC data: {exc}") from exc

    if cache_path:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as handle:
            json.dump({"fetched_at": time.time(), "data": data}, handle)
    return data


def normalize_name(name):
    """Reduce a company name to its identifying stem for cross-source matching."""
    stem = name.split("/")[0].strip().lower()
    stem = re.sub(r"[^a-z0-9& ]", " ", stem)
    tokens = [t for t in stem.split() if t and t not in _NAME_SUFFIXES]
    return " ".join(tokens)


def load_universe(force_refresh=False):
    """Every registered ticker with its canonical name, exchange and CIK.

    Returns a dict keyed by upper-case ticker. Duplicate tickers do not occur in the
    SEC file, so this is a clean join key against the app's own symbol lists.
    """
    if force_refresh and os.path.exists(UNIVERSE_CACHE):
        os.remove(UNIVERSE_CACHE)
    try:
        payload = _get_json(UNIVERSE_URL, cache_path=UNIVERSE_CACHE)
    except UniverseUnavailable:
        return {}

    universe = {}
    for cik, name, ticker, exchange in payload.get("data", []):
        universe[ticker.upper()] = {
            "cik": cik,
            "name": name,
            "exchange": exchange,
            "normalized": normalize_name(name),
        }
    return universe


def build_name_index(universe):
    """Normalized company name -> ticker, keeping only unambiguous names.

    Ambiguous stems are dropped rather than guessed at, so a name lookup can never
    resolve to the wrong company.
    """
    index = {}
    ambiguous = set()
    for ticker, entry in universe.items():
        normalized = entry["normalized"]
        if not normalized:
            continue
        if normalized in index:
            ambiguous.add(normalized)
        else:
            index[normalized] = ticker
    for normalized in ambiguous:
        index.pop(normalized, None)
    return index


def find_cik_by_name(name, universe):
    """CIK for a company name, matched on the identifying stem. None when unclear."""
    index = build_name_index(universe)
    ticker = index.get(normalize_name(name))
    if not ticker:
        return None
    return universe[ticker]["cik"]


