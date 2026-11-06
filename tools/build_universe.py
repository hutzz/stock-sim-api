"""Build the stock universe from SEC EDGAR and report drift against data.txt.

Run manually, never from a request handler::

    python tools\\build_universe.py            # refresh cache if stale, write universe.json
    python tools\\build_universe.py --refresh  # force a fresh download from the SEC

Output goes to ``StockSim.Frontend/wwwroot/universe.json`` as a checked-in static asset,
so page loads never depend on the SEC. The drift report compares the live SEC list with
the hand-maintained data.txt so a snapshot going stale is visible in plain text.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.sec_data import UNIVERSE_URL, UniverseUnavailable, load_universe, normalize_name

FRONTEND_WWWROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "stock-sim", "StockSim.Frontend", "wwwroot")
UNIVERSE_OUTPUT = os.path.join(FRONTEND_WWWROOT, "universe.json")
LEGACY_LIST = os.path.join(FRONTEND_WWWROOT, "data.txt")


def read_legacy_list(path):
    """The hand-maintained ticker,name file. Returns an ordered list of pairs."""
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.strip()
            if not line or "," not in line:
                continue
            ticker, name = line.split(",", 1)
            rows.append((ticker.strip().upper(), name.strip()))
    return rows


def write_universe(universe, path):
    payload = {
        ticker: {"name": entry["name"], "exchange": entry["exchange"]}
        for ticker, entry in sorted(universe.items())
    }
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp_path, path)
    return len(payload)


def drift_report(universe, legacy):
    """What the SEC list and data.txt disagree about.

    A legacy ticker missing from the SEC list is reported separately from one whose
    company still exists under a different ticker (a rename), matched on the name stem.
    """
    sec_by_ticker = universe
    legacy_by_ticker = dict(legacy)

    gone = [t for t in legacy_by_ticker if t not in sec_by_ticker]
    new = [t for t in sec_by_ticker if t not in legacy_by_ticker]
    overlap = [t for t in legacy_by_ticker if t in sec_by_ticker]

    # Share classes are spelled differently by the two sources (data.txt "BRK.B",
    # the SEC file "BRK-B"), so a dot/dash difference counts as the same listing.
    def canonical(ticker):
        return ticker.replace(".", "-")

    sec_canonical = {canonical(t): t for t in sec_by_ticker}
    sec_by_stem = {}
    for ticker, entry in sec_by_ticker.items():
        sec_by_stem.setdefault(normalize_name(entry["name"]), []).append(ticker)

    renamed = []
    relisted = {}
    for ticker in gone:
        match = sec_canonical.get(canonical(ticker))
        if match:
            relisted[ticker] = match
            continue
        stem = normalize_name(legacy_by_ticker[ticker])
        candidates = sec_by_stem.get(stem, []) if stem else []
        if len(candidates) == 1:
            renamed.append(ticker)
            relisted[ticker] = candidates[0]

    exchanges = {}
    for entry in sec_by_ticker.values():
        key = entry.get("exchange") or "Unknown"
        exchanges[key] = exchanges.get(key, 0) + 1

    print(f"SEC universe rows:      {len(sec_by_ticker)}")
    print(f"data.txt rows:          {len(legacy_by_ticker)}")
    print(f"in both:                {len(overlap)}")
    print(f"only in data.txt:       {len(gone)}  "
          f"(of which {len(renamed)} match a SEC company under a different ticker)")
    print(f"only in SEC universe:   {len(new)}")
    print("SEC exchange spread:    " + ", ".join(
        f"{k} {v}" for k, v in sorted(exchanges.items(), key=lambda kv: -kv[1])))

    def show(title, tickers, limit=20):
        print(f"\n{title} (first {min(limit, len(tickers))}):")
        for ticker in tickers[:limit]:
            match = relisted.get(ticker)
            sec_name = sec_by_ticker.get(match, {}).get("name", "")
            print(f"  {ticker:<8} data.txt: {legacy_by_ticker.get(ticker, '-')}")
            print(f"           SEC:     {match or '(no match)'} {sec_name}".rstrip())

    show("Renamed - company is in the SEC list under a new ticker", renamed)
    show("Gone - no SEC row and no matching company name",
         [t for t in gone if t not in relisted])
    return {"gone": gone, "new": new, "renamed": renamed, "overlap": overlap,
            "relisted": relisted}


def main(argv):
    force_refresh = "--refresh" in argv
    try:
        universe = load_universe(force_refresh=force_refresh)
    except UniverseUnavailable as exc:
        print(f"Cannot build the universe: {exc}", file=sys.stderr)
        return 1
    if not universe:
        print("SEC returned no rows; leaving universe.json untouched.", file=sys.stderr)
        return 1

    legacy = read_legacy_list(LEGACY_LIST)
    count = write_universe(universe, UNIVERSE_OUTPUT)
    print(f"Wrote {count} tickers to {UNIVERSE_OUTPUT}\n")
    drift_report(universe, legacy)
    print(f"\nSource: {UNIVERSE_URL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
