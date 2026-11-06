import math
from decimal import Decimal, ROUND_HALF_UP

import yfinance as yf
from yfinance import Ticker

from app import yahoo_rate_limit as yahoo

# interval can be 1m, 2m, 5m, 15m, 30m, 60m, 90m, 1h, 1d, 5d, 1wk, 1mo, 3mo
ALLOWED_INTERVALS = frozenset({
    '1m', '2m', '5m', '15m', '30m', '60m', '90m',
    '1h', '1d', '5d', '1wk', '1mo', '3mo',
})
# period is more flexible; restricted so a single request cannot return an
# unbounded payload (e.g. interval=1m with period=max). Must stay a superset of
# every period the frontend offers - see GraphIntervals.razor.cs, which exposes
# 1d/1h, 7d/1d, 1mo/1d and 1y/1wk. Dropping one breaks that graph button.
ALLOWED_PERIODS = frozenset({'1d', '5d', '7d', '1mo', '3mo', '6mo', '1y'})
MAX_HISTORY_ROWS = 5000

HIST_KEYS = ['Datetime', 'Open', 'Close', 'High', 'Low', 'Volume', 'Dividends', 'Stock Splits']


class InvalidPriceRequest(ValueError):
    """The caller asked for something we refuse to serve."""


class PriceUnavailable(Exception):
    """The market-data provider returned nothing usable for this symbol."""


def _clean_number(value):
    """numpy scalars are not JSON-serialisable and NaN/inf breaks jsonify."""
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def get_hist_data(ticker: Ticker, interval: str, period: str) -> dict:
    if interval not in ALLOWED_INTERVALS:
        raise InvalidPriceRequest(f"Invalid interval '{interval}'.")
    if period not in ALLOWED_PERIODS:
        raise InvalidPriceRequest(f"Invalid period '{period}'.")

    try:
        yahoo.acquire_call_slot()
    except yahoo.YahooBudgetExceeded as exc:
        raise PriceUnavailable('No Yahoo lookup budget left for this request.') from exc
    try:
        hist = ticker.history(interval=interval, period=period)
    except Exception as exc:
        if yahoo.is_rate_limit_error(exc):
            yahoo.note_rate_limited()
            raise PriceUnavailable('Yahoo is rate limiting this symbol.') from exc
        raise PriceUnavailable('No market data available for this symbol.') from exc
    if hist is None or len(hist) == 0:
        raise PriceUnavailable('No market data available for this symbol.')
    if len(hist) > MAX_HISTORY_ROWS:
        raise InvalidPriceRequest(
            f'Request would return {len(hist)} rows; choose a shorter period.'
        )

    datetime_list = list(hist.index.strftime('%Y-%m-%d %H:%M:%S'))
    dict_list = {key: (
        datetime_list if key == 'Datetime' else [_clean_number(v) for v in hist[key]]
    ) for key in HIST_KEYS}
    if all(v is None for v in dict_list['Close']):
        raise PriceUnavailable('Market data for this symbol is incomplete.')
    return dict_list


def to_cents(price: float) -> int:
    """Convert a dollar amount to integer cents.

    Goes through Decimal(str(...)) so binary float noise (1.005 stored as
    1.0049999...) cannot shave a cent off the price we charge for a share.
    """
    return int(Decimal(str(price)).scaleb(2).quantize(Decimal('1'), rounding=ROUND_HALF_UP))


def get_dated_closing_prices(symbol: str, count: int = 1) -> list:
    """Up to ``count`` most recent usable daily closes as ``(date, cents)``, oldest first.

    ``count`` of 2 asks for today's close plus the previous close; a symbol with
    only one usable close returns a single entry rather than failing.

    Yahoo leaves an empty bar for every session that has not settled - the current
    day before its close, weekends, holidays - so the freshest rows are routinely
    unusable. Unusable rows are dropped and each surviving price keeps the trading
    date it belongs to, which makes the fallback visible: the price we hand back is
    the last real close *of that date*, never a stale close pretending to be today's.
    Callers that need a calendar day use the returned date, not the wall clock.
    """
    try:
        yahoo.acquire_call_slot()
    except yahoo.YahooBudgetExceeded as exc:
        # Out of politeness budget: report no quote so callers fall back the same way
        # they already do for a delisted symbol, rather than getting Yahoo angry.
        raise PriceUnavailable(f'No lookup budget left for {symbol}.') from exc
    try:
        hist = yf.Ticker(symbol).history(interval='1d', period='5d')
    except Exception as exc:
        if yahoo.is_rate_limit_error(exc):
            yahoo.note_rate_limited()
            raise PriceUnavailable(f'Yahoo is rate limiting {symbol}.') from exc
        raise PriceUnavailable(f'No market data available for {symbol}.') from exc
    if hist is None or len(hist) == 0:
        raise PriceUnavailable(f'No market data available for {symbol}.')
    rows = [
        (idx.strftime('%Y-%m-%d'), _clean_number(close))
        for idx, close in zip(hist.index, hist['Close'])
    ]
    rows = [(date, close) for date, close in rows if close is not None]
    if not rows:
        raise PriceUnavailable(f'Market data for {symbol} is incomplete.')
    return [(date, to_cents(close)) for date, close in rows[-count:]]


def get_closing_prices(symbol: str, count: int = 1) -> list:
    """Up to ``count`` most recent daily closing prices in cents, oldest first.

    Thin wrapper over :func:`get_dated_closing_prices` for callers that only need the
    numbers; use the dated version when the price has to be attributed to a day.
    """
    return [cents for _, cents in get_dated_closing_prices(symbol, count)]
