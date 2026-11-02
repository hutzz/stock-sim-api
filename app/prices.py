import math
from decimal import Decimal, ROUND_HALF_UP

import yfinance as yf
from yfinance import Ticker

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

    hist = ticker.history(interval=interval, period=period)
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


def get_closing_prices(symbol: str, count: int = 1) -> list:
    """Up to ``count`` most recent daily closing prices in cents, oldest first.

    ``count`` of 2 asks for today's close plus the previous close; a symbol with
    only one usable close returns a single entry rather than failing.
    """
    hist = yf.Ticker(symbol).history(interval='1d', period='5d')
    if hist is None or len(hist) == 0:
        raise PriceUnavailable(f'No market data available for {symbol}.')
    closes = [_clean_number(v) for v in hist['Close']]
    closes = [c for c in closes if c is not None]
    if not closes:
        raise PriceUnavailable(f'Market data for {symbol} is incomplete.')
    return [to_cents(c) for c in closes[-count:]]
