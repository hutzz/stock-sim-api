import datetime
from zoneinfo import ZoneInfo

from index import db

STARTING_BALANCE_CENTS = 10_000_00

MARKET_TZ_NAME = 'America/New_York'

try:
    MARKET_TZ = ZoneInfo(MARKET_TZ_NAME)
except Exception:
    # Windows has no system tz database, so zoneinfo needs the tzdata package. Without
    # it the exchange day cannot be resolved and snapshots fall back to the UTC day.
    MARKET_TZ = None


def utcnow_naive():
    """UTC timestamp without tzinfo; SQLite DATETIME columns store naive values."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def market_today():
    """The exchange's calendar day right now.

    Quotes and snapshots are all US trading days, so the day a snapshot belongs to is
    decided in New York time: an evening dashboard visit on Nov 4 is a Nov 4 point,
    not a Nov 5 one.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    if MARKET_TZ is None:
        return now.date()
    return now.astimezone(MARKET_TZ).date()


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    balance_cents = db.Column(db.Integer, nullable=False, default=STARTING_BALANCE_CENTS)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    stocks = db.relationship('Stock', backref='user', cascade='all, delete-orphan', passive_deletes=True)
    transactions = db.relationship('Transaction', backref='user', cascade='all, delete-orphan', passive_deletes=True)

    @property
    def balance(self):
        """Balance in dollars, derived from the cents column."""
        return round(self.balance_cents / 100, 2)


class Stock(db.Model):
    __tablename__ = 'stock'
    __table_args__ = (db.UniqueConstraint('user_id', 'symbol', name='uq_stock_user_symbol'),)
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    symbol = db.Column(db.String(12), nullable=False)
    # Total cost basis of the position in cents. Stored as a total rather than an
    # average so repeat purchases accumulate exactly with no rounding drift.
    cost_basis_cents = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    @property
    def avg_cost_cents(self):
        return round(self.cost_basis_cents / self.quantity)


class PortfolioSnapshot(db.Model):
    """One row per user per day: the portfolio roll-up as of the latest dashboard load.

    The trend chart needs history the app never kept before, so it is captured on each
    summary request. Values are stored, not recomputed later, because prices move and a
    chart drawn from today's quotes would silently rewrite yesterday's line.
    """
    __tablename__ = 'portfolio_snapshot'
    __table_args__ = (db.UniqueConstraint('user_id', 'snapshot_date', name='uq_snapshot_user_date'),)
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    snapshot_date = db.Column(db.Date, nullable=False)
    cash_cents = db.Column(db.Integer, nullable=False)
    market_value_cents = db.Column(db.Integer, nullable=False)
    total_value_cents = db.Column(db.Integer, nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive)


class Transaction(db.Model):
    """Append-only ledger of every cash movement: buys, sells and resets."""
    __tablename__ = 'transaction'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    symbol = db.Column(db.String(12))
    side = db.Column(db.String(5), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    price_cents = db.Column(db.Integer, nullable=False, default=0)
    cash_delta_cents = db.Column(db.Integer, nullable=False)
    realized_pnl_cents = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive)
    