import datetime

from index import db

STARTING_BALANCE_CENTS = 10_000_00


def utcnow_naive():
    """UTC timestamp without tzinfo; SQLite DATETIME columns store naive values."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


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
    