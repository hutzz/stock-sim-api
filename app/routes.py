from index import app, db
from flask import request, jsonify
from app.models import (
    User,
    Stock,
    Transaction,
    PortfolioSnapshot,
    STARTING_BALANCE_CENTS,
    utcnow_naive,
    market_today,
)
from app.prices import (
    get_hist_data,
    get_dated_closing_prices,
    to_cents,
    InvalidPriceRequest,
    PriceUnavailable,
)
from app import sectors as sector_lookup
from app.yahoo_rate_limit import budget
import yfinance as yf
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from functools import wraps
from decimal import Decimal, ROUND_HALF_UP
import uuid
import jwt
import datetime
import re


class InvalidInput(ValueError):
    """The request body was missing a field or had an unusable value."""


SYMBOL_RE = re.compile(r'^[A-Z][A-Z.\-]{0,7}$')


def parse_symbol(value):
    if not isinstance(value, str):
        raise InvalidInput('Symbol must be a string.')
    symbol = value.strip().upper()
    if not SYMBOL_RE.match(symbol):
        raise InvalidInput('Invalid symbol. Use 1-8 letters, optionally with "." or "-".')
    return symbol


def parse_quantity(value):
    # Type is validated before the range so "abc" reports a type error, not a range error.
    if isinstance(value, bool):
        raise InvalidInput('Quantity must be an integer.')
    if isinstance(value, int):
        quantity = value
    elif isinstance(value, str) and value.isdigit():
        quantity = int(value)
    else:
        raise InvalidInput('Quantity must be an integer.')
    if quantity < 1:
        raise InvalidInput('Quantity must be at least 1.')
    return quantity


def json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise InvalidInput('Request body must be a JSON object.')
    return data


def cents_to_dollars(cents):
    if cents is None:
        return None
    return float(Decimal(cents).scaleb(-2).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))


def _as_date(value):
    """Accept the ISO string Yahoo gives us or an already-parsed date."""
    if isinstance(value, datetime.date):
        return value
    return datetime.datetime.strptime(value, '%Y-%m-%d').date()


def record_portfolio_snapshot(user, market_value_cents, quote_date=None):
    """Store a portfolio roll-up against the trading day its prices belong to.

    The trend chart plots stored values only. Recomputing history from live quotes
    would let today's prices rewrite what yesterday's dashboard showed.

    ``quote_date`` is the session the freshest close came from, not the clock on the
    wall: Yahoo has no settled bar for an in-progress session, weekends or holidays, so
    stamping the snapshot with "today" invents a point whose value is just the previous
    close - a flat duplicate that reads as a real day. A snapshot is therefore filed
    under its own data date, and a date older than the newest stored point is skipped:
    it can add nothing to the chart, and writing cash into an older row would rewrite
    history. Returns the date recorded, or None when the visit added nothing.
    """
    snapshot_date = _as_date(quote_date) if quote_date is not None else market_today()
    newest_date = db.session.query(
        func.max(PortfolioSnapshot.snapshot_date)
    ).filter(PortfolioSnapshot.user_id == user.id).scalar()
    if newest_date is not None and snapshot_date < newest_date:
        return None
    snapshot = PortfolioSnapshot.query.filter_by(user_id=user.id, snapshot_date=snapshot_date).first()
    if snapshot is None:
        snapshot = PortfolioSnapshot(user_id=user.id, snapshot_date=snapshot_date)
        db.session.add(snapshot)
    snapshot.cash_cents = user.balance_cents
    snapshot.market_value_cents = market_value_cents
    snapshot.total_value_cents = user.balance_cents + market_value_cents
    snapshot.updated_at = utcnow_naive()
    return snapshot_date


def require_token(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        token = None 
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Missing token.'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except Exception:
            return jsonify({'message': 'Invalid token.'}), 401
        # Tokens outlive the account they were issued for; treat them as invalid.
        if not current_user:
            return jsonify({'message': 'User not found.'}), 401
        return function(current_user, *args, **kwargs)
    return decorator

def require_refresh_token(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        token = None 
        if 'x-refresh-token' in request.headers:
            token = request.headers['x-refresh-token']
        if not token:
            return jsonify({'message': 'Missing refresh token.'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except Exception:
            return jsonify({'message': 'Invalid refresh token.'}), 401
        if not current_user:
            return jsonify({'message': 'User not found.'}), 401
        return function(current_user, *args, **kwargs)
    return decorator

@app.route('/user')
@require_token
def get_users(current_user):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        users = User.query.all()
        if not users:
            return jsonify({'message': 'No users found.'}), 404
        user_list = []
        for user in users:
            data = {}
            data['public_id'] = user.public_id
            data['email'] = user.email
            data['username'] = user.username
            data['balance'] = user.balance
            data['admin'] = user.admin
            user_list.append(data)
        return jsonify({'users': user_list})
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/user/<public_id>')
@require_token
def get_user(current_user, public_id):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        data = {}
        data['public_id'] = user.public_id
        data['username'] = user.username 
        data['balance'] = user.balance
        data['admin'] = user.admin 
        return jsonify(data)
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500
    
@app.route('/me')
@require_token
def get_current_user(current_user):
    data = {}
    data['public_id'] = current_user.public_id
    data['username'] = current_user.username 
    data['balance'] = current_user.balance
    data['admin'] = current_user.admin
    return jsonify(data) 

@app.route('/user', methods=['POST'])
@require_token
def create_user(current_user):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        data = json_body()
        for field in ('username', 'email', 'password'):
            if not data.get(field):
                raise InvalidInput(f'{field} is required.')
        hashed_pw = generate_password_hash(data['password'])
        user = User(public_id=str(uuid.uuid4()), username=data['username'], email=data['email'], password=hashed_pw, admin=bool(data.get('admin')), balance_cents=STARTING_BALANCE_CENTS)
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User created.'})
    except InvalidInput as e:
        db.session.rollback()
        return jsonify({'message': str(e)}), 400
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Username or email already exists.'}), 409
    except Exception as e:
        app.logger.error(e)
        db.session.rollback()
        return jsonify({'message': "An error occurred."}), 500

@app.route('/user/<public_id>', methods=['DELETE'])
@require_token
def delete_user(current_user, public_id):
    try:
        if not current_user.admin:
            return jsonify({'message': "Insufficient permissions."}), 401
        user = User.query.filter_by(public_id=public_id).first()
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        # Deleting a user cascades to their positions and ledger entries at the
        # database level (ON DELETE CASCADE, enabled by the foreign_keys pragma).
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted.'})
    except Exception as e:
        app.logger.error(e)
        db.session.rollback()
        return jsonify({'message': "An error occurred."}), 500

@app.route('/login')
def login():
    try:
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return jsonify({'message': 'Invalid or missing credentials.'}), 401
        user = User.query.filter_by(username=auth.username).first()
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        try:
            password_ok = check_password_hash(user.password, auth.password)
        except ValueError:
            # Stored hash uses a format this Werkzeug version cannot verify.
            password_ok = False
        if password_ok:
            token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'], algorithm='HS256')
            refresh = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=15)}, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'token': token, 'refresh': refresh})
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500
    return jsonify({'message': 'Invalid or missing credentials.'}), 401

@app.route('/register', methods=['POST'])
def register():
    try:
        data = json_body()
        if not re.search(r".+@.+\..+", data.get('email', '')) or re.search(r"[%\\\?\"\'~/\$\*\{\}\s]", data.get('email', '')) or len(data.get('email', '')) > 128 or not data.get('email', '').isascii():
            return jsonify({'message': 'Invalid email. Check for any special characters that may be present, and ensure that the entered email address is formatted correctly.'}), 401
        if not data.get('username') or re.search(r"[%\\\?\"\'~/\$\*\{\}\s]", data['username']) or len(data['username']) > 32 or not data['username'].isascii():
            return jsonify({'message': 'Invalid username. Check for any special characters that may be present.'}), 401
        if not data.get('password') or re.search(r"[%\\\?\"\'~/\$\*\{\}\s]", data["password"]) or len(data["password"]) < 8 or not data['password'].isascii():
            return jsonify({'message': 'Invalid password. Check for any special characters that may be present.'}), 401
        hashed_pw = generate_password_hash(data['password'])
        user = User(public_id=str(uuid.uuid4()), username=data['username'], email=data['email'], password=hashed_pw, balance_cents=STARTING_BALANCE_CENTS, admin=False)
        db.session.add(user)
        # Uniqueness is enforced by the database, so concurrent signups cannot both win.
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Username or email is already taken.'}), 409
    except Exception as e:
        app.logger.error(e)
        db.session.rollback()
        return jsonify({'message': "An error occurred."}), 500
    return jsonify({'message': 'User created.'})

@app.route('/refresh')
@require_refresh_token
def refresh_token(current_user):
    try:
        refresh_token = request.headers['x-refresh-token']
        if not refresh_token:
            return jsonify({'message': 'Missing refresh token.'}), 401
        try:
            jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except Exception:
            return jsonify({'message': 'Invalid refresh token.'}), 401
        now = datetime.datetime.now(datetime.UTC)
        return jsonify({'token': jwt.encode({'public_id': current_user.public_id, 'exp': now + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'], algorithm='HS256'), 'refresh': jwt.encode({'public_id': current_user.public_id, 'exp': now + datetime.timedelta(days=15)}, app.config['SECRET_KEY'], algorithm='HS256')})
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/stock/<symbol>', methods=['POST'])
@budget
def get_stock_data(symbol):
    try:
        symbol = parse_symbol(symbol)
        data = json_body()
        interval = data.get('interval')
        period = data.get('period')
        if not interval or not period:
            raise InvalidInput('Both interval and period are required.')
        hist_data = get_hist_data(yf.Ticker(symbol), interval, period)
        return jsonify(hist_data)
    except InvalidInput as e:
        return jsonify({'message': str(e)}), 400
    except InvalidPriceRequest as e:
        return jsonify({'message': str(e)}), 400
    except PriceUnavailable as e:
        return jsonify({'message': str(e)}), 404
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/stock/get')
@require_token 
@budget
def get_user_stocks(current_user):
    try:
        stocks = Stock.query.filter_by(user_id=current_user.id).all()
        if not stocks:
            return jsonify({'message': 'User has no stocks!'}), 400
        stock_list = []
        for stock in stocks:
            data = {}
            # One history call per stock; 5d gives us the latest close plus the previous
            # close so the dashboard can show a day-over-day trend without extra lookups.
            try:
                closes = get_dated_closing_prices(stock.symbol, count=2)
                price_date, price_cents = closes[-1]
                previous_date, previous_price_cents = closes[-2] if len(closes) > 1 else (None, None)
            except PriceUnavailable:
                # A delisted symbol must not fail the whole portfolio request. It has no
                # price and no session to attribute one to, which the caller must show as
                # "no quote" rather than as a value of its own.
                price_date, price_cents = None, None
                previous_date, previous_price_cents = None, None
            market_value_cents = None if price_cents is None else price_cents * stock.quantity
            data['symbol'] = stock.symbol
            data['price'] = cents_to_dollars(price_cents)
            # Every price we report belongs to a specific settled session. Yahoo has no
            # settled bar for an in-progress session, weekends or holidays, so the latest
            # close is routinely from an earlier day; showing its date stops a Friday
            # close being read as today's.
            data['price_date'] = price_date
            data['previous_price'] = cents_to_dollars(previous_price_cents)
            data['previous_price_date'] = previous_date
            data['quantity'] = stock.quantity
            data['avg_cost'] = cents_to_dollars(stock.avg_cost_cents)
            data['market_value'] = cents_to_dollars(market_value_cents)
            unrealized_cents = None if market_value_cents is None else market_value_cents - stock.cost_basis_cents
            data['unrealized_pnl'] = cents_to_dollars(unrealized_cents)
            stock_list.append(data)
        return jsonify(stock_list)
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500

@app.route('/stock/summary')
@require_token
@budget
def get_portfolio_summary(current_user):
    """Cash, market value and P&L rolled up from positions plus the trade ledger.

    Realized P&L only exists because every fill is recorded in the transaction
    table; unrealized P&L compares current market value against cost basis.
    The same roll-up is stored as a snapshot so the dashboard trend chart has
    history to draw, filed under the trading day the quotes came from.
    """
    try:
        positions = Stock.query.filter_by(user_id=current_user.id).all()
        market_value_cents = 0
        cost_basis_cents = 0
        quote_dates = []
        unquoted_symbols = []
        for position in positions:
            cost_basis_cents += position.cost_basis_cents
            try:
                quote_date, price_cents = get_dated_closing_prices(position.symbol, count=1)[0]
            except PriceUnavailable:
                # A delisted holding has no quote; fall back to what it cost so the
                # portfolio total stays computable instead of failing outright. It
                # carries no market date, so it cannot date the roll-up either, and
                # the caller must be told this part of the total is not a market value.
                price_cents = position.avg_cost_cents
                unquoted_symbols.append(position.symbol)
            else:
                quote_dates.append(quote_date)
            market_value_cents += price_cents * position.quantity
        realized_pnl_cents = db.session.query(
            func.coalesce(func.sum(Transaction.realized_pnl_cents), 0)
        ).filter(Transaction.user_id == current_user.id).scalar()
        # The freshest close in the book decides which session this roll-up describes.
        snapshot_date = max(quote_dates) if quote_dates else market_today()
        record_portfolio_snapshot(current_user, market_value_cents, snapshot_date)
        # The roll-up is read-only apart from the snapshot row, so committing here
        # persists only the chart history.
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500
    return jsonify({
        'cash': cents_to_dollars(current_user.balance_cents),
        'positions': len(positions),
        'cost_basis': cents_to_dollars(cost_basis_cents),
        'market_value': cents_to_dollars(market_value_cents),
        'unrealized_pnl': cents_to_dollars(market_value_cents - cost_basis_cents),
        'realized_pnl': cents_to_dollars(realized_pnl_cents),
        'total_value': cents_to_dollars(current_user.balance_cents + market_value_cents),
        'total_return': cents_to_dollars(
            current_user.balance_cents + market_value_cents - STARTING_BALANCE_CENTS),
        'quote_date': snapshot_date,
        # Positions priced at their average cost because Yahoo has no close for them.
        # Their share of the total is carried at cost, not marked to a market.
        'unquoted_symbols': unquoted_symbols,
    })


@app.route('/stock/quote')
@require_token
@budget
def get_stock_quote(current_user):
    """The price a trade on this symbol would fill at, and the session it comes from.

    The trade forms quote an order before submitting it so the amount about to move is
    visible up front. A fill always uses the latest settled close, which during an
    in-progress session is an earlier day's, so the date travels with the number.
    """
    try:
        symbol = parse_symbol(request.args.get('symbol'))
        quote_date, price_cents = get_dated_closing_prices(symbol, count=1)[0]
    except InvalidInput as e:
        return jsonify({'message': str(e)}), 400
    except PriceUnavailable as e:
        return jsonify({'message': str(e)}), 404
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500
    return jsonify({
        'symbol': symbol,
        'price': cents_to_dollars(price_cents),
        'price_date': quote_date,
    })

MAX_SECTOR_SYMBOLS = 40


@app.route('/stock/sectors')
@require_token
def get_sector_labels(current_user):
    """Sector label for each requested symbol, for the dashboard industry charts.

    Symbols come from the query string (``?symbols=AAPL,MSFT``). Labels are served from
    a persistent cache; only uncached symbols cost a Yahoo call, and those are spaced
    and capped so the app cannot get its IP blocked. A symbol Yahoo does not know
    returns ``sector: null``, which the frontend renders as Unclassified.
    """
    raw = request.args.get('symbols', '')
    symbols = []
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        try:
            symbols.append(parse_symbol(item))
        except InvalidInput:
            return jsonify({'message': f'Invalid symbol: {item}'}), 400
    if len(symbols) > MAX_SECTOR_SYMBOLS:
        return jsonify({
            'message': f'Request at most {MAX_SECTOR_SYMBOLS} symbols per call.'
        }), 400

    try:
        resolved = sector_lookup.get_sectors(symbols)
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500
    return jsonify({
        'sectors': [{'symbol': symbol, 'sector': resolved.get(symbol)} for symbol in symbols],
        'unclassified_label': 'Unclassified',
    })


@app.route('/stock/history')
@require_token
def get_portfolio_history(current_user):
    """Stored daily portfolio totals, oldest first, for the dashboard trend chart."""
    try:
        snapshots = (PortfolioSnapshot.query.filter_by(user_id=current_user.id)
                     .order_by(PortfolioSnapshot.snapshot_date.asc())
                     .limit(365)
                     .all())
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500
    return jsonify([
        {
            'date': snapshot.snapshot_date.strftime('%Y-%m-%d'),
            'cash': cents_to_dollars(snapshot.cash_cents),
            'market_value': cents_to_dollars(snapshot.market_value_cents),
            'total_value': cents_to_dollars(snapshot.total_value_cents),
        }
        for snapshot in snapshots
    ])


@app.route('/stock/buy', methods=['POST'])
@require_token
@budget
def buy_stock(current_user):
    try:
        data = json_body()
        symbol = parse_symbol(data.get('symbol'))
        quantity = parse_quantity(data.get('quantity'))
        # Price lookup happens before any balance check so a bad symbol reports as such.
        # The fill is the latest settled close, tagged with its session: during an
        # in-progress session that close belongs to an earlier day, and the confirmation
        # has to say so rather than implying the order filled at today's price.
        quote_date, price_cents = get_dated_closing_prices(symbol, count=1)[0]
    except InvalidInput as e:
        return jsonify({'message': str(e)}), 400
    except InvalidPriceRequest as e:
        return jsonify({'message': str(e)}), 400
    except PriceUnavailable as e:
        return jsonify({'message': str(e)}), 404
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500
    cost_cents = price_cents * quantity
    try:
        # Affordability is checked before anything is mutated, so a rejected order
        # leaves no half-applied position behind.
        if current_user.balance_cents < cost_cents:
            return jsonify({'message': 'Insufficient funds!'}), 400
        position = Stock.query.filter_by(user_id=current_user.id, symbol=symbol).first()
        if position:
            position.quantity += quantity
            # Cost basis accumulates, keeping the average cost correct for repeat buys.
            position.cost_basis_cents += cost_cents
        else:
            db.session.add(Stock(user_id=current_user.id, symbol=symbol, cost_basis_cents=cost_cents, quantity=quantity))
        current_user.balance_cents -= cost_cents
        db.session.add(Transaction(user_id=current_user.id, symbol=symbol, side='buy', quantity=quantity, price_cents=price_cents, cash_delta_cents=-cost_cents))
        db.session.commit()
    except Exception as e:
        app.logger.error(e)
        db.session.rollback()
        return jsonify({'message': 'Failed to commit changes to database.'}), 500
    return jsonify({
        'message': f'Successfully purchased {quantity} {symbol}.',
        'balance': current_user.balance,
        'filled_price': cents_to_dollars(price_cents),
        'fill_date': quote_date,
    })

@app.route('/stock/sell', methods=['POST'])
@require_token
def sell_stock(current_user):
    try:
        data = json_body()
        symbol = parse_symbol(data.get('symbol'))
        quantity = parse_quantity(data.get('quantity'))
        # Same fill rule as a buy: the latest settled close, tagged with its session.
        quote_date, price_cents = get_dated_closing_prices(symbol, count=1)[0]
    except InvalidInput as e:
        return jsonify({'message': str(e)}), 400
    except InvalidPriceRequest as e:
        return jsonify({'message': str(e)}), 400
    except PriceUnavailable as e:
        return jsonify({'message': str(e)}), 404
    except Exception as e:
        app.logger.error(e)
        return jsonify({'message': "An error occurred."}), 500
    proceeds_cents = price_cents * quantity
    try:
        position = Stock.query.filter_by(user_id=current_user.id, symbol=symbol).first()
        if not position:
            return jsonify({'message': 'Stock not found!'}), 404
        if position.quantity < quantity:
            return jsonify({'message': f'You have less than {quantity} of that stock!'}), 400
        avg_cost_cents = round(position.cost_basis_cents / position.quantity)
        realized_pnl_cents = (price_cents - avg_cost_cents) * quantity
        # Removing the proportional share of cost basis keeps the remaining average exact.
        position.cost_basis_cents -= round(position.cost_basis_cents * quantity / position.quantity)
        position.quantity -= quantity
        if position.quantity == 0: 
            db.session.delete(position)
        current_user.balance_cents += proceeds_cents
        db.session.add(Transaction(user_id=current_user.id, symbol=symbol, side='sell', quantity=quantity, price_cents=price_cents, cash_delta_cents=proceeds_cents, realized_pnl_cents=realized_pnl_cents))
        db.session.commit()
    except Exception as e:
        app.logger.error(e)
        db.session.rollback()
        return jsonify({'message': 'Failed to commit changes to database.'}), 500
    return jsonify({
        'message': f'Successfully sold {quantity} {symbol}.',
        'balance': current_user.balance,
        'filled_price': cents_to_dollars(price_cents),
        'fill_date': quote_date,
    })

@app.route('/expiry', methods=['POST'])
def get_expiry_time():
    try:
        data = json_body()
    except InvalidInput as e:
        return jsonify({'error': str(e)}), 400
    token = data.get('token')
    if not token:
        return jsonify({'error': 'Token is missing'}), 400
    try:
        # Signature verification is intentionally skipped: this endpoint only reports
        # the expiry claim a client already holds, and proves nothing about validity.
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'], options={"verify_signature": False},)
        expiry_time = decoded_token['exp']
        return jsonify({'expiry_time': expiry_time})
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401
        
@app.route('/stock/reset')
@require_token 
def reset_self(current_user):
    try:
        stocks = Stock.query.filter_by(user_id=current_user.id).all()
        # Reset is idempotent: with no positions it just restores the starting balance.
        cash_delta_cents = STARTING_BALANCE_CENTS - current_user.balance_cents
        for stock in stocks:
            db.session.delete(stock)
        current_user.balance_cents = STARTING_BALANCE_CENTS
        db.session.add(Transaction(user_id=current_user.id, symbol=None, side='reset', quantity=0, price_cents=0, cash_delta_cents=cash_delta_cents))
        db.session.commit()
        return jsonify({'message': 'Successfully reset your stock purchases and account balance.', 'balance': current_user.balance})
    except Exception as e:
        app.logger.error(e)
        db.session.rollback()
        return jsonify({'message': "An error occurred."}), 500
