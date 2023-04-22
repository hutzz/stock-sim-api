from index import app, db
from flask import request, jsonify, make_response
from app.models import User, Stock
from app.prices import get_hist_data
import yfinance as yf
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import uuid
import jwt
import datetime

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
        except:
            return jsonify({'message': 'Invalid token.'}), 401
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
        except:
            return jsonify({'message': 'Invalid refresh token.'}), 401
        return function(current_user, *args, **kwargs)
    return decorator

@app.route('/user')
@require_token
def get_users(current_user):
    if not current_user.admin:
        return jsonify({'message': "Insufficient permissions."}), 401
    users = User.query.all()
    if not users:
        return jsonify({'message': 'No users found.'}), 404
    user_list = []
    for user in users:
        data = {}
        data['public_id'] = user.public_id
        data['username'] = user.username
        data['password'] = user.password
        data['balance'] = user.balance
        data['admin'] = user.admin
        user_list.append(data)
    return jsonify({'users: ': user_list})

@app.route('/user/<public_id>')
@require_token
def get_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': "Insufficient permissions."}), 401
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'User not found.'})
    data = {}
    data['public_id'] = user.public_id
    data['username'] = user.username 
    data['password'] = user.password 
    data['balance'] = user.balance
    data['admin'] = user.admin 
    return jsonify(data)

@app.route('/user', methods=['POST'])
@require_token
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message': "Insufficient permissions."}), 401
    data = request.get_json()
    hashed_pw = generate_password_hash(data['password'], method='sha256')
    user = User(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_pw, admin=data['admin'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created.'})

@app.route('/user/<public_id>', methods=['DELETE'])
@require_token
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': "Insufficient permissions."}), 401
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'User not found.'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted.'})

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response(jsonify('Invalid or missing credentials.'), 401)
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response(jsonify('User not found.'), 404)
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'], algorithm='HS256')
        refresh = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=15)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token, 'refresh': refresh})
    return make_response(jsonify('Invalid or missing credentials.'), 401)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_pw = generate_password_hash(data['password'], method='sha256')
    user = User(public_id=str(uuid.uuid4()), username=data['username'], email=data['email'], password=hashed_pw, balance=10000.00, admin=False)
    db.session.add(user)
    try:
        db.session.commit()
    except:
        return jsonify({'message': 'Failed to commit changes to database.'}), 500
    return jsonify({'message': 'User created.'})

@app.route('/refresh')
@require_refresh_token
def refresh_token(current_user):
    refresh_token = request.headers['x-refresh-token']
    if not refresh_token:
        return make_response(jsonify({'message': 'Missing refresh token.'}), 401)
    try:
        jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except:
        return make_response(jsonify({'message': 'Invalid refresh token.'}), 401)
    if not current_user:
        return make_response(jsonify({'message': 'User not found.'}), 404)
    return jsonify({'token': jwt.encode({'public_id': current_user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)}, app.config['SECRET_KEY'], algorithm='HS256'), 'refresh': jwt.encode({'public_id': current_user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=15)}, app.config['SECRET_KEY'], algorithm='HS256')})

@app.route('/stock/<symbol>', methods=['POST'])
def get_stock_data(symbol):
    ticker = yf.Ticker(symbol.upper())
    data = request.get_json()
    interval = data['interval']
    period = data['period']
    try:
        hist_data = get_hist_data(ticker, interval, period)
    except:
        return jsonify({'message': 'Invalid input.'}), 403
    return jsonify(hist_data)

@app.route('/stock/get')
@require_token 
def get_user_stocks(current_user):
    stocks = Stock.query.filter_by(user_id=User.query.filter_by(public_id=current_user.public_id).first().id).all()
    if not stocks:
        return jsonify({'message': 'User has no stocks!'})
    stock_list = []
    for stock in stocks:
        data = {}
        data['symbol'] = stock.symbol
        data['price_at_purchase'] = stock.price_at_purchase
        data['quantity'] = stock.quantity
        stock_list.append(data)
    return jsonify(stock_list)

@app.route('/stock/add/<symbol>', methods=['POST'])
@require_token
def add_stock(current_user, symbol):
    data = request.get_json()
    try:
        ticker = yf.Ticker(symbol.upper())
        current_price = round(get_hist_data(ticker, interval="1d", period="1d")['Close'][-1], 2)
    except:
        return jsonify({'message': 'Invalid input.'}), 403
    try:
        data['quantity'] = int(data['quantity'])
        stock = Stock(user_id=User.query.filter_by(public_id=current_user.public_id).first().id, symbol=symbol.upper(), price_at_purchase=current_price, quantity=data['quantity'])
        current_stock = Stock.query.filter_by(symbol=symbol.upper()).first()
        if current_stock:
            current_stock.quantity += data['quantity']
        else:
            db.session.add(stock)
        current_user.balance -= current_price * data['quantity']
        current_user.balance = round(current_user.balance, 2) # correcting potential floating point imprecision 
        if current_user.balance < 0:
            return jsonify({'message': 'Insufficient funds!'})
        db.session.commit()
    except:
        return jsonify({'message': 'Failed to commit changes to database.'}), 500
    return jsonify({'message': f'Successfully purchased {data["quantity"]} {symbol.upper()}.'})

@app.route('/stock/delete/<symbol>/<quantity>')
@require_token
def sell_stock(current_user, symbol, quantity):
    try:
        ticker = yf.Ticker(symbol.upper())
        current_price = round(get_hist_data(ticker, interval="1d", period="1d")['Close'][-1], 2)
    except:
        return jsonify({'message': 'Invalid input.'}), 403
    try:
        quantity = int(quantity)
        stock = Stock.query.filter_by(user_id=User.query.filter_by(public_id=current_user.public_id).first().id, symbol=symbol.upper()).first()
        if not stock:
            return jsonify({'message': 'Stock not found!'}), 404
        if stock.quantity < quantity:
            return jsonify({'message': f'You have less than {quantity} of that stock!'})
        stock.quantity -= quantity 
        if stock.quantity == 0: 
            db.session.delete(stock)
        current_user.balance += current_price * quantity
        current_user.balance = round(current_user.balance, 2) # correcting potential floating point imprecision 
        db.session.commit()
    except:
        return jsonify({'message': 'Failed to commit changes to database.'}), 500
    return jsonify({'message': f'Successfully sold {quantity} {symbol.upper()}.'})

@app.route('/stock/reset')
@require_token 
def reset_self(current_user):
    stocks = Stock.query.filter_by(user_id=User.query.filter_by(public_id=current_user.public_id).first().id).all()
    if not stocks:
        return jsonify({'message': 'User has no stocks!'})
    current_user.balance = 10000.00
    for stock in stocks:
        db.session.delete(stock)
    db.session.commit()
    return jsonify({'message': 'Successfully reset your stock purchases and account balance.'})
