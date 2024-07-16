from flask import Flask, request, jsonify, session
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import pyotp
import qrcode
from io import BytesIO
import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import re
import json
from datetime import datetime
import bleach
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'another-super-secret')
app.config['SESSION_TIMEOUT'] = 30 * 60  # 30 minutes

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Rate limiter configurations
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Logger configuration
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory user storage
users = {}

# encryption key parameters
SALT = b'some_salt'
KEY = PBKDF2(os.getenv('ENCRYPTION_KEY', 'default-key'), SALT, dkLen=32)

def encryptData(data):
    cipher = AES.new(KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decryptData(data):
    data = base64.b64decode(data.encode('utf-8'))
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Helper function to generate OTP QR code
def qrCodeGen(user_email, secret):
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user_email, issuer_name="NYCeBanking")
    img = qrcode.make(uri)
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

# Validation Functions
def emailValidation(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

def passwordValidation(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[\W_]', password):
        return False
    return True

def creditcardValidation(card_number):
    def luhn_checksum(card_number):
        def digits_of(n):
            return [int(d) for d in str(n)]
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d*2))
        return checksum % 10
    return luhn_checksum(card_number) == 0

def dateValidation(date_str):
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def postiveAmountValidation(amount):
    try:
        value = float(amount)
        return value > 0
    except ValueError:
        return False

class User:
    def __init__(self, email, password, creditCardNumber, birthDate):
        self.email = email
        self.hashedPassword = bcrypt.generate_password_hash(password).decode('utf-8')
        self.creditCardNumber = encryptData(creditCardNumber)
        self.birthDate = encryptData(birthDate)
        self.balance = encryptData('0')
        self.secretOTP = pyotp.random_base32()
    
    def passwordHashingCheck(self, password):
        return bcrypt.check_password_hash(self.hashedPassword, password)
    
    def check_otp(self, otp):
        totp = pyotp.TOTP(self.secretOTP)
        return totp.verify(otp)

# Sanitize input data
def inputSanitization(data):
    if isinstance(data, dict):
        return {key: bleach.clean(value) if isinstance(value, str) else value for key, value in data.items()}
    return data

# Register route
@app.route('/userRegister', methods=['POST'])
@limiter.limit("5 per minute")
def userRegister():
    data = inputSanitization(request.get_json())
    email = data.get('email')
    password = data.get('password')
    creditCardNumber = data.get('creditCardNumber')
    birthDate = data.get('birthDate')

    logger.info(f"Register attempt for email: {email}")

    try:
        if not email or not password or not creditCardNumber or not birthDate:
            return jsonify({'message': 'Missing required fields'}), 400

        if not emailValidation(email):
            return jsonify({'message': 'Invalid email format'}), 400

        if not passwordValidation(password):
            return jsonify({'message': 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character'}), 400

        if not creditcardValidation(creditCardNumber):
            return jsonify({'message': 'Invalid credit card number'}), 400

        if not dateValidation(birthDate):
            return jsonify({'message': 'Invalid date of birth format. Use YYYY-MM-DD'}), 400

        if email in users:
            return jsonify({
                            
                'message': 'User already exists'}), 409

        users[email] = User(email, password, creditCardNumber, birthDate)
        qrCode = qrCodeGen(email, users[email].secretOTP)
        logger.info(f"User registered successfully: {email}")
        return jsonify({'message': 'User registered successfully', 'qrCode': qrCode}), 201
    except Exception as e:
        logger.error(f"Error during registration: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

# Login route
@app.route('/userLogin', methods=['POST'])
@limiter.limit("10 per minute")
def userLogin():
    data = inputSanitization(request.get_json())
    email = data.get('email')
    password = data.get('password')
    otp = data.get('otp')

    logger.info(f"Login attempt for email: {email}")

    try:
        if not email or not password or not otp:
            return jsonify({'message': 'Missing required fields'}), 400
        
        user = users.get(email)
        if not user or not user.passwordHashingCheck(password) or not user.check_otp(otp):
            return jsonify({'message': 'Invalid credentials'}), 401
        
        accessToken = create_access_token(identity=email)
        session['logged_in'] = True
        session['email'] = email
        session.permanent = True
        app.permaSesLifeTime = app.config['SESSION_TIMEOUT']
        logger.info(f"User logged in successfully: {email}")
        return jsonify({'accessToken': accessToken}), 200
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

# Require OTP for balance-related actions
def require_otp(func):
    def wrapper(*args, **kwargs):
        data = inputSanitization(request.get_json())
        otp = data.get('otp')
        if not otp:
            return jsonify({'message': 'OTP is required'}), 400

        email = get_jwt_identity()
        user = users.get(email)
        if not user.check_otp(otp):
            return jsonify({'message': 'Invalid OTP'}), 401
        
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# Deposit route
@app.route('/userDeposit', methods=['POST'])
@jwt_required()
@require_otp
@limiter.limit("5 per minute")
def userDeposit():
    data = inputSanitization(request.get_json())
    amount = data.get('amount')

    email = get_jwt_identity()
    logger.info(f"Deposit attempt for email: {email}, amount: {amount}")

    try:
        if not amount or not postiveAmountValidation(amount):
            return jsonify({'message': 'Invalid amount'}), 400
        
        user = users[email]
        currentBalance = float(decryptData(user.balance))
        newBalance = currentBalance + float(amount)
        user.balance = encryptData(str(newBalance))
        logger.info(f"Deposit successful for email: {email}, new balance: {newBalance}")
        return jsonify({'message': 'Deposit successful', 'newBalance': newBalance}), 200
    except Exception as e:
        logger.error(f"Error during deposit: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

# Withdraw route
@app.route('/userWithdraw', methods=['POST'])
@jwt_required()
@require_otp
@limiter.limit("5 per minute")
def userWithdraw():
    data = inputSanitization(request.get_json())
    amount = data.get('amount')

    email = get_jwt_identity()
    logger.info(f"Withdrawal attempt for email: {email}, amount: {amount}")

    try:
        if not amount or not postiveAmountValidation(amount):
            return jsonify({'message': 'Invalid amount'}), 400
        
        user = users[email]
        currentBalance = float(decryptData(user.balance))
        
        if float(amount) > currentBalance:
            return jsonify({'message': 'Insufficient funds'}), 400
        
        newBalance = currentBalance - float(amount)
        user.balance = encryptData(str(newBalance))
        logger.info(f"Withdrawal successful for email: {email}, new balance: {newBalance}")
        return jsonify({'message': 'Withdrawal successful', 'newBalance': newBalance}), 200
    except Exception as e:
        logger.error(f"Error during withdrawal: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500

# Check balance route
@app.route('/userBalance', methods=['GET'])
@jwt_required()
@require_otp
@limiter.limit("5 per minute")
def userBalance():
    email = get_jwt_identity()
    logger.info(f"Balance check for email: {email}")

    try:
        user = users[email]
        currentBalance = float(decryptData(user.balance))
        logger.info(f"Balance check successful for email: {email}, balance: {currentBalance}")
        return jsonify({'balance': currentBalance}), 200
    except Exception as e:
        logger.error(f"Error during balance check: {str(e)}")
        return jsonify({'message': 'Internal server error'}), 500


# Error handling
@app.errorhandler(404)
def notFound(error):
    logger.error(f"404 Not Found: {request.url}")
    return jsonify({'message': 'Not found'}), 404

@app.errorhandler(500)
def internalError(error):
    logger.error(f"500 Internal Server Error: {request.url} - {str(error)}")
    return jsonify({'message': 'Internal server error'}), 500

# Logging request details
@app.beforeRequest
def logInfo():
    logger.info('Request Headers: %s', request.headers)
    logger.info('Request Body: %s', request.get_data())

# Session timeout management
@app.beforeRequest
def sessionManagement():
    session.permanent = True
    app.permaSesLifeTime = app.config['SESSION_TIMEOUT']

if __name__ == '__main__':
    app.run(debug=True)
