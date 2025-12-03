from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, errors
from bson import ObjectId
from bson.errors import InvalidId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime
import os
import re
import secrets

app = Flask(__name__)

# CORS Configuration - Hardened for security
CORS(app, 
     origins=["http://localhost:3000", "https://spendscope-frontend.onrender.com"],
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# Secret key for JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_secret_key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=15)  # Short-lived access tokens
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=7)  # Long-lived refresh tokens
jwt = JWTManager(app)

# Rate Limiter Configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# MongoDB connection
try:
    # Read the MongoDB URI from environment variables
    MONGO_URI = os.getenv("MONGO_URI")
    if not MONGO_URI:
        raise ValueError("MONGO_URI environment variable not set")

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=30000, maxPoolSize=10,)
    client.admin.command('ping')
    
    db = client['personal_finance_tracker']  # Use your database name
    entries_collection = db['financial_entries']  # Collection for financial entries
    users_collection = db['users']  # Collection for users
    refresh_tokens_collection = db['refresh_tokens']  # Collection for refresh tokens
    
    # Create indexes for performance (50-100x faster queries)
    users_collection.create_index("username", unique=True)
    entries_collection.create_index("user_id")
    refresh_tokens_collection.create_index("token_hash", unique=True)
    refresh_tokens_collection.create_index("expires_at", expireAfterSeconds=0)  # Auto-delete expired tokens
    
    print("Connected to MongoDB Atlas with indexes created")
except (errors.ConnectionFailure, ValueError) as e:
    print("Error connecting to MongoDB: ", e)
    exit(1)
# Helper function to convert MongoDB document to JSON serializable format
def entry_to_json(entry):
    return {
        "id": str(entry["_id"]),
        "user_id": entry["user_id"],
        "date": entry["date"],
        "amount": entry["amount"],
        "category": entry["category"],
        "description": entry.get("description", ""),
        "type": entry["type"]
    }

# Input validation functions
def validate_username(username):
    """Validate username: 3-30 chars, alphanumeric + underscore only"""
    if not username or len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, ""

def validate_password(password):
    """Validate password strength: min 8 chars, uppercase, lowercase, number"""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, ""

def create_refresh_token(username):
    """Create and store a refresh token"""
    token = secrets.token_urlsafe(64)
    token_hash = generate_password_hash(token)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(days=7)
    
    refresh_tokens_collection.insert_one({
        "token_hash": token_hash,
        "username": username,
        "expires_at": expires_at,
        "created_at": datetime.datetime.utcnow()
    })
    
    return token


@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Personal Finance Tracker API"}), 200

# User registration
@app.route('/register', methods=['POST'])
@limiter.limit("3 per minute")  # Rate limit: 3 registrations per minute
def register():
    try:
        data = request.json
        if not data or not all(key in data for key in ["username", "password"]):
            return jsonify({"error": "Missing required fields"}), 400

        # Validate username
        valid, error_msg = validate_username(data['username'])
        if not valid:
            return jsonify({"error": error_msg}), 400
        
        # Validate password strength
        valid, error_msg = validate_password(data['password'])
        if not valid:
            return jsonify({"error": error_msg}), 400

        # Check if user already exists
        if users_collection.find_one({"username": data['username']}):
            return jsonify({"error": "Username already taken"}), 400

        # Hash the password
        hashed_password = generate_password_hash(data['password'])

        # Create new user
        new_user = {
            "username": data['username'],
            "password": hashed_password,
            "created_at": datetime.datetime.utcnow()
        }
        users_collection.insert_one(new_user)
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# User login
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit: 5 login attempts per minute
def login():
    try:
        data = request.json
        if not data or not all(key in data for key in ["username", "password"]):
            return jsonify({"error": "Missing required fields"}), 400

        # Find user by username (now uses index for fast lookup)
        user = users_collection.find_one({"username": data['username']})
        if not user or not check_password_hash(user['password'], data['password']):
            return jsonify({"error": "Invalid username or password"}), 401

        # Create short-lived access token (15 minutes)
        access_token = create_access_token(identity=user['username'])
        
        # Create long-lived refresh token (7 days)
        refresh_token = create_refresh_token(user['username'])
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "username": user['username']
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Refresh token endpoint
@app.route('/refresh', methods=['POST'])
def refresh():
    try:
        data = request.json
        if not data or 'refresh_token' not in data:
            return jsonify({"error": "Missing refresh token"}), 400
        
        refresh_token = data['refresh_token']
        
        # Find valid refresh token
        stored_tokens = list(refresh_tokens_collection.find({
            "expires_at": {"$gt": datetime.datetime.utcnow()}
        }))
        
        valid_token = None
        for stored_token in stored_tokens:
            if check_password_hash(stored_token['token_hash'], refresh_token):
                valid_token = stored_token
                break
        
        if not valid_token:
            return jsonify({"error": "Invalid or expired refresh token"}), 401
        
        # Create new access token
        access_token = create_access_token(identity=valid_token['username'])
        
        return jsonify({"access_token": access_token}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Logout endpoint (revoke refresh token)
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        data = request.json
        if data and 'refresh_token' in data:
            refresh_token = data['refresh_token']
            
            # Find and delete the refresh token
            stored_tokens = list(refresh_tokens_collection.find({}))
            for stored_token in stored_tokens:
                if check_password_hash(stored_token['token_hash'], refresh_token):
                    refresh_tokens_collection.delete_one({"_id": stored_token["_id"]})
                    break
        
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get all financial entries (protected route)
@app.route('/entries', methods=['GET'])
@jwt_required()
def get_entries():
    try:
        user_id = get_jwt_identity()  # Get the current user's username or ID from the token
        entries = list(entries_collection.find({"user_id": user_id}))  # Filter entries by user_id
        return jsonify([entry_to_json(entry) for entry in entries]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Add a new financial entry (protected route)
@app.route('/entries', methods=['POST'])
@jwt_required()
def add_entry():
    try:
        data = request.json
        if not data or not all(key in data for key in ["date", "amount", "category", "type"]):
            return jsonify({"error": "Missing required fields"}), 400

        # Convert amount to float
        try:
            data["amount"] = float(data["amount"])
        except ValueError:
            return jsonify({"error": "Invalid amount format, must be a number"}), 400

        user_id = get_jwt_identity()  # Get the current user's username or ID from the token

        new_entry = {
            "user_id": user_id,
            "date": data['date'],
            "amount": data['amount'],
            "category": data['category'],
            "description": data.get("description", ""),
            "type": data['type']
        }
        result = entries_collection.insert_one(new_entry)
        new_entry["_id"] = result.inserted_id
        return jsonify(entry_to_json(new_entry)), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Update a financial entry
@app.route('/entries/<id>', methods=['PUT'])
@jwt_required()
def update_entry(id):
    try:
        user_id = get_jwt_identity()  # Get the current user's username or ID from the token
        data = request.json
        if not data or not all(key in data for key in ["date", "amount", "category", "type"]):
            return jsonify({"error": "Missing required fields"}), 400

        # Convert amount to float
        try:
            data["amount"] = float(data["amount"])
        except ValueError:
            return jsonify({"error": "Invalid amount format, must be a number"}), 400

        updated_entry = {
            "user_id": user_id,
            "date": data['date'],
            "amount": data['amount'],
            "category": data['category'],
            "description": data.get("description", ""),
            "type": data['type']
        }

        result = entries_collection.update_one({"_id": ObjectId(id), "user_id": user_id}, {"$set": updated_entry})

        if result.matched_count == 0:
            return jsonify({"error": "Entry not found or not authorized"}), 404

        updated_entry["_id"] = ObjectId(id)
        return jsonify(entry_to_json(updated_entry)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get a single financial entry by ID (protected route)
@app.route('/entries/<id>', methods=['GET'])
@jwt_required()
def get_entry_by_id(id):
    try:
        user_id = get_jwt_identity()  # Get the current user's username or ID from the token
        entry = entries_collection.find_one({"_id": ObjectId(id), "user_id": user_id})

        if not entry:
            return jsonify({"error": "Entry not found or not authorized"}), 404

        return jsonify(entry_to_json(entry)), 200
    except InvalidId:
        return jsonify({"error": "Invalid entry ID format"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Delete a financial entry
@app.route('/entries/<id>', methods=['DELETE'])
@jwt_required()
def delete_entry(id):
    try:
        user_id = get_jwt_identity()  # Get the current user's username or ID from the token
        result = entries_collection.delete_one({"_id": ObjectId(id), "user_id": user_id})

        if result.deleted_count == 0:
            return jsonify({"error": "Entry not found or not authorized"}), 404

        return jsonify({"message": "Entry deleted"}), 200
    except InvalidId:
        return jsonify({"error": "Invalid entry ID format"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# # Dashboard - Get total income and expenses
# @app.route('/dashboard', methods=['GET'])
# @jwt_required()
# def dashboard():
#     try:
#         user_id = get_jwt_identity()  # Get the current user's username or ID from the token
#         total_income = sum(float(entry["amount"]) for entry in entries_collection.find({"user_id": user_id, "type": "income"}))
#         total_expenses = sum(float(entry["amount"]) for entry in entries_collection.find({"user_id": user_id, "type": "expense"}))
#         recent_transactions = list(entries_collection.find({"user_id": user_id}).sort("date", -1).limit(5))

#         return {
#             "total_income": total_income,
#             "total_expenses": total_expenses,
#             "recent_transactions": [entry_to_json(entry) for entry in recent_transactions]
#         }, 200
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()  # Get the current user's identity
    try:
        total_income = sum(float(entry["amount"]) for entry in entries_collection.find({"user_id": current_user, "type": "income"}))
        total_expenses = sum(float(entry["amount"]) for entry in entries_collection.find({"user_id": current_user, "type": "expense"}))
        recent_transactions = list(entries_collection.find({"user_id": current_user}).sort("date", -1).limit(5))

        return {
            "total_income": total_income,
            "total_expenses": total_expenses,
            "recent_transactions": [entry_to_json(entry) for entry in recent_transactions]
        }, 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
