from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, errors
from bson import ObjectId
from bson.errors import InvalidId
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
import os

app = Flask(__name__)
CORS(app)

# Secret key for JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_secret_key')
jwt = JWTManager(app)

# MongoDB connection
try:
    client = MongoClient('mongodb://localhost:27017/')
    db = client['personal_finance_tracker']
    entries_collection = db['financial_entries']
    users_collection = db['users']  # Collection for users
    print("Connected to MongoDB")
except errors.ConnectionError as e:
    print("Error connecting to MongoDB : ", e)
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

# User registration
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not data or not all(key in data for key in ["username", "password"]):
            return jsonify({"error": "Missing required fields"}), 400

        # Check if user already exists
        if users_collection.find_one({"username": data['username']}):
            return jsonify({"error": "User already exists"}), 400

        # Hash the password
        hashed_password = generate_password_hash(data['password'])

        # Create new user
        new_user = {
            "username": data['username'],
            "password": hashed_password
        }
        users_collection.insert_one(new_user)
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# User login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data or not all(key in data for key in ["username", "password"]):
            return jsonify({"error": "Missing required fields"}), 400

        # Find user by username
        user = users_collection.find_one({"username": data['username']})
        if not user or not check_password_hash(user['password'], data['password']):
            return jsonify({"error": "Invalid username or password"}), 401

        # Create JWT token
        access_token = create_access_token(identity=user['username'], expires_delta=datetime.timedelta(hours=1))
        return jsonify({"access_token": access_token}), 200
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


if __name__ == '__main__':
    app.run(debug=True)
