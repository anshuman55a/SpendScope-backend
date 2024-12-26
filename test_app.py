import pytest
import json
from flask import Flask
from app import app  
from pymongo import MongoClient

@pytest.fixture
def client():
    # Setting up the Flask test client
    app.config['TESTING'] = True
    app.config['JWT_SECRET_KEY'] = 'test_secret_key'  # Setting  a test secret key
    with app.test_client() as client:
        yield client

@pytest.fixture(scope='module')
def init_db():
    # Set up MongoDB connection for testing
    client = MongoClient('mongodb://localhost:27017/')
    db = client['personal_finance_tracker']
    yield db
    client.drop_database('personal_finance_tracker')  # Clean up after tests

def test_register(client, init_db):
    response = client.post('/register', json={"username": "testuser", "password": "testpass"})
    assert response.status_code == 201
    assert b"User registered successfully" in response.data

def test_login(client):
    response = client.post('/login', json={"username": "testuser", "password": "testpass"})
    assert response.status_code == 200
    assert b"access_token" in response.data
    
    # Extract and validate the access token
    token = json.loads(response.data)["access_token"]
    assert isinstance(token, str)
    return token  # Return the token for further tests

def test_add_entry(client):
    token = test_login(client)
    response = client.post('/entries', json={
        "date": "2024-10-12",
        "amount": 100.0,
        "category": "Food",
        "type": "expense"
    }, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 201
    assert b"amount" in response.data

def test_get_entries(client):
    token = test_login(client)
    response = client.get('/entries', headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert isinstance(json.loads(response.data), list)

def test_update_entry(client):
    token = test_login(client)
    # First, add an entry to update
    add_response = client.post('/entries', json={
        "date": "2024-10-12",
        "amount": 200.0,
        "category": "Transport",
        "type": "expense"
    }, headers={"Authorization": f"Bearer {token}"})
    
    assert add_response.status_code == 201
    entry_id = json.loads(add_response.data)["id"]

    # Now, update that entry
    response = client.put(f'/entries/{entry_id}', json={
        "date": "2024-10-12",
        "amount": 250.0,
        "category": "Transport",
        "type": "expense"
    }, headers={"Authorization": f"Bearer {token}"})
    
    assert response.status_code == 200
    assert b"amount" in response.data

def test_delete_entry(client):
    token = test_login(client)
    # First, adding an entry to delete
    add_response = client.post('/entries', json={
        "date": "2024-10-12",
        "amount": 150.0,
        "category": "Entertainment",
        "type": "expense"
    }, headers={"Authorization": f"Bearer {token}"})
    
    assert add_response.status_code == 201
    entry_id = json.loads(add_response.data)["id"]

    # Now, delete that entry
    response = client.delete(f'/entries/{entry_id}', headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert b"Entry deleted" in response.data

def test_dashboard(client):
    token = test_login(client)
    
    # Add entries if necessary for dashboard calculation
    client.post('/entries', json={
        "date": "2024-10-12",
        "amount": 300.0,
        "category": "Income",
        "type": "income"
    }, headers={"Authorization": f"Bearer {token}"})
    
    response = client.get('/dashboard', headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert b"total_income" in response.data
    assert b"total_expenses" in response.data

if __name__ == '__main__':
    pytest.main()
