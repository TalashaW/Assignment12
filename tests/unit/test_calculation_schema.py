import pytest
from pydantic import ValidationError
from uuid import uuid4
from datetime import datetime
from app.schemas.calculation import (
    CalculationCreate,
    CalculationUpdate,
    CalculationRead
    
)
from app.schemas.user import UserCreate, PasswordUpdate

def test_calculation_create_valid():
    """Test creating a valid CalculationCreate schema."""
    data = {
        "type": "addition",
        "inputs": [10.5, 3.0],
        "user_id": uuid4()
    }
    calc = CalculationCreate(**data)
    assert calc.type == "addition"
    assert calc.inputs == [10.5, 3.0]
    assert calc.user_id is not None

def test_calculation_create_missing_type():
    """Test CalculationCreate fails if 'type' is missing."""
    data = {
        "inputs": [10.5, 3.0],
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    # Look for a substring that indicates a missing required field.
    assert "required" in str(exc_info.value).lower()

def test_calculation_create_missing_inputs():
    """Test CalculationCreate fails if 'inputs' is missing."""
    data = {
        "type": "multiplication",
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    assert "required" in str(exc_info.value).lower()

def test_calculation_create_invalid_inputs():
    """Test CalculationCreate fails if 'inputs' is not a list of floats."""
    data = {
        "type": "division",
        "inputs": "not-a-list",
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    error_message = str(exc_info.value)
    # Ensure that our custom error message is present (case-insensitive)
    assert "input should be a valid list" in error_message.lower(), error_message

def test_calculation_create_unsupported_type():
    """Test CalculationCreate fails if an unsupported calculation type is provided."""
    data = {
        "type": "square_root",  # Unsupported type
        "inputs": [25],
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    error_message = str(exc_info.value).lower()
    # Check that the error message indicates the value is not permitted.
    assert "one of" in error_message or "not a valid" in error_message

def test_calculation_update_valid():
    """Test a valid partial update with CalculationUpdate."""
    data = {
        "inputs": [42.0, 7.0]
    }
    calc_update = CalculationUpdate(**data)
    assert calc_update.inputs == [42.0, 7.0]

def test_calculation_update_no_fields():
    """Test that an empty update is allowed (i.e., no fields)."""
    calc_update = CalculationUpdate()
    assert calc_update.inputs is None

def test_calculation_response_valid():
    """Test creating a valid CalculationRead schema."""
    data = {
        "id": uuid4(),
        "user_id": uuid4(),
        "type": "subtraction",
        "inputs": [20, 5],
        "result": 15.5,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    calc_response = CalculationRead(**data)
    assert calc_response.id is not None
    assert calc_response.user_id is not None
    assert calc_response.type == "subtraction"
    assert calc_response.inputs == [20, 5]
    assert calc_response.result == 15.5

def test_calculation_create_insufficient_inputs():
    """Test CalculationCreate fails with less than 2 inputs"""
    data = {
        "type": "addition",
        "inputs": [10.5],  # Only 1 input
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "at least two numbers are required" in error_message


def test_calculation_create_division_by_zero():
    """Test CalculationCreate fails when dividing by zero"""
    data = {
        "type": "division",
        "inputs": [100, 0],  # Division by zero
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "cannot divide by zero" in error_message


def test_calculation_create_division_by_zero_multiple():
    """Test division by zero with multiple inputs"""
    data = {
        "type": "division",
        "inputs": [100, 2, 0],  # Zero in the middle
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "cannot divide by zero" in error_message


def test_calculation_update_insufficient_inputs():
    """Test CalculationUpdate fails with less than 2 inputs"""
    data = {
        "inputs": [42.0]  # Only 1 input
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationUpdate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "at least two numbers are required" in error_message

@pytest.mark.unit
def test_user_create_password_mismatch():
    """Test UserCreate fails when passwords don't match"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "password": "SecurePass123!",
        "confirm_password": "DifferentPass456!"
    }
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "passwords do not match" in error_message or "password" in error_message


@pytest.mark.unit
def test_user_create_password_too_short():
    """Test UserCreate fails with short password"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "password": "Short1!",  # Only 7 characters
        "confirm_password": "Short1!"
    }
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "at least 8 characters" in error_message or "password must be" in error_message


@pytest.mark.unit
def test_user_create_password_no_uppercase():
    """Test UserCreate fails without uppercase letter"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "password": "lowercase123!",
        "confirm_password": "lowercase123!"
    }
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "uppercase" in error_message


@pytest.mark.unit
def test_user_create_password_no_lowercase():
    """Test UserCreate fails without lowercase letter"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "password": "UPPERCASE123!",
        "confirm_password": "UPPERCASE123!"
    }
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "lowercase" in error_message


@pytest.mark.unit
def test_user_create_password_no_digit():
    """Test UserCreate fails without digit"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "password": "NoDigitsHere!",
        "confirm_password": "NoDigitsHere!"
    }
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "digit" in error_message


@pytest.mark.unit
def test_user_create_password_no_special_char():
    """Test UserCreate fails without special character"""
    data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "username": "johndoe",
        "password": "NoSpecial123",
        "confirm_password": "NoSpecial123"
    }
    with pytest.raises(ValidationError) as exc_info:
        UserCreate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "special" in error_message


@pytest.mark.unit
def test_password_update_mismatch():
    """Test PasswordUpdate fails when new passwords don't match"""
    data = {
        "current_password": "OldPass123!",
        "new_password": "NewPass456!",
        "confirm_new_password": "DifferentPass789!"
    }
    with pytest.raises(ValidationError) as exc_info:
        PasswordUpdate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "do not match" in error_message or "password" in error_message


@pytest.mark.unit
def test_password_update_same_as_current():
    """Test PasswordUpdate fails when new password same as current"""
    data = {
        "current_password": "SamePass123!",
        "new_password": "SamePass123!",
        "confirm_new_password": "SamePass123!"
    }
    with pytest.raises(ValidationError) as exc_info:
        PasswordUpdate(**data)
    
    error_message = str(exc_info.value).lower()
    assert "different" in error_message or "same" in error_message  
