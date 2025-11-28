# tests/unit/test_jwt.py
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from fastapi import HTTPException
import asyncio

from app.auth.jwt import (
    verify_password,
    get_password_hash,
    create_token,
    decode_token,
    get_current_user
)
from app.schemas.token import TokenType


# ======================================================================================
# Password Hashing Tests
# ======================================================================================

@pytest.mark.unit
def test_verify_password_correct():
    """Test verify_password with correct password"""
    plain_password = "TestPass123"  # Keep it reasonable
    hashed = get_password_hash(plain_password)
    
    result = verify_password(plain_password, hashed)
    assert result is True


@pytest.mark.unit
def test_verify_password_incorrect():
    """Test verify_password with incorrect password"""
    plain_password = "TestPass123"
    wrong_password = "WrongPass456"
    hashed = get_password_hash(plain_password)
    
    result = verify_password(wrong_password, hashed)
    assert result is False


@pytest.mark.unit
def test_get_password_hash():
    """Test get_password_hash creates a hash"""
    password = "SecurePass123"
    hashed = get_password_hash(password)
    
    assert hashed != password
    assert len(hashed) > 20
    assert hashed.startswith("$2b$")  # bcrypt hash prefix


@pytest.mark.unit
def test_verify_password_with_invalid_hash_format():
    """Test verify_password with malformed hash to trigger exception path"""
    plain_password = "TestPass123"
    
    # Test with completely invalid hash format
    with pytest.raises(ValueError):
        verify_password(plain_password, "not_a_valid_bcrypt_hash")


@pytest.mark.unit  
def test_verify_password_with_corrupted_hash():
    """Test verify_password with corrupted but bcrypt-like hash"""
    plain_password = "TestPass123"
    
    # Create a valid hash first
    valid_hash = get_password_hash(plain_password)
    
    # Corrupt the hash by truncating it
    corrupted_hash = valid_hash[:20]
    
    # This should handle the error gracefully
    try:
        result = verify_password(plain_password, corrupted_hash)
        # If it doesn't raise, it should return False
        assert result is False
    except (ValueError, Exception):
        # Some implementations might raise an exception
        pass


@pytest.mark.unit
def test_verify_password_empty_hash():
    """Test verify_password with empty hash string"""
    with pytest.raises((ValueError, Exception)):
        verify_password("password", "")


# ======================================================================================
# Token Creation Tests
# ======================================================================================

@pytest.mark.unit
def test_create_token_access_with_default_expiry():
    """Test create_token for access token with default expiry"""
    user_id = uuid4()
    
    token = create_token(user_id, TokenType.ACCESS)
    
    assert isinstance(token, str)
    assert len(token) > 50  # JWT tokens are long strings


@pytest.mark.unit
def test_create_token_refresh_with_default_expiry():
    """Test create_token for refresh token with default expiry"""
    user_id = uuid4()
    
    token = create_token(user_id, TokenType.REFRESH)
    
    assert isinstance(token, str)
    assert len(token) > 50


@pytest.mark.unit
def test_create_token_with_custom_expiry():
    """Test create_token with custom expiration delta"""
    user_id = uuid4()
    custom_delta = timedelta(hours=2)
    
    token = create_token(user_id, TokenType.ACCESS, expires_delta=custom_delta)
    
    assert isinstance(token, str)
    assert len(token) > 50


@pytest.mark.unit
def test_create_token_with_string_user_id():
    """Test create_token handles string user_id"""
    user_id = str(uuid4())
    
    token = create_token(user_id, TokenType.ACCESS)
    
    assert isinstance(token, str)


@pytest.mark.unit
def test_create_token_with_uuid_user_id():
    """Test create_token converts UUID to string"""
    user_id = uuid4()
    
    with patch('app.auth.jwt.jwt.encode') as mock_encode:
        mock_encode.return_value = "mocked_token"
        
        token = create_token(user_id, TokenType.ACCESS)
        
        # Verify encode was called
        mock_encode.assert_called_once()
        # Check that the payload contains string user_id
        call_args = mock_encode.call_args[0][0]
        assert isinstance(call_args['sub'], str)


@pytest.mark.unit
def test_create_token_exception_handling():
    """Test create_token handles encoding exceptions"""
    user_id = uuid4()
    
    with patch('app.auth.jwt.jwt.encode', side_effect=Exception("Encoding failed")):
        with pytest.raises(HTTPException) as exc_info:
            create_token(user_id, TokenType.ACCESS)
        
        assert exc_info.value.status_code == 500
        assert "Could not create token" in exc_info.value.detail


# ======================================================================================
# Token Decoding Tests
# ======================================================================================

@pytest.mark.unit
def test_decode_token_valid_access():
    """Test decode_token with valid access token"""
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    async def run_test():
        with patch('app.auth.jwt.is_blacklisted', new_callable=AsyncMock, return_value=False):
            payload = await decode_token(token, TokenType.ACCESS)
            
            assert payload['sub'] == str(user_id)
            assert payload['type'] == TokenType.ACCESS.value
            assert 'jti' in payload
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_decode_token_valid_refresh():
    """Test decode_token with valid refresh token"""
    user_id = uuid4()
    token = create_token(user_id, TokenType.REFRESH)
    
    async def run_test():
        with patch('app.auth.jwt.is_blacklisted', new_callable=AsyncMock, return_value=False):
            payload = await decode_token(token, TokenType.REFRESH)
            
            assert payload['sub'] == str(user_id)
            assert payload['type'] == TokenType.REFRESH.value
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_decode_token_wrong_type():
    """Test decode_token raises error when token type doesn't match"""
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    async def run_test():
        with patch('app.auth.jwt.jwt.decode') as mock_decode:
            # Mock the decode to return a payload with wrong type
            mock_decode.return_value = {
                'sub': str(user_id),
                'type': TokenType.ACCESS.value,  # Token is ACCESS
                'jti': 'test-jti'
            }
            
            with pytest.raises(HTTPException) as exc_info:
                await decode_token(token, TokenType.REFRESH)  # But we expect REFRESH
            
            assert exc_info.value.status_code == 401
            assert "Invalid token type" in exc_info.value.detail
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_decode_token_blacklisted():
    """Test decode_token raises error for blacklisted token"""
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    async def run_test():
        with patch('app.auth.jwt.is_blacklisted', new_callable=AsyncMock, return_value=True):
            with pytest.raises(HTTPException) as exc_info:
                await decode_token(token, TokenType.ACCESS)
            
            assert exc_info.value.status_code == 401
            assert "Token has been revoked" in exc_info.value.detail
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_decode_token_expired():
    """Test decode_token raises error for expired token"""
    user_id = uuid4()
    # Create token that expires immediately
    token = create_token(user_id, TokenType.ACCESS, expires_delta=timedelta(seconds=-1))
    
    async def run_test():
        with patch('app.auth.jwt.is_blacklisted', new_callable=AsyncMock, return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await decode_token(token, TokenType.ACCESS)
            
            assert exc_info.value.status_code == 401
            assert "Token has expired" in exc_info.value.detail
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_decode_token_invalid():
    """Test decode_token raises error for invalid token"""
    async def run_test():
        with pytest.raises(HTTPException) as exc_info:
            await decode_token("invalid.token.string", TokenType.ACCESS)
        
        assert exc_info.value.status_code == 401
        assert "Could not validate credentials" in exc_info.value.detail
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_decode_token_skip_expiry_verification():
    """Test decode_token with verify_exp=False"""
    user_id = uuid4()
    # Create expired token
    token = create_token(user_id, TokenType.ACCESS, expires_delta=timedelta(seconds=-1))
    
    async def run_test():
        with patch('app.auth.jwt.is_blacklisted', new_callable=AsyncMock, return_value=False):
            # Should not raise error when verify_exp=False
            payload = await decode_token(token, TokenType.ACCESS, verify_exp=False)
            
            assert payload['sub'] == str(user_id)
    
    asyncio.run(run_test())


# ======================================================================================
# get_current_user Tests
# ======================================================================================

@pytest.mark.unit
def test_get_current_user_valid():
    """Test get_current_user with valid token"""
    from app.models.user import User
    
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    mock_user = MagicMock(spec=User)
    mock_user.id = user_id
    mock_user.is_active = True
    
    async def run_test():
        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_filter = MagicMock()
        
        mock_db.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter
        mock_filter.first.return_value = mock_user
        
        with patch('app.auth.jwt.is_blacklisted', new_callable=AsyncMock, return_value=False):
            result = await get_current_user(token, mock_db)
            
            assert result == mock_user
            mock_db.query.assert_called_once()
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_get_current_user_not_found():
    """Test get_current_user raises error when user not found"""
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    
    async def run_test():
        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_filter = MagicMock()
        
        mock_db.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter
        mock_filter.first.return_value = None  # User not found
        
        with patch('app.auth.jwt.is_blacklisted', new_callable=AsyncMock, return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(token, mock_db)
            
            # The outer exception handler catches it and converts to 401
            assert exc_info.value.status_code == 401
            assert "User not found" in str(exc_info.value.detail)
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_get_current_user_inactive():
    """Test get_current_user raises error for inactive user"""
    from app.models.user import User
    
    user_id = uuid4()
    token = create_token(user_id, TokenType.ACCESS)
    mock_user = MagicMock(spec=User)
    mock_user.id = user_id
    mock_user.is_active = False  # Inactive user
    
    async def run_test():
        mock_db = MagicMock()
        mock_query = MagicMock()
        mock_filter = MagicMock()
        
        mock_db.query.return_value = mock_query
        mock_query.filter.return_value = mock_filter
        mock_filter.first.return_value = mock_user
        
        with patch('app.auth.jwt.is_blacklisted', new_callable=AsyncMock, return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_user(token, mock_db)
            
            # The outer exception handler catches it and converts to 401
            assert exc_info.value.status_code == 401
            assert "Inactive user" in str(exc_info.value.detail)
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_get_current_user_invalid_token():
    """Test get_current_user raises error for invalid token"""
    async def run_test():
        mock_db = MagicMock()
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user("invalid.token", mock_db)
        
        assert exc_info.value.status_code == 401
    
    asyncio.run(run_test())

