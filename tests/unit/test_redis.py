# tests/unit/test_redis.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio


@pytest.mark.unit
def test_get_redis_creates_connection():
    """Test get_redis creates Redis connection"""
    from app.auth import redis
    
    # Clear any existing redis attribute
    if hasattr(redis.get_redis, "redis"):
        delattr(redis.get_redis, "redis")
    
    mock_redis_instance = MagicMock()
    
    async def run_test():
        # Use AsyncMock for async function
        with patch('app.auth.redis.aioredis.from_url', new_callable=AsyncMock, return_value=mock_redis_instance) as mock_from_url:
            result = await redis.get_redis()
            
            # Verify from_url was called
            mock_from_url.assert_called_once()
            # Verify the mock redis was returned
            assert result == mock_redis_instance
            # Verify it was cached
            assert hasattr(redis.get_redis, "redis")
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_get_redis_returns_cached():
    """Test get_redis returns cached connection"""
    from app.auth import redis
    
    # Set up a cached redis connection
    mock_redis = MagicMock()
    redis.get_redis.redis = mock_redis
    
    async def run_test():
        with patch('app.auth.redis.aioredis.from_url', new_callable=AsyncMock) as mock_from_url:
            result = await redis.get_redis()
            
            # Verify from_url was NOT called (using cached)
            mock_from_url.assert_not_called()
            # Verify cached redis was returned
            assert result == mock_redis
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_add_to_blacklist():
    """Test add_to_blacklist adds JTI to Redis"""
    from app.auth import redis
    
    mock_redis = AsyncMock()
    
    async def run_test():
        with patch('app.auth.redis.get_redis', return_value=mock_redis):
            jti = "test-jti-12345"
            exp = 3600
            
            await redis.add_to_blacklist(jti, exp)
            
            # Verify Redis set was called with correct parameters
            mock_redis.set.assert_called_once_with(f"blacklist:{jti}", "1", ex=exp)
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_is_blacklisted_returns_true():
    """Test is_blacklisted returns True when JTI exists"""
    from app.auth import redis
    
    mock_redis = AsyncMock()
    mock_redis.exists = AsyncMock(return_value=1)
    
    async def run_test():
        with patch('app.auth.redis.get_redis', return_value=mock_redis):
            jti = "blacklisted-jti"
            
            result = await redis.is_blacklisted(jti)
            
            # Verify exists was called
            mock_redis.exists.assert_called_once_with(f"blacklist:{jti}")
            # Verify it returned True (1)
            assert result == 1
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_is_blacklisted_returns_false():
    """Test is_blacklisted returns False when JTI doesn't exist"""
    from app.auth import redis
    
    mock_redis = AsyncMock()
    mock_redis.exists = AsyncMock(return_value=0)
    
    async def run_test():
        with patch('app.auth.redis.get_redis', return_value=mock_redis):
            jti = "not-blacklisted-jti"
            
            result = await redis.is_blacklisted(jti)
            
            # Verify exists was called
            mock_redis.exists.assert_called_once_with(f"blacklist:{jti}")
            # Verify it returned False (0)
            assert result == 0
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_get_redis_uses_custom_url():
    """Test get_redis uses settings.REDIS_URL when provided"""
    from app.auth import redis
    
    # Clear cached redis
    if hasattr(redis.get_redis, "redis"):
        delattr(redis.get_redis, "redis")
    
    mock_redis = MagicMock()
    custom_url = "redis://custom:6379/1"
    
    async def run_test():
        with patch('app.auth.redis.settings') as mock_settings:
            mock_settings.REDIS_URL = custom_url
            # Use AsyncMock for async function
            with patch('app.auth.redis.aioredis.from_url', new_callable=AsyncMock, return_value=mock_redis) as mock_from_url:
                await redis.get_redis()
                
                # Verify from_url was called with custom URL
                mock_from_url.assert_called_once_with(custom_url)
    
    asyncio.run(run_test())


@pytest.mark.unit
def test_get_redis_defaults_to_localhost():
    """Test get_redis falls back to localhost when REDIS_URL is None"""
    from app.auth import redis
    
    # Clear cached redis
    if hasattr(redis.get_redis, "redis"):
        delattr(redis.get_redis, "redis")
    
    mock_redis = MagicMock()
    
    async def run_test():
        with patch('app.auth.redis.settings') as mock_settings:
            mock_settings.REDIS_URL = None
            # Use AsyncMock for async function
            with patch('app.auth.redis.aioredis.from_url', new_callable=AsyncMock, return_value=mock_redis) as mock_from_url:
                await redis.get_redis()
                
                # Verify from_url was called with default localhost
                mock_from_url.assert_called_once_with("redis://localhost")
    
    asyncio.run(run_test())