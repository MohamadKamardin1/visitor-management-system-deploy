# Redis Cache Configuration Fix

## Issue
The API endpoint `/api/hosts/for_kiosk/` was failing with Redis connection errors when Redis was not running.

## Solution
Updated the cache configuration to:
1. Default to local memory cache (works without Redis)
2. Only use Redis if explicitly enabled via `USE_REDIS_CACHE=True`
3. Added error handling in cache operations

## Changes Made

### 1. settings.py
- Changed cache backend to use local memory by default
- Added `USE_REDIS_CACHE` environment variable
- Removed problematic `CLIENT_CLASS` option

### 2. core/utils.py
- Added try-catch blocks around cache operations
- Cache failures now log warnings but don't break the app

## Configuration

### Without Redis (Default - Works Immediately)
```bash
USE_REDIS_CACHE=False
```
The app will use local memory cache. This works fine for development and small deployments.

### With Redis (For Production)
1. Install and start Redis:
```bash
sudo apt-get install redis-server
redis-server
```

2. Update .env:
```bash
USE_REDIS_CACHE=True
REDIS_URL=redis://localhost:6379/0
```

## Testing

The `/api/hosts/for_kiosk/` endpoint should now work without Redis. Test it:

```bash
curl http://localhost:8000/api/hosts/for_kiosk/
```

## Note

- Local memory cache is per-process (not shared across workers)
- For production with multiple workers, use Redis
- Celery still requires Redis for async tasks
- SMS will work without Redis (logged to console in DEBUG mode)






