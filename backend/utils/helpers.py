import os
from typing import Optional, Callable, Any
from functools import wraps

def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path

def validate_path(path: str, must_exist: bool = True) -> bool:
    if must_exist and not os.path.exists(path):
        return False
    return True

def sanitize_filename(filename: str) -> str:
    safe_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_'
    return ''.join(c if c in safe_chars else '_' for c in filename)

def format_number(num: float, decimals: int = 6) -> str:
    if num >= 1:
        return f"{num:.{decimals}f}"
    return f"{num:.8f}"

def calculate_time_range(hours: int = 24) -> tuple:
    from datetime import datetime, timedelta
    end = datetime.utcnow()
    start = end - timedelta(hours=hours)
    return start.isoformat(), end.isoformat()

def retry(max_attempts: int = 3, delay: float = 1.0, exceptions: tuple = (Exception,)):
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        import asyncio
                        await asyncio.sleep(delay * (attempt + 1))
            raise last_exception
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        import time
                        time.sleep(delay * (attempt + 1))
            raise last_exception
        
        if hasattr(func, '__await__'):
            return async_wrapper
        return sync_wrapper
    return decorator

def chunk_list(lst: list, chunk_size: int) -> list:
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]