import os
import json
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent.parent / "data"

def ensure_data_dir() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR

def save_json(data: Dict[str, Any], filename: str, dirname: str = None) -> str:
    if dirname:
        target_dir = Path(dirname)
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / filename
    else:
        target_dir = ensure_data_dir()
        path = target_dir / filename
    
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    
    return str(path)

def load_json(filename: str, dirname: str = None) -> Optional[Dict[str, Any]]:
    if dirname:
        path = Path(dirname) / filename
    else:
        path = DATA_DIR / filename
    
    if not path.exists():
        return None
    
    with open(path, 'r') as f:
        return json.load(f)

def clear_cache():
    if DATA_DIR.exists():
        for file in DATA_DIR.glob('*.json'):
            file.unlink()

def get_cache_path() -> Path:
    return DATA_DIR