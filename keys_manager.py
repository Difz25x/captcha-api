import json
import os
import secrets
import time
from typing import Optional, Dict

KEYS_FILE = "keys.json"

def _load_keys() -> Dict:
    if not os.path.exists(KEYS_FILE):
        return {}
    try:
        with open(KEYS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_keys(keys: Dict):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=4)

def create_key(key_type: str = "free", expires_in: int = None) -> str:
    """
    Creates a new key and returns it.
    key_type: 'free' or 'paid'
    expires_in: seconds from now
    """
    keys = _load_keys()
    new_key = secrets.token_hex(16)
    
    expires_at = None
    if expires_in:
        expires_at = time.time() + expires_in
        
    keys[new_key] = {
        "type": key_type,
        "hwid": None,
        "created_at": time.time(),
        "expires_at": expires_at,
        "uses": 0
    }
    
    _save_keys(keys)
    return new_key

def validate_key(key: str, hwid: str) -> tuple[bool, str, Optional[str]]:
    """
    Validates a key against HWID.
    Returns (is_valid, message, key_type)
    """
    keys = _load_keys()
    if key not in keys:
        return False, "Invalid API key", None
    
    key_data = keys[key]
    
    # Check expiry
    if key_data.get("expires_at") and time.time() > key_data["expires_at"]:
        return False, "Key has expired", None
    
    # Check/Set HWID
    if key_data["hwid"] is None:
        # First use, lock to this HWID
        key_data["hwid"] = hwid
        _save_keys(keys)
    elif key_data["hwid"] != hwid:
        return False, "Key is locked to another device (HWID mismatch)", None
    
    # Update stats
    key_data["uses"] = key_data.get("uses", 0) + 1
    _save_keys(keys)
    
    return True, "Valid key", key_data["type"]

def delete_key(key: str) -> bool:
    keys = _load_keys()
    if key in keys:
        del keys[key]
        _save_keys(keys)
        return True
    return False

def reset_hwid(key: str) -> bool:
    keys = _load_keys()
    if key in keys:
        keys[key]["hwid"] = None
        _save_keys(keys)
        return True
    return False

def get_all_keys() -> Dict:
    """Returns all keys (for admin use)"""
    return _load_keys()
