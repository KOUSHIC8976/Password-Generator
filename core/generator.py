import secrets
import random
from typing import Optional, Dict, List
from .sets import LOWERCASE, UPPERCASE, DIGITS, SYMBOLS, ALL_STANDARD

STANDARD_POLICY: Dict[str, int] = {
    "lower": 1,
    "upper": 1,
    "digit": 1,
    "symbol": 1,
}

def generate_secure_password(
    length: int = 16,
    policy: Optional[Dict[str, int]] = None
) -> str:
    """
    Generates a cryptographically secure, high-entropy password based on a policy.

    It uses the `secrets` module for secure randomness and ensures minimum 
    character requirements are met, then securely shuffles the result.

    :param length: The desired total length of the password (SOTA >= 16).
    :param policy: A dictionary defining minimum character requirements 
                   (e.g., {"lower": 2, "upper": 1}). Defaults to STANDARD_POLICY.
    :return: The generated high-entropy password string.
    :raises ValueError: If minimum requirements exceed the specified length.
    """
    if length <= 0:
        raise ValueError("Password length must be a positive integer.")
    
    current_policy = policy if policy is not None else STANDARD_POLICY


    char_map: Dict[str, str] = {
        "lower": LOWERCASE,
        "upper": UPPERCASE,
        "digit": DIGITS,
        "symbol": SYMBOLS,
    }

    password_list: List[str] = []
    total_required = 0

    for char_type, min_count in current_policy.items():
        if min_count < 0:
            raise ValueError(f"Minimum count for {char_type} cannot be negative.")
        
        char_set = char_map.get(char_type)
        if char_set is None:
            continue 

        total_required += min_count
        
       
        for _ in range(min_count):
            password_list.append(secrets.choice(char_set))

    if total_required > length:
        raise ValueError(
            f"Minimum character requirements ({total_required}) exceed the total length ({length})."
        )

    all_available_chars = "".join(char_map.values())
    remaining_length = length - len(password_list)

    for _ in range(remaining_length):
        password_list.append(secrets.choice(all_available_chars))

    random.SystemRandom().shuffle(password_list)

    return "".join(password_list)


def generate_url_safe_token(n_bytes: int = 32) -> str:
    """
    Generates a secure, URL-safe, base64-encoded text string for use as 
    password reset tokens, API keys, etc. (SOTA token generation).
    
    :param n_bytes: The number of random bytes to generate (entropy source).
    :return: The base64-encoded string.
    """
    if n_bytes <= 0:
        raise ValueError("Byte count must be a positive integer.")
        
    return secrets.token_urlsafe(n_bytes)


def generate_hex_key(n_bytes: int = 32) -> str:
    """
    Generates a secure hexadecimal string suitable for cryptographic keys 
    (e.g., 32 bytes for a 256-bit AES key).
    
    :param n_bytes: The number of random bytes to generate (entropy source).
    :return: The hexadecimal key string.
    """
    if n_bytes <= 0:
        raise ValueError("Byte count must be a positive integer.")
        
    return secrets.token_hex(n_bytes)