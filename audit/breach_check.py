import hashlib
from typing import Final, Tuple, Dict, List

HASH_ALGORITHM: Final[str] = 'sha1'
PREFIX_LENGTH: Final[int] = 5
SIMULATED_BREACH_DATA: Final[Dict[str, List[Tuple[str, int]]]] = {
    '00000': [
        ('1A3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8', 1234),
        ('1B3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8', 5),
    ],
    'AE0FD': [
        ('13F402A7F99C6EE66FFDAE83DA0CC029115', 5000000), 
    ],
    'ABCDE': [('FGHIJK...', 1)],
    '11111': [('FFFFF...', 500)],
}

def check_breach_k_anonymity(secret: str) -> Tuple[bool, int]:
    """
    Checks a secret against known breaches using the privacy-preserving K-Anonymity method.
    
    :param secret: The password or key to check.
    :return: A tuple (is_breached, breach_count).
    """
    secret_upper = secret.upper()
    hash_obj = hashlib.sha1(secret_upper.encode('utf-8'))
    full_hash = hash_obj.hexdigest().upper()
    
    prefix = full_hash[:5] 
    suffix = full_hash[5:]
    
    breach_list = SIMULATED_BREACH_DATA.get(prefix, [])
    
    if not breach_list:
        return False, 0
    
    for breached_suffix, count in breach_list:
        if suffix == breached_suffix:
            return True, count
            
    return False, 0