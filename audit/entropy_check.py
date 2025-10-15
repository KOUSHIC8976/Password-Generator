import math
from typing import Dict, List, Final

try:
    from core.sets import LOWERCASE, UPPERCASE, DIGITS, SYMBOLS
except ImportError:
    LOWERCASE, UPPERCASE, DIGITS, SYMBOLS = "", "", "", ""
try:
    from core.passphrase import ENTROPY_PER_WORD, WORDLIST_SIZE
except ImportError:
    ENTROPY_PER_WORD: Final[float] = 1.0 
    WORDLIST_SIZE: Final[int] = 0

def calculate_string_entropy(secret: str) -> float:
    """
    Calculates the Shannon Entropy (H_Shannon) of a string in bits per character.
    (Used to detect predictability and repetition.)
    """
    if not secret:
        return 0.0

    char_counts: Dict[str, int] = {}
    for char in secret:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    length = len(secret)
    
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def calculate_string_strength_entropy(secret: str) -> float:
    """
    Calculates the estimated cryptographic strength (entropy) using the HYBRID SOTA Model.
    1. Base Strength (R-Model: Max potential entropy) is calculated.
    2. The score is capped by Shannon Entropy if predictability is detected.
    """
    if len(secret) == 0:
        return 0.0

    R = 0
    if any(c in LOWERCASE for c in secret): R += len(LOWERCASE)
    if any(c in UPPERCASE for c in secret): R += len(UPPERCASE)
    if any(c in DIGITS for c in secret): R += len(DIGITS)
    if any(c in SYMBOLS for c in secret): R += len(SYMBOLS)
        
    if R <= 1:
        return 0.0

    base_bits_per_char = math.log2(R)
    base_total_entropy = base_bits_per_char * len(secret)

    h_shannon_per_char = calculate_string_entropy(secret)
    shannon_total_entropy = h_shannon_per_char * len(secret)
    
    
    if h_shannon_per_char < (base_bits_per_char * 0.95):
        return shannon_total_entropy
    else:
        return base_total_entropy

def calculate_passphrase_entropy(passphrase: str, separator: str = "-") -> float:
    """
    Calculates the entropy of a passphrase based on the wordlist size (W).
    Total Entropy H = N * log2(W) where N is the number of words.
    """
    if WORDLIST_SIZE <= 1:
        return 0.0

    words: List[str] = passphrase.split(separator)
    word_count: int = len(words)
    
    if ENTROPY_PER_WORD > 0:
        return word_count * ENTROPY_PER_WORD
    else:
        return calculate_string_entropy(passphrase) * len(passphrase)


def assess_strength(secret: str, is_passphrase: bool = False, passphrase_separator: str = "-") -> Dict[str, str | float]:
    """
    Provides a human-readable assessment of a secret's strength.
    """
    if is_passphrase:
        total_entropy_bits = calculate_passphrase_entropy(secret, separator=passphrase_separator)
        length_metric = f"{len(secret.split(passphrase_separator))} words"
        entropy_per_char_display = "N/A (Wordlist)"
    else:
        total_entropy_bits = calculate_string_strength_entropy(secret)
        entropy_per_char_display = round(total_entropy_bits / len(secret), 2)
        length_metric = f"{len(secret)} chars"
        
    rating = "Very Weak"
    if total_entropy_bits >= 128:
        rating = "Excellent (Cryptographic Grade)"
    elif total_entropy_bits >= 80:
        rating = "Superior (SOTA Recommended)"
    elif total_entropy_bits >= 60:
        rating = "Moderate"
    elif total_entropy_bits < 30:
        rating = "Too Weak"
        
    return {
        "entropy_per_char": entropy_per_char_display,
        "total_entropy_bits": round(total_entropy_bits, 2),
        "length_metric": length_metric,
        "rating": rating
    }