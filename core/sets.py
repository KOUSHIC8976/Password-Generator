import string
from typing import Final
LOWERCASE: Final[str] = string.ascii_lowercase
UPPERCASE: Final[str] = string.ascii_uppercase
DIGITS: Final[str] = string.digits
SYMBOLS: Final[str] = "!@#$%^&*()-_+=[]{}|;:,.<>/?`~"
ALL_STANDARD: Final[str] = LOWERCASE + UPPERCASE + DIGITS + SYMBOLS
WORD_LIST: Final[list[str]] = [
    "alpha", "bravo", "charlie", "delta", "echo",
    "foxtrot", "golf", "hotel", "complex", "juliet"
]