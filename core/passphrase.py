import secrets
from typing import Final
from .Wordlist import EFF_WORDLIST
WORDLIST_SIZE: Final[int] = len(EFF_WORDLIST)
ENTROPY_PER_WORD: Final[float] = 12.92 


def generate_mnemonic_passphrase(word_count: int = 6, separator: str = " ") -> str:
    """
    Generates a cryptographically secure, high-entropy mnemonic passphrase 
    using the Diceware methodology (EFF wordlist).

    :param word_count: The number of words in the passphrase (6 words = SOTA strength).
    :param separator: The character/string used to join the words.
    :return: The generated passphrase string.
    :raises ValueError: If the word count is too low or word list is empty.
    """
    if word_count < 3:
        raise ValueError("Passphrase must contain at least 3 words for minimum security.")
    if WORDLIST_SIZE == 0:
         raise ValueError("The wordlist is empty. Cannot generate passphrase.")

    passphrase_words = []
    
    for _ in range(word_count):
        word = secrets.choice(EFF_WORDLIST)
        passphrase_words.append(word)

    return separator.join(passphrase_words)

