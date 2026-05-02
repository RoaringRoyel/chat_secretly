from collections import Counter
import string

ALPHABET = string.ascii_uppercase
COMMON_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"


def normalize_key(key: str) -> str:
    key = "".join(ch for ch in key.upper() if ch.isalpha())
    if len(key) != 26 or set(key) != set(ALPHABET):
        raise ValueError("Key must be a 26-letter permutation of A-Z")
    return key


def encrypt(plaintext: str, key: str) -> str:
    key = normalize_key(key)
    table = str.maketrans(ALPHABET + ALPHABET.lower(), key + key.lower())
    return plaintext.translate(table)


def decrypt(ciphertext: str, key: str) -> str:
    key = normalize_key(key)
    inv = {c: p for p, c in zip(ALPHABET, key)}
    table = str.maketrans(key + key.lower(), ALPHABET + ALPHABET.lower())
    return ciphertext.translate(table)


def frequency_analysis(text: str):
    letters = [c.upper() for c in text if c.isalpha()]
    total = len(letters) or 1
    counts = Counter(letters)
    return [{"letter": ch, "count": counts[ch], "percent": round(counts[ch] * 100 / total, 2)} for ch in ALPHABET]


def frequency_guess(ciphertext: str) -> str:
    counts = Counter(c for c in ciphertext.upper() if c.isalpha())
    ranked = [x for x, _ in counts.most_common()]
    mapping = {}
    for cipher_ch, plain_ch in zip(ranked, COMMON_ORDER):
        mapping[cipher_ch] = plain_ch
    return "".join(mapping.get(c.upper(), c) if c.isupper() else mapping.get(c.upper(), c).lower() for c in ciphertext)


def brute_force_caesar_only(ciphertext: str):
    results = []
    for shift in range(26):
        key = ALPHABET[shift:] + ALPHABET[:shift]
        results.append({"shift": shift, "plaintext": decrypt(ciphertext, key)})
    return results
