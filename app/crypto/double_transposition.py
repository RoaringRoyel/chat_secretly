import math
from .substitution import frequency_analysis


def parse_key(key: str):
    nums = [int(x.strip()) for x in key.replace(",", " ").split() if x.strip()]
    if sorted(nums) != list(range(1, len(nums) + 1)):
        raise ValueError("Permutation key must contain numbers 1..n exactly once, e.g. 3 1 4 2")
    return nums


def pad(text: str, block: int) -> str:
    rem = len(text) % block
    return text if rem == 0 else text + ("X" * (block - rem))


def columnar_encrypt(text: str, key):
    cols = len(key)
    text = pad(text, cols)
    rows = [text[i:i + cols] for i in range(0, len(text), cols)]
    order = sorted(range(cols), key=lambda i: key[i])
    return "".join("".join(row[i] for row in rows) for i in order)


def columnar_decrypt(cipher: str, key):
    cols = len(key)
    rows_count = math.ceil(len(cipher) / cols)
    order = sorted(range(cols), key=lambda i: key[i])
    columns = {}
    idx = 0
    for col in order:
        columns[col] = cipher[idx:idx + rows_count]
        idx += rows_count
    plain = []
    for r in range(rows_count):
        for c in range(cols):
            if r < len(columns[c]):
                plain.append(columns[c][r])
    return "".join(plain).rstrip("X")


def encrypt(plaintext: str, key1: str, key2: str) -> str:
    k1, k2 = parse_key(key1), parse_key(key2)
    return columnar_encrypt(columnar_encrypt(plaintext, k1), k2)


def decrypt(ciphertext: str, key1: str, key2: str) -> str:
    k1, k2 = parse_key(key1), parse_key(key2)
    return columnar_decrypt(columnar_decrypt(ciphertext, k2), k1)


def analyze(text: str):
    return frequency_analysis(text)
