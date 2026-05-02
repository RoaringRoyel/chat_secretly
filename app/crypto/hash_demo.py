import os

IV = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
]


def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def custom_sha_like(data: bytes) -> str:
    """Educational SHA-like Merkle-Damgard hash. Not secure for real passwords."""
    msg = bytearray(data)
    bit_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += bit_len.to_bytes(8, "big")
    h = IV[:]
    for block_start in range(0, len(msg), 64):
        block = msg[block_start:block_start + 64]
        words = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            words.append((rotl(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1) + i) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, hh = h
        for i, w in enumerate(words):
            mix = (rotl(a, 5) + ((b & c) ^ (~b & d)) + e + w + (0x9E3779B9 ^ i)) & 0xFFFFFFFF
            a, b, c, d, e, f, g, hh = mix, a, rotl(b, 30), c, d, e, f, g
        h = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return "".join(f"{x:08x}" for x in h)


def new_salt() -> str:
    return os.urandom(16).hex()


def hash_password(password: str, salt: str) -> str:
    value = (salt + ":" + password).encode()
    for _ in range(5000):
        value = bytes.fromhex(custom_sha_like(value))
    return custom_sha_like(value)


def verify_password(password: str, salt: str, expected: str) -> bool:
    return hash_password(password, salt) == expected
