# =========================================================
# DES-STYLE FEISTEL CIPHER
# =========================================================
#
# NOTE:
# This is an EDUCATIONAL DES-style implementation.
# It demonstrates:
#   - Feistel Network
#   - 16 Rounds
#   - Round Key Generation
#   - Encryption / Decryption
#
# It is NOT the official DES standard.
#
# Official DES uses:
#   - Initial Permutation
#   - Expansion Permutation
#   - S-Boxes
#   - P-Boxes
#   - DES Key Schedule
#
# This version is simplified for coursework learning.
#
# =========================================================

from hashlib import sha256


# =========================================================
# BLOCK SIZE
# =========================================================
BLOCK = 8      # 64-bit block


# =========================================================
# PKCS#7 PADDING
# =========================================================
def pad(data):

    """
    Pad plaintext to multiple of 8 bytes
    """

    padding_length = BLOCK - (len(data) % BLOCK)

    return data + bytes([padding_length]) * padding_length


# =========================================================
# REMOVE PADDING
# =========================================================
def unpad(data):

    """
    Remove PKCS#7 padding
    """

    padding_length = data[-1]

    return data[:-padding_length]


# =========================================================
# FEISTEL FUNCTION
# =========================================================
def feistel_function(right, round_key):

    """
    DES-style round function

    Steps:
    1. XOR with round key
    2. Bit rotation
    3. Multiplication scrambling
    4. XOR diffusion
    """

    x = (right ^ round_key) & 0xffffffff

    # Left rotate by 3 bits
    x = ((x << 3) | (x >> 29)) & 0xffffffff

    # Scrambling
    x = (x * 0x45D9F3B) & 0xffffffff

    # Final diffusion
    result = x ^ ((x >> 16) & 0xffffffff)

    return result


# =========================================================
# ROUND KEY GENERATION
# =========================================================
def generate_round_keys(key):

    """
    Generate 16 round keys

    Uses SHA-256 repeatedly
    """

    if len(key) != 8:

        raise ValueError(
            "Key must be exactly 8 bytes"
        )

    seed = key

    round_keys = []

    for i in range(16):

        seed = sha256(
            seed + bytes([i])
        ).digest()

        rk = int.from_bytes(
            seed[:4],
            'big'
        )

        round_keys.append(rk)

    return round_keys


# =========================================================
# ENCRYPT SINGLE BLOCK
# =========================================================
def encrypt_block(block, key):

    """
    Encrypt 64-bit block using
    16-round Feistel structure
    """

    # Split into left/right halves
    left = int.from_bytes(
        block[:4],
        'big'
    )

    right = int.from_bytes(
        block[4:],
        'big'
    )

    round_keys = generate_round_keys(key)

    print("\nENCRYPTION ROUNDS")
    print("-" * 50)

    # 16 rounds
    for i, rk in enumerate(round_keys):

        temp = left ^ feistel_function(
            right,
            rk
        )

        left = right
        right = temp

        print(
            f"Round {i+1:2d} | "
            f"L = {left:08X} | "
            f"R = {right:08X} | "
            f"K = {rk:08X}"
        )

    # Final swap
    ciphertext = (
        right.to_bytes(4, 'big') +
        left.to_bytes(4, 'big')
    )

    return ciphertext


# =========================================================
# DECRYPT SINGLE BLOCK
# =========================================================
def decrypt_block(block, key):

    """
    Decrypt block using reverse round keys
    """

    right = int.from_bytes(
        block[:4],
        'big'
    )

    left = int.from_bytes(
        block[4:],
        'big'
    )

    round_keys = generate_round_keys(key)

    print("\nDECRYPTION ROUNDS")
    print("-" * 50)

    for i, rk in enumerate(reversed(round_keys)):

        temp = right ^ feistel_function(
            left,
            rk
        )

        right = left
        left = temp

        print(
            f"Round {i+1:2d} | "
            f"L = {left:08X} | "
            f"R = {right:08X} | "
            f"K = {rk:08X}"
        )

    plaintext = (
        left.to_bytes(4, 'big') +
        right.to_bytes(4, 'big')
    )

    return plaintext


# =========================================================
# FULL ENCRYPTION
# =========================================================
def encrypt(plaintext, key):

    """
    Encrypt complete plaintext
    """

    data = pad(
        plaintext.encode()
    )

    ciphertext = b""

    for i in range(0, len(data), 8):

        block = data[i:i+8]

        encrypted = encrypt_block(
            block,
            key
        )

        ciphertext += encrypted

    return ciphertext.hex()


# =========================================================
# FULL DECRYPTION
# =========================================================
def decrypt(cipher_hex, key):

    """
    Decrypt complete ciphertext
    """

    data = bytes.fromhex(cipher_hex)

    plaintext = b""

    for i in range(0, len(data), 8):

        block = data[i:i+8]

        decrypted = decrypt_block(
            block,
            key
        )

        plaintext += decrypted

    plaintext = unpad(plaintext)

    return plaintext.decode(
        errors='replace'
    )


# =========================================================
# AUTO DEFAULT KEY
# =========================================================
def auto_key():

    """
    Default 8-byte key
    """

    return b"DESKEY!!"


# =========================================================
# DISPLAY ROUND KEYS
# =========================================================
def round_keys_hex(key):

    """
    Display round keys in hex
    """

    keys = generate_round_keys(key)

    return [
        f"{k:08X}"
        for k in keys
    ]


# =========================================================
# MAIN PROGRAM
# =========================================================
def main():

    print("=" * 60)
    print("DES-STYLE FEISTEL CIPHER")
    print("=" * 60)

    # -----------------------------------------------------
    # INPUT PLAINTEXT
    # -----------------------------------------------------
    plaintext = input(
        "\nEnter Plaintext: "
    )

    # -----------------------------------------------------
    # INPUT KEY
    # -----------------------------------------------------
    print("\nDES Key must be exactly 8 characters")

    user_key = input(
        "Enter Key (8 chars): "
    )

    # Validate key length
    if len(user_key) != 8:

        print("\nERROR:")
        print("Key must be exactly 8 characters")

        return

    key = user_key.encode()

    # -----------------------------------------------------
    # DISPLAY ROUND KEYS
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("16 ROUND KEYS")
    print("=" * 60)

    keys = round_keys_hex(key)

    for i, rk in enumerate(keys):

        print(
            f"Round {i+1:2d}: {rk}"
        )

    # -----------------------------------------------------
    # ENCRYPTION
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("ENCRYPTION")
    print("=" * 60)

    ciphertext = encrypt(
        plaintext,
        key
    )

    print("\nCiphertext (HEX):")
    print(ciphertext)

    # -----------------------------------------------------
    # DECRYPTION
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("DECRYPTION")
    print("=" * 60)

    recovered = decrypt(
        ciphertext,
        key
    )

    print("\nRecovered Plaintext:")
    print(recovered)

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    print(f"\nOriginal Plaintext : {plaintext}")
    print(f"Ciphertext (HEX)  : {ciphertext}")
    print(f"Recovered Text    : {recovered}")

    print("\nEncryption Successful?")
    print(plaintext == recovered)


# =========================================================
# RUN PROGRAM
# =========================================================
if __name__ == "__main__":
    main()