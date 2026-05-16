# =========================================================
# DOUBLE TRANSPOSITION CIPHER
# =========================================================

import math
from collections import Counter
import string


# =========================================================
# ALPHABET
# =========================================================
ALPHABET = string.ascii_uppercase


# =========================================================
# PARSE PERMUTATION KEY
# =========================================================
def parse_key(key):

    """
    Convert key string into permutation list

    Example:
        "3 1 4 2"
    becomes:
        [3,1,4,2]
    """

    nums = [
        int(x.strip())
        for x in key.replace(",", " ").split()
        if x.strip()
    ]

    # Validate permutation
    if sorted(nums) != list(range(1, len(nums) + 1)):

        raise ValueError(
            "Permutation key must contain "
            "numbers 1..n exactly once"
        )

    return nums


# =========================================================
# PADDING
# =========================================================
def pad(text, block_size):

    """
    Pad plaintext using X
    """

    remainder = len(text) % block_size

    if remainder == 0:
        return text

    needed = block_size - remainder

    return text + ("X" * needed)


# =========================================================
# COLUMNAR TRANSPOSITION ENCRYPTION
# =========================================================
def columnar_encrypt(text, key):

    """
    Perform single columnar transposition encryption
    """

    cols = len(key)

    # Pad text
    text = pad(text, cols)

    # Create rows
    rows = [
        text[i:i + cols]
        for i in range(0, len(text), cols)
    ]

    # Determine column read order
    order = sorted(
        range(cols),
        key=lambda i: key[i]
    )

    # Read columns
    ciphertext = ""

    for col in order:

        for row in rows:

            ciphertext += row[col]

    return ciphertext


# =========================================================
# COLUMNAR TRANSPOSITION DECRYPTION
# =========================================================
def columnar_decrypt(ciphertext, key):

    """
    Perform single columnar transposition decryption
    """

    cols = len(key)

    rows_count = math.ceil(
        len(ciphertext) / cols
    )

    order = sorted(
        range(cols),
        key=lambda i: key[i]
    )

    columns = {}

    index = 0

    # Fill columns
    for col in order:

        columns[col] = ciphertext[
            index:index + rows_count
        ]

        index += rows_count

    # Rebuild plaintext row-wise
    plaintext = []

    for r in range(rows_count):

        for c in range(cols):

            if r < len(columns[c]):

                plaintext.append(
                    columns[c][r]
                )

    return "".join(plaintext).rstrip("X")


# =========================================================
# DOUBLE TRANSPOSITION ENCRYPTION
# =========================================================
def encrypt(plaintext, key1, key2):

    """
    Apply columnar transposition twice
    """

    k1 = parse_key(key1)

    k2 = parse_key(key2)

    first_pass = columnar_encrypt(
        plaintext,
        k1
    )

    second_pass = columnar_encrypt(
        first_pass,
        k2
    )

    return second_pass


# =========================================================
# DOUBLE TRANSPOSITION DECRYPTION
# =========================================================
def decrypt(ciphertext, key1, key2):

    """
    Reverse double transposition
    """

    k1 = parse_key(key1)

    k2 = parse_key(key2)

    first_pass = columnar_decrypt(
        ciphertext,
        k2
    )

    second_pass = columnar_decrypt(
        first_pass,
        k1
    )

    return second_pass


# =========================================================
# FREQUENCY ANALYSIS
# =========================================================
def frequency_analysis(text):

    """
    Analyze character frequency
    """

    letters = [
        c.upper()
        for c in text
        if c.isalpha()
    ]

    total = len(letters)

    counts = Counter(letters)

    print("\nFrequency Analysis")
    print("-" * 35)

    for ch in ALPHABET:

        count = counts[ch]

        percent = (
            (count / total) * 100
            if total > 0 else 0
        )

        print(
            f"{ch} : {count:3d} times "
            f"({percent:.2f}%)"
        )


# =========================================================
# DISPLAY MATRIX
# =========================================================
def show_matrix(text, cols):

    """
    Display text in matrix form
    """

    rows = [
        text[i:i + cols]
        for i in range(0, len(text), cols)
    ]

    for row in rows:
        print(" ".join(row))


# =========================================================
# MAIN PROGRAM
# =========================================================
def main():

    print("=" * 60)
    print("DOUBLE TRANSPOSITION CIPHER")
    print("=" * 60)

    # -----------------------------------------------------
    # INPUT PLAINTEXT
    # -----------------------------------------------------
    plaintext = input(
        "\nEnter Plaintext: "
    )

    # -----------------------------------------------------
    # INPUT KEYS
    # -----------------------------------------------------
    print("\nEnter First Permutation Key")
    print("Example: 3 1 4 2")

    key1 = input("Key 1: ")

    print("\nEnter Second Permutation Key")
    print("Example: 2 4 1 3")

    key2 = input("Key 2: ")

    try:

        k1 = parse_key(key1)
        k2 = parse_key(key2)

    except ValueError as e:

        print("\nERROR:")
        print(e)

        return

    # -----------------------------------------------------
    # SHOW MATRICES
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("PLAINTEXT MATRIX")
    print("=" * 60)

    padded = pad(plaintext, len(k1))

    show_matrix(
        padded,
        len(k1)
    )

    # -----------------------------------------------------
    # ENCRYPTION
    # -----------------------------------------------------
    ciphertext = encrypt(
        plaintext,
        key1,
        key2
    )

    print("\n" + "=" * 60)
    print("ENCRYPTION")
    print("=" * 60)

    print("\nCiphertext:")
    print(ciphertext)

    # -----------------------------------------------------
    # DECRYPTION
    # -----------------------------------------------------
    decrypted = decrypt(
        ciphertext,
        key1,
        key2
    )

    print("\n" + "=" * 60)
    print("DECRYPTION")
    print("=" * 60)

    print("\nRecovered Plaintext:")
    print(decrypted)

    # -----------------------------------------------------
    # FREQUENCY ANALYSIS
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("FREQUENCY ANALYSIS")
    print("=" * 60)

    frequency_analysis(ciphertext)

    # -----------------------------------------------------
    # SHOW KEYS
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("KEY INFORMATION")
    print("=" * 60)

    print("\nFirst Key:")
    print(k1)

    print("\nSecond Key:")
    print(k2)


# =========================================================
# RUN PROGRAM
# =========================================================
if __name__ == "__main__":
    main()