# =========================================================
# SUBSTITUTION CIPHER
# =========================================================

from collections import Counter
import string


# ---------------------------------------------------------
# ALPHABET
# ---------------------------------------------------------
ALPHABET = string.ascii_uppercase

# English letter frequency order
COMMON_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"


# =========================================================
# VALIDATE KEY
# =========================================================
def normalize_key(key):

    """
    Validate substitution key.

    Rules:
    - Must contain exactly 26 letters
    - Must contain A-Z exactly once
    """

    key = key.upper()

    # Remove non-letters
    key = "".join(
        ch for ch in key
        if ch.isalpha()
    )

    # Validation
    if len(key) != 26:

        raise ValueError(
            "Key must contain exactly 26 letters."
        )

    if set(key) != set(ALPHABET):

        raise ValueError(
            "Key must be a permutation of A-Z."
        )

    return key


# =========================================================
# DISPLAY MAPPING
# =========================================================
def show_mapping(key):

    """
    Display substitution mapping
    """

    print("\nSubstitution Mapping")
    print("-" * 30)

    for p, c in zip(ALPHABET, key):

        print(f"{p} -> {c}")


# =========================================================
# ENCRYPTION
# =========================================================
def encrypt(plaintext, key):

    """
    Encrypt plaintext
    """

    key = normalize_key(key)

    # Create translation table
    table = str.maketrans(
        ALPHABET + ALPHABET.lower(),
        key + key.lower()
    )

    ciphertext = plaintext.translate(table)

    return ciphertext


# =========================================================
# DECRYPTION
# =========================================================
def decrypt(ciphertext, key):

    """
    Decrypt ciphertext
    """

    key = normalize_key(key)

    table = str.maketrans(
        key + key.lower(),
        ALPHABET + ALPHABET.lower()
    )

    plaintext = ciphertext.translate(table)

    return plaintext


# =========================================================
# FREQUENCY ANALYSIS
# =========================================================
def frequency_analysis(text):

    """
    Analyze letter frequency
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
# FREQUENCY-BASED GUESS
# =========================================================
def frequency_guess(ciphertext):

    """
    Simple frequency attack guess
    """

    counts = Counter(
        c for c in ciphertext.upper()
        if c.isalpha()
    )

    ranked = [
        x for x, _
        in counts.most_common()
    ]

    mapping = {}

    # Match frequency order
    for cipher_ch, plain_ch in zip(
        ranked,
        COMMON_ORDER
    ):

        mapping[cipher_ch] = plain_ch

    guessed_text = ""

    for c in ciphertext:

        if c.isalpha():

            guessed = mapping.get(
                c.upper(),
                c
            )

            if c.islower():
                guessed = guessed.lower()

            guessed_text += guessed

        else:
            guessed_text += c

    return guessed_text


# =========================================================
# MAIN PROGRAM
# =========================================================
def main():

    print("=" * 60)
    print("SUBSTITUTION CIPHER")
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
    print("\nEnter 26-letter substitution key")

    print("Example:")
    print("QWERTYUIOPASDFGHJKLZXCVBNM")

    key = input("\nKey: ")

    try:

        key = normalize_key(key)

    except ValueError as e:

        print("\nERROR:")
        print(e)

        return

    # -----------------------------------------------------
    # SHOW MAPPING
    # -----------------------------------------------------
    show_mapping(key)

    # -----------------------------------------------------
    # ENCRYPT
    # -----------------------------------------------------
    ciphertext = encrypt(
        plaintext,
        key
    )

    print("\n" + "=" * 60)
    print("ENCRYPTION")
    print("=" * 60)

    print("\nCiphertext:")
    print(ciphertext)

    # -----------------------------------------------------
    # DECRYPT
    # -----------------------------------------------------
    decrypted = decrypt(
        ciphertext,
        key
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
    # FREQUENCY ATTACK GUESS
    # -----------------------------------------------------
    guessed = frequency_guess(ciphertext)

    print("\nFrequency-Based Guess:")
    print(guessed)


# =========================================================
# RUN PROGRAM
# =========================================================
if __name__ == "__main__":
    main()