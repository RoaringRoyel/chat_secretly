# =========================================================
# RSA CRYPTOGRAPHY
# Command Line Educational Application
# =========================================================

import random
import math


# =========================================================
# EXTENDED EUCLIDEAN ALGORITHM
# =========================================================
def egcd(a, b):

    """
    Compute:
        gcd(a, b)

    Also returns coefficients x and y such that:

        ax + by = gcd(a,b)
    """

    if b == 0:
        return a, 1, 0

    g, x1, y1 = egcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return g, x, y


# =========================================================
# MODULAR INVERSE
# =========================================================
def modinv(a, m):

    """
    Compute modular inverse:

        a^-1 mod m
    """

    g, x, y = egcd(a, m)

    if g != 1:
        raise ValueError(
            "Modular inverse does not exist."
        )

    return x % m


# =========================================================
# MILLER-RABIN PRIMALITY TEST
# =========================================================
def is_probable_prime(n, k=8):

    """
    Probabilistic prime test
    """

    if n < 2:
        return False

    small_primes = [
        2, 3, 5, 7, 11,
        13, 17, 19, 23,
        29, 31, 37
    ]

    if n in small_primes:
        return True

    for p in small_primes:

        if n % p == 0:
            return False

    # Write n-1 as:
    # d * 2^s
    d = n - 1
    s = 0

    while d % 2 == 0:
        s += 1
        d //= 2

    # Witness loop
    for _ in range(k):

        a = random.randrange(2, n - 2)

        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):

            x = pow(x, 2, n)

            if x == n - 1:
                break

        else:
            return False

    return True


# =========================================================
# GENERATE PRIME
# =========================================================
def generate_prime(bits):

    """
    Generate random prime number
    """

    while True:

        n = random.getrandbits(bits)

        # Ensure:
        # - odd
        # - highest bit set
        n |= (1 << bits - 1) | 1

        if is_probable_prime(n):
            return n


# =========================================================
# GENERATE RSA KEYS
# =========================================================
def generate_keys(bits=512):

    """
    Generate RSA public/private keys
    """

    bits = max(64, int(bits))

    # Generate two primes
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    # RSA modulus
    n = p * q

    # Euler Totient
    phi = (p - 1) * (q - 1)

    # Standard public exponent
    e = 65537

    # Ensure coprime
    if math.gcd(e, phi) != 1:
        return generate_keys(bits)

    # Private exponent
    d = modinv(e, phi)

    return {
        "public": (e, n),
        "private": (d, n),
        "p": p,
        "q": q
    }


# =========================================================
# TEXT TO INTEGER
# =========================================================
def text_to_int(text):

    """
    Convert string to integer
    """

    return int.from_bytes(
        text.encode(),
        'big'
    )


# =========================================================
# INTEGER TO TEXT
# =========================================================
def int_to_text(number):

    """
    Convert integer back to text
    """

    return number.to_bytes(
        (number.bit_length() + 7) // 8,
        'big'
    ).decode(errors='replace')


# =========================================================
# ENCRYPTION
# =========================================================
def encrypt(plaintext, public_key):

    """
    RSA Encryption
    """

    e, n = public_key

    # Convert message to integer
    m = text_to_int(plaintext)

    if m >= n:

        raise ValueError(
            "Message too large for key size."
        )

    # Ciphertext
    c = pow(m, e, n)

    return c


# =========================================================
# DECRYPTION
# =========================================================
def decrypt(ciphertext, private_key):

    """
    RSA Decryption
    """

    d, n = private_key

    # Recover plaintext integer
    m = pow(ciphertext, d, n)

    # Convert back to text
    return int_to_text(m)


# =========================================================
# OPTIONAL FACTORIZATION ATTACK
# =========================================================
def factor_attack(n, limit=200000):

    """
    Trial division attack
    """

    for i in range(
        2,
        min(limit, int(n**0.5) + 1)
    ):

        if n % i == 0:

            return {
                "success": True,
                "p": i,
                "q": n // i
            }

    return {
        "success": False,
        "message":
        f"No factor found up to {limit}"
    }


# =========================================================
# MAIN PROGRAM
# =========================================================
def main():

    print("=" * 60)
    print("RSA CRYPTOGRAPHY")
    print("=" * 60)

    print("\nChoices")
    print("1. Generate Keys")
    print("2. Encrypt")
    print("3. Decrypt")

    choice = input("\nEnter Choice: ")

    # -----------------------------------------------------
    # KEY GENERATION
    # -----------------------------------------------------
    if choice == "1":

        bits = int(
            input(
                "\nEnter Key Size (128/ 256/ 512 / 1024): "
            )
        )

        keys = generate_keys(bits)

        public_key = keys["public"]
        private_key = keys["private"]

        print("\n" + "=" * 60)
        print("GENERATED KEYS")
        print("=" * 60)

        print("\nPrime p:")
        print(keys["p"])

        print("\nPrime q:")
        print(keys["q"])

        print("\nPublic Key (e, n):")
        print(public_key)

        print("\nPrivate Key (d, n):")
        print(private_key)

    # -----------------------------------------------------
    # ENCRYPTION
    # -----------------------------------------------------
    elif choice == "2":

        bits = int(
            input(
                "\nEnter Key Size (128 / 256/ 512 / 1024): "
            )
        )

        keys = generate_keys(bits)

        public_key = keys["public"]
        private_key = keys["private"]

        plaintext = input(
            "\nEnter Plaintext: "
        )

        ciphertext = encrypt(
            plaintext,
            public_key
        )

        decrypted = decrypt(
            ciphertext,
            private_key
        )

        print("\n" + "=" * 60)
        print("RSA ENCRYPTION")
        print("=" * 60)

        print("\nPublic Key:")
        print(public_key)

        print("\nPrivate Key:")
        print(private_key)

        print("\nCiphertext (Integer):")
        print(ciphertext)

        print("\nCiphertext (Hex):")
        print(hex(ciphertext))

        print("\nDecrypted Message:")
        print(decrypted)

    # -----------------------------------------------------
    # DECRYPTION
    # -----------------------------------------------------
    elif choice == "3":

        d = int(input("\nEnter d: "))
        n = int(input("Enter n: "))

        ciphertext = int(
            input(
                "\nEnter Ciphertext Integer: "
            )
        )

        plaintext = decrypt(
            ciphertext,
            (d, n)
        )

        print("\nRecovered Plaintext:")
        print(plaintext)

    # -----------------------------------------------------
    # INVALID CHOICE
    # -----------------------------------------------------
    else:

        print("\nInvalid choice.")

        return

    # -----------------------------------------------------
    # OPTIONAL FACTORIZATION ATTACK
    # -----------------------------------------------------
    attack = input(
        "\nPerform Factorization Attack? (y/n): "
    )

    if attack.lower() == 'y':

        if choice == "3":

            result = factor_attack(n)

        else:

            result = factor_attack(
                public_key[1]
            )

        print("\n" + "=" * 60)
        print("FACTORIZATION ATTACK")
        print("=" * 60)

        print(result)


# =========================================================
# RUN PROGRAM
# =========================================================
if __name__ == "__main__":
    main()