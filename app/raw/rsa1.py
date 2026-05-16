# =========================================================
# RSA CRYPTOGRAPHY
# Command Line Educational Application
# =========================================================
#
# FEATURES:
# ---------------------------------------------------------
# 1. Prime Number Generation
# 2. Miller-Rabin Primality Test
# 3. RSA Key Generation
# 4. RSA Encryption
# 5. RSA Decryption
# 6. Modular Inverse
# 7. Simple Factorization Attack Demo
#
# NOTE:
# ---------------------------------------------------------
# This is an EDUCATIONAL RSA implementation.
#
# No cryptographic libraries are used.
#
# Students implemented:
# - Prime generation
# - Key generation
# - Encryption/Decryption
# - Number theory operations
#
# =========================================================


import random
import math


# =========================================================
# EXTENDED EUCLIDEAN ALGORITHM
# =========================================================
def egcd(a, b):

    """
    Compute:
        gcd(a,b)

    Also computes x and y such that:

        ax + by = gcd(a,b)
    """

    if b == 0:

        return a, 1, 0

    gcd, x1, y1 = egcd(
        b,
        a % b
    )

    x = y1

    y = x1 - (a // b) * y1

    return gcd, x, y


# =========================================================
# MODULAR INVERSE
# =========================================================
def modinv(a, m):

    """
    Compute modular inverse:

        a^-1 mod m
    """

    gcd, x, y = egcd(a, m)

    if gcd != 1:

        raise ValueError(
            "Modular inverse does not exist"
        )

    return x % m


# =========================================================
# MILLER-RABIN PRIMALITY TEST
# =========================================================
def is_probable_prime(n, k=8):

    """
    Miller-Rabin Probabilistic Prime Test

    Returns:
        True  -> probably prime
        False -> composite
    """

    if n < 2:
        return False

    # Small prime checks
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

    # Write:
    # n - 1 = d × 2^s
    d = n - 1
    s = 0

    while d % 2 == 0:

        s += 1
        d //= 2

    # Witness loop
    for _ in range(k):

        a = random.randrange(
            2,
            n - 2
        )

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
# PRIME NUMBER GENERATION
# =========================================================
def generate_prime(bits):

    """
    Generate probable prime
    with specified bit size
    """

    while True:

        # Generate random number
        n = random.getrandbits(bits)

        # Force odd
        n |= 1

        # Force highest bit
        n |= (1 << (bits - 1))

        if is_probable_prime(n):

            return n


# =========================================================
# RSA KEY GENERATION
# =========================================================
def generate_keys(bits=512):

    """
    Generate RSA public/private keys
    """

    bits = max(64, int(bits))

    print("\nGenerating Prime p...")
    p = generate_prime(bits // 2)

    print("Generating Prime q...")
    q = generate_prime(bits // 2)

    # RSA modulus
    n = p * q

    # Euler Totient
    phi = (p - 1) * (q - 1)

    # Standard public exponent
    e = 65537

    # Ensure gcd(e, phi) = 1
    if math.gcd(e, phi) != 1:

        return generate_keys(bits)

    # Private exponent
    d = modinv(e, phi)

    return {

        "public": (e, n),

        "private": (d, n),

        "p": p,

        "q": q,

        "phi": phi
    }


# =========================================================
# TEXT TO INTEGER
# =========================================================
def text_to_int(text):

    """
    Convert plaintext into integer
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
    Convert integer back to plaintext
    """

    return number.to_bytes(
        (number.bit_length() + 7) // 8,
        'big'
    ).decode(errors='replace')


# =========================================================
# RSA ENCRYPTION
# =========================================================
def encrypt(plaintext, public_key):

    """
    RSA Encryption

        C = M^e mod n
    """

    e, n = public_key

    message_int = text_to_int(
        plaintext
    )

    # Ensure message < n
    if message_int >= n:

        raise ValueError(
            "Message too large for key size"
        )

    ciphertext = pow(
        message_int,
        e,
        n
    )

    return ciphertext


# =========================================================
# RSA DECRYPTION
# =========================================================
def decrypt(ciphertext, private_key):

    """
    RSA Decryption

        M = C^d mod n
    """

    d, n = private_key

    plaintext_int = pow(
        int(ciphertext),
        d,
        n
    )

    return int_to_text(
        plaintext_int
    )


# =========================================================
# FACTORIZATION ATTACK DEMO
# =========================================================
def factor_attack(n, limit=100000):

    """
    Simple trial division attack

    Demonstrates why
    small RSA keys are insecure
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

    # -----------------------------------------------------
    # INPUT KEY SIZE
    # -----------------------------------------------------
    bits = int(

        input(
            "\nEnter RSA Key Size "
            "(128 / 256 / 512): "
        )
    )

    # -----------------------------------------------------
    # KEY GENERATION
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("KEY GENERATION")
    print("=" * 60)

    keys = generate_keys(bits)

    public_key = keys["public"]

    private_key = keys["private"]

    p = keys["p"]

    q = keys["q"]

    phi = keys["phi"]

    e, n = public_key

    d, _ = private_key

    # -----------------------------------------------------
    # DISPLAY PARAMETERS
    # -----------------------------------------------------
    print("\nPrime p:")
    print(p)

    print("\nPrime q:")
    print(q)

    print("\nRSA Modulus n = p × q:")
    print(n)

    print("\nEuler Totient φ(n):")
    print(phi)

    print("\nPublic Key (e, n):")
    print(public_key)

    print("\nPrivate Key (d, n):")
    print(private_key)

    # -----------------------------------------------------
    # INPUT PLAINTEXT
    # -----------------------------------------------------
    plaintext = input(
        "\nEnter Plaintext: "
    )

    # -----------------------------------------------------
    # ENCRYPTION
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("ENCRYPTION")
    print("=" * 60)

    ciphertext = encrypt(
        plaintext,
        public_key
    )

    print("\nCiphertext:")
    print(ciphertext)

    # -----------------------------------------------------
    # DECRYPTION
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("DECRYPTION")
    print("=" * 60)

    recovered = decrypt(
        ciphertext,
        private_key
    )

    print("\nRecovered Plaintext:")
    print(recovered)

    # -----------------------------------------------------
    # FACTORIZATION ATTACK DEMO
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("FACTORIZATION ATTACK")
    print("=" * 60)

    attack = factor_attack(n)

    if attack["success"]:

        print("\nFactors Found!")

        print("p =", attack["p"])

        print("q =", attack["q"])

    else:

        print("\nAttack Failed")

        print(attack["message"])

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    print(f"\nOriginal Plaintext : {plaintext}")

    print(f"Recovered Plaintext: {recovered}")

    print("\nEncryption Successful?")

    print(plaintext == recovered)


# =========================================================
# RUN PROGRAM
# =========================================================
if __name__ == "__main__":

    main()