# =========================================================
# ELLIPTIC CURVE CRYPTOGRAPHY (ECC)
# =========================================================

# ---------------------------------------------------------
# POINT AT INFINITY
# ---------------------------------------------------------
O = None


# =========================================================
# MODULAR INVERSE
# =========================================================
def inv_mod(k, p):

    """
    Compute modular inverse:
        k^-1 mod p
    """

    return pow(k % p, -1, p)


# =========================================================
# CHECK WHETHER POINT IS ON CURVE
# =========================================================
def is_on_curve(P, a, b, p):

    """
    Check whether point satisfies:
        y^2 = x^3 + ax + b mod p
    """

    if P is O:
        return True

    x, y = P

    return (
        (y * y - (x**3 + a*x + b))
        % p == 0
    )


# =========================================================
# POINT ADDITION
# =========================================================
def add(P, Q, a, p):

    """
    ECC Point Addition
    """

    if P is O:
        return Q

    if Q is O:
        return P

    x1, y1 = P
    x2, y2 = Q

    # P + (-P) = O
    if x1 == x2 and (y1 + y2) % p == 0:
        return O

    # Point doubling
    if P == Q:

        m = (
            (3 * x1 * x1 + a)
            * inv_mod(2 * y1, p)
        ) % p

    # Normal addition
    else:

        m = (
            (y2 - y1)
            * inv_mod(x2 - x1, p)
        ) % p

    x3 = (m * m - x1 - x2) % p

    y3 = (m * (x1 - x3) - y1) % p

    return (x3, y3)


# =========================================================
# SCALAR MULTIPLICATION
# =========================================================
def mul(k, P, a, p):

    """
    Compute:
        k * P

    using Double-and-Add
    """

    R = O
    Q = P

    while k > 0:

        if k & 1:
            R = add(R, Q, a, p)

        Q = add(Q, Q, a, p)

        k //= 2

    return R


# =========================================================
# LIST ALL POINTS
# =========================================================
def list_points(p, a, b):

    """
    Generate all valid curve points
    """

    points = []

    for x in range(p):

        rhs = (x**3 + a*x + b) % p

        for y in range(p):

            if (y*y) % p == rhs:
                points.append((x, y))

    return points


# =========================================================
# MAIN PROGRAM
# =========================================================
def main():

    print("=" * 60)
    print("ELLIPTIC CURVE CRYPTOGRAPHY (ECC)")
    print("=" * 60)

    # -----------------------------------------------------
    # DOMAIN PARAMETERS
    # -----------------------------------------------------
    print("\nEnter Domain Parameters")

    p = int(input("Prime number p: "))
    a = int(input("Curve parameter a: "))
    b = int(input("Curve parameter b: "))

    # -----------------------------------------------------
    # GENERATOR POINT
    # -----------------------------------------------------
    print("\nEnter Generator Point G(x,y)")

    gx = int(input("Gx: "))
    gy = int(input("Gy: "))

    G = (gx, gy)

    # Verify point validity
    if not is_on_curve(G, a, b, p):

        print("\nERROR:")
        print("Generator point is NOT on curve!")

        return

    # -----------------------------------------------------
    # DISPLAY CURVE EQUATION
    # -----------------------------------------------------
    print("\nCurve Equation:")

    print(
        f"y^2 = x^3 + {a}x + {b} mod {p}"
    )

    # -----------------------------------------------------
    # LIST ALL POINTS
    # -----------------------------------------------------
    points = list_points(p, a, b)

    print("\nAll Points on Curve:")

    for pt in points:
        print(pt)

    print(f"\nTotal Points: {len(points)}")

    # -----------------------------------------------------
    # PRIVATE KEYS
    # -----------------------------------------------------
    print("\nEnter Private Keys")

    alice_private = int(
        input("Alice Private Key: ")
    )

    bob_private = int(
        input("Bob Private Key: ")
    )

    # -----------------------------------------------------
    # PUBLIC KEYS
    # -----------------------------------------------------
    alice_public = mul(
        alice_private,
        G,
        a,
        p
    )

    bob_public = mul(
        bob_private,
        G,
        a,
        p
    )

    # -----------------------------------------------------
    # SHARED SECRET
    # -----------------------------------------------------
    alice_shared = mul(
        alice_private,
        bob_public,
        a,
        p
    )

    bob_shared = mul(
        bob_private,
        alice_public,
        a,
        p
    )

    # -----------------------------------------------------
    # OUTPUT RESULTS
    # -----------------------------------------------------
    print("\n" + "=" * 60)
    print("OUTPUT")
    print("=" * 60)

    print("\nGenerator Point:")
    print(G)

    print("\nAlice Private Key:")
    print(alice_private)

    print("\nBob Private Key:")
    print(bob_private)

    print("\nAlice Public Key:")
    print(alice_public)

    print("\nBob Public Key:")
    print(bob_public)

    print("\nShared Key (Alice):")
    print(alice_shared)

    print("\nShared Key (Bob):")
    print(bob_shared)

    print("\nShared Keys Match?")
    print(alice_shared == bob_shared)


# =========================================================
# RUN PROGRAM
# =========================================================
if __name__ == "__main__":
    main()
    
#