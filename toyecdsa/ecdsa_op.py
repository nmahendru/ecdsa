"""
ecdsa for secp256k1.
Utilities for:
    1. EC Public Key generation
    2. Signing Using EC Private Key(integer)
    3. EC point addition
    4. EC point inverse.
    5. EC scalar multiplication
    6. Scalar inverse mod order and mod field size.

    Credit to:
    https://stackoverflow.com/questions/31074172/elliptic-curve-point-addition-over-a-finite-field-in-python

    Point addition is implementing:
    https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition

    Signature implementation is just implementing:
    https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

"""

from hashlib  import sha256
import random
from ecdsa import SECP256k1, SigningKey, BadSignatureError
from .toyrand import int_sample

# Create a simple Point class to represent points on the curve
from collections import namedtuple
Point = namedtuple("Point", "x y")

# The point at origin. This means generator * order = O
O = 'Origin'


# SECP256K1 domain params
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
generator = Point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
order=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
#############################

def valid(P):
    """
    wiestrass curve: y^2 = x^3 + ax + b
    Determine whether we have a valid representation of a point
    on our curve.  We assume that the x and y coordinates
    are always reduced modulo p, so that we can compare
    two points for equality with a simple ==.
    """
    if P == O:
        return True
    else:
        return (
            (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and
            0 <= P.x < p and 0 <= P.y < p)


def scalar_inv_mod_p(x):
    """
    Compute an inverse for x modulo p, assuming that x
    is not divisible by p.

    It's only recently that python has added the modular inverse operation.
    It calculates the multiplicative inverse  if exponent is negative and mod is prime
    https://docs.python.org/3/library/functions.html#pow
    """
    if x % p == 0:
        raise ZeroDivisionError("Impossible inverse")
    return pow(x, -1, p)

def scalar_inv_mod_order(x):
    """
    Compute an inverse for x modulo order, assuming that x
    is not divisible by p.

    It's only recently that python has added the modular inverse operation.
    It calculates the multiplicative inverse  if exponent is negative and mod is prime
    https://docs.python.org/3/library/functions.html#pow
    """
    if x % order == 0:
        raise ZeroDivisionError("Impossible inverse")
    return pow(x, -1, order)

def ec_inv(P):
    """
    Inverse of the point P on the elliptic curve y^2 = x^3 + ax + b.
    https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_negation
    """
    if P == O:
        return P

    inv = Point(P.x, (-P.y)%p)
    assert valid(inv)
    return inv

def ec_add(P, Q):
    """
    Sum of the points P and Q on the elliptic curve y^2 = x^3 + ax + b.
    https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
    """
    if not (valid(P) and valid(Q)):
        raise ValueError("Invalid inputs")

    # Deal with the special cases where either P, Q, or P + Q is
    # the origin.
    if P == O:
        result = Q
    elif Q == O:
        result = P
    # optimization as A + A_inv = Infinity point on the curve(Also called point at origin).
    # the calculation below will barf if we try to calculate this as it will give us an invalid point.
    elif Q == ec_inv(P):
        result = O
    else:
        # Cases not involving the origin.
        if P == Q:
            lambdA = (3 * P.x**2 + a) * scalar_inv_mod_p(2 * P.y)
        else:
            lambdA = (Q.y - P.y) * scalar_inv_mod_p(Q.x - P.x)
        x = (lambdA**2 - P.x - Q.x) % p
        y = (lambdA * (P.x - x) - P.y) % p
        result = Point(x, y)

    # The above computations *should* have given us another point
    # on the curve.
    assert valid(result)
    return result

def ec_scalar_mul(P, scalar):
    scalar %= order
    assert valid(P)
    cache = P
    ret = O
    # keep on doubling the generator and only add for binary 1.
    while  scalar:
        if  scalar & 1:
            ret = ec_add(ret, cache)
        cache = ec_add(cache, cache)
        scalar = scalar >> 1
    assert valid(ret)
    return ret

def pub_key_from_priv(private):
    return ec_scalar_mul(generator, private)

class Point(Point):
    def __repr__(self):
        """Uncompressed"""
        return f"04{self.x:0>64X}{self.y:0>64X}"
    def __eq__(self, other):
        if isinstance(self, str) and isinstance(other, str):
            return True
        if isinstance(self, str) or isinstance(other, str):
            return  False


        return self.x == other.x and self.y == other.y
    
def compressed_hex(point) -> str:
    if point.y % 2 == 0:
        return f"02{point.x:0>64X}"
    else:
        return f"03{point.x:0>64X}"


Signature = namedtuple("Signature", "r s")

def ecdsa_sign(private, message):
    """
    Implementing  https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    """
    e = int.from_bytes(sha256(message).digest(), byteorder="big")
    L_n = order.bit_length()
    e_bit_len = e.bit_length()
    print(f"bit lengths order={L_n}, e={e_bit_len}")
    z = e if L_n >= e_bit_len else e >> (e_bit_len - L_n)
    # not a great way to seed the rng
    random.seed()
    r = 0
    k = 0
    R = O
    s = 0
    while s == 0:
        while r == 0:
            k = int_sample(order)
            R = ec_scalar_mul(generator, k)
            r = R.x % order
        s = scalar_inv_mod_order(k) * (z + r*private) % order
    return Signature(r, s)


class Signature(Signature):
    def __repr__(self):
        return f"{self.r:0>64X}{self.s:0>64X}"

    def __eq__(self, other):
        return self.r == other.r and self.s == other.s


