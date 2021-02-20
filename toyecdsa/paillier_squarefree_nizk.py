"""
Implementation of Section 3.2 of the below: 
https://eprint.iacr.org/2018/057.pdf
"""

from hashlib import sha256
from typing import List

import math


salt = b"polysign"

# below values are from sections 6.2.3
# https://eprint.iacr.org/2018/987.pdf
m = 11
alpha = 6370


def i2osp(x: int, xLen: int) -> bytes:
    """
    https://tools.ietf.org/html/rfc8017#section-4.1
    """
    assert xLen >= 0
    assert x <= pow(256, xLen), "Input integer is too big for the xLen."
    # need to return big endian of the integer left padded with zero bytes.
    return x.to_bytes(xLen, byteorder='big')


def mgf1(seed: bytes, mask_len: int) -> int:
    """
    This implements the below:
    https://tools.ietf.org/html/rfc8017#appendix-B.2.1
    """

    assert mask_len <= pow(2, 32), "Mask Length is too long."
    hlen = 32  # SHA-256
    res = bytearray()
    for i in range(math.ceil(mask_len / hlen)):
        res.extend(sha256(seed + i2osp(i, 4)).digest())
    return res[:mask_len]


def fiat_shamir_seed(public_key_bytes, salt, index, counter):
    return sha256(public_key_bytes + salt + index.to_bytes(4, byteorder='big') + counter.to_bytes((counter.bit_length() + 7)//8, byteorder='big')).digest()

def calc_rho_vec(N, salt, m):
    rho_vec = []
    byte_size_N = math.ceil(N.bit_length()/8)
    counter = 0
    for index in range(m):
        seed = fiat_shamir_seed(N.to_bytes(
            byte_size_N, byteorder='big'), salt, index, counter)
        rho_i = int.from_bytes(mgf1(seed, byte_size_N), byteorder='big') % N
        rho_vec.append(rho_i)

    return rho_vec

def calc_sigma_vec_from_rho_vec(rho_vec, totient, N):
    sigma_vec = []
    N_inv_mod_totient = pow(N, -1, totient)
    for rho in rho_vec:
        sigma_i = pow(rho, N_inv_mod_totient, N)
        sigma_vec.append(sigma_i)
    return sigma_vec

def proove(p: int, q: int) -> List[int]:
    """
    This function will return the Nth roots of random points.
    These can later be verified by verifiers.

    In the actual implementation these points are determinsitic and that
    happens using the Fiat - Shamir transform as described in section 4:
    https://eprint.iacr.org/2018/057.pdf
    """

    assert p != q
    totient = (p-1) * (q-1)
    N = p * q
    return calc_sigma_vec_from_rho_vec(calc_rho_vec(N, salt, m), totient, N)

def check_prime(num: int) -> bool:
    if num <= 1: return False
    if num == 2:
        return True
    elif num % 2:
        return False
    check_num = num // 2
    # start with 3 and skip all even numbers as we have checked for 2.
    for i in range(3, check_num, 2):
        if num % i == 0:
            return False
    return True

def calc_allprimes_under_alpha(alpha: int):
    primes = [2]
    if alpha != 2:
        for i in range(3, alpha+1, 2):
            if check_prime(i):
                primes.append(i)
    return primes

def verify(proof: List[int], N: int) -> bool:
    if not N >= 0: return False
    product_all_primes_less_than_alpha = math.prod(calc_allprimes_under_alpha(alpha))
    # check that N is not divisible by any prime less than alpha
    if not math.gcd(product_all_primes_less_than_alpha, N) == 1:
        return False
    rho_vec = calc_rho_vec(N, salt, m)
    if not len(rho_vec) == len(proof): return False
    for i, num in enumerate(proof):
        if not num >= 0: return False
        if not rho_vec[i] == pow(num, N, N): return False
    return True
        

