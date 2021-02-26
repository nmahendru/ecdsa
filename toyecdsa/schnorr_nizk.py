"""
This module is an implementation of the Schnorr's NIZK over elliptic curve SECP256k1
Please refer to https://tools.ietf.org/html/rfc8235#section-3.2

"""

from .ecdsa_op import ec_add, ec_scalar_mul, O, order, pub_key_from_priv, generator, valid, compressed_hex
from .toyrand import int_sample
from collections import namedtuple

from hashlib import sha256

import random


SchnorrNIZK = namedtuple('SchnorrNIZK', ['V', 'A', 'r', 'c', 'user_id'])


def proove(secret: int, user_id: bytes=b"DEFAULT") -> SchnorrNIZK:
    """
    Non Interactive zero knowledge proof that the proover knows the secret.
    """
    random.seed()
    temp_ecdsa_private = int_sample(order - 1)
    temp_ecdsa_public = pub_key_from_priv(temp_ecdsa_private)
    V = pub_key_from_priv(secret)
    # calculate challenge use Fiat Shamir Transform.
    challenge = int.from_bytes(sha256(
        bytes.fromhex(compressed_hex(generator)) +
        bytes.fromhex(compressed_hex(V)) +
        bytes.fromhex(compressed_hex(temp_ecdsa_public)) +
        user_id).digest(), byteorder='big')
    r = (secret - temp_ecdsa_private * challenge) % order
    return SchnorrNIZK(V=V, A=temp_ecdsa_public, r=r, c=challenge, user_id=user_id)


def verify(proof: SchnorrNIZK) -> bool:
    """
    Verify the above zero knowledge proof.
    """

    # verify A is valid.
    if not valid(proof.A):
        return False
    # calculate challenge again
    challenge = int.from_bytes(sha256(
        bytes.fromhex(compressed_hex(generator)) +
        bytes.fromhex(compressed_hex(proof.V)) +
        bytes.fromhex(compressed_hex(proof.A)) +
        proof.user_id).digest(), byteorder='big')
    if proof.c != challenge:
        return False
    # verify V = G * [r] + A * [c]
    return proof.V == ec_add(ec_scalar_mul(generator, proof.r), ec_scalar_mul(proof.A, proof.c))