"""
Tests
"""

import pytest
import random
from hashlib import sha256
from ecdsa import SECP256k1, SigningKey, BadSignatureError
from toyecdsa.ecdsa_op import ec_scalar_mul, ec_scalar_mul, pub_key_from_priv, O, generator, order, ecdsa_sign, ec_add

def test_ecdsa():
    # private key as an integer
    secret = 5
    m = b"Nitin"

    # check if order and generator are in sync
    assert O == ec_scalar_mul(generator, order), "Generator seems off"

    sig_hex = str(ecdsa_sign(secret, m))

    pub = pub_key_from_priv(secret)
    assert pub
    print(f"pub key\n{pub_key_from_priv(secret)}\n")
    print(f"signature\n{sig_hex}\n")

    priv = SigningKey.from_secret_exponent(secret, SECP256k1, hashfunc=sha256)
    pub = priv.verifying_key
    pub.verify(bytes.fromhex(sig_hex), m)
    pytest.raises(BadSignatureError, pub.verify, bytes.fromhex(sig_hex), b"wrongdata")

def test_point_addition():
    secret1 = random.randint(0, order - 1)
    secret2 = random.randint(0, order - 1)
    pub1 = pub_key_from_priv(secret1)
    pub2 = pub_key_from_priv(secret2)
    master_secret = (secret1 + secret2) % order
    assert ec_add(pub1, pub2)  == pub_key_from_priv(master_secret)


