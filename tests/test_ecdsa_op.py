"""
Tests
"""

import pytest
from hashlib import sha256
from ecdsa import SECP256k1, SigningKey, BadSignatureError
from toyecdsa.ecdsa_op import ec_scalar_mul, ec_scalar_mul, pub_key_from_priv, O, generator, order, ecdsa_sign

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
