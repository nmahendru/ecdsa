"""
Tests
"""

import pytest
from  toyecdsa.ecdsa_threshold import Polynomial, MPCKeyPair, mpc_signing
from toyecdsa.ecdsa_op import order, pub_key_from_priv

import random
from hashlib import sha256
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.ellipticcurve import Point as PointReal


def test_polynomial():
    for i in range(5):

        t = random.randint(1, 15)
        n = random.randint(t+1,16)
        print(f"\nt={t} n={n}")
        assert Polynomial(t,n)

def test_mpc_keypair():
    for i in range(2):

        t = random.randint(1, 15)
        n = random.randint(t+1,16)
        print(f"\nt={t} n={n}")
        poly = [Polynomial(t, n) for _ in range(n)]
        mpc_key = MPCKeyPair(poly, t, n)
        print(f"keypair\n{str(mpc_key)}")
        assert mpc_key
        assert mpc_key.pub
        assert len(mpc_key.shards) == n

        # test if the combine pub key is correct
        master_secret = sum([s.secret for s in poly]) % order
        assert mpc_key.pub == pub_key_from_priv(master_secret)

def test_mpc_signing():
    t = 1
    n = 3

    poly = [Polynomial(t, n) for _ in range(n)]
    mpc_keypair = MPCKeyPair(poly, t, n)
    message = b"Nitin"
    participants = [1, 2, 3]
    signature  = mpc_signing(mpc_keypair, message, participants)
    sig_hex = str(signature)
    pub = VerifyingKey.from_string(bytes.fromhex(str(mpc_keypair.pub)), curve=SECP256k1, hashfunc=sha256)

    pub.verify(bytes.fromhex(sig_hex), message)
    pytest.raises(BadSignatureError, pub.verify, bytes.fromhex(sig_hex), b"wrongdata")
