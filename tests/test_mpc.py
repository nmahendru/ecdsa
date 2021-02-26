"""
Tests
"""

import pytest
import os
from toyecdsa.ecdsa_threshold import Polynomial, MPCKeyPair, mpc_signing
from toyecdsa.ecdsa_op import order, pub_key_from_priv

import random
import secrets
from hashlib import sha256
from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.ellipticcurve import Point as PointReal


def generate_t_n():
    t = random.randint(1, 14)
    n = random.randint(t+2, 16)
    return t, n


def test_polynomial():
    for _ in range(5):
        t, n = generate_t_n()
        print(f"\nt={t} n={n}")
        assert Polynomial(t, n)


def test_mpc_keypair():
    t, n = generate_t_n()
    print(f"\nt={t} n={n}")
    generate_mpc_keypair(t, n)


def generate_mpc_keypair(t, n):
    poly = [Polynomial(t, n) for _ in range(n)]
    mpc_key = MPCKeyPair(poly, t, n)
    assert mpc_key
    assert mpc_key.pub
    assert len(mpc_key.shards) == n

    # test if the combine pub key is correct
    master_secret = sum([s.secret for s in poly]) % order
    assert mpc_key.pub == pub_key_from_priv(master_secret)
    return mpc_key


@pytest.mark.parametrize("t,n", [(1, 3), (2, 4)])
def test_mpc_signing(t, n):
    keypair = generate_mpc_keypair(t, n)
    mpc_keygen_sign(t, n, keypair)
    mpc_keygen_sign(t, n, keypair, True)


@pytest.mark.skipif(not os.environ.get('SOAK_TEST'), reason="No need to run every time.")
def test_random_threshold_mpc_signing():
    t, n = generate_t_n()
    print(f"Keypair generated with t ={t} and n={n}")
    keypair = generate_mpc_keypair(t, n)
    for _ in range(2):
        mpc_keygen_sign(t, n, keypair, True)


def mpc_keygen_sign(t, n, mpc_keypair, trim=False):
    message_to_sign = secrets.token_bytes(32)
    print(f"bytes to sign: [{message_to_sign.hex().upper()}]")
    # participants = [x+1 for x in range(n)]
    participants = [x+1 for x in range(n)]
    if trim:
        # remove and reduce participants upto t+1
        for _ in range(n-t-1):
            participants.remove(
                participants[random.randint(0, len(participants) - 1)])
    print(f"participants signing = {participants}")
    signature = mpc_signing(mpc_keypair, message_to_sign, participants)
    sig_hex = str(signature)
    print(f"public_key = [{mpc_keypair.pub}] signature = [{sig_hex}]")
    pub = VerifyingKey.from_string(bytes.fromhex(
        str(mpc_keypair.pub)), curve=SECP256k1, hashfunc=sha256)
    pub.verify(bytes.fromhex(sig_hex), message_to_sign)
    pytest.raises(BadSignatureError, pub.verify, bytes.fromhex(
        sig_hex), message_to_sign + b"polysign")
