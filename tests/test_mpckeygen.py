"""
Tests
"""

import pytest
from  toyecdsa.ecdsa_threshold import Polynomial, MPCKeyPair
from toyecdsa.ecdsa_op import order, pub_key_from_priv
import random


def test_polynomial():
    for i in range(5):

        t = random.randint(1, 15)
        n = random.randint(t+1,16)
        print(f"\nt={t} n={n}")
        assert Polynomial(t,n)

def test_mpc_keypair():
    for i in range(5):

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
