"""
Tests
"""

import pytest
from  toyecdsa.ecdsa_threshold import Polynomial, MPCKeyPair
import random


def test_polynomial():
    for i in range(5):

        t = random.randint(1, 15)
        n = random.randint(t+1,16)
        print(f"t={t} n={n}")
        assert Polynomial(t,n)

def test_mpc_keypair():
    for i in range(5):

        t = random.randint(1, 15)
        n = random.randint(t+1,16)
        print(f"t={t} n={n}")
        poly = [Polynomial(t, n) for _ in range(n)]
        mpc_key = MPCKeyPair(poly, t, n)
        print(f"keypair\n{str(mpc_key)}\n")
        assert mpc_key
        assert mpc_key.pub
        assert len(mpc_key.shards) == n
