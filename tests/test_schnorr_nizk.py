from toyecdsa.schnorr_nizk import SchnorrNIZK, proove, verify
from toyecdsa.ecdsa_op import order

import random


def test_schnorr_nizk_proof():
    secret = random.randint(0, order-1)    
    proof = proove(secret)
    assert verify(proof)
    bad_proof = SchnorrNIZK(A=proof.A, V=proof.V, c=proof.c, r=proof.r, user_id=b"WRONG")
    assert not verify(bad_proof)