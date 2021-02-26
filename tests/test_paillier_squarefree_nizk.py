import pytest

from phe import paillier

from toyecdsa.paillier_squarefree_nizk import i2osp, mgf1, proove, verify

def test_i2osp():
    input_int = int(pow(33,8))
    intended_octet_len = 40

    ret = i2osp(input_int, intended_octet_len)
    assert len(ret) == intended_octet_len


def test_mgf1():
    seed = b"polysign"
    assert len(mgf1(seed, 1000)) == 1000

def test_paillier_square_free():
    _pub, priv = paillier.generate_paillier_keypair()
    proof = proove(priv.p, priv.q)
    N = priv.p * priv.q
    assert verify(proof, N)

    # adding a square in N 
    proof = proove(priv.p * priv.p, priv.q)
    N = priv.p * priv.p * priv.q
    assert not verify(proof, N)

