"""
Commitment scheme using a hash function(ROM) and fixed length blinding factor.

Please refer to https://eprint.iacr.org/2020/540.pdf section 2.6
"""

import secrets
import hashlib

blind_length = 32

def commit(input: bytes) -> (bytes, bytes):
    r = secrets.token_bytes(blind_length)
    return hashlib.sha3_256(input + r).digest(), r

def verify_commitment(commitment: bytes, r: bytes, input: bytes) -> bool:
    assert len(commitment) > 0
    assert len(r) == blind_length
    assert len(input) > 0
    return hashlib.sha3_256(input + r).digest() == commitment

    