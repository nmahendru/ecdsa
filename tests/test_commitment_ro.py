import pytest
import hashlib
import secrets

from toyecdsa.commitment_ro import commit, verify_commitment, blind_length

def test_commitment_scheme():
    value_to_commit = secrets.token_hex(32)
    print(f"value commiting to [{value_to_commit}]")
    C, R = commit(bytes.fromhex(value_to_commit))
    assert verify_commitment(C, R, bytes.fromhex(value_to_commit))
    # should not match commitment for another value.
    another_value = secrets.token_hex(32)
    print(f"another value [{another_value}]")
    assert not verify_commitment(C, R, bytes.fromhex(another_value))