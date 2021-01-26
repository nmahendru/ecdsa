# ecdsa_op
toy implementation of ecdsa in pure python

# threshold_ecdsa
toy implementation of Threshold ecdsa in pure python. It's based on this paper [GG20](https://eprint.iacr.org/2020/540.pdf)

There are basic tests with the APIs.

In no manner is this production ready. *So please only look at this at your own risk*.



# Reasoning on why simplification of GG20 should work.
1. ZK proofs and range proofs are necessary to point out the malicious adversary.
    But if all you want is for the signature to not checkout in the end and restart the signature
    generation process then it's not needed.
2. VSS can be added but adds no big value under the above assumption.

# Trying it.
This library is really not written to be shipped and used.(At least at the moment).
As the package name suggests, it's a "toy" implementation.

But in case you would like to see it in action:
1. $pip install pytest ecdsa phe 
2. $pytest

The pytest command should run all the tests. test_mpc_signing actually generates a usable signature.

