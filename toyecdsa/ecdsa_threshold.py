"""
Toy implementation of ECDSA threshold signatures as described here:
https://eprint.iacr.org/2020/540.pdf
"""



"""
The threshold scheme is based on values t,n
t = minimum number of participants who cannot sign
n = total number of participants.


Keygen for GG20 can be simplified by not trying to prove anything.
Assumptions:
1. If you trust all the participants (Honest player assumption) that they will always do the right thing.
2. All participants will always authenticate all messages from other participants.
Simplified protocol:
1. Each participant creates a polynomial of degree t and sends out yval on that polynomial to all the
    other participants
2. Each participant adds the yval it receives from other participants. In the end all of them have a point
    on a line that no one knows about. If t + 1 participants cooperate then they can sign a message.
"""

import random
from typing import List

from .ecdsa_op import Point, Signature, order, p, O, pub_key_from_priv, ec_add
class Polynomial:
    def __init__(self, t, n):
        self.yval = [0 for _ in range(n)]
        random.seed()

        self.coefficients = [random.randint(0, order-1) for _ in range(t)]
        for i in range(n):

            self.yval[i] =  self.coefficients[-1]
            for j in range(t-2, -1, -1):
                self.yval[i] = (self.yval[i] * (i+1) + self.coefficients[j]) % order
        self.secret = self.coefficients[0]
        self.pub = pub_key_from_priv(self.secret)

class MPCKeyPair:
    def __init__(self, poly: List[List[Polynomial]], t, n):
        self.t = t
        self.n = n
        self.shards = [0] * n
        self.pub = O
        for i in range(n):
            for pp in poly:
                self.shards[i] += pp.yval[i]
            self.shards[i] %= order
            self.pub = ec_add(poly[i].pub, self.pub)
    def __repr__(self):
        contents = [f"public_key [{str(self.pub)}]"]
        for i,v in enumerate(self.shards):
            contents.append(f"shard{i+1}=>[{v:0>64X}]")
        return " ".join(contents)
