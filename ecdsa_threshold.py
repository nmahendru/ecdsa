"""
Toy implementation of ECDSA threshold signatures as described here:
https://eprint.iacr.org/2020/540.pdf
"""



"""
The threshold scheme is based on values t,n
t = minimum number of participants who cannot sign
n = total number of participants.


Keygen for GG20 can be simplified but not trying to prove anything.
Simplified protocol:
1. Each participant creates a polynomial of degree t and sends out points on that polynomial to all the
    other participants
2. Each participant adds the points it receives from other participants. In the end all of them have a point
    on a line that no one knows about. If t + 1 participants cooperate then they can sign a message.
"""

import random

from ecdsa_op import Point, Signature
class Polynomial:
    def __init__(self, t, n):
