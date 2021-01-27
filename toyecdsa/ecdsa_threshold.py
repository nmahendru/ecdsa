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
import copy
from hashlib import sha256
from phe import paillier

from .ecdsa_op import Point, Signature, order, p, O, pub_key_from_priv, ec_add, scalar_inv_mod_order, ec_scalar_mul
class Polynomial:
    def __init__(self, t, n, index, key_id):
        self.master_wrapping_secret = master_wrapping_secret(index)
        print(f"len of master_wrapping_secret {len(self.master_wrapping_secret)}")
        self.key_id = key_id
        self.yval = [0 for _ in range(n)]

        self.coef = [deterministic_integer(self.master_wrapping_secret + bytes(self.key_id, encoding='utf-8'), i) for i in range(1, t+2)]
        for i in range(1, n+1):
            self.yval[i - 1] = self.coef[-1]
            for j in range(len(self.coef) - 2, -1, -1):
                self.yval[i-1]  = (self.yval[i-1] * i  + self.coef[j] )% order

        self.secret = self.coef[0]
        self.pub = pub_key_from_priv(self.secret)


class MPCKeyPair:
    def __init__(self, poly: List[Polynomial], t, n):
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
        contents = [f"public_key [{str(self.pub)}]\n"]
        row = 1
        for i, v in enumerate(self.shards):
            contents.append(f"shard{i+1}=>[{v:0>64X}]")
            if row % 2 == 0:
                contents.append("\n")
            row += 1
        return " ".join(contents)


def remap_shares(t, n, x, secret_y, participants):
    """
    Calculate the lagrange coefficient lambda_index to remap the share_y
    to w_i.
    If each party participating in signing calculates this coefficient and multiplies
    that by it's share, they all as a group would have generated an additive share of the
    MPC keypair private key.

    Each coefficient  with x = 0 when added up gives us the y intercept which is the master secret.

    For more details refer Page 14 Section 3.2 of GG20 paper.

    Arguments:
    t: Threshold of the scheme. 2-of-3 scheme has threshold 1.
    n: Total number of parties.
    x: x coordinate for the party we are calculating the coefficient for.
    secret_y: parties' shard.
    participants: 1 indexed list of parties involved in signing.

    """
    num = 1
    denom = 1
    participants.sort()
    if max(participants) > n or min(participants) < 1 or len(set(participants)) < t+1:
        raise ValueError("The participants array is incorrect {participants}")
    for i in participants:
        if i != x:
            num = num * i
            denom = denom * (i - x)
    denom_inv = scalar_inv_mod_order(denom)
    lam_iS = (num * denom_inv) % order
    return  lam_iS * secret_y % order


def MTA(a_encrypted, b, det_nonce):
    """
    multiplicative to additive  conversion for two EC scalars
    """
    nonce = int.from_bytes(det_nonce, byteorder="big") % order
    alpha_encrypted, beta = ((a_encrypted * b) + nonce, -1 * nonce)
    return (alpha_encrypted, beta)

def deterministic_k(nonce):
    return deterministic_integer(nonce, 1)

def deterministic_gamma(nonce):
    return deterministic_integer(nonce, 2)

def seq_to_bytes(seq):
    assert 0 < seq < 17
    return seq.to_bytes(4, 'big')

def deterministic_integer(nonce, seq):
    """
    All the ephemeral secrets  that need to be used should be deterministic.
    That will make the signature scheme deterministic.

    Each of the k and gamma if deterministic will make w deterministic.
    """
    return int.from_bytes(sha256(nonce).digest() + seq_to_bytes(seq), byteorder="big")  % order

def master_wrapping_secret(index):
    """
    Generate a wrapping key based on the index. In reality you would never do that.
    Max index is 16 - a random value I chose for tests.

    This secret could be used to encrypt secret values.(AES - 256)
    """
    assert 0 < index < 17
    return bytes(28) + seq_to_bytes(index)

class MPCSigner:
    def __init__(self, mpc_keypair, index, participants, message=b"Nitin"):
        self.master_wrapping_secret = master_wrapping_secret(index)
        self.message = message

        self.keypair = copy.deepcopy(mpc_keypair)
        self.paillier_pub, self.paillier_priv = paillier.generate_paillier_keypair()

        self.gamma_i = deterministic_gamma(self.det_nonce(index))
        self.g_gamma_i = pub_key_from_priv(self.gamma_i)
        self.k_i = deterministic_k(self.det_nonce(index))
        self.index = index
        self.w_i = remap_shares(mpc_keypair.t, mpc_keypair.n,
                                index, mpc_keypair.shards[index - 1], participants)
        self.g_wi = pub_key_from_priv(self.w_i)
        self.alpha_vec = []
        self.beta_vec = []
        self.miu_vec = []
        self.ni_vec = []
        self.delta_i = 0
        self.sigma_i = 0
        self.s_i = 0

    def det_nonce(self, seq):
        assert len(self.master_wrapping_secret) == 32
        assert len(self.message) != 0 and int.from_bytes(self.message, byteorder="big") != 0
        return self.master_wrapping_secret + seq_to_bytes(seq) + sha256(self.message).digest()


def phase1_phase2(signers: List[MPCSigner], participants: List[int]):
    assert len(signers) == len(participants)
    for i, pa in enumerate(participants):
        for j in range(i+1, len(participants)):
            # k_i * gamma_j
            nonce = signers[i].det_nonce(3)
            alpha, beta = MTA(signers[i].paillier_pub.encrypt(signers[i].k_i), signers[j].gamma_i, nonce)
            signers[i].alpha_vec.append(signers[i].paillier_priv.decrypt(alpha))
            signers[j].beta_vec.append(beta)

            nonce = signers[i].det_nonce(4)
            alpha, beta = MTA(signers[j].paillier_pub.encrypt(signers[j].k_i), signers[i].gamma_i, nonce)
            signers[j].alpha_vec.append(signers[j].paillier_priv.decrypt(alpha))
            signers[i].beta_vec.append(beta)

            # k_i * w_j
            nonce = signers[i].det_nonce(5)
            miu, ni = MTA(signers[i].paillier_pub.encrypt(signers[i].k_i), signers[j].w_i, nonce)
            signers[i].miu_vec.append(signers[i].paillier_priv.decrypt(miu))
            signers[j].ni_vec.append(ni)

            nonce = signers[i].det_nonce(6)
            miu, ni = MTA(signers[j].paillier_pub.encrypt(signers[j].k_i), signers[i].w_i, nonce)
            signers[j].miu_vec.append(signers[j].paillier_priv.decrypt(miu))
            signers[i].ni_vec.append(ni)

    # No real need for this but adding asserts as I write it up.
    for i, v in enumerate(signers):
        assert len(v.alpha_vec) == len(participants) - 1
        assert len(v.beta_vec) == len(participants) - 1
        assert len(v.miu_vec) == len(participants) - 1
        assert len(v.ni_vec) == len(participants) - 1
        # calculate delta_i
        signers[i].delta_i = sum(
            [
                signers[i].k_i * signers[i].gamma_i % order,
                sum(signers[i].alpha_vec),
                sum(signers[i].beta_vec)
            ]
        ) % order
        # calculate  sigma_i
        signers[i].sigma_i = sum(
            [
                signers[i].k_i * signers[i].w_i % order,
                sum(signers[i].miu_vec),
                sum(signers[i].ni_vec)
            ]
        ) % order

def calculate_R(delta_inv, g_gamma_i_vec: List[int]):
    g_gamma = g_gamma_i_vec[0]
    for v in g_gamma_i_vec[1:]:
        g_gamma = ec_add(g_gamma, v)
    return ec_scalar_mul(g_gamma, delta_inv)


def phase3_phase4(signers: List[MPCSigner], participants: List[int]):
    """
    This returns r of the signature.
    """
    assert len(signers) == len(participants)
    delta = 0
    for i,v in enumerate(signers):
        delta += v.delta_i
    delta %= order
    delta_inv = scalar_inv_mod_order(delta)
    R = calculate_R(delta_inv, [v.g_gamma_i for v in signers])
    r = R.x % order
    return r

def phase6(r, signers: List[MPCSigner], participants, message: bytes):
    assert len(signers) == len(participants)
    m = int.from_bytes(sha256(message).digest(), byteorder='big')
    s_vec = []
    for i,v in enumerate(signers):
        v.s_i =  (r * v.sigma_i + m * v.k_i ) % order
        s_vec.append(v.s_i)
    s = sum(s_vec) % order
    return Signature(r, s)

def mpc_signing(mpc_keypair, message, participants) -> Signature:
    t = mpc_keypair.t
    n = mpc_keypair.n
    signers = [MPCSigner(mpc_keypair, i + 1, participants) for i in range(n)]
    phase1_phase2(signers, participants)
    r = phase3_phase4(signers, participants)
    return phase6(r, signers, participants, message)
