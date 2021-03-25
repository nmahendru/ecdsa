"""
Toy implementation of ECDSA threshold signatures as described here:
https://eprint.iacr.org/2020/540.pdf
"""


"""
The threshold scheme is based on values t,n
t = minimum number of participants who cannot sign
n = total number of participants.

"""




import random
import secrets
from typing import List
import copy
from hashlib import sha256
from phe import paillier
from .ecdsa_op import Point, Signature, order, p, O, pub_key_from_priv, ec_add, scalar_inv_mod_order, ec_scalar_mul
from .schnorr_nizk import proove, verify
from .paillier_squarefree_nizk import proove as squarefree_proof
from .paillier_squarefree_nizk import verify as squarefree_verify
from .toyrand import int_sample
from .commitment_ro import commit, verify_commitment

class Polynomial:
    def __init__(self, t, n):
        # y coordinates to be stored in this list.
        self.yval = [0 for _ in range(n)]
        random.seed()
        # the coefficients chosen below represent the polynomial
        self.coef = [int_sample(order) for _ in range(t+1)]
        # below loop solves for x = 1, 2, 3.... and obtains the y value. 
        # For example let the polynomial be y = ax^2 + bx + c
        # self.coef = [c, b, a]
        # This can be evaulated in degree number of steps. degree is 2 so two steps:
        # step 0(initialize):
        #   y = self.coef[-1] = a
        # step 1(multiply with x and add next coef):
        #   y = a*(x) + b
        # step 2(multiply with x and add next coef):
        #   y = (a*(x) + b) * (x) + c
        # the loop var i represents x.
        for i in range(1, n+1):
            self.yval[i - 1] = self.coef[-1]
            for j in range(len(self.coef) - 2, -1, -1):
                self.yval[i-1] = (self.yval[i-1] * i + self.coef[j]) % order

        self.secret = self.coef[0]
        self.pub = pub_key_from_priv(self.secret)
        # each party will publish the public points for the coefficients of their secret polynomial
        self.vss = [pub_key_from_priv(x) for x in self.coef]


class MPCKeyPair:
    def __init__(self, poly: List[Polynomial], t, n):
        self.t = t
        self.n = n
        self.shards = [0] * n
        self.pub = O
        self.proof_ni_x_i = []
        self.paillier = [paillier.generate_paillier_keypair()
                         for _ in range(n)]
        self.paillier_proof = [squarefree_proof(
            x[1].p, x[1].q) for x in self.paillier]
        for i in range(n):
            for pp in poly:
                self.shards[i] += pp.yval[i]
            self.shards[i] %= order
            assert pub_key_from_priv(
                self.shards[i]) == self.calc_vss_proof(i+1, poly)
            self.pub = ec_add(poly[i].pub, self.pub)
            self.proof_ni_x_i.append(proove(self.shards[i]))
            # In a real implementation all the other parties would verify this proof for this i.
            assert verify(self.proof_ni_x_i[-1])
            assert squarefree_verify(
                self.paillier_proof[i], self.paillier[i][0].n)

    def calc_vss_proof(self, player, poly: List[Polynomial]):
        """
        Calculate the right side of the vss equation in section 2.8 in https://eprint.iacr.org/2020/540.pdf
        """
        start = 0
        final_point = O
        for p in poly:
            start = 0
            for v in p.vss:
                final_point = ec_add(ec_scalar_mul(
                    v, pow(player, start)), final_point)
                start += 1
        return final_point

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
    return lam_iS * secret_y % order


def MTA(a_encrypted, b):
    """
    multiplicative to additive  conversion for two EC scalars
    """
    nonce = int_sample(order)
    alpha_encrypted, beta = ((a_encrypted * b) + nonce, -1 * nonce)
    B = pub_key_from_priv(b)
    B_prime = pub_key_from_priv(nonce)
    B_proof = proove(b)
    B_prime_proof = proove(nonce)
    # return (alpha_encrypted, beta, B, B_prime, B_proof, B_prime_proof)
    return (alpha_encrypted, beta, B, B_prime, B_proof, B_prime_proof)


class MPCSigner:
    def __init__(self, mpc_keypair, index, participants):
        self.keypair = copy.deepcopy(mpc_keypair)
        assert index in participants
        self.paillier_pub, self.paillier_priv = mpc_keypair.paillier[index-1]
        self.gamma_i = int_sample(order)
        self.g_gamma_i = pub_key_from_priv(self.gamma_i)
        self.g_gamma_i_commit = commit(bytes.fromhex(str(self.g_gamma_i)))
        self.k_i = int_sample(order)
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
        self.commitments = []

def mta_proof_check(B, B_prime, B_proof, B_prime_proof, alpha, a):
        # alice verifies Bob's Proof. Please refer to section 5 in:
        # https://eprint.iacr.org/2019/114.pdf
        assert pub_key_from_priv(alpha) == ec_add(
            ec_scalar_mul(B, a), B_prime)
        verify(B_proof)
        verify(B_prime_proof)

def phase1_phase2(signers: List[MPCSigner], participants: List[int]):
    assert len(signers) == len(participants)
    # gather commitments for g_gamma_i from other signers.
    # these values need to be verified later in beginning of phase 4
    for i, v in enumerate(participants):
        for j, _ in enumerate(participants):
            if j != i:
                signers[i].commitments.append(signers[j].g_gamma_i_commit[0]) 
    for i, _ in enumerate(participants):
        for j in range(i+1, len(participants)):
            # k_i * gamma_j
            alpha_enc, beta, B, B_prime, B_proof, B_prime_proof = MTA(
                signers[i].paillier_pub.encrypt(signers[i].k_i), signers[j].gamma_i)
            alpha = signers[i].paillier_priv.decrypt(alpha_enc)
            mta_proof_check(B, B_prime, B_proof, B_prime_proof, alpha, signers[i].k_i)
            signers[i].alpha_vec.append(alpha)
            signers[j].beta_vec.append(beta)

            alpha_enc, beta, B, B_prime, B_proof, B_prime_proof = MTA(signers[j].paillier_pub.encrypt(
                signers[j].k_i), signers[i].gamma_i)
            alpha = signers[j].paillier_priv.decrypt(alpha_enc)
            mta_proof_check(B, B_prime, B_proof, B_prime_proof, alpha, signers[j].k_i)
            signers[j].alpha_vec.append(alpha)
            signers[i].beta_vec.append(beta)

            # k_i * w_j
            miu_enc, ni, B, B_prime, B_proof, B_prime_proof = MTA(signers[i].paillier_pub.encrypt(
                signers[i].k_i), signers[j].w_i)
            miu = signers[i].paillier_priv.decrypt(miu_enc)
            mta_proof_check(B, B_prime, B_proof, B_prime_proof, miu, signers[i].k_i)
            signers[i].miu_vec.append(miu)
            signers[j].ni_vec.append(ni)

            miu_enc, ni, B, B_prime, B_proof, B_prime_proof = MTA(signers[j].paillier_pub.encrypt(
                signers[j].k_i), signers[i].w_i)
            miu = signers[j].paillier_priv.decrypt(miu_enc)
            mta_proof_check(B, B_prime, B_proof, B_prime_proof, miu, signers[j].k_i)
            signers[j].miu_vec.append(miu)
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
    # verify commitments shipped out in phase 1.
    for i, v in enumerate(participants):
        k = 0
        # each participant verifies the commitment from other participants.
        # only if these commitments verify can we proceed.
        for j, _ in enumerate(participants):
            if j != i:
                r = signers[j].g_gamma_i_commit[1]
                bytes_g_gamma = bytes.fromhex(str(signers[j].g_gamma_i))
                assert verify_commitment(signers[i].commitments[k], r, bytes_g_gamma)
                k += 1

    delta = 0
    for i, v in enumerate(signers):
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
    for _, v in enumerate(signers):
        v.s_i = (r * v.sigma_i + m * v.k_i) % order
        s_vec.append(v.s_i)
    s = sum(s_vec) % order
    return Signature(r, s)


def mpc_signing(mpc_keypair, message, participants) -> Signature:
    signers = []
    for index in participants:
        signers.append(MPCSigner(mpc_keypair, index, participants))
    phase1_phase2(signers, participants)
    r = phase3_phase4(signers, participants)
    return phase6(r, signers, participants, message)
