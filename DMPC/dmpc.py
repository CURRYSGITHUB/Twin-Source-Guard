#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
D-SMPC
- Algorithm 1 (dynamic CP selection / identity confirmation):
  token_i = Encrypt(VID_i, Cpk), Sign_i = Sign(VID_i, Vski),
  Cloud verifies then returns Encrypt(i, Vpki).
- Algorithm 2 (encrypted secret sharing + SMPC):
  DP splits data by Shamir; for each CP index i, encrypt share_{n,i} with ComVpk[i];
  CP decrypts shares and computes intermediate [result]_i; upload Encrypt([result]_i, Cpk).
"""

import json
import time
import math
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime

# ────────── Parameters (paper: n, t, ComVpk, Cpk) ──────────
DATA_COUNT = 20          # number of DPs
COMP_COUNT = 5           # number of candidate CPs
THRESHOLD  = 3           # t (1 < t <= #selected CPs)

CURVE_NAME = "P-256"     # used for Algorithm 1 auth + ECIES-like payload encryption
LOG_FILE = Path("d_smpc_protocol_flow.log")

VID_LEN    = 4           # fixed encoding for VID
IDX_LEN    = 2           # fixed encoding for CP index i
SHARE_LEN  = 32          # numeric share bytes (for Z_q where q ~ 256-bit here)
PT_LEN     = 33          # SEC1 compressed point length for P-256
NONCE_LEN  = 12          # AES-GCM nonce length
TAG_LEN    = 16          # AES-GCM tag length

# ────────── JSONL logger (communication bytes + compute durations) ──────────
logger = logging.getLogger("D_SMPC")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(message)s")
console = logging.StreamHandler(); console.setFormatter(fmt)
file_hdl = logging.FileHandler(LOG_FILE, "w", encoding="utf-8"); file_hdl.setFormatter(fmt)
logger.handlers.clear()
logger.addHandler(console)
logger.addHandler(file_hdl)

def jlog(*, src: str = "", dst: str = "", bytes_: int = 0,
         phase: Optional[str] = None, duration: Optional[float] = None):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "src": src,
        "dst": dst,
        "bytes": int(bytes_),
    }
    if phase is not None:
        entry["phase"] = phase
    if duration is not None:
        entry["duration"] = float(duration)
    logger.info(json.dumps(entry, ensure_ascii=False))

def i2b_fixed(x: int, n: int) -> bytes:
    return int(x).to_bytes(n, "big", signed=False)

# ────────── Z_q for Shamir (use P-256 group order as q) ──────────
_curve = ECC._curves[CURVE_NAME]
G_ec = _curve.G
Q = int(_curve.order)  # field modulus for Shamir/MPC arithmetic (Z_q)

# ────────── EC point (compressed) for ECIES-like transport ──────────
Pp = int(_curve.p)
Bb = int(_curve.b)
Aa = (Pp - 3) % Pp

def point_to_bytes(Pt) -> bytes:
    if Pt.is_point_at_infinity():
        return b"\x00" * PT_LEN
    x = int(Pt.x)
    y = int(Pt.y)
    prefix = 2 + (y & 1)
    return bytes([prefix]) + i2b_fixed(x, PT_LEN - 1)

def bytes_to_point(buf: bytes):
    if len(buf) != PT_LEN:
        raise ValueError("bad point length")
    if buf == b"\x00" * PT_LEN:
        return G_ec * 0
    prefix = buf[0]
    if prefix not in (2, 3):
        raise ValueError("bad point prefix")
    x = int.from_bytes(buf[1:], "big")
    rhs = (pow(x, 3, Pp) + (Aa * x) + Bb) % Pp
    y = pow(rhs, (Pp + 1) // 4, Pp)  # P-256: p % 4 == 3
    if (y & 1) != (prefix & 1):
        y = Pp - y
    return ECC.EccPoint(x, y, curve=CURVE_NAME)

def kdf_sha256(shared_x: int, context: bytes = b"") -> bytes:
    return SHA256.new(i2b_fixed(shared_x, 32) + context).digest()

# ────────── ECIES-like PKE for Algorithm 1 token and for numeric shares/results ──────────
def ecies_encrypt(recipient_pub_point, plaintext: bytes, aad: bytes = b"") -> bytes:
    r = secrets.randbelow(Q - 1) + 1
    R = G_ec * r
    S = recipient_pub_point * r
    key = kdf_sha256(int(S.x), context=b"ECIESv1")
    nonce = secrets.token_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return point_to_bytes(R) + nonce + ct + tag

def ecies_decrypt(recipient_priv_d: int, ciphertext: bytes, aad: bytes = b"") -> bytes:
    if len(ciphertext) < (PT_LEN + NONCE_LEN + TAG_LEN):
        raise ValueError("ciphertext too short")
    Rb = ciphertext[:PT_LEN]
    nonce = ciphertext[PT_LEN:PT_LEN + NONCE_LEN]
    tag = ciphertext[-TAG_LEN:]
    ct = ciphertext[PT_LEN + NONCE_LEN:-TAG_LEN]
    R = bytes_to_point(Rb)
    S = R * int(recipient_priv_d)
    key = kdf_sha256(int(S.x), context=b"ECIESv1")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)

# ────────── PVSS public parameters (paper Eq.(3)(4): mod p with generators g, h) ──────────
# We generate a prime p at runtime for demonstration; g and h are public.
PVSS_P = getPrime(1024)           # p (prime modulus)
PVSS_G = 2                        # g
# h = g^alpha mod p, alpha random (public)
_alpha = secrets.randbelow(PVSS_P - 3) + 2
PVSS_H = pow(PVSS_G, _alpha, PVSS_P)
PVSS_LEN = (PVSS_P.bit_length() + 7) // 8  # bytes to encode E/C

def pvss_commit(share: int, r: int) -> int:
    # C = g^{share} * h^{r} mod p   (paper Eq.(3))
    return (pow(PVSS_G, share, PVSS_P) * pow(PVSS_H, r, PVSS_P)) % PVSS_P

def pvss_encrypt(pk: int, share: int) -> int:
    # E = pk^{share} mod p          (paper Eq.(3))
    return pow(pk, share, PVSS_P)

def pvss_decrypt_to_D(E: int, sk_inv: int) -> int:
    # D = E^{sk^{-1}} = g^{share}   (paper Eq.(4))
    return pow(E, sk_inv, PVSS_P)

def pvss_verify(C: int, D: int, r: int) -> bool:
    # verify C == D * h^{r} mod p   (paper Eq.(4))
    return C % PVSS_P == (D * pow(PVSS_H, r, PVSS_P)) % PVSS_P

# ────────── Shamir sharing in Z_q (paper Eq.(1)(2) for SSS) ──────────
def eval_poly(coeffs: List[int], x: int) -> int:
    acc = 0
    for a in reversed(coeffs):
        acc = (acc * x + a) % Q
    return acc

def lagrange_zero(xs: List[int], ys: List[int]) -> int:
    res = 0
    for i, xi in enumerate(xs):
        num = 1
        den = 1
        for xj in xs:
            if xj != xi:
                num = (num * (-xj)) % Q
                den = (den * (xi - xj)) % Q
        res = (res + ys[i] * num * pow(den, -1, Q)) % Q
    return res

# ────────── Messages (Algorithm 1) ──────────
@dataclass
class AuthRequest:
    vid: int
    token: bytes
    nonce: bytes
    ts: int
    sig: bytes

@dataclass
class AuthResponse:
    enc_index: bytes

# ────────── Entities ──────────
class CloudServer:
    """Algorithm 1: Cloud holds (Cpk,Csk), verifies token/sign, returns Enc(i, Vpki)."""
    def __init__(self, capacity: int):
        self.key = ECC.generate(curve=CURVE_NAME)  # (Cpk, Csk)
        self.capacity = capacity
        self.registry: Dict[int, ECC.EccKey] = {}  # VID -> Vpki (auth key)
        self.cp_list: Dict[int, int] = {}          # i -> VID

    @property
    def pub_point(self):
        return self.key.public_key().pointQ

    @property
    def priv_d(self):
        return int(self.key.d)

    def register_cp(self, vid: int, pubkey: ECC.EccKey):
        self.registry[vid] = pubkey

    def verify_one(self, req: AuthRequest, task_id: bytes) -> Tuple[bool, Optional[int]]:
        # token = Enc(VID, Cpk)  (Algorithm 1)
        try:
            vid_bytes = ecies_decrypt(self.priv_d, req.token, aad=task_id)
        except Exception:
            return (False, None)

        recovered_vid = int.from_bytes(vid_bytes, "big")
        if recovered_vid != req.vid:
            return (False, None)

        # Verify Sign(task_id||VID||nonce||ts, Vsk)  (Algorithm 1)
        pubkey = self.registry.get(recovered_vid)
        if pubkey is None:
            return (False, None)
        msg = task_id + vid_bytes + req.nonce + i2b_fixed(req.ts, 8)
        verifier = DSS.new(pubkey, "fips-186-3")
        try:
            verifier.verify(SHA256.new(msg), req.sig)
        except ValueError:
            return (False, None)

        # select CP index i if capacity allows
        if len(self.cp_list) >= self.capacity:
            return (True, None)
        assigned = len(self.cp_list) + 1
        self.cp_list[assigned] = recovered_vid
        return (True, assigned)

    def build_response(self, vid: int, index_i: int, task_id: bytes) -> AuthResponse:
        pubkey = self.registry[vid]
        enc = ecies_encrypt(pubkey.pointQ, i2b_fixed(index_i, IDX_LEN), aad=task_id)
        return AuthResponse(enc_index=enc)

class ComputeParty:
    """
    CP has:
    - ECC keypair for Algorithm 1 auth + ECIES-like decryption of numeric shares
    - PVSS keypair (pk=g^{sk} mod p) for Eq.(3)(4) checks
    """
    def __init__(self, vid: int):
        self.vid = vid
        self.key = ECC.generate(curve=CURVE_NAME)          # (Vpki, Vski) for Algorithm 1
        self.index_i: Optional[int] = None
        self.sum_share: int = 0                            # [result]_i for Func=sum

        # PVSS keys: pk = g^sk mod p, and sk_inv = sk^{-1} mod (p-1) (paper Eq.(4))
        self.pvss_sk = self._sample_pvss_sk()
        self.pvss_pk = pow(PVSS_G, self.pvss_sk, PVSS_P)
        self.pvss_sk_inv = pow(self.pvss_sk, -1, PVSS_P - 1)

    def _sample_pvss_sk(self) -> int:
        while True:
            sk = secrets.randbelow(PVSS_P - 2) + 2
            if math.gcd(sk, PVSS_P - 1) == 1:
                return sk

    @property
    def pubkey(self):
        return self.key.public_key()

    @property
    def pub_point(self):
        return self.key.public_key().pointQ

    @property
    def priv_d(self):
        return int(self.key.d)

    def make_auth_request(self, cloud_pub_point, task_id: bytes) -> AuthRequest:
        nonce = secrets.token_bytes(16)
        ts = int(time.time())
        vid_bytes = i2b_fixed(self.vid, VID_LEN)
        token = ecies_encrypt(cloud_pub_point, vid_bytes, aad=task_id)
        msg = task_id + vid_bytes + nonce + i2b_fixed(ts, 8)
        sig = DSS.new(self.key, "fips-186-3").sign(SHA256.new(msg))
        return AuthRequest(vid=self.vid, token=token, nonce=nonce, ts=ts, sig=sig)

    def recv_auth_response(self, resp: AuthResponse, task_id: bytes):
        idx_bytes = ecies_decrypt(self.priv_d, resp.enc_index, aad=task_id)
        self.index_i = int.from_bytes(idx_bytes, "big")

    def recv_share_packet(self,
                          enc_share_scalar: bytes,
                          pvss_E: int,
                          pvss_C: int,
                          pvss_r: int,
                          task_id: bytes):
        """
        Algorithm 2 (CP side) + PVSS Eq.(3)(4):
        - decrypt numeric share_{n,i} (for MPC in Z_q)
        - PVSS check:
          D = E^{sk^{-1}} should equal g^{share}
          C should equal D * h^{r}
        """
        if self.index_i is None:
            raise RuntimeError(f"CP VID={self.vid} not selected")

        # decrypt numeric share_{n,i} (Algorithm 2)
        y = int.from_bytes(ecies_decrypt(self.priv_d, enc_share_scalar, aad=task_id), "big") % Q

        # PVSS decrypt to D (paper Eq.(4))
        D_from_E = pvss_decrypt_to_D(pvss_E, self.pvss_sk_inv)

        # bind PVSS D to numeric y: g^{y} must match
        D_from_y = pow(PVSS_G, y, PVSS_P)
        if D_from_E != D_from_y:
            raise ValueError(f"PVSS binding failed (VID={self.vid}, i={self.index_i})")

        # verify commitment (paper Eq.(4))
        if not pvss_verify(pvss_C, D_from_E, pvss_r):
            raise ValueError(f"PVSS verify failed (VID={self.vid}, i={self.index_i})")

        # local MPC for Func=sum (Algorithm 2)
        self.sum_share = (self.sum_share + y) % Q

    def send_result_to_edge(self, cloud_pub_point, task_id: bytes) -> Tuple[bytes, bytes]:
        # send Encrypt([result]_i, Cpk) to Edge (Algorithm 2)
        if self.index_i is None:
            raise RuntimeError(f"CP VID={self.vid} not selected")
        idx_plain = i2b_fixed(self.index_i, IDX_LEN)
        enc_res = ecies_encrypt(cloud_pub_point, i2b_fixed(self.sum_share, SHARE_LEN), aad=task_id)
        return idx_plain, enc_res

class DataProvider:
    """Algorithm 2 (DP side) + PVSS attachment (Eq.(3))."""
    def __init__(self, did: int, secret: int):
        self.did = did
        self.secret = secret

    def distribute_once(self,
                        threshold: int,
                        cp_ecc_pub_by_index: Dict[int, ECC.EccKey],
                        cp_pvss_pk_by_index: Dict[int, int],
                        task_id: bytes):
        """
        For each DP:
        - Shamir split in Z_q: share_{n,i} = f(i)
        - Encrypt share_{n,i} with ComVpk[i] (Algorithm 2)
        - Attach PVSS tuple (E,C,r) as in Eq.(3):
            E = pk_i^{share} mod p
            C = g^{share} h^{r} mod p
        """
        coeffs = [self.secret % Q] + [secrets.randbelow(Q) for _ in range(threshold - 1)]

        packets: Dict[int, Tuple[bytes, int, int, int]] = {}
        for idx_i, ecc_pub in cp_ecc_pub_by_index.items():
            y = eval_poly(coeffs, idx_i)

            # Algorithm 2: Eshare_{n,i} = Encrypt(share_{n,i}, ComVpk[i])
            enc_share = ecies_encrypt(ecc_pub.pointQ, i2b_fixed(y, SHARE_LEN), aad=task_id)

            # PVSS Eq.(3): build (E, C, r)
            r = secrets.randbelow(PVSS_P - 1)
            pk_pvss = cp_pvss_pk_by_index[idx_i]
            E = pvss_encrypt(pk_pvss, y)
            C = pvss_commit(y, r)

            packets[idx_i] = (enc_share, E, C, r)

        return packets

class EdgeAggregator:
    """Algorithm 2: decrypt Encrypt([result]_i,Cpk) and reconstruct by Lagrange (t shares)."""
    def __init__(self, cloud_priv_d: int):
        self.cloud_priv_d = cloud_priv_d

    def reconstruct_sum(self, xs: List[int], enc_results: List[bytes], task_id: bytes) -> int:
        ys = []
        for enc in enc_results:
            yb = ecies_decrypt(self.cloud_priv_d, enc, aad=task_id)
            ys.append(int.from_bytes(yb, "big") % Q)
        return lagrange_zero(xs, ys)

# ────────── Main flow: Algorithm 1 -> Algorithm 2 -> reconstruct ──────────
def main():
    if not (1 < THRESHOLD <= COMP_COUNT):
        raise ValueError("Need 1 < THRESHOLD <= COMP_COUNT")

    cloud = CloudServer(capacity=COMP_COUNT)
    edge = EdgeAggregator(cloud_priv_d=cloud.priv_d)
    task_id = secrets.token_bytes(16)

    # CP candidates and registration (paper: Vpki known to cloud for Verify)
    cps = [ComputeParty(vid=i + 1) for i in range(COMP_COUNT)]
    for cp in cps:
        cloud.register_cp(cp.vid, cp.pubkey)

    # Algorithm 1: Cloud publishes Cpk (comm only)
    for cp in cps:
        jlog(src="Cloud", dst=f"CP(VID={cp.vid})", bytes_=PT_LEN)

    # Algorithm 1: CP uploads token/sign (comm only)
    requests: List[AuthRequest] = []
    for cp in cps:
        req = cp.make_auth_request(cloud.pub_point, task_id)
        requests.append(req)
        jlog(src=f"CP(VID={cp.vid})", dst="Cloud",
             bytes_=len(req.token) + len(req.nonce) + 8 + len(req.sig))

    # Algorithm 1: Cloud verifies (compute only) and returns Enc(i, Vpki) (comm only)
    verify_times: List[float] = []
    for cp, req in zip(cps, requests):
        t1 = time.perf_counter()
        ok, idx = cloud.verify_one(req, task_id)
        verify_times.append(time.perf_counter() - t1)
        if not ok:
            raise RuntimeError(f"Auth failed for VID={cp.vid}")
        if idx is not None:
            resp = cloud.build_response(cp.vid, idx, task_id)
            jlog(src="Cloud", dst=f"CP(VID={cp.vid})", bytes_=len(resp.enc_index))
            cp.recv_auth_response(resp, task_id)

    avg_verify_one = (sum(verify_times) / len(verify_times)) if verify_times else 0.0
    jlog(phase="party_auth_verify_one", duration=round(avg_verify_one, 6))

    selected = [cp for cp in cps if cp.index_i is not None]
    if len(selected) < THRESHOLD:
        raise RuntimeError("Not enough selected CPs to satisfy THRESHOLD")

    # DP secrets
    dp_secrets = [secrets.randbelow(100) for _ in range(DATA_COUNT)]
    logger.info(f"[Raw data] {DATA_COUNT} DP secrets: {dp_secrets}\n")
    dps = [DataProvider(did=i + 1, secret=dp_secrets[i]) for i in range(DATA_COUNT)]

    # Service assignment (implicit): build ComVpk[i] for Algorithm 2
    cp_ecc_pub_by_index: Dict[int, ECC.EccKey] = {cp.index_i: cp.pubkey for cp in selected}  # type: ignore
    cp_pvss_pk_by_index: Dict[int, int] = {cp.index_i: cp.pvss_pk for cp in selected}        # type: ignore

    # Algorithm 2 (DP side): split + Encrypt(share, ComVpk[i]) + attach PVSS (E,C,r)
    comp_time_dp = 0.0
    distributions: List[Dict[int, Tuple[bytes, int, int, int]]] = []

    for dp in dps:
        t1 = time.perf_counter()
        packets = dp.distribute_once(THRESHOLD, cp_ecc_pub_by_index, cp_pvss_pk_by_index, task_id)
        comp_time_dp += (time.perf_counter() - t1)
        distributions.append(packets)

        # DP -> CP communication bytes:
        # numeric share ciphertext + PVSS(E,C,r) attachment (Eq.(3))
        for cp in selected:
            enc_share, E, C, r = packets[cp.index_i]  # type: ignore
            bytes_ = len(enc_share) + PVSS_LEN + PVSS_LEN + SHARE_LEN  # E + C + r(32B)
            jlog(src=f"DP{dp.did}", dst=f"CP(i={cp.index_i})", bytes_=bytes_)

    jlog(phase="share_encrypt_pvss_attach_done", duration=round(comp_time_dp, 6))

    # Algorithm 2 (CP side): decrypt share + PVSS verify (Eq.(4)) + local MPC compute
    comp_time_cp = 0.0
    for packets in distributions:
        for cp in selected:
            enc_share, E, C, r = packets[cp.index_i]  # type: ignore
            t1 = time.perf_counter()
            cp.recv_share_packet(enc_share, E, C, r, task_id)
            comp_time_cp += (time.perf_counter() - t1)

    jlog(phase="cp_decrypt_pvss_verify_local_compute_done", duration=round(comp_time_cp, 6))

    # Algorithm 2: CP -> Edge: Encrypt([result]_i, Cpk) (comm only)
    enc_results: List[bytes] = []
    xs: List[int] = []
    for cp in selected[:THRESHOLD]:
        idx_plain, enc_res = cp.send_result_to_edge(cloud.pub_point, task_id)
        jlog(src=f"CP(i={cp.index_i})", dst="Edge", bytes_=len(idx_plain) + len(enc_res))
        xs.append(int.from_bytes(idx_plain, "big"))
        enc_results.append(enc_res)

    # Edge reconstruct (compute only)
    t1 = time.perf_counter()
    sum_secret = edge.reconstruct_sum(xs, enc_results, task_id)
    comp_time_recon = time.perf_counter() - t1
    jlog(phase="edge_reconstruct_done", duration=round(comp_time_recon, 6))

    # Output (this demo uses small secrets so no modular wrap in practice)
    sum_plain = sum(dp_secrets)
    avg_plain = sum_plain / DATA_COUNT
    avg_mpc = sum_secret / DATA_COUNT

    print("\n======= D-SMPC Results =======")
    print(f"Expected sum        : {sum_plain}")
    print(f"MPC recovered sum   : {sum_secret}")
    print(f"Expected average    : {avg_plain:.3f}")
    print(f"MPC recovered avg   : {avg_mpc:.3f}")
    print(f"\nLog written to {LOG_FILE.resolve()}")

    if sum_secret != sum_plain:
        raise AssertionError("Reconstruction mismatch: protocol run failed")

if __name__ == "__main__":
    main()
