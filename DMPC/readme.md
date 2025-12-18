# D-SMPC Prototype (Core Protocol)

This repository provides a protocol prototype of the D-SMPC scheme described in the paper. It aligns with the paper’s Algorithm 1 / Algorithm 2 / threshold reconstruction.

---

## Demonstrates

* **Dynamic Computing Party (CP) selection / identity confirmation** (Paper Algorithm 1)
* **Encrypted secret sharing** from Data Providers (DPs) to CPs (Paper Algorithm 2)
* **Local computation at CPs** and **encrypted result upload** to the Edge (Paper Algorithm 2)
* **Threshold reconstruction** at the Edge using `t` CP contributions
* **PVSS attachment + verification**

The demo instantiates `Func` as **sum / average** over DP secrets.

---

## Protocol mapping to the paper

### 1) Algorithm 1 — Dynamic CP selection

1. Cloud publishes **task** and **Cpk** (Cloud public key).
2. Each CP sends:

   * `token = Enc_Cpk(VID)`
   * `Sign(...)` (signature binds at least `VID`; the prototype additionally binds `task_id || nonce || ts` for replay resistance)
3. Cloud verifies `(token, signature, Vpk)` and, if accepted, returns:

   * `Enc_Vpki(i)` where `i` is the assigned CP index/order

### 2) Algorithm 2 — Encrypted secret sharing + SMPC + feedback

1. Each DP creates a Shamir polynomial `f(x)` (threshold `t`) and computes:

   * `share_{n,i} = f(i)` in field `Z_q`
2. DP encrypts the share **per recipient**:

   * `Eshare_{n,i} = Enc_{ComVpk[i]}(share_{n,i})`
3. Each CP decrypts its shares and computes local intermediate result:

   * for this prototype: local sum-share accumulation for `Func = sum`
4. Each CP uploads:

   * `Enc_Cpk([result]_i)` to the Edge
5. Edge decrypts and reconstructs final result from `t` CP results.


---

## Requirements

* Python 3.9+
* Dependency: `pycryptodome`

Install:

* `pip install pycryptodome`

---

## Run

* `python d_smpc.py`

---

## Outputs

### Console

* Plaintext total/average of DP secrets
* Reconstructed total/average from D-SMPC (should match)

### Log file (JSON Lines)

* File: `d_smpc_protocol_flow.log`
* Contains:

  * per-message **byte counts** (`src`, `dst`, `bytes`)
  * per-phase **compute durations** (`phase`, `duration`)

---

## Quick sanity check

After running:

* `MPC reconstructed sum == plaintext sum`
* `MPC reconstructed average == plaintext average`

If the assertion fails, check:

* `THRESHOLD <= number of selected CPs`
* dependency installation (`pycryptodome`)
* you did not modify `p`, `g`, `h`, or share encoding inconsistently
