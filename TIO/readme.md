# TIO Prototype (Core Algorithm)

This repository provides the **Triggered Interval Observer (TIO)** scheme. The implementation focuses on the **core TIO interval observer recursion** with an optional **event-trigger gate**.

---

## Demonstrates

* **TIO interval observer driven by the digital-twin output** `y^d` (core recursion)
* **Interval-boundary (state-escape) detection** as the fault/attack indicator
* **Two attack channels**:
  * **Physical fault**: injection affects the plant state `x^p`
  * **Data tampering**: injection affects the twin state `x^d`
* **Explicit viability checks** required by the TIO/IO theory:
  * `M = A - L C` is **elementwise nonnegative**
  * `M` is **Schur stable** (`rho(M) < 1`)
* Optional: **event-trigger gate** based on output mismatch

---

## Algorithm 

### 1) TIO interval observer recursion (core)

At each step, the interval observer uses the **twin output** `y^d(k)` to propagate the lower/upper state bounds:

* `x_l(k+1) = A x_l(k) + B u(k) + L (y^d(k) - C x_l(k)) - |L| V`
* `x_u(k+1) = A x_u(k) + B u(k) + L (y^d(k) - C x_u(k)) + |L| V`

In code:

* `io_step(xl, xu, y_d, u_k, V_vec)`  

Notes for this prototype:

* The noise bound is implemented as a **vector bound** `V_vec` with conservative propagation via `|L|`.
* The observer is **driven by `y^d`** (digital-twin output), consistent with the TIO construction.

---

### 2) Attack / fault injection model (A-1 vs A-2)

A single-shot injection is applied at a chosen time `inject_k`:

* **Physical fault** (`attack_type="physical"`): inject into plant state `x^p`
* **Data tampering** (`attack_type="data_tampering"`): inject into twin state `x^d`

In code:
* `step_truth(...)`  
* `step_truth_with_B(...)`

The injected direction is fixed by the channel `E`:

* `x := x + E * f`  or  `x^d := x^d + E * f`

---

### 3) Detection rule

After a warm-up period, detection is triggered if the relevant state violates the interval:

* Physical fault: `x^p ∉ [x_l, x_u]`
* data tampering: `x^d ∉ [x_l, x_u]`


---

### 4) Optional event-trigger gate

The trigger condition is:

* Trigger if `||y^d(t) - y^p(t+1)|| > δ ||y^d(t)||`

In code:

* `detect_run_event_triggered(...)`
* `evaluate_detection_curve_vs_delta(...)`

This branch is included to study sensitivity to `δ` (delta sweep). It does not change the interval observer structure; it only gates detection evaluation.

---

## Requirements

* Python 3.9+
* Dependencies:
  * `numpy`

Install:

* `pip install numpy`

---

## Run

* `python TIO.py`

---

## Outputs

### Console

* **TIO viability checks**:
  * prints `M = A - L C`
  * prints `rho(M)` (spectral radius)
  * raises an exception if nonnegativity or Schur stability is violated
* Basic run configuration and threshold diagnostics (informational)

### CSV files

1) `tio_static_detection_rate.csv`  
   Detection rate vs fault intensity (physical and data tampering)

2) `tio_static_detection_rate_vs_delta.csv`  
   Detection rate vs event-trigger threshold `δ` (physical and data tampering)

---

## Quick sanity check

After running:

1) The program must print `rho(M) < 1` and must not raise an exception.
2) CSV files should be created in the working directory:
   * `tio_static_detection_rate.csv`
   * `tio_static_detection_rate_vs_delta.csv`

If the viability check fails, verify:

* `L` is designed such that `M = A - L C` is elementwise nonnegative
* `rho(M) < 1` (Schur stability)


