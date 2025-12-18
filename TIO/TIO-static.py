import csv
import numpy as np
from numpy.random import default_rng

"""
TIO prototype (paper-oriented):
- Interval observer driven by digital-twin output y^d (TIO core recursion, paper Eq. (12) form).
- Detection by "state escapes the interval" (paper evaluation logic for A-1/A-2).
- Optional event-trigger gate based on output mismatch (paper Eq. (19) form).
"""

CSV_RATE_OUT = "tio_static_detection_rate.csv"
CSV_DELTA_OUT = "tio_static_detection_rate_vs_delta.csv"

# System matrices (paper evaluation setting)
A = np.array([[0.5, 1.0],
              [0.0, -0.5]])
B = np.eye(2)
C = np.array([[1.0, -1.0],
              [0.0,  1.0]])
L = np.array([[0.25,  0.25],
              [0.0,  -0.75]])

# Fault/disturbance channel: x := x + E f
E = np.array([1.0, 1.0 / 3.0]).reshape(2, 1)  # (n,1)

# Structured measurement noise channel: y = Cx + S * v_s
S = E.flatten()  # (p,)

# Event-triggered branch uses an input scaling to emulate a separate setup (kept as-is)
INPUT_GAIN_EVENT = 1e-4
B_EFF_EVENT = INPUT_GAIN_EVENT * B

EPS_DETECT = 1e-10  # numeric tolerance for boundary checks

ATTACK_PHYSICAL = "physical"
ATTACK_DATA_TAMPERING = "data_tampering"
ATTACK_NONE = "none"


def normalize_attack_type(attack_type):
    """
    Normalizes attack type names used by this prototype.
    Backward compatible: accepts legacy "cyber" and maps it to "data_tampering".
    """
    if attack_type is None:
        return ATTACK_NONE
    at = str(attack_type).strip().lower()
    if at in ("cyber", "data tampering", "data_tampering", "tampering"):
        return ATTACK_DATA_TAMPERING
    return at


def check_tio_assumptions(A_mat, C_mat, L_mat, tol=1e-12):
    """
    TIO/IO viability check (paper assumption):
      1) M = A - L C is elementwise nonnegative (Metzler / monotone requirement in IO context).
      2) M is Schur stable (spectral radius < 1).
    Raises ValueError if violated; returns (M, rho).
    """
    M = A_mat - L_mat @ C_mat

    if np.any(M < -tol):
        bad = np.argwhere(M < -tol)
        i, j = bad[0]
        raise ValueError(
            f"TIO assumption violated: M = A - L C is not elementwise nonnegative. "
            f"Example entry M[{i},{j}] = {M[i, j]:.6e} < 0 (tol={tol})."
        )

    eigvals = np.linalg.eigvals(M)
    rho = float(np.max(np.abs(eigvals)))
    if rho >= 1.0 - tol:
        raise ValueError(
            f"TIO assumption violated: M = A - L C is not Schur stable. "
            f"Spectral radius rho(M) = {rho:.12f} >= 1 (tol={tol})."
        )

    return M, rho


def u_vec(k, h=0.01):
    t = (k + 1) * h
    u1 = 2.0 + np.sin(2 * np.pi * t)
    u2 = 2.0 + np.cos(2 * np.pi * t)
    return np.array([u1, u2])


def v_s_base(k):
    return 0.2 * np.sin(0.5 * (k + 1)) + 0.1 * np.cos(0.5 * (k + 1))


def analytic_V_scalar():
    return np.sqrt(0.2 ** 2 + 0.1 ** 2)


absL = np.abs(L)
barL = absL.copy()  # conservative bound propagation


def io_step(xl, xu, y_d, u_k, V_vec):
    """
    TIO interval observer update driven by y^d (paper Eq. (12) form):
      x_l^+ = A x_l + B u + L(y^d - C x_l) - |L| V
      x_u^+ = A x_u + B u + L(y^d - C x_u) + |L| V
    """
    bias = (barL @ V_vec)
    xl_next = A @ xl + B @ u_k + L @ (y_d - C @ xl) - bias
    xu_next = A @ xu + B @ u_k + L @ (y_d - C @ xu) + bias
    return xl_next, xu_next


def io_step_with_B(xl, xu, y_d, u_k, V_vec, B_mat):
    bias = (barL @ V_vec)
    xl_next = A @ xl + B_mat @ u_k + L @ (y_d - C @ xl) - bias
    xu_next = A @ xu + B_mat @ u_k + L @ (y_d - C @ xu) + bias
    return xl_next, xu_next


def step_truth(x, x_dt, k, f_impulse=None, attack_type="none"):
    """
    Plant and twin propagation; single-shot injection x := x + E f (A-1/A-2 separation):
      - physical: inject into plant state
      - data tampering: inject into twin state
    """
    attack_type = normalize_attack_type(attack_type)
    u_k = u_vec(k)
    x_next = A @ x + B @ u_k
    xdt_next = x_next.copy()

    if f_impulse is not None:
        if attack_type == ATTACK_DATA_TAMPERING:
            xdt_next = xdt_next + (E.flatten() * f_impulse)
        elif attack_type == ATTACK_PHYSICAL:
            x_next = x_next + (E.flatten() * f_impulse)

    return x_next, xdt_next


def step_truth_with_B(x, x_dt, k, f_impulse=None, attack_type="none", B_mat=None):
    attack_type = normalize_attack_type(attack_type)
    if B_mat is None:
        B_mat = B
    u_k = u_vec(k)
    x_next = A @ x + B_mat @ u_k
    xdt_next = x_next.copy()

    if f_impulse is not None:
        if attack_type == ATTACK_DATA_TAMPERING:
            xdt_next = xdt_next + (E.flatten() * f_impulse)
        elif attack_type == ATTACK_PHYSICAL:
            x_next = x_next + (E.flatten() * f_impulse)

    return x_next, xdt_next


def y_from_x(x, k):
    v_s = v_s_base(k)
    return C @ x + (S * v_s)


def out_of_interval(vec, low, high, eps=EPS_DETECT):
    return np.any(vec < low - eps) or np.any(vec > high + eps)


def compute_thresholds_structured(V_scalar, S_vec):
    """
    Conservative thresholds used for reporting (not required for the core TIO recursion).
    Kept as-is to preserve your prototype interface.
    """
    n = A.shape[0]
    M = A - L @ C
    I = np.eye(n)

    V_vec = np.abs(S_vec) * V_scalar
    bmax = (np.abs(L) @ V_vec) + (np.abs(L @ S_vec) * V_scalar)
    eub = np.linalg.solve(I - M, bmax)

    CE = (C @ E).reshape(-1)
    CE_abs = np.abs(CE)
    C_abs = np.abs(C)

    base_vec = (C_abs @ eub)
    numer_vec = base_vec + 2.0 * V_vec

    tiny = 1e-12
    denom = np.maximum(CE_abs, tiny)
    fmin_p_vec = numer_vec / denom
    fmin_c_vec = numer_vec / denom
    fmin_p = float(np.max(fmin_p_vec))
    fmin_c = float(np.max(fmin_c_vec))
    return eub, fmin_p_vec, fmin_p, fmin_c_vec, fmin_c, bmax, V_vec


def detect_run(T, attack_type, inject_k, f_level, V_vec_out, warmup=40, eps=EPS_DETECT):
    """
    Detection by state escaping the TIO interval boundary (paper evaluation logic):
      - physical: check x escapes [x_l, x_u]
      - data tampering: check x^d escapes [x_l, x_u]
    """
    attack_type = normalize_attack_type(attack_type)
    x = np.zeros(2)
    xdt = np.zeros(2)
    xl = np.zeros(2)
    xu = np.zeros(2)

    for k in range(T):
        y_d_k = y_from_x(xdt, k)
        u_k = u_vec(k)
        xl, xu = io_step(xl, xu, y_d_k, u_k, V_vec_out)

        if attack_type in (ATTACK_PHYSICAL, ATTACK_DATA_TAMPERING) and (k == inject_k):
            x, xdt = step_truth(x, xdt, k, f_impulse=float(f_level), attack_type=attack_type)
        else:
            x, xdt = step_truth(x, xdt, k, f_impulse=None, attack_type="none")

        if k >= warmup:
            if attack_type == ATTACK_PHYSICAL:
                if out_of_interval(x, xl, xu, eps=eps):
                    return True
            elif attack_type == ATTACK_DATA_TAMPERING:
                if out_of_interval(xdt, xl, xu, eps=eps):
                    return True
            else:
                if out_of_interval(x, xl, xu, eps=eps) or out_of_interval(xdt, xl, xu, eps=eps):
                    return True

    return False


def detect_run_event_triggered(T, attack_type, inject_k, f_level, V_vec_out,
                               delta, warmup=40, eps=EPS_DETECT):
    """
    Event-triggered gate (paper Eq. (19) form) + state-escape detection:
      Trigger if ||y^d(t) - y^p(t+1)|| > delta * ||y^d(t)||, then apply the same escape test.
    """
    attack_type = normalize_attack_type(attack_type)
    x = np.zeros(2)
    xdt = np.zeros(2)
    xl = np.zeros(2)
    xu = np.zeros(2)

    y_d_prev = y_from_x(xdt, 0)

    for k in range(T):
        u_k = u_vec(k)
        xl, xu = io_step_with_B(xl, xu, y_d_prev, u_k, V_vec_out, B_mat=B_EFF_EVENT)

        if attack_type in (ATTACK_PHYSICAL, ATTACK_DATA_TAMPERING) and (k == inject_k):
            x, xdt = step_truth_with_B(
                x, xdt, k, f_impulse=float(f_level),
                attack_type=attack_type, B_mat=B_EFF_EVENT
            )
        else:
            x, xdt = step_truth_with_B(
                x, xdt, k, f_impulse=None,
                attack_type="none", B_mat=B_EFF_EVENT
            )

        y_p_next = y_from_x(x, k + 1)
        y_d_next = y_from_x(xdt, k + 1)

        if k >= warmup:
            r = np.linalg.norm(y_d_prev - y_p_next, 2)
            s = np.linalg.norm(y_d_prev, 2)
            if s == 0.0:
                s = 1e-12
            triggered = (r > float(delta) * s)

            if triggered:
                if attack_type == ATTACK_PHYSICAL:
                    if out_of_interval(x, xl, xu, eps=eps):
                        return True
                elif attack_type == ATTACK_DATA_TAMPERING:
                    if out_of_interval(xdt, xl, xu, eps=eps):
                        return True
                else:
                    if out_of_interval(x, xl, xu, eps=eps) or out_of_interval(xdt, xl, xu, eps=eps):
                        return True

        y_d_prev = y_d_next

    return False


def bootstrap_percentile_ci_binary(hits, rng, alpha=0.05, n_boot=2000):
    hits = np.asarray(hits, dtype=float)
    n = int(hits.size)
    if n <= 0:
        return 0.0, 0.0
    if np.all(hits == hits[0]):
        m = float(hits[0])
        return m, m

    idx = rng.integers(0, n, size=(int(n_boot), n))
    means = hits[idx].mean(axis=1)
    low = float(np.quantile(means, alpha / 2.0))
    high = float(np.quantile(means, 1.0 - alpha / 2.0))
    return low, high


def evaluate_detection_curve(levels_fault, V_vec_out, attack_type,
                             T=200, warmup=40, eps=EPS_DETECT,
                             n_injections=100, seed=2025,
                             ci_alpha=0.05, ci_n_boot=2000):
    rng = default_rng(seed)
    rates, ci_l, ci_u, detected_counts = [], [], [], []

    for f_level in levels_fault:
        candidate_ks = np.arange(warmup, T - 1)
        if n_injections > candidate_ks.size:
            raise ValueError(f"n_injections={n_injections} exceeds available inject times={candidate_ks.size}")
        inject_ks = rng.choice(candidate_ks, size=int(n_injections), replace=False)

        hits = np.zeros(int(n_injections), dtype=int)
        for i, inject_k in enumerate(inject_ks):
            hit = detect_run(
                T=T, attack_type=attack_type,
                inject_k=int(inject_k), f_level=float(f_level),
                V_vec_out=V_vec_out, warmup=warmup, eps=eps
            )
            hits[i] = int(bool(hit))

        detected = int(hits.sum())
        rate = float(detected) / float(n_injections)
        low, high = bootstrap_percentile_ci_binary(hits, rng=rng, alpha=float(ci_alpha), n_boot=int(ci_n_boot))
        rates.append(rate)
        ci_l.append(low)
        ci_u.append(high)
        detected_counts.append(detected)

    return (np.asarray(rates), np.asarray(ci_l), np.asarray(ci_u), np.asarray(detected_counts))


def evaluate_detection_curve_vs_delta(delta_values, f_level, V_vec_out, attack_type,
                                      T=200, warmup=40, eps=EPS_DETECT,
                                      n_injections=100, seed=2025,
                                      ci_alpha=0.05, ci_n_boot=2000):
    rng = default_rng(seed)
    rates, ci_l, ci_u, detected_counts = [], [], [], []

    candidate_ks = np.arange(warmup, T - 1)
    if n_injections > candidate_ks.size:
        raise ValueError(f"n_injections={n_injections} exceeds available inject times={candidate_ks.size}")

    for delta in delta_values:
        inject_ks = rng.choice(candidate_ks, size=int(n_injections), replace=False)
        hits = np.zeros(int(n_injections), dtype=int)

        for i, inject_k in enumerate(inject_ks):
            hit = detect_run_event_triggered(
                T=T, attack_type=attack_type,
                inject_k=int(inject_k), f_level=float(f_level),
                V_vec_out=V_vec_out, delta=float(delta),
                warmup=warmup, eps=eps
            )
            hits[i] = int(bool(hit))

        detected = int(hits.sum())
        rate = float(detected) / float(n_injections)
        low, high = bootstrap_percentile_ci_binary(hits, rng=rng, alpha=float(ci_alpha), n_boot=int(ci_n_boot))
        rates.append(rate)
        ci_l.append(low)
        ci_u.append(high)
        detected_counts.append(detected)

    return (np.asarray(rates), np.asarray(ci_l), np.asarray(ci_u), np.asarray(detected_counts))


def save_detection_curve_csv(out_csv, x_name, x_values,
                             rate_p, lo_p, hi_p, det_p,
                             rate_c, lo_c, hi_c, det_c):
    x_values = np.asarray(x_values)
    rate_p, lo_p, hi_p, det_p = map(np.asarray, (rate_p, lo_p, hi_p, det_p))
    rate_c, lo_c, hi_c, det_c = map(np.asarray, (rate_c, lo_c, hi_c, det_c))

    n = int(x_values.size)
    if not (rate_p.size == lo_p.size == hi_p.size == det_p.size ==
            rate_c.size == lo_c.size == hi_c.size == det_c.size == n):
        raise ValueError("CSV output dimension mismatch.")

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            x_name,
            "rate_physical", "ci_low_physical", "ci_high_physical", "detected_physical",
            "rate_data_tampering", "ci_low_data_tampering", "ci_high_data_tampering", "detected_data_tampering",
        ])
        for i in range(n):
            w.writerow([
                float(x_values[i]),
                float(rate_p[i]), float(lo_p[i]), float(hi_p[i]), int(det_p[i]),
                float(rate_c[i]), float(lo_c[i]), float(hi_c[i]), int(det_c[i]),
            ])


if __name__ == "__main__":
    # Explicit TIO assumption checks for this prototype (paper requirement on A - L C)
    M, rho = check_tio_assumptions(A, C, L, tol=1e-12)

    T = 200
    warmup = 40
    eps = EPS_DETECT
    n_injections = 100
    ci_alpha = 0.05
    ci_n_boot = 2000

    V_scalar = analytic_V_scalar()
    V_vec_out = np.abs(S) * V_scalar

    eub, fmin_p_vec, f_min_p, fmin_c_vec, f_min_c, bmax, _ = compute_thresholds_structured(V_scalar, S)

    levels_fault = np.linspace(0.0, 0.4, 50)

    print("=== TIO prototype checks ===")
    print("M = A - L C:")
    print(M)
    print(f"rho(M) = {rho:.12f}  (Schur stable: rho < 1)")

    print("\n=== State-escape detection (TIO) ===")
    print(f"V_scalar  = {V_scalar:.9f}")
    print(f"V_vec_out = {V_vec_out}")
    print(f"b_max     = {bmax}")
    print(f"e_ub      = {eub}")
    print(f"f_min^p   = {f_min_p:.9f}  (per-out: {fmin_p_vec})")
    print(f"f_min^c   = {f_min_c:.9f}  (per-out: {fmin_c_vec})")
    print(f"n_injections per level = {n_injections}")
    print(f"bootstrap CI = {(1.0-ci_alpha)*100:.1f}% percentile, n_boot={ci_n_boot}")

    print("\n[Evaluating physical faults ...]")
    rate_p, lo_p, hi_p, det_p = evaluate_detection_curve(
        levels_fault, V_vec_out=V_vec_out, attack_type="physical",
        T=T, warmup=warmup, eps=eps, n_injections=n_injections, seed=2025,
        ci_alpha=ci_alpha, ci_n_boot=ci_n_boot
    )

    print("[Evaluating data tampering ...]")
    rate_c, lo_c, hi_c, det_c = evaluate_detection_curve(
        levels_fault, V_vec_out=V_vec_out, attack_type="data_tampering",
        T=T, warmup=warmup, eps=eps, n_injections=n_injections, seed=2026,
        ci_alpha=ci_alpha, ci_n_boot=ci_n_boot
    )

    save_detection_curve_csv(
        out_csv=CSV_RATE_OUT,
        x_name="fault_intensity",
        x_values=levels_fault,
        rate_p=rate_p, lo_p=lo_p, hi_p=hi_p, det_p=det_p,
        rate_c=rate_c, lo_c=lo_c, hi_c=hi_c, det_c=det_c,
    )
    print(f"\nCSV saved: {CSV_RATE_OUT}")

    f_fixed = 0.6
    delta_values = np.linspace(0.0, 5, 50)

    print("\n=== Event-triggered gate (delta sweep) ===")
    print(f"fixed fault intensity f = {f_fixed}")
    print(f"delta grid = [{delta_values.min():.3f}, {delta_values.max():.3f}] with {delta_values.size} points")

    print("\n[Evaluating physical faults with event-trigger ...]")
    rate_p_d, lo_p_d, hi_p_d, det_p_d = evaluate_detection_curve_vs_delta(
        delta_values, f_level=f_fixed, V_vec_out=V_vec_out, attack_type="physical",
        T=T, warmup=warmup, eps=eps, n_injections=n_injections, seed=3031,
        ci_alpha=ci_alpha, ci_n_boot=ci_n_boot
    )

    print("[Evaluating data tampering with event-trigger ...]")
    rate_c_d, lo_c_d, hi_c_d, det_c_d = evaluate_detection_curve_vs_delta(
        delta_values, f_level=f_fixed, V_vec_out=V_vec_out, attack_type="data_tampering",
        T=T, warmup=warmup, eps=eps, n_injections=n_injections, seed=3032,
        ci_alpha=ci_alpha, ci_n_boot=ci_n_boot
    )

    save_detection_curve_csv(
        out_csv=CSV_DELTA_OUT,
        x_name="delta",
        x_values=delta_values,
        rate_p=rate_p_d, lo_p=lo_p_d, hi_p=hi_p_d, det_p=det_p_d,
        rate_c=rate_c_d, lo_c=lo_c_d, hi_c=hi_c_d, det_c=det_c_d,
    )
    print(f"\nCSV saved: {CSV_DELTA_OUT}")
