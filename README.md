## Twin-Source-Guard

This repository provides reproducible code and datasets/configurations for our paper, including:

- **DMPC (D-SMPC protocol prototype)**: dynamic computing-party selection + encrypted Shamir secret sharing + threshold reconstruction for secure edge aggregation (Python).
- **TIO (Triggered Interval Observer)**: interval observer driven by digital-twin outputs with optional event-triggered detection (Python).
- **SUMO scenario configs & dataset**: network, routes, and simulation configuration files (SUMO input).

---

### Repository structure

```text
.
├── DMPC/
│   ├── dmpc.py
│   ├── d_smpc_protocol_flow.log
│   └── readme.md
├── TIO/
│   ├── TIO-static.py
│   ├── tio_static_detection_rate.csv
│   ├── tio_static_detection_rate_vs_delta.csv
│   └── readme.md
├── selected.net.xml
├── selected.rou.xml
└── selected.sumocfg
```

---

### Quick start

#### 1) DMPC (D-SMPC protocol prototype)

- **Requirements**: Python 3.9+, `pycryptodome`

```bash
pip install pycryptodome
python DMPC/dmpc.py
```

- **Outputs**:
  - Console: plaintext aggregation result and threshold-reconstructed result (should match)
  - Log: `DMPC/d_smpc_protocol_flow.log` (JSON Lines; communication bytes and per-phase durations)

For details, see: `DMPC/readme.md`.

#### 2) TIO (Triggered Interval Observer)

- **Requirements**: Python 3.9+, `numpy`

```bash
pip install numpy
python TIO/TIO-static.py
```

- **Outputs**:
  - `TIO/tio_static_detection_rate.csv`: detection rate vs. fault/attack intensity
  - `TIO/tio_static_detection_rate_vs_delta.csv`: detection rate vs. event-trigger threshold \( \delta \)

For details and the viability checks (elementwise nonnegativity and Schur stability of \(M=A-LC\)), see: `TIO/readme.md`.

#### 3) SUMO scenario (optional)

This repository includes the three standard SUMO inputs:

- **Network**: `selected.net.xml`
- **Routes**: `selected.rou.xml`
- **Config**: `selected.sumocfg`

Example run (requires SUMO installed locally):

```bash
sumo-gui -c selected.sumocfg
```

---

### Notes

- This repository is intended for algorithm reproduction and academic research. For large-scale simulations or additional parameter details, please open an Issue in this repository or contact the authors.


