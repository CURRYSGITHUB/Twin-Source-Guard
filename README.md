## Twin-Source-Guard

本仓库提供论文可复现实验代码与数据/配置，包含：

- **DMPC（D-SMPC 协议原型）**：动态计算方选择 + 加密 Shamir 共享 + 阈值重构的端-边协同安全聚合流程（Python 实现）。
- **TIO（Triggered Interval Observer）**：基于数字孪生输出驱动的区间观测器与事件触发检测（Python 实现）。
- **SUMO 场景配置与数据集**：路网、车流与仿真配置文件（SUMO 输入）。

---

### 仓库结构

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

### 快速开始

#### 1) DMPC（D-SMPC 协议原型）

- **依赖**：Python 3.9+，`pycryptodome`

```bash
pip install pycryptodome
python DMPC/dmpc.py
```

- **输出**：
  - 控制台：明文聚合结果与阈值重构结果（应一致）
  - 日志：`DMPC/d_smpc_protocol_flow.log`（JSON Lines，包含通信字节数与各阶段耗时）

更多实现细节见：`DMPC/readme.md`。

#### 2) TIO（Triggered Interval Observer）

- **依赖**：Python 3.9+，`numpy`

```bash
pip install numpy
python TIO/TIO-static.py
```

- **输出**：
  - `TIO/tio_static_detection_rate.csv`：检测率 vs 故障强度
  - `TIO/tio_static_detection_rate_vs_delta.csv`：检测率 vs 事件触发阈值 δ

更多实现细节与理论可行性检查（\(M=A-LC\) 的非负性与 Schur 稳定性）见：`TIO/readme.md`。

#### 3) SUMO 场景（可选）

本仓库提供 SUMO 输入三件套：

- **路网**：`selected.net.xml`
- **车流**：`selected.rou.xml`
- **配置**：`selected.sumocfg`

示例运行（需本机已安装 SUMO）：

```bash
sumo-gui -c selected.sumocfg
```

---

### 说明

- 本仓库面向论文复现实验与学术研究使用；如需进一步的实验脚本整合/参数说明，可在此仓库提 Issue 或联系作者。


