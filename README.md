# 🦀 Crab-shield

> A hybrid, real-time ransomware detection system for Linux — combining eBPF kernel-level monitoring, static signature analysis, and machine learning behavioral classification, built in Rust.

---

## Overview

Crab-shield is a low-level security tool developed as a Final Year Project (Bachelor of Computer Science — Cyber Security, Multimedia University Malaysia). It addresses the growing threat of ransomware on Linux systems — particularly **partial encryption ransomware** that evades traditional detection by encrypting only portions of files to minimize resource footprint.

The system uses a **hybrid detection approach**:
- **Static Analysis** — SHA256 signature verification via VirusTotal for known ransomware
- **Dynamic Analysis** — Real-time eBPF-based behavioral monitoring (syscalls, file entropy, process metrics)
- **ML Classification** — A trained Random Forest model classifies process behavior in real time
- **SIEM Integration** — Alert forwarding to platforms like Splunk for centralized SOC monitoring

---

## Architecture

The system is composed of two layers:

```
┌─────────────────────────────────────────────────────┐
│                  User Space (Rust)                  │
│                                                     │
│  EbpfHelper → Aggregator → MLClassifier             │
│      │            │             │                   │
│  Entropy      Signature    AlertManager             │
│  Monitor      Verifier      (→ Splunk/SIEM)         │
└────────────────────┬────────────────────────────────┘
                     │ BPF Maps
┌────────────────────▼────────────────────────────────┐
│                 Kernel Space (C / eBPF)             │
│                                                     │
│   Hooked syscalls: open, write, rename, unlink      │
│   Tracepoints → BPF Maps → User Space Events        │
└─────────────────────────────────────────────────────┘
```

### Core Modules

| Module | Description |
|--------|-------------|
| `EbpfHelper` | Loads eBPF programs into the kernel, manages BPF maps, streams events to user space |
| `Aggregator` | Collects behavioral features per process (syscall counts, entropy shifts, resource usage) |
| `Entropy` | Calculates Shannon entropy of data written by each process to detect encryption activity |
| `Signature` | Performs static analysis — hashes executables (SHA256) and queries VirusTotal |
| `MLClassifier` | Runs the ONNX-exported Random Forest model to classify processes in real time |
| `AlertManager` | Generates alerts with severity scores and forwards them to SIEM (Splunk) |
| `Config` | Loads user-defined configuration (monitored paths, thresholds, SIEM endpoints) |

---

## How It Works

### Static Analysis Flow
1. A new process is detected
2. The executable binary is hashed (SHA256)
3. The hash is checked against VirusTotal's known ransomware signature database
4. If matched → immediate alert is fired

### Dynamic Analysis Flow
1. eBPF programs hook into key Linux syscalls (`open`, `write`, `rename`, `unlink`) at the kernel level with no kernel modification required
2. Per-process events stream to user space via BPF maps
3. The **Aggregator** builds feature vectors from:
   - Syscall counts per second (open, write, rename, delete)
   - Shannon entropy of written data: `H(X) = -Σ p(xᵢ) log₂ p(xᵢ)`
   - Process CPU and memory usage
   - Syscall sequences and access patterns
4. Features are passed to the **MLClassifier** (Random Forest via ONNX runtime)
5. The model outputs a ransomware probability score
6. **AlertManager** triggers alerts based on configurable severity thresholds and forwards them to Splunk

---

## Machine Learning Model

### Datasets

The model was trained on two real-world datasets:

| Dataset | Description |
|---------|-------------|
| **ebpfangle** | eBPF-collected syscall traces from ransomware and benign Linux processes |
| **RanSMAP** | Linux ransomware behavioral dataset with per-process features |

### Features Used for Training

| Feature | Source |
|---------|--------|
| Syscall frequency (open/write/rename/unlink per sec) | eBPF hooks |
| Shannon entropy delta of written data | Entropy module |
| Process CPU usage | Process monitor |
| Process memory usage | Process monitor |
| Syscall sequence patterns | eBPF hooks |

### Algorithm
**Random Forest** — chosen for its high accuracy, resistance to overfitting, support for high-dimensional features, and interpretable feature importance scores. Trained with bootstrap aggregation (bagging) and cross-validation.

### Model Performance

| Metric | Result |
|--------|--------|
| Accuracy | High (validated on held-out test set) |
| F1-Score | Evaluated per class (ransomware / benign) |
| AUC-ROC | Plotted and confirmed strong separation |
| False Positives | Minimized via combined entropy + syscall features |

The trained model is exported to **ONNX format** and embedded directly in the Rust binary for zero-dependency real-time inference.

---

## Ransomware Types Detected

- **Full-File Encryption Ransomware** — encrypts entire files using AES/RSA; detected via high entropy spikes and rapid sequential file rewrites
- **Partial Encryption Ransomware** — encrypts only portions of files to stay under resource-usage thresholds; detected via syscall patterns and entropy deltas even at low I/O rates (the key innovation of this project)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Kernel probes | C (eBPF, compiled via Clang/LLVM) |
| User-space daemon | Rust (`tokio` async, `aya` eBPF library) |
| ML training | Python (scikit-learn, pandas, numpy, Jupyter) |
| ML inference | ONNX Runtime (embedded in Rust binary) |
| SIEM integration | Splunk HTTP Event Collector (HEC) |
| Build | Cargo, Make |

### Key Rust Dependencies
- `aya` — eBPF program loading and BPF map management
- `tokio` — async runtime and safe multi-threaded communication between modules
- `ort` — ONNX Runtime bindings for embedded ML inference
- `serde` / `serde_json` — config and alert serialization

---

## Project Structure

```
Crab-shield/
├── src_ebpf/           # eBPF C programs — kernel-side syscall hooks & BPF maps
├── ebpf_user/          # Rust user-space daemon
│   └── src/
│       ├── ebpf_helper.rs      # eBPF loader and BPF map event reader
│       ├── aggregator.rs       # Per-PID feature aggregation
│       ├── entropy.rs          # Shannon entropy calculation on write data
│       ├── signature.rs        # Static analysis / VirusTotal hash lookup
│       ├── ml_classifier.rs    # ONNX model inference engine
│       ├── alert_manager.rs    # Alert generation + Splunk forwarding
│       └── config.rs           # TOML configuration management
└── ml_learn/           # Jupyter notebooks: dataset prep, training, evaluation, ONNX export
```

---

## Prerequisites

- Linux kernel **5.8+** with BTF (BPF Type Format) support
- Clang/LLVM (for compiling eBPF C programs to BPF bytecode)
- Rust toolchain (`cargo`) — stable channel
- Python 3.8+ with Jupyter (for ML training notebooks)
- `libbpf` development headers

```bash
# Ubuntu/Debian
sudo apt-get install -y linux-headers-$(uname -r) clang llvm libelf-dev libbpf-dev

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

---

## Getting Started

```bash
# Clone the repo
git clone https://github.com/Cythonic1/Crab-shield.git
cd Crab-shield

# 1. Build eBPF kernel programs
cd src_ebpf && make

# 2. Build the Rust user-space daemon
cd ../ebpf_user && cargo build --release

# 3. Run (root required for eBPF program loading)
sudo ./target/release/ebpf_user --config config.toml
```

> **Note:** Loading eBPF programs requires root privileges or `CAP_BPF` + `CAP_PERFMON`.

---

## Configuration

```toml
min_severity_to_report = "Medium"
splunk_path = "http://localhost:8088"
splunk_token = "TOKEN"
index_name = "security"
report_interval = 10
virus_total_api_key = "API_KEY"
directory_to_watch = ["/tmp/", "/root/", "/var/", "/dev/", "/etc/"]
module_path = "rf_iris.onnx"
module_scale_path = "scaler.json"
hash_algorith = "MD5"
```

---

## ML Training (Notebooks)

The `ml_learn/` directory contains Jupyter notebooks covering:

1. **Dataset preparation** — merging ebpfangle + RanSMAP, feature selection, normalization
2. **Model training** — Random Forest with hyperparameter tuning and cross-validation
3. **Evaluation** — confusion matrix, F1-score, AUC-ROC, feature importance plots
4. **ONNX export** — converting the trained model for embedding in the Rust daemon

```bash
cd ml_learn
pip install -r requirements.txt
jupyter notebook
```

---

## Limitations

- **False positives** — compression tools (e.g., gzip, zip) generate high entropy similar to encryption; mitigated by combining entropy with syscall sequence analysis
- **Evasion** — fileless, polymorphic, or highly obfuscated ransomware may reduce detection confidence
- **Resource overhead** — real-time entropy calculation and syscall tracing add CPU overhead; tunable via `check_interval_ms`
- **Linux only** — Windows is explicitly out of scope

---

