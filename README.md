# 🦀 Crab-shield

> An eBPF-based ransomware detection system powered by machine learning — real-time protection at the Linux kernel level.

---

## Overview

Crab-shield is a low-level security tool that detects ransomware in real time by combining **eBPF kernel probes** with **machine learning classification**. It intercepts suspicious file system behavior directly at the kernel level — before encryption can complete — with minimal system overhead.

The project is split into three components:

| Directory | Language | Purpose |
|-----------|----------|---------|
| `src_ebpf/` | C | eBPF kernel programs — hooks into system calls to monitor file operations |
| `ebpf_user/` | Rust | User-space daemon — loads eBPF programs, reads kernel events, triggers responses |
| `ml_learn/` | Python / Jupyter | ML model training, feature engineering, and evaluation notebooks |

---

## How It Works

1. **Kernel-level monitoring** — eBPF programs written in C are attached to kernel tracepoints and kprobes. They watch for patterns typical of ransomware: rapid file reads, rewrites, renames, and deletions.

2. **Event streaming** — BPF maps pass events from kernel space to the Rust user-space daemon with near-zero latency.

3. **ML classification** — The trained model (developed in the `ml_learn` notebooks) classifies process behavior as benign or ransomware-like based on aggregated syscall features.

4. **Response** — On detection, the daemon can terminate the offending process before significant data loss occurs.

---

## Tech Stack

- **C** — eBPF kernel programs (compiled to BPF bytecode via Clang/LLVM)
- **Rust** — User-space orchestration, safe and performant
- **Python / Jupyter** — ML model training and evaluation
- **libbpf** — BPF program loading and map management

---

## Why eBPF?

Traditional antivirus relies on user-space hooks or signature scanning — both slow and bypassable. eBPF runs inside the kernel's sandboxed virtual machine, giving:

- **Zero kernel modifications** — no custom modules needed
- **Ultra-low latency** — events are captured at the syscall level
- **High visibility** — sees everything before user-space can interfere

---

## Project Structure

```
Crab-shield/
├── src_ebpf/       # eBPF C programs (kernel-side probes)
├── ebpf_user/      # Rust user-space daemon
└── ml_learn/       # Jupyter notebooks for ML model training
```

---

## Prerequisites

- Linux kernel 5.8+ (with BTF support)
- Clang/LLVM (for compiling eBPF programs)
- Rust toolchain (`cargo`)
- Python 3 + Jupyter (for ML notebooks)
- `libbpf` development headers

---

## Getting Started

```bash
# Clone the repo
git clone https://github.com/Cythonic1/Crab-shield.git
cd Crab-shield

# Build eBPF kernel programs
cd src_ebpf && make

# Build and run the user-space daemon
cd ../ebpf_user && cargo build --release
sudo ./target/release/ebpf_user
```

> **Note:** Loading eBPF programs requires root privileges or `CAP_BPF`.

---

## ML Model

The `ml_learn/` directory contains notebooks for:

- Feature extraction from syscall traces
- Model training (classification of benign vs. ransomware behavior)
- Accuracy and latency benchmarking

---

## Author

**Cythonic1** — [GitHub](https://github.com/Cythonic1)
