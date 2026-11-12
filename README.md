# `zen5-scheduler` — Entropy-Driven Hybrid Scheduler & Per-Instruction Energy Engine for AMD Ryzen AI 7 350

[![Language: Rust](https://img.shields.io/badge/Language-Rust_2021-orange.svg)](#)
[![Kernel: eBPF sched_ext + Ring-0 LKM](https://img.shields.io/badge/Kernel-eBPF_sched__ext_%2B_Ring--0_LKM-blue.svg)](#)
[![Silicon: AMD Ryzen AI 7 350 (Krackan Point)](https://img.shields.io/badge/Silicon-AMD_Ryzen_AI_7_350_(Zen_5_%2B_Zen_5c)-red.svg)](#)
[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-green.svg)](LICENSE)

> **Reverse-engineered hybrid CPU scheduler for the AMD Ryzen AI 7 350 ("Krackan Point", Family `0x1A` Model `0x60`) written in native Rust + Linux `sched_ext` eBPF + Ring-0 Kernel Module.**
>
> Models **Zen 5** cores as **High-Entropy execution engines** (`5.09 GHz`, `CoreType=0`) and **Zen 5c** cores as **Low-Entropy laminar engines** (`3.51 GHz`, `CoreType=1`), enforcing a strict hardware/kernel boundary so **workloads meant for a Zen 5 core are never allocated onto a Zen 5c core** while mathematically right-sizing core frequencies below the cubic **Upper Voltage Barrier** (`40.2%`–`59.9%` lower energy per instruction in $\text{pJ/instr}$).

---

## 1. The Silicon Bug We Reverse-Engineered on Linux

On the **AMD Ryzen AI 7 350** (4x **Zen 5** + 4x **Zen 5c** physical cores, 16 threads sharing a single 16 MiB L3 CCX), we extracted and disassembled the running Linux kernel (`vmlinux`) around `amd_detect_prefcore` (`0xffffffff81382760`), `amd_get_highest_perf`, and `amd_hfi`, and executed raw `CPUID` probes (`0x80000026` Extended CPU Topology & `0x80000027` Heterogeneous Core Ranking) across all 16 logical CPUs.

### Discovery #1: Physical Cores Alternate Even/Odd Inside One CCX
Unlike Intel P/E architectures (which group all P-cores first and all E-cores second), the Ryzen AI 7 350 **interleaves Zen 5 and Zen 5c on alternating physical core IDs**:

| Logical CPUs (Primary / SMT) | Physical Core ID | `CPUID 0x80000026` `CoreType` | Silicon Microarchitecture | ACPI CPPC `highest_perf` | Max Clock | Entropy Domain |
| :--- | :---: | :---: | :--- | :---: | :---: | :--- |
| **CPU 4, 6** *(SMT: 12, 14)* | Core 4, Core 6 | `0` (Classic) | **Zen 5 Golden** | **`208`** | **5090.9 MHz** | **Peak-Entropy** *(Audio DSP, Compositor, Game/UI Render)* |
| **CPU 2** *(SMT: 10)* | Core 2 | `0` (Classic) | **Zen 5 Silver** | **`202`** | **5090.9 MHz** | **High-Entropy** *(Interactive, Browser, IDE, AI)* |
| **CPU 0** *(SMT: 8)* | Core 0 | `0` (Classic) | **Zen 5 Base** | **`196`** | **5090.9 MHz** | **High-Entropy** *(Interactive, Foreground)* |
| **CPU 1, 3, 5, 7** *(SMT: 9, 11, 13, 15)* | Core 1, 3, 5, 7 | `1` (Dense) | **Zen 5c Dense** | **`135`** | **3506.5 MHz** | **Low-Entropy** *(Batch Compiles, Compression, System Daemons)* |

- **All High-Entropy Zen 5 Logical CPUs**: `0, 2, 4, 6, 8, 10, 12, 14` (`0x5555`)
  - Primary Zen 5 Threads: `0, 2, 4, 6` (`0x0055`) | Golden Primary: `4, 6` (`0x0050`) | Zen 5 SMT Siblings: `8, 10, 12, 14` (`0x5500`)
- **All Low-Entropy Zen 5c Logical CPUs**: `1, 3, 5, 7, 9, 11, 13, 15` (`0xAAAA`)

### Discovery #2: Why Stock Linux Mis-Schedules High-Entropy Tasks onto Zen 5c
1. Disassembling `amd_detect_prefcore` (`0xffffffff81382760`) revealed that during early boot, `amd-pstate` reads `MSR_AMD_CPPC_CAP1` (`0xc00102b0`). On this firmware, the raw MSR reports a uniform value before ACPI `_CPC` tables are parsed, whereas the true asymmetric rankings (`208, 202, 196, 135`) are exposed via ACPI CPPC (`acpi_cppc/highest_perf`) and the SMU's `AMDI0104:00` (`amd_hfi`) mailbox.
2. Because `amd_detect_prefcore` sees uniform initial MSR caps, it sets `/sys/devices/system/cpu/amd_pstate/prefcore = disabled`, never calls `sched_set_itmt_support()`, and leaves `/sys/devices/system/cpu/cpu*/cpu_capacity = 1024` across all 16 threads!
3. Even worse, because all 16 threads share a single 16 MiB L3 cache (`cache_leaves = 4`), `select_idle_sibling()` treats CPU 1 (`3.50 GHz` Zen 5c) as an equal neighbor to CPU 0 (`5.09 GHz` Zen 5). Before loading `zen5-scheduler`, real-time audio (`pipewire`, `wireplumber`, `pipewire-pulse`) and display (`Xwayland`) were stranded on 3.5 GHz Zen 5c cores — suffering a **+42.7% to +45.7% latency penalty (1.46x slowdown)**.

---

## 2. Architecture: Execution Entropy & Per-Instruction Energy Physics

```mermaid
flowchart TD
    subgraph Silicon["AMD Ryzen AI 7 350 Silicon & SMU Telemetry"]
        CPUID["CPUID 0x80000026 / 0x80000027<br/>CoreType: 0=Zen 5, 1=Zen 5c"]
        CPPC["ACPI CPPC Curve (24..208)<br/>Zen 5: 208/202/196 | Zen 5c: 135"]
        HFI["AMD HFI Mailbox (AMDI0104:00)<br/>3 Workload Classes + IPC/Energy Hints"]
        PWR["Power & Thermal Sensors<br/>ACAD/BAT1 + hwmon5 (W) + hwmon6 (°C)"]
    end

    subgraph Engine["Execution Entropy & CMOS Energy Physics (Rust + eBPF + Ring-0 LKM)"]
        ENT["Real-Time Execution Entropy Score H(τ) ∈ [0, 1000]<br/>Context-Switch Entropy + Burst Jitter + Thread Fan-Out"]
        BAR["Upper Voltage Barrier Avoidance<br/>Zen 5 Knee: CPPC 168 (4.36 GHz, 1.07V) vs Wall (5.09 GHz, 1.38V)<br/>Zen 5c Knee: CPPC 116 (3.01 GHz, 0.94V) vs Wall (3.51 GHz, 1.05V)"]
        EINSTR["Per-Instruction Energy Calculator<br/>E_instr = (C_eff · V(p_req)²) / IPC (pJ/instr)"]
    end

    subgraph Queues["Strict Entropy Dispatch Fences (Zero Zen 5 -> Zen 5c Spill)"]
        G["★ Peak-Entropy Golden Zen 5<br/>CPUs 4, 6 (CPPC 208)"]
        P["▲ High-Entropy Primary Zen 5<br/>CPUs 0, 2 (CPPC 196, 202)"]
        S["▲ High-Entropy Zen 5 SMT Overflow<br/>CPUs 8, 10, 12, 14 (Never Zen 5c!)"]
        D["∙ Low-Entropy Dense Zen 5c<br/>CPUs 1, 3, 5, 7, 9, 11, 13, 15 (CPPC 135)"]
    end

    CPUID --> ENT
    CPPC --> BAR
    HFI --> ENT
    PWR --> ENT
    PWR --> BAR
    ENT --> BAR
    BAR --> EINSTR
    EINSTR -->|"H(τ) >= 750 (AC) / 800 (Bat)"| G
    EINSTR -->|"H(τ) >= 300 (AC) / 480 (Bat)"| P
    G -->|"Primary Busy Overflow"| S
    P -->|"Primary Busy Overflow"| S
    EINSTR -->|"H(τ) < Gate (Laminar / Batch)"| D
```

### 2.1 High-Entropy (Zen 5) vs. Low-Entropy (Zen 5c) Classification
Every task $\tau$ is scored in real time with an **Execution Entropy Score** $H(\tau) \in [0, 1000]$ combining:
1. **Context-Switch Entropy**: Ratio of voluntary context switches ($\Delta\text{nvcsw}$, event-driven wakeups on audio/UI/input/network I/O) vs. non-voluntary preemptions ($\Delta\text{nivcsw}$, time-sliced laminar batch loops).
2. **Runtime Burst Jitter**: Coefficient of variation $\frac{|\Delta t - \mu_t|}{\mu_t}$ distinguishing short irregular interactive micro-bursts from continuous steady-state throughput.
3. **Thread Pool Fan-Out**: Single/dual-thread latency-critical flows vs. wide parallel worker pools ($N_{\text{threads}} \ge 16$).
4. **Hardware HFI Class (`amd_hfi_cpuinfo`)**: Direct kernel symbol inspection of the SMU's per-task workload class ranking.

### 2.2 First-Principles Per-Instruction Energy ($E_{\text{instr}}$) & Upper Voltage Barrier Avoidance
On TSMC 4nm (`N4P`) CMOS silicon, dynamic power is $P_{\text{dyn}} = C_{\text{eff}} \cdot V(f)^2 \cdot f$, and instruction throughput is $\text{IPS} = f \cdot \text{IPC}(H, \text{core})$. The frequency $f$ cancels out of the **Energy per Instruction**:

$$E_{\text{instr}}(p_{\text{req}}) = \frac{C_{\text{eff}} \cdot V(p_{\text{req}})^2}{\text{IPC}(H, \text{core})} \quad [\text{picojoules / instruction (pJ/instr)}]$$

Above the **V/F Efficiency Knee** (`CPPC 168 / 4363 MHz` on Zen 5; `CPPC 116 / 3013 MHz` on Zen 5c), the SMU enters the quadratic **Upper Voltage Barrier** where chasing the last `+14%` of clock speed (`4.36 GHz -> 5.09 GHz`) requires pumping core voltage from `~1.07V` to `~1.38V`, costing **+67% more energy per instruction**!

`zen5-scheduler` computes each task's exact required CPPC performance target $p_{\text{req}}$ from its entropy $H(\tau)$ and utilization $U(\tau)$, right-sizing the core frequency via `scx_bpf_cpuperf_set(cpu, target)` and `scaling_max_freq` so **every task gets what it requires without ever hitting the inefficient upper V/F barrier**:

| Operating Point | Core Frequency | Core Voltage $V(p)$ | Energy / Instruction ($E_{\text{instr}}$) | Total Energy (450M Instr) | Energy Saved vs. Upper Wall |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Unclamped Zen 5 Upper Wall (`CPPC 208`)** | `5091 MHz` | `1.38 V` | `996.1 pJ/instr` | `448.2 mJ` | Baseline (0.0%) |
| **Right-Sized Zen 5 Efficiency Knee (`CPPC 168`, AC)** | `4364 MHz` | `1.07 V` | **`595.5 pJ/instr`** | **`268.0 mJ`** | **`-40.2%` energy saved** |
| **Right-Sized Zen 5 Interactive Flow (`CPPC 108`)** | `2805 MHz` | `0.89 V` | **`385.1 pJ/instr`** | **`173.3 mJ`** | **`-57.8%` energy saved** |
| **Low-Entropy Laminar Flow on Zen 5c (`CPPC 73`)** | `1896 MHz` | `0.80 V` | **`283.2 pJ/instr`** | **`127.4 mJ`** | **Optimal laminar efficiency** |

### 2.3 Automatic AC Mains vs. Battery Power Adaptation
`zen5-scheduler` continuously reads `/sys/class/power_supply/ACAD/online` and `/sys/class/power_supply/BAT1/status`:
- **Strict Zen 5 Rule Preserved 100% on Both AC & Battery**: Active high-entropy flows (`pipewire`, audio DSP, games, UI compositors, browsers, IDEs, terminals) **never** touch a Zen 5c core in either power state (`target_mask & 0xAAAA == 0`).
- **Smart Battery Gate Tightening**: On battery power, the Zen 5 admission threshold tightens slightly (`300 -> 480`) so *dormant/idle* background helpers (`0%` CPU, `0` wakeups) park on low-leakage Zen 5c cores until the exact millisecond they exhibit an active burst or voluntary wakeup, at which point they immediately promote back to Zen 5.
- **Battery Upper-Barrier Clamp**: On battery, the upper-barrier ceiling tightens to `CPPC 152` (`3948 MHz`) on Zen 5 and `CPPC 100` (`2597 MHz`) on Zen 5c.

---

## 3. Real Hardware Benchmark Results (AMD Ryzen AI 7 350)

Measured via `zen5 bench` (`45,000,000` iterations of a branch-heavy, pointer-chasing High-Entropy flow vs. an 8-way independent ILP Low-Entropy flow):

```text
==========================================================================================
 AMD Ryzen AI 7 350 — Native Rust Hardware Entropy, Latency & Per-Instruction Energy Bench
==========================================================================================
 Core Tier                        | High-Entropy Flow (ms) | Low-Entropy Flow (ms)
----------------------------------+------------------------+------------------------------
 CPU  4 (Zen 5 Golden #1, CPPC208)|              66.69 ms  |            64.96 ms
 CPU  0 (Zen 5 Base #4,   CPPC196)|              66.59 ms  |            48.91 ms
 CPU 12 (Zen 5 Golden SMT Sibling)|              66.09 ms  |            49.68 ms
 CPU  1 (Zen 5c Dense,    CPPC135)|              95.18 ms  |            70.87 ms
----------------------------------+------------------------+------------------------------
 ★ Zen 5 Golden vs Zen 5c Speedup on High-Entropy Flow : +42.7% faster (1.43x)
 ▲ Zen 5 SMT (CPU 12) vs Zen 5c (CPU 1) Overflow Gain  : +44.0% faster (1.44x)
 ⚡ Upper-Barrier Energy Saved per Instruction          : -40.2% pJ/instr by clamping at V/F knee
==========================================================================================
```

> **Key Takeaway**: Even a **Zen 5 SMT sibling thread** (`CPU 12`, `66.09 ms`) executes high-entropy workloads **44.0% faster** than a dedicated physical **Zen 5c** core (`CPU 1`, `95.18 ms`). That is why `zen5-scheduler` routes Zen 5 overflow onto Zen 5 SMT siblings (`8, 10, 12, 14`) and **never** lets high-entropy tasks spill onto Zen 5c.

---

## 4. Repository Structure

| File / Directory | Description |
| :--- | :--- |
| [`src/main.rs`](src/main.rs) | **100% Native Rust Scheduler Stack (`zen5`)**: Direct x86_64 `CPUID` topology prober, real-time Execution Entropy classifier, CMOS per-instruction energy calculator (`pJ/instr` & `mJ`), userspace affinity arbiter daemon, and native `libbpf` FFI `sched_ext` loader |
| [`src/scx_ryzen350.bpf.c`](src/scx_ryzen350.bpf.c) | **Linux Kernel `sched_ext` eBPF Scheduler**: 4-tier Entropy DSQs (`DSQ_ZEN5_GOLDEN`, `DSQ_ZEN5_PRIMARY`, `DSQ_ZEN5_SMT`, `DSQ_ZEN5C_DENSE`), live `amd_hfi_cpuinfo` `__ksym` integration, demand-exact `scx_bpf_cpuperf_set()` scaling below the Upper Voltage Barrier, and in-kernel fixed-point energy accounting |
| [`src/scx_ryzen350.h`](src/scx_ryzen350.h) | Shared topology bitmasks, entropy thresholds, and eBPF telemetry structures between C and Rust |
| [`kmod/zen5_entropy_kmod.c`](kmod/zen5_entropy_kmod.c) | **Ring-0 Loadable Linux Kernel Module (`zen5_entropy_kmod.ko`)**: Directly patches `per_cpu(cpu_scale, cpu)` (`1024` Zen 5 Golden, `994` Silver, `965` Base, `664` Zen 5c Dense), activates `sched_set_itmt_core_prio()` + `sched_set_itmt_support()`, and exposes `/proc/zen5_entropy` |
| [`kernel/0001-x86-amd-ryzen-ai-350-entropy-scheduler.patch`](kernel/0001-x86-amd-ryzen-ai-350-entropy-scheduler.patch) | **Static Linux Kernel Patch**: Patches `drivers/cpufreq/amd-pstate.c` and `drivers/platform/x86/amd/hfi/hfi.c` for custom kernel builds |
| [`build.rs`](build.rs) | Cargo build script that automatically compiles `src/scx_ryzen350.bpf.c` via `clang -target bpf` and links `libbpf` |
| [`systemd/`](systemd/) | Systemd user (`zen5-arbiter.service`) and system (`scx-ryzen350.service`) service units |

---

## 5. Build & Quick Start

### Prerequisites
- Linux kernel `>= 6.12` (tested on Fedora 45 `7.3.3-300.fc45.x86_64` with `CONFIG_SCHED_CLASS_EXT=y`)
- Rust toolchain (`cargo`, `rustc`), `clang`, `libbpf-devel`, and `kernel-devel` (for building the optional Ring-0 kernel module)

### Build Everything
```bash
# 1. Build the native Rust binary + eBPF sched_ext object (via build.rs) and run unit tests
cargo test
cargo build --release
cp target/release/zen5 bin/zen5

# 2. (Optional) Build the Ring-0 Loadable Kernel Module (zen5_entropy_kmod.ko)
make -C kmod
cp kmod/zen5_entropy_kmod.ko bin/
```

### Usage (`zen5` CLI)
```bash
# Enable Easy Mode (starts the background Rust Entropy Arbiter immediately — no root required for user tasks!)
./bin/zen5 easy-mode on

# View live Silicon Topology, APU Power/Temp, Per-Instruction Energy (pJ/instr) & Entropy Dashboard
./bin/zen5 status

# Run the native Rust High-Entropy vs. Low-Entropy hardware benchmark & energy analysis
./bin/zen5 bench

# Launch any latency-critical command strictly on Peak-Entropy Golden Zen 5 cores (CPUs 4, 6)
./bin/zen5 run --golden -- <command> [args...]

# Pin a specific PID or process name to an entropy tier ('golden', 'zen5', or 'dense')
./bin/zen5 pin pipewire golden
./bin/zen5 pin rustc dense

# Dump raw x86_64 CPUID leaves (0x80000026 & 0x80000027) and ACPI CPPC registers
./bin/zen5 probe
```

### Kernel-Level Ring-0 & `sched_ext` Activation (Root)
```bash
# 1. Load Ring-0 Kernel Module (fixes cpu_capacity 1024/664, enables ITMT, clamps upper V/F barrier, shields system.slice)
sudo ./bin/zen5 hw-tune apply
cat /proc/zen5_entropy

# 2. Attach the kernel-wide eBPF sched_ext scheduler
sudo ./bin/zen5 scx-load
```

---

## 6. License
Licensed under the **GNU General Public License v2.0 (GPL-2.0)** — see [LICENSE](LICENSE).
