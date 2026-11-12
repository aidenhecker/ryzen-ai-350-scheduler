/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SCX_RYZEN350_H
#define __SCX_RYZEN350_H

#define MAX_CPUS 16

/*
 * AMD Ryzen AI 7 350 ("Krackan Point") Hardware Topology, Entropy & Energy Model
 * Reverse-engineered from CPUID 0x80000026, 0x80000027 & ACPI CPPC:
 *
 * HIGH-ENTROPY CORES (Zen 5 — Dynamic, branch/burst/latency-sensitive):
 *   Physical Core 4 (Zen 5,  CPPC 208, Max 5.09 GHz, Barrier Knee 4.36 GHz [CPPC 168]): CPU 4,  SMT 12
 *   Physical Core 6 (Zen 5,  CPPC 208, Max 5.09 GHz, Barrier Knee 4.36 GHz [CPPC 168]): CPU 6,  SMT 14
 *   Physical Core 2 (Zen 5,  CPPC 202, Max 5.09 GHz, Barrier Knee 4.36 GHz [CPPC 168]): CPU 2,  SMT 10
 *   Physical Core 0 (Zen 5,  CPPC 196, Max 5.09 GHz, Barrier Knee 4.36 GHz [CPPC 168]): CPU 0,  SMT 8
 *
 * LOW-ENTROPY CORES (Zen 5c — Laminar, steady-state, uniform throughput):
 *   Physical Core 1 (Zen 5c, CPPC 135, Max 3.51 GHz, Barrier Knee 3.01 GHz [CPPC 116]): CPU 1,  SMT 9
 *   Physical Core 3 (Zen 5c, CPPC 135, Max 3.51 GHz, Barrier Knee 3.01 GHz [CPPC 116]): CPU 3,  SMT 11
 *   Physical Core 5 (Zen 5c, CPPC 135, Max 3.51 GHz, Barrier Knee 3.01 GHz [CPPC 116]): CPU 5,  SMT 13
 *   Physical Core 7 (Zen 5c, CPPC 135, Max 3.51 GHz, Barrier Knee 3.01 GHz [CPPC 116]): CPU 7,  SMT 15
 */
#define ZEN5_GOLDEN_MASK   ((1ULL << 4) | (1ULL << 6))
#define ZEN5_SILVER_MASK   ((1ULL << 2) | (1ULL << 0))
#define ZEN5_PRIM_MASK     (ZEN5_GOLDEN_MASK | ZEN5_SILVER_MASK)         /* 0x0055: CPUs 0,2,4,6 */
#define ZEN5_SMT_MASK      ((1ULL << 8) | (1ULL << 10) | (1ULL << 12) | (1ULL << 14)) /* 0x5500: CPUs 8,10,12,14 */
#define ZEN5_ALL_MASK      (ZEN5_PRIM_MASK | ZEN5_SMT_MASK)              /* 0x5555: All Zen 5 threads */

#define ZEN5C_PRIM_MASK    ((1ULL << 1) | (1ULL << 3) | (1ULL << 5) | (1ULL << 7))    /* 0x00AA: CPUs 1,3,5,7 */
#define ZEN5C_SMT_MASK     ((1ULL << 9) | (1ULL << 11) | (1ULL << 13) | (1ULL << 15)) /* 0xAA00: CPUs 9,11,13,15 */
#define ZEN5C_ALL_MASK     (ZEN5C_PRIM_MASK | ZEN5C_SMT_MASK)            /* 0xAAAA: All Zen 5c threads */

/* Upper Voltage/Thermal Barrier Ceilings (in SCX_CPUPERF_ONE = 1024 scale) */
#define ZEN5_BARRIER_CAP_AC       825U  /* CPPC 168 / 208 = 4.36 GHz (avoids 1.38V cubic V/F wall) */
#define ZEN5_BARRIER_CAP_BAT      748U  /* CPPC 152 / 208 = 3.95 GHz on Battery */
#define ZEN5C_BARRIER_CAP_AC      858U  /* CPPC 116 / 135 = 3.01 GHz (avoids Zen 5c 3.51 GHz wall) */
#define ZEN5C_BARRIER_CAP_BAT     740U  /* CPPC 100 / 135 = 2.60 GHz on Battery */

/* Custom Dispatch Queue (DSQ) IDs ordered by Entropy Tier */
#define DSQ_ZEN5_GOLDEN    0x100ULL /* Peak-Entropy: CPUs 4, 6 */
#define DSQ_ZEN5_PRIMARY   0x101ULL /* High-Entropy: CPUs 0, 2, 4, 6 */
#define DSQ_ZEN5_SMT       0x102ULL /* High-Entropy SMT Overflow: CPUs 8, 10, 12, 14 */
#define DSQ_ZEN5C_DENSE    0x103ULL /* Low-Entropy Laminar Flow: CPUs 1, 3, 5, 7, 9, 11, 13, 15 */

/* Workload Entropy Tier Classifications */
enum ryzen350_tier {
    TIER_AUTO        = 0,
    TIER_ZEN5_GOLDEN = 1, /* Peak Entropy: bursty, high jitter, RT/audio/gaming -> CPUs 4,6 first, never Zen 5c */
    TIER_ZEN5_STRICT = 2, /* High Entropy: interactive, variable control flow -> CPUs 0,2,4,6,8,10,12,14, never Zen 5c */
    TIER_ZEN5C_DENSE = 3, /* Low Entropy: steady-state, laminar batch, daemons -> CPUs 1,3,5,7,9,11,13,15 */
};

/* Per-task Execution Entropy, Instruction Energy & AMD HFI telemetry tracked in BPF task storage */
struct task_Telemetry {
    unsigned long long last_run_at_ns;
    unsigned long long avg_runtime_ns;
    unsigned long long runtime_jitter_ns;   /* Slice-to-slice execution variance (entropy signal #1) */
    unsigned long long last_wake_at_ns;
    unsigned long long avg_wake_delta_ns;
    unsigned long long wake_jitter_ns;      /* Wakeup interval unpredictability (entropy signal #2) */
    unsigned long long wake_freq_hz;
    unsigned long long last_nvcsw;
    unsigned long long last_nivcsw;
    unsigned long long est_instructions;    /* Cumulative estimated instructions executed */
    unsigned long long est_energy_nj;       /* Cumulative estimated task energy in nanojoules (nJ) */
    unsigned int       energy_pj_per_instr; /* Live energy cost in picojoules per instruction (pJ/instr) */
    unsigned int       req_cpuperf;         /* Right-sized CPPC performance demand (0..1024, capped below Upper Barrier) */
    unsigned int       entropy_score;       /* 0..1000: <300 = Low Entropy (Zen 5c), >=300 = High Entropy (Zen 5) */
    unsigned int       tier;
    short              hfi_class;
};

/* Global runtime control config updated live by Rust arbiter (AC vs Battery) */
struct ryzen350_config {
    unsigned int on_battery;               /* 0 = AC Power, 1 = Battery Discharging */
    unsigned int entropy_zen5_threshold;   /* 300 on AC, 480 on Battery */
    unsigned int entropy_golden_threshold; /* 750 on AC, 800 on Battery */
    unsigned int strict_zen5_fence;        /* Always 1: never spill Zen 5 tasks to Zen 5c */
    unsigned int zen5_barrier_cap;         /* 825 (4.36 GHz) on AC, 748 (3.95 GHz) on Battery */
    unsigned int zen5c_barrier_cap;        /* 858 (3.01 GHz) on AC, 740 (2.60 GHz) on Battery */
};

/* Global telemetry counters exported to userspace */
struct ryzen350_stats {
    unsigned long long zen5_golden_dispatches;  /* Peak-entropy dispatches */
    unsigned long long zen5_primary_dispatches; /* High-entropy dispatches */
    unsigned long long zen5_smt_dispatches;     /* High-entropy SMT overflow */
    unsigned long long zen5c_dense_dispatches;  /* Low-entropy dispatches */
    unsigned long long zen5c_spill_prevented;   /* High-entropy tasks rescued from Zen 5c */
    unsigned long long hfi_class0_hits;
    unsigned long long direct_idle_hits;
    unsigned long long high_entropy_classifications;
    unsigned long long low_entropy_classifications;
    unsigned long long upper_barrier_clamps;    /* Times CPPC was clamped below Upper Voltage Barrier */
    unsigned long long total_energy_Saved_uj;   /* Estimated microjoules saved by Upper-Barrier clamping */
    unsigned long long cpu_dispatches[MAX_CPUS];
};

#endif /* __SCX_RYZEN350_H */
