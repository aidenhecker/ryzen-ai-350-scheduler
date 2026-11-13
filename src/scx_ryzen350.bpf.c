/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_ryzen350.bpf.c - Entropy-Driven sched_ext (scx) eBPF Scheduler for AMD Ryzen AI 7 350
 *
 * Core Philosophy:
 *   - Zen 5 Cores (CPUs 0,2,4,6 + SMT 8,10,12,14 @ 5.09 GHz, CPPC 196-208) are
 *     HIGH-ENTROPY CORES built for dynamic, unpredictable, bursty, branch-heavy,
 *     and latency-critical execution flows.
 *   - Zen 5c Cores (CPUs 1,3,5,7 + SMT 9,11,13,15 @ 3.51 GHz, CPPC 135) are
 *     LOW-ENTROPY CORES built for laminar, steady-state, uniform throughput,
 *     and background execution flows.
 *
 * Guarantees ("Easy Mode"):
 *   1. Real-time Execution Entropy Scoring (0..1000) from slice runtime jitter,
 *      wakeup interval variance, voluntary/involuntary switch ratio, and AMD HFI
 *      hardware workload class (`amd_hfi_cpuinfo`).
 *   2. High-entropy tasks (>= 300) are strictly fenced onto Zen 5 cores (preferring
 *      Golden CPUs 4,6 -> Primary 2,0 -> Zen 5 SMT 12,14,10,8) and NEVER spilled
 *      onto a low-entropy Zen 5c core.
 *   3. Low-entropy tasks (< 300) flow smoothly onto Zen 5c cores (1,3,5,7,9,11,13,15),
 *      keeping Zen 5 cores uncontested and thermally primed for high-entropy bursts.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "scx_ryzen350.h"

char _license[] SEC("license") = "GPL";

/* Tunable configuration (updated live from userspace) */
const volatile bool strict_zen5_fence = true;     /* Never spill High-Entropy Zen 5 tasks to Zen 5c */
const volatile bool enable_hfi_telemetry = true;  /* Use AMD HFI hardware class telemetry */
const volatile bool boost_zen5_cppc = true;       /* Drive CPPC 1024 on High-Entropy Zen 5 cores */
const volatile u32  entropy_zen5_threshold = 300; /* Score >= 300 -> High-Entropy Zen 5 */
const volatile u32  entropy_golden_threshold = 700; /* Score >= 700 -> Peak-Entropy Golden Zen 5 (4,6) */
const volatile u64  zen5_slice_ns = 4000000ULL;   /* 4ms agile slice for High-Entropy Zen 5 */
const volatile u64  zen5c_slice_ns = 16000000ULL; /* 16ms laminar slice for Low-Entropy Zen 5c */

/* Kernel AMD HFI per-CPU symbol (exposed in vmlinux BTF) */
extern const struct amd_hfi_cpuinfo amd_hfi_cpuinfo __ksym __weak;

#ifndef BPF_STRUCT_OPS
#define BPF_STRUCT_OPS(name, args...) \
    SEC("struct_ops/"#name) \
    BPF_PROG(name, ##args)
#endif

#ifndef BPF_STRUCT_OPS_SLEEPABLE
#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
    SEC("struct_ops.s/"#name) \
    BPF_PROG(name, ##args)
#endif

static __always_inline void dsq_insert_compat(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags)
{
    if (bpf_ksym_exists(scx_bpf_dsq_insert___v2))
        scx_bpf_dsq_insert___v2(p, dsq_id, slice, enq_flags);
    else
        scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags);
}

static __always_inline bool dsq_move_to_local_compat(u64 dsq_id)
{
    return scx_bpf_dsq_move_to_local(dsq_id);
}

/* Explicit PID / TGID tier override maps populated by zen5-arbiter and `zen5` CLI */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u32);
    __type(value, u32);
} pid_tier_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u32);
    __type(value, u32);
} tgid_tier_map SEC(".maps");

/* Per-task Execution Entropy & HFI telemetry storage */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_Telemetry);
} task_telemetry_map SEC(".maps");

/* Global telemetry stats array (1 entry) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ryzen350_stats);
} stats_map SEC(".maps");

/* Live AC / Battery power & entropy gate configuration map (1 entry) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ryzen350_config);
} config_map SEC(".maps");

/* Ordered CPU preference arrays for Ryzen AI 7 350 */
static const s32 zen5_golden_order[2]   = { 4, 6 };
static const s32 zen5_silver_order[2]   = { 2, 0 };
static const s32 zen5_smt_order[4]      = { 12, 14, 10, 8 };
static const s32 zen5c_primary_order[4] = { 1, 3, 5, 7 };
static const s32 zen5c_smt_order[4]     = { 9, 11, 13, 15 };

static __always_inline bool is_zen5_cpu(s32 cpu)
{
    return cpu >= 0 && cpu < 16 && ((cpu & 1) == 0);
}

static __always_inline bool is_zen5_golden_cpu(s32 cpu)
{
    return cpu == 4 || cpu == 6;
}

static __always_inline bool is_zen5_primary_cpu(s32 cpu)
{
    return cpu == 0 || cpu == 2 || cpu == 4 || cpu == 6;
}

static __always_inline bool is_zen5c_cpu(s32 cpu)
{
    return cpu >= 0 && cpu < 16 && ((cpu & 1) == 1);
}

static __always_inline bool cpu_allowed(const struct task_struct *p, s32 cpu)
{
    if (cpu < 0 || cpu >= 16)
        return false;
    u64 mask = p->cpus_mask.bits[0];
    return (mask & (1ULL << cpu)) != 0;
}

static __always_inline u64 abs_diff_u64(u64 a, u64 b)
{
    return (a > b) ? (a - b) : (b - a);
}

/*
 * Compute a task's Real-Time Execution Entropy Score (0..1000) and map it to
 * a Ryzen AI 7 350 core tier:
 *   - High Entropy (>= 700): TIER_ZEN5_GOLDEN (CPUs 4,6 -> 2,0 -> 12,14,10,8)
 *   - Medium-High Entropy (300..699): TIER_ZEN5_STRICT (CPUs 0,2,4,6,8,10,12,14)
 *   - Low Entropy (< 300): TIER_ZEN5C_DENSE (CPUs 1,3,5,7,9,11,13,15)
 */
static __always_inline u32 classify_task_by_entropy(struct task_struct *p,
                                                    struct task_Telemetry *tel,
                                                    struct ryzen350_stats *st)
{
    u32 pid = p->pid;
    u32 tgid = p->tgid;

    /* 1. Check explicit userspace override maps */
    u32 *pinned = bpf_map_lookup_elem(&pid_tier_map, &pid);
    if (pinned && *pinned != TIER_AUTO)
        return *pinned;

    pinned = bpf_map_lookup_elem(&tgid_tier_map, &tgid);
    if (pinned && *pinned != TIER_AUTO)
        return *pinned;

    /* 2. Hard priority / policy rules */
    if (p->prio < 100 || p->static_prio < 120) {
        if (tel)
            tel->entropy_score = 950;
        return TIER_ZEN5_GOLDEN;
    }
    if (p->policy == 3 /* SCHED_BATCH */ || p->policy == 5 /* SCHED_IDLE */ || p->static_prio > 125) {
        if (tel)
            tel->entropy_score = 100;
        return TIER_ZEN5C_DENSE;
    }
    if ((p->flags & 0x00200000 /* PF_KTHREAD */) && p->nr_cpus_allowed > 1) {
        if (tel)
            tel->entropy_score = 150;
        return TIER_ZEN5C_DENSE;
    }

    if (!tel)
        return TIER_ZEN5_STRICT;

    /*
     * 3. Calculate Execution Entropy Score (baseline = 500 for new user threads
     *    so newly spawned interactive tasks start on High-Entropy Zen 5)
     */
    u32 score = 500;

    /* Component A: Runtime Burstiness & Slice Jitter (high variance = high entropy) */
    if (tel->avg_runtime_ns > 0) {
        if (tel->avg_runtime_ns < 1500000ULL) {
            /* Sub-1.5ms micro-bursts (audio DSP, UI event loop, input handler) */
            score += 250;
        } else if (tel->avg_runtime_ns < 4000000ULL) {
            /* 1.5ms..4ms interactive/gaming frame bursts */
            score += 120;
        } else if (tel->avg_runtime_ns > 12000000ULL) {
            /* Continuous full-slice execution (>12ms) = laminar steady-state flow */
            score -= 220;
        }

        /* High relative runtime jitter (runtime_jitter_ns > 25% of avg_runtime_ns) -> High Entropy */
        if (tel->runtime_jitter_ns * 4 > tel->avg_runtime_ns)
            score += 120;
        else if (tel->runtime_jitter_ns * 10 < tel->avg_runtime_ns && tel->avg_runtime_ns > 6000000ULL)
            /* Very low jitter (<10%) + long runtime = ultra-laminar low-entropy flow */
            score -= 150;
    }

    /* Component B: Wakeup Frequency & Wakeup Interval Jitter */
    if (tel->wake_freq_hz >= 60) {
        score += 140; /* Frame-rate / audio-rate or higher event frequency */
    } else if (tel->wake_freq_hz < 15 && tel->avg_runtime_ns > 8000000ULL) {
        score -= 120; /* Infrequent wakeups + long crunching = batch worker */
    }
    if (tel->avg_wake_delta_ns > 0 && tel->wake_jitter_ns * 3 > tel->avg_wake_delta_ns) {
        score += 80;  /* Unpredictable event arrival times = higher entropy */
    }

    /* Component C: Voluntary vs. Involuntary Context Switch Entropy */
    u64 nvcsw_delta = (p->nvcsw >= tel->last_nvcsw) ? (p->nvcsw - tel->last_nvcsw) : 0;
    u64 nivcsw_delta = (p->nivcsw >= tel->last_nivcsw) ? (p->nivcsw - tel->last_nivcsw) : 0;
    if (nvcsw_delta + nivcsw_delta > 4) {
        if (nvcsw_delta > nivcsw_delta * 2)
            score += 100; /* Event/IO/sync driven -> High Entropy */
        else if (nivcsw_delta > nvcsw_delta * 3)
            score -= 140; /* Time-slice preempted cruncher -> Low Entropy */
    }

    /* Component D: AMD Hardware Feedback Interface (`amd_hfi_cpuinfo`) */
    if (enable_hfi_telemetry && tel->hfi_class == 0) {
        score += 150; /* Silicon reports high single-core IPC scaling class */
    }

    if (score > 1000)
        score = 1000;
    tel->entropy_score = score;

    u32 zero = 0;
    struct ryzen350_config *cfg = bpf_map_lookup_elem(&config_map, &zero);
    u32 zen5_thresh = (cfg && cfg->entropy_zen5_threshold > 0)
                      ? cfg->entropy_zen5_threshold
                      : entropy_zen5_threshold;
    u32 golden_thresh = (cfg && cfg->entropy_golden_threshold > 0)
                        ? cfg->entropy_golden_threshold
                        : entropy_golden_threshold;

    if (score >= golden_thresh) {
        if (st)
            __sync_fetch_and_add(&st->high_entropy_classifications, 1);
        return TIER_ZEN5_GOLDEN;
    } else if (score >= zen5_thresh) {
        if (st)
            __sync_fetch_and_add(&st->high_entropy_classifications, 1);
        return TIER_ZEN5_STRICT;
    } else {
        if (st)
            __sync_fetch_and_add(&st->low_entropy_classifications, 1);
        return TIER_ZEN5C_DENSE;
    }
}

static __always_inline s32 try_pick_idle_from_list(const struct task_struct *p, const s32 *cpus, int cnt)
{
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (i >= cnt)
            break;
        s32 c = cpus[i];
        if (cpu_allowed(p, c) && scx_bpf_test_and_clear_cpu_idle(c))
            return c;
    }
    return -1;
}

s32 BPF_STRUCT_OPS(ryzen350_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    (void)ctx;
    (void)wake_flags;
    u32 zero = 0;
    struct ryzen350_stats *st = bpf_map_lookup_elem(&stats_map, &zero);
    struct task_Telemetry *tel = bpf_task_storage_get(&task_telemetry_map, p, 0,
                                                      BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (tel) {
        u64 now = bpf_ktime_get_ns();
        if (tel->last_wake_at_ns > 0 && now > tel->last_wake_at_ns) {
            u64 delta_ns = now - tel->last_wake_at_ns;
            if (tel->avg_wake_delta_ns == 0) {
                tel->avg_wake_delta_ns = delta_ns;
            } else {
                u64 w_diff = abs_diff_u64(delta_ns, tel->avg_wake_delta_ns);
                tel->wake_jitter_ns = (tel->wake_jitter_ns * 3 + w_diff) >> 2;
                tel->avg_wake_delta_ns = (tel->avg_wake_delta_ns * 3 + delta_ns) >> 2;
            }
            if (delta_ns > 0) {
                u64 inst_hz = 1000000000ULL / delta_ns;
                if (inst_hz > 10000)
                    inst_hz = 10000;
                tel->wake_freq_hz = (tel->wake_freq_hz * 3 + inst_hz) >> 2;
            }
        }
        tel->last_wake_at_ns = now;
    }

    /*
     * 0. ZERO-FRICTION PER-CPU KTHREAD FAST-PATH:
     *    Tasks strictly bound to a single CPU (e.g., kworker/u, migration/N, rcuop)
     *    must dispatch directly to SCX_DSQ_LOCAL on prev_cpu without entering shared DSQs.
     */
    if (p->nr_cpus_allowed == 1 && cpu_allowed(p, prev_cpu)) {
        if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
            if (st)
                __sync_fetch_and_add(&st->direct_idle_hits, 1);
            dsq_insert_compat(p, SCX_DSQ_LOCAL, zen5_slice_ns, 0);
        }
        return prev_cpu;
    }

    u32 tier = classify_task_by_entropy(p, tel, st);
    if (tel)
        tel->tier = tier;

    s32 cpu = -1;

    if (tier == TIER_ZEN5_GOLDEN || tier == TIER_ZEN5_STRICT) {
        /*
         * HIGH-ENTROPY FLOW (Zen 5 — CPUs 4,6 -> 2,0 -> 12,14,10,8):
         * 1. L1/L2 Cache Continuity: Prefer prev_cpu first if it is an idle Zen 5 primary core!
         *    If prev_cpu was a Low-Entropy Zen 5c core (1,3,5,7,9,11,13,15),
         *    NEVER keep it there — migrate immediately to a High-Entropy Zen 5 core!
         */
        if (tier == TIER_ZEN5_GOLDEN && is_zen5_golden_cpu(prev_cpu) &&
            cpu_allowed(p, prev_cpu) && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
            cpu = prev_cpu;
        } else if (is_zen5_primary_cpu(prev_cpu) &&
                   cpu_allowed(p, prev_cpu) && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
            cpu = prev_cpu;
        }

        /* 2. Peak-Entropy Golden Zen 5 physical cores (4, 6 - CPPC 208) */
        if (cpu < 0)
            cpu = try_pick_idle_from_list(p, zen5_golden_order, 2);

        /* 3. High-Entropy Silver/Base Zen 5 physical cores (2, 0 - CPPC 202/196) */
        if (cpu < 0)
            cpu = try_pick_idle_from_list(p, zen5_silver_order, 2);

        /* 4. Warm L2 Cache Continuity on Zen 5 SMT before scanning cold Zen 5 SMT siblings */
        if (cpu < 0 && is_zen5_cpu(prev_cpu) &&
            cpu_allowed(p, prev_cpu) && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
            cpu = prev_cpu;
        }

        /* 5. High-Entropy Zen 5 SMT siblings (12, 14, 10, 8) BEFORE ever touching Zen 5c! */
        if (cpu < 0)
            cpu = try_pick_idle_from_list(p, zen5_smt_order, 4);

        if (cpu >= 0) {
            if (st) {
                __sync_fetch_and_add(&st->direct_idle_hits, 1);
                if (is_zen5c_cpu(prev_cpu))
                    __sync_fetch_and_add(&st->zen5c_spill_prevented, 1);
            }
            dsq_insert_compat(p, SCX_DSQ_LOCAL, zen5_slice_ns, 0);
            return cpu;
        }

        return is_zen5_cpu(prev_cpu) ? prev_cpu : 4;
    } else {
        /*
         * LOW-ENTROPY LAMINAR FLOW (Zen 5c — CPUs 1,3,5,7 then 9,11,13,15):
         * Keep steady-state throughput/background threads on Dense Zen 5c cores.
         */
        if (is_zen5c_cpu(prev_cpu) && cpu_allowed(p, prev_cpu) &&
            scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
            cpu = prev_cpu;
        }
        if (cpu < 0)
            cpu = try_pick_idle_from_list(p, zen5c_primary_order, 4);
        if (cpu < 0)
            cpu = try_pick_idle_from_list(p, zen5c_smt_order, 4);

        if (cpu >= 0) {
            if (st)
                __sync_fetch_and_add(&st->direct_idle_hits, 1);
            dsq_insert_compat(p, SCX_DSQ_LOCAL, zen5c_slice_ns, 0);
            return cpu;
        }
        return is_zen5c_cpu(prev_cpu) ? prev_cpu : 1;
    }
}

void BPF_STRUCT_OPS(ryzen350_enqueue, struct task_struct *p, u64 enq_flags)
{
    (void)ctx;
    u32 zero = 0;
    struct ryzen350_stats *st = bpf_map_lookup_elem(&stats_map, &zero);

    /* Per-CPU bound kthreads/tasks go directly to their local DSQ to prevent cross-CPU DSQ head-of-line blocking */
    if (p->nr_cpus_allowed == 1) {
        dsq_insert_compat(p, SCX_DSQ_LOCAL, zen5_slice_ns, enq_flags);
        return;
    }

    struct task_Telemetry *tel = bpf_task_storage_get(&task_telemetry_map, p, 0,
                                                      BPF_LOCAL_STORAGE_GET_F_CREATE);
    u32 tier = tel ? tel->tier : TIER_AUTO;
    if (tier == TIER_AUTO)
        tier = classify_task_by_entropy(p, tel, st);

    u64 allowed = p->cpus_mask.bits[0];

    /* Honor explicit user cpuset/affinity masks if restricted to a single domain */
    if ((allowed & ZEN5_ALL_MASK) == 0) {
        dsq_insert_compat(p, DSQ_ZEN5C_DENSE, zen5c_slice_ns, enq_flags);
        if (st)
            __sync_fetch_and_add(&st->zen5c_dense_dispatches, 1);
        return;
    }
    if ((allowed & ZEN5C_ALL_MASK) == 0 && tier == TIER_ZEN5C_DENSE) {
        tier = TIER_ZEN5_STRICT;
    }

    if (tier == TIER_ZEN5_GOLDEN) {
        dsq_insert_compat(p, DSQ_ZEN5_GOLDEN, zen5_slice_ns, enq_flags);
        if (st)
            __sync_fetch_and_add(&st->zen5_golden_dispatches, 1);
        s32 prev_c = scx_bpf_task_cpu(p);
        s32 pref_c = (p->pid & 1) ? 6 : 4;
        s32 alt_c = (pref_c == 6) ? 4 : 6;
        s32 kick_c = (is_zen5_golden_cpu(prev_c) && cpu_allowed(p, prev_c)) ? prev_c
                   : (cpu_allowed(p, pref_c) ? pref_c
                   : (cpu_allowed(p, alt_c) ? alt_c : -1));
        if (kick_c >= 0)
            scx_bpf_kick_cpu(kick_c, SCX_KICK_IDLE | SCX_KICK_PREEMPT);
    } else if (tier == TIER_ZEN5_STRICT) {
        dsq_insert_compat(p, DSQ_ZEN5_PRIMARY, zen5_slice_ns, enq_flags);
        if (st)
            __sync_fetch_and_add(&st->zen5_primary_dispatches, 1);
    } else {
        dsq_insert_compat(p, DSQ_ZEN5C_DENSE, zen5c_slice_ns, enq_flags);
        if (st)
            __sync_fetch_and_add(&st->zen5c_dense_dispatches, 1);
    }
}

void BPF_STRUCT_OPS(ryzen350_dispatch, s32 cpu, struct task_struct *prev)
{
    (void)ctx;
    (void)prev;
    if (is_zen5_golden_cpu(cpu)) {
        /* Peak-Entropy Golden Zen 5 cores (4, 6) */
        if (dsq_move_to_local_compat(DSQ_ZEN5_GOLDEN))
            return;
        if (dsq_move_to_local_compat(DSQ_ZEN5_PRIMARY))
            return;
        if (dsq_move_to_local_compat(DSQ_ZEN5_SMT))
            return;
        dsq_move_to_local_compat(DSQ_ZEN5C_DENSE);
    } else if (is_zen5_primary_cpu(cpu)) {
        /* High-Entropy Silver/Base Zen 5 physical cores (2, 0) */
        if (dsq_move_to_local_compat(DSQ_ZEN5_PRIMARY))
            return;
        if (dsq_move_to_local_compat(DSQ_ZEN5_GOLDEN))
            return;
        if (dsq_move_to_local_compat(DSQ_ZEN5_SMT))
            return;
        dsq_move_to_local_compat(DSQ_ZEN5C_DENSE);
    } else if (is_zen5_cpu(cpu)) {
        /* High-Entropy Zen 5 SMT Siblings (8, 10, 12, 14): Absorb High-Entropy overflow! */
        if (dsq_move_to_local_compat(DSQ_ZEN5_GOLDEN))
            return;
        if (dsq_move_to_local_compat(DSQ_ZEN5_PRIMARY))
            return;
        if (dsq_move_to_local_compat(DSQ_ZEN5_SMT))
            return;
        dsq_move_to_local_compat(DSQ_ZEN5C_DENSE);
    } else {
        /*
         * Low-Entropy Zen 5c Dense Cores (1, 3, 5, 7, 9, 11, 13, 15):
         * In Strict Easy Mode (`strict_zen5_fence == true`), Low-Entropy Zen 5c cores
         * NEVER pull from `DSQ_ZEN5_GOLDEN` or `DSQ_ZEN5_PRIMARY`!
         */
        if (dsq_move_to_local_compat(DSQ_ZEN5C_DENSE))
            return;
        if (!strict_zen5_fence) {
            if (dsq_move_to_local_compat(DSQ_ZEN5_SMT))
                return;
            dsq_move_to_local_compat(DSQ_ZEN5_PRIMARY);
        }
    }
}

void BPF_STRUCT_OPS(ryzen350_running, struct task_struct *p)
{
    (void)ctx;
    s32 cpu = scx_bpf_task_cpu(p);
    u32 zero = 0;
    struct ryzen350_stats *st = bpf_map_lookup_elem(&stats_map, &zero);
    struct ryzen350_config *cfg = bpf_map_lookup_elem(&config_map, &zero);

    if (st && cpu >= 0 && cpu < MAX_CPUS)
        __sync_fetch_and_add(&st->cpu_dispatches[cpu], 1);

    struct task_Telemetry *tel = bpf_task_storage_get(&task_telemetry_map, p, 0,
                                                      BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (tel)
        tel->last_run_at_ns = bpf_ktime_get_ns();

    /*
     * DEMAND-EXACT CPPC SCALING WITH UPPER-BARRIER SHIELD:
     * Calculate exact required performance level (0..1024) for this task's entropy
     * and runtime demand, strictly clamped at the V/F Efficiency Knee so the core
     * gets ONLY what is required without hitting the cubic 1.38V Upper Barrier!
     */
    if (boost_zen5_cppc && bpf_ksym_exists(scx_bpf_cpuperf_set) && cpu >= 0 && cpu < 16) {
        bool on_bat = cfg && cfg->on_battery;
        u32 score = tel ? tel->entropy_score : 500;
        u32 req_perf;

        if (is_zen5_cpu(cpu)) {
            u32 barrier_cap = (cfg && cfg->zen5_barrier_cap > 0)
                              ? cfg->zen5_barrier_cap
                              : (on_bat ? ZEN5_BARRIER_CAP_BAT : ZEN5_BARRIER_CAP_AC);
            /* Scale proportionally between nominal (380 -> 2.0 GHz) and barrier_cap (825 -> 4.36 GHz) */
            if (barrier_cap <= 380U) {
                req_perf = barrier_cap;
            } else {
                req_perf = 380U + ((score * (barrier_cap - 380U)) / 1000U);
            }
            if (req_perf >= barrier_cap) {
                req_perf = barrier_cap;
                if (st)
                    __sync_fetch_and_add(&st->upper_barrier_clamps, 1);
            }
        } else {
            u32 barrier_cap = (cfg && cfg->zen5c_barrier_cap > 0)
                              ? cfg->zen5c_barrier_cap
                              : (on_bat ? ZEN5C_BARRIER_CAP_BAT : ZEN5C_BARRIER_CAP_AC);
            /* Scale Low-Entropy Zen 5c between 360 (1.23 GHz) and barrier_cap (858 -> 3.01 GHz) */
            if (barrier_cap <= 360U) {
                req_perf = barrier_cap;
            } else {
                req_perf = 360U + ((score * (barrier_cap - 360U)) / 600U);
            }
            if (req_perf >= barrier_cap) {
                req_perf = barrier_cap;
                if (st)
                    __sync_fetch_and_add(&st->upper_barrier_clamps, 1);
            }
        }

        if (tel)
            tel->req_cpuperf = req_perf;
        scx_bpf_cpuperf_set(cpu, req_perf);
    }
}

void BPF_STRUCT_OPS(ryzen350_stopping, struct task_struct *p, bool runnable)
{
    (void)ctx;
    (void)runnable;
    struct task_Telemetry *tel = bpf_task_storage_get(&task_telemetry_map, p, 0, 0);
    if (!tel)
        return;

    u32 zero = 0;
    struct ryzen350_stats *st = bpf_map_lookup_elem(&stats_map, &zero);
    s32 cpu = scx_bpf_task_cpu(p);

    u64 now = bpf_ktime_get_ns();
    if (tel->last_run_at_ns > 0 && now > tel->last_run_at_ns) {
        u64 delta = now - tel->last_run_at_ns;
        if (tel->avg_runtime_ns == 0) {
            tel->avg_runtime_ns = delta;
        } else {
            u64 r_diff = abs_diff_u64(delta, tel->avg_runtime_ns);
            tel->runtime_jitter_ns = (tel->runtime_jitter_ns * 3 + r_diff) >> 2;
            tel->avg_runtime_ns = (tel->avg_runtime_ns * 3 + delta) >> 2;
        }

        /*
         * PER-INSTRUCTION & PER-SLICE MATHEMATICAL ENERGY ENGINE (Fixed-Point):
         *   1. req_perf (0..1024) -> Frequency f_mhz
         *   2. Cycles = (delta_ns * f_mhz) / 1000
         *   3. IPC_x100 = 225 on Zen 5 (high-entropy), 190 on Zen 5c (low-entropy)
         *   4. Instructions = (Cycles * IPC_x100) / 100
         *   5. Voltage V_mv = 660 + (req_perf * 460) / 1024
         *   6. E_instr (pJ/instr) = (C_eff_x100 * V_mv^2) / (100000 * IPC_x100)
         */
        u64 perf = tel->req_cpuperf ? tel->req_cpuperf : 750ULL;
        bool zen5 = is_zen5_cpu(cpu);
        u64 max_mhz = zen5 ? 5091ULL : 3506ULL;
        u64 f_mhz = (max_mhz * perf) >> 10;
        if (f_mhz < 623ULL)
            f_mhz = 623ULL;

        u64 cycles = (delta * f_mhz) / 1000ULL;
        u64 ipc_x100 = zen5 ? 225ULL : 190ULL;
        u64 instrs = (cycles * ipc_x100) / 100ULL;

        u64 v_mv = 660ULL + ((perf * 460ULL) >> 10);
        if (zen5 && perf > 825ULL) {
            u64 d = perf - 825ULL;
            v_mv += (d * d) / 140ULL; /* Quadratic upper-barrier overdrive above 4.36 GHz knee */
        } else if (!zen5 && perf > 858ULL) {
            u64 d = perf - 858ULL;
            v_mv += (d * d) / 200ULL; /* Quadratic upper-barrier overdrive above 3.01 GHz knee */
        }
        u64 c_eff_x100 = zen5 ? 118ULL : 86ULL; /* 1.18 nF Zen 5 vs 0.86 nF Zen 5c */
        u64 e_pj_per_instr = (c_eff_x100 * v_mv * v_mv) / (1000ULL * ipc_x100);
        if (e_pj_per_instr < 10ULL)
            e_pj_per_instr = 10ULL;

        /* Unclamped upper-barrier energy (5.09 GHz @ 1380 mV -> ~998 pJ/instr on Zen 5) */
        u64 barrier_pj = zen5 ? 998ULL : 640ULL;
        u64 slice_energy_nj = (instrs * e_pj_per_instr) / 1000ULL;

        tel->est_instructions += instrs;
        tel->est_energy_nj += slice_energy_nj;
        tel->energy_pj_per_instr = (u32)e_pj_per_instr;

        if (st && barrier_pj > e_pj_per_instr) {
            u64 saved_nj = (instrs * (barrier_pj - e_pj_per_instr)) / 1000ULL;
            __sync_fetch_and_add(&st->total_energy_Saved_uj, saved_nj / 1000ULL);
        }
    }

    tel->last_nvcsw = p->nvcsw;
    tel->last_nivcsw = p->nivcsw;

    /* Sample AMD HFI hardware workload class from per-CPU amd_hfi_cpuinfo */
    if (enable_hfi_telemetry && bpf_ksym_exists(&amd_hfi_cpuinfo)) {
        const struct amd_hfi_cpuinfo *hfi = bpf_this_cpu_ptr(&amd_hfi_cpuinfo);
        if (hfi) {
            s16 cls = hfi->class_index;
            tel->hfi_class = cls;
            if (cls == 0 && st) {
                __sync_fetch_and_add(&st->hfi_class0_hits, 1);
            }
        }
    }
}

s32 BPF_STRUCT_OPS_SLEEPABLE(ryzen350_init)
{
    (void)ctx;
    s32 err;

    err = scx_bpf_create_dsq(DSQ_ZEN5_GOLDEN, -1);
    if (err)
        return err;
    err = scx_bpf_create_dsq(DSQ_ZEN5_PRIMARY, -1);
    if (err)
        return err;
    err = scx_bpf_create_dsq(DSQ_ZEN5_SMT, -1);
    if (err)
        return err;
    err = scx_bpf_create_dsq(DSQ_ZEN5C_DENSE, -1);
    if (err)
        return err;

    return 0;
}

SEC(".struct_ops.link")
struct sched_ext_ops ryzen350_ops = {
    .select_cpu     = (void *)ryzen350_select_cpu,
    .enqueue        = (void *)ryzen350_enqueue,
    .dispatch       = (void *)ryzen350_dispatch,
    .running        = (void *)ryzen350_running,
    .stopping       = (void *)ryzen350_stopping,
    .init           = (void *)ryzen350_init,
    .flags          = SCX_OPS_ENQ_LAST,
    .timeout_ms     = 5000U,
    .name           = "ryzen350_entropy_easymode",
};
