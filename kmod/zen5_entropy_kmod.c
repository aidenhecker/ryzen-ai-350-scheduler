// SPDX-License-Identifier: GPL-2.0
/*
 * zen5_entropy_kmod.c - Native Ring-0 Linux Kernel Module for AMD Ryzen AI 7 350
 *
 * Directly patches the running Linux 7.3.3 kernel scheduler in Ring 0:
 *   1. Programs per-CPU `cpu_scale` (`arch_scale_cpu_capacity`) across all 16
 *      logical CPUs so the native EEVDF scheduler & `/sys/.../cpu_capacity`
 *      reflect the true asymmetric capacities of:
 *        - Peak-Entropy Golden Zen 5 (CPUs 4, 6   @ CPPC 208) -> capacity 1024
 *        - High-Entropy Silver Zen 5 (CPU  2      @ CPPC 202) -> capacity 994
 *        - High-Entropy Base   Zen 5 (CPU  0      @ CPPC 196) -> capacity 965
 *        - High-Entropy Zen 5 SMT    (CPUs 8..14)             -> capacity 820
 *        - Low-Entropy  Zen 5c Dense (CPUs 1,3,5,7 @ CPPC 135)-> capacity 664
 *        - Low-Entropy  Zen 5c SMT   (CPUs 9..15   @ CPPC 135)-> capacity 512
 *   2. Resolves & invokes `sched_set_itmt_core_prio()` and `sched_set_itmt_support()`
 *      so x86 `SD_ASYM_PACKING` orders cores strictly by Zen 5 > Zen 5 SMT > Zen 5c.
 *   3. Exposes `/proc/zen5_entropy` for live Ring-0 verification.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/arch_topology.h>
#include <asm/processor.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aiden");
MODULE_DESCRIPTION("AMD Ryzen AI 7 350 Ring-0 Entropy Capacity & ITMT Scheduler Module");
MODULE_VERSION("1.0.0");

/* Exported by vmlinux (EXPORT_SYMBOL_GPL) */
DECLARE_PER_CPU(unsigned long, cpu_scale);

static unsigned long orig_cpu_scale[16];
static bool itmt_activated = false;

/* Exact CPPC & Entropy Capacity Tables for AMD Ryzen AI 7 350 */
static const int ryzen350_itmt_prio[16] = {
    /* Primary threads 0..7 (even = Zen 5, odd = Zen 5c) */
    [0]  = 196, /* Zen 5 Base   */
    [1]  = 135, /* Zen 5c Dense */
    [2]  = 202, /* Zen 5 Silver */
    [3]  = 135, /* Zen 5c Dense */
    [4]  = 208, /* Zen 5 Golden #1 */
    [5]  = 135, /* Zen 5c Dense */
    [6]  = 208, /* Zen 5 Golden #2 */
    [7]  = 135, /* Zen 5c Dense */
    /* SMT sibling threads 8..15 (Zen 5 SMT ranked ABOVE Zen 5c Primary!) */
    [8]  = 160, /* Zen 5 Base SMT   (> 135 so Zen 5 SMT beats Zen 5c!) */
    [9]  = 105, /* Zen 5c Dense SMT */
    [10] = 165, /* Zen 5 Silver SMT */
    [11] = 105, /* Zen 5c Dense SMT */
    [12] = 172, /* Zen 5 Golden #1 SMT */
    [13] = 105, /* Zen 5c Dense SMT */
    [14] = 172, /* Zen 5 Golden #2 SMT */
    [15] = 105, /* Zen 5c Dense SMT */
};

static const unsigned long ryzen350_entropy_capacity[16] = {
    [0]  = 965,  /* Zen 5 Base   (196/208 * 1024) */
    [1]  = 664,  /* Zen 5c Dense (135/208 * 1024) */
    [2]  = 994,  /* Zen 5 Silver (202/208 * 1024) */
    [3]  = 664,  /* Zen 5c Dense */
    [4]  = 1024, /* Zen 5 Golden #1 (Peak Entropy) */
    [5]  = 664,  /* Zen 5c Dense */
    [6]  = 1024, /* Zen 5 Golden #2 (Peak Entropy) */
    [7]  = 664,  /* Zen 5c Dense */
    [8]  = 788,  /* Zen 5 Base SMT   (ranked > 664 so Zen 5 SMT absorbs high-entropy overflow) */
    [9]  = 512,  /* Zen 5c Dense SMT */
    [10] = 812,  /* Zen 5 Silver SMT */
    [11] = 512,  /* Zen 5c Dense SMT */
    [12] = 840,  /* Zen 5 Golden #1 SMT */
    [13] = 512,  /* Zen 5c Dense SMT */
    [14] = 840,  /* Zen 5 Golden #2 SMT */
    [15] = 512,  /* Zen 5c Dense SMT */
};

typedef void (*sched_set_itmt_core_prio_fn)(int prio, int core_cpu);
typedef int  (*sched_set_itmt_support_fn)(void);

static void *lookup_sym(const char *name)
{
    struct kprobe kp = {
        .symbol_name = name,
    };
    void *addr = NULL;

    if (register_kprobe(&kp) < 0)
        return NULL;
    addr = kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static int zen5_proc_show(struct seq_file *m, void *v)
{
    int cpu;

    seq_puts(m, "========================================================================\n");
    seq_puts(m, " AMD Ryzen AI 7 350 — Ring-0 Kernel Entropy Capacity & ITMT Status\n");
    seq_puts(m, "========================================================================\n");
    seq_printf(m, " ITMT Asymmetric Packing : %s\n", itmt_activated ? "ACTIVE" : "CAPACITY-ONLY");
    seq_puts(m, "------------------------------------------------------------------------\n");
    seq_puts(m, " CPU | Domain                        | Ring-0 Capacity | ITMT Prio\n");
    seq_puts(m, "------------------------------------------------------------------------\n");

    for_each_online_cpu(cpu) {
        if (cpu >= 16)
            break;
        const char *dom;
        if (cpu == 4 || cpu == 6)
            dom = "Zen 5 Golden  [Peak Entropy]";
        else if (cpu == 0 || cpu == 2)
            dom = "Zen 5 Primary [High Entropy]";
        else if ((cpu & 1) == 0)
            dom = "Zen 5 SMT     [High Entropy]";
        else if (cpu < 8)
            dom = "Zen 5c Dense  [Low Entropy] ";
        else
            dom = "Zen 5c SMT    [Low Entropy] ";

        seq_printf(m, "  %2d | %s |      %4lu       |    %3d\n",
                   cpu, dom, per_cpu(cpu_scale, cpu), ryzen350_itmt_prio[cpu]);
    }
    seq_puts(m, "========================================================================\n");
    return 0;
}

static int zen5_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, zen5_proc_show, NULL);
}

static const struct proc_ops zen5_proc_fops = {
    .proc_open    = zen5_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init zen5_entropy_kmod_init(void)
{
    int cpu;
    sched_set_itmt_core_prio_fn set_prio_fn;
    sched_set_itmt_support_fn set_support_fn;

    pr_info("zen5_entropy_kmod: Initializing Ring-0 Entropy Capacity & ITMT for AMD Ryzen AI 7 350\n");

    set_prio_fn = (sched_set_itmt_core_prio_fn)lookup_sym("sched_set_itmt_core_prio");
    set_support_fn = (sched_set_itmt_support_fn)lookup_sym("sched_set_itmt_support");

    for_each_online_cpu(cpu) {
        if (cpu >= 16)
            break;
        orig_cpu_scale[cpu] = per_cpu(cpu_scale, cpu);
        WRITE_ONCE(per_cpu(cpu_scale, cpu), ryzen350_entropy_capacity[cpu]);

        if (set_prio_fn)
            set_prio_fn(ryzen350_itmt_prio[cpu], cpu);
    }

    if (set_support_fn) {
        int rc = set_support_fn();
        itmt_activated = (rc == 0);
        pr_info("zen5_entropy_kmod: sched_set_itmt_support() returned %d\n", rc);
    }

    proc_create("zen5_entropy", 0444, NULL, &zen5_proc_fops);
    pr_info("zen5_entropy_kmod: Asymmetric cpu_capacity programmed (Zen5=1024..788, Zen5c=664..512)\n");
    return 0;
}

static void __exit zen5_entropy_kmod_exit(void)
{
    int cpu;

    remove_proc_entry("zen5_entropy", NULL);
    for_each_online_cpu(cpu) {
        if (cpu >= 16)
            break;
        if (orig_cpu_scale[cpu] != 0)
            WRITE_ONCE(per_cpu(cpu_scale, cpu), orig_cpu_scale[cpu]);
    }
    pr_info("zen5_entropy_kmod: Restored default cpu_scale capacities and unloaded.\n");
}

module_init(zen5_entropy_kmod_init);
module_exit(zen5_entropy_kmod_exit);
