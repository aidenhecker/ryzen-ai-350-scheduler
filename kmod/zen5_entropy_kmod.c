// SPDX-License-Identifier: GPL-2.0
/*
 * zen5_entropy_kmod.c - Native Ring-0 Linux Kernel Module for AMD Ryzen AI 7 350
 *
 * Directly programs per-CPU hybrid capacities and x86 ITMT asymmetric packing
 * priorities using the kernel's x86 topology (`cpu_data(cpu).topo.amd_type`)
 * and `arch_set_cpu_capacity()` / `sched_set_itmt_core_prio()` interfaces:
 *   - Peak-Entropy Golden Zen 5 (CPPC 208) -> capacity 1024, prio 208
 *   - High-Entropy Silver Zen 5 (CPPC 202) -> capacity 994,  prio 202
 *   - High-Entropy Base   Zen 5 (CPPC 196) -> capacity 965,  prio 196
 *   - High-Entropy Zen 5 SMT               -> capacity 840..788, prio 172..160
 *   - Low-Entropy  Zen 5c Dense (CPPC 135) -> capacity 664,  prio 135
 *   - Low-Entropy  Zen 5c SMT              -> capacity 512,  prio 105
 *
 * Exposes `/proc/zen5_entropy` for live Ring-0 verification.
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
#include <linux/topology.h>
#include <asm/processor.h>
#include <asm/topology.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aiden Hecker");
MODULE_DESCRIPTION("AMD Ryzen AI 7 350 Ring-0 Entropy Capacity & ITMT Scheduler Module");
MODULE_VERSION("1.1.0");

#define MAX_RYZEN350_CPUS 16

/* Exported by vmlinux (EXPORT_SYMBOL_GPL) */
DECLARE_PER_CPU(unsigned long, cpu_scale);

static unsigned long orig_arch_cap[MAX_RYZEN350_CPUS];
static unsigned long orig_cpu_scale[MAX_RYZEN350_CPUS];
static bool itmt_activated;
static bool hybrid_scale_enabled;

/* Fallback CPPC & Entropy Capacity Tables for AMD Ryzen AI 7 350 */
static const int ryzen350_itmt_prio[MAX_RYZEN350_CPUS] = {
	[0]  = 196, /* Zen 5 Base */
	[1]  = 135, /* Zen 5c Dense */
	[2]  = 202, /* Zen 5 Silver */
	[3]  = 135, /* Zen 5c Dense */
	[4]  = 208, /* Zen 5 Golden #1 */
	[5]  = 135, /* Zen 5c Dense */
	[6]  = 208, /* Zen 5 Golden #2 */
	[7]  = 135, /* Zen 5c Dense */
	[8]  = 160, /* Zen 5 Base SMT (> 135 so Zen 5 SMT beats Zen 5c) */
	[9]  = 105, /* Zen 5c Dense SMT */
	[10] = 165, /* Zen 5 Silver SMT */
	[11] = 105, /* Zen 5c Dense SMT */
	[12] = 172, /* Zen 5 Golden #1 SMT */
	[13] = 105, /* Zen 5c Dense SMT */
	[14] = 172, /* Zen 5 Golden #2 SMT */
	[15] = 105, /* Zen 5c Dense SMT */
};

static const unsigned long ryzen350_entropy_capacity[MAX_RYZEN350_CPUS] = {
	[0]  = 965,  /* Zen 5 Base (196/208 * 1024) */
	[1]  = 664,  /* Zen 5c Dense (135/208 * 1024) */
	[2]  = 994,  /* Zen 5 Silver (202/208 * 1024) */
	[3]  = 664,  /* Zen 5c Dense */
	[4]  = 1024, /* Zen 5 Golden #1 (Peak Entropy) */
	[5]  = 664,  /* Zen 5c Dense */
	[6]  = 1024, /* Zen 5 Golden #2 (Peak Entropy) */
	[7]  = 664,  /* Zen 5c Dense */
	[8]  = 788,  /* Zen 5 Base SMT (> 664 so Zen 5 SMT absorbs overflow) */
	[9]  = 512,  /* Zen 5c Dense SMT */
	[10] = 812,  /* Zen 5 Silver SMT */
	[11] = 512,  /* Zen 5c Dense SMT */
	[12] = 840,  /* Zen 5 Golden #1 SMT */
	[13] = 512,  /* Zen 5c Dense SMT */
	[14] = 840,  /* Zen 5 Golden #2 SMT */
	[15] = 512,  /* Zen 5c Dense SMT */
};

typedef void (*sched_set_itmt_core_prio_fn)(int prio, int core_cpu);
typedef int (*sched_set_itmt_support_fn)(void);
typedef bool (*arch_enable_hybrid_fn)(void);
typedef void (*arch_set_cap_fn)(int cpu, unsigned long cap, unsigned long max_cap,
				unsigned long cap_freq, unsigned long base_freq);
typedef unsigned long (*arch_scale_cap_fn)(int cpu);

static arch_set_cap_fn set_arch_cap_fn;
static arch_scale_cap_fn get_arch_cap_fn;

static void *lookup_sym(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name,
	};
	void *addr;

	if (register_kprobe(&kp) < 0)
		return NULL;
	addr = kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

static bool is_smt_secondary_cpu(int cpu)
{
	return cpumask_first(topology_sibling_cpumask(cpu)) != (unsigned int)cpu;
}

static bool is_zen5c_core(int cpu)
{
	const struct cpuinfo_x86 *c = &cpu_data(cpu);

	if (c->extended_cpuid_level >= 0x80000026)
		return c->topo.amd_type != 0;

	return (cpu & 1) != 0;
}

static int zen5_proc_show(struct seq_file *m, void *v)
{
	int cpu;

	seq_puts(m, "========================================================================\n");
	seq_puts(m, " AMD Ryzen AI 7 350 - Ring-0 Kernel Entropy Capacity & ITMT Status\n");
	seq_puts(m, "========================================================================\n");
	seq_printf(m, " Hybrid Capacity Scaling : %s\n",
		   hybrid_scale_enabled ? "ACTIVE" : "FALLBACK");
	seq_printf(m, " ITMT Asymmetric Packing : %s\n",
		   itmt_activated ? "ACTIVE" : "CAPACITY-ONLY");
	seq_puts(m, "------------------------------------------------------------------------\n");
	seq_puts(m, " CPU | Domain                        | Ring-0 Capacity | ITMT Prio\n");
	seq_puts(m, "------------------------------------------------------------------------\n");

	for_each_online_cpu(cpu) {
		const char *dom;
		unsigned long cap;
		bool smt;
		bool dense;

		if (cpu >= MAX_RYZEN350_CPUS)
			break;

		smt = is_smt_secondary_cpu(cpu);
		dense = is_zen5c_core(cpu);
		if (!dense && !smt && (cpu == 4 || cpu == 6))
			dom = "Zen 5 Golden  [Peak Entropy]";
		else if (!dense && !smt)
			dom = "Zen 5 Primary [High Entropy]";
		else if (!dense)
			dom = "Zen 5 SMT     [High Entropy]";
		else if (!smt)
			dom = "Zen 5c Dense  [Low Entropy] ";
		else
			dom = "Zen 5c SMT    [Low Entropy] ";

		cap = get_arch_cap_fn ? get_arch_cap_fn(cpu) : per_cpu(cpu_scale, cpu);
		seq_printf(m, "  %2d | %s |      %4lu       |    %3d\n",
			   cpu, dom, cap, ryzen350_itmt_prio[cpu]);
	}
	seq_puts(m, "========================================================================\n");
	return 0;
}

static int zen5_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, zen5_proc_show, NULL);
}

static const struct proc_ops zen5_proc_fops = {
	.proc_open	= zen5_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init zen5_entropy_kmod_init(void)
{
	sched_set_itmt_core_prio_fn set_prio_fn;
	sched_set_itmt_support_fn set_support_fn;
	arch_enable_hybrid_fn enable_hybrid_fn;
	int cpu;

	pr_info("zen5_entropy_kmod: Initializing Ring-0 Entropy Capacity & ITMT\n");

	set_prio_fn = lookup_sym("sched_set_itmt_core_prio");
	set_support_fn = lookup_sym("sched_set_itmt_support");
	enable_hybrid_fn = lookup_sym("arch_enable_hybrid_capacity_scale");
	set_arch_cap_fn = lookup_sym("arch_set_cpu_capacity");
	get_arch_cap_fn = lookup_sym("arch_scale_cpu_capacity");

	if (enable_hybrid_fn)
		hybrid_scale_enabled = enable_hybrid_fn();

	for_each_online_cpu(cpu) {
		unsigned long cap;
		int prio;

		if (cpu >= MAX_RYZEN350_CPUS)
			break;

		orig_cpu_scale[cpu] = per_cpu(cpu_scale, cpu);
		if (get_arch_cap_fn)
			orig_arch_cap[cpu] = get_arch_cap_fn(cpu);

		cap = ryzen350_entropy_capacity[cpu];
		prio = ryzen350_itmt_prio[cpu];

		if (set_arch_cap_fn)
			set_arch_cap_fn(cpu, cap, SCHED_CAPACITY_SCALE, 1, 1);

		WRITE_ONCE(per_cpu(cpu_scale, cpu), cap);

		if (set_prio_fn)
			set_prio_fn(prio, cpu);
	}

	if (set_support_fn) {
		int rc = set_support_fn();

		itmt_activated = (rc == 0);
		pr_info("zen5_entropy_kmod: sched_set_itmt_support() returned %d\n", rc);
	}

	proc_create("zen5_entropy", 0444, NULL, &zen5_proc_fops);
	pr_info("zen5_entropy_kmod: Asymmetric capacity active (Zen5=1024..788, Zen5c=664..512)\n");
	return 0;
}

static void __exit zen5_entropy_kmod_exit(void)
{
	int cpu;

	remove_proc_entry("zen5_entropy", NULL);
	for_each_online_cpu(cpu) {
		if (cpu >= MAX_RYZEN350_CPUS)
			break;
		if (set_arch_cap_fn && orig_arch_cap[cpu] != 0)
			set_arch_cap_fn(cpu, orig_arch_cap[cpu],
					SCHED_CAPACITY_SCALE, 1, 1);
		if (orig_cpu_scale[cpu] != 0)
			WRITE_ONCE(per_cpu(cpu_scale, cpu), orig_cpu_scale[cpu]);
	}
	pr_info("zen5_entropy_kmod: Restored default cpu capacities and unloaded.\n");
}

module_init(zen5_entropy_kmod_init);
module_exit(zen5_entropy_kmod_exit);
