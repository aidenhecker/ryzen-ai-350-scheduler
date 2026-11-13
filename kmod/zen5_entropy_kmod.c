// SPDX-License-Identifier: GPL-2.0
/*
 * zen5_entropy_kmod.c - Native Ring-0 Linux Kernel Module for AMD Ryzen AI 7 350
 *
 * Reads per-CPU ACPI CPPC highest/nominal performance capabilities (with
 * static Ryzen AI 7 350 fallback tables), enforces symmetric capacity across
 * SMT siblings (`topology_sibling_cpumask()`), enables x86 hybrid capacity
 * scaling via `arch_enable_hybrid_capacity_scale()` + `arch_set_cpu_capacity()`,
 * updates `topology_set_cpu_scale()` (`/sys/devices/system/cpu/cpuX/cpu_capacity`),
 * programs ITMT core/SMT priorities, and triggers a real scheduler domain rebuild
 * (`x86_topology_update = true` + `rebuild_sched_domains()`) so EEVDF sees
 * `SD_ASYM_CPUCAPACITY`.
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
#include <linux/jump_label.h>
#include <linux/sched.h>
#include <linux/topology.h>
#include <acpi/cppc_acpi.h>
#include <asm/processor.h>
#include <asm/topology.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aiden Hecker");
MODULE_DESCRIPTION("AMD Ryzen AI 7 350 Ring-0 Entropy Capacity & ITMT Scheduler Module");
MODULE_VERSION("1.2.0");

#define MAX_RYZEN350_CPUS	64
#define RYZEN350_TABLE_CPUS	16
#define RYZEN350_NOMINAL_PERF	77UL

/* Exported by vmlinux (EXPORT_SYMBOL_GPL) */
DECLARE_PER_CPU(unsigned long, cpu_scale);

static u32 hw_highest_perf[MAX_RYZEN350_CPUS];
static u32 hw_nominal_perf[MAX_RYZEN350_CPUS];
static u32 max_sys_perf;
static unsigned long orig_arch_cap[MAX_RYZEN350_CPUS];
static unsigned long orig_cpu_scale[MAX_RYZEN350_CPUS];
static int orig_itmt_prio[MAX_RYZEN350_CPUS];
static bool orig_saved[MAX_RYZEN350_CPUS];
static bool has_orig_prio[MAX_RYZEN350_CPUS];
static u64 orig_max_freq_ratio = SCHED_CAPACITY_SCALE;
static bool itmt_activated;
static bool hybrid_scale_enabled;
static bool cppc_live_source;

/* Fallback ACPI CPPC highest_perf values for AMD Ryzen AI 7 350 */
static const u32 fallback_highest_perf[RYZEN350_TABLE_CPUS] = {
	[0]  = 196, /* Zen 5 Base */
	[1]  = 135, /* Zen 5c Dense */
	[2]  = 202, /* Zen 5 Silver */
	[3]  = 135, /* Zen 5c Dense */
	[4]  = 208, /* Zen 5 Golden #1 */
	[5]  = 135, /* Zen 5c Dense */
	[6]  = 208, /* Zen 5 Golden #2 */
	[7]  = 135, /* Zen 5c Dense */
	[8]  = 196, /* Zen 5 Base SMT */
	[9]  = 135, /* Zen 5c Dense SMT */
	[10] = 202, /* Zen 5 Silver SMT */
	[11] = 135, /* Zen 5c Dense SMT */
	[12] = 208, /* Zen 5 Golden #1 SMT */
	[13] = 135, /* Zen 5c Dense SMT */
	[14] = 208, /* Zen 5 Golden #2 SMT */
	[15] = 135, /* Zen 5c Dense SMT */
};

typedef unsigned long (*kallsyms_lookup_fn)(const char *name);
typedef void (*sched_set_itmt_core_prio_fn)(int prio, int core_cpu);
typedef int (*arch_asym_cpu_priority_fn)(int cpu);
typedef int (*sched_set_itmt_support_fn)(void);
typedef bool (*arch_enable_hybrid_fn)(void);
typedef void (*arch_set_cap_fn)(int cpu, unsigned long cap, unsigned long max_cap,
				unsigned long cap_freq, unsigned long base_freq);
typedef void (*topology_set_scale_fn)(unsigned int cpu, unsigned long capacity);
typedef void (*rebuild_sched_domains_fn)(void);

static kallsyms_lookup_fn ksym_lookup_fn;
static arch_set_cap_fn set_arch_cap_fn;
static topology_set_scale_fn topo_set_scale_fn;
static sched_set_itmt_core_prio_fn set_itmt_prio_fn;
static arch_asym_cpu_priority_fn get_itmt_prio_fn;
static bool *sysctl_itmt_ptr;
static bool *x86_topo_update_ptr;
static rebuild_sched_domains_fn rebuild_domains_fn;

static void *kprobe_lookup_text(const char *name)
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

static void *resolve_sym(const char *name)
{
	if (!ksym_lookup_fn)
		return kprobe_lookup_text(name);

	return (void *)ksym_lookup_fn(name);
}

static bool is_smt_secondary_cpu(int cpu)
{
	return cpumask_first(topology_sibling_cpumask(cpu)) != (unsigned int)cpu;
}

static bool is_zen5c_core(int cpu)
{
	const struct cpuinfo_x86 *c = &cpu_data(cpu);

	if (c->extended_cpuid_level >= 0x80000026)
		return c->topo.amd_type != AMD_CPU_TYPE_PERFORMANCE;

	return (cpu & 1) != 0;
}

static int compute_itmt_prio(int cpu)
{
	u32 base = hw_highest_perf[cpu];

	if (!base)
		base = (cpu < RYZEN350_TABLE_CPUS) ?
		       fallback_highest_perf[cpu] :
		       (is_zen5c_core(cpu) ? 135U : 196U);

	if (is_smt_secondary_cpu(cpu))
		return (int)((base * 7U) / 8U);

	return (int)base;
}

static void trigger_sched_domain_rebuild(void)
{
	if (!rebuild_domains_fn)
		return;

	if (x86_topo_update_ptr)
		WRITE_ONCE(*x86_topo_update_ptr, true);

	rebuild_domains_fn();
}

static int zen5_proc_show(struct seq_file *m, void *v)
{
	bool itmt_live = sysctl_itmt_ptr ? READ_ONCE(*sysctl_itmt_ptr) : itmt_activated;
	int cpu;

	seq_puts(m, "==================================================================================\n");
	seq_puts(m, " AMD Ryzen AI 7 350 - Ring-0 Entropy Capacity & ITMT Status\n");
	seq_puts(m, "==================================================================================\n");
	seq_printf(m, " Hybrid Capacity Scaling : %s (sys_max_perf=%u, source=%s)\n",
		   hybrid_scale_enabled ? "ACTIVE" : "FALLBACK",
		   max_sys_perf,
		   cppc_live_source ? "ACPI-CPPC" : "STATIC-TABLE");
	seq_printf(m, " ITMT Asymmetric Packing : %s\n",
		   itmt_live ? "ACTIVE" : "DISABLED");
	seq_puts(m, "----------------------------------------------------------------------------------\n");
	seq_puts(m, " CPU | Domain                        | CPPC | Arch Cap | Sysfs Cap | ITMT Prio\n");
	seq_puts(m, "----------------------------------------------------------------------------------\n");

	for_each_online_cpu(cpu) {
		const char *dom;
		unsigned long arch_cap;
		unsigned long sys_cap;
		int prio;
		bool smt;
		bool dense;

		if (cpu >= MAX_RYZEN350_CPUS)
			break;

		smt = is_smt_secondary_cpu(cpu);
		dense = is_zen5c_core(cpu);
		if (!dense && !smt && hw_highest_perf[cpu] >= max_sys_perf)
			dom = "Zen 5 Golden  [Peak Entropy]";
		else if (!dense && !smt)
			dom = "Zen 5 Primary [High Entropy]";
		else if (!dense)
			dom = "Zen 5 SMT     [High Entropy]";
		else if (!smt)
			dom = "Zen 5c Dense  [Low Entropy] ";
		else
			dom = "Zen 5c SMT    [Low Entropy] ";

		arch_cap = arch_scale_cpu_capacity(cpu);
		sys_cap = READ_ONCE(per_cpu(cpu_scale, cpu));
		prio = get_itmt_prio_fn ? get_itmt_prio_fn(cpu) : compute_itmt_prio(cpu);

		seq_printf(m, "  %2d | %s | %4u |   %4lu   |   %4lu    |    %3d\n",
			   cpu, dom, hw_highest_perf[cpu], arch_cap, sys_cap, prio);
	}
	seq_puts(m, "==================================================================================\n");
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
	struct static_key_false *hybrid_cap_key;
	sched_set_itmt_support_fn set_support_fn;
	arch_enable_hybrid_fn enable_hybrid_fn;
	u64 *max_freq_ratio_ptr;
	u32 min_perf = U32_MAX;
	int live_cppc_cpus = 0;
	int cpu;

	pr_info("zen5_entropy_kmod: Initializing Ring-0 Entropy Capacity & ITMT\n");

	ksym_lookup_fn = kprobe_lookup_text("kallsyms_lookup_name");
	enable_hybrid_fn = resolve_sym("arch_enable_hybrid_capacity_scale");
	set_arch_cap_fn = resolve_sym("arch_set_cpu_capacity");
	topo_set_scale_fn = resolve_sym("topology_set_cpu_scale");
	set_itmt_prio_fn = resolve_sym("sched_set_itmt_core_prio");
	get_itmt_prio_fn = resolve_sym("arch_asym_cpu_priority");
	set_support_fn = resolve_sym("sched_set_itmt_support");
	sysctl_itmt_ptr = resolve_sym("sysctl_sched_itmt_enabled");
	x86_topo_update_ptr = resolve_sym("x86_topology_update");
	rebuild_domains_fn = resolve_sym("rebuild_sched_domains");
	hybrid_cap_key = resolve_sym("arch_hybrid_cap_scale_key");
	max_freq_ratio_ptr = resolve_sym("arch_max_freq_ratio");

	if (max_freq_ratio_ptr)
		orig_max_freq_ratio = READ_ONCE(*max_freq_ratio_ptr);

	for_each_online_cpu(cpu) {
		struct cppc_perf_caps caps;

		if (cpu >= MAX_RYZEN350_CPUS)
			break;

		orig_arch_cap[cpu] = arch_scale_cpu_capacity(cpu);
		orig_cpu_scale[cpu] = READ_ONCE(per_cpu(cpu_scale, cpu));
		if (get_itmt_prio_fn) {
			orig_itmt_prio[cpu] = get_itmt_prio_fn(cpu);
			has_orig_prio[cpu] = true;
		}
		orig_saved[cpu] = true;

		if (cppc_get_perf_caps(cpu, &caps) == 0 &&
		    caps.highest_perf && caps.nominal_perf) {
			hw_highest_perf[cpu] = caps.highest_perf;
			hw_nominal_perf[cpu] = caps.nominal_perf;
			live_cppc_cpus++;
		} else {
			hw_highest_perf[cpu] = (cpu < RYZEN350_TABLE_CPUS) ?
					       fallback_highest_perf[cpu] :
					       (is_zen5c_core(cpu) ? 135U : 196U);
			hw_nominal_perf[cpu] = RYZEN350_NOMINAL_PERF;
		}
	}

	cppc_live_source = (live_cppc_cpus > 0);

	/*
	 * Ensure SMT siblings share identical capacity before deriving
	 * max_sys_perf so SD_SHARE_CPUCAPACITY never disagrees with sibling CPUs.
	 */
	for_each_online_cpu(cpu) {
		const struct cpumask *sib_mask = topology_sibling_cpumask(cpu);
		u32 sib_max = 0;
		int sib;

		if (cpu >= MAX_RYZEN350_CPUS)
			break;

		for_each_cpu(sib, sib_mask) {
			if (sib < MAX_RYZEN350_CPUS && hw_highest_perf[sib] > sib_max)
				sib_max = hw_highest_perf[sib];
		}
		if (!sib_max)
			continue;

		for_each_cpu(sib, sib_mask) {
			if (sib < MAX_RYZEN350_CPUS)
				hw_highest_perf[sib] = sib_max;
		}

		if (sib_max > max_sys_perf)
			max_sys_perf = sib_max;
		if (sib_max < min_perf)
			min_perf = sib_max;
	}

	if (!max_sys_perf || min_perf >= max_sys_perf) {
		pr_warn("zen5_entropy_kmod: No hybrid performance delta detected (min=%u max=%u)\n",
			min_perf, max_sys_perf);
		return -ENODEV;
	}

	if (hybrid_cap_key && static_key_enabled(hybrid_cap_key))
		hybrid_scale_enabled = true;
	else if (enable_hybrid_fn)
		hybrid_scale_enabled = enable_hybrid_fn();

	for_each_online_cpu(cpu) {
		unsigned long cap;
		u32 nom;

		if (cpu >= MAX_RYZEN350_CPUS)
			break;

		nom = hw_nominal_perf[cpu] ? hw_nominal_perf[cpu] : RYZEN350_NOMINAL_PERF;

		if (hybrid_scale_enabled && set_arch_cap_fn)
			set_arch_cap_fn(cpu, hw_highest_perf[cpu], max_sys_perf,
					hw_highest_perf[cpu], nom);

		cap = hybrid_scale_enabled ?
		      arch_scale_cpu_capacity(cpu) :
		      div_u64((u64)hw_highest_perf[cpu] << SCHED_CAPACITY_SHIFT,
			      max_sys_perf);

		if (topo_set_scale_fn)
			topo_set_scale_fn(cpu, cap);
		else
			WRITE_ONCE(per_cpu(cpu_scale, cpu), cap);

		if (set_itmt_prio_fn)
			set_itmt_prio_fn(compute_itmt_prio(cpu), cpu);
	}

	if (set_support_fn) {
		int rc = set_support_fn();

		itmt_activated = (rc == 0);
		pr_info("zen5_entropy_kmod: sched_set_itmt_support() returned %d\n", rc);
	}

	/* Force asym_cpu_capacity_scan() and refresh sg->asym_prefer_cpu */
	trigger_sched_domain_rebuild();

	if (!proc_create("zen5_entropy", 0444, NULL, &zen5_proc_fops))
		pr_warn("zen5_entropy_kmod: Failed to create /proc/zen5_entropy\n");

	pr_info("zen5_entropy_kmod: Active (hybrid=%d itmt=%d source=%s max_perf=%u)\n",
		hybrid_scale_enabled, itmt_activated,
		cppc_live_source ? "ACPI-CPPC" : "STATIC-TABLE",
		max_sys_perf);
	return 0;
}

static void __exit zen5_entropy_kmod_exit(void)
{
	int cpu;

	remove_proc_entry("zen5_entropy", NULL);
	for (cpu = 0; cpu < MAX_RYZEN350_CPUS; cpu++) {
		unsigned long cap;

		if (!orig_saved[cpu] || !cpu_online(cpu))
			continue;

		cap = orig_arch_cap[cpu] ? orig_arch_cap[cpu] : SCHED_CAPACITY_SCALE;
		if (hybrid_scale_enabled && set_arch_cap_fn)
			set_arch_cap_fn(cpu, cap, SCHED_CAPACITY_SCALE,
					orig_max_freq_ratio, SCHED_CAPACITY_SCALE);

		cap = orig_cpu_scale[cpu] ? orig_cpu_scale[cpu] : SCHED_CAPACITY_SCALE;
		if (topo_set_scale_fn)
			topo_set_scale_fn(cpu, cap);
		else
			WRITE_ONCE(per_cpu(cpu_scale, cpu), cap);

		if (set_itmt_prio_fn && has_orig_prio[cpu])
			set_itmt_prio_fn(orig_itmt_prio[cpu], cpu);
	}

	trigger_sched_domain_rebuild();
	pr_info("zen5_entropy_kmod: Restored default cpu capacities and unloaded.\n");
}

module_init(zen5_entropy_kmod_init);
module_exit(zen5_entropy_kmod_exit);
