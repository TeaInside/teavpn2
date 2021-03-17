// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/cpu.c
 *
 *  CPU affinity and nice setup
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <sched.h>
#include <unistd.h>
#include <teavpn2/cpu.h>
#include <teavpn2/base.h>


static int count_online_cpu(void)
{
	return (int)sysconf(_SC_NPROCESSORS_ONLN);
}


int optimize_cpu_affinity(int need, struct cpu_ret_info *ret)
{
	int err;
	int ncpu;
	int used = 0;
	cpu_set_t cs;
	cpu_set_t *aff = &ret->affinity;
	char buf[512] = "[", *p = buf + 1;

	CPU_ZERO(&cs);
	if (unlikely(sched_getaffinity(0, sizeof(cs), &cs) < 0)) {
		err = errno;
		pr_err("sched_getaffinity: " PRERF, PREAR(err));
		return -1;
	}

	ncpu = count_online_cpu();
	ret->online = ncpu;
	CPU_ZERO(aff);
	for (int i = 0; (i < CPU_SETSIZE) && (used < need); i++) {
		if (likely(CPU_ISSET(i, &cs))) {
			p += sprintf(p, "%s%d", (used ? ", " : ""), i);
			prl_notice(4, "CPU_SET(%d, &affinity)", i);
			CPU_SET(i, aff);
			used++;
		}
	}

	*p++ = ']';
	*p++ = '\0';

	if (unlikely(sched_setaffinity(0, sizeof(cpu_set_t), aff) < 0)) {
		err = errno;
		pr_err("sched_setaffinity: " PRERF, PREAR(err));
		return -1;
	}

	prl_notice(4, "sched_setaffinity() success!");
	prl_notice(4, "You have %d online CPU(s)", ncpu);

	if (used == need) {
		prl_notice(4, "I will only use specified CPU to keep CPU cache "
			   "hot (used CPUs: %s)", buf);
		prl_notice(4, "This affinity can be overriden by taskset, see: "
			   "man 1 taskset");
	}
	return 0;
}


int optimize_process_priority(int nice_val, struct cpu_ret_info *ret)
{
	int err;
	int nice_ret;

	prl_notice(4, "Call nice(%d)", nice_val);

	errno = 0;
	nice_ret = nice(nice_val);
	err = errno;
	if (unlikely(err != 0)) {
		pr_err("nice(%d): " PRERF, nice_val, PREAR(err));
		return -1;
	}

	prl_notice(4, "nice(%d) success, retval = %d", nice_val, nice_ret);

	if (nice_ret < 0) {
		prl_notice(4, "I am a high priority process now, excellent!");
		prl_notice(4, "This priority can be overriden by renice, see: "
			   "man 1 renice");
	}

	ret->nice = nice_ret;
	return 0;
}
