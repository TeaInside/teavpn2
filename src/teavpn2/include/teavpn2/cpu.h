
#ifndef TEAVPN2__CPU_H
#define TEAVPN2__CPU_H

#include <sched.h>
#include <unistd.h>
#include <teavpn2/base.h>


struct cpu_ret_info {
	int		online;
	int		nice;
	cpu_set_t	affinity;
};


int optimize_cpu_affinity(int need, struct cpu_ret_info *ret);
int optimize_process_priority(int nice_val, struct cpu_ret_info *ret);

#endif /* #ifndef TEAVPN2__CPU_H */
