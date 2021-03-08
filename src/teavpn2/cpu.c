
#include <sched.h>
#include <unistd.h>
#include <teavpn2/base.h>


static int count_online_cpu(void)
{
	return (int)sysconf(_SC_NPROCESSORS_ONLN);
}


int set_cpu_init(void)
{
	int err;
	int ncpu;
	int tcpu = -1;
	int used = 0;

	cpu_set_t cs;
	cpu_set_t affinity;

	CPU_ZERO(&cs);
	if (unlikely(sched_getaffinity(0, sizeof(cs), &cs) < 0)) {
		err = errno;
		pr_err("sched_getaffinity: " PRERF, PREAR(err));
		prl_notice(4, "Continuing...");
		goto set_nice;
	}

	ncpu = count_online_cpu();
	CPU_ZERO(&affinity);
	for (int i = 0; (i < 128) && (used < 2); i++) {
		if (likely(CPU_ISSET(i, &cs))) {
			used++;
			prl_notice(4, "CPU_SET(%d, &affinity)", i);
			if (tcpu == -1) {
				/*
				 * Give one CPU core for the thread.
				 */
				tcpu = i;
				continue;
			}

			/* CPU core for main process */
			CPU_SET(i, &affinity);
		}
	}

	if (unlikely(sched_setaffinity(0, sizeof(cpu_set_t), &affinity) < 0)) {
		err = errno;
		pr_err("sched_setaffinity: " PRERF, PREAR(err));
	} else {
		if ((used != 2) || (used == ncpu))
			goto set_nice;

		prl_notice(4, "sched_setaffinity() success!");
		prl_notice(4, "You have %d online CPU(s)", ncpu);
		prl_notice(4, "I will only use %d specific CPU(s) to keep cache"
			   " and NUMA locality", used);
	}


set_nice:
	errno = 0;
	/* Unreliable return value, let's just check errno. */
	nice(-20);
	nice(-20);
	err = errno;
	if (unlikely(err != 0)) {
		pr_err("nice: " PRERF, PREAR(err));
		prl_notice(4, "nice is not mandatory, continuing...");
	} else {
		prl_notice(4, "nice(-20) success");
		prl_notice(4, "I am a high priority process now, excellent!");
	}

	return tcpu;
}
