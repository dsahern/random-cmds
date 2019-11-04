/* 
 * walks /proc and shows process scheduling parameters and
 * cpu and memory affinities.
 *
 * David Ahern <dsahern@gmail.com>
 */

#define _GNU_SOURCE

#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sched.h>
#include <dirent.h>
#include <libgen.h>
#include <errno.h>

static int str_to_int(const char *str, int min, int max, int *value)
{
	int number;
	char *end;

	errno = 0;
	number = (int) strtol(str, &end, 10);

	if ( ((*end == '\0') || (*end == '\n')) && (end != str) &&
	     (errno != ERANGE) && (min <= number) && (number <= max)) {
		*value = number;
		return 0;
	}

	return -1;
}

static const char *policy_int2str(int policy)
{
	const char *str;
	
	switch(policy) {
	case SCHED_OTHER:
		str = "other";
		break;

	case SCHED_FIFO:
		str = "FIFO";
		break;

	case SCHED_RR:
		str = "RR";
		break;

	default:
		str = "<unknown>";
	}

	return str;
}

static int get_sched(pid_t pid, int *policy, int *prio, bool rt_only)
{
	struct sched_param param;

	*policy = sched_getscheduler(pid);
	if (*policy < 0) {
		fprintf(stderr, 
			"failed to get scheduler priority for process %d: %s\n",
			pid, strerror(errno));
		return 0;
	}

	if (rt_only && (policy == SCHED_OTHER))
		return 0;

	if (policy == SCHED_OTHER) {
		errno = 0;
		*prio = getpriority(PRIO_PROCESS, pid);
		if (*prio == -1 && errno != 0) {
			fprintf(stderr,
				"failed to get priority for process %d: %s\n",
				pid, strerror(errno));
			prio = 0;
		}
	} else {
		if (sched_getparam(pid, &param) < 0) {
			fprintf(stderr,
				"failed to get scheduler parameters for process %d: %s\n",
				pid, strerror(errno));
			return 0;
		}
		*prio = param.__sched_priority;
	}

	return 1;
}

static void show_proc(pid_t pid, pid_t pid_main, int policy, int prio)
{
	const char *name = "";
	const char *cpus = "";
	const char *mem = "";
	char fname[PATH_MAX];
	char buf[8192];
	ssize_t len;
	int fd = -1;
	char *nl;

	if (snprintf(fname, sizeof(fname),
		     "/proc/%d/status", pid) >= sizeof(fname)) {
		fprintf(stderr, "fname buffer too small for pid %d\n", pid);
		goto out;
	}

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "failed to open %s: %s\n",
			fname, strerror(errno));
		goto out;
	}

	len = read(fd, buf, sizeof(buf)-1);
	if (len < 0) {
		fprintf(stderr, "failed to read status file for pid %d\n", pid);
		goto out;
	}

	name = strstr(buf, "Name:");
	if (!name) {
		fprintf(stderr, "failed to find name for pid %d\n", pid);
		name = "";
		goto out;
	}
	name += 5; /* strlen("Name:"); */
	while ((*name != '\0') && isspace(*name))
		++name;

	nl = strchr(name, '\n');
	if (nl) {
		char *p = (char *) name;
		int len;

		*nl = '\0';
		len = strlen(name);
		if (len > 20)
			p[19] = '\0';
	} else
		goto out;

	cpus = strstr(nl + 1, "Cpus_allowed_list:");
	if (!cpus) {
		cpus = "<unknown>";
	} else {
		cpus += 18;
		while ((*cpus != '\0') && isspace(*cpus))
			++cpus;

		nl = strchr(cpus, '\n');
		if (nl)
			*nl = '\0';
		else
			goto out;
	}

	mem = strstr(nl + 1, "Mems_allowed_list:");
	if (!mem) {
		mem = "<unknown>";
	} else {
		mem += 18;
		while ((*mem != '\0') && isspace(*mem))
			++mem;

		nl = strchr(mem, '\n');
		if (nl)
			*nl = '\0';
	}
out:
	if (fd >= 0)
		close(fd);

	printf("%6d  %6d  %-20s  %12s  %4d  %16s  %16s\n",
	       pid_main, pid, *name == '\0' ? "unknown" : name,
	       policy_int2str(policy), prio, cpus, mem);
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s -r\n    -r   show only real-time processes\n", prog);
}

int main(int argc, char *argv[])
{
	const char *prog = basename(argv[0]);
	bool real_time_only = 0;
	unsigned int nproc = 0;
	pid_t pid, pid_main;
	const char *pid_str;
	int policy, prio;
	struct dirent *e;
	DIR *proc_dir;
	
	char taskpath[PATH_MAX];
	struct dirent *task_e;
	DIR *task_dir;

	int rc;
	extern int optind, optopt;
	extern char *optarg;

	if ((getuid() != 0) && (geteuid() != 0)) {
		fprintf(stderr,
			"must run as root to retrieve scheduling parameters\n");
		return 1;
	}

	while ((rc = getopt(argc, argv, ":r")) != -1) {
		switch (rc) {
		case 'r':
			real_time_only = 1;
			break;

		default:
			print_usage(prog);
			return 2;
		}
	}

	proc_dir = opendir("/proc");
	if (proc_dir == NULL) {
		perror("Cannot open /proc");
		return 1;
	}

	printf("%6s  %6s  %-20s  %12s  %4s  %16s  %16s\n",
	       "PID", "LWP", "COMM", "POLICY", "PRIO", "CPU MASK", "MEM MASK");

	while ((e = readdir(proc_dir)) != NULL)
	{
		pid_str = e->d_name;
		if ((e->d_type != DT_DIR)  || !isdigit(*pid_str) ||
		    (str_to_int(pid_str, 0, INT_MAX, &pid) != 0)) {
			continue;
		}
	
		if (snprintf(taskpath, sizeof(taskpath), 
			     "/proc/%d/task", pid) >= sizeof(taskpath)) {
			fprintf(stderr, "path too long for process %d\n", pid);
			continue;
		}

		task_dir = opendir(taskpath);
		if (task_dir == NULL) {
			if (get_sched(pid, &policy, &prio, real_time_only)) {
				nproc++;
				show_proc(pid, pid, policy, prio);
			}
			continue;
		}

		pid_main = pid;
		while ((task_e = readdir(task_dir)) != NULL) {
			pid_str = task_e->d_name;
			if (str_to_int(pid_str, 0, INT_MAX, &pid) != 0)
				continue;

			if (get_sched(pid, &policy, &prio, real_time_only)) {
				nproc++;
				show_proc(pid, pid_main, policy, prio);
			}
		}
		closedir(task_dir);
	}

	closedir(proc_dir);

	if (!nproc)
		printf("     ***  no processes to show  ***\n");

	return 0;
}
