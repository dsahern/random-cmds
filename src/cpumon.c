/* lightweight cpu monitor
 * - works for 5.11 kernel
 */
#include <sys/time.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#define MAX_CPUS   64

#define SYS_STATS_FILE    "/proc/stat"
#define STATS_PERIOD 1000000

static bool skip_idle;

/* data in cpuN lines in /proc/stat
 * numbers are in units of jiffies
 */
struct raw_cpu_stat
{
	unsigned long user;
	unsigned long nice;
	unsigned long system;
	unsigned long idle;
	unsigned long iowait;
	unsigned long irq;
	unsigned long softirq;
	unsigned long steal;
	unsigned long guest;
	unsigned long guest_nice;

	unsigned long sum;

};

struct raw_stats
{
	struct raw_cpu_stat cstat[MAX_CPUS];
};

static int ncpus;

#define USECS_PER_SEC  1000000

static inline void convert_usec_timeval(struct timeval *tv, unsigned int dt)
{
	tv->tv_sec = dt / USECS_PER_SEC;
	tv->tv_usec = dt - tv->tv_sec * USECS_PER_SEC;
}

static int parsestr(char *str, const char *delims, char *fields[], int nmax)
{
	int n;

	if ((str == NULL) || (*str == '\0'))
		return 0;

	n = 0;
	fields[0] = strtok(str, delims);
	while ( (fields[n] != (char *) NULL) && (n < (nmax-1)) ) {
		++n;
		fields[n] = strtok(NULL, delims);
	}

	if ( (n == (nmax - 1)) && (fields[n] != (char *) NULL) )
		++n;

	return n;

}

/* convert string to unsigned long */
static int str_to_ul(const char *str, unsigned long *value)
{
	char *end;

	errno = 0;
	*value = strtoul(str, &end, 10);

	/* entire string should be consumed by conversion
	 * and value should be between min and max
	 */
	if ((*end == '\0') && (end != str) && (errno != ERANGE))
		return 0;

	return -1;
}

/* convert string to unsigned long */
static const char *timestamp(struct timeval tv, char *date, int dlen)
{
	unsigned long msec = tv.tv_usec / 1000;
	struct tm ltime;
	char buf[32];


	memset(date, 0, dlen);

	if (localtime_r(&tv.tv_sec, &ltime)) {
		strftime(date, dlen, "%H:%M:%S", &ltime);
		snprintf(buf, sizeof(buf), ".%03ld", msec);
		strcat(date, buf);
	} else {
		strcpy(date, "unknown");
	}

	return date;
}

static void print_cpu_stats(int cpu, const struct raw_cpu_stat *current,
			    const struct raw_cpu_stat *prev)
{
	float user;
	float nice;
	float system;
	float idle;
	float iowait;
	float irq;
	float softirq;
	float dj;

	/* CPU counters are in jiffies. */
	if (current->sum <= prev->sum)
		return;

	dj = (float) (current->sum - prev->sum);

	user    = ((float)(current->user    - prev->user)    * 100) / dj;
	nice    = ((float)(current->nice    - prev->nice)    * 100) / dj;
	system  = ((float)(current->system  - prev->system)  * 100) / dj;
	idle    = ((float)(current->idle    - prev->idle)    * 100) / dj;
	iowait  = ((float)(current->iowait  - prev->iowait)  * 100) / dj;
	irq     = ((float)(current->irq     - prev->irq)     * 100) / dj;
	softirq = ((float)(current->softirq - prev->softirq) * 100) / dj;

	if (skip_idle && idle == 100.0)
		return;

	printf("%3d %8.1f %8.1f %8.1f %8.1f %8.1f %8.1f %8.1f\n",
		cpu, user, system, nice, iowait, irq, softirq, idle);
}

static void print_stats(const struct raw_stats *current,
			const struct raw_stats *prev)
{
	int i;

	for (i = 0; i < ncpus; ++i)
		print_cpu_stats(i, &current->cstat[i], &prev->cstat[i]);

	printf("\n");
}

static void show_stats_hdr(void)
{
	printf("%3s %8s %8s %8s %8s %8s %8s %8s\n",
		"cpu", "user", "system", "nice", "iowait", "irq",
		"softirq", "idle");
}

static void parse_cpu_stats(struct raw_cpu_stat *cstat, char **fields, int nfields)
{
	if (nfields < 9)
		return;

	if (str_to_ul(fields[1], &cstat->user) ||
	    str_to_ul(fields[2], &cstat->nice) ||
	    str_to_ul(fields[3], &cstat->system) ||
	    str_to_ul(fields[4], &cstat->idle)   ||
	    str_to_ul(fields[5], &cstat->iowait) ||
	    str_to_ul(fields[6], &cstat->irq)    ||
	    str_to_ul(fields[7], &cstat->softirq) ||
	    str_to_ul(fields[8], &cstat->steal))
		return;



	if (nfields > 9) {
	    if (str_to_ul(fields[9], &cstat->guest))
		    return;
	    if (nfields > 10 && str_to_ul(fields[10], &cstat->guest_nice))
		    return;
	    if (nfields > 11) {
		    static int warn_once = 1;

		    if (warn_once) {
		    	fprintf(stderr, "unaccounted for fields in CPU stats\n");
		    	warn_once = 0;
		    }
	    }
	}

	/* all fields converted ok */
	cstat->sum = cstat->user    + cstat->nice   + cstat->system +
	             cstat->idle    + cstat->iowait + cstat->irq +
	             cstat->softirq + cstat->steal  + cstat->guest;
}

static void read_sysstats(struct raw_stats *stats)
{
	static int fd = -1;
	char *fields[12];  /* number expected + 1 */
	char *nl, *line;
	char buf[4096]; 
	int nfields;
	int n;

	memset(stats, 0, sizeof(*stats));

	/* open file if not already open */
	if (fd < 0) {
		fd = open(SYS_STATS_FILE, O_RDONLY);

		/* required file and should be accessible */
		if (fd < 0) {
			fprintf(stderr, "failed to open %s: %d\n", SYS_STATS_FILE, errno);
			exit(1);
		}
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		fprintf(stderr, "lseek failed on %s: %d\n", SYS_STATS_FILE, errno);
		exit(1);
	}

	n = read(fd, buf, sizeof(buf)-1);
	if (n < 0) {
		fprintf(stderr, "read failed on %s: %d\n", SYS_STATS_FILE, errno);
		exit(1);
	}

	buf[n] = '\0';
	line = buf;
	while (1)
	{
		nl = strchr(line, '\n');
		if (nl) *nl = '\0';

		nfields = parsestr(line, " \t", fields, 10);

		/* for now, we only care about the line that starts with cpu
		 * and no number -- ie., the summary line
		 */
		if (strncmp(fields[0], "cpu", 3) == 0) {
			char *str = fields[0] + 3;
			unsigned long c;

			if (str_to_ul(str, &c) == 0 && c < ncpus)
				parse_cpu_stats(&stats->cstat[c], fields,
						nfields);
		}
		
		/* goto next line */
		if (!nl) break;
		line = nl+1;
	}

	return;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s OPTS\n"
	        "\n"
		"    -i                    skip print of idle cpus\n"
	        "    -s sample-interval    time between samples in usec\n"
	        "                          default is %d.\n"
	        , argv0, STATS_PERIOD);
}

static void sighdlr(int sig)
{
}

int main(int argc, char *argv[])
{
	struct raw_stats s1, s2, *current = &s1, *prev = &s2, *tmp;
	unsigned int stats_period = STATS_PERIOD;
	struct itimerval tval = { };
	struct timeval tv_current;
	char date[64];
	int rc;
        extern char *optarg;

	while ((rc = getopt(argc, argv, "his:"))  != -1) {
		switch (rc) {
		case 'i':
			skip_idle = true;
			break;
		case 's':
			stats_period = atoi(optarg);
			if (stats_period == 0) {
				fprintf(stderr, "invalid sample period\n");
				return 1;
			}
			break;
		case 'h':
			usage(argv[0]);
			return 1;
		}
	}

	setlinebuf(stdout);
	ncpus = get_nprocs();

	signal(SIGALRM, sighdlr);

	convert_usec_timeval(&tval.it_interval, stats_period);
	convert_usec_timeval(&tval.it_value, stats_period);
	if (setitimer(ITIMER_REAL, &tval, NULL)) {
		fprintf(stderr, "setitimer failed: %s\n", strerror(errno));
		return 1;
	}

	read_sysstats(prev);
	while (1)
	{
		pause();

		read_sysstats(current);

		gettimeofday(&tv_current, NULL);
		printf("%s\n", timestamp(tv_current, date, sizeof(date)));

		show_stats_hdr();
		print_stats(current, prev);

		/* rotate stats */
		tmp = current;
		current = prev;
		prev = tmp;
	}

	return 0;
}
