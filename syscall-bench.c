// SPDX-License-Identifier: MIT
//
// syscall-bench: measure the per-call latency of a few syscalls that EDR/eBPF
// sensors (falcon-sensor-bpf, osquery) hook heavily. The point is not raw
// performance but to expose the interception tax: openat/execve are hooked,
// getpid is essentially not, so (openat - getpid) isolates the hook cost.
//
// One op per invocation; prints a single JSON line. The caller is expected to
// run it several times and keep the minimum (least-interfered estimator).
//
// Deliberately low profile: small default iteration counts, a distinct binary
// name for EDR allowlisting and dashboard filtering, optional CPU pinning to
// get deterministic results.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now_ns(void) {
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static double rusage_ns(const struct rusage *ru) {
	double us = (double)ru->ru_utime.tv_sec * 1e6 + ru->ru_utime.tv_usec;
	double sy = (double)ru->ru_stime.tv_sec * 1e6 + ru->ru_stime.tv_usec;

	return (us + sy) * 1e3;
}

static long bench_getpid(long iters) {
	for (long i = 0; i < iters; i++)
		syscall(SYS_getpid);
	return iters;
}

static long bench_openat(long iters) {
	char path[] = "/dev/shm/power-syscall-bench.XXXXXX";
	int seed = mkstemp(path);

	if (seed < 0) {
		perror("mkstemp");
		return -1;
	}
	for (long i = 0; i < iters; i++) {
		int fd = openat(AT_FDCWD, path, O_RDONLY);

		if (fd < 0) {
			perror("openat");
			close(seed);
			unlink(path);
			return -1;
		}
		close(fd);
	}
	close(seed);
	unlink(path);
	return iters;
}

static long bench_execve(long iters) {
	static const char *prog = "/usr/bin/true";
	char *const argv[] = {(char *)prog, NULL};
	char *const envp[] = {NULL};

	for (long i = 0; i < iters; i++) {
		pid_t pid = fork();

		if (pid < 0) {
			perror("fork");
			return -1;
		}
		if (pid == 0) {
			execve(prog, argv, envp);
			_exit(127);
		}
		int status;

		if (waitpid(pid, &status, 0) < 0) {
			perror("waitpid");
			return -1;
		}
	}
	return iters;
}

static int parse_ulong(unsigned long *u, const char *s) {
	unsigned long val;
	char *endptr;

	if (s == NULL) {
		errno = EINVAL;
		return -1;
	}

	errno = 0;
	val = strtoul(s, &endptr, 10);
	if (errno != 0)
		return -1;
	if (*endptr != '\0') {
		errno = EINVAL;
		return -1;
	}

	*u = val;

	return 0;
}

static int usage(const char *me, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int usage(const char *me, const char *fmt, ...) {
	int ret = EXIT_SUCCESS;
	if (fmt != NULL) {
		va_list ap;
		fprintf(stderr, "error: ");
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
		ret = EXIT_FAILURE;
	}
	fprintf(stderr, "usage: %s [-n iters] <getpid|openat|execve>\n", me);
	return ret;
}

int main(int argc, char **argv) {
	const char *me = argv[0];
	unsigned long iters = 0;
	const char *op;
	int c;

	opterr = 0; // disable getopt default error reporting
	while ((c = getopt(argc, argv, "hn:")) != -1) {
		switch (c) {
		case 'n':
			if (parse_ulong(&iters, optarg) < 0)
				return usage(me, "-n %s: %s", optarg, strerror(errno));
			break;
		case 'h':
			return usage(me, NULL);
		case ':':
			return usage(me, "-%c requires a value", optopt);
		case '?':
			return usage(me, "-%c unknown option", optopt);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1)
		return usage(me, "invalid arguments");

	op = argv[0];

	// Per-op defaults: enough for a stable minimum, small enough to stay a
	// blip. execve is the closest proxy to "compile is slow" (every gcc
	// spawns cc1/as/ld) but also the most expensive and most alarming to an
	// EDR, so keep its count modest.
	long (*run)(long) = NULL;
	long warmup;

	if (!strcmp(op, "getpid")) {
		if (!iters)
			iters = 1000000;
		warmup = iters / 10;
		run = bench_getpid;
	} else if (!strcmp(op, "openat")) {
		if (!iters)
			iters = 200000;
		warmup = iters / 10;
		run = bench_openat;
	} else if (!strcmp(op, "execve")) {
		if (!iters)
			iters = 2000;
		warmup = iters / 10;
		run = bench_execve;
	} else {
		return usage(me, "%s: Unsupported operation", op);
	}

	// warmup (discarded)
	run(warmup);

	struct rusage ru0, ru1, rc0, rc1;

	getrusage(RUSAGE_SELF, &ru0);
	getrusage(RUSAGE_CHILDREN, &rc0);
	double t0 = now_ns();
	long done = run(iters);
	double t1 = now_ns();

	getrusage(RUSAGE_SELF, &ru1);
	getrusage(RUSAGE_CHILDREN, &rc1);

	if (done <= 0)
		return 1;

	double wall = (t1 - t0) / (double)done;
	double cpu_ns = (rusage_ns(&ru1) - rusage_ns(&ru0) + rusage_ns(&rc1) - rusage_ns(&rc0))
		/ (double)done;

	printf("{\"op\":\"%s\",\"iters\":%ld,\"wall_ns\":%.1f,\"cpu_ns\":%.1f}\n",
	       op,
	       done,
	       wall,
	       cpu_ns);
	return 0;
}
