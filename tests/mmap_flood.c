#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <assert.h>

#define _GNU_SOURCE
#include <fcntl.h>

#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)

#include "utils.h"

void pmemcpy(void *dst, const void *src, size_t cnt);

enum {
	OPCODE_MEMCPY = 0,
	OPCODE_NTSTORE,
	OPCODE_NTZERO,
	OPCODE_CAL_SIMD,
	OPCODE_CAL_SIMD_CACHE,
	OPCODE_CAL_NORMAL_ENHANCED,
	OPCODE_CAL_NORMAL,
	OPCODE_MAX
};

const char *opcode_string[] = {
	"memcpy",
	"ntstore",
	NULL,
};

struct {
	size_t filesize;
	size_t iosize;;
	int threads_num;
	int total_time;
	int opcode;
	int do_random;
	int do_read;
	int do_wc;
	const char *test_dir;
	pid_t tgid;
	int do_verbose;
	char *tag;
} Conf;

struct io_worker_bag {
	pthread_t t;
	int id;
	pid_t tid;
	unsigned long io_nanos;
	volatile long count;
	long prev_count;
	long prev_faults[2];
};

/*
 * Copy from kernel source code
 */
static void __memcpy_flushcache(void *_dst, const void *_src, size_t size)
{
	unsigned long dest = (unsigned long) _dst;
	unsigned long source = (unsigned long) _src;

	/* 4x8 movnti loop */
	while (size >= 32) {
		asm("movq    (%0), %%r8\n"
		    "movq   8(%0), %%r9\n"
		    "movq  16(%0), %%r10\n"
		    "movq  24(%0), %%r11\n"
		    "movnti  %%r8,   (%1)\n"
		    "movnti  %%r9,  8(%1)\n"
		    "movnti %%r10, 16(%1)\n"
		    "movnti %%r11, 24(%1)\n"
		    :: "r" (source), "r" (dest)
		    : "memory", "r8", "r9", "r10", "r11");
		dest += 32;
		source += 32;
		size -= 32;
	}

	/* 1x8 movnti loop */
	while (size >= 8) {
		asm("movq    (%0), %%r8\n"
		    "movnti  %%r8,   (%1)\n"
		    :: "r" (source), "r" (dest)
		    : "memory", "r8");
		dest += 8;
		source += 8;
		size -= 8;
	}

	/* 1x4 movnti loop */
	while (size >= 4) {
		asm("movl    (%0), %%r8d\n"
		    "movnti  %%r8d,   (%1)\n"
		    :: "r" (source), "r" (dest)
		    : "memory", "r8");
		dest += 4;
		source += 4;
		size -= 4;
	}

	/* cache copy for remaining bytes */
	if (size)
		memcpy((void *) dest, (void *) source, size);
}

static __always_inline void memcpy_flushcache(void *dst, const void *src, size_t cnt)
{
	switch (cnt) {
		case 4:
			asm ("movntil %1, %0" : "=m"(*(unsigned int *)dst) : "r"(*(unsigned int *)src));
			return;
		case 8:
			asm ("movntiq %1, %0" : "=m"(*(unsigned long *)dst) : "r"(*(unsigned long *)src));
			return;
		case 16:
			asm ("movntiq %1, %0" : "=m"(*(unsigned long *)dst) : "r"(*(unsigned long *)src));
			asm ("movntiq %1, %0" : "=m"(*(unsigned long *)(dst + 8)) : "r"(*(unsigned long *)(src + 8)));
			return;
	}
	__memcpy_flushcache(dst, src, cnt);
}

static void init_default_conf(void)
{
	Conf.filesize = 256 * 1024 * 1024;
	Conf.iosize = 256;
	Conf.threads_num = 8;
	Conf.total_time = 120; //in seconds
	Conf.opcode = OPCODE_MEMCPY;
	Conf.do_random = 0;
	Conf.do_read = 0;
	Conf.do_wc = 0;
	Conf.test_dir = "./";
	Conf.do_verbose = 0;
	Conf.tag = "test";
}

static void dump_conf(void)
{
	printf("filesize   : %ld\n"\
		   "iosize     : %ld\n"\
		   "thread num : %d\n"\
		   "time       : %d seconds\n"\
		   "test dir   : %s\n"\
		   "opcode     : %s\n"\
		   "random IO  : %d\n"\
		   "rw         : %s\n"\
		   "use wc     : %d\n"\
		   "verbose    : %d\n",
		   Conf.filesize,
		   Conf.iosize,
		   Conf.threads_num,
		   Conf.total_time,
		   Conf.test_dir,
		   opcode_string[Conf.opcode],
		   Conf.do_random,
		   Conf.do_read ? "read" : "write",
		   Conf.do_wc,
		   Conf.do_verbose);
}

static void help(void)
{
	printf("-S filesize(256M)\n"\
		   "-s iosize(256)\n"\
		   "-t thread num(8)\n"\
		   "-T time(120 seconds)\n"\
		   "-d test directory(./)\n"\
		   "-o opcode, 0 (default) memcpy, 1 ntstore\n"\
		   "-r random IO\n"\
		   "-p file prefix tag\n"\
		   "-R do read (write by default)\n"\
		   "-c use write combine(need kernel support)\n"\
		   "-v show verbose information\n"\
		   );
	exit(1);
}

struct mem_op_data {
	void *mem;
	void *work_buf;
	ssize_t slot;
	ssize_t slots_total;
	struct ioflood_rand rand;
};

static void mem_do_copy(struct mem_op_data *op)
{
	void *src, *dest;

	if (Conf.do_read) {
		src = op->mem + (op->slot * Conf.iosize);
		dest = op->work_buf;
		memcpy(dest, src, Conf.iosize);
		goto out;
	}

	dest = op->mem + (op->slot * Conf.iosize);
	src = op->work_buf;

	switch (Conf.opcode) {
	case OPCODE_MEMCPY:
		memcpy(dest, src, Conf.iosize);
		break;
	case OPCODE_NTSTORE:
		memcpy_flushcache(dest, src, Conf.iosize);
		break;
	default:
		break;
	}

out:
	if (Conf.do_random) {
		op->slot = ioflood_get_rand(&op->rand) % op->slots_total;
	} else {
		op->slot++;
		op->slot = op->slot % op->slots_total;
	}
}

static void* io_worker(void *arg)
{
	struct io_worker_bag *bag = (struct io_worker_bag *)arg;
	int id = bag->id;
	char filename[64];
	void *mem;
	time_t start_time, now;
	struct timespec before_ts, after_ts;
	unsigned long io_nanos = 0;
	int io_lat = Conf.do_verbose > 1;
	int fd, count;
	struct mem_op_data op;
	unsigned long i;

	bag->tid = gettid();
	sprintf(filename, "%s/%s_io_worker_file_%d", Conf.test_dir,  Conf.tag, id);

	fd = open(filename, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		printf("open %s failed due to %s\n", filename, strerror(errno));
		exit(1);
	}

	if (ftruncate(fd, Conf.filesize)) {
		printf("ftruncate %s failed due to %s\n", filename, strerror(errno));
		exit(1);
	}

	mem = mmap(0, Conf.filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		printf("mmap %s failed due to %s\n", filename, strerror(errno));
		exit(1);
	}

	for (i = 0; i < Conf.filesize >> 12; i++) {
		*(long *)(mem + (i << 12)) = 0;
	}

	op.work_buf = (char *)malloc(Conf.iosize);
	memset(op.work_buf, 0, Conf.iosize);

	count = 0;
	op.slots_total = Conf.filesize / Conf.iosize;
	op.mem = mem;

	ioflood_rand_init(&op.rand);

	if (Conf.do_random) {
		op.slot = ioflood_get_rand(&op.rand) % op.slots_total;
	} else {
		op.slot = 0;
	}
	
	start_time = time(NULL);
	while (1) {

		if (io_lat)
			clock_gettime(CLOCK_MONOTONIC, &before_ts);

		mem_do_copy(&op);

		if (io_lat) {
			clock_gettime(CLOCK_MONOTONIC, &after_ts);
			io_nanos += ((after_ts.tv_sec - before_ts.tv_sec) * 1000000000) + (after_ts.tv_nsec - before_ts.tv_nsec);
		}
		count++;
		bag->count = count;
		if (count && (count % 1000 == 0)) {
			now = time(NULL);
			if ((now - start_time) == Conf.total_time)
				break;
		}
	}

	bag->io_nanos = io_nanos;
	munmap(mem, Conf.filesize);
	close(fd);

	return NULL;
}

int main (int argc, char *argv[])
{
	char opt;
	struct io_worker_bag *bags;
	int i, secs;
	long sum, prev, count;

	init_default_conf();

	while ((opt = getopt (argc, argv, "s:S:t:T:l:fo:hrRd:cvp:")) != -1)
	switch (opt) {
	case 't':
		Conf.threads_num = atoi(optarg);
		break;
	case 's':
		Conf.iosize = atoi(optarg);
		break;
	case 'S':
		Conf.filesize = atol(optarg);
		break;
	case 'T':
		Conf.total_time = atoi(optarg);
		break;
	case 'd':
		Conf.test_dir = optarg;
		break;
	case 'o':
		Conf.opcode = atoi(optarg);
		if (Conf.opcode >= OPCODE_MAX)
			help();
		break;
	case 'r':
		Conf.do_random = 1;
		break;
	case 'R':
		Conf.do_read = 1;
		break;
	case 'c':
		Conf.do_wc = 1;
		break;
	case 'v':
		Conf.do_verbose++;
		break;
	case 'p':
		Conf.tag = optarg;
		break;
	default:
		help();
		break;
	}

	dump_conf();

	bags = (struct io_worker_bag *)malloc(Conf.threads_num * sizeof(struct io_worker_bag));

	for (i = 0; i < Conf.threads_num; i++) {
		bags[i].id = i;
		bags[i].count = 0;
		if (pthread_create(&bags[i].t, NULL, io_worker, (void *)(&bags[i]))) {
			printf("create thread failed due to %s\n", strerror(errno));
			exit(1);
		}   
	}

	Conf.tgid = getpid();
	sum = 0;
	prev = 0;
	secs = 0;
	while (secs < Conf.total_time) {
		sleep(1);
		secs++;
		sum = 0;
		if (Conf.do_verbose)
			printf("%7s %10s\n", "Thid", "BW(MiB/s)");
		for (i = 0; i < Conf.threads_num; i++) {
			count = bags[i].count;
			sum += count;
			if (!Conf.do_verbose)
				continue;

			printf("%7d %10ld\n",
					bags[i].tid,
					((count - bags[i].prev_count)* Conf.iosize) / (1024 * 1024));
			bags[i].prev_count = count;
		}
		printf("---------------------------\n");
		printf("Total BW %5ld MiB/s\n", ((sum - prev)* Conf.iosize) / (1024 * 1024));
		prev = sum;
	}

	for (i = 0; i < Conf.threads_num; i++) {
		pthread_join(bags[i].t, NULL);
		if (Conf.do_verbose > 1)
			printf("IO lat %ld ns per %ld Bytes\n",
					bags[i].io_nanos/bags[i].count, Conf.iosize);
	}

	free(bags);
	return(0);
}

