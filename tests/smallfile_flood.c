#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#define __USE_GNU
#include <unistd.h>

#define _GNU_SOURCE
#include <fcntl.h>

#include "utils.h"

#define SUCCESS 0
#define FAIL (-1)

struct {
	int threads_num;
	const char *test_dir;
	int dir_num;
	int file_num;
	int done_step;
} Conf;

enum {
	STEP_CREATE_WRITE = 0,
	STEP_REWRITE,
	STEP_READ,
	STEP_DELETE,
	STEP_DONE,
};

const char *step_name[] = {
	"create_write",
	"rewrite",
	"read",
	"delete",
	"done"
};

struct ioworker_step {
	int step;
	int finish;
	pthread_cond_t push;
	pthread_cond_t next;
	pthread_mutex_t lock;
};

struct ioworker_bag {
	pthread_t t;
	int id;
	struct ioworker_step *step;
};

struct dir_info {
	int file_num;
	int created;
};

static void default_conf(void)
{
	Conf.threads_num = 8;
	Conf.test_dir = ".";
	Conf.dir_num = 32;
	Conf.file_num = 1024;
	Conf.done_step = STEP_DONE;
}

static void help(void)
{
	printf("-t threads_num(8)\n"\
			"-d test_dir(.)\n"\
			"-D dir_num(32)\n"\
			"-F file_num(1024)\n"\
			"-s finish step (1 rewrite 2 read 3 delete 4 done)\n");
	exit(0);
}

static int parse(int argc, char *argv[])
{
	char opt;

	while ((opt = getopt (argc, argv, "t:d:hD:F:s:")) != -1)
	switch (opt) {
	case 't':
		Conf.threads_num = atoi(optarg);
		break;
	case 'd':
		Conf.test_dir = optarg;
		break;
	case 'D':
		Conf.dir_num = atoi(optarg);
		break;
	case 'F':
		Conf.file_num = atoi(optarg);
		break;
	case 's':
		Conf.done_step = atoi(optarg);
		break;
	default:
		help();
		break;
	}

	return 0;
}

static unsigned long ms_delta(struct timespec *a, struct timespec *b)
{
	unsigned long ams = a->tv_sec * 1000 + a->tv_nsec / 1000000;
	unsigned long bms = b->tv_sec * 1000 + b->tv_nsec / 1000000;

	return ams - bms;
}

static void drop_cache(void)
{
	int fd;
	char *name = "/proc/sys/vm/drop_caches";

	fd = open(name, O_WRONLY, S_IRUSR|S_IWUSR);
	if (fd < 0) {
		printf("open %s failed due to %s\n",
				name, strerror(errno));
		exit(FAIL);
	}

	if (write(fd, "3", 1) < 0) {
		printf("write %s failed due to %s\n",
				name, strerror(errno));
		exit(FAIL);	
	}

	close(fd);
}

static void sync_fs(void)
{
	int fd;

	fd = open(Conf.test_dir, O_RDONLY, S_IRUSR);
	if (fd < 0) {
		printf("open %s failed due to %s\n",
				Conf.test_dir, strerror(errno));
		exit(FAIL);
	}

	if (syncfs(fd)){
		printf("syncfs %s failed due to %s\n",
				Conf.test_dir, strerror(errno));
		exit(FAIL);
	}

	close(fd);
}

static void wait_step(struct ioworker_step *step)
{
	struct timespec before_ts, after_ts;
	unsigned long ms;

	pthread_mutex_lock(&step->lock);
	while (step->step != Conf.done_step) {
		clock_gettime(CLOCK_MONOTONIC, &before_ts);

		while (step->finish != Conf.threads_num)
			pthread_cond_wait(&step->push, &step->lock);

		sync_fs();
	
		clock_gettime(CLOCK_MONOTONIC, &after_ts);
		ms = ms_delta(&after_ts, &before_ts);
		printf("Step %s take %lds %ldms\n",
				step_name[step->step],
				ms / 1000, ms % 1000);

		drop_cache();
		step->finish = 0;
		step->step++;
		pthread_cond_broadcast(&step->next);
	}
	pthread_mutex_unlock(&step->lock);
}

static int push_step(struct ioworker_step *step)
{
	int done;

	pthread_mutex_lock(&step->lock);
	step->finish++;
	pthread_cond_signal(&step->push);
	pthread_cond_wait(&step->next, &step->lock);
	done = step->step == Conf.done_step;
	pthread_mutex_unlock(&step->lock);

	return done;
}

static void *ioworker(void *arg)
{
	struct ioworker_bag *bag = (struct ioworker_bag *)arg;
	struct stat st = { 0 };
	char dir_name[128];
	char file_name[256];
	struct ioflood_rand rand;
	int i, d, f, fd;
	int total =  Conf.dir_num * Conf.file_num;
	struct dir_info *info;
	struct {
		char *buf;
		int size;
	} ios[4];
	
	ioflood_rand_init(&rand);

	info = (struct dir_info *)malloc(sizeof(*info) * Conf.dir_num);
	for (d = 0; d < Conf.dir_num; d++) {
		info[d].file_num = 0;
		info[d].created = 0;
	}

	for (i = 0; i < 4; i++) {
		ios[i].size = (i + 1) << 12;
		ios[i].buf = (char *)malloc(ios[i].size);
	}

	/*
	 * Step 1
	 * Create the test dir for this ioworker
	 */
	sprintf(dir_name, "%s/ioworker-%d", Conf.test_dir, bag->id);
	if (stat(dir_name, &st))
	    mkdir(dir_name, 0700);

	/*
	 * Step 2
	 * Create the Conf.dir_num directories and each of them has
	 * Conf.file_num files, then write random size between
	 * {4K, 8K, 16K, 32K} data into them.
	 */
	for (i = 0; i < total; i++) {
		do {
			d = ioflood_get_rand(&rand) % Conf.dir_num;
		} while (info[d].file_num >= Conf.file_num);

		if (!info[d].created) {
			sprintf(file_name, "%s/%d.dir", dir_name, d);
	    	if (mkdir(file_name, 0700)) {
				printf("failed to create dir %s due to %s\n",
						file_name, strerror(errno));
				exit(FAIL);
			}
			info[d].created = 1;
		}
		f = info[d].file_num++;

		sprintf(file_name, "%s/%d.dir/%d.file",
				dir_name, d, f);

		fd = open(file_name, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
		if (fd < 0) {
			printf("open %s failed due to %s\n", file_name, strerror(errno));
			exit(FAIL);
		}

		if (write(fd, ios[f % 4].buf, ios[f % 4].size) < 0) {
			printf("write %s failed due to %s\n", file_name, strerror(errno));
			exit(FAIL);
		}
		close(fd);
	}

	if (push_step(bag->step))
		goto out;

	/*
	 * Step 3
	 * Rewrite the files with random iosize between {4K, 8K, 16K, 32K}
	 */
	for (d = 0; d < Conf.dir_num; d++)
		info[d].file_num = 0;

	for (i = 0; i < total; i++) {
		do {
			d = ioflood_get_rand(&rand) % Conf.dir_num;
		} while (info[d].file_num >= Conf.file_num);

		f = info[d].file_num++;

		sprintf(file_name, "%s/%d.dir/%d.file",
				dir_name, d, f);

		fd = open(file_name, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
		if (fd < 0) {
			printf("open %s failed due to %s\n", file_name, strerror(errno));
			exit(FAIL);
		}

		if (write(fd, ios[f % 4].buf, ios[f % 4].size) < 0) {
			printf("write %s failed due to %s\n", file_name, strerror(errno));
			exit(FAIL);
		}
		close(fd);
	}

	if (push_step(bag->step))
		goto out;

	/*
	 * Step 4
	 * read the files with random iosize between {4K, 8K, 16K, 32K}
	 */
	for (d = 0; d < Conf.dir_num; d++)
		info[d].file_num = 0;

	for (i = 0; i < total; i++) {
		do {
			d = ioflood_get_rand(&rand) % Conf.dir_num;
		} while (info[d].file_num >= Conf.file_num);

		f = info[d].file_num++;

		sprintf(file_name, "%s/%d.dir/%d.file",
				dir_name, d, f);

		fd = open(file_name, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
		if (fd < 0) {
			printf("open %s failed due to %s\n", file_name, strerror(errno));
			exit(FAIL);
		}

		if (read(fd, ios[f % 4].buf, ios[f % 4].size) < 0) {
			printf("write %s failed due to %s\n", file_name, strerror(errno));
			exit(FAIL);
		}
		close(fd);
	}

	if (push_step(bag->step))
		goto out;


	/*
	 * Step 5
	 * delete all files and directories
	 */
	for (i = 0; i < total; i++) {
		do {
			d = ioflood_get_rand(&rand) % Conf.dir_num;
		} while (info[d].file_num == 0);

		f = --info[d].file_num;

		sprintf(file_name, "%s/%d.dir/%d.file",
				dir_name, d, f);

		if (remove(file_name)) {
			printf("failed to remove file %s due to %s\n",
					file_name, strerror(errno));
			exit(FAIL);
		}

		if (!info[d].file_num) {
			sprintf(file_name, "%s/%d.dir", dir_name, d);
			if (remove(file_name)) {
				printf("failed to remove dir %s due to %s\n",
						file_name, strerror(errno));
				exit(FAIL);
			}
		}
	}

	push_step(bag->step);

out:
	free(info);
	for (i = 0; i < 4; i++)
		free(ios[i].buf);

	return NULL;
}

int main (int argc, char *argv[])
{
	int i;
	struct ioworker_bag *bags;
	struct ioworker_step step;

	default_conf();

	if (parse(argc, argv))
		return FAIL;

	pthread_cond_init(&step.push, NULL);
	pthread_cond_init(&step.next, NULL);
	pthread_mutex_init(&step.lock, NULL);
	step.finish = 0;
	step.step = STEP_CREATE_WRITE;

	bags = (struct ioworker_bag *)malloc(sizeof(struct ioworker_bag) * Conf.threads_num);
	for (i = 0; i < Conf.threads_num; i++) {
		bags[i].id = i;
		bags[i].step = &step;
		if (pthread_create(&bags[i].t, NULL, ioworker, (void *)(&bags[i]))) {
			printf("create thread failed due to %s\n", strerror(errno));
			exit(FAIL);
		}
	}

	wait_step(&step);

	for (i = 0; i < Conf.threads_num; i++)
		pthread_join(bags[i].t, NULL);

	pthread_cond_destroy(&step.push);
	pthread_cond_destroy(&step.next);
	pthread_mutex_destroy(&step.lock);
	free(bags);
	return 0;
}

