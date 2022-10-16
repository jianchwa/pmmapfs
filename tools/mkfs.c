#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <linux/types.h>
#include <sys/ioctl.h>

/*
 * Copied from fs/pmmap/ctl.h
 */
#define PMMAP_IOCTL_MAGIC 0x80

struct pmmap_ioc_mkfs {
	char bdev_name[32];
	__u64 bg_size;
	__u32 log_len;
};

#define PMMAP_IOC_MKFS _IOW(PMMAP_IOCTL_MAGIC, 1, struct pmmap_ioc_mkfs)

#define INFO(fmt, ...) fprintf(stdout, "%s: " fmt, __func__, ##__VA_ARGS__)
#define ERR(fmt, ...) fprintf(stderr, "%s: " fmt, __func__, ##__VA_ARGS__)

struct {
	const char *bdev_name;
	unsigned long bg_size;
	unsigned log_len;
} Conf;

enum {
	OP_HELP = 0,
	OP_BDEVNAME,
	OP_BG_SIZE,
	OP_LOG_LEN,
	OP_MAX,
};

static char *options_help[OP_MAX] = {
	"Show help page",
	"Device name (pmemX)",
	"Block group size (in GiB, 16 by default)",
	"Log length ( in MiB, 128 by default)"
};

static struct option long_options[] = {
	{"help", no_argument, 0, OP_HELP},
	{"bdev", required_argument, 0, OP_BDEVNAME},
	{"bgsz", required_argument, 0, OP_BG_SIZE},
	{"log", required_argument, 0, OP_LOG_LEN},
	{0, 0, 0, 0},
};

static void conf_default_init(void)
{
	Conf.log_len = 128;
	Conf.bg_size = 16;
}

static void help(void)
{
	int i;

	printf("pmmap_ctl:\n");
	for (i = 0; i < OP_MAX; i++) {
		printf("--%-10s %s\n", long_options[i].name,
				options_help[long_options[i].val]);
	}
	exit(1);
}

static void parse_options(int argc, char *argv[])
{
	int op;

	while(1) {
		op = getopt_long(argc, argv, "", long_options, NULL);
		if (op == -1)
			break;

		switch (op) {
		case OP_HELP:
			help();
			break;
		case OP_BDEVNAME:
			Conf.bdev_name = optarg;
			break;
		case OP_BG_SIZE:
			Conf.bg_size = atoi(optarg);
			break;
		case OP_LOG_LEN:
			Conf.log_len = atoi(optarg);
			break;
		default:
			help();
			break;
		}
	}
}

static int get_bdev_dax(const char *bdev_name, int *dax)
{
	int fd, ret;
	char name[64];
	char buf[64];

	*dax = 0;
	sprintf(name, "/sys/block/%s/queue/dax", bdev_name);
	fd = open(name, O_RDONLY, S_IRUSR);
	if (fd < 0) {
		ret = errno;
		ERR("Cannot open %s due to %s\n", name, strerror(ret));
		return ret;
	}

	if (read(fd, buf, 64) <= 0) {
		ret = errno;
		ERR("Read failed %s due to %s\n", name, strerror(ret));
		close(fd);
		return ret;
	}

	*dax = atoi(buf);
	close(fd);

	return 0;
}

static int mkfs_check_sanity(void)
{
	int dax;
	int ret;

	if (!Conf.bdev_name) {
		ERR("bdev_name is needed\n");
		return -EINVAL;
	}

	ret = get_bdev_dax(Conf.bdev_name, &dax);
	if (ret)
		return ret;

	if (!dax) {
		ERR("%s doesn't support dax\n", Conf.bdev_name);
		return -EINVAL;
	}

	if (Conf.log_len < 16 || Conf.log_len > 512) {
		ERR("invalid log len %d\n", Conf.log_len);
		return -EINVAL;
	}

	if (Conf.bg_size < 4 || Conf.bg_size > 128){
		ERR("invalid block group size %ld\n", Conf.bg_size);
		return -EINVAL;
	}

	return 0;
}

static int do_mkfs(void)
{
	struct pmmap_ioc_mkfs mkfs;
	int fd;
	int err;

	err = mkfs_check_sanity();
	if (err)
		return err;

	fd = open("/dev/pmmapfs_ctl",  O_RDWR);
	if (fd < 0) {
		err = errno;
		ERR("Open /dev/pmmapfs_ctl failed due to %s\n", strerror(err));
		return err;
	}

	sprintf(mkfs.bdev_name, "/dev/%s", Conf.bdev_name);

	mkfs.log_len = Conf.log_len << 20;
	mkfs.bg_size = Conf.bg_size << 30;

	err = ioctl(fd, PMMAP_IOC_MKFS, &mkfs);
	if (err < 0) {
		err = errno;
		ERR("PMMAP_IOC_MKFS failed due to %s\n", strerror(err));
	}

	close(fd);
	return err;
}

int main(int argc, char *argv[])
{
	int ret;

	conf_default_init();
	parse_options(argc, argv);
	ret = do_mkfs();

	return ret;
}
