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

#include "../kernel/ctl.h"

#define INFO(fmt, ...) fprintf(stdout, "%s: " fmt, __func__, ##__VA_ARGS__)
#define ERR(fmt, ...) fprintf(stderr, "%s: " fmt, __func__, ##__VA_ARGS__)

enum pmmap_cli_type {
	PMMAP_CLI_MKFS,
	PMMAP_CLI_ADIR,
	PMMAP_CLI_MAX,
};

struct {
	enum pmmap_cli_type type;
	union {
		struct {
			const char *bdev_name;
			long bg_size;
			int log_len;
		} mkfs;

		struct {
			const char *name;
			unsigned sz;
		} adir;
	};
} Conf;

enum {
	OP_HELP = 0,
	OP_CMD,
	OP_BDEVNAME,
	OP_BG_SIZE,
	OP_LOG_LEN,
	OP_NAME,
	OP_SZ,
	OP_MAX,
};

static char *options_help[OP_MAX] = {
	"Show help page",
	"Command: mkfs, adir",
	"mkfs - Device name (pmemX)",
	"mkfs - Block group size (in GiB, 16 by default)",
	"mkfs - Log length ( in MiB, 128 by default)",
	"adir - File name",
	"adir - Aggregated chunk size (pud, pmd), set adir if provide asz, get adir if not",
};

static struct option long_options[] = {
	{"help", no_argument, 0, OP_HELP},
	{"cmd", required_argument, 0, OP_CMD},
	{"bdev", required_argument, 0, OP_BDEVNAME},
	{"bgsz", required_argument, 0, OP_BG_SIZE},
	{"log", required_argument, 0, OP_LOG_LEN},
	{"name", required_argument, 0, OP_NAME},
	{"sz", required_argument, 0, OP_SZ},
	{0, 0, 0, 0},
};

static void help(void)
{
	int i;

	printf("pmmap_cli:\n");
	for (i = 0; i < OP_MAX; i++) {
		printf("--%-10s %s\n", long_options[i].name,
				options_help[long_options[i].val]);
	}
	exit(1);
}

static void parse_options(int argc, char *argv[])
{
	enum pmmap_cli_type type;
	int op;

	Conf.type = type = PMMAP_CLI_MAX;
	while(1) {
		op = getopt_long(argc, argv, "", long_options, NULL);
		if (op == -1)
			break;

		switch (type) {
		case PMMAP_CLI_MAX:
			switch (op) {
			case OP_CMD:
				if (!strcmp(optarg, "mkfs")) {
					Conf.type = type = PMMAP_CLI_MKFS;
					Conf.mkfs.log_len = 129;
					Conf.mkfs.bg_size = 16;
				} else if (!strcmp(optarg, "adir")) {
					Conf.type = type = PMMAP_CLI_ADIR;
					Conf.adir.sz = 0;
				}
				break;
			default:
				help();
				break;
			}
			break;
		case PMMAP_CLI_MKFS:
			switch (op) {
			case OP_BDEVNAME:
				Conf.mkfs.bdev_name = optarg;
				break;
			case OP_BG_SIZE:
				Conf.mkfs.bg_size = atoi(optarg);
				break;
			case OP_LOG_LEN:
				Conf.mkfs.log_len = atoi(optarg);
				break;
			default:
				help();
				break;
			}
			break;
		case PMMAP_CLI_ADIR:
			switch (op) {
			case OP_NAME:
				Conf.adir.name = optarg;
				break;
			case OP_SZ:
				if (!strcmp(optarg, "pmd"))
					Conf.adir.sz = PMMAP_ADIR_SZ_PMD;
				else if (!strcmp(optarg, "pud"))
					Conf.adir.sz = PMMAP_ADIR_SZ_PUD;
				else
					help();
				break;
			default:
				help();
			}
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

	if (!Conf.mkfs.bdev_name) {
		ERR("bdev_name is needed\n");
		return -EINVAL;
	}

	ret = get_bdev_dax(Conf.mkfs.bdev_name, &dax);
	if (ret)
		return ret;

	if (!dax) {
		ERR("%s doesn't support dax\n", Conf.mkfs.bdev_name);
		return -EINVAL;
	}

	if (Conf.mkfs.log_len < 16 || Conf.mkfs.log_len > 512) {
		ERR("invalid log len %d\n", Conf.mkfs.log_len);
		return -EINVAL;
	}

	if (Conf.mkfs.bg_size < 4 || Conf.mkfs.bg_size > 128){
		ERR("invalid block group size %ld\n", Conf.mkfs.bg_size);
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

	sprintf(mkfs.bdev_name, "/dev/%s", Conf.mkfs.bdev_name);

	mkfs.log_len = Conf.mkfs.log_len << 20;
	mkfs.bg_size = Conf.mkfs.bg_size << 30;

	err = ioctl(fd, PMMAP_IOC_MKFS, &mkfs);
	if (err < 0) {
		err = errno;
		ERR("PMMAP_IOC_MKFS failed due to %s\n", strerror(err));
	}

	close(fd);
	return err;
}

static int do_ioctl(const char *name, unsigned int cmd, void *arg)
{
	int fd, err;

	fd = open(name,  O_RDONLY);
	if (fd < 0) {
		err = errno;
		ERR("Open %s failed due to %s\n", name, strerror(err));
		return err;
	}

	err = ioctl(fd, cmd, arg);
	if (err < 0) {
		err = errno;
		ERR("ioctl %x failed due to %d %s\n", cmd, err, strerror(err));
	}

	close(fd);

	return err;
}

static int do_adir_dir(void)
{
	unsigned int sz = Conf.adir.sz;
	struct stat st;
	int err;

	if (lstat(Conf.adir.name, &st)) {
		ERR("%s is not existed\n", Conf.adir.name);
		return -EINVAL;
	}

	if (Conf.adir.sz) {
		if ((st.st_mode & S_IFMT) != S_IFDIR) {
			ERR("%s is not directory\n", Conf.adir.name);
			return -EINVAL;
		}

		err = do_ioctl(Conf.adir.name, PMMAP_IOC_SET_ADIR, (void *)(unsigned long)sz);
		if (err)
			ERR("Set adir(%s) on directory %s failed\n",
					Conf.adir.sz == PMMAP_ADIR_SZ_PMD ? "pmd" : "pud",
					Conf.adir.name);
	} else {
		err = do_ioctl(Conf.adir.name, PMMAP_IOC_GET_ADIR, &sz);
		if (err) {
			ERR("Get adir on directory %s failed\n", Conf.adir.name);
		} else {
			const char *str;
			switch (sz) {
			case PMMAP_ADIR_SZ_NONE:
				str = "none";
				break;
			case PMMAP_ADIR_SZ_PMD:
				str = "pmd";
				break;
			case PMMAP_ADIR_SZ_PUD:
				str = "pud";
				break;
			default:
				str = "invalid";
				break;
			}
			printf("%s\n", str);
		}
	}

	return err;
}

int main(int argc, char *argv[])
{
	int ret;

	parse_options(argc, argv);

	switch (Conf.type) {
	case PMMAP_CLI_MKFS:
		ret = do_mkfs();
		break;
	case PMMAP_CLI_ADIR:
		ret = do_adir_dir();
		break;
	default:
		help();
		break;
	}

	return ret;
}
