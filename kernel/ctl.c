// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2021 Wang Jianchao
 */

#include "pmmap.h"
#include "ctl.h"

extern int opcode_to_len[];
static int pmmap_ctl_create_file(void *kaddr, u64 dir_ino,
		u64 ino, const char *name, u64 meta_ver, umode_t mode)
{
	struct pmmap_log_record *rec = kaddr;
	struct pmmap_log_create *create = kaddr + sizeof(*rec);
	short fin_len = sizeof(*rec);
	short name_len = strlen(name);
	struct timespec64 now;

	ktime_get_coarse_real_ts64(&now);

	rec->magic = cpu_to_le64(PMMAP_LOG_RECORD_MAGIC);
	rec->ver = cpu_to_le64(meta_ver);
	rec->ino = cpu_to_le64(ino);
	rec->crc = 0;
	rec->opflags = cpu_to_le16(PMMAP_CREATE);
	rec->time = cpu_to_le32(now.tv_sec);

	create->dir_ino = cpu_to_le64(dir_ino);
	create->mode = cpu_to_le16(mode);
	create->name_len = name_len;
	memcpy(create->name, name, name_len);
	create->name[name_len] = 0;
	fin_len += sizeof(*create) + name_len + 1;
	
	fin_len = round_up(fin_len, 64);
	rec->len = cpu_to_le16(fin_len);
	rec->crc = crc32(PMMAP_CRC_SEED, (void *)rec, fin_len);

	arch_wb_cache_pmem(kaddr, fin_len);

	return opcode_to_len[PMMAP_CREATE];
}

/*
 * The kaddr is the address of admin log area
 */
static void pmmap_ctl_create_meta_files(void *kaddr, u64 meta_ver)
{
	umode_t mode = S_IRUSR | S_IXUSR;
	u64 ino = PMMAP_ADMIN_DIR_INO;
	u64 sub_dir[2];
	char buf[32];
	int i;

	kaddr += pmmap_ctl_create_file(kaddr, 0, PMMAP_ADMIN_DIR_INO,
		".admin", meta_ver, mode | S_IFDIR);

	ino++;
	sub_dir[0] = ino;
	sprintf(buf, "%llx", meta_ver);
	kaddr += pmmap_ctl_create_file(kaddr, PMMAP_ADMIN_DIR_INO, ino,
		buf, meta_ver,	mode | S_IFDIR);

	ino++;
	sub_dir[1] = ino;
	sprintf(buf, "%llx", meta_ver - 1);
	kaddr += pmmap_ctl_create_file(kaddr, PMMAP_ADMIN_DIR_INO, ino,
		buf, meta_ver,	mode | S_IFDIR);

	mode = S_IRUSR;
	for (i = 0; i < PMMAP_INODE_HASH_NR; i++) {
		sprintf(buf, "%x", i);

		ino++;
		kaddr += pmmap_ctl_create_file(kaddr, sub_dir[0], ino,
			buf, meta_ver, mode | S_IFREG);

		ino++;
		kaddr += pmmap_ctl_create_file(kaddr, sub_dir[1], ino,
			buf, meta_ver, mode | S_IFREG);
	}
}

static int pmmap_super_format(struct pmmap_super *ps)
{
	struct pmmap_nv_sb *primary = ps->nv_sb.primary;
	struct pmmap_nv_sb *secondary = ps->nv_sb.secondary;
	struct pmmap_nv_sb *in_core = ps->nv_sb.in_core;
	union pmmap_sb_factor factor;

	memset(in_core, 0, sizeof(*in_core));
	in_core->magic = cpu_to_le32(PMMAP_SB_MAGIC);
	in_core->blks_per_grp = cpu_to_le64(1 << ps->blks_per_grp_shift);
	in_core->bg_num = cpu_to_le32(ps->bg_num);
	in_core->last_bg_blks = cpu_to_le64(ps->last_bg_blks);
	in_core->log_len = cpu_to_le32(ps->fs_log_len);

	/*
	 * Use random 64bits values as initial meta_ver to avoid
	 * to replay log of different format.
	 */
	in_core->meta[0].ver = cpu_to_le64(get_random_long());

	factor.val = 0;
	factor.info.crc = crc32(PMMAP_CRC_SEED,
			(void *)in_core, sizeof(*in_core));
	in_core->factor = cpu_to_le64(factor.val);
	memcpy_flushcache(primary, in_core, sizeof(*in_core));
	memcpy_flushcache(secondary, in_core, sizeof(*in_core));

	pmmap_ctl_create_meta_files(ps->meta_kaddr + ps->admin.log_off,
			le64_to_cpu(in_core->meta[0].ver));

	return blkdev_issue_zeroout(ps->bdev,
			ps->fs_log_off >> SECTOR_SHIFT,
			8, GFP_KERNEL, 0);
}

static int pmmap_ctl_mkfs(struct pmmap_ioc_mkfs __user *u)
{
	struct pmmap_super *ps; /* dummy */
	struct pmmap_ioc_mkfs *mkfs;
	long err;

	ps = kzalloc(sizeof(*ps), GFP_KERNEL);
	if (!ps)
		return -ENOMEM;

	mkfs = memdup_user((void __user *)u, sizeof(*mkfs));
	if (IS_ERR(mkfs)) {
		err = PTR_ERR(mkfs);
		goto out_mkfs;
	}

	ps->bdev = blkdev_get_by_path(mkfs->bdev_name,
			FMODE_READ | FMODE_WRITE, NULL);
	if (IS_ERR(ps->bdev)) {
		err = PTR_ERR(ps->bdev);
		goto out_bdev;
	}

	ps->dax_dev = fs_dax_get_by_bdev(ps->bdev);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
	if (!bdev_dax_supported(ps->bdev, PAGE_SIZE)) {
#else
	if (!dax_supported(ps->dax_dev, ps->bdev, PAGE_SIZE, 0,
				bdev_nr_sectors(ps->bdev))) {
#endif
		err = -EINVAL;
		goto out_dax;
	}

	ps->fs_log_len = mkfs->log_len;

	ps->durable = true;
	pmmap_super_calc_cap(ps, mkfs->bg_size >> PAGE_SHIFT);

	err = dax_direct_access(ps->dax_dev, 0,
			PHYS_PFN(PMMAP_META_MAX_LEN),
			(void **)&ps->meta_kaddr, NULL);
	if (err < PHYS_PFN(PMMAP_META_MAX_LEN)) {
		PERR("cannot access metadata of %s due to %ld\n",
				ps->bdev->bd_disk->disk_name, err);
		goto out_access;
	}

	pmmap_meta_layout_init(ps);
	err = pmmap_super_format(ps);

out_access:
	fs_put_dax(ps->dax_dev);
out_dax:
	blkdev_put(ps->bdev, FMODE_WRITE | FMODE_READ);
out_bdev:
	kfree(mkfs);
out_mkfs:
	kfree(ps);
	return err;
}

static int pmmap_ctl_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static long pmmap_ctl_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	ret = -EINVAL;
	switch (cmd) {
	case PMMAP_IOC_MKFS:
		ret = pmmap_ctl_mkfs((struct pmmap_ioc_mkfs __user *)arg);
		break;
	default:
		break;
	}

	return ret;
}

static const struct file_operations pmmap_ctl_fops = {
	.open = pmmap_ctl_open,
	.unlocked_ioctl	 = pmmap_ctl_ioctl,
	.compat_ioctl = pmmap_ctl_ioctl,
	.owner	 = THIS_MODULE,
	.llseek = noop_llseek,
};

static struct miscdevice pmmap_misc = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name		= "pmmapfs_ctl",
	.fops		= &pmmap_ctl_fops
};

int pmmap_ctl_init(void)
{
	return misc_register(&pmmap_misc);
}

void pmmap_ctl_exit(void)
{
	misc_deregister(&pmmap_misc);
}
