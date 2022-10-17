// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2021 Wang Jianchao
 */
#include "pmmap.h"

static struct kobject *pmmap_kobj_root;

struct pmmap_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct pmmap_super *, char *);
	ssize_t (*store)(struct pmmap_super *, const char *, size_t);
};

static ssize_t pmmap_super_show(struct pmmap_super *ps, char *page)
{
	ssize_t ret;

	ret = sprintf(page, "dev name: %s\n", ps->bdev->bd_disk->disk_name);
	ret += sprintf(page + ret, "blks_per_grp: %lu\n", 1UL << ps->blks_per_grp_shift);
	ret += sprintf(page + ret, "last_bg_blks: %llu\n", ps->last_bg_blks);
	ret += sprintf(page + ret, "bg_num: %llu\n", ps->bg_num);
	ret += sprintf(page + ret, "bg_balance: %d\n", ps->bg_balance);
	ret += sprintf(page + ret, "zero_new: %d\n", ps->zero_new);

	return ret;
}

static struct pmmap_sysfs_entry pmmap_super_entry = {
	.attr = {.name = "info", .mode = 0444},
	.show = pmmap_super_show,
};

static ssize_t __alloc_show(struct pmmap_super *ps, char *page)
{
	struct pmmap_stat *stat;
	int i, ret;
	long sum[6];

	memset(sum, 0, sizeof(sum));
	for_each_online_cpu(i) {
		stat = per_cpu_ptr(ps->stats, i);
		sum[0] += stat->levels[0].alloc;
		sum[1] += stat->levels[0].mmap;
		sum[2] += stat->levels[1].alloc;
		sum[3] += stat->levels[1].mmap;
		sum[4] += stat->levels[2].alloc;
		sum[5] += stat->levels[2].mmap;
	}

	ret = sprintf(page, "pud: alloc %ld map %ld\n", sum[4], sum[5]);
	ret += sprintf(page + ret, "pmd: alloc %ld map %ld\n", sum[2], sum[3]);
	ret += sprintf(page + ret, "pte: alloc %ld map %ld\n", sum[0], sum[1]);

	return ret;
}

static ssize_t pmmap_stat_show(struct pmmap_super *ps, char *page)
{
	ssize_t ret;
	
	ret = __alloc_show(ps, page);
	ret += sprintf(page + ret, "max_ino : %lu\n",
				ps->max_ino);

	ret += sprintf(page + ret, "inodes : %llu\n",
			pmmap_count_inodes(ps));

	if (!ps->durable)
		return ret;

	ret += pmmap_meta_stat(ps, page + ret);

	return ret;
}

static struct pmmap_sysfs_entry pmmap_stat_entry = {
	.attr = {.name = "stat", .mode = 0444},
	.show = pmmap_stat_show,
};

static ssize_t pmmap_block_grps_show(struct pmmap_super *ps, char *page)
{
	struct pmmap_block_grp *bg;
	int i, ret;

	ret = 0;
	for (i = 0; i < ps->bg_num; i++) {
		bg = &ps->bgs[i];
		ret += sprintf(page + ret, "#%d PUD %llu PMD %llu PTE %llu\n",
				i, bg->pud.free, bg->pmd.free, bg->pte.free);
	}

	return ret;
}

static struct pmmap_sysfs_entry pmmap_block_grps_entry = {
	.attr = {.name = "bgs", .mode = 0444},
	.show = pmmap_block_grps_show,
};

static ssize_t pmmap_sync_store(struct pmmap_super *ps,
		const char *page, size_t size)
{
	if (!ps->durable)
		return -EOPNOTSUPP;

	pmmap_sync_all_meta(ps);

	return size;
}

static struct pmmap_sysfs_entry pmmap_sync_entry = {
	.attr = {.name = "sync", .mode = 0222},
	.store = pmmap_sync_store,
};

static struct attribute *pmmap_attrs[] = {
	&pmmap_super_entry.attr,
	&pmmap_stat_entry.attr,
	&pmmap_block_grps_entry.attr,
	&pmmap_sync_entry.attr,
	NULL,
};

static ssize_t
pmmap_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct pmmap_sysfs_entry *entry = (struct pmmap_sysfs_entry *)attr;
	struct pmmap_super *ps = container_of(kobj, struct pmmap_super, kobj);

	if (!entry->show)
		return -EIO;

	return entry->show(ps, page);
}

static ssize_t
pmmap_attr_store(struct kobject *kobj, struct attribute *attr,
		    const char *page, size_t length)
{
	struct pmmap_sysfs_entry *entry = (struct pmmap_sysfs_entry *)attr;
	struct pmmap_super *ps = container_of(kobj, struct pmmap_super, kobj);

	if (!entry->store)
		return -EIO;

	return entry->store(ps, page, length);
}

static const struct sysfs_ops pmmap_sysfs_ops = {
	.show	= pmmap_attr_show,
	.store	= pmmap_attr_store,
};

static void pmmap_release(struct kobject *kobj);
static struct kobj_type pmmap_ktype = {
	.sysfs_ops = &pmmap_sysfs_ops,
	.default_attrs = pmmap_attrs,
	.release = pmmap_release,
};

static unsigned long pmmap_default_max_inodes(struct pmmap_super *ps)
{
	/*
	 * In durable mode, massive inodes need very long time to do sync.
	 * Hard code the max number of inodes to 1 million to let the user
	 * know this.
	 */
	if (ps->durable)
		return 1 << 20;
	else
		return min(totalram_pages() - totalhigh_pages(), totalram_pages() / 2);
}

static int pmmap_parse_options(char *options, struct pmmap_super *ps,
			       bool remount)
{
	char *this_char, *value, *rest;
	unsigned long tmp;

	while (options != NULL) {
		this_char = options;
		for (;;) {
			options = strchr(options, ',');
			if (options == NULL)
				break;
			options++;
			if (!isdigit(*options)) {
				options[-1] = '\0';
				break;
			}
		}
		if (!*this_char)
			continue;
		if ((value = strchr(this_char,'=')) != NULL) {
			*value++ = 0;
		} else {
			PERR("No value for mount option '%s'\n",
			       this_char);
			goto error;
		}

		if (!strcmp(this_char, "zeronew")) {
			tmp = !!simple_strtoul(value, &rest, 10);
			if (*rest)
				goto bad_val;
			ps->zero_new = tmp;
		} else if (!strcmp(this_char, "pesz")) {
			if (!strcmp(value, "pte"))
				ps->pesz = PE_SIZE_PTE;
			else if (!strcmp(value, "pmd"))
				ps->pesz = PE_SIZE_PMD;
			else if (!strcmp(value, "pud"))
				ps->pesz = PE_SIZE_PUD;
			else
				goto bad_val;
		} else if (!strcmp(this_char, "durable")) {
			if (remount)
				continue;
			tmp = !!simple_strtoul(value, &rest, 10);
			if (*rest)
				goto bad_val;
			ps->durable = tmp;
		} else {
			PERR("Bad mount option %s\n", this_char);
			goto error;
		}
	}
	return 0;

bad_val:
	PERR("Bad value '%s' for mount option '%s'\n",
	       value, this_char);
error:
	return -EINVAL;

}

static int pmmap_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct pmmap_super *ps = PMMAP_SB(dentry->d_sb);

	buf->f_type = PMMAP_SB_MAGIC;
	buf->f_bsize = PAGE_SIZE;
	buf->f_namelen = NAME_MAX;
	if (ps->dax_dev) {
		buf->f_blocks = ps->blks_total;
		buf->f_bavail = buf->f_bfree = percpu_counter_sum(&ps->free_blks);
	}

	buf->f_files = pmmap_default_max_inodes(ps);
	buf->f_ffree = atomic64_read(&ps->free_inodes);
	/* else leave those fields 0 like simple_statfs */
	return 0;
}

static int pmmap_sync_fs(struct super_block *sb, int wait)
{
	struct pmmap_super *ps = PMMAP_SB(sb);

	if (!wait ||
	    !ps->durable ||
	    test_bit(PMMAP_SUPER_FLAGS_UMOUNT, &ps->flags) ||
	    test_bit(PMMAP_SUPER_FLAGS_MNT_FAIL, &ps->flags) ||
	    test_bit(PMMAP_SUPER_FLAGS_NO_META, &ps->flags)) {
		return 0;
	}

	pmmap_sync_all_meta(ps);

	return 0;
}

static int pmmap_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct pmmap_super *ps = PMMAP_SB(sb);

	pmmap_sync_fs(sb, 1);
	return pmmap_parse_options(data, ps, true);
}

static int pmmap_show_options(struct seq_file *seq, struct dentry *root)
{
	struct pmmap_super *ps = PMMAP_SB(root->d_sb);
	static const char *str[] = { "pte", "pmd", "pud" };

	seq_printf(seq, ",zeronew=%d", ps->zero_new);
	seq_printf(seq, ",pesz=%s", str[ps->pesz]);
	seq_printf(seq, ",durable=%d",ps->durable);

	return 0;
}

static void pmmap_super_exit(struct pmmap_super *ps)
{
	if (ps->durable) {
		flush_work(&ps->defer_free_work);
		pmmap_meta_exit(ps);
	}

	pmmap_hash_workqueue_exit(ps);
	pmmap_alloc_exit(ps);
	percpu_counter_destroy(&ps->free_blks);

	if (ps->stats)
		free_percpu(ps->stats);

	if (ps->dax_dev) {
		fs_put_dax(ps->dax_dev);
		ps->dax_dev = NULL;
	}
}

static void pmmap_release(struct kobject *kobj)
{
	struct pmmap_super *ps = container_of(kobj, struct pmmap_super, kobj);
	pmmap_super_exit(ps);
}

static void pmmap_put_super(struct super_block *sb)
{
	struct pmmap_super *ps = PMMAP_SB(sb);

	if (ps)
		kobject_put(&ps->kobj);

	sb->s_fs_info = NULL;
}

static struct kmem_cache *pmmap_inode_cachep;

static struct inode *pmmap_alloc_inode(struct super_block *sb)
{
	struct pmmap_inode *pino;

	pino = kmem_cache_alloc(pmmap_inode_cachep, GFP_KERNEL);
	if (!pino)
		return NULL;

	return &pino->vfs_inode;
}

static void pmmap_destroy_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct pmmap_inode *pino = PMMAP_I(inode);

	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);

	if (IS_ADIR(pino) && pino->adir)
		pmmap_free_adir(pino->adir);

	kmem_cache_free(pmmap_inode_cachep, PMMAP_I(inode));
}

static void pmmap_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, pmmap_destroy_callback);
}

static const struct super_operations pmmap_ops = {
	.alloc_inode	= pmmap_alloc_inode,
	.destroy_inode	= pmmap_destroy_inode,
	.sync_fs = pmmap_sync_fs,
	.statfs		= pmmap_statfs,
	.remount_fs	= pmmap_remount_fs,
	.show_options	= pmmap_show_options,
	.evict_inode	= pmmap_evict_inode,
	.drop_inode	= generic_delete_inode,
	.put_super	= pmmap_put_super,
};

void pmmap_super_calc_cap(struct pmmap_super *ps, u64 blks_per_grp)
{
	u64 bdev_size, bgsz_shift, last_bg_blks;

	bdev_size = i_size_read(ps->bdev->bd_inode);

	if (!blks_per_grp) {
		blks_per_grp = (bdev_size >> PAGE_SHIFT) / max((num_online_cpus() / nr_node_ids), 64U);
		/*
	 	 * The size of block group must be aligned with 1G except for the last one.
	 	 */
		blks_per_grp = round_up(blks_per_grp, PUD_SIZE / PAGE_SIZE);
		blks_per_grp = roundup_pow_of_two(blks_per_grp);
	}
	ps->blks_per_grp_shift = ilog2(blks_per_grp);
	bgsz_shift = ps->blks_per_grp_shift + PAGE_SHIFT;
	ps->bg_num = bdev_size >> bgsz_shift;
	/*
	 * Decide the size of last bg blks
	 */
	last_bg_blks = bdev_size - (ps->bg_num << bgsz_shift);
	last_bg_blks = round_down(last_bg_blks, PUD_SIZE);
	last_bg_blks = last_bg_blks >> PAGE_SHIFT;
	if (last_bg_blks)
		ps->bg_num++;
	else
		last_bg_blks = 1 << ps->blks_per_grp_shift;

	ps->last_bg_blks = last_bg_blks;

	ps->blks_total = (ps->bg_num - 1) << ps->blks_per_grp_shift;
	ps->blks_total += ps->last_bg_blks;
}

static int pmmap_super_load_cap(struct pmmap_super *ps)
{
	struct pmmap_nv_sb *in_core = ps->nv_sb.in_core;

	if (!pmmap_load_super(ps))
		goto unclean;

	ps->fs_log_len = le32_to_cpu(in_core->log_len);
	ps->meta_len += ps->fs_log_len;

	pmmap_super_calc_cap(ps, le64_to_cpu(in_core->blks_per_grp));
	if (ps->bg_num != le32_to_cpu(in_core->bg_num)) {
		PWARN("calc bg_num (%lld) doesn't match with (%d) in sb\n",
				ps->bg_num, le32_to_cpu(in_core->bg_num));
		goto unclean;
	}
	if (ps->last_bg_blks != le64_to_cpu(in_core->last_bg_blks)) {
		PWARN("calc last_bg_blks (%llx) doesn't match with (%llx) in sb\n",
				ps->last_bg_blks, le64_to_cpu(in_core->last_bg_blks));
		goto unclean;
	}

	return 0;
unclean:
	return -EUCLEAN;
}

static int pmmap_super_config_init(struct pmmap_super *ps, char *data)
{
	long ret;
	int err = 0;
	/*
	 * Configs by default, some ones are set by __GFP_ZERO
	 */
	ps->uid = current_fsuid();
	ps->gid = current_fsgid();
	ps->mode = 0777 | S_ISVTX;
	ps->pesz = PE_SIZE_PMD;
	ps->bg_balance = 2 * (percpu_counter_batch * nr_cpu_ids);
	ps->durable = true;
	ps->hash_wq_cnt = PMMAP_INODE_HASH_NR;

	err = -EINVAL;
	/*
	 * Configs from mount options
	 */
	if (pmmap_parse_options(data, ps, false))
		goto out;

	atomic64_set(&ps->free_inodes, pmmap_default_max_inodes(ps));

	err = -EINVAL;
	ps->dax_dev = fs_dax_get_by_bdev(ps->bdev);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
	if (!bdev_dax_supported(ps->bdev, PAGE_SIZE)) {
#else
	if (!dax_supported(ps->dax_dev, ps->bdev, PAGE_SIZE, 0,
				bdev_nr_sectors(ps->bdev))) {
#endif
	
		PERR("DAX unsupported by block device %s\n",
				ps->bdev->bd_disk->disk_name);
		goto out;
	}

	ps->node_id = ps->bdev->bd_disk->node_id;

	/*
	 * When setup PUD_SIZE mapping, alignment of pfn is required.
	 * However the pfn of the start of the pmem device maybe not
	 * PUD_SIZE aligned. At this moment, any chunk we get cannot
	 * be accepted by the pud fault code. Force the address align
	 * of nvdimm namespace to 1G to make life easier.
	 */
	ret = dax_direct_access(ps->dax_dev, 0,
			PHYS_PFN(PMMAP_META_MAX_LEN),
			(void **)&ps->meta_kaddr, NULL);
	if (ret < PHYS_PFN(PMMAP_META_MAX_LEN)) {
		PERR("cannot access metadata of %s due to %ld\n",
				ps->bdev->bd_disk->disk_name, ret);
		goto out;
	}
	if (round_up((u64)ps->meta_kaddr, PUD_SIZE) - (u64)ps->meta_kaddr != 0) {
		PERR("please configure nvdimm namespace align to 1G\n");
		goto out;
	}

	if (ps->durable) {
		pmmap_meta_layout_init(ps);
		err = pmmap_super_load_cap(ps);
		if (err == -EUCLEAN) {
			PWARN("super block is unclean\n");
			goto out;
		}
	} else {
		pmmap_super_calc_cap(ps, 0);
	}

	err = 0;
out:
	return err;
}

/*
 * Do memory allocation and structure init
 */
int pmmap_super_common_init(struct pmmap_super *ps)
{
	struct super_block *sb = ps->sb;
	int i;

	sb->s_flags |= SB_NOSEC | SB_LAZYTIME;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = PMMAP_SB_MAGIC;
	sb->s_op = &pmmap_ops;
	sb->s_time_gran = 1;
	uuid_gen(&sb->s_uuid);

	ps->flags = 0;
	ps->stats = alloc_percpu(struct pmmap_stat);
	if (!ps->stats)
		return -ENOMEM;

	if (percpu_counter_init(&ps->free_blks, ps->blks_total, GFP_KERNEL))
		return -ENOMEM;

	for (i = 0; i < PMMAP_INODE_HASH_NR; i++) {
		struct pmmap_inode_bucket *b = &ps->bucket[i];
	
		init_rwsem(&b->rw_sem);
		b->rb_by_ino = RB_ROOT;
		INIT_LIST_HEAD(&b->list_sync);
		INIT_LIST_HEAD(&b->list_empty);
		INIT_LIST_HEAD(&b->list_admin);
	}

	return pmmap_hash_workqueue_init(ps);
}

static struct dentry *__make_dir(struct dentry *parent,
		const char *name)
{
	struct dentry *den;
	int ret;

	den = d_alloc_name(parent, name);
	if (!den) {
		PERR("create %s dentry failed\n", name);
		return ERR_PTR(-ENOMEM);
	}
	d_add(den, NULL);

	ret = pmmap_mknod(d_inode(parent), den,
			S_IRUSR | S_IWUSR | S_IFDIR, 0);
	if (ret) {
		PERR("make %s inode failed %d\n", name, ret);
		dput(den);
		return ERR_PTR(ret);
	}

	dput(den);

	return den;
}

static int pmmap_super_tree_init(struct pmmap_super *ps)
{
	struct super_block *sb = ps->sb;
	struct inode *inode;
	int err = -ENOMEM;

	inode = pmmap_get_inode(sb, NULL, S_IFDIR | ps->mode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	pmmap_store_inode(ps, inode,
		PMMAP_STORE_FLAGS_LOOKUP |
		PMMAP_STORE_FLAGS_SYNC);

	inode->i_uid = ps->uid;
	inode->i_gid = ps->gid;
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		iput(inode);
		goto out;
	}

	if (!ps->durable)
		return 0;

	/*
	 * lost+found directory is for self-fsck to carry the
	 * files/directories that lose their parent.
	 */
	ps->lost_found = __make_dir(ps->sb->s_root, "lost+found");
	if (IS_ERR(ps->lost_found)) {
		err = PTR_ERR(ps->lost_found);
		goto out;
	}

	return pmmap_meta_load(ps);
out:
	return err;
}

int pmmap_fill_super(struct super_block *sb, void *data, int silent)
{
	struct pmmap_super *ps;
	int err = -ENOMEM;

	/* Round up to L1_CACHE_BYTES to resist false sharing */
	ps = kzalloc(max((int)sizeof(struct pmmap_super),
				L1_CACHE_BYTES), GFP_KERNEL);
	if (!ps) {
		sb->s_fs_info = NULL;
		return -ENOMEM;
	}

	sb->s_fs_info = ps;
	ps->sb = sb;
	ps->bdev = sb->s_bdev;

	/*
	 * kobj is used as refcount, so init it first
	 */
	kobject_init(&ps->kobj, &pmmap_ktype);

	err = pmmap_super_config_init(ps, data);
	if (err)
		goto out;

	err = pmmap_super_common_init(ps);
	if (err)
		goto out;

	err = pmmap_alloc_init(ps);
	if (err)
		goto out;

	err = pmmap_meta_init(ps);
	if (err)
		goto out;

	err = pmmap_super_tree_init(ps);
	if (err)
		goto out;

	err = kobject_add(&ps->kobj, pmmap_kobj_root,
			"%s", ps->bdev->bd_disk->disk_name);
	if (err) {
		PWARN("kobject_add returns %d\n", err);
		PWARN("you cannot access sysfs helper interfaces of mount %s\n",
				ps->bdev->bd_disk->disk_name);
	}

out:
	if (err)
		set_bit(PMMAP_SUPER_FLAGS_MNT_FAIL, &ps->flags);
	return err;
}


static struct dentry *pmmap_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, pmmap_fill_super);
}

static void pmmap_kill_super(struct super_block *sb)
{
	pmmap_sync_fs(sb, true);
	set_bit(PMMAP_SUPER_FLAGS_UMOUNT, &PMMAP_SB(sb)->flags);
	/*
	 * This is necessary for mem fs
	 */
	if (sb->s_root)
		d_genocide(sb->s_root);
	kill_block_super(sb);
}

static struct file_system_type pmmap_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "pmmapfs",
	.mount		= pmmap_mount,
	.kill_sb	= pmmap_kill_super, 
	.fs_flags	= FS_USERNS_MOUNT | FS_RENAME_DOES_D_MOVE,
};

static void pmmap_init_vfs_inode(void *foo)
{
	struct pmmap_inode *pino = foo;
	inode_init_once(&pino->vfs_inode);
}

void pmmap_exit(void)
{
	if (pmmap_inode_cachep)
		kmem_cache_destroy(pmmap_inode_cachep);

	if (pmmap_kobj_root)
		kobject_put(pmmap_kobj_root);

	pmmap_ctl_exit();
	unregister_filesystem(&pmmap_fs_type);
}

int __init pmmap_init(void)
{
	int err;

	pmmap_inode_cachep = kmem_cache_create("pmmap_inode_cache",
				sizeof(struct pmmap_inode),
				0, SLAB_ACCOUNT, pmmap_init_vfs_inode);
	if (!pmmap_inode_cachep)
		return -ENOMEM;

	pmmap_kobj_root = kobject_create_and_add("pmmap", fs_kobj);
	if (!pmmap_kobj_root) {
		err = -EINVAL;
		goto error;
	}

	err = pmmap_ctl_init();
	if (err) {
		PERR("ctl init failed %d\n", err);
		goto error;
	}

	err = register_filesystem(&pmmap_fs_type);
	if (err) {
		PERR("cannot register pmmapfs %d\n", err);
		goto error;
	}

	pmmap_log_module_init();
	return 0;

error:
	pmmap_exit();
	return err;
}

module_init(pmmap_init);
module_exit(pmmap_exit);

MODULE_AUTHOR("Wang Jianchao");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PMmap Filesystem");
