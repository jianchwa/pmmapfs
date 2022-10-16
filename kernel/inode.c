// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Wang Jianchao
 */
#include "pmmap.h"

const struct file_operations pmmap_file_dax_operations;
const struct address_space_operations pmmap_aops;

static bool inline is_admin(struct dentry *den)
{
	return d_inode(den);
}

static u64 pmmap_get_next_ino(struct pmmap_super *ps)
{
	unsigned long old, ret;

	old = READ_ONCE(ps->max_ino);
	while (1) {
		ret = cmpxchg(&ps->max_ino, old, old + 1);
		if (ret == old)
			break;
		old = ret;
	}
	return ret;
}

void pmmap_update_max_ino(struct pmmap_super *ps,
		unsigned long ino)
{
	unsigned long old, ret;

	/*
	 * max_ino is the next available inode number
	 */
	ino += 1;
	old = READ_ONCE(ps->max_ino);
	while (1) {
		if (ino <= old)
			break;
		ret = cmpxchg(&ps->max_ino, old, ino);
		if (ret == old)
			break;
		old = ret;
	}
}

void pmmap_init_inode(struct inode *inode)
{
	struct pmmap_inode *pino = PMMAP_I(inode);
	/*
	 * Spread the data around all of the bgs
	 */
	pino->max_index = 0;
	pino->prev_alloc_bg = -1;
	pino->empty = true;
	pino->admin = false;
	init_rwsem(&pino->mmap_rwsem);
	init_rwsem(&pino->bmap_rwsem);
	xa_init(&pino->dax_mapping);
	RB_CLEAR_NODE(&pino->rb_node);
	INIT_LIST_HEAD(&pino->list_node);
}

static inline bool pmmap_reserve_inode_nr(struct super_block *sb)
{
	struct pmmap_super *ps = PMMAP_SB(sb);

	return (atomic64_inc_not_zero(&ps->free_inodes));
}

static inline void pmmap_free_inode_nr(struct super_block *sb)
{
	struct pmmap_super *ps = PMMAP_SB(sb);

	atomic64_dec(&ps->free_inodes);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_getattr(const struct path *path, struct kstat *stat,
			 u32 request_mask, unsigned int query_flags)
#else
static int pmmap_getattr(struct user_namespace *mnt_userns,
		const struct path *path, struct kstat *stat,
		u32 request_mask, unsigned int query_flags)
#endif
{
	struct inode *inode = path->dentry->d_inode;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
	generic_fillattr(inode, stat);
#else
	generic_fillattr(&init_user_ns, inode, stat);
#endif
	return 0;
}

int pmmap_setattr_inode(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
	error = setattr_prepare(dentry, attr);
#else
	error = setattr_prepare(&init_user_ns, dentry, attr);
#endif
	if (error)
		return error;

	if (S_ISREG(inode->i_mode) && (attr->ia_valid & ATTR_SIZE)) {
		loff_t oldsize = inode->i_size;
		loff_t newsize = attr->ia_size;

		if (newsize != oldsize) {
			i_size_write(inode, newsize);
			inode->i_ctime = inode->i_mtime = current_time(inode);
		}

		if (newsize <= oldsize) {
			loff_t holebegin = round_up(newsize, PAGE_SIZE);
			if (oldsize > holebegin)
				unmap_mapping_range(inode->i_mapping,
							holebegin, 0, 1);
			if (IS_DAX(inode))
				pmmap_truncate_range(inode, newsize, (loff_t)-1);
			/* unmap again to remove racily COWed private pages */
			if (oldsize > holebegin)
				unmap_mapping_range(inode->i_mapping,
							holebegin, 0, 1);
		}
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
	setattr_copy(inode, attr);
#else
	setattr_copy(&init_user_ns, inode, attr);
#endif
	return error;
}

#define NEED_LOG_ATTR (ATTR_UID | ATTR_GID | ATTR_ATIME |\
		ATTR_MTIME | ATTR_CTIME | ATTR_MODE | ATTR_SIZE)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_setattr(struct dentry *dentry, struct iattr *attr)
#else
static int pmmap_setattr(struct user_namespace *mnt_userns,
		struct dentry *dentry, struct iattr *attr)
#endif
{
	struct inode *inode = d_inode(dentry);
	struct pmmap_log_cursor lcur;
	unsigned int ia_valid = attr->ia_valid;
	int ret;

	if(PMMAP_I(d_inode(dentry))->admin &&
	   (attr->ia_valid & ATTR_MODE))
	    return -EPERM;

	/*
	 * If only update time and has not passed 1 second, don't log
	 */
	if (ia_valid & ATTR_ATIME &&
	    attr->ia_atime.tv_sec == inode->i_atime.tv_sec)
	    ia_valid &= ~ATTR_ATIME;

	if (ia_valid & ATTR_MTIME &&
	    attr->ia_mtime.tv_sec == inode->i_mtime.tv_sec)
	    ia_valid &= ~ATTR_MTIME;

	if (ia_valid & ATTR_CTIME &&
	    attr->ia_ctime.tv_sec == inode->i_ctime.tv_sec)
	    ia_valid &= ~ATTR_CTIME;

	if (ia_valid & NEED_LOG_ATTR) {
		ret = pmmap_log_start(&lcur, PMMAP_SB(dentry->d_sb),
				PMMAP_SETATTR, PMMAP_I(inode)->admin);
		if (ret)
			return ret;

		ret = pmmap_setattr_inode(dentry, attr);
		if (!ret)
			pmmap_log_record_setattr(&lcur, d_inode(dentry), attr);
		pmmap_log_finish(&lcur, !ret);
	} else {
		ret = pmmap_setattr_inode(dentry, attr);
	}

	return ret;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_tmp_setattr(struct dentry *dentry, struct iattr *attr)
#else
static int pmmap_tmp_setattr(struct user_namespace *mnt_userns,
		struct dentry *dentry, struct iattr *attr)
#endif
{
	return pmmap_setattr_inode(dentry, attr);
}

void pmmap_evict_inode(struct inode *inode)
{
	struct pmmap_super *ps = PMMAP_SB(inode->i_sb);
	struct pmmap_inode *pino = PMMAP_I(inode);

	inode->i_size = 0;
	pmmap_truncate_range(inode, 0, (loff_t)-1);
	pmmap_erase_inode(ps, inode);
	xa_destroy(&pino->dax_mapping);
	/*
	 * When do umount, we don't erase the bmap
	 */
	if (!test_bit(PMMAP_SUPER_FLAGS_UMOUNT, &ps->flags)) {
		if (inode->i_blocks || inode->i_nlink)
			PWARN("inode %lu not clear i_blocks %llu i_nlink %d\n",
					inode->i_ino, inode->i_blocks, inode->i_nlink);
	}
	pmmap_free_inode_nr(inode->i_sb);
	clear_inode(inode);
}

static struct inode *
__pmmap_get_inode(struct pmmap_create_inode_data *cd)
{
	struct super_block *sb = cd->sb;
	struct inode *dir = cd->dir;
	struct pmmap_super *ps = PMMAP_SB(sb);
	struct inode *inode;

	if (!pmmap_reserve_inode_nr(sb))
		return ERR_PTR(-ENOSPC);

	inode = new_inode(sb);
	if (!inode) {
		pmmap_free_inode_nr(sb);
		return ERR_PTR(-ENOMEM);
	}

	inode->i_flags |= S_DAX;
	if (cd->replay) {
		inode->i_ino = cd->ino;
		pmmap_update_max_ino(ps, cd->ino);
	} else {
		inode->i_ino = pmmap_get_next_ino(ps);
	}
	
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
	inode_init_owner(inode, dir, cd->mode);
#else
	inode_init_owner(&init_user_ns, inode, dir, cd->mode);
#endif
	inode->i_blocks = 0;
	if (cd->replay) {
		inode->i_atime.tv_sec =
		inode->i_mtime.tv_sec =
		inode->i_ctime.tv_sec = cd->tsec;
	} else {
		inode->i_atime =
		inode->i_mtime =
		inode->i_ctime = current_time(inode);
	}
	pmmap_init_inode(inode);
	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		break;
	case S_IFDIR:
		inc_nlink(inode);
		inode->i_size = 2 * BOGO_DIRENT_SIZE;
		break;
	case S_IFLNK:
		break;
	default:
		break;
	}
	pmmap_arm_inode(inode);
	PMMAP_I(inode)->admin = !!test_bit(PMMAP_SUPER_FLAGS_ADMIN, &ps->flags);

	return inode;
}

int pmmap_create_inode(struct pmmap_create_inode_data *cd)
{
	struct inode *inode;
	struct inode *dir = cd->dir;
	struct dentry *dentry = cd->dentry;

	inode = __pmmap_get_inode(cd);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	dir->i_size += BOGO_DIRENT_SIZE;
	dir->i_ctime = dir->i_mtime = current_time(dir);
	d_instantiate(dentry, inode);
	dget(dentry); /* Extra count - pin the dentry in core */
	return 0;
}

int pmmap_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct pmmap_create_inode_data cd;
	int ret, flags;

	cd.sb = dir->i_sb;
	cd.dir = dir;
	cd.dentry = dentry;
	cd.mode = mode;
	cd.replay = false;

	ret = pmmap_create_inode(&cd);
	if (ret)
		return ret;

	if (PMMAP_I(d_inode(dentry))->admin)
		flags = PMMAP_STORE_FLAGS_LOOKUP | PMMAP_STORE_FLAGS_ADMIN;
	else
		flags = PMMAP_STORE_FLAGS_SYNC;

	pmmap_store_inode(PMMAP_SB(dir->i_sb), d_inode(dentry), flags);

	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
#else
static int pmmap_mkdir(struct user_namespace *mnt_userns,
		struct inode *dir, struct dentry *dentry, umode_t mode)
#endif
{
	int ret;
	struct pmmap_log_cursor lcur;

	ret = pmmap_log_start(&lcur, PMMAP_SB(dir->i_sb),
			PMMAP_CREATE, PMMAP_I(dir)->admin);
	if (ret)
		return ret;

	ret = pmmap_mknod(dir, dentry, mode | S_IFDIR, 0);
	if (!ret) {
		pmmap_log_record_create(&lcur, dir, dentry);
		inc_nlink(dir);
	}
	pmmap_log_finish(&lcur, !ret);
	return ret;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_tmp_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
#else
static int pmmap_tmp_mkdir(struct user_namespace *mnt_userns,
		struct inode *dir, struct dentry *dentry, umode_t mode)
#endif
{
	int ret;
	ret = pmmap_mknod(dir, dentry, mode | S_IFDIR, 0);
	if (!ret) {
		inc_nlink(dir);
	}
	return ret;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
#else
static int pmmap_create(struct user_namespace *mnt_userns,
		struct inode *dir, struct dentry *dentry,
		umode_t mode, bool excl)
#endif
{
	int ret;
	struct pmmap_log_cursor lcur;

	ret = pmmap_log_start(&lcur, PMMAP_SB(dir->i_sb),
			PMMAP_CREATE, PMMAP_I(dir)->admin);
	if (ret)
		return ret;

	ret = pmmap_mknod(dir, dentry, mode | S_IFREG, 0);
	if (!ret) {
		/*
		 * FIXME: What if the max ino is updated but create fail ?
		 */
		pmmap_log_record_create(&lcur, dir, dentry);
	}
	pmmap_log_finish(&lcur, !ret);
	return ret;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_tmp_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
#else
static int pmmap_tmp_create(struct user_namespace *mnt_userns,
		struct inode *dir, struct dentry *dentry,
		umode_t mode, bool excl)
#endif
{
	return pmmap_mknod(dir, dentry, mode | S_IFREG, 0);
}

/*
 * Link a file..
 */
int pmmap_link_inode(struct dentry *old_dentry,
		struct inode *dir, struct dentry *dentry, u32 tsec)
{
	struct inode *inode = d_inode(old_dentry);

	if (!pmmap_reserve_inode_nr(inode->i_sb))
		return -ENOSPC;

	/*
	 * even if the dentry has been added to parent's d_subdirs,
	 * it won't be synced by pmmap_sync_dentries because inode
	 * has not been installed.
	 */
	dir->i_size += BOGO_DIRENT_SIZE;
	inode->i_ctime.tv_sec = tsec;
	dir->i_ctime.tv_sec = dir->i_mtime.tv_sec = tsec;
	inc_nlink(inode);
	ihold(inode);	/* New dentry reference */
	dget(dentry);		/* Extra pinning count for the created dentry */
	d_instantiate(dentry, inode);
	return 0;
}

static int pmmap_link(struct dentry *old_dentry,
		struct inode *dir, struct dentry *dentry)
{
	struct pmmap_log_cursor lcur;
	int ret;

	ret = pmmap_log_start(&lcur, PMMAP_SB(dir->i_sb),
			PMMAP_LINK, PMMAP_I(dir)->admin);
	if (ret)
		return ret;

	ret = pmmap_link_inode(old_dentry, dir, dentry,
			current_time(dir).tv_sec);
	if (!ret) {
		pmmap_log_record_link(&lcur, d_inode(old_dentry),
				dir, dentry);
	}
	pmmap_log_finish(&lcur, !ret);

	return ret;
}

static int pmmap_tmp_link(struct dentry *old_dentry,
		struct inode *dir, struct dentry *dentry)
{
	return pmmap_link_inode(old_dentry, dir, dentry,
			current_time(dir).tv_sec);
}

/*
 * The inode is evicted in do_unlinkat, which has been out of
 * log transaction. To avoid sync process write the unliked
 * inode to metadat but get rid of its unlink log, sync process
 * need to check the inode->i_nlink.
 */
int pmmap_unlink_inode(struct inode *dir,
		struct dentry *dentry, u32 tsec, bool replay)
{
	struct inode *inode = d_inode(dentry);

	if (inode->i_nlink > 1 && !S_ISDIR(inode->i_mode))
		pmmap_free_inode_nr(inode->i_sb);

	dir->i_size -= BOGO_DIRENT_SIZE;
	inode->i_ctime.tv_sec = tsec;
	dir->i_ctime.tv_sec = dir->i_mtime.tv_sec = tsec;
	drop_nlink(inode);
	dput(dentry);	/* Undo the count from "create" - this does all the work */
	return 0;
}

static int pmmap_unlink(struct inode *dir, struct dentry *dentry)
{
	struct pmmap_log_cursor lcur;
	int ret;

	if (PMMAP_I(d_inode(dentry))->admin)
		return -EPERM;

	ret = pmmap_log_start(&lcur, PMMAP_SB(dir->i_sb),
			PMMAP_UNLINK, PMMAP_I(dir)->admin);
	if (ret)
		return ret;

	pmmap_log_record_unlink(&lcur, dir, dentry);
	pmmap_unlink_inode(dir, dentry, current_time(dir).tv_sec, false);
	pmmap_log_finish(&lcur, true);
	return 0;
}

static int pmmap_tmp_unlink(struct inode *dir, struct dentry *dentry)
{
	pmmap_unlink_inode(dir, dentry, current_time(dir).tv_sec, false);
	return 0;
}

static int pmmap_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct pmmap_log_cursor lcur;
	int ret;

	if (!simple_empty(dentry))
		return -ENOTEMPTY;

	ret = pmmap_log_start(&lcur, PMMAP_SB(dir->i_sb),
			PMMAP_UNLINK, PMMAP_I(dir)->admin);
	if (ret)
		return ret;

	pmmap_log_record_unlink(&lcur, dir, dentry);
	drop_nlink(d_inode(dentry));
	drop_nlink(dir);
	pmmap_unlink_inode(dir, dentry, current_time(dir).tv_sec, false);
	pmmap_log_finish(&lcur, true);

	return 0;
}

static int pmmap_tmp_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (!simple_empty(dentry))
		return -ENOTEMPTY;

	drop_nlink(d_inode(dentry));
	drop_nlink(dir);
	pmmap_unlink_inode(dir, dentry, current_time(dir).tv_sec, false);

	return 0;
}

int pmmap_rename_inode(struct inode *old_dir,
		struct dentry *old_dentry,
		struct inode *new_dir,
		struct dentry *new_dentry,
		u32 tsec)
{
	struct inode *inode = d_inode(old_dentry);
	int they_are_dirs = S_ISDIR(inode->i_mode);

	if (!simple_empty(new_dentry))
		return -ENOTEMPTY;

	if (d_really_is_positive(new_dentry)) {
		/*
	 	 * If the target is a real file, remove it first
	 	 */
		pmmap_unlink_inode(new_dir, new_dentry, tsec, false);
		if (they_are_dirs) {
			drop_nlink(d_inode(new_dentry));
			drop_nlink(old_dir);
		}
	} else if (they_are_dirs) {
		drop_nlink(old_dir);
		inc_nlink(new_dir);
	}

	old_dir->i_size -= BOGO_DIRENT_SIZE;
	new_dir->i_size += BOGO_DIRENT_SIZE;
	old_dir->i_ctime.tv_sec = old_dir->i_mtime.tv_sec = tsec;
	new_dir->i_ctime.tv_sec = new_dir->i_mtime.tv_sec = tsec;
	inode->i_ctime.tv_sec = tsec;
	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_rename(struct inode *old_dir,
		struct dentry *old_dentry,
		struct inode *new_dir,
		struct dentry *new_dentry,
#else
static int pmmap_rename(struct user_namespace *mnt_userns,
		struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry,
#endif
		unsigned int flags)
{
	int ret;
	struct pmmap_log_cursor lcur;


	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	ret = pmmap_log_start(&lcur, PMMAP_SB(old_dir->i_sb),
			PMMAP_REANME, PMMAP_I(old_dir)->admin);
	if (ret)
		return ret;

	ret = pmmap_rename_inode(old_dir, old_dentry,
			new_dir, new_dentry, current_time(old_dir).tv_sec);
	if (!ret) {
		pmmap_log_record_rename(&lcur, old_dir,
				old_dentry, new_dir, new_dentry);

		d_move(old_dentry, new_dentry);
	}

	pmmap_log_finish(&lcur, !ret);
	return ret;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_tmp_rename(struct inode *old_dir,
		struct dentry *old_dentry,
		struct inode *new_dir,
		struct dentry *new_dentry,
#else
static int pmmap_tmp_rename(struct user_namespace *mnt_userns,
		struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry,
#endif
		unsigned int flags)
{
	int ret;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	ret = pmmap_rename_inode(old_dir, old_dentry,
			new_dir, new_dentry, current_time(old_dir).tv_sec);
	if (!ret) {
		d_move(old_dentry, new_dentry);
	}

	return ret;
}

int pmmap_symlink_inode(struct inode *dir,
		struct dentry *dentry,
		const char *symname, u32 tsec,
		u64 ino)
{
	int len, flags;
	struct inode *inode;
	struct pmmap_create_inode_data cd;

	len = strlen(symname) + 1;
	/*
	 * TODO: support longer length than 128
	 */
	if (len > PMMAP_SHORT_SYMLINK_LEN)
		return -ENAMETOOLONG;

	cd.sb = dir->i_sb;
	cd.dir = dir;
	cd.dentry = dentry;
	cd.mode = S_IFLNK | 0777;
	cd.tsec = tsec;

	if (ino) {
		cd.replay = true;
		cd.ino = ino;
		flags = PMMAP_STORE_FLAGS_SYNC | PMMAP_STORE_FLAGS_LOOKUP;
	} else {
		cd.replay = false;
		flags = PMMAP_STORE_FLAGS_SYNC;
	}

	inode = __pmmap_get_inode(&cd);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_size = len - 1;
	inode->i_link = kmemdup(symname, len, GFP_KERNEL);
	if (!inode->i_link) {
		iput(inode);
		return -ENOMEM;
	}

	pmmap_store_inode(PMMAP_SB(dir->i_sb), inode, flags);
	dir->i_size += BOGO_DIRENT_SIZE;
	dir->i_ctime.tv_sec = dir->i_mtime.tv_sec = tsec;
	d_instantiate(dentry, inode);
	dget(dentry);
	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_symlink(struct inode *dir,
		struct dentry *dentry, const char *symname)
#else
static int pmmap_symlink(struct user_namespace *mnt_userns,
		struct inode *dir, struct dentry *dentry,
		const char *symname)
#endif
{
	struct pmmap_log_cursor lcur;
	int ret;

	ret = pmmap_log_start(&lcur, PMMAP_SB(dir->i_sb),
			PMMAP_SYMLINK, PMMAP_I(dir)->admin);
	if (ret)
		return ret;

	ret = pmmap_symlink_inode(dir, dentry, symname,
			current_time(dir).tv_sec, 0);
	if (!ret)
		pmmap_log_record_symlink(&lcur, dir, dentry, symname);

	pmmap_log_finish(&lcur, !ret);

	return ret;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
static int pmmap_tmp_symlink(struct inode *dir,
		struct dentry *dentry, const char *symname)
#else
static int pmmap_tmp_symlink(struct user_namespace *mnt_userns,
		struct inode *dir, struct dentry *dentry,
		const char *symname)
#endif
{
	return pmmap_symlink_inode(dir, dentry, symname,
			current_time(dir).tv_sec, 0);
}

static const struct inode_operations pmmap_short_symlink_operations = {
	.get_link	= simple_get_link,
};

const struct inode_operations pmmap_inode_operations = {
	.getattr	= pmmap_getattr,
	.setattr	= pmmap_setattr,
};

const struct inode_operations pmmap_tmp_inode_operations = {
	.getattr	= pmmap_getattr,
	.setattr	= pmmap_tmp_setattr,
};

const struct inode_operations pmmap_dir_inode_operations = {
	.create		= pmmap_create,
	.lookup		= simple_lookup,
	.link		= pmmap_link,
	.unlink		= pmmap_unlink,
	.symlink	= pmmap_symlink,
	.mkdir		= pmmap_mkdir,
	.rmdir		= pmmap_rmdir,
	.rename		= pmmap_rename,
};

const struct inode_operations pmmap_tmp_dir_inode_operations = {
	.create		= pmmap_tmp_create,
	.lookup		= simple_lookup,
	.link		= pmmap_tmp_link,
	.unlink		= pmmap_tmp_unlink,
	.symlink	= pmmap_tmp_symlink,
	.mkdir		= pmmap_tmp_mkdir,
	.rmdir		= pmmap_tmp_rmdir,
	.rename		= pmmap_tmp_rename,
};

void pmmap_arm_inode(struct inode *inode)
{
	struct pmmap_super *ps = PMMAP_SB(inode->i_sb);

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_fop = &pmmap_file_dax_operations;
		inode->i_mapping->a_ops = &pmmap_aops;
		if (ps->durable)
			inode->i_op = &pmmap_inode_operations;
		else
			inode->i_op = &pmmap_tmp_inode_operations;

		break;
	case S_IFDIR:
		if (ps->durable)
			inode->i_op = &pmmap_dir_inode_operations;
		else
			inode->i_op = &pmmap_tmp_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		break;
	case S_IFLNK:
		if (inode->i_size + 1 <= PMMAP_SHORT_SYMLINK_LEN)
			inode->i_op = &pmmap_short_symlink_operations;
		else
			WARN_ON(1);
		break;
	default:
		WARN_ON(1);
		break;
	}
}

struct inode *pmmap_get_inode(struct super_block *sb,
		struct inode *dir, umode_t mode)
{
	struct pmmap_create_inode_data cd;

	cd.sb = sb;
	cd.dir = dir;
	cd.mode = mode;
	cd.replay = false;
	return __pmmap_get_inode(&cd);
}

static int pmmap_file_iomap_begin(struct inode *inode,
		loff_t offset, loff_t length,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,10,0)
		unsigned flags, struct iomap *iomap)
#else
		unsigned flags, struct iomap *iomap, struct iomap *srcomap)
#endif
{
	struct pmmap_bmap_cur bcur = {
		.inode = inode,
		.file = {
			.off = offset,
			.len = length,
		},
	};
	int ret;

	PDBG("%s off %llx len %llx\n",
			flags & IOMAP_WRITE ? "write" : "read",
			offset, length);
	/*
	 * TODO:
	 * Partial truncating would zero the partial blk with IOMAP_ZERO
	 */
	if (flags & IOMAP_WRITE)
		ret = pmmap_bmap_write(&bcur);
	else
		ret = pmmap_bmap_read(&bcur);

	if (ret)
		return ret;

	iomap->addr = bcur.extent.d_off;
	iomap->offset = bcur.extent.f_off;
	iomap->length = bcur.extent.len;
	iomap->type = bcur.map_type;

	if (bcur.new)
		iomap->flags |= IOMAP_F_NEW;

	BUG_ON(iomap->type != IOMAP_MAPPED && iomap->type != IOMAP_HOLE);
	PDBG("bmap (%s) doff %llx len %llx\n",
			iomap->type == IOMAP_MAPPED ? "mapped" : "hole",
			iomap->addr, iomap->length);
	/*
	 * This seems to give us a chance to operate more than one pmems
	 */
	iomap->bdev = PMMAP_SB(inode->i_sb)->bdev;
	iomap->dax_dev = PMMAP_SB(inode->i_sb)->dax_dev;

	return 0;
}

const struct iomap_ops pmmap_iomap_ops = {
	.iomap_begin = pmmap_file_iomap_begin,
};

void pmmap_truncate_range(struct inode *inode,
		loff_t lstart, loff_t lend)
{
	struct pmmap_inode *pino = PMMAP_I(inode);
	unsigned long blksz = 1 << PAGE_SHIFT;
	struct pmmap_bmap_cur bcur = {
		.inode = inode,
		.file = {
			.off = lstart,
			.len = lend - lstart,
		},
	};

	down_write(&pino->mmap_rwsem);
	/*
	 * Don't do bmap erase when umount
	 */
	if (!test_bit(PMMAP_SUPER_FLAGS_UMOUNT,
		      &PMMAP_SB(inode->i_sb)->flags))
		pmmap_bmap_erase(&bcur);
	truncate_inode_pages_range(inode->i_mapping, lstart, lend);
	up_write(&pino->mmap_rwsem);

	/*
	 * zero the partial blks
	 */
	if (lstart & (blksz - 1)) {
		iomap_zero_range(inode, lstart,
				round_up(lstart, blksz), NULL, &pmmap_iomap_ops);
	}
}

static ssize_t pmmap_file_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (!iov_iter_count(to))
		return 0;

	if (!inode_trylock_shared(inode)) {
		if (iocb->ki_flags & IOCB_NOWAIT)
			return -EAGAIN;
		inode_lock_shared(inode);
	}

	ret = dax_iomap_rw(iocb, to, &pmmap_iomap_ops);
	inode_unlock_shared(inode);
	file_accessed(iocb->ki_filp);

	return ret;
}

/*
 * file size update is in separate transaction with block alloc&install.
 * The worst result is file's i_blocks is bigger than i_size. This is
 * acceptable as the blocks are not lost.
 */
void pmmap_file_update_size(struct inode *inode, ssize_t size)
{
	struct pmmap_super *ps = PMMAP_SB(inode->i_sb); 

	i_size_write(inode, size);
	if (ps->durable) {
		struct pmmap_log_cursor lcur;
		if (!pmmap_log_start(&lcur, ps, PMMAP_SIZE, PMMAP_I(inode)->admin)) {
			pmmap_log_record_size(&lcur, inode);
			pmmap_log_finish(&lcur, true);
		}
	}
}

static ssize_t pmmap_file_dax_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (PMMAP_I(inode)->admin)
		return -EPERM;

	if (!iov_iter_count(from))
		return 0;

	if (!inode_trylock(inode)) {
		if (iocb->ki_flags & IOCB_NOWAIT)
			return -EAGAIN;
		inode_lock(inode);
	}

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	ret = file_remove_privs(iocb->ki_filp);
	if (ret)
		goto out;

	ret = dax_iomap_rw(iocb, from, &pmmap_iomap_ops);

	if (ret > 0 && iocb->ki_pos > i_size_read(inode))
		pmmap_file_update_size(inode, iocb->ki_pos);
out:
	inode_unlock(inode);

	return ret;
}

static vm_fault_t pmmap_pud_fault(struct vm_fault *vmf)
{
	struct inode *inode = vmf->vma->vm_file->f_mapping->host;
	bool write = vmf->flags & FAULT_FLAG_WRITE;
	struct pmmap_bmap_cur bcur;
	vm_fault_t ret;
	pfn_t pfn;
	int err;

	bcur.inode = inode;
	bcur.file.off = round_down(vmf->pgoff << PAGE_SHIFT, PUD_SIZE);
	bcur.file.len = PUD_SIZE;

	if (bcur.file.off >= i_size_read(inode)) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	err = pmmap_bmap_write(&bcur);
	if (err) {
		ret = vmf_error(err);
		goto out;
	}

	if (bcur.extent.len < PUD_SIZE) {
		ret = VM_FAULT_FALLBACK;
		goto out;
	}

	err = pmmap_dax_pfn(PMMAP_SB(inode->i_sb),
			bcur.extent.d_off, PUD_SIZE, &pfn);
	if (err) {
		ret = vmf_error(err);
		goto out;
	}

	ret = vmf_insert_pfn_pud(vmf, pfn, write);
	if (ret != VM_FAULT_SIGBUS && bcur.new) {
		count_vm_event(PGMAJFAULT);
		ret |= VM_FAULT_MAJOR;
	}

out:
	return ret;
}

static bool pud_fault_fallback(struct vm_fault *vmf, size_t fault_size)
{
	unsigned long colour = (fault_size >> PAGE_SHIFT) - 1;
	unsigned long mask = ~(fault_size - 1);
	unsigned long addr = vmf->address & mask;
	pgoff_t max_pgoff;

	/*
	 * offset in file and address must be aligned in fault_size
	 */
	if ((vmf->pgoff & colour) !=
	    ((vmf->address >> PAGE_SHIFT) & colour))
		return true;

	if ((addr < vmf->vma->vm_start) ||
	    (addr + fault_size) > vmf->vma->vm_end)
		return true;

	if ((vmf->flags & FAULT_FLAG_WRITE) &&
	    !(vmf->vma->vm_flags & VM_SHARED))
		return true;

	max_pgoff = i_size_read(vmf->vma->vm_file->f_mapping->host);
	max_pgoff = DIV_ROUND_UP(max_pgoff, PAGE_SIZE);
	if ((vmf->pgoff | colour) >= max_pgoff)
		return true;

	return false;
}

/*
 * ext4/xfs use 'mmap_supported_flags = MAP_SYNC' to tell they
 * employs the synchronous page fault to guarantee that block
 * mapping has been flushed to disk when the userland apps
 * access the mapped space. Because the bmap has been persistent
 * through intend log when pmmap_bmap_write returns, so we needn't
 * support MAP_SYNC. And we don't set IOMAP_F_DIRTY to iomap.flags
 * to avoid dax_iomap_fault defer vmf_insert_mixed_mkwrite.
 */
static vm_fault_t __pmmap_huge_fault(struct vm_fault *vmf,
		enum page_entry_size pe_size, bool write_fault)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct pmmap_super *ps = PMMAP_SB(inode->i_sb);
	struct pmmap_inode *pino = PMMAP_I(inode);
	vm_fault_t ret;

	if (pe_size > ps->pesz)
		return VM_FAULT_FALLBACK;

	if (pe_size == PE_SIZE_PUD &&
	    pud_fault_fallback(vmf, PUD_SIZE))
		return VM_FAULT_FALLBACK;

	if (write_fault)
		file_update_time(vmf->vma->vm_file);

	if (pe_size == PE_SIZE_PUD) {
		/*
		 * Use mmap_rwsem to serialize all of fault on this file
		 */
		down_write(&pino->mmap_rwsem);
		ret = pmmap_pud_fault(vmf);
		up_write(&pino->mmap_rwsem);
	} else {
		pfn_t pfn;
		int err;

		if (write_fault)
			down_write(&pino->mmap_rwsem);
		else
			down_read(&pino->mmap_rwsem);

		ret = dax_iomap_fault(vmf, pe_size, &pfn,
			&err, &pmmap_iomap_ops);

		if (write_fault)
			up_write(&pino->mmap_rwsem);
		else
			up_read(&pino->mmap_rwsem);
	}

	if (ret & VM_FAULT_NOPAGE)
		pmmap_stat_add(PMMAP_SB(inode->i_sb), pe_size, mmap, 1);

	return ret;
}

static vm_fault_t pmmap_huge_fault(struct vm_fault *vmf, enum page_entry_size pe_size)
{
	return __pmmap_huge_fault(vmf, pe_size, vmf->flags & FAULT_FLAG_WRITE);
}

static vm_fault_t pmmap_fault(struct vm_fault *vmf)
{
	return pmmap_huge_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct pmmap_vm_ops = {
	.fault = pmmap_fault,
	.huge_fault = pmmap_huge_fault,
	.page_mkwrite = pmmap_fault,
	.pfn_mkwrite = pmmap_fault,
};

static int pmmap_file_dax_mmap(struct file *file,
		struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_ops = &pmmap_vm_ops;
	vma->vm_flags |= VM_HUGEPAGE;
	return 0;
}

static long pmmap_file_dax_fallocate(struct file *file, int mode,
		loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	struct pmmap_super *ps = PMMAP_SB(inode->i_sb);
	struct pmmap_bmap_cur bcur = { 0 };
	int ret;

	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	bcur.inode = inode;
	bcur.file.off = offset & PAGE_MASK;
	bcur.file.len = roundup(offset + len, 1 << PAGE_SHIFT) - bcur.file.off;

	if ((bcur.file.len >> PAGE_SHIFT) > percpu_counter_sum(&ps->free_blks))
		return -ENOSPC;

	inode_lock(inode);
	/*
	 * We need to check rlimit even when FALLOC_FL_KEEP_SIZE
	 */
	ret = inode_newsize_ok(inode, offset + len);
	if (ret)
		goto out;

	while (bcur.file.len) {
		if (pmmap_bmap_write(&bcur))
			break;
		bcur.file.off += bcur.extent.len;
		/*
		 * We may get a full pud/pmd chunk
		 */
		if (bcur.extent.len > bcur.file.len)
			bcur.file.len = 0;
		else
			bcur.file.len -= bcur.extent.len;
	}

	/*
	 * TODO:
	 * If cannot get enough blks, we should free the allocated ones.
	 * And we need a good way to record this in log.
	 */
	if (bcur.file.len) {
		ret = -ENOSPC;
		goto out;
	}

	ret = 0;
	if (!(mode & FALLOC_FL_KEEP_SIZE) && offset + len > inode->i_size)
		pmmap_file_update_size(inode, offset + len);

	inode->i_ctime = current_time(inode);

out:
	inode_unlock(inode);
	return ret;
}

static loff_t pmmap_file_dax_llseek(struct file *file,
		loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	struct pmmap_bmap_cur bcur = { 0 };
	int ret;

	if (whence != SEEK_DATA && whence != SEEK_HOLE)
		return generic_file_llseek_size(file, offset, whence,
					MAX_LFS_FILESIZE, i_size_read(inode));

	inode_lock(inode);

	if (offset < 0 || offset >= inode->i_size) {
		offset = -ENXIO;
		goto out;
	}

	bcur.inode = inode;

	while (offset < inode->i_size) {
		bcur.file.off = offset;
		bcur.file.len = inode->i_size - offset;
		ret = pmmap_bmap_read(&bcur);
		if (ret) {
			offset = ret;
			goto out;
		}

		/*
		 * There are two principles in pmmap_bmap_read,
		 * (1) it returns a contiguous _mapped_ or _non_mapped_region
		 * (2) the returned extent doesn't cross PMD boundary
		 */
		if ((whence == SEEK_DATA && bcur.map_type == IOMAP_HOLE) ||
		    (whence == SEEK_HOLE && bcur.map_type == IOMAP_MAPPED)) {
			offset = bcur.extent.f_off + bcur.extent.len;
		} else {
			break;
		}
	}
	if (offset >= inode->i_size) {
		if (whence == SEEK_DATA)
		    offset = -ENXIO;
		else
		    offset = inode->i_size;
	}
out:
	if (offset >= 0)
		offset = vfs_setpos(file, offset, MAX_LFS_FILESIZE);

	inode_unlock(inode);

	return offset;
}

static inline unsigned long __get_len_pad(
		unsigned long pgoff, unsigned long len, unsigned long size)
{
	loff_t off = (loff_t)pgoff << PAGE_SHIFT;
	loff_t off_end = off + len;
	loff_t off_align = round_up(off, size);
	unsigned long len_pad;

	if (off_end <= off_align || (off_end - off_align) < size)
		return 0;

	len_pad = len + size;
	if (len_pad < len || (off + len_pad) < off)
		return 0;

	return len_pad;
}

static unsigned long pmmap_get_unmapped_area(struct file *filp,
				      unsigned long addr, unsigned long len,
				      unsigned long pgoff, unsigned long flags)
{

	unsigned long len_pad;
	unsigned long size;

	if (addr)
		goto out;

	size = PUD_SIZE;
	len_pad = __get_len_pad(pgoff, len, size);
	if (!len_pad) {
		size = PMD_SIZE;
		len_pad = __get_len_pad(pgoff, len, size);
		if (!len_pad)
			goto out;
	}

	addr = current->mm->get_unmapped_area(filp, 0, len_pad,
				      pgoff, flags);

	if (!IS_ERR_VALUE(addr)) {
		addr += ((pgoff << PAGE_SHIFT) - addr) & (size - 1);
		return addr;
	}

out:
	return current->mm->get_unmapped_area(filp, addr, len, pgoff, flags);
}

static int __pmmap_sync_time(struct inode *inode)
{
	struct pmmap_log_cursor lcur;
	struct iattr attr;
	int ret;

	ret = pmmap_log_start(&lcur, PMMAP_SB(inode->i_sb),
			PMMAP_SETATTR, PMMAP_I(inode)->admin);
	if (ret)
		return ret;

	attr.ia_valid = ATTR_ATIME | ATTR_MTIME | ATTR_CTIME;
	attr.ia_atime.tv_sec = inode->i_atime.tv_sec;
	attr.ia_mtime.tv_sec = inode->i_mtime.tv_sec;
	attr.ia_ctime.tv_sec = inode->i_ctime.tv_sec;

	pmmap_log_record_setattr(&lcur, inode, &attr);
	pmmap_log_finish(&lcur, true);

	return 0;
}

/*
 * a/m time cannot be synced by fsync. Right now, they can only
 * be persisted to pmem with full sync process.
 */
static int pmmap_file_dax_fsync(struct file *file, loff_t start,
		loff_t end, int datasync)
{
	struct inode *inode = file_inode(file);
	int ret;

	if (!PMMAP_SB(inode->i_sb)->durable)
		return 0;
	
	ret = generic_file_fsync(file, start, end, datasync);
	if (datasync || ret)
		goto out;

	ret = __pmmap_sync_time(inode);
out:
	return ret;
}

const struct file_operations pmmap_file_dax_operations = {
	.fallocate = pmmap_file_dax_fallocate,
	.mmap 		= pmmap_file_dax_mmap,
	.get_unmapped_area = pmmap_get_unmapped_area,
	.llseek		= pmmap_file_dax_llseek,
	.read_iter	= pmmap_file_dax_read_iter,
	.write_iter	= pmmap_file_dax_write_iter,
	.fsync		= pmmap_file_dax_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
};

static int pmmap_dax_writepages(struct address_space *mapping,
		struct writeback_control *wbc)
{
	struct pmmap_super *ps = PMMAP_SB(mapping->host->i_sb);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,10,0)
	return dax_writeback_mapping_range(mapping, ps->bdev, wbc);
#else
	return dax_writeback_mapping_range(mapping, ps->dax_dev, wbc);
#endif
}

const struct address_space_operations pmmap_aops = {
	.writepages		= pmmap_dax_writepages,
	.direct_IO = noop_direct_IO,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,0)
	.set_page_dirty		= noop_set_page_dirty,
#else
	.set_page_dirty		= __set_page_dirty_no_writeback,
#endif
	.invalidatepage	= noop_invalidatepage,
};

