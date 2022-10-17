// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 - 2021 Wang Jianchao
 */
#include "pmmap.h"

/*
 * pmmapfs use full meta and intend log to reconstruct the
 * whole filesystem during mount, so the mount process can
 * also be deemed as fsck. When there is softwrare bug or
 * metadata corruption, load and repaly may fail. At this
 * moment, we should continue the process to complete the
 * mount, then we could get tree. After confirm the files
 * and directory manuanlly, trigger a full sync to repair
 * every thing.
 */
static inline bool mnt_stop(struct pmmap_super *ps, int err)
{
	bool ret = false;

	switch (err) {
	case -ENOMEM:
		ret = true;
		break;
	default:
		break;
	}

	return ret;
}

static inline bool meta_exhaust(struct pmmap_meta_cursor *mcur)
{
	return mcur->eof;
}

static inline bool meta_skip(struct pmmap_meta_cursor *mcur)
{
	return mcur->corrupted || mcur->eof;
}

static void __pmmap_meta_cursor_reset(
		struct pmmap_meta_cursor *mcur,
		struct pmmap_super *ps)
{
	mcur->ps = ps;
	mcur->page_off = 0;
	mcur->corrupted = false;
	mcur->eof = false;
	mcur->last = false;
}

static void __pmmap_meta_read(struct pmmap_meta_cursor *mcur)
{
	u32 crc, zero = 0;

	if (mcur->off >= mcur->end) {
		mcur->eof = true;
		mcur->page_off = mcur->page->len = sizeof(struct pmmap_nv_page);
		return;
	}

	mcur->access_page(mcur, true);
	/*
 	 * crc checksum follows the 64bits magic
 	 */
	crc = crc32(PMMAP_CRC_SEED, (void *)mcur->page, 8);
	crc = crc32(crc, &zero, 4);
	crc = crc32(crc, (void *)mcur->page + 12, PAGE_SIZE - 12);

	if (crc == le32_to_cpu(mcur->page->chksum)) {
		mcur->corrupted = false;
	} else {
		mcur->corrupted = true;
		PWARN_LIMIT("meta page %llx is corrupted\n", mcur->off);
	}

	mcur->page_off = sizeof(struct pmmap_nv_page);
	mcur->off += PAGE_SIZE;
}

/*
 * Both read/write are streaming fashion
 * If the read encounters corrupted page, this reading won't cross
 * the page boundary and may return non-zero mcur->len
 */
static void pmmap_meta_read(struct pmmap_meta_cursor *mcur)
{
	int copy_len, page_len;
	void *dest;

	dest = mcur->data;
	if (!mcur->page_off)
		__pmmap_meta_read(mcur);

again:
	page_len = le16_to_cpu(mcur->page->len);
	/*
	 * When we get the last page which is partial, copy_len
	 * will be zero. We won't do copy or push cursor but
	 * just attempt to read the next page. At the moment,
	 * meta.end is reached and eof is set.
	 */
	copy_len = min(mcur->len, page_len - mcur->page_off);
	/*
	 * If the page is corrupted, only push the curosr, don't
	 * do copy and cross the page boundary.
	 */
	if (likely(!mcur->corrupted))
		memcpy(dest, (void *)mcur->page + mcur->page_off, copy_len);

	mcur->page_off += copy_len;
	mcur->len -= copy_len;
	if (mcur->len && !mcur->eof) {
		if (!mcur->corrupted) {
			__pmmap_meta_read(mcur);
			dest += copy_len;
			goto again;
		} else {
			/*
			 * Read in the next page in next round
			 */
			mcur->page_off = 0;
		}
	}
}

static void __pmmap_meta_write(struct pmmap_meta_cursor *mcur)
{
	mcur->page->magic = cpu_to_le64(PMMAP_NV_PAGE_MAGIC);
	mcur->page->chksum = 0;
	mcur->page->len = mcur->page_off;
	mcur->page->reserved = 0;
	mcur->page->chksum = cpu_to_le32(crc32(PMMAP_CRC_SEED,
				mcur->page, PAGE_SIZE));

	mcur->access_page(mcur, false);
	/*
	 * meta.off should point to the last page that has metadata
	 */
	if (!mcur->last) {
		mcur->off += PAGE_SIZE;
		mcur->page_off = sizeof(struct pmmap_nv_page);
		if (mcur->off >= mcur->end)
			mcur->eof = true;
	}
}

static void pmmap_meta_write(struct pmmap_meta_cursor *mcur)
{
	int copy_len;
	void *src = mcur->data;

	if (!mcur->page_off)
		mcur->page_off = sizeof(struct pmmap_nv_page);

again:
	/*
	 * The metadata space has been used up !
	 */
	if (mcur->eof)
		return;

	copy_len = min(mcur->len, (int)(PAGE_SIZE - mcur->page_off));
	memcpy((void *)mcur->page + mcur->page_off, src, copy_len);
	mcur->page_off += copy_len;
	mcur->len -= copy_len;

	if (mcur->page_off == PAGE_SIZE || mcur->last)
		__pmmap_meta_write(mcur);

	if (mcur->len) {
		src += copy_len;
		goto again;
	}

	return;
}

struct pmmap_sync_bmap_data {
	struct pmmap_meta_cursor *mcur;
	struct pmmap_nv_bmap nv_bmap;
	union pmmap_nv_extent nv_ext;
	u64 blocks;
};

static inline u64 __ext_to_blocks(union pmmap_nv_extent *nv_ext)
{
	u64 blks;

	blks = nv_ext->info.cnt * (1 << pmmap_orders[nv_ext->info.order]);
	blks = blks * BLOCKS_PER_PAGE;
	return blks;
}

static bool __sync_bmap(struct pmmap_inode *pino,
	struct xa_state *xas, union pmmap_entry de, void *priv)
{
	struct pmmap_sync_bmap_data *sd = priv;
	struct pmmap_nv_bmap *nv_bmap = &sd->nv_bmap;
	union pmmap_nv_extent *nv_ext = &sd->nv_ext;

	switch (de.info.order) {
	case PMMAP_EMPTY:
		break;
	case PMMAP_PTE:
		if (!nv_ext->val) {
			nv_ext->info.blk = de.info.blk;
			nv_ext->info.cnt = 1;
			nv_ext->info.order = PMMAP_PTE;
			nv_bmap->index = cpu_to_le64(xas->xa_index);
		} else {
			nv_ext->info.cnt++;
		}
		break;
	case PMMAP_PMD:
		nv_ext->info.order = PMMAP_PMD;
		nv_ext->info.cnt = 1;
		nv_ext->info.blk = de.info.blk;
		nv_bmap->index = cpu_to_le64(xas->xa_index);
		nv_bmap->extent = cpu_to_le64(nv_ext->val);
		break;
	case PMMAP_PUD:
		nv_ext->info.order = PMMAP_PUD;
		nv_ext->info.cnt = 1;
		nv_ext->info.blk = de.info.blk;
		nv_bmap->index = cpu_to_le64(xas->xa_index);
		break;
	default:
		BUG_ON(1);
		break;
	}
	if (de.info.order && !de.info.next_contig) {
		nv_bmap->extent = cpu_to_le64(nv_ext->val);
		sd->mcur->data = (void *)nv_bmap;
		sd->mcur->len = sizeof(*nv_bmap);
		PDBG("dblk index %llx blk %llx order %d cnt %d\n",
				nv_bmap->index,
				(u64)nv_ext->info.blk, nv_ext->info.order,
				nv_ext->info.cnt);
		pmmap_meta_write(sd->mcur);
		sd->blocks -= __ext_to_blocks(nv_ext);
		nv_ext->val = 0;
	}

	return !sd->blocks || meta_exhaust(sd->mcur);
}

static void pmmap_sync_bmap(struct pmmap_meta_cursor *mcur,
		struct pmmap_inode *pino)
{
	struct pmmap_bmap_iter_data id;
	struct pmmap_sync_bmap_data sd;

	sd.mcur = mcur;
	sd.nv_ext.val = 0;
	sd.blocks = pino->vfs_inode.i_blocks;

	id.pino = pino;
	id.iter = __sync_bmap;
	id.priv = &sd;
	id.start_index = 0;
	id.end_index = pino->max_index;

	pmmap_bmap_iterate(&id);
}

static inline u8 __ifmt_to_type(umode_t mode)
{
	u8 t;

	switch (mode & S_IFMT) {
	case S_IFREG:
		t = PMMAP_NV_DEN_REG;
		break;
	case S_IFDIR:
		t = PMMAP_NV_DEN_DIR;
		break;
	case S_IFLNK:
		t = PMMAP_NV_DEN_LNK;
		break;
	default:
		t = 0;
		PWARN("not support mode %x\n", mode);
		break;
	}

	return t;
}

static inline umode_t __type_to_ifmt(u8 type)
{
	umode_t m;

	switch (type) {
	case PMMAP_NV_DEN_REG:
		m = S_IFREG;
		break;
	case PMMAP_NV_DEN_DIR:
		m = S_IFDIR;
		break;
	case PMMAP_NV_DEN_LNK:
		m = S_IFLNK;
		break;
	default:
		m = 0;
		PWARN("not support type %d\n", type);
		break;
	}

	return m;
}

static inline bool need_skip(struct inode *inode)
{
	bool ret;
	/*
	 * inode 1 is lost_found, skip it
	 */
	if (inode->i_ino == 1)
		return true;

	if (!inode->i_nlink)
		return true;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
	case S_IFLNK:
		ret = false;
		break;
	default:
		ret = true;
		break;
	}

	return ret;
}

static void pmmap_sync_dentries(struct pmmap_meta_cursor *mcur,
		struct pmmap_inode *pino)
{
	struct dentry *dentry;
	struct pmmap_nv_dentry nde;
	struct dentry *de;

	dentry = d_find_alias(&pino->vfs_inode);
	spin_lock(&dentry->d_lock);
	list_for_each_entry(de, &dentry->d_subdirs, d_child) {
		if (meta_exhaust(mcur))
			break;

		if (!simple_positive(de))
			continue;

		if (need_skip(d_inode(de)))
			continue;

		nde.inode = cpu_to_le64(d_inode(de)->i_ino);
		nde.type = __ifmt_to_type(d_inode(de)->i_mode);
		nde.name_len = strlen(de->d_name.name);

		mcur->data = (void *)&nde;
		mcur->len = sizeof(nde);
		PDBG("dentry ino %llu %s\n", nde.inode, de->d_name.name);
		pmmap_meta_write(mcur);

		mcur->data = (void *)de->d_name.name;
		mcur->len = strlen(de->d_name.name);
		pmmap_meta_write(mcur);
	}
	spin_unlock(&dentry->d_lock);
	dput(dentry);
}

static void pmmap_sync_symlink(struct pmmap_meta_cursor *mcur,
		struct pmmap_inode *pino)
{
	mcur->data = pino->vfs_inode.i_link;
	mcur->len = pino->vfs_inode.i_size;
	pmmap_meta_write(mcur);
}

static void pmmap_sync_inode(struct pmmap_meta_cursor *mcur,
		struct inode *inode)
{
	struct pmmap_nv_inode nv_inode;
	struct pmmap_inode *pino = PMMAP_I(inode);

	nv_inode.ino = cpu_to_le64(inode->i_ino);
	nv_inode.mode = cpu_to_le16(inode->i_mode);
	nv_inode.links_count = cpu_to_le16(inode->i_nlink);
	nv_inode.iflags = cpu_to_le32(inode->i_flags);
	nv_inode.size = cpu_to_le64(inode->i_size);
	nv_inode.blocks = cpu_to_le64(inode->i_blocks);
	nv_inode.uid = cpu_to_le32(i_uid_read(inode));
	nv_inode.gid = cpu_to_le32(i_gid_read(inode));
	nv_inode.atime = cpu_to_le32(inode->i_atime.tv_sec);
	nv_inode.ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	nv_inode.mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	PDBG("ino %lu mode %x atime %x ctime %x\n",
			inode->i_ino, inode->i_mode,
			(u32)inode->i_atime.tv_sec,
			(u32)inode->i_ctime.tv_sec);
	mcur->data = &nv_inode;
	mcur->len = sizeof(nv_inode);
	pmmap_meta_write(mcur);
	if (meta_exhaust(mcur))
		return;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		pmmap_sync_bmap(mcur, pino);
		break;
	case S_IFDIR:
		pmmap_sync_dentries(mcur, pino);
		break;
	case S_IFLNK:
		pmmap_sync_symlink(mcur, pino);
		break;
	default:
		PWARN("file %lu type %x is not supported\n",
				inode->i_ino,
				inode->i_mode & S_IFMT);
		break;
	}
}

static __le64 pmmap_nv_file_magic = cpu_to_le64(PMMAP_NV_FILE_MAGIC);
static __le64 pmmap_nv_feof_magic = cpu_to_le64(PMMAP_NV_FEOF_MAGIC);

static int __pmmap_sync_meta(struct inode *inode, void *priv)
{
	struct pmmap_meta_cursor *mcur = priv;

	if (need_skip(inode))
		return 0;

	mcur->data = (void *)&pmmap_nv_file_magic;
	mcur->len = sizeof(__le64);
	pmmap_meta_write(mcur);

	pmmap_sync_inode(mcur, inode);

	mcur->data = (void *)&pmmap_nv_feof_magic;
	mcur->len = sizeof(__le64);
	pmmap_meta_write(mcur);

	return meta_exhaust(mcur) ? -ENOSPC : 0;
}

/*
 * If this happen, pmmapfs is not the choice for you
 */
static void pmmap_meta_exhaust(struct pmmap_super *ps)
{
	WARN_ON(1);
	PWARN("meta(%llx) on %s has been used up\n",
			ps->meta_len,
			ps->sb->s_bdev->bd_disk->disk_name);

	/*
	 * Tell the callers of pmmap_log_reserve NO SPACE
	 */
	set_bit(PMMAP_SUPER_FLAGS_NO_META, &ps->flags);
	/*
	 * Mount the filesystem as READONLY to prevent new write.
	 */
	ps->sb->s_flags |= SB_RDONLY;
}

static int pmmap_resv_and_install_blk(struct pmmap_super *ps,
		struct inode *inode,
		struct pmmap_nv_bmap *nv_bmap)
{
	struct pmmap_alloc_data ad;
	union pmmap_nv_extent ext;
	struct pmmap_block_grp *bg;
	int order, ret;

	ext.val = le64_to_cpu(nv_bmap->extent);
	bg = &ps->bgs[ext.info.blk >> ps->blks_per_grp_shift];
	switch (ext.info.order) {
	case PMMAP_PTE:
		ad.level = &bg->pte;
		ad.len = ext.info.cnt;
		order = 0;
		break;
	case PMMAP_PMD:
		ad.level = &bg->pmd;
		ad.len = 1 << PMMAP_PMD_ORDER;
		order = PMMAP_PMD_ORDER;
		break;
	case PMMAP_PUD:
		ad.level = &bg->pud;
		ad.len = 1 << PMMAP_PUD_ORDER;
		order = PMMAP_PUD_ORDER;
		break;
	default:
		/*
		 * This would only happen when there is bug in code
		 */
		PWARN("invalid extent index %llx blk %llx order %d cnt %d\n",
				le64_to_cpu(nv_bmap->index),
				(u64)ext.info.blk,
				(int)ext.info.order,
				(int)ext.info.cnt);
		return -EINVAL;
	}
	ad.dblk = ext.info.blk;
	PDBG("inode %lu bmap index %llx blk %llx order %d cnt %d\n",
			inode->i_ino,
			le64_to_cpu(nv_bmap->index),
			(u64)ext.info.blk,
			(int)ext.info.order,
			(int)ext.info.cnt);

	ret = pmmap_reserve_level(&ad);
	if (ret) {
		PWARN_LIMIT("reserve blk (%llx %d %d) for ino %lu failed %d\n",
			(u64)ext.info.blk, (int)ext.info.order,
			(int)ext.info.cnt, inode->i_ino, ret);
		return ret;
	}

	if (pmmap_install_blks(PMMAP_I(inode),
			le64_to_cpu(nv_bmap->index), ad.dblk,
			ad.len, order)) {
		PERR("install block for ino %lu failed\n", inode->i_ino);
		return -ENOMEM;
	}
	inode->i_blocks += ad.len * BLOCKS_PER_PAGE;
	pmmap_stat_add(ps, ad.level->level, alloc, ad.len >> order);
	percpu_counter_sub(&ps->free_blks, ad.len);

	return 0;
}

static int pmmap_load_bmap(struct pmmap_meta_cursor *mcur,
		struct inode *inode)
{
	struct pmmap_nv_bmap nv_bmap;
	__le64 magic;
	int ret = 0;

	while (!mcur->eof) {
		mcur->data = &magic;
		mcur->len = sizeof(magic);
		pmmap_meta_read(mcur);
		if (meta_skip(mcur))
			break;
		if (magic == cpu_to_le64(PMMAP_NV_FEOF_MAGIC))
			break;
		memcpy((void *)&nv_bmap, (void *)&magic, sizeof(magic));
		mcur->data = ((void *)&nv_bmap) + sizeof(magic);
		mcur->len = sizeof(nv_bmap) - sizeof(magic);
		pmmap_meta_read(mcur);
		if (meta_skip(mcur))
			break;
		ret = pmmap_resv_and_install_blk(mcur->ps, inode, &nv_bmap);
		if (ret)
			break;
	}

	return ret;
}

static int pmmap_create_empty_inode(
		struct pmmap_super *ps,
		struct inode *dir, struct dentry *dentry,
		u64 ino, umode_t mode)
{
	struct pmmap_create_inode_data cd;
	int ret;

	cd.sb = ps->sb;
	cd.dir = dir;
	cd.dentry = dentry;
	cd.mode = mode;
	cd.replay = true;
	cd.ino = ino;
	cd.tsec = current_time(dir).tv_sec;
	ret = pmmap_create_inode(&cd);
	if (ret)
		return ret;

	if (S_ISDIR(mode))
		inc_nlink(dir);

	pmmap_store_inode(ps, d_inode(dentry),
			PMMAP_STORE_FLAGS_LOOKUP |
			PMMAP_STORE_FLAGS_EMPTY);
	return 0;
}

static int pmmap_load_one_dentry(struct pmmap_super *ps,
		struct dentry *parent,
		struct pmmap_nv_dentry *nde)
{
	struct inode *inode;
	struct dentry *dentry, *old_den;
	u64 ino = le64_to_cpu(nde->inode);
	int ret;

	dentry = d_alloc_name(parent, nde->name);
	if (!dentry) {
		PERR("create dentry %llu(%s) failed\n", ino, nde->name);
		return -ENOMEM;
	}
	d_add(dentry, NULL);

	inode = pmmap_lookup_inode(ps, ino);
	if (!inode) {
		ret = pmmap_create_empty_inode(ps, d_inode(parent),
				dentry, ino, __type_to_ifmt(nde->type));
		if (ret) {
			dput(dentry);
			PERR("create empty inode for %llu failed(%d)\n", ino, ret);
			return ret;
		}
		inode = d_inode(dentry);
		dput(dentry);
		PDBG("create empty inode for %llu(%s) %d\n",
				ino, nde->name, dentry->d_lockref.count);
		return 0;
	} 
	
	old_den = d_find_alias(inode);
	if (old_den->d_parent == ps->lost_found) {
		d_inode(ps->lost_found)->i_size -= BOGO_DIRENT_SIZE;
		if (S_ISDIR(inode->i_mode)) {
			drop_nlink(d_inode(ps->lost_found));
			inc_nlink(d_inode(parent));
		}
		PDBG("move from lost_found to %s/%s\n",
				dentry->d_parent->d_name.name,
				dentry->d_name.name);
		d_move(old_den, dentry);
	} else {
		/*
		 * This should be the hardlink case
		 */
		inc_nlink(inode);
		ihold(inode);
		dget(dentry);
		d_instantiate(dentry, inode);
	}
	d_inode(parent)->i_size += BOGO_DIRENT_SIZE;
	dput(old_den);
	dput(dentry);

	return 0;
}

static int pmmap_load_dentries(
		struct pmmap_meta_cursor *mcur,
		struct inode *dir,
		struct pmmap_nv_dentry *nde)
{
	struct dentry *parent;
	__le64 magic;
	int ret = 0;

	parent = d_find_alias(dir);
	while (!mcur->eof) {
		mcur->data = &magic;
		mcur->len = sizeof(magic);
		pmmap_meta_read(mcur);
		if (meta_skip(mcur))
			break;

		if (magic == cpu_to_le64(PMMAP_NV_FEOF_MAGIC))
			break;

		memcpy((void *)nde, (void *)&magic, sizeof(magic));
		mcur->data = (void *)nde + sizeof(magic);
		mcur->len = sizeof(*nde) - sizeof(magic);
		pmmap_meta_read(mcur);
		if (meta_skip(mcur))
			break;
		mcur->data = nde->name;
		mcur->len = nde->name_len;
		pmmap_meta_read(mcur);
		if (meta_skip(mcur))
			break;
		nde->name[nde->name_len] = 0;
		PDBG("dentry inode %llu name %s\n",
				le64_to_cpu(nde->inode), nde->name);
		ret = pmmap_load_one_dentry(mcur->ps, parent, nde);
		if (ret)
			break;

	}
	dput(parent);
	return ret;
}

/*
 * To support self-fsck during mount, following fields are
 * updated during mount instead of being fixed by the nv_inode.
 * i_blocks is updated after install blocks
 * i_nlink is updated after there is dentry references it
 * i_size of directory is updated when dentry is added into it
 */
static void pmmap_fill_inode_from_meta(struct inode *inode,
		struct pmmap_nv_inode *nv_inode)
{
	int flags;

	inode->i_ino = le64_to_cpu(nv_inode->ino);
	inode->i_mode = le16_to_cpu(nv_inode->mode);
	inode->i_flags = le32_to_cpu(nv_inode->iflags);
	i_uid_write(inode, le32_to_cpu(nv_inode->uid));
	i_gid_write(inode, le32_to_cpu(nv_inode->gid));

	inode->i_atime.tv_sec = (signed)le32_to_cpu(nv_inode->atime);
	inode->i_mtime.tv_sec = (signed)le32_to_cpu(nv_inode->mtime);
	inode->i_ctime.tv_sec = (signed)le32_to_cpu(nv_inode->ctime);

	if (!S_ISDIR(inode->i_mode))
		inode->i_size = le64_to_cpu(nv_inode->size);

	/*
	 * inode has been added to LOOKUP when create empty inode
	 */
	if (PMMAP_I(inode)->admin)
		flags = PMMAP_STORE_FLAGS_ADMIN;
	else
		flags = PMMAP_STORE_FLAGS_SYNC;

	pmmap_store_inode(PMMAP_SB(inode->i_sb), inode, flags);
}

static struct inode *
__pmmap_create_inode_from_meta(struct pmmap_super *ps,
		struct pmmap_nv_inode *nv_inode)
{
	u64 ino = le64_to_cpu(nv_inode->ino);
	struct dentry *dentry;
	char name[128];
	int ret;

	sprintf(name, "%llu", ino);
	dentry = d_alloc_name(ps->lost_found, name);
	if (!dentry) {
		PERR("alloc temporary dentry for %llu failed\n", ino);
		return ERR_PTR(-ENOMEM);
	}

	d_add(dentry, NULL);
	ret = pmmap_create_empty_inode(ps, d_inode(ps->lost_found),
			dentry, ino, le16_to_cpu(nv_inode->mode));
	if (ret) {
		dput(dentry);
		PERR("create empty inode for %llu failed(%d)\n", ino, ret);
		return ERR_PTR(ret);
	}
	dput(dentry);

	pmmap_fill_inode_from_meta(d_inode(dentry), nv_inode);
	PMMAP_I(d_inode(dentry))->empty = false;

	PDBG("create non-linked inode %lu(%s)\n",
			d_inode(dentry)->i_ino, dentry->d_name.name);

	return d_inode(dentry);
}

static struct inode *
pmmap_create_inode_from_meta(struct pmmap_super *ps,
		struct pmmap_nv_inode *nv_inode)
{
	u64 ino = le64_to_cpu(nv_inode->ino);
	struct pmmap_inode *pino;
	struct inode *inode;

	inode = pmmap_lookup_inode(ps, ino);
	if (!inode)
		return __pmmap_create_inode_from_meta(ps, nv_inode);

	pino = PMMAP_I(inode);
	if (!pino->empty) {
		if (inode->i_ino != 0) {
			PWARN("get non-empty inode %lu mode %x blocks %llu\n",
					inode->i_ino,
					inode->i_mode & S_IFMT,
					inode->i_blocks);
		}
		return inode;
	}

	pmmap_fill_inode_from_meta(inode, nv_inode);
	pino->empty = false;
	PDBG("fill empty inode %lu\n", inode->i_ino);

	return inode;
}

static int pmmap_load_symlink(struct pmmap_meta_cursor *mcur,
		struct inode *inode)
{
	if (inode->i_size > PMMAP_SHORT_SYMLINK_LEN)
		return -EINVAL;

	inode->i_link = kmalloc(inode->i_size + 1, GFP_KERNEL);
	if (!inode->i_link)
		return -ENOMEM;

	mcur->data = inode->i_link;
	mcur->len = inode->i_size;
	pmmap_meta_read(mcur);
	inode->i_link[inode->i_size] = 0;

	return 0;
}

static int pmmap_discard_empty_inode(struct inode *inode,
		void *priv)
{
	struct inode *dir;
	struct dentry *dentry;
	int *cnt = priv;
	int n;

	*cnt = *cnt + 1;
	n = S_ISDIR(inode->i_mode) ? 1 : inode->i_nlink;
	while (n) {
		/*
		 * This inode could have multiple dentries linked to it.
		 */
		dentry = d_find_alias(inode);
		dir = d_inode(dentry->d_parent);
		pmmap_unlink_inode(dir, dentry, dir->i_ctime.tv_sec, true);
		if (S_ISDIR(inode->i_mode)) {
			drop_nlink(inode);
			drop_nlink(dir);
		}
		d_delete(dentry);
		d_drop(dentry);
		dput(dentry);
		n--;
	}

	return 0;
}

static int pmmap_load_meta(struct pmmap_meta_cursor *mcur)
{
	struct pmmap_super *ps = mcur->ps;
	struct pmmap_nv_inode nv_inode;
	struct pmmap_nv_dentry *nde;
	struct inode *inode;
	__le64 magic;
	int ret = 0;

	nde = kmalloc(sizeof(*nde) + 256, GFP_KERNEL);
	if (!nde)
		return -ENOMEM;

	while (!mcur->eof) {
		mcur->data = &magic;
		mcur->len = sizeof(magic);
		pmmap_meta_read(mcur);
		if (meta_skip(mcur))
			continue;

		if (magic != cpu_to_le64(PMMAP_NV_FILE_MAGIC))
			continue;

		mcur->data = &nv_inode;
		mcur->len = sizeof(nv_inode);
		pmmap_meta_read(mcur);
		if (meta_skip(mcur))
			continue;

		PDBG("load inode %llu size %llu mode %x atime %x ctime %x\n",
				le64_to_cpu(nv_inode.ino),
				le64_to_cpu(nv_inode.size),
				le16_to_cpu(nv_inode.mode),
				le32_to_cpu(nv_inode.atime),
				le32_to_cpu(nv_inode.ctime));

		inode = pmmap_create_inode_from_meta(ps, &nv_inode);
		if (IS_ERR(inode))
			return PTR_ERR(inode);

		switch (le16_to_cpu(nv_inode.mode) & S_IFMT) {
		case S_IFREG:
			ret = pmmap_load_bmap(mcur, inode);
			break;
		case S_IFDIR:
			ret = pmmap_load_dentries(mcur, inode, nde);
			break;
		case S_IFLNK:
			ret = pmmap_load_symlink(mcur, inode);
			break;
		default:
			/*
			 * This should not happen
			 */
			PWARN("inode %llu type %x is not supported\n",
					le64_to_cpu(nv_inode.ino),
					le16_to_cpu(nv_inode.mode) & S_IFMT);
			break;
		}

		if (mnt_stop(ps, ret))
			return ret;
	}

	return 0;
}

static inline bool __ref_drain(struct pmmap_meta_context *mc)
{
	return !(READ_ONCE(mc->factor.info.ref) & PMMAP_LOG_REF_MASK);
}

static inline bool __ref_avail(struct pmmap_meta_context *mc)
{
	return READ_ONCE(mc->factor.info.ref) < PMMAP_LOG_MAX_REF;
}

static inline bool __no_space(struct pmmap_super *ps)
{
	return test_bit(PMMAP_SUPER_FLAGS_NO_META, &ps->flags);
}

/*
 * guarantee all of the previous log transaction has passed
 */
static void __pmmap_log_barrier(struct pmmap_meta_context *mc)
{
	union pmmap_log_factor factor;
	u64 old;

	while (1) {
		old = factor.val = READ_ONCE(mc->factor.val);
		factor.info.ref |= PMMAP_LOG_REF_BARRIER;
		if (cmpxchg(&mc->factor.val, old, factor.val) == old)
			break;
	}

	while(!wait_event_timeout(mc->wait_drain,
		    __ref_drain(mc), 100)) {}

	while (1) {
		old = factor.val = READ_ONCE(mc->factor.val);
		if (!(factor.info.ref & PMMAP_LOG_REF_BARRIER))
			break;
		factor.info.ref &= ~PMMAP_LOG_REF_BARRIER;
		if (cmpxchg(&mc->factor.val, old, factor.val) == old)
			break;
	}
	wake_up_all(&mc->wait_avail);
}

void pmmap_log_barrier(struct pmmap_super *ps)
{
	return __pmmap_log_barrier(&ps->meta.fs_ctx);
}

static void __pmmap_kick_off_sync(struct pmmap_meta_context *mc,
		bool wait)
{
 	union pmmap_log_factor factor;
	u64 old;

	old = factor.val = READ_ONCE(mc->factor.val);
	if (factor.info.ref >= PMMAP_LOG_REF_FLUSH)
		return;

	factor.info.ref += PMMAP_LOG_REF_FLUSH;
	if (cmpxchg(&mc->factor.val, old, factor.val) == old) {
		/*
		 * We win, start the sync process
		 */
		mc->ops->sync(mc);
	}

	if (wait)
		wait_event(mc->wait_avail,
			__ref_avail(mc) || __no_space(mc->ps));
}

void pmmap_sync_all_meta(struct pmmap_super *ps)
{
	__pmmap_kick_off_sync(&ps->meta.fs_ctx, true);
	__pmmap_kick_off_sync(&ps->meta.admin_ctx, true);
}

static void pmmap_log_reserve_slow(struct pmmap_meta_context *mc, int len)
{
 	union pmmap_log_factor factor;
	u64 old;

	old = factor.val = READ_ONCE(mc->factor.val);
	if (factor.info.ref < PMMAP_LOG_MAX_REF &&
	    (factor.info.off + len <= mc->log_len))
		return;
	/*
	 * Log space is not enough, start sync process
	 */
	if (factor.info.ref < PMMAP_LOG_MAX_REF)
		__pmmap_kick_off_sync(mc, false);

	wait_event(mc->wait_avail,
		__ref_avail(mc) || __no_space(mc->ps));
}

static int __pmmap_log_reserve(struct pmmap_meta_context *mc, int len)
{
	union pmmap_log_factor factor;
	u64 old;
	int ret = -ENOSPC;

	while (!__no_space(mc->ps)) {
		ret = -ENOSPC;
		old = factor.val = READ_ONCE(mc->factor.val);
		if (factor.info.off + len > mc->log_len ||
		    factor.info.ref >= PMMAP_LOG_MAX_REF) {
			pmmap_log_reserve_slow(mc, len);
			continue;
		}

		ret = factor.info.off;
		factor.info.off += len;
		factor.info.ref += 1;
		if (cmpxchg(&mc->factor.val,
					old, factor.val) == old)
			break;
	}

	return ret;
}

int pmmap_log_reserve(struct pmmap_super *ps, int len)
{
	return __pmmap_log_reserve(&ps->meta.fs_ctx, len);
}

static void __pmmap_log_release(struct pmmap_meta_context *mc)
{
	union pmmap_log_factor factor;
	u64 old;

	while (1) {
		old = factor.val = READ_ONCE(mc->factor.val);
		factor.info.ref -= 1;
		if (cmpxchg(&mc->factor.val, old, factor.val) == old)
			break;
	}

	factor.val = old;

	if ((factor.info.ref & PMMAP_LOG_REF_MASK) == 1) {
		if (factor.info.ref & (PMMAP_LOG_REF_FLUSH | PMMAP_LOG_REF_BARRIER))
			wake_up(&mc->wait_drain);
	} else if (factor.info.ref >= PMMAP_LOG_MAX_REF) {
		if (waitqueue_active(&mc->wait_avail))
		    wake_up(&mc->wait_avail);
	}
}

void pmmap_log_release(struct pmmap_super *ps)
{
	return __pmmap_log_release(&ps->meta.fs_ctx);
}

int opcode_to_len[PMMAP_OP_MAX];

void pmmap_log_module_init(void )
{
	int namelen = 256;
	int rec = sizeof(struct pmmap_log_record);

	opcode_to_len[PMMAP_CREATE] = round_up(rec +
			sizeof(struct pmmap_log_create) + namelen, 64);
	opcode_to_len[PMMAP_LINK] = round_up(rec +
			sizeof(struct pmmap_log_link) + namelen, 64);
	opcode_to_len[PMMAP_UNLINK] = round_up(rec +
			sizeof(struct pmmap_log_unlink) + namelen, 64);
	opcode_to_len[PMMAP_SYMLINK] = round_up(rec +
			sizeof(struct pmmap_log_symlink) + 2 * namelen, 64);
	opcode_to_len[PMMAP_REANME] = round_up(rec +
			sizeof(struct pmmap_log_rename) + 2 * namelen, 64);
	opcode_to_len[PMMAP_SETATTR] = round_up(rec +
			sizeof(struct pmmap_log_setattr), 64);

	opcode_to_len[PMMAP_INSTALL] = round_up(rec +
			sizeof(struct pmmap_log_install) +
			PMMAP_MAX_PTE_BATCH * sizeof(struct pmmap_nv_bmap), 64);

	opcode_to_len[PMMAP_SIZE] = round_up(rec +
			sizeof(struct pmmap_log_size), 64);
}

int pmmap_log_start(struct pmmap_log_cursor *lcur,
		struct pmmap_super *ps, int opcode, bool admin)
{
	struct pmmap_meta_context *ctx;
	int resv_len = opcode_to_len[opcode];
	int off;

	ctx = admin ? &ps->meta.admin_ctx : &ps->meta.fs_ctx;
	lcur->ctx = ctx;
	lcur->opcode = opcode;
	lcur->fin_len = sizeof(struct pmmap_log_record);
	lcur->first = true;

	off = __pmmap_log_reserve(ctx, resv_len);
	if (off < 0)
		return off;

	PDBG("op %d resv len %d get off %d\n",
			opcode, resv_len, off);
	lcur->resv_addr = ctx->log_kaddr + off;

	return 0;
}

void pmmap_log_finish(struct pmmap_log_cursor *lcur,
		bool success)
{
	struct pmmap_log_record *rec = lcur->resv_addr;
	struct timespec64 now;

	ktime_get_coarse_real_ts64(&now);
	/*
	 * Round it up to cacheline
	 */
	lcur->fin_len = round_up(lcur->fin_len, 64);

	rec->magic = cpu_to_le64(PMMAP_LOG_RECORD_MAGIC);
	rec->ver = cpu_to_le64(lcur->ctx->meta_ver);
	rec->ino = cpu_to_le64(lcur->ino);
	rec->crc = 0;

	/*
	 * If the operation fails, we need to skip its log
	 */
	if (!success)
		rec->opflags = cpu_to_le16(lcur->opcode | REC_OP_FAIL);
	else
		rec->opflags = cpu_to_le16(lcur->opcode);

	rec->len = cpu_to_le16(lcur->fin_len);
	rec->time = cpu_to_le32(now.tv_sec);

	rec->crc = crc32(PMMAP_CRC_SEED, (void *)rec, lcur->fin_len);
	arch_wb_cache_pmem((void *)rec, lcur->fin_len);

	__pmmap_log_release(lcur->ctx);
}

static inline void *log_body(struct pmmap_log_cursor *lcur)
{
	return (void *)((struct pmmap_log_record *)lcur->resv_addr + 1);
}

static inline void *log_body2(struct pmmap_log_record *rec)
{
	return (void *)(rec + 1);
}

void pmmap_log_record_create(struct pmmap_log_cursor *lcur,
		struct inode *dir, struct dentry *dentry)
{
	struct pmmap_log_create *create = log_body(lcur);
	struct inode *inode = d_inode(dentry);
	const char *name = dentry->d_name.name;
	int len = strlen(name);

	lcur->ino = inode->i_ino;

	create->dir_ino = cpu_to_le64(dir->i_ino);
	create->mode = cpu_to_le16(inode->i_mode);
	create->name_len = len;
	memcpy(create->name, name, len);
	create->name[len] = 0;

	lcur->fin_len += sizeof(*create) + len + 1;
}

void pmmap_log_record_link(struct pmmap_log_cursor *lcur,
		 struct inode *inode, struct inode *dir,
		 struct dentry *dentry)
{
	struct pmmap_log_link *link = log_body(lcur);
	const char *link_name = dentry->d_name.name;
	int len = strlen(link_name);

	lcur->ino = inode->i_ino;

	link->dir_ino = dir->i_ino;
	link->name_len = len;
	memcpy(link->name, link_name, len);
	link->name[len] = 0;

	lcur->fin_len += sizeof(*link) + len + 1;
}

void pmmap_log_record_unlink(struct pmmap_log_cursor *lcur,
		struct inode *dir, struct dentry *dentry)
{
	struct pmmap_log_unlink *unlink = log_body(lcur);
	const char *name = dentry->d_name.name;
	int len = strlen(name);

	lcur->ino = d_inode(dentry)->i_ino;
	unlink->dir_ino = cpu_to_le64(dir->i_ino);
	unlink->name_len = len;
	memcpy(unlink->name, name, len);
	unlink->name[len] = 0;

	lcur->fin_len += sizeof(*unlink) + len + 1;
}

void pmmap_log_record_symlink(struct pmmap_log_cursor *lcur,
		struct inode *dir, struct dentry *dentry,
		const char *link_name)
{
	struct pmmap_log_symlink *symlink = log_body(lcur);
	int link_len = strlen(link_name);
	int name_len = strlen(dentry->d_name.name);

	lcur->ino = d_inode(dentry)->i_ino;

	symlink->dir_ino = cpu_to_le64(dir->i_ino);
	symlink->name_len = name_len;
	symlink->link_len = link_len;
	memcpy(symlink->name, dentry->d_name.name, name_len + 1);
	memcpy(symlink->name + name_len + 1,
			link_name, link_len + 1);

	lcur->fin_len += sizeof(*symlink) + name_len + link_len + 2;
}

void pmmap_log_record_rename(struct pmmap_log_cursor *lcur,
		struct inode *old_dir, struct dentry *old_den,
		struct inode *new_dir, struct dentry *new_den)
{
	struct pmmap_log_rename *rename = log_body(lcur);
	char *name;
	int len;

	lcur->ino = d_inode(old_den)->i_ino;

	rename->old_dir = cpu_to_le64(old_dir->i_ino);
	rename->new_dir = cpu_to_le64(new_dir->i_ino);

	/*
	 * Because of hardlink, an inode(non-dir) could have multiple
	 * dentries. We have to record the name of both old and new
	 * dentry.
	 */
	name = rename->name;
	len = strlen(old_den->d_name.name);
	rename->old_len = len;
	memcpy(name, old_den->d_name.name, len);
	name[len] = 0;
	lcur->fin_len += len + 1;

	name += len + 1;
	len = strlen(new_den->d_name.name);
	rename->new_len = len;
	memcpy(name, new_den->d_name.name, len);
	name[len] = 0;
	lcur->fin_len += len + 1;

	lcur->fin_len += sizeof(*rename);
}

void pmmap_log_record_size(struct pmmap_log_cursor *lcur,
		struct inode *inode)
{
	struct pmmap_log_size *sz = log_body(lcur);

	lcur->ino = inode->i_ino;
	sz->size = cpu_to_le64(i_size_read(inode));
}

void pmmap_log_record_install(struct pmmap_log_cursor *lcur,
		struct inode *inode, u64 index,
		u64 dblk, int order, int cnt)
{
	struct pmmap_log_install *install = log_body(lcur);
	struct pmmap_nv_bmap *nv_bmap;
	union pmmap_nv_extent ext;

	PDBG("inode %lu index %llx dlblk %llx order %d cnt %d\n",
			inode->i_ino, index, dblk, order, cnt);
	lcur->ino = inode->i_ino;
	ext.info.blk = dblk;
	switch (order) {
	case 0:
		ext.info.order = PMMAP_PTE;
		ext.info.cnt = cnt;
		break;
	case PMMAP_PMD_ORDER:
		ext.info.order = PMMAP_PMD;
		ext.info.cnt = 1;
		break;
	case PMMAP_PUD_ORDER:
		ext.info.order = PMMAP_PUD;
		ext.info.cnt = 1;
		break;
	default:
		break;
	}

	if (lcur->first) {
		lcur->ino = inode->i_ino;
		lcur->fin_len += sizeof(*install);
		lcur->first = false;
		install->bmap_cnt = 0;
	}

	nv_bmap = &install->nv_bmaps[install->bmap_cnt];
	nv_bmap->index = cpu_to_le64(index);
	nv_bmap->extent = cpu_to_le64(ext.val);
	install->bmap_cnt++;

	lcur->fin_len += sizeof(*nv_bmap);
}

void pmmap_log_record_setattr(struct pmmap_log_cursor *lcur,
		struct inode *inode, struct iattr *attr)
{
	struct pmmap_log_setattr *sa = log_body(lcur);

	lcur->ino = inode->i_ino;

	sa->valid = cpu_to_le32(attr->ia_valid);
	sa->mode = cpu_to_le16(attr->ia_mode);
	sa->uid = cpu_to_le32(attr->ia_uid.val);
	sa->gid = cpu_to_le32(attr->ia_gid.val);
	sa->size = cpu_to_le64(attr->ia_size);
	sa->atime = cpu_to_le32(attr->ia_atime.tv_sec);
	sa->mtime = cpu_to_le32(attr->ia_mtime.tv_sec);
	sa->ctime = cpu_to_le32(attr->ia_ctime.tv_sec);

	lcur->fin_len += sizeof(*sa);
}

static struct dentry *__lookup_dentry(struct inode *dir,
		char *name, bool create)
{
	struct qstr dname;
	struct dentry *dir_den, *den;

	PDBG("lookup %lu/%s\n", dir->i_ino, name);

	dir_den = d_find_alias(dir);
	BUG_ON(!dir_den);

	dname.name = name;
	dname.hash_len = hashlen_string(dir_den, name);
	den = d_lookup(dir_den, &dname);
	if (den || !create)
		goto out;

	den = d_alloc(dir_den, &dname);
out:
	dput(dir_den);
	return den;
}

static int log_replay_create(struct pmmap_super *ps,
		struct pmmap_log_record *rec)
{
	struct pmmap_create_inode_data cd;
	struct pmmap_log_create *create = log_body2(rec);
	struct inode *dir, *inode;
	struct dentry *dir_den, *dentry;
	const char *err;
	int ret;

	dir = pmmap_lookup_inode(ps, le64_to_cpu(create->dir_ino));
	if (!dir) {
		err = "no dir";
		ret = -ENOENT;
		goto error;
	}

	inode = pmmap_lookup_inode(ps, le64_to_cpu(rec->ino));
	if (inode) {
		err = "exist";
		ret = -EEXIST;
		goto error;
	}

	dir_den = d_find_alias(dir);
	dentry = d_alloc_name(dir_den, create->name);
	dput(dir_den);
	if (!dentry) {
		ret = -ENOMEM;
		err = "no dentry";
		goto error;
	}
	d_add(dentry, NULL);

	cd.sb = ps->sb;
	cd.dir = dir;
	cd.dentry = dentry;
	cd.mode = le16_to_cpu(create->mode);
	cd.replay = true;
	cd.ino = le64_to_cpu(rec->ino);
	cd.tsec = le32_to_cpu(rec->time);
	ret = pmmap_create_inode(&cd);
	if (ret) {
		dput(dentry);
		err = "create inode";
		goto error;
	}
	PDBG("create inode %llu(%s %s) in inode %llu\n",
			le64_to_cpu(rec->ino),
			create->name,
			S_ISDIR(cd.mode) ? "dir" : "file",
			le64_to_cpu(create->dir_ino));

	if (PMMAP_I(d_inode(dentry))->admin)
		ret = PMMAP_STORE_FLAGS_LOOKUP | PMMAP_STORE_FLAGS_ADMIN;
	else
		ret = PMMAP_STORE_FLAGS_LOOKUP | PMMAP_STORE_FLAGS_SYNC;

	pmmap_store_inode(ps, d_inode(dentry), ret);

	if (S_ISDIR(d_inode(dentry)->i_mode))
		inc_nlink(dir);

	dput(dentry);

	return 0;
error:
	PERR("create %llu(%s) in %llu failed(%s, %d)\n",
			le64_to_cpu(rec->ino),
			create->name,
			le64_to_cpu(create->dir_ino),
			err, ret);
	return ret;
}

static int log_replay_link(struct pmmap_super *ps,
		struct pmmap_log_record *rec)
{
	struct pmmap_log_link *link = log_body2(rec);
	struct inode *dir, *inode;
	struct dentry *dir_den, *src_den, *dentry;
	const char *err;
	int ret;

	dir_den = NULL;
	src_den = NULL;
	PDBG("link inode %llu to dir %llu/%s\n",
			le64_to_cpu(rec->ino),
			le64_to_cpu(link->dir_ino),
			link->name);

	ret = -ENOENT;
	dir = pmmap_lookup_inode(ps, le64_to_cpu(link->dir_ino));
	if (!dir) {
		err = "no dir";
		goto error;
	}

	inode = pmmap_lookup_inode(ps, le64_to_cpu(rec->ino));
	if (!inode) {
		err = "no inode";
		goto error;
	}

	dir_den = d_find_alias(dir);
	dentry = d_alloc_name(dir_den, link->name);
	if (!dentry) {
		err = "no dentry";
		ret = -ENOMEM;
		goto error;
	}
	d_add(dentry, NULL);

	src_den = d_find_alias(inode);
	ret = pmmap_link_inode(src_den, dir,
			dentry, le32_to_cpu(rec->time));
	dput(dentry);
	if (ret) {
		err = "link inode";
		goto error;
	}

	dput(dir_den);
	dput(src_den);
	return 0;
error:
	if (dir_den)
		dput(dir_den);
	if (src_den)
		dput(src_den);
	PERR("link %llu in %llu/%s failed(%s, %d)\n",
			le64_to_cpu(rec->ino),
			le64_to_cpu(link->dir_ino),
			link->name,
			err, ret);
	return ret;
}

static int log_replay_unlink(struct pmmap_super *ps,
		struct pmmap_log_record *rec)
{
	struct pmmap_log_unlink *unlink = log_body2(rec);
	struct inode *dir, *inode;
	struct dentry *dentry;
	const char *err;
	int ret;

	dir = pmmap_lookup_inode(ps, le64_to_cpu(unlink->dir_ino));
	if (!dir) {
		err = "no dir";
		ret = -ENOENT;
		goto error;
	}

	dentry = __lookup_dentry(dir, unlink->name, false);
	inode = d_inode(dentry);

	PDBG("unlink %llu/%s -> inode %lu\n",
			le64_to_cpu(unlink->dir_ino),
			unlink->name, inode->i_ino);

	pmmap_unlink_inode(dir, dentry, le32_to_cpu(rec->time), true);
	if (S_ISDIR(inode->i_mode)) {
		drop_nlink(inode);
		drop_nlink(dir);
	}
	d_delete(dentry);
	d_drop(dentry);
	dput(dentry);

	return 0;
error:
	PERR("unlink %llu/%s failed(%s)\n",
			le64_to_cpu(unlink->dir_ino),
			unlink->name,
			err);
	return ret;

}

static int log_replay_symlink(struct pmmap_super *ps,
		struct pmmap_log_record *rec)
{
	struct pmmap_log_symlink *symlink = log_body2(rec);
	char *link_name = symlink->name + symlink->name_len + 1;
	struct inode *dir;
	struct dentry *dir_den, *dentry;
	const char *err;
	int ret;

	PDBG("symlink inode %llu/%s to %llu(%s)\n",
			le64_to_cpu(symlink->dir_ino),
			symlink->name, le64_to_cpu(rec->ino),
			link_name);

	dir = pmmap_lookup_inode(ps, le64_to_cpu(symlink->dir_ino));
	if (!dir) {
		err = "no dir";
		ret = -ENOENT;
		goto error;
	}

	dir_den = d_find_alias(dir);
	dentry = d_alloc_name(dir_den, symlink->name);
	dput(dir_den);
	if (!dentry) {
		err = "no dentry";
		ret = -ENOMEM;
		goto error;
	}
	d_add(dentry, NULL);
	ret = pmmap_symlink_inode(dir, dentry, link_name,
			le32_to_cpu(rec->time), le64_to_cpu(rec->ino));
	dput(dentry);
	if (ret) {
		PERR("pmmap_symlink_inode returns %d\n", ret);
		err = "symlink failed";
		goto error;
	}

	return 0;
error:
	PERR("symlink inode %llu/%s to %s failed(%s, %d)\n",
			le64_to_cpu(symlink->dir_ino),
			symlink->name,
			link_name, err, ret);
	return ret;
}

static int log_replay_rename(struct pmmap_super *ps,
		struct pmmap_log_record *rec)
{
	struct pmmap_log_rename *rename = log_body2(rec);
	struct inode *old_dir, *new_dir;
	struct dentry *old_den, *new_den;
	const char *err;
	int ret = -ENOENT;

	old_den = NULL;
	new_den = NULL;
	old_dir = pmmap_lookup_inode(ps, le64_to_cpu(rename->old_dir));
	if (!old_dir) {
		err = "no old dir";
		goto error;
	}

	new_dir = pmmap_lookup_inode(ps, le64_to_cpu(rename->new_dir));
	if (!new_dir) {
		err = "no new dir";
		goto error;
	}

	old_den = __lookup_dentry(old_dir, rename->name, false);
	if (!old_den) {
		err = "no old dentry";
		goto error;
	}

	new_den = __lookup_dentry(new_dir,
			rename->name + rename->old_len + 1, true);
	if (!new_den) {
		err = "no new dentry";
		goto error;
	}
	
	ret = pmmap_rename_inode(old_dir, old_den, new_dir,
			new_den, le32_to_cpu(rec->time));
	if (ret) {
		err = "rename failed";
		goto error;
	}
	d_move(old_den, new_den);
	dput(old_den);
	dput(new_den);

	return 0;
error:
	if (old_den)
		dput(old_den);
	if (new_den)
		dput(new_den);
	PERR("rename %llu/%s to %llu/%s failed(%s, %d)\n",
				le64_to_cpu(rename->old_dir),
				rename->name,
				le64_to_cpu(rename->new_dir),
				rename->name + rename->old_len + 1,
				err, ret);
	return ret;
}

static int log_replay_install(struct pmmap_super *ps,
		struct pmmap_log_record *rec)
{
	struct pmmap_log_install *install = log_body2(rec);
	struct inode *inode;
	int i, cnt, ret;
	const char *err;

	inode = pmmap_lookup_inode(ps, le64_to_cpu(rec->ino));
	if (!inode) {
		err = "no inode";
		ret = -ENOENT;
		goto error;
	}
	cnt = install->bmap_cnt;
	PDBG("inode %llu bmap_cnt %d\n",
			i_size_read(inode), cnt);
	for (i = 0; i < cnt; i++) {
		ret = pmmap_resv_and_install_blk(ps, inode, &install->nv_bmaps[i]);
		if (ret) {
			err = "resv install";
			goto error;
		}
	}

	inode->i_ctime.tv_sec = le32_to_cpu(rec->time);
	return 0;
error:
	PERR("install blk to inode %llu failed(%s, %d)\n",
			le64_to_cpu(rec->ino), err, ret);
	return ret;
}

static int log_replay_size(struct pmmap_super *ps,
		struct pmmap_log_record *rec)
{
	struct pmmap_log_size *sz = log_body2(rec);
	struct inode *inode;
	const char *err;

	inode = pmmap_lookup_inode(ps, le64_to_cpu(rec->ino));
	if (!inode) {
		err = "no inode";
		goto error;
	}

	i_size_write(inode, le64_to_cpu(sz->size));
	inode->i_ctime.tv_sec = le32_to_cpu(rec->time);

	return 0;
error:
	PERR("update size of inode %llu failed(%s)\n",
			le64_to_cpu(rec->ino), err);

	return -ENOENT;
}

static int log_replay_setattr(struct pmmap_super *ps,
		struct pmmap_log_record *rec)
{
	struct pmmap_log_setattr *sa = log_body2(rec);
	struct inode *inode;
	struct dentry *dentry;
	struct iattr attr;
	const char *err;

	memset(&attr, 0, sizeof(attr));
	inode = pmmap_lookup_inode(ps, le64_to_cpu(rec->ino));
	if (!inode) {
		err = "no inode";
		goto error;
	}

	dentry = d_find_alias(inode);

	attr.ia_valid = le32_to_cpu(sa->valid);
	attr.ia_mode = le16_to_cpu(sa->mode);
	attr.ia_uid.val = le32_to_cpu(sa->uid);
	attr.ia_gid.val = le32_to_cpu(sa->gid);
	attr.ia_size = le64_to_cpu(sa->size);
	attr.ia_atime.tv_sec = le32_to_cpu(sa->atime);
	attr.ia_mtime.tv_sec = le32_to_cpu(sa->mtime);
	attr.ia_ctime.tv_sec = le32_to_cpu(sa->ctime);

	pmmap_setattr_inode(dentry, &attr);
	dput(dentry);

	return 0;
error:
	PERR("setattr inode %llu failed(%s)\n",
			le64_to_cpu(rec->ino), err);
	return -ENOENT;
}

static bool __log_record_stop(struct pmmap_log_record *rec, u64 ver)
{
	u16 opcode, len;
	u32 crc, calc, zero = 0;

	if (le64_to_cpu(rec->magic) != PMMAP_LOG_RECORD_MAGIC)
		return true;

	if (le64_to_cpu(rec->ver) != ver)
		return true;

	opcode = REC_OP(le16_to_cpu(rec->opflags));
	if (opcode >= PMMAP_OP_MAX)
		return true;

	len = le16_to_cpu(rec->len);
	if (len > opcode_to_len[opcode])
		return true;

	crc = le32_to_cpu(rec->crc);
	calc = crc32(PMMAP_CRC_SEED, (void *)rec, 8);
	calc = crc32(calc, &zero, 4);
	calc = crc32(calc, (void *)rec + 12, len - 12);
	if (calc != crc)
		return true;

	return false;
}

#ifdef PMMAP_DEBUG
static const char *opcode_str[] = {
	"create",
	"link",
	"unlink",
	"symlink",
	"rename",
	"install",
	"setattr",
	"size",
	NULL
};
#endif

static int pmmap_log_replay(struct pmmap_meta_context *mc)
{
	struct pmmap_super *ps = mc->ps;
	void *kaddr = mc->log_kaddr;
	void *end = kaddr + mc->log_len;
	struct pmmap_log_record *rec;
	u16 opcode, opflags;
	int ret = 0;

	while (kaddr <= end) {
		rec = kaddr;

		PDBG("rec magic %llx ver %llu(%llu)\n",
 				le64_to_cpu(rec->magic),
				le64_to_cpu(rec->ver), mc->meta_ver);

		if (__log_record_stop(rec, mc->meta_ver))
			break;

		opflags = le16_to_cpu(rec->opflags);
		opcode = REC_OP(opflags);

		/*
		 * Skip the log of failed operation
		 */
		if (opflags & REC_OP_FAIL) {
			kaddr += opcode_to_len[opcode];
			continue;
		}

		PDBG("replay op %s len %d\n",
				opcode_str[le16_to_cpu(opcode)],
				le16_to_cpu(rec->len));

		switch (opcode) {
		case PMMAP_CREATE:
			ret = log_replay_create(ps, rec);
			break;
		case PMMAP_LINK:
			ret = log_replay_link(ps, rec);
			break;
		case PMMAP_UNLINK:
			ret = log_replay_unlink(ps, rec);
			break;
		case PMMAP_SYMLINK:
			ret = log_replay_symlink(ps, rec);
			break;
		case PMMAP_REANME:
			ret = log_replay_rename(ps, rec);
			break;
		case PMMAP_INSTALL:
			ret = log_replay_install(ps, rec);
			break;
		case PMMAP_SETATTR:
			ret = log_replay_setattr(ps, rec);
			break;
		case PMMAP_SIZE:
			ret = log_replay_size(ps, rec);
			break;
		default:
			break;
		}

		if (mnt_stop(ps, ret))
			break;

		kaddr += opcode_to_len[opcode];
	}

	/*
	 * Append new log after mount
	 */
	mc->factor.info.off = kaddr - mc->log_kaddr;

	return ret;
}

static int __direct_access_page(struct pmmap_meta_cursor *mcur, bool read)
{
	void *kaddr = mcur->priv + mcur->off;

	if (read)
		memcpy((void *)mcur->page, kaddr, PAGE_SIZE);
	else
		memcpy_flushcache(kaddr, (void *)mcur->page, PAGE_SIZE);

	return 0;
}

static void pmmap_admin_meta_commit(struct pmmap_meta_cursor *mcur)
{
	union pmmap_sb_factor factor;
	struct pmmap_super *ps = mcur->ps;
	struct pmmap_nv_sb *in_core = ps->nv_sb.in_core;
	struct pmmap_nv_sb *primary = ps->nv_sb.primary;
	struct pmmap_nv_sb *secondary = ps->nv_sb.secondary;
	struct pmmap_meta_context *mc = &ps->meta.admin_ctx;
	__le64 val;
	int index;

	factor.val = le64_to_cpu(in_core->factor);
	index = factor.info.sync_seq % 2;
	/*
	 * Modify the metadata info in core
	 */
	in_core->meta[index].end = cpu_to_le64(mcur->off) + PAGE_SIZE;
	in_core->meta[index].ver = mc->meta_ver + 1;
	/*
	 * calculate crc of the nv_sb
	 */
	factor.info.crc = crc32(PMMAP_CRC_SEED, (void *)in_core, sizeof(*in_core));
	/*
	 * Modify the metadata info on pmem
	 */
	memcpy_flushcache(&primary->meta[index],
			  &in_core->meta[index],
			  sizeof(struct pmmap_nv_meta));
	memcpy_flushcache(&secondary->meta[index],
			  &in_core->meta[index],
			  sizeof(struct pmmap_nv_meta));
	/*
	 * Modify the metadata factor which is atomic
	 */
	val = cpu_to_le64(factor.val);
	memcpy_flushcache(&primary->factor, &val, sizeof(val));
	memcpy_flushcache(&secondary->factor, &val, sizeof(val));
	/*
	 * Push to next sync transaction
	 */
	factor.info.crc = 0;
	factor.info.sync_seq++;
	in_core->factor = cpu_to_le64(factor.val);

	mc->meta_ver++;
	/*
	 * log factor is a in-core variable. On pmem, we use meta_ver and crc32
	 * to know the end of log. Zeroing log factor will get rid of all of
	 * the intend log.
	 */
	WRITE_ONCE(mc->factor.val, 0);
	PDBG("sync_seq %u meta version %llu\n", factor.info.sync_seq, mc->meta_ver);
}

/*
 * Even if there is no log, we still need to sync. This is to
 * guarantee the inode time to be synced to disk when fs sync.
 */
void pmmap_sync_admin_meta(struct pmmap_super *ps)
{
	struct pmmap_nv_sb *nv_sb = ps->nv_sb.in_core;
	struct pmmap_meta_cursor mcur;
	union pmmap_sb_factor factor;
	int index;

	__pmmap_meta_cursor_reset(&mcur, ps);
	mcur.page = ps->meta.admin_sync_page;

	factor.val = le64_to_cpu(nv_sb->factor);
	index = factor.info.sync_seq % 2;

	mcur.access_page = __direct_access_page;
	mcur.off = 0;
	mcur.end = ps->admin.meta_len;
	mcur.priv = ps->meta_kaddr + ps->admin.meta_off[index];

	pmmap_iterate_admin_inodes(ps,
			__pmmap_sync_meta, &mcur);
	mcur.len = 0;
	mcur.last = true;
	pmmap_meta_write(&mcur);
	if (meta_exhaust(&mcur))
		pmmap_meta_exhaust(ps);
	else
		pmmap_admin_meta_commit(&mcur);
}

static u64 pmmap_admin_meta_size(struct pmmap_meta_context *mc)
{
	struct pmmap_nv_sb *in_core = mc->ps->nv_sb.in_core;
	union pmmap_sb_factor factor;
	int index;

	factor.val = le64_to_cpu(in_core->factor);
	index = factor.info.sync_seq % 2;
	return le64_to_cpu(in_core->meta[index].end);
}

static int pmmap_admin_sync(struct pmmap_meta_context *mc)
{
	struct pmmap_super *ps = mc->ps;

	while(!wait_event_timeout(mc->wait_drain,
				__ref_drain(mc), 100)){}

	pmmap_sync_admin_meta(ps);
	wake_up_all(&mc->wait_avail);

	return 0;
}

static int pmmap_admin_load(struct pmmap_meta_context *mc)
{
	struct pmmap_super *ps = mc->ps;
	struct pmmap_nv_sb *nv_sb = ps->nv_sb.in_core;
	struct pmmap_meta_cursor mcur;
	union pmmap_sb_factor factor;
	int index, ret;

	__pmmap_meta_cursor_reset(&mcur, ps);
	mcur.page = ps->meta.admin_sync_page;

	factor.val = le64_to_cpu(nv_sb->factor);
	index = factor.info.sync_seq % 2;

	mcur.access_page = __direct_access_page;
	mcur.off = 0;
	mcur.end = le64_to_cpu(nv_sb->meta[index].end);
	mcur.priv = ps->meta_kaddr + ps->admin.meta_off[index];

	ret = pmmap_load_meta(&mcur);
	if (ret)
		return ret;

	/*
	 * Note, empty inodes in .admin means metada data lost
	 */
	ret = 0;
	pmmap_iterate_empty_inodes(ps,
			pmmap_discard_empty_inode, &ret);
	if (ret)
		PERR("discard %d inodes\n", ret);

	return 0;
}

static struct pmmap_meta_ops admin_meta_ops = {
	.meta_size = pmmap_admin_meta_size,
	.sync = pmmap_admin_sync,
	.load = pmmap_admin_load,
};

static u64 pmmap_fs_meta_size(struct pmmap_meta_context *ctx)
{
	struct dentry *admin_den, *den;
	u64 sum = 0;

	admin_den = ctx->ps->meta.meta_dirs[ctx->meta_ver & 1];
	spin_lock(&admin_den->d_lock);
	list_for_each_entry(den, &admin_den->d_subdirs, d_child) {
		if (!simple_positive(den))
			continue;
	
		if (!PMMAP_I(d_inode(den))->admin)
			continue;
		sum += i_size_read(d_inode(den));
	}
	spin_unlock(&admin_den->d_lock);

	return sum;
}

/*
 * This is not standard file operation
 */
static int __file_access_page(struct pmmap_meta_cursor *mcur, bool read)
{
	struct inode *inode = mcur->priv;
	struct pmmap_bmap_cur bcur = {
		.inode = inode,
		.file = {
			.off = mcur->off,
			.len = PAGE_SIZE,
		},
	};
	void *kaddr;
	u64 doff;
	int ret;

	inode_lock(inode);
	ret = pmmap_bmap_write(&bcur);
	if (ret) {
		PWARN_LIMIT("bmap write failed %d\n", ret);
		goto out;
	}

	doff = bcur.extent.d_off + (bcur.file.off - bcur.extent.f_off);
	kaddr = pmmap_dax_map(mcur->ps, doff, PAGE_SIZE);
	if (IS_ERR(kaddr)) {
		PWARN_LIMIT("dax map failed %ld\n", PTR_ERR(kaddr));
		ret = PTR_ERR(kaddr);
		goto out;
	}

	if (read)
		memcpy((void *)mcur->page, kaddr, PAGE_SIZE);
	else
		memcpy_flushcache(kaddr, (void *)mcur->page, PAGE_SIZE);

	if (mcur->last) {
		struct timespec64 now = current_time(inode);

		generic_update_time(inode, &now, S_MTIME | S_CTIME);
		pmmap_file_update_size(inode, mcur->off + PAGE_SIZE);
	}
out:
	inode_unlock(inode);
	return ret;
}

static void __fs_sync_hash_work(struct pmmap_super *ps,
		int id, void *priv)
{
	struct pmmap_meta_context *ctx = &ps->meta.fs_ctx;
	struct pmmap_meta_cursor mcur;
	struct dentry *dir_den, *den;
	char buf[8];

	/*
	 * Find the next metadata directory based on meta_ver
	 */
	dir_den = ps->meta.meta_dirs[(ctx->meta_ver + 1) & 1];

	sprintf(buf, "%x", id);
	den = __lookup_dentry(d_inode(dir_den), buf, false);
	if (!den) {
		PERR("cannot find dentry of metadata file %s\n", buf);
		return;
	}

	/*
	 * sync metadata into it
	 */
	__pmmap_meta_cursor_reset(&mcur, ps);
	mcur.page = ps->meta.fs_sync_page[id];
	mcur.access_page = __file_access_page;
	mcur.off = 0;
	mcur.end = PUD_SIZE;
	mcur.priv = d_inode(den);
	dput(den);

	pmmap_iterate_sync_inodes(ps, __pmmap_sync_meta, id, &mcur);
	mcur.len = 0;
	mcur.last = true;
	pmmap_meta_write(&mcur);
	if (meta_exhaust(&mcur))
		pmmap_meta_exhaust(ps);
}

static int pmmap_fs_meta_commit(struct pmmap_meta_context *ctx)
{
	struct pmmap_super *ps = ctx->ps;
	struct dentry *dir_den, *den;
	char buf[32];

	dir_den = ps->meta.meta_dirs[(ctx->meta_ver + 1) & 1];
	/*
	 * commit the sync by rename the directory to new version
	 */
	sprintf(buf, "%llx", ctx->meta_ver + 1);
	den = __lookup_dentry(d_inode(ps->meta.admin_dir), buf, true);
	if (!den) {
		PERR("create new dentry failed\n");
		return -ENOMEM;
	}
	d_move(dir_den, den);
	dput(den);

	ctx->meta_ver++;

	return 0;
}

static int pmmap_fs_sync(struct pmmap_meta_context *ctx)
{
	struct pmmap_super *ps = ctx->ps;
	struct pmmap_hash_work hw;
	u64 start, intv;

	start = ktime_to_ns(ktime_get());

	while(!wait_event_timeout(ctx->wait_drain,
				__ref_drain(ctx), 100)){}

	pmmap_queue_hash_work(ps, &hw, __fs_sync_hash_work, NULL);
	pmmap_fs_meta_commit(ctx);

	WRITE_ONCE(ctx->factor.val, 0);
	wake_up_all(&ctx->wait_avail);

	intv = (ktime_to_ns(ktime_get()) - start) / 1000;
	if (intv > ps->meta.sync_max_us)
		ps->meta.sync_max_us = intv;
	ps->meta.sync_cnt++;
	ps->meta.sync_total_us += intv;

	return 0;
}

static int pmmap_prepare_fs_meta(struct pmmap_meta_context *ctx)
{
	struct pmmap_super *ps = ctx->ps;
	struct inode *admin_dir;
	struct dentry *admin_den, *den;
	u64 ver;

	/*
	 * Decide the meta version number
	 */
	admin_dir = pmmap_lookup_inode(ps, PMMAP_ADMIN_DIR_INO);
	if (!admin_dir) {
		PERR("cannot find inode of admin directory\n");
		return -ENOENT;
	}

	admin_den = d_find_alias(admin_dir);
	ps->meta.admin_dir = admin_den;

	spin_lock(&admin_den->d_lock);
	list_for_each_entry(den, &admin_den->d_subdirs, d_child) {
		if (!simple_positive(den))
			continue;
	
		if (!PMMAP_I(d_inode(den))->admin)
			continue;

		ver = simple_strtoul(den->d_name.name, NULL, 16);
		ps->meta.meta_dirs[ver & 1] = den;
		if (ver > ctx->meta_ver)
			ctx->meta_ver = ver;
	}
	spin_unlock(&admin_den->d_lock);
	dput(admin_den);

	return 0;
}

static int pmmap_fs_load(struct pmmap_meta_context *ctx)
{
	struct pmmap_super *ps = ctx->ps;
	struct pmmap_meta_cursor mcur;
	struct dentry *den, *dir_den;
	int i, ret;
	char buf[8];

	ret = pmmap_prepare_fs_meta(ctx);
	if (ret)
		return ret;

	dir_den = ps->meta.meta_dirs[ctx->meta_ver & 1];

	for (i = 0; i < PMMAP_INODE_HASH_NR; i++) {
		sprintf(buf, "%x", i);
		den = __lookup_dentry(d_inode(dir_den), buf, false);
		if (!den) {
			PERR("cannot find dentry of meta file %s\n", buf);
			return -ENOENT;
		}

		__pmmap_meta_cursor_reset(&mcur, ps);
		mcur.page = ps->meta.fs_sync_page[0];
		mcur.access_page = __file_access_page;
		mcur.off = 0;
		mcur.end = i_size_read(d_inode(den));
		mcur.priv = d_inode(den);
		dput(den);

		ret = pmmap_load_meta(&mcur);
		if (ret)
			break;
	}

	if (ret)
		return ret;

	ret = 0;
	pmmap_iterate_empty_inodes(ps,
			pmmap_discard_empty_inode, &ret);
	if (ret)
		PERR("discard %d inodes\n", ret);

	return 0;
}

static struct pmmap_meta_ops fs_meta_ops = {
	.meta_size = pmmap_fs_meta_size,
	.sync = pmmap_fs_sync,
	.load = pmmap_fs_load,
};

static void init_admin_meta_context(struct pmmap_super *ps)
{
	struct pmmap_meta_context *mc = &ps->meta.admin_ctx;
	struct pmmap_nv_sb *in_core = ps->nv_sb.in_core;
	union pmmap_sb_factor factor;
	int index;

	mc->ps = ps;
	mc->log_kaddr = ps->meta_kaddr + ps->admin.log_off;
	mc->log_len = ps->admin.log_len;

	factor.val = le64_to_cpu(in_core->factor);
	index = factor.info.sync_seq % 2;
	mc->meta_ver = le64_to_cpu(in_core->meta[index].ver);
	/*
	 * log_factor.info.off is set when .replay
	 */
	mc->ops = &admin_meta_ops;
	init_waitqueue_head(&mc->wait_drain);
	init_waitqueue_head(&mc->wait_avail);
}

static void init_fs_meta_context(struct pmmap_super *ps)
{
	struct pmmap_meta_context *mc = &ps->meta.fs_ctx;

	mc->ps = ps;
	mc->log_kaddr = ps->meta_kaddr + ps->fs_log_off;
	mc->log_len = ps->fs_log_off;
	/*
	 * fs's meta ver is decided by the name of directory
	 * of metadata files. This is done when load
	 */
	mc->ops = &fs_meta_ops;
	init_waitqueue_head(&mc->wait_drain);
	init_waitqueue_head(&mc->wait_avail);
}

static const char *memuint[] = {
	"B",
	"K",
	"M",
	"G",
	NULL
};

static void __atomem(char *buf, u64 val)
{
	int u = 0;

	while(val > 1024) {
		u++;
		val = val >> 10;
	}
	if (u >= 4)
		sprintf(buf, "N/A");
	else
		sprintf(buf, "%llu%s", val, memuint[u]);
}

int pmmap_meta_stat(struct pmmap_super *ps, char *page)
{
	struct pmmap_meta *pm = &ps->meta;
	struct pmmap_meta_context *ctx;
	char buf[16];
	long tmp;
	int pcnt, ret;

	/*
	 * admin metadata statistics
	 */
	ret = sprintf(page, "admin:");
	ctx = &ps->meta.admin_ctx;
	tmp = ctx->ops->meta_size(ctx);
	pcnt = tmp ? max((int)((tmp * 100) / ps->admin.meta_len), 1) : 0;
	__atomem(buf, tmp);
	ret += sprintf(page + ret, " meta %s (%%%d)", buf, pcnt);

	tmp = ctx->factor.info.off;
	pcnt = tmp ? max((int)((tmp * 100) / ps->admin.log_len), 1) : 0;
	__atomem(buf, tmp);
	ret += sprintf(page + ret, " log %s (%%%d)\n", buf, pcnt);

	/*
	 * fs metadata statistics
	 */
	ret += sprintf(page + ret, "fs:");
	ctx = &ps->meta.fs_ctx;
	tmp = ctx->ops->meta_size(ctx);
	__atomem(buf, tmp);
	ret += sprintf(page + ret, " meta %s", buf);

	tmp = ctx->factor.info.off;
	pcnt = tmp ? max((int)((tmp * 100) / ps->fs_log_len), 1) : 0;
	__atomem(buf, tmp);
	ret += sprintf(page + ret, " log %s (%%%d)\n", buf, pcnt);

	ret += sprintf(page + ret, "sync: total %llu max %llu (us) avg %llu (us)\n",
			pm->sync_cnt, pm->sync_max_us,
			pm->sync_cnt ? pm->sync_total_us / pm->sync_cnt : 0);

	return ret;
}

int pmmap_meta_load(struct pmmap_super *ps)
{
	struct pmmap_meta_context *admin_ctx = &ps->meta.admin_ctx;
	struct pmmap_meta_context *fs_ctx = &ps->meta.fs_ctx;
	int err;

	set_bit(PMMAP_SUPER_FLAGS_REPLAY, &ps->flags);
	set_bit(PMMAP_SUPER_FLAGS_ADMIN, &ps->flags);
	/*
	 * load and replay the admin metadata to construct the
	 * metadata files of filesystem
	 */
	err = admin_ctx->ops->load(admin_ctx);
	if (err)
		goto out;

	err = pmmap_log_replay(admin_ctx);
	if (err)
		goto out;

	clear_bit(PMMAP_SUPER_FLAGS_ADMIN, &ps->flags);

	err = fs_ctx->ops->load(fs_ctx);
	if (err)
		goto out;

	err = pmmap_log_replay(fs_ctx);
out:
	clear_bit(PMMAP_SUPER_FLAGS_ADMIN, &ps->flags);
	clear_bit(PMMAP_SUPER_FLAGS_REPLAY, &ps->flags);
	/*
	 * If fail in load tree or replay log, just quit and let the
	 * generic_shutdown_super will get rid of the inodes and dentries.
	 */
	return err;
}

/*
 * When this function is invoked, the alloc compoments should have been
 * initialized well.
 */
static int pmmap_meta_space_reserve(struct pmmap_super *ps)
{
	struct pmmap_alloc_data ad;
	u64 resv_len;
	u64 dblk;
	int ret;

	/*
	 * This meta_len includes:
	 * (1) primary and secondary super block
	 * (2) admin metadata and log
	 * (3) fs log
	 */
	resv_len = ps->meta_len;
	resv_len = round_up(resv_len, PMD_SIZE);

	ad.level = &ps->bgs[0].pmd;
	ad.len = 1 << PMMAP_PMD_ORDER;

	for (dblk = 0; dblk < resv_len; dblk += PMD_SIZE) {
		ad.dblk = dblk >> PAGE_SHIFT;
		ret = pmmap_reserve_level(&ad);
		if (ret) {
			PWARN_LIMIT("reserve dblk %llx failed due to %d\n",
					dblk, ret);
			break;
		}
	}

	return ret;
}

int pmmap_meta_init(struct pmmap_super *ps)
{
	struct pmmap_meta *pm = &ps->meta;
	int i;

	if (!ps->durable)
		return 0;

	pm->sync_max_us = 0;
	pm->sync_total_us = 0;
	pm->sync_cnt = 0;

	for (i = 0; i < PMMAP_INODE_HASH_NR; i++) {
		ps->meta.fs_sync_page[i] = kmalloc_node(PAGE_SIZE, GFP_KERNEL, ps->node_id);
		if (!ps->meta.fs_sync_page[i])
			return -ENOMEM;
	}

	ps->meta.admin_sync_page = kmalloc_node(PAGE_SIZE, GFP_KERNEL, ps->node_id);
	if (!ps->meta.admin_sync_page)
		return -ENOMEM;

	init_admin_meta_context(ps);
	init_fs_meta_context(ps);

	return pmmap_meta_space_reserve(ps);
}

void pmmap_meta_exit(struct pmmap_super *ps)
{
	int i;

	for (i = 0; i < PMMAP_INODE_HASH_NR; i++) {
		if (ps->meta.fs_sync_page[i])
			kfree(ps->meta.fs_sync_page[i]);
	}

	if (ps->meta.admin_sync_page)
		kfree(ps->meta.admin_sync_page);
}

static bool __verify_super(struct pmmap_super *ps)
{
	struct pmmap_nv_sb *in_core = ps->nv_sb.in_core;
	union pmmap_sb_factor factor;
	u32 crc, chk_crc;

	if (in_core->magic != le32_to_cpu(PMMAP_SB_MAGIC))
		return false;
	
	factor.val = le64_to_cpu(in_core->factor);
	chk_crc = factor.info.crc;
	factor.info.crc = 0;
	in_core->factor = cpu_to_le64(factor.val);

	crc = crc32(PMMAP_CRC_SEED, in_core, sizeof(*in_core));
	if (crc != chk_crc)
		return false;

	return true;
}

bool pmmap_load_super(struct pmmap_super *ps)
{
	memcpy(ps->nv_sb.in_core,
	       ps->nv_sb.primary,
	       sizeof(struct pmmap_nv_sb));

	if (__verify_super(ps))
		return true;

	memcpy(ps->nv_sb.in_core,
	       ps->nv_sb.secondary,
	       sizeof(struct pmmap_nv_sb));

	if (!__verify_super(ps))
		return false;

	/*
	 * Secondary super block is OK, fix the primary one
	 */
	memcpy_flushcache(ps->nv_sb.primary,
			ps->nv_sb.secondary,
			sizeof(struct pmmap_nv_sb));

	return true;
}

/*
 * Metadata len is fixed to PUD_SIZE (1G) for 3 reasons
 * (1) if metadata is too big, full sync can cost too much time
 * (2) start address of data chunks should be aligned to PUD_SIZE
 * (3) secondary super block can have fixed position
 * Layout: || padding
 *      admin   admin   admin
 *  sb0  log    meta0   meta1    sb1     fs log
 * |--||-----||-------||-------||--||||------------||
 * \________________ _________________/
 *                  v
 *               meta_len
 */
void pmmap_meta_layout_init(struct pmmap_super *ps)
{
	u64 tmp;

	ps->meta_len = PMMAP_ADMIN_META_LEN;
	ps->super_off[0] = 0;
	ps->super_off[1] = ps->meta_len - PAGE_SIZE;

	ps->admin.log_off = PAGE_SIZE + PMMAP_META_PADDING_LEN;
	ps->admin.log_len = PMMAP_ADMIN_LOG_LEN;

	tmp = ps->meta_len - (2 * PAGE_SIZE) - ps->admin.log_len;
	/*
	 * meta_len should be 4K aligned
	 */
	tmp -= 6 * PMMAP_META_PADDING_LEN;
	ps->admin.meta_len = tmp >> 1;

	tmp = ps->admin.log_off + ps->admin.log_len;
	ps->admin.meta_off[0] = tmp + PMMAP_META_PADDING_LEN;
	ps->admin.meta_off[1] = ps->admin.meta_off[0] + ps->admin.meta_len + PMMAP_META_PADDING_LEN;

	ps->fs_log_off = ps->meta_len;

	ps->nv_sb.in_core = &ps->inlined_sb;
	ps->nv_sb.primary = ps->meta_kaddr + ps->super_off[0];
	ps->nv_sb.secondary = ps->meta_kaddr + ps->super_off[1];
}


