// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "auditmod2xattr: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/timekeeping.h>
#include <linux/time64.h>
#include <linux/xattr.h>
#include <linux/uidgid.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/rtc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rui Gomes");
MODULE_DESCRIPTION("Kernel module auditing file modifications into xattrs");
MODULE_VERSION("3.3");



/* ---- Tunables ---- */
#define FLUSH_INTERVAL_MS   1000
#define MAX_LINE_LEN        256
#define XATTR_NAME          "trusted.modification"
#define ROLLING_CAP_BYTES   4096
#define DEDUPE_WINDOW_MS    200
#define MOD_BITS            10      /* 1024 buckets for mod_table */
#define MAX_OLD_XATTR_BYTES (1U << 20) /* 1 MiB guard for preexisting xattr */

/* ---- Fallback magics (if missing from your headers) ---- */
#ifndef RPC_PIPEFS_MAGIC
#define RPC_PIPEFS_MAGIC     0x67596969
#endif
#ifndef FUSE_CTL_SUPER_MAGIC
#define FUSE_CTL_SUPER_MAGIC 0x65735543
#endif
#ifndef SMACK_MAGIC
#define SMACK_MAGIC          0x43415d53
#endif
#ifndef CONFIGFS_MAGIC
#define CONFIGFS_MAGIC       0x62656570
#endif

/* ---- Per-event node in mod_table and (transferred into) batch table ---- */
struct mod_entry {
	struct hlist_node hnode;
	struct dentry *dentry;
	pid_t pid;
	kuid_t uid;
	unsigned long last_jiffies;
	char line[MAX_LINE_LEN];
};

/* Global pending hash and lock */
static DECLARE_HASHTABLE(mod_table, MOD_BITS);
static DEFINE_SPINLOCK(mod_table_lock);

/* Slab cache for mod_entry */
static struct kmem_cache *mod_entry_cache;

/* Workqueue */
static struct workqueue_struct *flush_wq;
static struct delayed_work flush_dwork;

/* ---- FS filter ---- */
static bool is_special_fs(const struct super_block *sb)
{
	switch (sb->s_magic) {
	case PROC_SUPER_MAGIC:
	case SYSFS_MAGIC:
	case DEBUGFS_MAGIC:
	case TMPFS_MAGIC:
	case CGROUP_SUPER_MAGIC:
	case CGROUP2_SUPER_MAGIC:
	case DEVPTS_SUPER_MAGIC:
	case PIPEFS_MAGIC:
	case RPC_PIPEFS_MAGIC:
	case BPF_FS_MAGIC:
	case NSFS_MAGIC:
	case TRACEFS_MAGIC:
	case EFIVARFS_MAGIC:
	case FUSE_CTL_SUPER_MAGIC:
	case SELINUX_MAGIC:
	case SECURITYFS_MAGIC:
	case SMACK_MAGIC:
	case CONFIGFS_MAGIC:
	case RAMFS_MAGIC:
		return true;
	default:
		return false;
	}
}

/* ---- Rolling cap: keep last ROLLING_CAP_BYTES, drop oldest ---- */
static void rolling_cap(char *buf, size_t *len_io)
{
	size_t len = *len_io;

	if (len <= ROLLING_CAP_BYTES)
		return;

	size_t start = len - ROLLING_CAP_BYTES;
	while (start < len && buf[start] != '\n')
		start++;
	if (start < len)
		start++;

	memmove(buf, buf + start, len - start);
	*len_io = len - start;
}

/* ---- Append lines to xattr (with newline and cap) ---- */
static void append_line_to_xattr(struct dentry *dentry, const char *append)
{
	    struct mnt_idmap *idmap = &nop_mnt_idmap;
	    ssize_t oldlen, ret;
	    char *oldbuf = NULL, *newbuf = NULL;
	    size_t sep = 0, newlen;
	    size_t applen = strlen(append);

	oldlen = vfs_getxattr(idmap, dentry, XATTR_NAME, NULL, 0);
	if (oldlen == -ENODATA)
		oldlen = 0;
	else if (oldlen < 0)
		oldlen = 0;

	if ((size_t)oldlen > MAX_OLD_XATTR_BYTES)
		oldlen = MAX_OLD_XATTR_BYTES;

	if (oldlen > 0) {
		oldbuf = kvzalloc(oldlen, GFP_KERNEL);
		if (!oldbuf)
			return;
		ret = vfs_getxattr(idmap, dentry, XATTR_NAME, oldbuf, oldlen);
		if (ret < 0) {
			kvfree(oldbuf);
			oldbuf = NULL;
			oldlen = 0;
		} else if (ret < oldlen) {
			oldlen = ret;
		}
	}

	if (oldlen > 0 && oldbuf[oldlen - 1] != '\n')
		sep = 1;

	newlen = (size_t)oldlen + sep + applen;
	newbuf = kvzalloc(max_t(size_t, newlen, ROLLING_CAP_BYTES), GFP_KERNEL);
	if (!newbuf) {
		kvfree(oldbuf);
		return;
	}

	if (oldlen > 0)
		memcpy(newbuf, oldbuf, oldlen);
	if (sep)
		newbuf[oldlen] = '\n';
	memcpy(newbuf + oldlen + sep, append, applen);

	{
		size_t cur = newlen;
		rolling_cap(newbuf, &cur);
		newlen = cur;
	}

	ret = vfs_setxattr(idmap, dentry, XATTR_NAME, newbuf, newlen, 0);
	if (ret && ret != -EOPNOTSUPP)
		pr_debug("vfs_setxattr failed: %zd\n", ret);

	kvfree(oldbuf);
	kvfree(newbuf);
}

/* ---- Enqueue from kprobe ---- */
static void enqueue_mod_entry(struct dentry *dentry)
{
	struct inode *ino = d_inode(dentry);
	struct mod_entry *me;
	unsigned long flags;
	unsigned long now = jiffies;
	struct timespec64 ts;
	struct rtc_time tm;
	unsigned long key = (unsigned long)dentry;

	if (!ino || !S_ISREG(ino->i_mode))
		return;
	if (is_special_fs(dentry->d_sb))
		return;

	spin_lock_irqsave(&mod_table_lock, flags);
	{
		struct mod_entry *it;
		hash_for_each_possible(mod_table, it, hnode, key) {
			if (it->dentry == dentry && it->pid == task_pid_nr(current)) {
				if (time_before(now, it->last_jiffies + msecs_to_jiffies(DEDUPE_WINDOW_MS))) {
					spin_unlock_irqrestore(&mod_table_lock, flags);
					return;
				}
				break;
			}
		}
	}
	spin_unlock_irqrestore(&mod_table_lock, flags);

	me = kmem_cache_alloc(mod_entry_cache, GFP_ATOMIC);
	if (!me)
		return;

	ktime_get_real_ts64(&ts);
	rtc_time64_to_tm(ts.tv_sec, &tm);

	me->dentry = dget(dentry);
	me->pid = task_pid_nr(current);
	me->uid = current_uid();
	me->last_jiffies = now;

	snprintf(me->line, sizeof(me->line),
	         "%04d-%02d-%02dT%02d:%02d:%02d.%09lu pid=%d uid=%u comm=%s\n",
	         tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	         tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec,
	         me->pid, from_kuid(&init_user_ns, me->uid), current->comm);

	spin_lock_irqsave(&mod_table_lock, flags);
	hash_add(mod_table, &me->hnode, key);
	spin_unlock_irqrestore(&mod_table_lock, flags);
}

/* ---- Worker: drain mod_table and batch ---- */
static void flush_worker_fn(struct work_struct *work)
{
	unsigned long flags;
	struct mod_entry *me, *batch_me;
	struct hlist_node *tmp;
	int bkt;

	const unsigned int nbuckets = 256;
	struct hlist_head *batch = kcalloc(nbuckets, sizeof(*batch), GFP_KERNEL);
	if (!batch)
		goto out_rearm;

	for (bkt = 0; bkt < nbuckets; bkt++)
		INIT_HLIST_HEAD(&batch[bkt]);

	spin_lock_irqsave(&mod_table_lock, flags);
	hash_for_each_safe(mod_table, bkt, tmp, me, hnode) {
		unsigned long k = (unsigned long)me->dentry;
		unsigned int idx = k & (nbuckets - 1);
		bool merged = false;

		hash_del(&me->hnode);

		hlist_for_each_entry(batch_me, &batch[idx], hnode) {
			if (batch_me->dentry == me->dentry) {
				strlcat(batch_me->line, me->line, MAX_LINE_LEN);
				dput(me->dentry);
				kmem_cache_free(mod_entry_cache, me);
				merged = true;
				break;
			}
		}

		if (!merged) {
			INIT_HLIST_NODE(&me->hnode);
			hlist_add_head(&me->hnode, &batch[idx]);
		}
	}
	spin_unlock_irqrestore(&mod_table_lock, flags);

	for (bkt = 0; bkt < nbuckets; bkt++) {
		struct hlist_node *n;
		hlist_for_each_entry_safe(batch_me, n, &batch[bkt], hnode) {
			hlist_del(&batch_me->hnode);
			if (batch_me->dentry && d_inode(batch_me->dentry) &&
			    S_ISREG(d_inode(batch_me->dentry)->i_mode) &&
			    !is_special_fs(batch_me->dentry->d_sb)) {
				append_line_to_xattr(batch_me->dentry, batch_me->line);
			}
			dput(batch_me->dentry);
			kmem_cache_free(mod_entry_cache, batch_me);
		}
	}

	kfree(batch);

out_rearm:
	queue_delayed_work(flush_wq, &flush_dwork, msecs_to_jiffies(FLUSH_INTERVAL_MS));
}

/* ---- Kprobe pre-handler ---- */
static int pre_notify_change(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry;

#if defined(CONFIG_X86_64)
	dentry = (struct dentry *)regs->si; /* notify_change(mnt_idmap*, dentry*, ...) */
#else
# error "Only x86_64 currently supported."
#endif

	if (dentry)
		enqueue_mod_entry(dentry);

	return 0;
}

static struct kprobe kp = {
	.symbol_name = "notify_change",
	.pre_handler = pre_notify_change,
};

/* ---- Module init/exit ---- */
static int __init auditmod2xattr_init(void)
{
	int ret;

	hash_init(mod_table);

	mod_entry_cache = kmem_cache_create("auditmod2xattr_entry",
	                                    sizeof(struct mod_entry),
	                                    0, 0, NULL);
	if (!mod_entry_cache)
		return -ENOMEM;

	flush_wq = alloc_workqueue("auditmod2xattr_wq", WQ_UNBOUND | WQ_FREEZABLE, 1);
	if (!flush_wq) {
		kmem_cache_destroy(mod_entry_cache);
		return -ENOMEM;
	}

	INIT_DELAYED_WORK(&flush_dwork, flush_worker_fn);
	queue_delayed_work(flush_wq, &flush_dwork, msecs_to_jiffies(FLUSH_INTERVAL_MS));

	ret = register_kprobe(&kp);
	if (ret) {
		pr_err("register_kprobe(%s) failed: %d\n", kp.symbol_name, ret);
		cancel_delayed_work_sync(&flush_dwork);
		destroy_workqueue(flush_wq);
		kmem_cache_destroy(mod_entry_cache);
		return ret;
	}

	pr_info("init: hooked notify_change → %s (flush=%ums, dedupe=%ums)\n",
	        XATTR_NAME, FLUSH_INTERVAL_MS, DEDUPE_WINDOW_MS);
	return 0;
}

static void __exit auditmod2xattr_exit(void)
{
	unsigned long flags;
	struct mod_entry *me;
	struct hlist_node *tmp;
	int bkt;

	cancel_delayed_work_sync(&flush_dwork);
	if (flush_wq) {
		flush_workqueue(flush_wq);
		destroy_workqueue(flush_wq);
	}

	unregister_kprobe(&kp);

	spin_lock_irqsave(&mod_table_lock, flags);
	hash_for_each_safe(mod_table, bkt, tmp, me, hnode) {
		hash_del(&me->hnode);
		dput(me->dentry);
		kmem_cache_free(mod_entry_cache, me);
	}
	spin_unlock_irqrestore(&mod_table_lock, flags);

	if (mod_entry_cache)
		kmem_cache_destroy(mod_entry_cache);

	pr_info("exit\n");
}

module_init(auditmod2xattr_init);
module_exit(auditmod2xattr_exit);


