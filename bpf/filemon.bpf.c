// SPDX-License-Identifier: GPL-2.0-only
// Logical file bytes for Linux 7.x.
//
// Byte counts come from the syscall entry points (__x64_sys_read and so on).
// Those are called through the syscall table, so a compiler cannot inline
// them. The VFS functions underneath (vfs_read, vfs_write, do_sendfile,
// do_splice) are static and single-caller, and LTO/AutoFDO kernels inline
// them into their callers, which silently removes the fentry/fexit site.
// Counting at the outermost layer also means nothing is counted twice.
//
//   read/pread64/readv/preadv/preadv2 and the write set -> __x64_sys_*
//   sendfile, splice, copy_file_range                   -> __x64_sys_*
//   io_uring read/write -> kiocb_done (inline) or io_complete_rw[_iopoll]
//   path                -> walked from the dentry the first time a file is counted
//
// The `hits` map counts how often each hook fired, so a hook that never
// fires on a given kernel shows up in `--dump`.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Linux 7.2 BTF. Anonymous enums, so CO-RE cannot look them up by name. */
#define FRV_IOCB_WRITE (1 << 18)
#define FRV_REQ_F_ASYNC_DATA (1ULL << 22)
#define FRV_REQ_F_IOPOLL (1ULL << 41)

#define FRV_S_IFMT 00170000
#define FRV_S_IFREG 0100000
#define FRV_BTRFS_SUPER_MAGIC 0x9123683EULL

struct file_key {
	__u64 dev;
	__u64 ino;
	__u32 tgid;
	__u32 pad;
};

struct file_stat {
	__u64 rbytes;
	__u64 wbytes;
	__u64 reads;
	__u64 writes;
	char comm[16];
};

struct path_key {
	__u64 dev;
	__u64 ino;
};

struct path_val {
	char path[512];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct file_key);
	__type(value, struct file_stat);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct path_key);
	__type(value, struct path_val);
} paths SEC(".maps");

/* The path is built backwards, right-aligned at buf[1023]. A 512 byte window
 * from the start of the path is then copied to `out`, which goes into `paths`.
 * buf is 1536 bytes so the masked indexes below stay in bounds for the verifier. */
#define WALK_BUF 1024
#define WALK_DEPTH 24
#define WALK_MIN 520

struct walk_scratch {
	char buf[WALK_BUF + 512];
	char out[512];
	char comp[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct walk_scratch);
} walk SEC(".maps");

enum hook {
	H_READ,
	H_PREAD,
	H_READV,
	H_PREADV,
	H_PREADV2,
	H_WRITE,
	H_PWRITE,
	H_WRITEV,
	H_PWRITEV,
	H_PWRITEV2,
	H_SENDFILE,
	H_SPLICE,
	H_COPY,
	H_URING_DONE,
	H_URING_RW,
	H_URING_POLL,
	H_PATH_OK,
	H_PATH_TRUNC, /* walk hit the depth or length limit */
	H_PATH_EMPTY, /* walk produced nothing */
	H_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, H_MAX);
	__type(key, __u32);
	__type(value, __u64);
} hits SEC(".maps");

static __always_inline void hit(__u32 hook)
{
	__u64 *slot = bpf_map_lookup_elem(&hits, &hook);

	if (slot)
		*slot += 1;
}

static __always_inline void copy_comm(char dst[16], const char src[16])
{
	__builtin_memcpy(dst, src, 16);
}

/* The kernel's internal dev_t is major<<20 | minor. stat() reports the
 * new_encode_dev layout, and userspace joins on that, so convert here. */
static __always_inline __u64 encode_dev(__u32 dev)
{
	__u32 major = dev >> 20;
	__u32 minor = dev & 0xfffff;

	return (minor & 0xff) | (major << 8) | ((__u64)(minor & ~0xffu) << 12);
}

/* dev must match userspace stat().st_dev. btrfs stat uses the subvolume
 * anon device, not the block device in i_sb->s_dev. Walking back from
 * inode to btrfs_inode is a container_of the verifier rejects, so the
 * address is computed as a scalar and the two fields are probe-read.
 * Offsets are CO-RE relocated against the kernel this binary is built for. */
static __always_inline __u64 stat_dev(struct inode *inode)
{
	__u64 magic = BPF_CORE_READ(inode, i_sb, s_magic);
	__u32 dev32 = BPF_CORE_READ(inode, i_sb, s_dev);
	struct btrfs_root *root = NULL;
	__u32 anon = 0;
	__u64 addr;

	if (magic != FRV_BTRFS_SUPER_MAGIC)
		return encode_dev(dev32);
	addr = (__u64)inode - bpf_core_field_offset(struct btrfs_inode, vfs_inode);
	if (bpf_probe_read_kernel(&root, sizeof(root), (const void *)addr))
		return encode_dev(dev32);
	if (!root)
		return encode_dev(dev32);
	if (bpf_core_field_size(struct btrfs_root, anon_dev) != sizeof(anon))
		return encode_dev(dev32);
	addr = (__u64)root + bpf_core_field_offset(struct btrfs_root, anon_dev);
	if (bpf_probe_read_kernel(&anon, sizeof(anon), (const void *)addr))
		return encode_dev(dev32);
	return encode_dev(anon ? anon : dev32);
}

static __always_inline int identify(struct file *file, __u64 *dev, __u64 *ino)
{
	struct inode *inode;
	__u16 mode;

	if (!file)
		return -1;
	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return -1;
	mode = BPF_CORE_READ(inode, i_mode);
	if ((mode & FRV_S_IFMT) != FRV_S_IFREG)
		return -1;
	*dev = stat_dev(inode);
	*ino = BPF_CORE_READ(inode, i_ino);
	return 0;
}

static __always_inline void note_path(struct file *file, __u64 dev, __u64 ino)
{
	struct path_key pk = {};
	struct walk_scratch *w;
	struct dentry *dentry, *mnt_root;
	struct vfsmount *vfs;
	__u64 mnt;
	__u32 zero = 0;
	__u32 pos = WALK_BUF - 1;
	int truncated = 0;
	int i;

	pk.dev = dev;
	pk.ino = ino;
	if (bpf_map_lookup_elem(&paths, &pk))
		return;
	w = bpf_map_lookup_elem(&walk, &zero);
	if (!w)
		return;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	vfs = BPF_CORE_READ(file, f_path.mnt);
	if (!dentry || !vfs)
		return;
	mnt = (__u64)vfs - bpf_core_field_offset(struct mount, mnt);
	mnt_root = BPF_CORE_READ(vfs, mnt_root);
	w->buf[(WALK_BUF - 1) & (WALK_BUF - 1)] = 0;

	for (i = 0; i < WALK_DEPTH; i++) {
		struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
		const unsigned char *name;
		long len;

		if (dentry == mnt_root) {
			struct mount *cur = (struct mount *)mnt;
			struct mount *up = BPF_CORE_READ(cur, mnt_parent);

			if ((__u64)up == mnt || !up)
				break;
			dentry = BPF_CORE_READ(cur, mnt_mountpoint);
			mnt = (__u64)up;
			cur = up;
			mnt_root = BPF_CORE_READ(cur, mnt.mnt_root);
			continue;
		}
		if (dentry == parent || !parent)
			break;
		name = BPF_CORE_READ(dentry, d_name.name);
		len = bpf_probe_read_kernel_str(w->comp, sizeof(w->comp), name);
		if (len <= 1)
			break;
		len -= 1; /* drop the NUL */
		if (pos < WALK_MIN + (__u32)len) {
			truncated = 1;
			break;
		}
		pos -= len;
		bpf_probe_read_kernel(&w->buf[pos & (WALK_BUF - 1)], len & 255, w->comp);
		pos -= 1;
		w->buf[pos & (WALK_BUF - 1)] = '/';
		dentry = parent;
	}
	if (i == WALK_DEPTH)
		truncated = 1;
	if (pos == WALK_BUF - 1) {
		/* The file is the root of its filesystem, or nothing was readable. */
		pos -= 1;
		w->buf[pos & (WALK_BUF - 1)] = '/';
		if (!truncated) {
			hit(H_PATH_EMPTY);
			return;
		}
	}
	if (truncated)
		hit(H_PATH_TRUNC);
	if (bpf_probe_read_kernel(w->out, sizeof(w->out), &w->buf[pos & (WALK_BUF - 1)]))
		return;
	hit(H_PATH_OK);
	bpf_map_update_elem(&paths, &pk, w->out, BPF_ANY);
}

static __always_inline void add_id(__u64 dev, __u64 ino, __u32 tgid, const char comm[16],
				   int is_write, __u64 bytes)
{
	struct file_key key = {};
	struct file_stat *val;
	struct file_stat init = {};

	if (!bytes || !tgid)
		return;
	key.dev = dev;
	key.ino = ino;
	key.tgid = tgid;
	val = bpf_map_lookup_elem(&stats, &key);
	if (!val) {
		copy_comm(init.comm, comm);
		bpf_map_update_elem(&stats, &key, &init, BPF_NOEXIST);
		val = bpf_map_lookup_elem(&stats, &key);
		if (!val)
			return;
	}
	copy_comm(val->comm, comm);
	if (is_write) {
		__sync_fetch_and_add(&val->wbytes, bytes);
		__sync_fetch_and_add(&val->writes, 1);
	} else {
		__sync_fetch_and_add(&val->rbytes, bytes);
		__sync_fetch_and_add(&val->reads, 1);
	}
}

static __always_inline void account_file(struct file *file, __u32 tgid, const char comm[16],
					  int is_write, __u64 bytes)
{
	__u64 dev = 0, ino = 0;

	if (identify(file, &dev, &ino))
		return;
	note_path(file, dev, ino);
	add_id(dev, ino, tgid, comm, is_write, bytes);
}

static __always_inline void account_current(struct file *file, int is_write, __u64 bytes)
{
	char comm[16] = {};
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	bpf_get_current_comm(comm, sizeof(comm));
	account_file(file, tgid, comm, is_write, bytes);
}

static __always_inline struct file *file_from_fd(int fd)
{
	struct task_struct *task;
	struct files_struct *files;
	struct fdtable *fdt;
	struct file **fds;
	struct file *file = NULL;
	unsigned int max_fds, idx;

	if (fd < 0)
		return NULL;
	idx = (unsigned int)fd;
	/* Constant bound so the verifier accepts the pointer arithmetic. */
	if (idx >= 65536)
		return NULL;
	task = bpf_get_current_task_btf();
	files = BPF_CORE_READ(task, files);
	if (!files)
		return NULL;
	fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return NULL;
	max_fds = BPF_CORE_READ(fdt, max_fds);
	if (idx >= max_fds)
		return NULL;
	fds = BPF_CORE_READ(fdt, fd);
	if (!fds)
		return NULL;
	if (bpf_probe_read_kernel(&file, sizeof(file), fds + idx))
		return NULL;
	return file;
}

static __always_inline __u32 uring_tgid(struct io_kiocb *req, char comm[16])
{
	struct task_struct *task;
	char buf[16] = {};
	__u32 tgid = 0;

	task = BPF_CORE_READ(req, tctx, task);
	if (task) {
		tgid = BPF_CORE_READ(task, tgid);
		/* A parameter declared as char[16] is a pointer, so sizeof(*dst)
		 * would be 1. The local array keeps the 16-byte copy. */
		BPF_CORE_READ_STR_INTO(&buf, task, comm);
		copy_comm(comm, buf);
	}
	if (!tgid) {
		bpf_get_current_comm(comm, 16);
		tgid = bpf_get_current_pid_tgid() >> 32;
	}
	return tgid;
}

/* kiocb is the first field of io_rw, and that command occupies io_kiocb offset 0. */
static __always_inline struct io_kiocb *req_from_kiocb(struct kiocb *kiocb)
{
	return (struct io_kiocb *)kiocb;
}

static __always_inline __u64 rw_total(struct io_kiocb *req, long res)
{
	__u64 flags, done, total;
	struct io_async_rw *io;

	if (res <= 0)
		return 0;
	total = (__u64)res;
	flags = BPF_CORE_READ(req, flags);
	if (!(flags & FRV_REQ_F_ASYNC_DATA))
		return total;
	io = BPF_CORE_READ(req, async_data);
	if (!io)
		return total;
	done = BPF_CORE_READ(io, bytes_done);
	return total + done;
}

static __always_inline void account_uring(struct io_kiocb *req, struct kiocb *kiocb, long res)
{
	char comm[16] = {};
	struct file *file;
	__u32 tgid;
	int is_write;
	__u64 total;

	total = rw_total(req, res);
	if (!total)
		return;
	file = BPF_CORE_READ(kiocb, ki_filp);
	is_write = (BPF_CORE_READ(kiocb, ki_flags) & FRV_IOCB_WRITE) != 0;
	tgid = uring_tgid(req, comm);
	account_file(file, tgid, comm, is_write, total);
}

#if defined(__TARGET_ARCH_x86)
#define SYS "__x64_sys_"
#elif defined(__TARGET_ARCH_arm64)
#define SYS "__arm64_sys_"
#else
#error "syscall wrappers are only known for x86_64 and arm64"
#endif

/* The wrapper's argument is the user register set. fd is always argument 1. */
static __always_inline void account_fd(int fd, int is_write, long ret)
{
	if (ret > 0)
		account_current(file_from_fd(fd), is_write, (__u64)ret);
}

#define RW_HOOK(name, id, is_write)                                              \
	SEC("fexit/" SYS #name)                                                  \
	int BPF_PROG(on_sys_##name, struct pt_regs *regs, long ret)              \
	{                                                                        \
		if (ret > 0) {                                                   \
			hit(id);                                                 \
			account_fd((int)PT_REGS_PARM1_CORE_SYSCALL(regs), is_write, ret); \
		}                                                                \
		return 0;                                                        \
	}

RW_HOOK(read, H_READ, 0)
RW_HOOK(pread64, H_PREAD, 0)
RW_HOOK(readv, H_READV, 0)
RW_HOOK(preadv, H_PREADV, 0)
RW_HOOK(preadv2, H_PREADV2, 0)
RW_HOOK(write, H_WRITE, 1)
RW_HOOK(pwrite64, H_PWRITE, 1)
RW_HOOK(writev, H_WRITEV, 1)
RW_HOOK(pwritev, H_PWRITEV, 1)
RW_HOOK(pwritev2, H_PWRITEV2, 1)

/* Two files, one byte count: source is argument a, destination argument b. */
static __always_inline void account_pair(int in_fd, int out_fd, long ret)
{
	char comm[16] = {};
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	bpf_get_current_comm(comm, sizeof(comm));
	account_file(file_from_fd(in_fd), tgid, comm, 0, (__u64)ret);
	account_file(file_from_fd(out_fd), tgid, comm, 1, (__u64)ret);
}

SEC("fexit/" SYS "sendfile64")
int BPF_PROG(on_sys_sendfile64, struct pt_regs *regs, long ret)
{
	if (ret > 0) {
		hit(H_SENDFILE);
		/* sendfile(out_fd, in_fd, ...) */
		account_pair((int)PT_REGS_PARM2_CORE_SYSCALL(regs),
			     (int)PT_REGS_PARM1_CORE_SYSCALL(regs), ret);
	}
	return 0;
}

SEC("fexit/" SYS "splice")
int BPF_PROG(on_sys_splice, struct pt_regs *regs, long ret)
{
	if (ret > 0) {
		hit(H_SPLICE);
		/* splice(fd_in, off_in, fd_out, ...) */
		account_pair((int)PT_REGS_PARM1_CORE_SYSCALL(regs),
			     (int)PT_REGS_PARM3_CORE_SYSCALL(regs), ret);
	}
	return 0;
}

SEC("fexit/" SYS "copy_file_range")
int BPF_PROG(on_sys_copy_file_range, struct pt_regs *regs, long ret)
{
	if (ret > 0) {
		hit(H_COPY);
		/* copy_file_range(fd_in, off_in, fd_out, ...) */
		account_pair((int)PT_REGS_PARM1_CORE_SYSCALL(regs),
			     (int)PT_REGS_PARM3_CORE_SYSCALL(regs), ret);
	}
	return 0;
}

SEC("fentry/kiocb_done")
int BPF_PROG(on_kiocb_done, struct io_kiocb *req, ssize_t ret, struct io_br_sel *sel,
	     unsigned int issue_flags)
{
	__u64 flags;

	if (ret <= 0)
		return 0;
	flags = BPF_CORE_READ(req, flags);
	/* IOPOLL and queued completions are counted from their completion hook.
	 * io_rw (and its kiocb) overlays req->cmd, which is at the start of req. */
	if (flags & FRV_REQ_F_IOPOLL)
		return 0;
	hit(H_URING_DONE);
	account_uring(req, (struct kiocb *)req, ret);
	return 0;
}

SEC("fentry/io_complete_rw")
int BPF_PROG(on_io_complete_rw, struct kiocb *kiocb, long res)
{
	if (res > 0)
		hit(H_URING_RW);
	if (res > 0)
		account_uring(req_from_kiocb(kiocb), kiocb, res);
	return 0;
}

SEC("fentry/io_complete_rw_iopoll")
int BPF_PROG(on_io_complete_rw_iopoll, struct kiocb *kiocb, long res)
{
	if (res > 0)
		hit(H_URING_POLL);
	if (res > 0)
		account_uring(req_from_kiocb(kiocb), kiocb, res);
	return 0;
}
