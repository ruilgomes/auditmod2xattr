# auditmod2xattr — In-Kernel File Modification Logger

---

## Overview

`auditmod2xattr` is a lightweight, in-kernel auditing module that tracks file modification events, 
each modification (e.g., `chmod`, `chown`, `truncate`, `utimes`) appends an entry into a per-file extended attribute (`trusted.modification`).

This allows **low-overhead, persistent audit trails** directly on the inode, with zero userspace daemons or syscalls involved.

---

## ✨ Key Features

- 🧩 **Kernel-space file modification audit**
  - Hooks `notify_change()` directly — captures changes to file metadata (mode, owner, timestamps, size).
- 🪶 **Per-file audit history**
  - Each event is appended to the file’s extended attribute (`trusted.modification`).
- 🧵 **Batching and deduplication**
  - Events are buffered and coalesced (by PID/inode) for up to 200 ms before writing.
  - Flush worker commits aggregated logs every 1000 ms.
- 🚫 **Special filesystem filtering**
  - Automatically skips `/proc`, `/sys`, `tmpfs`, `bpf`, `securityfs`, and similar pseudo filesystems.
- ⚙️ **Rolling-cap audit buffer**
  - Keeps the last ~8 KB of log data per file to prevent runaway growth.
- 🔒 **Lock-safe and atomic**
  - Uses `spin_lock_irqsave` for synchronization in the kprobe path.
- 💾 **Efficient memory usage**
  - `kmem_cache` allocator for log entries (slab cache).
  - Reuses `mod_entry` structs between tables to minimize allocation churn.
- 🧠 **Kernel-version aware**
  - Tested on both `6.8.x` (Ubuntu 24.04) and `5.14.x` (RHEL/Rocky 9) kernels.
- 🧰 **No userspace helper**
  - Fully in-kernel, no `execve()` or external scripts required.

---

## 🧪 Example Output

After loading the module and touching a file:

```bash
# touch /var/tmp/t
# chmod 640 /var/tmp/t
# sleep 2
# getfattr -m - -d /var/tmp/t --only-values
```

Example xattr contents:

```
# file: var/tmp/t
2025-10-16T15:34:20.204 pid=1624 uid=0 comm=touch
2025-10-16T15:34:20.214 pid=1626 uid=0 comm=chmod
"
```

Each line records:
- Timestamp (`clock_gettime(CLOCK_REALTIME)`)
- Process ID
- UID
- Command name (`current->comm`)

---

## ⚙️ Build & Installation

### 1. Build the module
```bash
make
```

Requires kernel headers for the currently running kernel:
```bash
sudo apt install linux-headers-$(uname -r)
# or on RHEL/Rocky:
sudo dnf install kernel-devel-$(uname -r)
```

### 2. Insert the module
```bash
sudo insmod auditmod2xattr.ko
```

Expected log in `dmesg`:
```
auditmod2xattr: init: hooked notify_change → trusted.modification (flush=1000ms, dedupe=200ms)
```

### 3. Verify probe attachment
```bash
cat /sys/kernel/debug/kprobes/list | grep notify_change
```

### 4. Test
```bash
touch /var/tmp/demo
chmod 600 /var/tmp/demo
sleep 2
getfattr -m - -d /var/tmp/demo
```

### 5. Remove the module
```bash
sudo rmmod auditmod2xattr
```

---

## 🧭 Supported / Tested Environments

| Distribution        | Kernel Version                  | Status      |
|---------------------|---------------------------------|--------------|
| **Ubuntu 24.04**    | `6.8.0-85`              | ✅ Tested, stable |
| **Rocky Linux 9.6** | `5.14.0-570.49.1.el9_6.x86_64`  | ✅ Tested, stable |


---

## 🏁 Summary

`auditmod2xattr` provides **efficient, per-file, in-kernel modification auditing** with zero userspace footprint.  

---
