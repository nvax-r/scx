//! Cgroupv2 lifecycle helpers for `scx_invariant`'s spawn mode.
//!
//! `scx_invariant record -- <cmd>` creates a fresh cgroupv2 directory under
//! `/sys/fs/cgroup`, hands its inode (== cgroup id) to BPF rodata as
//! `target_cgid`, and lets the BPF gate
//! `is_target_task(p) = bpf_task_under_cgroup(p, bpf_cgroup_from_id(target_cgid))`
//! filter recording callbacks. We always own the cgroup we create and rmdir
//! it on Drop. Filtering on `p` (the wakee in wakeup callbacks) is enforced
//! in BPF and must not be regressed here.
//!
//! This module is intentionally minimal: only what spawn mode needs. Earlier
//! drafts exposed `attach()`, `add_pid()`, and `path()`; they were dropped
//! when attach mode was cut from this iteration to keep the surface small.

use std::ffi::CString;
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";
/// `CGROUP2_SUPER_MAGIC` from `<linux/magic.h>` ("cgrp"). statfs(2)'s `f_type`
/// is the only reliable way to distinguish cgroupv2 unified hierarchy from
/// hybrid/v1 mounts where `/sys/fs/cgroup` is a tmpfs containing v1
/// controller subdirectories.
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

/// Refuse to start unless `/sys/fs/cgroup` is a cgroupv2 unified mount.
///
/// Hybrid systems where `/sys/fs/cgroup` is tmpfs and v2 is mounted at
/// `/sys/fs/cgroup/unified` are intentionally rejected: the BPF gate is
/// hard-wired to `bpf_cgroup_from_id(target_cgid)` and only the unified
/// hierarchy gives a single inode-id namespace.
pub fn ensure_cgroup_v2_unified() -> Result<()> {
    let path = CString::new(CGROUP_V2_ROOT).expect("static path has no NUL");
    let mut buf: MaybeUninit<libc::statfs> = MaybeUninit::uninit();
    let rc = unsafe { libc::statfs(path.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("statfs({CGROUP_V2_ROOT})"));
    }
    let st = unsafe { buf.assume_init() };
    if (st.f_type as i64) != CGROUP2_SUPER_MAGIC {
        bail!(
            "{CGROUP_V2_ROOT} is not a cgroupv2 unified mount \
             (statfs f_type=0x{:x}, expected 0x{:x}); refusing to start. \
             Boot with `systemd.unified_cgroup_hierarchy=1` or remount.",
            st.f_type as i64,
            CGROUP2_SUPER_MAGIC
        );
    }
    Ok(())
}

/// A cgroupv2 directory we created under `/sys/fs/cgroup`, owned for the
/// lifetime of this process and rmdired on Drop.
pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    /// Create a fresh, empty cgroup at `/sys/fs/cgroup/<name>`.
    ///
    /// If a leftover empty directory exists at the path (e.g. a prior crashed
    /// run with the same PID — unlikely, but cheap to handle), `rmdir` it and
    /// re-create. A non-empty leftover is a hard error: we won't reuse a
    /// cgroup some other process is using.
    pub fn create_temporary(name: &str) -> Result<Self> {
        let path = PathBuf::from(CGROUP_V2_ROOT).join(name);
        if path.exists() {
            // Distinguish "really non-empty" from every other rmdir failure
            // mode (EACCES, EROFS, EIO, ...). Conflating them — as an earlier
            // version did with a blanket "(likely non-empty)" wrap — sends
            // operators chasing cgroup.procs when the real cause is
            // permissions or a read-only mount.
            //
            // cgroupv2 returns EBUSY when the directory contains live tasks
            // and ENOTEMPTY when it contains sub-cgroups; both warrant the
            // "refuse to reuse" hard error. Everything else is surfaced
            // verbatim through the anyhow source chain.
            match fs::remove_dir(&path) {
                Ok(()) => {}
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::EBUSY) | Some(libc::ENOTEMPTY)
                    ) =>
                {
                    bail!(
                        "leftover cgroup at {p} is not empty (live tasks or sub-cgroups present); \
                         refusing to reuse — inspect {p}/cgroup.procs and rmdir manually",
                        p = path.display()
                    );
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e))
                        .with_context(|| format!("rmdir leftover cgroup at {}", path.display()));
                }
            }
        }
        fs::create_dir(&path)
            .with_context(|| format!("create_dir({}) for new cgroup", path.display()))?;
        Ok(Self { path })
    }

    /// `<cgroup>/cgroup.procs` — the spawned child writes "0" here from
    /// `pre_exec` to assign itself to this cgroup.
    pub fn procs_path(&self) -> PathBuf {
        self.path.join("cgroup.procs")
    }

    /// Cgroup id — the inode number of the directory. This is what
    /// `bpf_cgroup_from_id()` expects; it matches `kernfs_node->id` for the
    /// cgroupfs entry.
    pub fn cgid(&self) -> Result<u64> {
        let meta =
            fs::metadata(&self.path).with_context(|| format!("stat({})", self.path.display()))?;
        Ok(meta.ino())
    }

    /// SIGKILL every task in this cgroup, including descendants spawned via
    /// fork/clone (cgroup membership is inherited).
    ///
    /// Backed by cgroupv2's `cgroup.kill` (kernel ≥ 5.14). Synchronous wrt
    /// signal delivery — by the time the write returns, every member has had
    /// SIGKILL queued — but **asynchronous wrt task exit**: tasks are still
    /// running `do_exit` afterwards, so `cgroup.procs` may briefly remain
    /// non-empty. Pair with [`wait_empty`] before `rmdir`.
    ///
    /// Safe to call on an already-empty cgroup (no-op signal delivery).
    pub fn kill_all(&self) -> Result<()> {
        let kill_path = self.path.join("cgroup.kill");
        fs::write(&kill_path, "1\n")
            .with_context(|| format!("write 1 -> {}", kill_path.display()))
    }

    /// Block until `cgroup.procs` is empty or `timeout` elapses.
    ///
    /// Polls every 10 ms. Intended to follow [`kill_all`]: cgroup.kill queues
    /// signals synchronously but reaping is asynchronous, and `rmdir(2)` on a
    /// cgroup with any live (or still-exiting) member returns `EBUSY`.
    pub fn wait_empty(&self, timeout: Duration) -> Result<()> {
        let procs = self.procs_path();
        let deadline = Instant::now() + timeout;
        loop {
            // Treat any read error as "assume non-empty, keep polling" —
            // transient kernfs hiccups during mass exit are not worth
            // surfacing as errors.
            let empty = fs::read_to_string(&procs)
                .map(|s| s.trim().is_empty())
                .unwrap_or(false);
            if empty {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "cgroup {} still non-empty after {:?}",
                    self.path.display(),
                    timeout
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // Happy path: main has already done kill_all + wait_empty + watcher
        // join, so the cgroup is empty and rmdir succeeds in one shot.
        if fs::remove_dir(&self.path).is_ok() {
            return;
        }

        // Salvage path: we got here without main's explicit cleanup running
        // (early `?` return, panic, or future refactor that misses the
        // happy-path branch). Send SIGKILL to anything still inside, wait
        // briefly for the kernel to reap, then retry rmdir. Never panic.
        if let Err(e) = self.kill_all() {
            log::warn!(
                "cgroup salvage: cgroup.kill on {} failed: {}",
                self.path.display(),
                e
            );
        }
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            if fs::remove_dir(&self.path).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        log::warn!(
            "rmdir({}) failed after kill+poll; cgroup leaked",
            self.path.display()
        );
    }
}
