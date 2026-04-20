mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
mod cgroup;
mod output;
mod recorder;

use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use libbpf_rs::OpenObject;
use log::{info, warn};
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;

use crate::cgroup::{ensure_cgroup_v2_unified, Cgroup};
use crate::output::CpuTopo;

const SCHEDULER_NAME: &str = "scx_invariant";

#[derive(Parser, Debug)]
#[clap(name = "scx_invariant", about = "Record scheduler-invariant workload identity")]
struct Args {
    /// Output trace file path.  If omitted, events are counted but not written.
    ///
    /// Legacy form: `scx_invariant -o file.scxi` is equivalent to
    /// `scx_invariant record -o file.scxi` (system-wide), kept for backwards
    /// compatibility with the pre-subcommand syntax.
    ///
    /// **Cannot be combined with a subcommand.** If you use `record`, pass
    /// `-o` to it (e.g. `scx_invariant record -o file.scxi -- cmd`). Mixing
    /// the two forms is rejected at startup to avoid silently dropping the
    /// outer `-o` on the floor.
    #[clap(short, long)]
    output: Option<String>,

    #[command(subcommand)]
    cmd: Option<SubCmd>,
}

#[derive(Subcommand, Debug)]
enum SubCmd {
    /// Record a trace, optionally scoped to a spawned workload.
    ///
    /// Two modes:
    ///   * spawn       — `record -o trace.scxi -- <cmd> <args...>` creates a
    ///                   fresh cgroupv2 dir, fork+execs the workload into it,
    ///                   records until the workload exits, then `rmdir`s.
    ///   * system-wide — `record -o trace.scxi` (no trailing command)
    ///                   records every task on the system. Useful for
    ///                   debugging; identical to the legacy top-level form.
    Record(RecordArgs),
}

#[derive(Parser, Debug)]
struct RecordArgs {
    /// Output trace file path. If omitted, events are counted but not written.
    #[clap(short, long)]
    output: Option<String>,

    /// Workload command and arguments. Everything after `--` is passed
    /// verbatim to the spawned process. `last = true` lets clap accept
    /// hyphen-prefixed args (e.g. `-- stress-ng --cpu 4`) without requiring
    /// `--` quoting per token.
    #[clap(last = true)]
    command: Vec<String>,
}

/// Resolved recording mode after CLI parsing.
#[derive(Debug)]
enum Mode {
    /// No filtering; record every task on the system. Shutdown on SIGINT.
    SystemWide { output: Option<String> },
    /// Create a fresh cgroupv2 dir, spawn the workload into it, record until
    /// the workload exits (or SIGINT), then rmdir the cgroup.
    Spawn {
        output: Option<String>,
        command: Vec<String>,
    },
}

impl Mode {
    fn output(&self) -> Option<&str> {
        match self {
            Mode::SystemWide { output } | Mode::Spawn { output, .. } => output.as_deref(),
        }
    }
}

fn resolve_mode(args: Args) -> Result<Mode> {
    // Reject mixed legacy/subcommand forms. Previously the outer `-o` was
    // silently dropped whenever a subcommand was present, which turned the
    // typo `scx_invariant -o file record -- cmd` into "trace counted but
    // nothing written." We refuse rather than guess: the user is told to
    // pick one form. We don't try to be clever about "outer == inner" or
    // "outer set, inner unset" — a single hard rule is easier to teach and
    // leaves no ambiguous case for future readers.
    if args.output.is_some() && args.cmd.is_some() {
        bail!(
            "the legacy top-level `-o` cannot be combined with a subcommand; \
             pass `-o` to the subcommand instead \
             (e.g. `scx_invariant record -o <file> -- <cmd>`)"
        );
    }

    Ok(match args.cmd {
        None => Mode::SystemWide {
            output: args.output,
        },
        Some(SubCmd::Record(r)) => {
            if r.command.is_empty() {
                Mode::SystemWide { output: r.output }
            } else {
                Mode::Spawn {
                    output: r.output,
                    command: r.command,
                }
            }
        }
    })
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    /// Open, configure rodata, load, and attach the BPF scheduler.
    ///
    /// `target_cgid`:
    ///   * `None`         — system-wide mode; rodata `cgroup_filtering = false`.
    ///   * `Some(cgid)`   — filter to the cgroup whose inode == `cgid`;
    ///                      BPF gates every recording callback on
    ///                      `bpf_task_under_cgroup(p, bpf_cgroup_from_id(cgid))`.
    ///
    /// Rodata MUST be set between open and load — once `scx_ops_load!` has
    /// freezed the maps, the values are immutable for the lifetime of the
    /// BPF program.
    fn init(
        open_object: &'a mut MaybeUninit<OpenObject>,
        target_cgid: Option<u64>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();

        info!("{} starting", SCHEDULER_NAME);

        let skel_builder = BpfSkelBuilder::default();
        let mut skel = scx_ops_open!(skel_builder, open_object, invariant_ops, None::<libbpf_rs::libbpf_sys::bpf_object_open_opts>)?;

        {
            let rodata = skel
                .maps
                .rodata_data
                .as_mut()
                .ok_or_else(|| anyhow!("BPF skeleton has no rodata map"))?;
            match target_cgid {
                Some(cgid) => {
                    rodata.cgroup_filtering = true;
                    rodata.target_cgid = cgid;
                    info!("Cgroup filtering enabled, target_cgid={cgid}");
                }
                None => {
                    rodata.cgroup_filtering = false;
                    rodata.target_cgid = 0;
                    info!("Cgroup filtering disabled (system-wide)");
                }
            }
        }

        let mut skel = scx_ops_load!(skel, invariant_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, invariant_ops)?);

        info!("{} scheduler attached", SCHEDULER_NAME);

        Ok(Self { skel, struct_ops })
    }

    fn run(
        &mut self,
        shutdown: Arc<AtomicBool>,
        output_path: Option<&str>,
        topology: &[CpuTopo],
        nr_cpus: u16,
    ) -> Result<UserExitInfo> {
        let event_count =
            recorder::run_consumer(&self.skel, shutdown, output_path, topology, nr_cpus)?;
        info!("Recorded {} events", event_count);

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregistering {}", SCHEDULER_NAME);
    }
}

/// Spawn the workload command and have the **child** assign itself into
/// the given cgroup before `exec()`.
///
/// Why child-side and not parent-side: writing the parent's pid to
/// `cgroup.procs` would migrate `scx_invariant` itself into the target
/// cgroup, making us record our own scheduling. By writing "0" from inside
/// `pre_exec`, only the post-fork child enters. There is a brief window
/// between fork and the cgroup.procs write where the child is still in our
/// cgroup; the resulting handful of stray events is acceptable per task.md.
///
/// `pre_exec` closures must be async-signal-safe — we pre-build the
/// CString in the parent and use raw libc calls inside the closure.
fn spawn_workload(command: &[String], cgroup: &Cgroup) -> Result<Child> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow!("empty workload command"))?;

    let procs_path_cstr = CString::new(
        cgroup
            .procs_path()
            .to_str()
            .ok_or_else(|| anyhow!("cgroup.procs path is not valid UTF-8"))?,
    )
    .context("cgroup.procs path contains an interior NUL")?;

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // SAFETY: closure body only calls async-signal-safe libc functions
    // (open, write, close) and accesses an already-allocated CString.
    unsafe {
        cmd.pre_exec(move || {
            let fd = libc::open(procs_path_cstr.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Writing "0" assigns the calling task (the post-fork child).
            let buf: &[u8] = b"0\n";
            let n = libc::write(fd, buf.as_ptr() as *const _, buf.len());
            let werr = if n != buf.len() as isize {
                Some(std::io::Error::last_os_error())
            } else {
                None
            };
            libc::close(fd);
            if let Some(e) = werr {
                return Err(e);
            }
            Ok(())
        });
    }

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn workload `{program}`"))?;
    // Log program name + arg count only. Workload argv frequently carries
    // credentials (e.g. `mysql -p$PASS`, `curl -u user:pass`, `redis-cli -a
    // $TOKEN`); stderr can be captured to journald / files where exposure
    // outlives the process. /proc/<pid>/cmdline already covers the
    // transient-debug case for anyone with procfs access.
    info!(
        "Workload spawned: pid={} program={program} args=({})",
        child.id(),
        args.len()
    );
    Ok(child)
}

/// Wait for the workload to exit on a background thread and flip the shared
/// shutdown flag. The recorder loop already polls this flag every 1 ms
/// (`src/recorder.rs:58`), so no recorder changes are needed.
///
/// Joined by main on the shutdown path *after* `Cgroup::kill_all` +
/// `wait_empty`. On the workload-driven exit path the join returns
/// immediately (the watcher already woke up); on the SIGINT path the join
/// returns once the kernel reaps our direct child, which happens promptly
/// after `cgroup.kill` SIGKILLs every member of the target cgroup.
fn spawn_child_watcher(mut child: Child, shutdown: Arc<AtomicBool>) -> JoinHandle<()> {
    std::thread::spawn(move || match child.wait() {
        Ok(status) => {
            info!("Workload exited: {status}");
            shutdown.store(true, Ordering::Relaxed);
        }
        Err(e) => {
            warn!("waitpid on workload failed: {e}");
            shutdown.store(true, Ordering::Relaxed);
        }
    })
}

fn build_topology() -> Result<(Vec<CpuTopo>, u16)> {
    let topo = Topology::new().context("Failed to read CPU topology")?;
    let mut entries: Vec<CpuTopo> = Vec::new();

    for (_id, cpu) in &topo.all_cpus {
        entries.push(CpuTopo {
            cpu_id: cpu.id as u16,
            llc_id: cpu.llc_id as u16,
            numa_id: cpu.node_id as u16,
            max_freq_mhz: (cpu.max_freq / 1000) as u16,
            capacity: cpu.cpu_capacity as u32,
            _pad: 0,
        });
    }

    entries.sort_by_key(|e| e.cpu_id);
    let nr_cpus = entries.len() as u16;
    info!("Topology: {} CPUs", nr_cpus);
    Ok((entries, nr_cpus))
}

fn main() -> Result<()> {
    let args = Args::parse();

    let loglevel = simplelog::LevelFilter::Info;
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Info)
        .set_location_level(simplelog::LevelFilter::Info)
        .set_target_level(simplelog::LevelFilter::Info)
        .set_thread_level(simplelog::LevelFilter::Info);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let mode = resolve_mode(args)?;
    // Manual summary instead of `{mode:?}`: Mode::Spawn carries the full
    // workload argv via `command: Vec<String>`, and stderr can outlive the
    // process (journald, redirected files). Print program + arg count only.
    // `Debug` on Mode is intentionally retained for tests/dbg!() use; do not
    // restore `info!("{mode:?}")` here.
    match &mode {
        Mode::SystemWide { output } => {
            info!(
                "Mode: system-wide, output={}",
                output.as_deref().unwrap_or("<none>")
            );
        }
        Mode::Spawn { output, command } => {
            let program = command.first().map(String::as_str).unwrap_or("<none>");
            let nargs = command.len().saturating_sub(1);
            info!(
                "Mode: spawn, output={}, program={program}, args=({nargs})",
                output.as_deref().unwrap_or("<none>"),
            );
        }
    }

    let (topology, nr_cpus) = build_topology()?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    // Resolve cgroup setup BEFORE BPF load — we need its inode to feed
    // `target_cgid` into rodata. `Cgroup` lives until end of main; on Drop
    // it best-effort rmdirs the temporary directory we created.
    let cgroup: Option<Cgroup> = match &mode {
        Mode::SystemWide { .. } => None,
        Mode::Spawn { .. } => {
            ensure_cgroup_v2_unified()?;
            let name = format!("scx_invariant-{}", std::process::id());
            Some(Cgroup::create_temporary(&name)?)
        }
    };

    let target_cgid = cgroup.as_ref().map(|c| c.cgid()).transpose()?;

    let mut open_object = MaybeUninit::uninit();
    let mut sched = Scheduler::init(&mut open_object, target_cgid)?;

    // Spawn the workload AFTER the BPF scheduler is attached so its very
    // first scheduling transition is captured. The watcher thread flips
    // `shutdown` when the child exits; SIGINT continues to work in parallel.
    let watcher: Option<JoinHandle<()>> = match &mode {
        Mode::Spawn { command, .. } => {
            let cg = cgroup.as_ref().expect("spawn mode always has a cgroup");
            let child = spawn_workload(command, cg)?;
            Some(spawn_child_watcher(child, shutdown.clone()))
        }
        Mode::SystemWide { .. } => None,
    };

    let exit_info = sched.run(shutdown, mode.output(), &topology, nr_cpus)?;

    if exit_info.should_restart() {
        info!("Scheduler requested restart");
    }

    // Spawn-mode shutdown sequencing. `sched.run` returned because shutdown
    // was set — either by the watcher (workload exited normally) or by the
    // SIGINT handler (workload still running). Treat both the same:
    //   1. cgroup.kill — SIGKILL every task still in the cgroup, including
    //      descendants (no-op if already empty).
    //   2. wait_empty  — block until the kernel finishes reaping so the
    //      subsequent rmdir won't EBUSY.
    //   3. watcher.join — flush the watcher's "Workload exited" log and
    //      ensure no detached thread outlives main's cleanup.
    // Any failure here is logged and swallowed: the eventual `drop(cgroup)`
    // re-attempts cleanup via its salvage path.
    if let (Some(cg), Some(w)) = (cgroup.as_ref(), watcher) {
        if let Err(e) = cg.kill_all() {
            warn!("cgroup.kill on shutdown: {e}");
        }
        if let Err(e) = cg.wait_empty(std::time::Duration::from_millis(500)) {
            warn!("waiting for cgroup to drain: {e}");
        }
        let _ = w.join();
    }

    // `cgroup` Drops here: rmdir succeeds on the happy path because the
    // explicit cleanup above already drained the cgroup; the Drop's salvage
    // path is the safety net for early-return / panic cases.
    drop(cgroup);
    Ok(())
}
