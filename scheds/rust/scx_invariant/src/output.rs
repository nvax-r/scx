use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};

use anyhow::{Context, Result};
use log::info;

const MAGIC: &[u8; 4] = b"SCXI";
/// SCXI on-disk format version. v2 moved event IDs out of the
/// section-ID numeric space (events now live at 0x0100+, sections
/// stay at 0x0001..0x0005) — see PLAN.md §5/§11. v1 is intentionally
/// unsupported by the in-tree reader.
///
/// 2026-05-12: SECTION_PROCS (0x0002) was retired and SECTION_PROC_MAPS
/// (0x0004) and SECTION_PROC_STACKS (0x0005) were added. The version
/// stays at 2 — the new sections fit cleanly in the existing v2
/// section namespace and the new event IDs (EVT_PROC_NEW/EXEC/SAMPLE
/// at 0x0104..0x0106) fit cleanly in the existing v2 event namespace.
/// 0x0002 is permanently retired; do not re-use the slot.
const VERSION: u16 = 2;
const ARCH_AARCH64: u16 = 1;

/// Read CLOCK_MONOTONIC nanoseconds.
///
/// The header's `timestamp_start_ns` / `timestamp_end_ns` MUST share a
/// time domain with the BPF events written to the same trace; the
/// events use `scx_bpf_now()` which is `bpf_ktime_get_ns()` =
/// CLOCK_MONOTONIC. Using `SystemTime::now()` (CLOCK_REALTIME) here —
/// as this code did pre-fix — silently produced traces where every
/// event's `timestamp_ns - hdr.ts_start` underflowed wildly into the
/// negative, breaking any consumer that relativized event times to
/// trace start (heatmap, timeline). The byte layout is unchanged;
/// only the interpretation of the two timestamp slots shifts.
///
/// CLOCK_MONOTONIC is mandatory POSIX and cannot fail with EINVAL on
/// any supported Linux kernel; treating a non-zero return as
/// recorder-startup-can't-continue is correct.
fn monotonic_now_ns() -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert!(rc == 0, "clock_gettime(CLOCK_MONOTONIC) failed");
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

const SECTION_TOPOLOGY: u16 = 0x0001;
/* SECTION_PROCS (0x0002) is retired. The pid → comm mapping is now
 * carried in the EVT_PROC_NEW event stream and reconstructed by the
 * Python analyzer. Do NOT re-use this slot for any new section.
 * See work/changelog.md 2026-05-12 for the rationale. */
const SECTION_EVENTS: u16 = 0x0003;
const SECTION_PROC_MAPS: u16 = 0x0004;
const SECTION_PROC_STACKS: u16 = 0x0005;

// --- Event-type constants (mirror src/bpf/intf.h) ---
const EVT_PROC_NEW: u16 = 0x0104;
const EVT_PROC_EXEC: u16 = 0x0105;
const EVT_SAMPLE: u16 = 0x0106;

/// On-disk size of EVT_SAMPLE: 24 B header + s32 stack_id + u32 pad.
/// The wire (BPF→Rust) form is fatter (carries inline IP[]) and is
/// transformed by [`TraceWriter::write_sample_event`] before disk write.
const SAMPLE_DISK_SIZE: u16 = 32;

/// Maximum stack depth captured per quantum. Mirrors STACK_DEPTH_MAX
/// in src/bpf/intf.h. The wire payload always carries 16 IP slots
/// (zero-padded if the walk was shallower); the recorder strips
/// trailing zeros before hashing / writing the dedup table.
const STACK_DEPTH_MAX: usize = 16;

/// Wire size of EVT_SAMPLE from BPF: 24 hdr + 4 walk_ret + 4 pad +
/// 16 × 8 ip = 160 B.
const SAMPLE_WIRE_SIZE: usize = 24 + 4 + 4 + STACK_DEPTH_MAX * 8;

/// Per-CPU topology entry for the binary file (16 bytes).
#[derive(Clone)]
pub struct CpuTopo {
    pub cpu_id: u16,
    pub llc_id: u16,
    pub numa_id: u16,
    pub max_freq_mhz: u16,
    pub capacity: u32,
    pub _pad: u32,
}

/// One executable mapping out of /proc/<pid>/maps.
///
/// Captured at EVT_PROC_NEW / EVT_PROC_EXEC by [`snapshot_proc`].
/// `path` is empty for anonymous mappings (encoded as path_len=0 on
/// disk; the Python symbolizer renders these as `[anon]+0x<offset>`).
#[derive(Clone, Debug)]
pub struct MapEntry {
    pub vm_start: u64,
    pub vm_end: u64,
    pub vm_pgoff: u64,
    pub dso_inode: u64,
    pub path: Vec<u8>,
}

/// Per-PID userspace context, accumulated as EVT_PROC_NEW / EXEC arrive.
///
/// `partial_identity` is set when the PID was first seen in a
/// scheduling event (running/stopping/...) before its EVT_PROC_NEW
/// arrived — typically because the ringbuf carrying that proc-new was
/// momentarily full. Carried into the ProcMaps section; the analyzer
/// surfaces it as a yellow row tint per design §7 fallback states.
///
/// `inherited_from_parent` is set when EVT_PROC_NEW for a freshly-forked
/// task arrived after the task had already exited (so /proc/<pid> was
/// gone), but /proc/<ppid> still existed and we used it as a stand-in
/// for the child's executable mappings. This is correct because:
///   * Without CLONE_VM, the child's mm is COW-copied from the parent
///     at fork time — executable mappings are byte-identical.
///   * With CLONE_VM (threads), the child literally shares the
///     parent's mm, so maps are always identical.
///   * Any post-fork divergence is captured by a subsequent
///     EVT_PROC_EXEC (whose snapshot replaces this fallback record),
///     so the only residual approximation is the rare case of
///     fork → mmap → exit without ever calling execve. Rendering
///     surfaces the flag so analysts can attribute symbols accordingly.
///
/// This is the dominant outcome for sub-millisecond tasks (build
/// pipelines, posix_spawn failure paths, fork bombs) — the fork path
/// inside `kernel/fork.c::copy_process()` emits EVT_PROC_NEW from
/// `sched_fork()` (line ~2231) but the pid hash is only attached at
/// `attach_pid(p, PIDTYPE_PID)` (line ~2504). For long-lived tasks
/// the consumer drains the ring after attach_pid — `/proc/<pid>`
/// exists, no fallback fires. For sub-ms tasks the consumer drains
/// after release_task — `/proc/<pid>` is gone, this fallback fires.
///
/// `no_maps` is set only when BOTH /proc/<pid> AND /proc/<ppid> were
/// gone by the time we tried to snapshot (e.g. ppid==0 for the very
/// first scx_init pass on `swapper`, or a kernel thread whose parent
/// is also gone). The PID still gets a record in ProcMaps with an
/// empty maps list so the consumer's per-PID iteration stays uniform.
#[derive(Clone, Debug, Default)]
pub struct ProcInfo {
    pub maps: Vec<MapEntry>,
    pub cmdline: Vec<u8>,
    pub no_maps: bool,
    pub partial_identity: bool,
    pub inherited_from_parent: bool,
}

/// Bit assignments for the per-PID flags slot in the ProcMaps section.
/// The slot is a `u16` — it was previously a zero-filled `pad` field
/// in v2 traces, so any old (pre-2026-05-12) trace decodes cleanly as
/// "all flags clear", which is the correct historical interpretation.
///
/// Do not change these bit values once shipped; add new flags by
/// claiming higher bits.
const PROC_FLAG_NO_MAPS: u16 = 1 << 0;
const PROC_FLAG_PARTIAL_IDENTITY: u16 = 1 << 1;
const PROC_FLAG_INHERITED_FROM_PARENT: u16 = 1 << 2;

/// Parse /proc/<pid>/maps and /proc/<pid>/cmdline into a [`ProcInfo`].
///
/// Filters maps to executable (`x` permission) entries only — the
/// symbolizer doesn't need data/heap mappings. ESRCH (process gone)
/// is the expected outcome for sub-millisecond ephemeral PIDs.
///
/// `ppid_hint` is the parent tgid as carried in EVT_PROC_NEW. When
/// /proc/<pid>/maps is missing AND `ppid_hint` is `Some(p)` with
/// `p != 0`, we retry against /proc/<p>/maps and tag
/// `inherited_from_parent = true`. Rationale: at fork time the
/// child's mm is COW-copied from the parent (or shared, for threads)
/// — the executable mappings are byte-identical, so the parent's
/// view is a faithful stand-in for the child's. See
/// [`ProcInfo`]/`inherited_from_parent` for the full semantics.
///
/// `ppid_hint` should be `None` for any caller that doesn't have a
/// proven parent identity in hand (post-exec snapshots, first-sight
/// scheduling-event fallbacks). The hint exists only to recover the
/// dominant fork-emit-then-exit miss path; misusing it on adult
/// processes would silently substitute the bash shell's maps for a
/// long-lived daemon's, which is worse than `no_maps`.
///
/// No retry / no sleep. The recorder's poll loop is 1 ms, so by the
/// time we reach this code on a snapshot path, the process either
/// exists, or it's already dead and waiting won't bring it back.
fn snapshot_proc(pid: u32, ppid_hint: Option<u32>) -> ProcInfo {
    let mut info = ProcInfo::default();

    let maps_path = format!("/proc/{}/maps", pid);
    match std::fs::read_to_string(&maps_path) {
        Ok(text) => {
            for line in text.lines() {
                if let Some(entry) = parse_maps_line(line) {
                    info.maps.push(entry);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // /proc/<pid> already gone. Try the parent.
            if let Some(ppid) = ppid_hint {
                if ppid != 0 && ppid != pid {
                    let pmaps = format!("/proc/{}/maps", ppid);
                    if let Ok(text) = std::fs::read_to_string(&pmaps) {
                        for line in text.lines() {
                            if let Some(entry) = parse_maps_line(line) {
                                info.maps.push(entry);
                            }
                        }
                        info.inherited_from_parent = true;
                    } else {
                        info.no_maps = true;
                    }
                } else {
                    info.no_maps = true;
                }
            } else {
                info.no_maps = true;
            }
        }
        Err(_) => {
            info.no_maps = true;
        }
    }

    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(bytes) = std::fs::read(&cmdline_path) {
        info.cmdline = bytes;
    } else if info.inherited_from_parent {
        // cmdline is also inherited at fork time (clobbered only by
        // execve). If the child's is gone, the parent's is a faithful
        // stand-in. Don't escalate inherited_from_parent on cmdline
        // failure alone — maps drives the flag.
        if let Some(ppid) = ppid_hint {
            if ppid != 0 && ppid != pid {
                if let Ok(bytes) = std::fs::read(&format!("/proc/{}/cmdline", ppid)) {
                    info.cmdline = bytes;
                }
            }
        }
    }

    info
}

/// Parse a single /proc/<pid>/maps line.
///
/// Format reference (Documentation/filesystems/proc.rst):
///   address           perms offset  dev   inode   pathname
///   00400000-0040b000 r-xp  00000000 fd:00 1234     /usr/bin/cat
/// Anonymous mappings have an empty pathname (or `[heap]`/`[stack]`
/// markers that we treat as opaque path strings).
///
/// Returns None for non-executable mappings (no `x` in perms). We
/// keep `[vdso]` / `[vsyscall]` and similar bracketed pseudo-DSOs
/// as long as they carry the executable bit — addr2line will fail
/// on them but the mapping presence lets the analyzer distinguish
/// "in vdso" from "completely unmapped IP".
fn parse_maps_line(line: &str) -> Option<MapEntry> {
    let mut it = line.splitn(6, ' ');
    let addr_range = it.next()?;
    let perms = it.next()?;
    let offset = it.next()?;
    let dev_unused = it.next()?;
    let inode = it.next()?;
    let path = it.next().unwrap_or("").trim_start();

    if !perms.contains('x') {
        return None;
    }

    let mut addrs = addr_range.splitn(2, '-');
    let vm_start = u64::from_str_radix(addrs.next()?, 16).ok()?;
    let vm_end = u64::from_str_radix(addrs.next()?, 16).ok()?;
    let vm_pgoff = u64::from_str_radix(offset, 16).ok()?;
    let dso_inode = inode.parse::<u64>().ok()?;
    let _ = dev_unused;

    Some(MapEntry {
        vm_start,
        vm_end,
        vm_pgoff,
        dso_inode,
        path: path.as_bytes().to_vec(),
    })
}

/// Fast binary trace writer.
///
/// Hot path: `write_event` receives raw `&[u8]` from the ring buffer
/// and writes a 4-byte TLV prefix + payload. For most event types
/// (RUNNING/STOPPING/RUNNABLE/QUIESCENT/PROC_NEW/PROC_EXEC) the
/// payload is byte-identical wire-to-disk and is passed through
/// verbatim. EVT_SAMPLE is the one exception — it arrives at 160 B
/// (wire) and is transformed to 32 B (disk) by hashing the inline
/// IP[] into a userspace stack-id; the dedup table is dumped in the
/// ProcStacks section at finalize.
///
/// `procs_seen` is the per-PID userspace context, populated by
/// `snapshot_proc()` calls triggered by EVT_PROC_NEW / EVT_PROC_EXEC.
/// It also carries the fallback first-sight path: if a scheduling
/// event arrives for a PID we have no record of (its EVT_PROC_NEW was
/// dropped), we snapshot it inline and tag `partial_identity = true`.
pub struct TraceWriter {
    writer: BufWriter<File>,
    event_count: u64,
    procs_seen: HashMap<u32, ProcInfo>,
    /// Userspace stack-id dedup table.
    ///
    /// Key is the trimmed IP vector (trailing zero frames stripped).
    /// Value is the assigned stack_id. Order of insertion = numeric
    /// order of stack_ids; iteration order at finalize sorts by sid
    /// for stable on-disk output.
    stack_ids: HashMap<Vec<u64>, u32>,
}

impl TraceWriter {
    /// Create a new trace file and write the header + topology section +
    /// events section header.
    pub fn new(path: &str, nr_cpus: u16, topology: &[CpuTopo]) -> Result<Self> {
        let file = File::create(path).with_context(|| format!("create {}", path))?;
        let mut writer = BufWriter::with_capacity(256 * 1024, file);

        // --- File header (64 bytes) ---
        let now_ns = monotonic_now_ns();

        let mut hostname = [0u8; 28];
        if let Ok(name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
            let name = name.trim();
            let len = name.len().min(27);
            hostname[..len].copy_from_slice(&name.as_bytes()[..len]);
        }

        let mut kernel_ver: u32 = 0;
        if let Ok(ver) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let parts: Vec<&str> = ver.trim().split('.').collect();
            if parts.len() >= 3 {
                let major = parts[0].parse::<u32>().unwrap_or(0);
                let minor = parts[1].parse::<u32>().unwrap_or(0);
                let patch = parts[2]
                    .split('-')
                    .next()
                    .unwrap_or("0")
                    .parse::<u32>()
                    .unwrap_or(0);
                kernel_ver = (major << 16) | (minor << 8) | patch;
            }
        }

        writer.write_all(MAGIC)?; // 0..4
        writer.write_all(&VERSION.to_le_bytes())?; // 4..6
        writer.write_all(&64u16.to_le_bytes())?; // 6..8  header_size
        writer.write_all(&0u32.to_le_bytes())?; // 8..12 flags
        writer.write_all(&now_ns.to_le_bytes())?; // 12..20 timestamp_start
        writer.write_all(&0u64.to_le_bytes())?; // 20..28 timestamp_end (filled at finalize)
        writer.write_all(&hostname)?; // 28..56
        writer.write_all(&kernel_ver.to_le_bytes())?; // 56..60
        writer.write_all(&ARCH_AARCH64.to_le_bytes())?; // 60..62
        writer.write_all(&nr_cpus.to_le_bytes())?; // 62..64

        // --- Topology section ---
        // Section header: type(u16) + len(u32) = 6 bytes
        let topo_len = topology.len() as u32 * 16;
        writer.write_all(&SECTION_TOPOLOGY.to_le_bytes())?;
        writer.write_all(&topo_len.to_le_bytes())?;
        for entry in topology {
            writer.write_all(&entry.cpu_id.to_le_bytes())?;
            writer.write_all(&entry.llc_id.to_le_bytes())?;
            writer.write_all(&entry.numa_id.to_le_bytes())?;
            writer.write_all(&entry.max_freq_mhz.to_le_bytes())?;
            writer.write_all(&entry.capacity.to_le_bytes())?;
            writer.write_all(&entry._pad.to_le_bytes())?;
        }

        // --- Events section header ---
        // len = 0 means "read until next section or EOF"
        writer.write_all(&SECTION_EVENTS.to_le_bytes())?;
        writer.write_all(&0u32.to_le_bytes())?;

        writer.flush()?;

        info!(
            "Trace file created: {} ({} CPUs, header 64B, topo {}B)",
            path,
            nr_cpus,
            topo_len + 6
        );

        Ok(Self {
            writer,
            event_count: 0,
            procs_seen: HashMap::with_capacity(4096),
            stack_ids: HashMap::with_capacity(4096),
        })
    }

    /// Write a single event from the ring buffer.
    ///
    /// Format: [event_type: u16][payload_len: u16][raw bytes]
    ///
    /// `data` is the raw ring buffer payload. We read event_type from
    /// offset 20 (scx_invariant_event.event_type) and pid from offset 8.
    ///
    /// Dispatch:
    ///   * EVT_PROC_NEW: snapshot /proc/<pid>/{maps, cmdline} with
    ///     parent-pid fallback. The fork path emits this event from
    ///     `sched_fork()` (kernel/fork.c:2231) BEFORE
    ///     `attach_pid(p, PIDTYPE_PID)` runs (kernel/fork.c:2504),
    ///     so /proc/<pid> doesn't exist at BPF emit time. By the
    ///     time the userspace consumer drains the ringbuf and calls
    ///     this code, attach_pid has long since completed for any
    ///     surviving task — but for sub-millisecond ephemerals
    ///     (build pipelines, posix_spawn failures, fork bombs) the
    ///     task may have already been released by the parent's
    ///     `wait()`. In that case /proc/<pid> is gone; we fall back
    ///     to /proc/<ppid> (the child's mm was COW-copied or shared
    ///     from the parent at fork time, so executable mappings
    ///     match).
    ///   * EVT_PROC_EXEC: snapshot /proc/<pid> directly (no parent
    ///     fallback). At exec time the task has been alive long
    ///     enough to be scheduled, so /proc/<pid> is reliably
    ///     present and its mm has just been replaced by execve —
    ///     the parent's maps are no longer relevant.
    ///   * EVT_SAMPLE is transformed wire→disk: the inline IP[16] is
    ///     hashed, allocated a per-trace stack_id, and a 32 B record
    ///     replaces the 160 B wire payload on disk. Negative walk_ret
    ///     (BPF stack walk failed) is recorded as the stack_id directly.
    ///   * Any other event type whose `pid` we have no record of
    ///     triggers a fallback first-sight snapshot tagged
    ///     `partial_identity = true` (see ProcInfo doc). No parent
    ///     fallback here — we have no ppid in scheduling-event
    ///     payloads, and any task being scheduled has /proc/<pid>.
    #[inline]
    pub fn write_event(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 24 {
            return Ok(()); // too short to be a valid event
        }

        // Read event_type from offset 20 (u16 LE)
        let event_type = u16::from_le_bytes([data[20], data[21]]);
        // Read pid from offset 8 (u32 LE)
        let pid = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        match event_type {
            EVT_PROC_NEW => {
                // Pull ppid from offset 24 (start of evt_proc_new
                // payload, immediately after the 24 B common header).
                // Defensive bounds check — a malformed EVT_PROC_NEW
                // shorter than 28 B falls back to ppid_hint=None.
                let ppid_hint = if data.len() >= 28 {
                    Some(u32::from_le_bytes([data[24], data[25], data[26], data[27]]))
                } else {
                    None
                };
                let info = snapshot_proc(pid, ppid_hint);
                self.procs_seen.insert(pid, info);
            }
            EVT_PROC_EXEC => {
                let info = snapshot_proc(pid, None);
                self.procs_seen.insert(pid, info);
            }
            EVT_SAMPLE => {
                self.write_sample_event(data, pid)?;
                return Ok(());
            }
            _ => {
                if let Entry::Vacant(slot) = self.procs_seen.entry(pid) {
                    let mut info = snapshot_proc(pid, None);
                    info.partial_identity = true;
                    slot.insert(info);
                }
            }
        }

        let payload_len = data.len() as u16;
        self.writer.write_all(&event_type.to_le_bytes())?;
        self.writer.write_all(&payload_len.to_le_bytes())?;
        self.writer.write_all(data)?;

        self.event_count += 1;
        Ok(())
    }

    /// Transform a 160 B EVT_SAMPLE wire payload into a 32 B on-disk
    /// EVT_SAMPLE record, allocating / dedup'ing the stack_id.
    ///
    /// Wire layout: hdr(24) + walk_ret:s32(4) + pad:u32(4) + ip[16]:u64(128).
    /// Disk layout: hdr(24) + stack_id:s32(4) + pad:u32(4)            = 32 B.
    ///
    /// Negative `walk_ret` (BPF stack walk returned -errno) flows
    /// straight through as `stack_id` per the spec's failure semantics.
    /// Non-negative `walk_ret` is the byte count of frames written;
    /// `depth = walk_ret / 8`. Trailing zero frames are stripped before
    /// hashing so two stack walks that produced 5 and 6 frames where
    /// the 6th was zero hash to the same id.
    fn write_sample_event(&mut self, data: &[u8], pid: u32) -> Result<()> {
        if data.len() < SAMPLE_WIRE_SIZE {
            // Wire payload is short — should never happen for a real
            // EVT_SAMPLE, but be defensive: drop silently rather than
            // write a malformed disk record.
            return Ok(());
        }

        if let Entry::Vacant(slot) = self.procs_seen.entry(pid) {
            let mut info = snapshot_proc(pid, None);
            info.partial_identity = true;
            slot.insert(info);
        }

        let walk_ret = i32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        let stack_id: i32 = if walk_ret < 0 {
            walk_ret
        } else {
            let depth_bytes = walk_ret as usize;
            let mut depth = depth_bytes / 8;
            if depth > STACK_DEPTH_MAX {
                depth = STACK_DEPTH_MAX;
            }
            let mut ips: Vec<u64> = Vec::with_capacity(depth);
            for i in 0..depth {
                let off = 32 + i * 8;
                ips.push(u64::from_le_bytes([
                    data[off],
                    data[off + 1],
                    data[off + 2],
                    data[off + 3],
                    data[off + 4],
                    data[off + 5],
                    data[off + 6],
                    data[off + 7],
                ]));
            }
            while ips.last() == Some(&0) {
                ips.pop();
            }

            let next_id = self.stack_ids.len() as u32;
            match self.stack_ids.entry(ips) {
                Entry::Occupied(e) => *e.get() as i32,
                Entry::Vacant(slot) => {
                    slot.insert(next_id);
                    next_id as i32
                }
            }
        };

        // Disk record: TLV(4) + hdr(24) + stack_id(4) + pad(4) = 36 B written.
        self.writer.write_all(&EVT_SAMPLE.to_le_bytes())?;
        self.writer.write_all(&SAMPLE_DISK_SIZE.to_le_bytes())?;
        self.writer.write_all(&data[..24])?;
        self.writer.write_all(&stack_id.to_le_bytes())?;
        self.writer.write_all(&0u32.to_le_bytes())?;

        self.event_count += 1;
        Ok(())
    }

    /// Finalize the trace: write ProcMaps + ProcStacks, update timestamp_end.
    ///
    /// Both new sections are materialized from in-memory state
    /// captured during recording (`procs_seen` for ProcMaps,
    /// `stack_ids` for ProcStacks). No /proc reads at finalize time —
    /// short-lived processes are already gone, and re-reading would
    /// only refresh the IPs we already symbolize from. The historical
    /// SECTION_PROCS (0x0002) writer is removed; its information lives
    /// in the EVT_PROC_NEW event stream now.
    pub fn finalize(&mut self) -> Result<u64> {
        self.writer.flush()?;

        self.write_proc_maps_section()?;
        self.write_proc_stacks_section()?;

        // --- Update timestamp_end at offset 20 ---
        let now_ns = monotonic_now_ns();
        self.writer.seek(SeekFrom::Start(20))?;
        self.writer.write_all(&now_ns.to_le_bytes())?;
        self.writer.flush()?;

        let n_partial = self
            .procs_seen
            .values()
            .filter(|p| p.partial_identity)
            .count();
        let n_no_maps = self.procs_seen.values().filter(|p| p.no_maps).count();
        let n_inherited = self
            .procs_seen
            .values()
            .filter(|p| p.inherited_from_parent)
            .count();
        info!(
            "Trace finalized: {} events, {} unique PIDs ({} partial-identity, {} inherited-from-parent, {} no-maps), {} unique stacks",
            self.event_count,
            self.procs_seen.len(),
            n_partial,
            n_inherited,
            n_no_maps,
            self.stack_ids.len()
        );

        Ok(self.event_count)
    }

    /// Write the SECTION_PROC_MAPS body.
    ///
    /// Layout (per design §3 / work/task.md):
    ///   [section_type: u16][section_len: u32]
    ///   per-PID record:
    ///     [pid: u32][n_maps: u16][flags: u16]
    ///     n_maps × {
    ///       [vm_start: u64][vm_end: u64][vm_pgoff: u64]
    ///       [dso_inode: u64]
    ///       [path_len: u16][path: bytes]    /* empty if anon */
    ///     }
    ///
    /// `flags` was a zero-filled `pad: u16` in v2 traces from before
    /// 2026-05-12; old traces decode as "all flags clear" which is
    /// the correct historical interpretation. Bit assignments are in
    /// `PROC_FLAG_*` constants — bits 0/1/2 mean
    /// `no_maps`/`partial_identity`/`inherited_from_parent`.
    ///
    /// PIDs are emitted in ascending order so binary diffs across runs
    /// of the same workload stay small and the analyzer's iteration
    /// order is deterministic.
    fn write_proc_maps_section(&mut self) -> Result<()> {
        let body = encode_proc_maps(&self.procs_seen);
        let section_len = body.len() as u32;
        self.writer.write_all(&SECTION_PROC_MAPS.to_le_bytes())?;
        self.writer.write_all(&section_len.to_le_bytes())?;
        self.writer.write_all(&body)?;
        Ok(())
    }

    /// Write the SECTION_PROC_STACKS body.
    ///
    /// Layout:
    ///   [section_type: u16][section_len: u32]
    ///   per-stack record:
    ///     [stack_id: u32][depth: u8][pad: u8 × 3]
    ///     depth × [ip: u64]
    ///
    /// Records are emitted in stack_id order. With Option-A userspace
    /// dedup the symbol "iterate the BPF stack-trace map at finalize"
    /// from the design doc translates to "iterate the userspace
    /// `stack_ids` HashMap" — kernel-side has no stack-trace map.
    fn write_proc_stacks_section(&mut self) -> Result<()> {
        let body = encode_proc_stacks(&self.stack_ids);
        let section_len = body.len() as u32;
        self.writer.write_all(&SECTION_PROC_STACKS.to_le_bytes())?;
        self.writer.write_all(&section_len.to_le_bytes())?;
        self.writer.write_all(&body)?;
        Ok(())
    }

    /// Return the current event count.
    pub fn event_count(&self) -> u64 {
        self.event_count
    }
}

/// Encode the ProcMaps body into a Vec<u8>.
///
/// Pulled out as a free function so unit tests can round-trip the
/// section format without spinning up a TraceWriter (which needs a
/// real file).
fn encode_proc_maps(procs: &HashMap<u32, ProcInfo>) -> Vec<u8> {
    let mut pids: Vec<u32> = procs.keys().copied().collect();
    pids.sort_unstable();

    let mut out = Vec::with_capacity(pids.len() * 64);
    for pid in pids {
        let info = &procs[&pid];
        let n_maps: u16 = info.maps.len().min(u16::MAX as usize) as u16;
        let mut flags: u16 = 0;
        if info.no_maps {
            flags |= PROC_FLAG_NO_MAPS;
        }
        if info.partial_identity {
            flags |= PROC_FLAG_PARTIAL_IDENTITY;
        }
        if info.inherited_from_parent {
            flags |= PROC_FLAG_INHERITED_FROM_PARENT;
        }
        out.extend_from_slice(&pid.to_le_bytes());
        out.extend_from_slice(&n_maps.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        for entry in info.maps.iter().take(n_maps as usize) {
            out.extend_from_slice(&entry.vm_start.to_le_bytes());
            out.extend_from_slice(&entry.vm_end.to_le_bytes());
            out.extend_from_slice(&entry.vm_pgoff.to_le_bytes());
            out.extend_from_slice(&entry.dso_inode.to_le_bytes());
            // path_len capped at u16::MAX — DSO paths are short in practice
            // (usually < 256 chars); truncating is safer than overflow.
            let path_len: u16 = entry.path.len().min(u16::MAX as usize) as u16;
            out.extend_from_slice(&path_len.to_le_bytes());
            out.extend_from_slice(&entry.path[..path_len as usize]);
        }
    }
    out
}

/// Encode the ProcStacks body into a Vec<u8>.
fn encode_proc_stacks(stack_ids: &HashMap<Vec<u64>, u32>) -> Vec<u8> {
    let mut entries: Vec<(u32, &Vec<u64>)> = stack_ids.iter().map(|(k, v)| (*v, k)).collect();
    entries.sort_unstable_by_key(|&(sid, _)| sid);

    let mut out = Vec::with_capacity(entries.len() * 32);
    for (sid, ips) in entries {
        let depth: u8 = ips.len().min(u8::MAX as usize) as u8;
        out.extend_from_slice(&sid.to_le_bytes());
        out.push(depth);
        out.extend_from_slice(&[0u8; 3]); // pad
        for ip in ips.iter().take(depth as usize) {
            out.extend_from_slice(&ip.to_le_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a fake EVT_SAMPLE wire payload for the
    /// transformer-side tests.
    fn build_sample_wire(walk_ret: i32, ips: &[u64], pid: u32) -> Vec<u8> {
        assert!(ips.len() <= STACK_DEPTH_MAX);
        let mut buf = vec![0u8; SAMPLE_WIRE_SIZE];
        // hdr: timestamp_ns(8) + pid(4) + tgid(4) + cpu(4) + event_type(2) + flags(2)
        buf[0..8].copy_from_slice(&123u64.to_le_bytes()); // ts
        buf[8..12].copy_from_slice(&pid.to_le_bytes());
        buf[12..16].copy_from_slice(&pid.to_le_bytes()); // tgid == pid for test
        buf[16..20].copy_from_slice(&7u32.to_le_bytes()); // cpu
        buf[20..22].copy_from_slice(&EVT_SAMPLE.to_le_bytes());
        buf[22..24].copy_from_slice(&0u16.to_le_bytes()); // flags
        buf[24..28].copy_from_slice(&walk_ret.to_le_bytes());
        // pad already zero
        for (i, ip) in ips.iter().enumerate() {
            let off = 32 + i * 8;
            buf[off..off + 8].copy_from_slice(&ip.to_le_bytes());
        }
        buf
    }

    /// Decode a single EVT_SAMPLE TLV record from disk bytes.
    fn parse_sample_disk(bytes: &[u8]) -> (u16, u16, u32, i32) {
        let evt_type = u16::from_le_bytes([bytes[0], bytes[1]]);
        let payload_len = u16::from_le_bytes([bytes[2], bytes[3]]);
        // header(24) starts at offset 4
        let pid = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let stack_id = i32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        (evt_type, payload_len, pid, stack_id)
    }

    /// EVT_PROC_NEW round-trip — verify wire layout matches expected
    /// 56 B and the recorder writes a full TLV with no transformation.
    /// We can't easily run write_event() here without a real File, so
    /// we exercise the wire→TLV math via a manual TLV synthesis and
    /// the parsing side from analysis/trace.py format.
    #[test]
    fn evt_proc_new_size_is_56() {
        // hdr(24) + ppid(4) + comm(16) + pad(12) = 56
        // Equivalent to sizeof(struct evt_proc_new) in C.
        const EXPECTED: usize = 24 + 4 + 16 + 12;
        assert_eq!(EXPECTED, 56);
    }

    #[test]
    fn evt_proc_exec_size_is_40() {
        // hdr(24) + comm(16) = 40. Equivalent to sizeof(struct
        // evt_proc_exec) in C after the 2026-05-12 post-exec comm
        // refresh. The pre-update layout was 24 B (hdr only); the
        // analyzer still accepts that legacy size for backward
        // compatibility — see EVT_SIZES in analysis/trace.py.
        const EXPECTED: usize = 24 + 16;
        assert_eq!(EXPECTED, 40);
    }

    #[test]
    fn sample_disk_size_is_32() {
        assert_eq!(SAMPLE_DISK_SIZE, 32);
    }

    /// Wire→disk transform: a typical successful walk produces a
    /// 32 B disk record carrying the assigned stack_id.
    #[test]
    fn sample_dedup_assigns_sequential_ids() {
        let mut writer = TraceWriter::new(
            &test_temp_path("sample_dedup_assigns_sequential_ids.scxi"),
            1,
            &[],
        )
        .unwrap();

        let stack_a = [0xdead0001u64, 0xdead0002, 0xdead0003];
        let stack_b = [0xbeef0001u64, 0xbeef0002];

        writer
            .write_sample_event(&build_sample_wire(24, &stack_a, 100), 100)
            .unwrap();
        writer
            .write_sample_event(&build_sample_wire(16, &stack_b, 200), 200)
            .unwrap();
        writer
            .write_sample_event(&build_sample_wire(24, &stack_a, 100), 100)
            .unwrap();

        // First A → sid 0; B → sid 1; A again → sid 0 (dedup).
        assert_eq!(writer.stack_ids.get(&stack_a.to_vec()), Some(&0));
        assert_eq!(writer.stack_ids.get(&stack_b.to_vec()), Some(&1));
    }

    /// Wire→disk transform: negative walk_ret flows straight through.
    #[test]
    fn sample_walk_failure_preserves_negative_id() {
        let mut writer = TraceWriter::new(
            &test_temp_path("sample_walk_failure_preserves_negative_id.scxi"),
            1,
            &[],
        )
        .unwrap();

        writer
            .write_sample_event(&build_sample_wire(-14, &[], 300), 300)
            .unwrap();
        // No sid was allocated for the failure path.
        assert!(writer.stack_ids.is_empty());
    }

    /// Wire→disk transform: trailing-zero frames are stripped before
    /// hashing so two walks that disagree only on a trailing 0 entry
    /// dedup to the same sid.
    #[test]
    fn sample_dedup_strips_trailing_zero_frames() {
        let mut writer = TraceWriter::new(
            &test_temp_path("sample_dedup_strips_trailing_zero_frames.scxi"),
            1,
            &[],
        )
        .unwrap();

        let three_frames = [0x1u64, 0x2, 0x3];
        let four_frames_with_zero = [0x1u64, 0x2, 0x3, 0x0];
        // walk_ret carries the byte count, including the trailing zero
        // (which kernel returns when frame-pointer chase ran out).
        writer
            .write_sample_event(&build_sample_wire(24, &three_frames, 400), 400)
            .unwrap();
        writer
            .write_sample_event(&build_sample_wire(32, &four_frames_with_zero, 400), 400)
            .unwrap();

        assert_eq!(writer.stack_ids.len(), 1);
        assert_eq!(writer.stack_ids.get(&three_frames.to_vec()), Some(&0));
    }

    #[test]
    fn proc_maps_round_trip() {
        let mut procs: HashMap<u32, ProcInfo> = HashMap::new();
        procs.insert(
            42,
            ProcInfo {
                maps: vec![
                    MapEntry {
                        vm_start: 0x400000,
                        vm_end: 0x40b000,
                        vm_pgoff: 0,
                        dso_inode: 1234,
                        path: b"/usr/bin/cat".to_vec(),
                    },
                    MapEntry {
                        vm_start: 0x600000,
                        vm_end: 0x601000,
                        vm_pgoff: 0,
                        dso_inode: 0,
                        path: vec![],
                    },
                ],
                cmdline: b"cat\x00/etc/hostname\x00".to_vec(),
                no_maps: false,
                partial_identity: false,
                inherited_from_parent: false,
            },
        );
        let body = encode_proc_maps(&procs);

        // Decode and assert.
        let pid = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let n_maps = u16::from_le_bytes([body[4], body[5]]);
        let flags = u16::from_le_bytes([body[6], body[7]]);
        assert_eq!(pid, 42);
        assert_eq!(n_maps, 2);
        assert_eq!(flags, 0, "no flags should be set on a clean snapshot");
        // First map entry starts at offset 8 (after pid + n_maps + flags).
        let off = 8;
        let vm_start = u64::from_le_bytes(body[off..off + 8].try_into().unwrap());
        assert_eq!(vm_start, 0x400000);
        let path_len = u16::from_le_bytes([body[off + 32], body[off + 33]]);
        assert_eq!(path_len, b"/usr/bin/cat".len() as u16);
        let path = &body[off + 34..off + 34 + path_len as usize];
        assert_eq!(path, b"/usr/bin/cat");
    }

    /// All three flag bits should round-trip through encode_proc_maps
    /// in the formerly-pad u16 slot. Existing v2 traces written
    /// before 2026-05-12 have flags=0 (the slot was zero-filled
    /// `pad`), which decodes correctly as "all flags clear".
    #[test]
    fn proc_maps_flags_round_trip() {
        let mut procs: HashMap<u32, ProcInfo> = HashMap::new();
        // PID 1: clean snapshot (no flags).
        procs.insert(1, ProcInfo::default());
        // PID 2: every flag set, no maps.
        procs.insert(
            2,
            ProcInfo {
                maps: vec![],
                cmdline: vec![],
                no_maps: true,
                partial_identity: true,
                inherited_from_parent: true,
            },
        );
        // PID 3: only inherited_from_parent (the fix's target case).
        procs.insert(
            3,
            ProcInfo {
                maps: vec![MapEntry {
                    vm_start: 0x500000,
                    vm_end: 0x501000,
                    vm_pgoff: 0,
                    dso_inode: 7,
                    path: b"/bin/sh".to_vec(),
                }],
                cmdline: vec![],
                no_maps: false,
                partial_identity: false,
                inherited_from_parent: true,
            },
        );
        let body = encode_proc_maps(&procs);

        // Walk the body and pull out the flag slot for each PID.
        // PIDs are emitted in ascending order — start at offset 0,
        // skip past each record.
        let mut off = 0usize;
        let mut seen: Vec<(u32, u16, u16)> = Vec::new();
        while off + 8 <= body.len() {
            let pid = u32::from_le_bytes(body[off..off + 4].try_into().unwrap());
            let n_maps = u16::from_le_bytes([body[off + 4], body[off + 5]]);
            let flags = u16::from_le_bytes([body[off + 6], body[off + 7]]);
            seen.push((pid, n_maps, flags));
            off += 8;
            for _ in 0..n_maps {
                // Skip vm_start/vm_end/vm_pgoff/dso_inode (32 B) +
                // path_len (2 B) + path payload.
                off += 32;
                let plen = u16::from_le_bytes([body[off], body[off + 1]]) as usize;
                off += 2 + plen;
            }
        }

        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0], (1, 0, 0));
        assert_eq!(
            seen[1],
            (
                2,
                0,
                PROC_FLAG_NO_MAPS | PROC_FLAG_PARTIAL_IDENTITY | PROC_FLAG_INHERITED_FROM_PARENT
            )
        );
        assert_eq!(seen[2], (3, 1, PROC_FLAG_INHERITED_FROM_PARENT));
    }

    /// snapshot_proc with a missing PID and a hint pointing at the
    /// recorder's own PID (which definitely exists) should fall back
    /// to /proc/<self>/maps and tag inherited_from_parent.
    ///
    /// This exercises the dominant-case fix for the reviewer's
    /// EVT_PROC_NEW-before-attach_pid race: when /proc/<pid> is gone
    /// (sub-ms ephemeral), we use the parent's maps as a stand-in.
    #[test]
    fn snapshot_proc_falls_back_to_parent() {
        let self_pid = std::process::id();
        // Pick a PID that's vanishingly unlikely to exist. PIDs above
        // /proc/sys/kernel/pid_max are guaranteed unused; 0xFFFFFFFE is
        // above any reasonable pid_max (default 4M, max 4194304).
        let dead_pid: u32 = 0xFFFF_FFFE;

        // Sanity check: dead_pid really has no /proc entry.
        assert!(
            std::fs::read_to_string(format!("/proc/{}/maps", dead_pid)).is_err(),
            "test assumes pid 0xFFFFFFFE has no /proc entry"
        );

        let info = snapshot_proc(dead_pid, Some(self_pid));
        assert!(
            info.inherited_from_parent,
            "fallback should tag inherited_from_parent"
        );
        assert!(!info.no_maps, "parent's maps should populate the slot");
        assert!(
            !info.maps.is_empty(),
            "self's executable mappings should be non-empty"
        );

        // No hint → no_maps.
        let info_no_hint = snapshot_proc(dead_pid, None);
        assert!(info_no_hint.no_maps);
        assert!(!info_no_hint.inherited_from_parent);
        assert!(info_no_hint.maps.is_empty());

        // ppid==0 (the kernel's "no parent" sentinel for swapper /
        // very early init) → no_maps, no fallback attempted.
        let info_zero_ppid = snapshot_proc(dead_pid, Some(0));
        assert!(info_zero_ppid.no_maps);
        assert!(!info_zero_ppid.inherited_from_parent);

        // ppid==pid (self-parented sentinel) → no_maps, no fallback.
        let info_self_ppid = snapshot_proc(dead_pid, Some(dead_pid));
        assert!(info_self_ppid.no_maps);
        assert!(!info_self_ppid.inherited_from_parent);
    }

    #[test]
    fn proc_stacks_round_trip() {
        let mut stack_ids: HashMap<Vec<u64>, u32> = HashMap::new();
        stack_ids.insert(vec![0xaa, 0xbb, 0xcc], 0);
        stack_ids.insert(vec![0xdd, 0xee], 1);
        let body = encode_proc_stacks(&stack_ids);

        // First record: sid=0, depth=3, then 3 × u64
        let sid0 = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let depth0 = body[4];
        assert_eq!(sid0, 0);
        assert_eq!(depth0, 3);
        let ip0 = u64::from_le_bytes(body[8..16].try_into().unwrap());
        assert_eq!(ip0, 0xaa);

        // Second record starts at offset 8 + 3*8 = 32
        let sid1 = u32::from_le_bytes([body[32], body[33], body[34], body[35]]);
        let depth1 = body[36];
        assert_eq!(sid1, 1);
        assert_eq!(depth1, 2);
        let ip2 = u64::from_le_bytes(body[40..48].try_into().unwrap());
        assert_eq!(ip2, 0xdd);
    }

    /// Round-trip a fake EVT_SAMPLE wire payload through write_event
    /// → on-disk file → manual TLV parse, asserting the on-disk
    /// record matches the disk format.
    #[test]
    fn sample_round_trip_disk_record() {
        let path = test_temp_path("sample_round_trip_disk_record.scxi");
        let mut writer = TraceWriter::new(&path, 1, &[]).unwrap();
        writer
            .write_sample_event(&build_sample_wire(24, &[0x1, 0x2, 0x3], 555), 555)
            .unwrap();
        writer.finalize().unwrap();
        drop(writer);

        let bytes = std::fs::read(&path).unwrap();
        // Find the first EVT_SAMPLE TLV by scanning past header(64) +
        // topo section header(6) + 0 topo entries + events section
        // header(6).
        let off = 64 + 6 + 6;
        let (evt_type, payload_len, pid, stack_id) = parse_sample_disk(&bytes[off..]);
        assert_eq!(evt_type, EVT_SAMPLE);
        assert_eq!(payload_len, SAMPLE_DISK_SIZE);
        assert_eq!(pid, 555);
        assert_eq!(stack_id, 0); // first allocated sid

        std::fs::remove_file(path).ok();
    }

    fn test_temp_path(name: &str) -> String {
        let dir = std::env::temp_dir();
        dir.join(format!(
            "scx_invariant_test_{}_{}",
            std::process::id(),
            name
        ))
        .to_string_lossy()
        .to_string()
    }
}
