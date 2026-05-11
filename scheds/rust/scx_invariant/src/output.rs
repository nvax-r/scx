use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};

use anyhow::{Context, Result};
use log::info;

const MAGIC: &[u8; 4] = b"SCXI";
/// SCXI on-disk format version. v2 moved event IDs out of the
/// section-ID numeric space (events now live at 0x0100+, sections
/// stay at 0x0001..0x0003) — see PLAN.md §5/§11. v1 is intentionally
/// unsupported by the in-tree reader.
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
const SECTION_PROCS: u16 = 0x0002;
const SECTION_EVENTS: u16 = 0x0003;

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

/// Read /proc/<pid>/comm into a fixed 16-byte slot, NUL-padded.
///
/// Returns an all-zero array when the read fails (process already gone,
/// permission denied, etc). The 15-byte cap leaves room for a trailing
/// NUL inside the 16-byte on-disk slot, which matches the reader's
/// convention of treating the first NUL as the comm terminator.
fn read_proc_comm(pid: u32) -> [u8; 16] {
    let mut comm = [0u8; 16];
    let path = format!("/proc/{}/comm", pid);
    if let Ok(name) = std::fs::read_to_string(&path) {
        let name = name.trim();
        let len = name.len().min(15);
        comm[..len].copy_from_slice(&name.as_bytes()[..len]);
    }
    comm
}

/// Fast binary trace writer.
///
/// Hot path: `write_event` receives raw `&[u8]` from the ring buffer and
/// writes a 4-byte TLV prefix + raw payload.  No struct parsing.
///
/// `procs_seen` doubles as the unique-PID set and the per-PID `comm`
/// snapshot. Comm is captured the first time a PID is observed in
/// `write_event` rather than at `finalize`, because /proc/<pid>/comm
/// disappears as soon as the process exits — and short-lived workloads
/// (build steps, shell pipelines) routinely outlive the trace writer's
/// poll loop. First-sight capture turns "all-empty comms for short-lived
/// PIDs" (the prior behavior) into "comms recorded for every PID we
/// actually saw an event from while it was alive".
pub struct TraceWriter {
    writer: BufWriter<File>,
    event_count: u64,
    procs_seen: HashMap<u32, [u8; 16]>,
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

        writer.write_all(MAGIC)?;                           // 0..4
        writer.write_all(&VERSION.to_le_bytes())?;           // 4..6
        writer.write_all(&64u16.to_le_bytes())?;             // 6..8  header_size
        writer.write_all(&0u32.to_le_bytes())?;              // 8..12 flags
        writer.write_all(&now_ns.to_le_bytes())?;            // 12..20 timestamp_start
        writer.write_all(&0u64.to_le_bytes())?;              // 20..28 timestamp_end (filled at finalize)
        writer.write_all(&hostname)?;                        // 28..56
        writer.write_all(&kernel_ver.to_le_bytes())?;        // 56..60
        writer.write_all(&ARCH_AARCH64.to_le_bytes())?;      // 60..62
        writer.write_all(&nr_cpus.to_le_bytes())?;           // 62..64

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
        })
    }

    /// Write a single event from the ring buffer.
    ///
    /// Format: [event_type: u16][payload_len: u16][raw bytes]
    ///
    /// `data` is the raw ring buffer payload (e.g. 88 bytes for evt_running).
    /// We read event_type from offset 20 (scx_invariant_event.event_type)
    /// and pid from offset 8.
    #[inline]
    pub fn write_event(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < 24 {
            return Ok(()); // too short to be a valid event
        }

        // Read event_type from offset 20 (u16 LE)
        let event_type = u16::from_le_bytes([data[20], data[21]]);
        let payload_len = data.len() as u16;

        // Read pid from offset 8 (u32 LE)
        let pid = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        // First-sight comm capture. Entry API does a single hash lookup
        // — same hot-path cost as the prior HashSet::insert. On a repeat
        // PID we land in `Occupied` and skip the /proc read entirely.
        if let Entry::Vacant(slot) = self.procs_seen.entry(pid) {
            slot.insert(read_proc_comm(pid));
        }

        // Write TLV prefix
        self.writer.write_all(&event_type.to_le_bytes())?;
        self.writer.write_all(&payload_len.to_le_bytes())?;
        // Write raw payload
        self.writer.write_all(data)?;

        self.event_count += 1;
        Ok(())
    }

    /// Finalize the trace: write process table, update timestamp_end.
    ///
    /// The process table is materialized from the first-sight comm
    /// snapshots already in `procs_seen` — no /proc reads happen here.
    /// PIDs whose first-sight read failed (process already a zombie or
    /// the read raced with /proc/<pid> teardown) get a re-read attempt
    /// from /proc as a best-effort recovery; if that also fails the
    /// entry stays in the table with an empty comm so the section size
    /// math (20 B per entry) is unchanged from prior traces.
    pub fn finalize(&mut self) -> Result<u64> {
        // Flush any buffered event data first
        self.writer.flush()?;

        // --- Process table section ---
        // Pull the first-sight snapshots into a stable order (sorted by
        // pid) so binary diffs across runs of the same workload stay
        // small and reader output is deterministic.
        let mut proc_entries: Vec<(u32, [u8; 16])> =
            self.procs_seen.iter().map(|(&pid, &comm)| (pid, comm)).collect();
        proc_entries.sort_by_key(|(pid, _)| *pid);

        // Best-effort recovery for PIDs whose first-sight read failed.
        // Almost always still empty — by definition the process was
        // unreadable when alive — but cheap to retry.
        for (pid, comm) in proc_entries.iter_mut() {
            if comm[0] == 0 {
                *comm = read_proc_comm(*pid);
            }
        }

        // Section header: type(u16) + len(u32)
        // Each entry: pid(u32) + comm(16 bytes) = 20 bytes
        let procs_len = proc_entries.len() as u32 * 20;
        self.writer.write_all(&SECTION_PROCS.to_le_bytes())?;
        self.writer.write_all(&procs_len.to_le_bytes())?;
        for (pid, comm) in &proc_entries {
            self.writer.write_all(&pid.to_le_bytes())?;
            self.writer.write_all(comm)?;
        }
        self.writer.flush()?;

        // --- Update timestamp_end at offset 20 ---
        let now_ns = monotonic_now_ns();
        self.writer.seek(SeekFrom::Start(20))?;
        self.writer.write_all(&now_ns.to_le_bytes())?;
        self.writer.flush()?;

        info!(
            "Trace finalized: {} events, {} unique PIDs, {} procs resolved",
            self.event_count,
            self.procs_seen.len(),
            proc_entries.iter().filter(|(_, c)| c[0] != 0).count()
        );

        Ok(self.event_count)
    }

    /// Return the current event count.
    pub fn event_count(&self) -> u64 {
        self.event_count
    }
}
