mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
mod output;
mod recorder;

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::OpenObject;
use log::info;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;

use crate::output::CpuTopo;

const SCHEDULER_NAME: &str = "scx_invariant";

#[derive(Parser, Debug)]
#[clap(name = "scx_invariant", about = "Record scheduler-invariant workload identity")]
struct Args {
    /// Output trace file path.  If omitted, events are counted but not written.
    #[clap(short, long)]
    output: Option<String>,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        info!("{} starting", SCHEDULER_NAME);

        let skel_builder = BpfSkelBuilder::default();
        let mut skel = scx_ops_open!(skel_builder, open_object, invariant_ops, None::<libbpf_rs::libbpf_sys::bpf_object_open_opts>)?;
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

    let (topology, nr_cpus) = build_topology()?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut open_object = MaybeUninit::uninit();
    let mut sched = Scheduler::init(&mut open_object)?;
    let exit_info = sched.run(
        shutdown,
        args.output.as_deref(),
        &topology,
        nr_cpus,
    )?;

    if exit_info.should_restart() {
        info!("Scheduler requested restart");
    }

    Ok(())
}
