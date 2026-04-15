mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
mod recorder;

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use libbpf_rs::OpenObject;
use log::info;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

const SCHEDULER_NAME: &str = "scx_invariant";

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

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let event_count = recorder::run_consumer(&self.skel, shutdown)?;
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

fn main() -> Result<()> {
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

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut open_object = MaybeUninit::uninit();
    let mut sched = Scheduler::init(&mut open_object)?;
    let exit_info = sched.run(shutdown)?;

    if exit_info.should_restart() {
        info!("Scheduler requested restart");
    }

    Ok(())
}
