use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::RingBufferBuilder;
use log::info;

use crate::output::{CpuTopo, TraceWriter};
use crate::BpfSkel;

/// Global writer accessed by the ring buffer callback.
///
/// The ring buffer callback is a plain function pointer (not a closure),
/// so we need a global to pass state.  The Mutex is uncontended: only one
/// thread calls handle_event (the poll thread).
static WRITER: Mutex<Option<TraceWriter>> = Mutex::new(None);
static EVENT_COUNT: AtomicU64 = AtomicU64::new(0);

fn handle_event(data: &[u8]) -> i32 {
    EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut guard) = WRITER.lock() {
        if let Some(ref mut w) = *guard {
            let _ = w.write_event(data);
        }
    }
    0
}

pub fn run_consumer(
    skel: &BpfSkel,
    shutdown: Arc<AtomicBool>,
    output_path: Option<&str>,
    topology: &[CpuTopo],
    nr_cpus: u16,
) -> Result<u64> {
    // Reset event count
    EVENT_COUNT.store(0, Ordering::Relaxed);

    // Set up the writer if an output path was given
    if let Some(path) = output_path {
        let writer = TraceWriter::new(path, nr_cpus, topology)
            .with_context(|| format!("Failed to create trace writer for {}", path))?;
        *WRITER.lock().unwrap() = Some(writer);
    }

    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.events_rb_0, handle_event)?;
    builder.add(&skel.maps.events_rb_1, handle_event)?;
    builder.add(&skel.maps.events_rb_2, handle_event)?;
    builder.add(&skel.maps.events_rb_3, handle_event)?;
    builder.add(&skel.maps.events_rb_4, handle_event)?;
    builder.add(&skel.maps.events_rb_5, handle_event)?;
    let rb = builder.build()?;

    info!("Ring buffer consumer started (6 partitions)");

    // The BPF side submits with BPF_RB_NO_WAKEUP to avoid per-event IPIs at
    // 1M+ events/sec. ring_buffer__poll() is wakeup-driven (epoll-based) and
    // would never see those records, so we must pull-drain via
    // ring_buffer__consume() on a fixed cadence instead.
    while !shutdown.load(Ordering::Relaxed) {
        let _ = rb.consume();
        std::thread::sleep(Duration::from_millis(1));
    }

    // Final drain after shutdown signal
    let _ = rb.consume();

    let total = EVENT_COUNT.load(Ordering::Relaxed);

    // Finalize writer if active
    {
        let mut guard = WRITER.lock().unwrap();
        if let Some(ref mut w) = *guard {
            if let Err(e) = w.finalize() {
                log::error!("Failed to finalize trace: {}", e);
            }
        }
    }

    // Clear the global so it does not hold the file open
    *WRITER.lock().unwrap() = None;

    info!("Total events recorded: {}", total);
    Ok(total)
}
