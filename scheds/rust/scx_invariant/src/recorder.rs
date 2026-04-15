use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use log::info;

use crate::BpfSkel;

static EVENT_COUNT: AtomicU64 = AtomicU64::new(0);

fn handle_event(_data: &[u8]) -> i32 {
    EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    0
}

pub fn run_consumer(skel: &BpfSkel, shutdown: Arc<AtomicBool>) -> Result<u64> {
    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.events_rb_0, handle_event)?;
    builder.add(&skel.maps.events_rb_1, handle_event)?;
    builder.add(&skel.maps.events_rb_2, handle_event)?;
    builder.add(&skel.maps.events_rb_3, handle_event)?;
    builder.add(&skel.maps.events_rb_4, handle_event)?;
    builder.add(&skel.maps.events_rb_5, handle_event)?;
    let rb = builder.build()?;

    info!("Ring buffer consumer started (6 partitions)");

    while !shutdown.load(Ordering::Relaxed) {
        let _ = rb.poll(Duration::from_millis(1));
    }

    // Final drain
    let _ = rb.poll(Duration::from_millis(0));

    let total = EVENT_COUNT.load(Ordering::Relaxed);
    info!("Total events received: {}", total);
    Ok(total)
}
