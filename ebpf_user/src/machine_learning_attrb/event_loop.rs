use crate::features::features::Features;
use crate::features::pattren::{SimpleEvent, update_pattern};
use crate::utils::ring_buffer::SharedRingBuffer;
use std::collections::HashMap;

pub fn process_events(
    buffer: SharedRingBuffer<crate::manage::ebpf_helper::Event>,
    processes: &mut HashMap<u32, Features>,
) {
    while let Some(event) = buffer.lock().unwrap().pop() {
        if let Some(simple) = SimpleEvent::normalize(event.event_type as u32) {
            let feat = processes.entry(event.pid).or_default();

            feat.pattern_window.push(simple);
            if feat.pattern_window.len() == 3 {
                update_pattern(&mut feat.pattern, &feat.pattern_window);
                feat.pattern_window.clear();
            }
        }
    }
}
