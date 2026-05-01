use crate::manage::ebpf_helper::Event;
use crate::utils::ring_buffer::RingBuffer;
use aya::maps::{MapData, RingBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

pub async fn start_ebpf_reader(
    terminate: &Arc<AtomicBool>,
    events_map: Arc<Mutex<Option<RingBuf<MapData>>>>,
    out_buf: Arc<Mutex<RingBuffer<Event>>>, // <- change here
) {
    while terminate.load(Ordering::Acquire) {
        let event = {
            let mut guard = events_map.lock().unwrap();

            let ring: &mut RingBuf<MapData> = match guard.as_mut() {
                Some(r) => r,
                None => continue,
            };
            let record = match ring.next() {
                Some(rec) => rec,
                None => continue,
            };

            unsafe { (record.as_ptr() as *const Event).read_unaligned() }
        };

        out_buf.lock().unwrap().push(event);
    }
}
