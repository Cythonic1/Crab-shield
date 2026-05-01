use crate::{
    features::pattren::{PatternCounts, SimpleEvent},
    manage::ebpf_helper::ProcessIoStats,
};

#[derive(Default)]
#[allow(dead_code)]
pub struct Features {
    pub delete_syscalls: u64,
    pub open_syscalls: u64,
    pub close_syscalls: u64,

    pub pattern: PatternCounts,
    pub pattern_window: Vec<SimpleEvent>,

    pub entropy: f32,
}

#[allow(dead_code)]
impl Features {
    pub fn new() -> Self {
        Features {
            ..Default::default()
        }
    }

    pub fn from_io_stats(p: &ProcessIoStats) -> Self {
        Self {
            open_syscalls: p.open_syscalls,
            close_syscalls: p.close_syscalls,
            delete_syscalls: p.delete_syscall,
            pattern_window: Vec::with_capacity(3),
            pattern: Default::default(),
            entropy: 0.0,
        }
    }

    pub fn to_vec_to_ml(&self) -> Vec<f32> {
        vec![
            self.close_syscalls as f32,
            self.open_syscalls as f32,
            self.delete_syscalls as f32,
            (self.entropy / 10.0),
        ]
    }
}
