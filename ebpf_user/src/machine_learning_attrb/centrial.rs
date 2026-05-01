use anyhow::Result;
use log::{info, warn};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, atomic::AtomicBool, atomic::Ordering},
    time::Duration,
};

use crate::{
    alert::handler_alert::AlertManager,
    entropy::entropy::Entropy,
    features::features::Features,
    machine_learning_attrb::event_loop::process_events,
    machine_learning_module::machine_learning_module::ModuleFeatures,
    manage::ebpf_helper::{EbpfHelper, EbpfHelperError, Event},
    utils::ring_buffer::SharedRingBuffer,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimpleEvent {
    O, // open / openat
    C, // close
    D, // delete (future: unlink / rename)
}

#[allow(dead_code)]
impl SimpleEvent {
    fn normalize_event(event_type: u32) -> Option<SimpleEvent> {
        match event_type {
            1 => Some(SimpleEvent::O), // EVENT_OPEN
            3 => Some(SimpleEvent::C), // EVENT_CLOSE
            5 => Some(SimpleEvent::D), // EVENT_DELETE
            _ => None,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum AggregatorErrors {
    ErrorStarting(String),
    EbpfHelper(EbpfHelperError),
}
impl std::error::Error for AggregatorErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AggregatorErrors::EbpfHelper(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for AggregatorErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AggregatorErrors::ErrorStarting(msg) => {
                write!(f, "Aggregator failed to start: {}", msg)
            }
            AggregatorErrors::EbpfHelper(e) => {
                write!(f, "eBPF helper error: {:?}", e)
            }
        }
    }
}
impl From<EbpfHelperError> for AggregatorErrors {
    fn from(err: EbpfHelperError) -> Self {
        AggregatorErrors::EbpfHelper(err)
    }
}

#[allow(dead_code)]
pub struct Aggregator {
    pub ebpf_helper: EbpfHelper,
    pub processes: HashMap<u32, Features>,
    pub entropy_calculator: Entropy,
    pub module: ModuleFeatures,
}

#[allow(dead_code)]
impl Aggregator {
    pub fn new(
        machine_learning_module_path: String,
        data_scal_path: String,
        alert_manager: AlertManager,
        protected_paths: [&str; 5],
    ) -> Self {
        Aggregator {
            ebpf_helper: EbpfHelper::new(5, Some(&protected_paths)),
            processes: HashMap::new(),
            entropy_calculator: Entropy::new(),
            module: ModuleFeatures::new(
                machine_learning_module_path,
                data_scal_path,
                alert_manager,
            ),
        }
    }

    fn print_features(&self) {
        for (pid, val) in self.processes.iter() {
            println!("pid: {}, {}", pid, val.pattern);
        }

        println!(
            "====================Len of the hash map is {}===========================",
            self.processes.len()
        );
    }

    pub async fn init_ebpf(&mut self) -> Result<(), AggregatorErrors> {
        let obj_file = "/home/misabear/Desktop/FYP/project/learn_bpf/extract_sysCalls_to_map/src_ebpf/main.bpf.o";

        self.ebpf_helper.load_object_file(obj_file).await?;
        self.ebpf_helper.load_config_map("ConfigMap").await?;
        self.ebpf_helper.load_event_map("EventsMap").await?;
        self.ebpf_helper.load_proc_map("ProcMap").await?;
        self.ebpf_helper.load_buffers_map("BuffersMap").await?;
        self.ebpf_helper.send_config().await?;
        self.ebpf_helper.load_modules_and_attach().await?;

        Ok(())
    }

    async fn calculate_entropy_for_processes(&mut self) {
        info!("Calculating entropy...");
        let vec_proc_buf = match self.ebpf_helper.get_all_buffers().await {
            Ok(bufs) => bufs,
            Err(e) => {
                warn!("Failed to get eBPF buffers: {:?}", e);
                return;
            }
        };

        for (pid, buf) in vec_proc_buf {
            let entropy = self.entropy_calculator.calculate_entropy(buf).await;
            if let Some(proc) = self.processes.get_mut(&pid) {
                proc.entropy = entropy;
                info!("Entropy found for process {} with {}", pid, entropy);

                match self.ebpf_helper.buffers_map.as_mut().unwrap().remove(&pid) {
                    Ok(_) => info!(
                        "We got the buffer and remove entry of {} from the buffer hash map",
                        pid
                    ),
                    Err(err) => warn!("Error remove entry of {} from buffers map {}", pid, err),
                }
            } else {
                warn!(
                    "PID {} exists in the entropy map but not in processes map",
                    pid
                );
            }
        }
    }

    // This function will start the Ebpf Helper.
    pub async fn run(
        &mut self,
        ring_buffer: SharedRingBuffer<Event>,
        terminator: &Arc<AtomicBool>,
        report_interval: u64,
    ) -> Result<(), AggregatorErrors> {
        info!("Starting main loop");
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        let mut reset = tokio::time::interval(Duration::from_secs(report_interval));

        while terminator.load(Ordering::Acquire) {
            tokio::select! {
                _ = tick.tick() => {
                    // 1. Consume kernel events
                    process_events(ring_buffer.clone(), &mut self.processes);
                }
                _ = reset.tick() => {

                    self.sync_proc_stats().await?;
                    self.calculate_entropy_for_processes().await;
                    self.module.module_check(&self.processes).await;
                    self.clear().await;
                }
            }
        }

        Ok(())
    }

    async fn clear(&mut self) {
        self.processes.clear();
    }

    async fn sync_proc_stats(&mut self) -> Result<(), AggregatorErrors> {
        // Ask eBPF helper to construct a snapshot
        let new = self.ebpf_helper.construct_aggregator().await?;
        let map = self.ebpf_helper.proc_map.as_mut().unwrap();

        // Merge kernel snapshot into userspace state
        for (pid, feat) in new {
            self.processes
                .entry(pid)
                .and_modify(|old| {
                    // overwrite rolling counters
                    old.open_syscalls = feat.open_syscalls;
                    old.delete_syscalls = feat.delete_syscalls;
                    old.close_syscalls = feat.close_syscalls;
                })
                .or_insert(feat);
            match map.remove(&pid) {
                Ok(_) => info!("Process with pid of {}", pid),
                Err(err) => warn!("Err of {} removing pid with {}", err, pid),
            }
        }

        Ok(())
    }
}
