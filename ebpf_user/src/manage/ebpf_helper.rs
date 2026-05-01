use crate::features::features::Features;
use anyhow::Result;
use aya::Ebpf;
use aya::Pod;
use aya::maps::Array;
use aya::maps::HashMap;
use aya::maps::MapData;
use aya::maps::MapError;
use aya::maps::RingBuf;

use log::info;
use log::warn;
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use tokio::time::Interval;
use tokio::time::interval;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[allow(nonstandard_style, dead_code)]
pub enum EventType {
    EVENT_OPEN = 1,
    EVENT_CLOSE = 3,
    EVENT_DELETE = 5,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Event {
    pub pid: u32,
    pub event_type: EventType, // 1=open/openat, 2=write, 3=close
}

unsafe impl Pod for Event {}
#[derive(Debug)]
#[allow(dead_code)]
pub enum EbpfHelperError {
    ResettingMap(String),
    MapNotFound(String),
    InsertMapError(String),
    CalculateEntropy(String),
    ConstructAggregator(String),
    NoneExistingKey(String),
}

impl std::error::Error for EbpfHelperError {}

impl std::fmt::Display for EbpfHelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EbpfHelperError::ResettingMap(msg) => {
                write!(f, "Failed to reset eBPF map: {}", msg)
            }
            EbpfHelperError::MapNotFound(msg) => {
                write!(f, "eBPF map not found: {}", msg)
            }
            EbpfHelperError::InsertMapError(msg) => {
                write!(f, "Failed to insert into eBPF map: {}", msg)
            }
            EbpfHelperError::CalculateEntropy(msg) => {
                write!(f, "Entropy calculation failed: {}", msg)
            }
            EbpfHelperError::ConstructAggregator(msg) => {
                write!(f, "Failed to construct aggregator: {}", msg)
            }
            EbpfHelperError::NoneExistingKey(msg) => {
                write!(f, "Non-existing key accessed: {}", msg)
            }
        }
    }
}
#[allow(dead_code)]
pub enum EbpfHelperMapType {
    Array,
    HashMap,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EntropyBuffer {
    pub buf: [u8; 256],
    pub is_handled: bool, // This feild define is we need to get another sample or not. if true then we finish with this
    // this sample...
    pub size_of_written_data: u64,
    pub read_to_be_handled: bool,
}

unsafe impl Pod for EntropyBuffer {}
impl Default for EntropyBuffer {
    fn default() -> Self {
        Self {
            is_handled: false,
            size_of_written_data: 0,
            read_to_be_handled: false,
            buf: [0u8; 256],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ProcessIoStats {
    pub close_syscalls: u64,
    pub open_syscalls: u64,
    pub delete_syscall: u64,
}

unsafe impl Pod for ProcessIoStats {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ConfigUser {
    pub paths: [[u8; 126]; 5], // Changed from pointers to actual byte arrays
    pub number_of_entries: u32,
}

unsafe impl Pod for ConfigUser {}

impl ConfigUser {
    pub fn new(slices: &[&str]) -> Self {
        assert!(slices.len() <= 5, "Cannot have more than 5 paths");

        let mut paths = [[0u8; 126]; 5];

        for (i, path) in slices.iter().enumerate() {
            let bytes = path.as_bytes();
            let len = bytes.len().min(255); // Leave room for null terminator
            paths[i][..len].copy_from_slice(&bytes[..len]);
            paths[i][len] = 0; // Null terminator
        }

        ConfigUser {
            paths,
            number_of_entries: slices.len() as u32,
        }
    }
}

pub struct EbpfHelper {
    interval_out: u64,
    pub reset_timer: Interval,
    prog: Option<Ebpf>,
    pub proc_map: Option<HashMap<MapData, u32, ProcessIoStats>>, // implement Clone to this
    pub buffers_map: Option<HashMap<MapData, u32, EntropyBuffer>>, // implement Clone to this
    config_map: Option<Array<MapData, ConfigUser>>,
    pub events_map: Arc<Mutex<Option<RingBuf<MapData>>>>, // when read from it, we will case it into Event.
    user_config: ConfigUser,
}

#[allow(dead_code)]
impl EbpfHelper {
    pub fn new(interval_out: u64, paths: Option<&[&str]>) -> Self {
        EbpfHelper {
            interval_out,
            reset_timer: interval(Duration::from_secs(interval_out)),
            prog: None,
            proc_map: None,
            config_map: None,
            buffers_map: None,
            events_map: Arc::new(Mutex::new(None)),
            user_config: ConfigUser::new(paths.unwrap()),
        }
    }
    pub fn get_reset_timer(&mut self) -> &mut Interval {
        &mut self.reset_timer
    }

    async fn reset_map_on_timer(mut self) -> Result<usize, EbpfHelperError> {
        let mut removed_pids = Vec::new();
        if self.proc_map.is_some() {
            return Err(EbpfHelperError::ResettingMap(
                "Invalid Map found".to_string(),
            ));
        }
        let proc_map = self.proc_map.as_mut().unwrap();

        for (pid, _) in proc_map.iter().flatten() {
            removed_pids.push(pid);
        }

        let count = removed_pids.len();

        for pid in removed_pids {
            proc_map.remove(&pid).ok();
        }
        Ok(count)
    }

    pub async fn send_config(&mut self) -> Result<(), EbpfHelperError> {
        let map = self
            .config_map
            .as_mut()
            .ok_or_else(|| EbpfHelperError::MapNotFound("Config map not found".to_string()))?;

        match map.set(0, self.user_config, 0) {
            Ok(_) => {
                info!("config has been sent");
                Ok(())
            }
            Err(MapError::SyscallError(sys))
                if sys.io_error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                info!("config already exists");
                Ok(())
            }
            Err(e) => Err(EbpfHelperError::InsertMapError(e.to_string())),
        }
    }

    /// This function will  update the Interval as well
    pub async fn set_interval(mut self, interval_out: u64) -> Self {
        self.interval_out = interval_out;
        self.reset_timer = interval(Duration::from_secs(self.interval_out));
        self
    }

    /// This function will use the Ebpf::load_file to load the object file.
    pub async fn load_object_file(
        &mut self,
        object_file_path: &str,
    ) -> Result<(), EbpfHelperError> {
        self.prog = Ebpf::load_file(object_file_path)
            .map_err(|_| EbpfHelperError::MapNotFound("Failed to load object file".to_string()))?
            .into();

        info!("Object file opened successfully");
        Ok(())
    }

    /// This function will attept to find all program and load them and attache them as well
    pub async fn load_modules_and_attach(&mut self) -> Result<(), EbpfHelperError> {
        let prog = self
            .prog
            .as_mut()
            .ok_or_else(|| EbpfHelperError::MapNotFound("Program not loaded".to_string()))?;

        for (prog_name, prog) in prog.programs_mut() {
            Self::process_program(prog_name, prog).await;
        }

        Ok(())
    }

    async fn process_program(prog_name: &str, prog: &mut aya::programs::Program) {
        match prog {
            aya::programs::Program::TracePoint(tp) => {
                if let Err(e) = tp.load() {
                    warn!("✗ Unable to load {}: {}", prog_name, e);
                    return;
                }

                let (category, attach_name) = EbpfHelper::map_name(prog_name).await;

                if category.is_empty() {
                    return;
                }

                match tp.attach(category, attach_name) {
                    Ok(_) => info!("✓ TracePoint attached: {}", prog_name),
                    Err(err) => warn!("✗ TracePoint attach failed {}: {}", prog_name, err),
                }
            }

            _ => {
                warn!("Unsupported program type for {}", prog_name);
            }
        }
    }
    /// This function will attempt to load the map name provided
    pub async fn load_config_map(&mut self, map_name: &str) -> Result<(), EbpfHelperError> {
        let prog = self
            .prog
            .as_mut()
            .ok_or_else(|| EbpfHelperError::MapNotFound("eBPF program not loaded".to_string()))?;

        self.config_map = Array::try_from(
            prog.take_map(map_name)
                .ok_or_else(|| EbpfHelperError::MapNotFound(map_name.to_string()))?,
        )
        .ok();

        info!("Array map {} loaded", map_name);
        Ok(())
    }

    /// Load a HashMap from the eBPF program
    pub async fn load_proc_map(&mut self, map_name: &str) -> Result<(), EbpfHelperError> {
        let prog = self
            .prog
            .as_mut()
            .ok_or_else(|| EbpfHelperError::MapNotFound("eBPF program not loaded".to_string()))?;

        self.proc_map = HashMap::try_from(
            prog.take_map(map_name)
                .ok_or_else(|| EbpfHelperError::MapNotFound(map_name.to_string()))?,
        )
        .ok();

        info!("HashMap {} loaded", map_name);
        Ok(())
    }

    pub async fn load_event_map(&mut self, map_name: &str) -> Result<(), EbpfHelperError> {
        let prog = self
            .prog
            .as_mut()
            .ok_or_else(|| EbpfHelperError::MapNotFound("eBPF program not loaded".to_string()))?;

        // Need another look
        self.events_map = Arc::new(Mutex::new(Some(
            RingBuf::try_from(prog.take_map(map_name).unwrap()).unwrap(),
        )));

        info!("HashMap {} loaded", map_name);
        Ok(())
    }

    pub async fn load_buffers_map(&mut self, map_name: &str) -> Result<(), EbpfHelperError> {
        let prog = self
            .prog
            .as_mut()
            .ok_or_else(|| EbpfHelperError::MapNotFound("eBPF program not loaded".to_string()))?;

        self.buffers_map = HashMap::try_from(
            prog.take_map(map_name)
                .ok_or_else(|| EbpfHelperError::MapNotFound(map_name.to_string()))?,
        )
        .ok();

        info!("HashMap {} loaded", map_name);
        Ok(())
    }

    async fn map_name(prog_name: &str) -> (&str, &str) {
        match prog_name {
            "trace_enter_open" => ("syscalls", "sys_enter_open"),
            "trace_enter_openat" => ("syscalls", "sys_enter_openat"),
            "trace_enter_close" => ("syscalls", "sys_enter_close"),
            "trace_enter_write" => ("syscalls", "sys_enter_write"),
            "trace_enter_read" => ("syscalls", "sys_enter_read"),
            "trace_exec" => ("sched", "sched_process_exec"),
            "trace_exit" => ("sched", "sched_process_exit"),
            "trace_block_complete" => ("block", "block_rq_complete"),
            "trace_enter_unlink" => ("syscalls", "sys_enter_unlink"),
            "trace_enter_unlinkat" => ("syscalls", "sys_enter_unlinkat"),
            _ => ("", ""),
        }
    }
    pub async fn print_process_io_stats(&self) {
        // Header
        println!(
            "{:<8} {:>8} {:>8} {:>8} {:>8} {:>10}",
            "PID", "READ", "WRITE", "OPEN", "CLOSE", "ENCRYPT"
        );

        println!("{}", "-".repeat(60));

        // Rows
        for (pid, stats) in self.proc_map.as_ref().unwrap().iter().flatten() {
            let total = stats.open_syscalls;

            if total > 0 {
                println!("{:>8} {:>8} ", pid, stats.open_syscalls,);
            }
        }
    }

    pub async fn construct_aggregator(
        &mut self,
    ) -> Result<std::collections::HashMap<u32, Features>, EbpfHelperError> {
        if self.proc_map.is_none() {
            return Err(EbpfHelperError::ConstructAggregator(
                "processes Map does not exisit".to_string(),
            ));
        }
        let mut aggregator = std::collections::HashMap::new();

        let map = self.proc_map.as_mut().unwrap();

        for (pid, val) in map.iter().flatten() {
            let features = Features::from_io_stats(&val);
            aggregator.insert(pid, features);
        }

        Ok(aggregator)
    }

    pub async fn get_buffer_by_proc_id(&self, proc_id: u32) -> Result<Vec<u8>, EbpfHelperError> {
        match self.buffers_map.as_ref().unwrap().get(&proc_id, 0) {
            Ok(res) => Ok(res.buf.to_vec()),
            Err(err) => Err(EbpfHelperError::NoneExistingKey(err.to_string())),
        }
    }

    // NOTE: Make sure the to slice the buffer to avoid the zeros
    pub async fn get_all_buffers(&mut self) -> Result<Vec<(u32, Vec<u8>)>, EbpfHelperError> {
        let mut ret: Vec<(u32, Vec<u8>)> = Vec::new();
        let map = self.buffers_map.as_mut().unwrap();

        for (pid, val) in map.iter().flatten() {
            if val.read_to_be_handled {
                let buf_size = val.size_of_written_data as usize;
                let add = (pid, val.buf[0..buf_size].to_vec());
                ret.push(add);
            }
        }

        Ok(ret)
    }

    // is_handled: bool, // This feild define is we need to get another sample or not. if true then we finish with this
    // // this sample...
    // size_of_written_data: u64,
    // read_to_be_handled: bool,
    pub async fn update_buffer_info_after_process(&mut self, pid: u32) {
        let map = self.buffers_map.as_mut().unwrap();
        let new_sample_object = EntropyBuffer {
            is_handled: true,
            read_to_be_handled: false,
            size_of_written_data: 0,
            buf: [0; 256],
        };

        match map.insert(pid, new_sample_object, 0) {
            Ok(_) => info!("Entry has been updated for {}", pid),
            Err(err) => warn!("Error updating entry {} for {}", err, pid),
        }
    }
}
