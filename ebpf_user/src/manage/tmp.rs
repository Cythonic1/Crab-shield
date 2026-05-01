#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ProcInfo {
    pub read_sys: u64,
    pub write_sys: u64,
    pub open_sys: u64,
    pub close_sys: u64,
    pub read_bytes: u64,
    pub read_attempts: u64,
    pub write_bytes: u64,
    pub write_attempts: u64,
}
unsafe impl Pod for ProcInfo {}

fn map_name(prog_name: &str) -> (&str, &str) {
    match prog_name {
        "trace_enter_open" => ("syscalls", "sys_enter_open"),
        "trace_enter_openat" => ("syscalls", "sys_enter_openat"),
        "trace_enter_close" => ("syscalls", "sys_enter_close"),
        "trace_enter_write" => ("syscalls", "sys_enter_write"),
        "trace_enter_read" => ("syscalls", "sys_enter_read"),
        "trace_exec" => ("sched", "sched_process_exec"),
        "trace_exit" => ("sched", "sched_process_exit"),
        "trace_block_complete" => ("block", "block_rq_complete"),
        _ => ("", ""),
    }
}

fn reset_map_on_timer(prog_map: &mut HashMap<&mut MapData, u32, ProcInfo>) -> Result<usize> {
    let mut removed_pids = Vec::new();

    for (pid, _) in prog_map.iter().flatten() {
        removed_pids.push(pid);
    }

    let count = removed_pids.len();

    for pid in removed_pids {
        prog_map.remove(&pid).ok();
    }
    Ok(count)
}

// Work on access map

#[tokio::main]
async fn main() -> Result<()> {
    let key = 0;
    let mut prog = Ebpf::load_file(
        "/home/pythonic/Desktop/FYP/project/learn_bpf/extract_sysCalls_to_map/main.bpf.o",
    )
    .expect("Unable to load ");

    for (prog_name, prog) in prog.programs_mut() {
        match prog {
            aya::programs::Program::TracePoint(tp) => {
                tp.load().expect("Unable to load ");
                let (category, attach_name) = map_name(prog_name);
                if category.is_empty() {
                    continue;
                }

                match tp.attach(category, attach_name) {
                    Ok(_) => println!("✓ Attached: {}", prog_name),
                    Err(err) => eprintln!("✗ Error attaching {}: {}", prog_name, err),
                }
                println!("{prog_name}");
            }
            _ => {
                eprintln!("not like us");
            }
        }
    }

    let mut proc_map: HashMap<_, u32, ProcInfo> =
        HashMap::try_from(prog.map_mut("ProcMap").expect("map not found"))?;

    println!("\nMonitoring syscalls. Press Ctrl-C to exit...\n");
    println!(
        "{:<8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "PID",
        "READ",
        "WRITE",
        "OPEN",
        "CLOSE",
        "READ_BYTES",
        "READ_ATTEMPTS",
        "WRITE_BYTES",
        "WRITE_ATTEMPTS"
    );
    println!("{}", "=".repeat(120));

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\n\nReceived Ctrl-C, exiting...");
                break;
            }
            _ = reset_timer.tick() => {
                match reset_map_on_timer(&mut proc_map) {
                    Ok(count) => {
                        println!("\n🔄 Counters reset! Cleared {} process entries.", count);
                    }
                    Err(e) => eprintln!("Error resetting counters: {}", e),
                }

            }
            _ = sleep(Duration::from_secs(2)) => {
                for (pid, info) in proc_map.iter().flatten() {
                    let total = info.read_sys + info.write_sys
                        + info.open_sys + info.close_sys;

                    if total > 0 {


                        println!("{:<8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
                            pid,
                            info.read_sys, info.write_sys,
                            info.open_sys, info.close_sys,
                            info.read_bytes, info.read_attempts,
                            info.write_bytes, info.write_attempts);
                    }
                }

                println!("{}", "-".repeat(120));
                println!(
                    "{:<8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
                    "PID",
                    "READ",
                    "WRITE",
                    "OPEN",
                    "CLOSE",
                    "READ_BYTES",
                    "READ_ATTEMPTS",
                    "WRITE_BYTES",
                    "WRITE_ATTEMPTS"
                );
            }
        }
    }

    Ok(())
}
