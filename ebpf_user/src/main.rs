mod alert;
mod config_parser;
mod entropy;
mod features;
mod machine_learning_attrb;
mod machine_learning_module;
mod manage;
mod singature;
mod utils;
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::LevelFilter;
use log::info;
use log::warn;
use nix::libc::getuid;
use std::path::PathBuf;
use std::process::exit;
use std::sync::{Arc, Mutex, atomic::AtomicBool};

use crate::{
    alert::handler_alert::AlertManager,
    config_parser::parser::Config,
    machine_learning_attrb::centrial::Aggregator,
    manage::reader_ring_buf::start_ebpf_reader,
    singature::sig::Signature,
    utils::ring_buffer::{RingBuffer, SharedRingBuffer},
};

#[derive(Subcommand)]
enum SubCommands {
    /// Run CrabShield with the specified configuration
    ///
    /// This will start monitoring file system operations using eBPF
    /// and detect potential ransomware activity based on ML models.
    Run {
        /// Path to the configuration file
        ///
        /// The config file should be in TOML format and contain
        /// monitoring rules and ML model parameters.
        #[arg(short, long, default_value = "/root/.crab_shield.toml")]
        config_path: PathBuf,

        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },

    /// Generate a default configuration file
    ///
    /// Creates a new config file with recommended settings
    /// for ransomware detection.
    GenerateConfig {
        #[arg(short, long, default_value_t = false)]
        verbose: bool,
    },
}

#[derive(Parser)]
#[command(name = "CrabShield")]
#[command(about = "CrabShield is a Ransomware detection utility using eBPF and machine learning")]
#[command(
    long_about = "CrabShield monitors file system operations in real-time using eBPF probes \
                         and applies machine learning models to detect ransomware behavior patterns."
)]
#[command(version)] // Automatically adds version from Cargo.toml
struct Cli {
    #[command(subcommand)]
    command: SubCommands,
}

fn check_running_user() {
    unsafe {
        let uid = getuid();
        if uid != 0 {
            warn!("You need to run as root");
            exit(1);
        }
    }
}

fn init_logger(verbose: bool) {
    let log_level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    Builder::new()
        .filter_level(log_level)
        .format_timestamp_secs()
        .init();
}

// implement file parser
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    check_running_user();
    let cli = Cli::parse();

    let config = match &cli.command {
        SubCommands::Run {
            config_path,
            verbose,
        } => {
            println!("Config path is {:?}", config_path);
            init_logger(*verbose);
            Config::new(config_path).await
        }
        SubCommands::GenerateConfig { verbose } => {
            init_logger(*verbose);
            Config::default();
            info!("Log file has been generated");
            exit(0);
        }
    };

    info!("Starting system...");
    let paths = config.directory_to_watch.clone();
    let paths_arr: [&str; 5] = [
        paths[0].as_str(),
        paths[1].as_str(),
        paths[2].as_str(),
        paths[3].as_str(),
        paths[4].as_str(),
    ];
    let terminator = Arc::new(AtomicBool::new(true));
    let report_interval_copy = config.report_interval;

    let alert_manager = AlertManager::new(&config);

    // 1. Create Aggregator
    let mut aggregator = Aggregator::new(
        config.module_path,
        config.module_scale_path,
        alert_manager.clone(),
        paths_arr,
    );

    info!("Done init aggregator");

    let mut signature = Signature::new(
        singature::sig::AlgorithmType::SHA256,
        config.virus_total_api_key,
        alert_manager,
        &terminator,
    );
    tokio::spawn(async move {
        signature.static_analysis(report_interval_copy).await;
    });
    info!("Done Starting Static Analysis");

    // 2. Load & attach eBPF programs
    aggregator.init_ebpf().await?;
    info!("Done init ebpf");

    // 3. Shared ring buffer between threads
    let ring_buffer: SharedRingBuffer<_> = Arc::new(Mutex::new(RingBuffer::new()));

    // 4. Start eBPF reader task
    let event_map = Arc::clone(&aggregator.ebpf_helper.events_map);
    let buffer_clone = Arc::clone(&ring_buffer);

    let terminator_copy = Arc::clone(&terminator);

    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            eprintln!("Failed to listen for ctrl_c: {:?}", e);
        }
        println!("Ctrl+C received, shutting down...");
        terminator_copy.store(false, std::sync::atomic::Ordering::Release);
    });
    info!("Spawn thread monitor Ctrl+C signal");

    let terminator_clone = terminator.clone();
    tokio::spawn(async move {
        start_ebpf_reader(&terminator_clone, event_map, buffer_clone).await;
    });
    info!("Spawn thread monitor the ring buffer");

    // 5. Start aggregator main loop (blocking loop)
    aggregator
        .run(ring_buffer, &terminator, report_interval_copy)
        .await?;

    Ok(())
}
