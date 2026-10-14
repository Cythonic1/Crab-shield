use std::{
    fs::{self, OpenOptions},
    io::{self, ErrorKind},
    path::Path,
    process::{Command, exit},
};

use env_logger::{Builder, Target};
use log::{LevelFilter, info, warn};
use nix::libc::getuid;

pub fn check_running_user() {
    unsafe {
        let uid = getuid();
        if uid != 0 {
            warn!("You need to run as root");
            exit(1);
        }
    }
}

pub fn init_logger(verbose: bool) {
    let log_level = if verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("crab.log")
        .expect("cannot open log file");

    Builder::new()
        .filter_level(log_level)
        .format_timestamp_secs()
        .target(Target::Pipe(Box::new(file)))
        .init();
}

pub fn make_service(program_name: &str) {
    let formatted = format!(
        "[Unit]
Description={name}
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/{name}
ExecStart=/opt/{name}/bin/crab_shield run
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
",
        name = program_name
    );

    match write_with_dirs("/etc/systemd/system/crab.service", &formatted) {
        Result::Ok(()) => {
            info!("service file has been created starting service...");
            let steps: [&[&str]; 2] = [&["daemon-reload"], &["enable", "--now", "crab"]];

            for step in steps {
                if let Err(err) = systemctl(step) {
                    warn!("{err}");
                    return;
                }
            }
            info!("service started");
        }
        Result::Err(err) => {
            warn!("unable to make service configuration : {}", err);
            exit(1);
        }
    }
}

fn systemctl(args: &[&str]) -> io::Result<()> {
    let status = Command::new("systemctl").args(args).status()?;
    if status.success() {
        Result::Ok(())
    } else {
        Result::Err(io::Error::new(
            io::ErrorKind::Other,
            format!("systemctl {} failed with {status}", args.join(" ")),
        ))
    }
}

fn write_with_dirs(path: &str, contents: &str) -> io::Result<()> {
    match fs::write(path, contents) {
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if let Some(parent) = Path::new(path).parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, contents)
        }
        other => other,
    }
}
