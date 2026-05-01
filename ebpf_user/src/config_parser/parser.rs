use std::{env, path::PathBuf, str::FromStr};

use log::{info, warn};
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::{machine_learning_module::Severity, singature::sig::AlgorithmType};

#[derive(Deserialize, Debug, Serialize)]
pub struct Config {
    // Minimum severity level required for an event to be reported
    pub min_severity_to_report: Severity,

    // HTTP endpoint or URL path used to send data to Splunk
    pub splunk_path: String,

    // Authentication token used to authorize requests to Splunk
    pub splunk_token: String,

    // Name of the Splunk index where logs/events will be stored
    pub index_name: String,

    // Interval (in seconds) at which the system checks for findings
    // and reports them to Splunk
    pub report_interval: u64,

    // An Api key for virus total.
    pub virus_total_api_key: String,

    // A list of directories to monitor
    pub directory_to_watch: Vec<String>,

    // The path to the machine learning module module
    pub module_path: String,

    // Path to the scaled data.
    pub module_scale_path: String,

    pub hash_algorith: AlgorithmType,
}

impl Default for Config {
    fn default() -> Self {
        // This should be the root user always

        let default_path = Config::default_path();

        let config = Config {
            min_severity_to_report: Severity::Medium,
            splunk_path: String::from("http://localhost:8088"),
            splunk_token: String::from("Token here..."),
            index_name: String::from("security"),
            report_interval: 10,
            directory_to_watch: vec![
                String::from("/tmp/"),
                String::from("/root/"),
                String::from("/var/"),
                String::from("/dev/"),
                String::from("/etc/"),
            ],
            virus_total_api_key: String::from("API_KEY_HERE"),
            module_path: String::from(
                "/home/misabear/Desktop/FYP/project/learn_bpf/extract_sysCalls_to_map/testing/ml/rf_iris.onnx",
            ),
            module_scale_path: String::from(
                "/home/misabear/Desktop/FYP/project/learn_bpf/extract_sysCalls_to_map/testing/ml/scaler.json",
            ),
            hash_algorith: AlgorithmType::MD5,
        };

        let config_as_toml_string = toml::to_string(&config).expect("Error serializing config");

        match std::fs::write(default_path, config_as_toml_string) {
            Ok(res) => info!("Config has been written to {:?}", res),
            Err(err) => {
                warn!("Error writing config {}", err);
                panic!();
            }
        }
        config
    }
}

#[allow(dead_code)]
impl Config {
    pub async fn new(config_file_path: &PathBuf) -> Self {
        // Determine which path to use: provided or default

        // Try reading the config file
        let file_content = match fs::read_to_string(&config_file_path).await {
            Ok(content) => {
                info!("Config file has been read from {:?}", config_file_path);
                content
            }
            Err(err) => {
                warn!("Error finding config file: {}", err);
                panic!();
            }
        };

        // Try parsing the TOML content
        match toml::from_str::<Config>(&file_content) {
            Ok(config) => {
                info!("Config file has been parsed successfully.");
                config
            }
            Err(err) => {
                warn!(
                    "Failed to parse config file at {:?}: {}",
                    config_file_path, err
                );
                panic!("Invalid config file format, cannot continue.");
            }
        }
    }

    fn default_path() -> PathBuf {
        // let mut home_path_of_running_user = match env::home_dir() {
        //     Some(path) => {
        //         info!("Home path of the running user found under {:?}", path);
        //         path
        //     }
        //     None => {
        //         warn!("Unable to detect home path of the running user");
        //         panic!();
        //     }
        // };
        match PathBuf::from_str("/root/.crab_shield.toml") {
            Ok(path) => path,
            Err(err) => panic!("{err}"),
        }
    }
}
