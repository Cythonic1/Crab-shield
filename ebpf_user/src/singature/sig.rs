use log::{self, info, warn};
use reqwest::{
    Client, StatusCode,
    header::{self, HeaderValue},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

use crate::{alert::handler_alert::AlertManager, machine_learning_module::AlertingInfo};

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum AlgorithmType {
    MD5,
    SHA256,
}
#[derive(Debug)]
#[allow(dead_code)]
pub struct Signature {
    algorithm_types: AlgorithmType,
    client: Client,
    alert_manager: AlertManager,
    stop: Arc<AtomicBool>,
    system: System,
}

struct Process {
    pid: u32,
    exec: Option<PathBuf>,
}

impl Process {
    fn get_processes(sys: &sysinfo::System) -> Vec<Process> {
        let mut vector_of_process: Vec<Process> = Vec::new();
        for (proc_pid, process) in sys.processes() {
            let exec: Option<PathBuf> = match process.exe() {
                Some(path) => Some(path.to_owned()),
                None => None,
            };
            let tmp: Process = Process {
                pid: proc_pid.as_u32(),
                exec,
            };
            vector_of_process.push(tmp)
        }
        vector_of_process
    }
}

impl Signature {
    pub fn new(
        alg: AlgorithmType,
        api_key: String,
        alert_manager: AlertManager,
        stop: &Arc<AtomicBool>,
    ) -> Signature {
        let mut default_headers = header::HeaderMap::new();
        default_headers.insert(
            "x-apikey",
            HeaderValue::from_str(&api_key).expect("Invalue header value ffor Authorization"),
        );
        let client = Client::builder()
            .default_headers(default_headers)
            .timeout(Duration::from_secs(2))
            .build()
            .expect("Error constructing http client");

        let r = RefreshKind::nothing()
            .with_processes(ProcessRefreshKind::nothing().with_exe(sysinfo::UpdateKind::Always));
        Signature {
            algorithm_types: alg,
            alert_manager,
            client,
            stop: stop.clone(),
            system: System::new_with_specifics(r),
        }
    }

    async fn read_file(&mut self, file: &PathBuf) -> Option<Vec<u8>> {
        match tokio::fs::read(file).await {
            Ok(buf) => return Some(buf),
            Err(err) => {
                warn!("{err}");
                None
            }
        }
    }
    pub async fn claculate_signature(&mut self, file_bytes: Vec<u8>) -> String {
        match self.algorithm_types {
            AlgorithmType::MD5 => self.calculate_md5(file_bytes),
            AlgorithmType::SHA256 => self.calculate_sha256(file_bytes),
        }
    }

    fn calculate_md5(&mut self, file_bytes: Vec<u8>) -> String {
        let md5_hasher = md5::compute(file_bytes);
        let hash_string = format!("{:x}", md5_hasher);
        info!("calculated hash: {}", hash_string);
        hash_string
    }

    fn calculate_sha256(&mut self, file_bytes: Vec<u8>) -> String {
        let sha256_hasher = sha256::digest(&file_bytes);
        info!("Calculated hash: {}", sha256_hasher);
        sha256_hasher
    }

    pub async fn verify_file_signature(&mut self) {
        for proc in Process::get_processes(&self.system) {
            if let Some(path) = proc.exec {
                let file_bytes = self.read_file(&path).await;
                match file_bytes {
                    Some(bytes) => {
                        let hash = self.claculate_signature(bytes).await;
                        let res = self.make_virus_total_req(hash).await;
                        if res {
                            self.alert_manager
                                .send_alert(AlertingInfo(proc.pid, 100.0))
                                .await;
                        } else {
                            continue;
                        }
                    }
                    None => {
                        warn!("No data to process or hash")
                    }
                }
            } else {
                warn!("No path to find hash for.");
            }
        }
    }

    async fn make_virus_total_req(&self, hash: String) -> bool {
        let path = format!("https://www.virustotal.com/api/v3/files/{}", hash);
        let req = self.client.get(path).send().await;
        match req {
            Ok(res) => res.status() == StatusCode::OK,
            Err(err) => {
                warn!("Error making request to virustotal {}", err);
                false
            }
        }
    }

    pub async fn static_analysis(&mut self, secs: u64) {
        let mut timer = tokio::time::interval(Duration::from_secs(secs));
        while !self.stop.load(Ordering::Acquire) {
            // Added ! (not)
            tokio::select! {
                _ = timer.tick() => {  // Also added => here
                    self.verify_file_signature().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::{
        path::PathBuf,
        str::FromStr,
        sync::{Arc, atomic::AtomicBool},
    };

    use crate::{
        alert::handler_alert::AlertManager, config_parser::parser::Config,
        singature::sig::Signature,
    };

    #[tokio::test]
    async fn test_signature() {
        let path_config = PathBuf::from_str("/root/.crab_shield.toml").unwrap();
        let config = Config::new(&path_config).await;
        let mut alert = AlertManager::new(&config);
        let automic = Arc::new(AtomicBool::new(false));
        let mut sig = Signature::new(
            super::AlgorithmType::MD5,
            config.virus_total_api_key,
            alert.clone(),
            &automic,
        );
        let malware_path =
            PathBuf::from_str("/home/misabear/Desktop/FYP/MalwareSample/sample.exe").unwrap();
        let file_bytes = sig.read_file(&malware_path).await;
        let md5 = sig.calculate_md5(file_bytes.unwrap());
        let res = sig.make_virus_total_req(md5).await;
        alert
            .send_alert(crate::machine_learning_module::AlertingInfo(12, 100.0))
            .await;
        assert!(res, "Alert did not sent");
    }
}
