// Splunk token
//1aedcce2-1597-43f9-ae10-7e2b9809ebd0

use std::{
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use log::{info, warn};
use reqwest::{
    Client, Method, Url,
    header::{self, HeaderValue},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    config_parser::parser::Config,
    machine_learning_module::{AlertingInfo, Severity},
};
#[derive(Debug, Clone)]
pub struct AlertManager {
    pub client: Client,
    splunk_path: Url,
    pub min_alert: Severity, //  a minimum severity to alert
    index_name: String,
}

/// Represents the actual event data that will be sent to Splunk.
#[derive(Serialize, Debug)]
struct Event {
    /// Unique identifier for this event.
    /// Helps prevent duplicates and allows referencing the event later.
    id: String,

    /// Type of the event (e.g., "phishing_email", "malware_detected").
    /// `#[serde(rename = "type")]` ensures it is serialized as "type" in JSON,
    /// because `type` is a reserved Rust keyword.
    #[serde(rename = "type")]
    type_event: String,

    /// Severity level of the event (e.g., "low", "medium", "high", "critical").
    /// Useful for dashboards, alerts, and filtering in Splunk.
    severity: String,

    /// Human-readable description of the event.
    /// Provides context for SOC analysts or for auditing.
    description: String,

    /// Action that was taken automatically or manually (e.g., "quarantined", "blocked", "ignored").
    action_taken: String,

    /// Tags for categorizing or filtering events (e.g., ["phishing", "soar", "malware"]).
    /// Useful for dashboards, searches, and field extraction.
    tags: Vec<String>,
}

impl Event {
    pub fn new(event_type: Severity, pid: u32) -> Self {
        Event {
            id: AlertManager::generate_id(),
            type_event: String::from("Ransomware suspicious"),
            severity: event_type.to_string(),
            description: event_type.description(pid),
            action_taken: String::from("quarantined"),
            tags: vec!["security".to_string(), "Ransomware".to_string()],
        }
    }
}

/// Represents the top-level structure of a Splunk HEC request.
#[derive(Serialize, Debug)]
struct SplunkRequestOption {
    /// The event timestamp. Splunk uses this to index the event correctly.
    /// If omitted, Splunk will use the ingestion time.
    time: u64,

    /// Source of the event, usually the system or application generating it (e.g., "soar_tool").
    source: String,

    /// Splunk sourcetype. Classifies the kind of event for indexing and field extraction.
    /// Example: "security:alert", "web:access", etc.
    sourcetype: String,

    /// Index in Splunk where this event will be stored (e.g., "security", "main").
    /// Helps organize events by type or team.
    index: String,

    /// The actual event payload containing detailed information.
    event: Event,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct SplunkResponseOption {
    text: String,
    code: u64,
}

impl SplunkRequestOption {
    fn new(event: Event, index_name: &String) -> Self {
        SplunkRequestOption {
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            source: String::from("pythonic"),
            sourcetype: String::from("security:alert"),
            index: index_name.to_string(),
            event,
        }
    }
}
impl AlertManager {
    pub fn new(config: &Config) -> Self {
        let mut token_value = String::from("Splunk ");
        token_value.push_str(&config.splunk_token);

        let mut default_headers = header::HeaderMap::new();
        default_headers.insert(
            "Authorization",
            HeaderValue::from_str(&token_value).expect("Invalue header value ffor Authorization"),
        );
        default_headers.insert(
            "Content-Type",
            HeaderValue::from_str("application/json")
                .expect("Error from_str in content_type header"),
        );
        let client = Client::builder()
            .default_headers(default_headers)
            .timeout(Duration::from_secs(2))
            .build()
            .expect("Error constructing http client");

        // expecting a path like http://localhost:8000
        let mut url = match Url::from_str(&config.splunk_path) {
            Ok(url) => url,
            Err(err) => {
                warn!("Unable to parse URL: {}", err);
                std::process::exit(1);
            }
        };

        // Add a path segment (e.g., "event" for HEC batch endpoint)
        url.path_segments_mut()
            .expect("Cannot modify URL path")
            .push("services");

        url.path_segments_mut()
            .expect("Cannot modify URL path")
            .push("collector");

        AlertManager {
            client,
            min_alert: config.min_severity_to_report,
            index_name: config.index_name.clone(),
            splunk_path: url,
        }
    }
    fn generate_id() -> String {
        Uuid::new_v4().to_string()
    }

    pub async fn send_alert(&mut self, alert_info: AlertingInfo) {
        let module_predection = alert_info.1;
        let severity = Severity::to_enum_member(module_predection);

        if self.min_alert > severity {
            info!(
                "Will not report seveirty lesser than or equal to {}",
                self.min_alert.to_string()
            );
            return;
        }
        let event = Event::new(severity, alert_info.0);
        let request = SplunkRequestOption::new(event, &self.index_name);

        info!("Sending request to {}", self.splunk_path);
        info!("Sent request {:#?}", request);
        let res = self
            .client
            .request(Method::POST, self.splunk_path.clone())
            .json(&request)
            .send()
            .await;
        match res {
            Ok(res) => {
                let hec_response: SplunkResponseOption = res.json().await.unwrap();
                info!("response is {:#?}", hec_response);
            }
            Err(err) => warn!("Error {}", err),
        }
    }
}
