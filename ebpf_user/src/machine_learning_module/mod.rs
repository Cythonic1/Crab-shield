pub mod machine_learning_module;
use serde::{Deserialize, Serialize};
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, Copy, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Converts a severity percentage (0.0–100.0) to an enum member
    pub fn to_enum_member(severity: f32) -> Severity {
        match severity {
            x if (0.0..=25.0).contains(&x) => Severity::Low,
            x if (25.0..=50.0).contains(&x) => Severity::Medium,
            x if (50.0..=75.0).contains(&x) => Severity::High,
            x if (75.0..=100.0).contains(&x) => Severity::Critical,
            _ => Severity::Low, // fallback for out-of-range values
        }
    }
    /// Converts the enum variant to a human-readable string
    pub fn to_string(&self) -> String {
        match self {
            Severity::Low => String::from("low"),
            Severity::Medium => String::from("medium"),
            Severity::High => String::from("high"),
            Severity::Critical => String::from("critical"),
        }
    }
    pub fn description(&self, pid: u32) -> String {
        match self {
            Severity::Low => {
                format!(
                    "Process with PID {} has shown minor suspicious behavior. Monitor activity.",
                    pid
                )
            }
            Severity::Medium => {
                format!(
                    "Process with PID {} has shown moderate suspicious behavior. \
                     Potential ransomware activity detected.",
                    pid
                )
            }
            Severity::High => {
                format!(
                    "Process with PID {} shows strong indications of ransomware. \
                     Take preventive actions.",
                    pid
                )
            }
            Severity::Critical => {
                format!(
                    "Process with PID {} is a critical threat! Immediate containment action required.",
                    pid
                )
            }
        }
    }
}

// pid, predection,
pub struct AlertingInfo(pub u32, pub f32);
