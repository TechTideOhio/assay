use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvelopeStatus {
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessEnvelope<T: Serialize> {
    pub status: EnvelopeStatus,
    pub summary: String,
    pub next_actions: Vec<String>,
    pub artifacts: Vec<String>,
    pub data: T,
}

impl<T: Serialize> HarnessEnvelope<T> {
    pub fn success(
        summary: impl Into<String>,
        next_actions: Vec<String>,
        artifacts: Vec<String>,
        data: T,
    ) -> Self {
        Self {
            status: EnvelopeStatus::Success,
            summary: summary.into(),
            next_actions,
            artifacts,
            data,
        }
    }

    pub fn warning(
        summary: impl Into<String>,
        next_actions: Vec<String>,
        artifacts: Vec<String>,
        data: T,
    ) -> Self {
        Self {
            status: EnvelopeStatus::Warning,
            summary: summary.into(),
            next_actions,
            artifacts,
            data,
        }
    }

    pub fn error(
        summary: impl Into<String>,
        next_actions: Vec<String>,
        artifacts: Vec<String>,
        data: T,
    ) -> Self {
        Self {
            status: EnvelopeStatus::Error,
            summary: summary.into(),
            next_actions,
            artifacts,
            data,
        }
    }

    pub fn print_json(&self) -> Result<(), serde_json::Error> {
        let serialized = serde_json::to_string_pretty(self)?;
        println!("{serialized}");
        Ok(())
    }
}
