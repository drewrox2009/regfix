use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: IssueSeverity,
    pub message: String,
    pub details: Option<String>,
    pub fix_type: Option<FixType>,
    pub fix_data: Option<FixData>,
}

#[derive(Debug, Clone)]
pub enum FixData {
    HiveBinsSize(u32),
    Checksum(u32),
    SequenceNumbers(u32, u32),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FixType {
    HiveBinsSize,
    Checksum,
    SequenceNumbers,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IssueSeverity {
    Critical,
    Warning,
}

impl std::fmt::Display for IssueSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueSeverity::Critical => write!(f, "CRITICAL"),
            IssueSeverity::Warning => write!(f, "WARNING"),
        }
    }
}

#[derive(Debug)]
pub enum Message {
    FileSelected(PathBuf),
    AnalysisComplete(AnalysisResult),
    FixSelected(Vec<FixType>),
    FixComplete(String),
}

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub issues: Vec<ValidationIssue>,
    pub file_info: FileInfo,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: String,
    pub size: u32,
    pub signature: String,
    pub primary_seq_num: u32,
    pub secondary_seq_num: u32,
    pub last_written: u64,
    pub major_version: u32,
    pub minor_version: u32,
    pub file_type: u32,
    pub file_format: u32,
    pub root_cell_offset: u32,
    pub hive_bins_size: u32,
    pub measured_hive_bins_size: u32,
    pub clustering_factor: u32,
    pub stored_checksum: u32,
    pub calculated_checksum: u32,
}
