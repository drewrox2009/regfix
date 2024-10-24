use crate::types::*;
use anyhow::Result;
use std::fs::File;
use std::fs;
use std::io::{self, Write, Seek, SeekFrom};
use memmap::MmapOptions;
use winreg::RegKey;

pub fn calculate_header_checksum(data: &[u8]) -> u32 {
    let mut checksum: u32 = 0;
    
    for i in (0..508).step_by(4) {
        let chunk = &data[i..i+4];
        let value = u32::from_le_bytes(chunk.try_into().unwrap());
        checksum ^= value;
    }
    
    if checksum == 0xFFFFFFFF {
        checksum = 0xFFFFFFFE;
    } else if checksum == 0 {
        checksum = 1;
    }
    
    checksum
}

pub fn prompt_yes_no(prompt: &str) -> Result<bool> {
    print!("{} (y/n): ", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_lowercase() == "y")
}

pub fn backup_file(file_path: &str) -> Result<String> {
    let backup_path = format!("{}.backup", file_path);
    fs::copy(file_path, &backup_path)?;
    Ok(backup_path)
}

pub fn update_hive_bins_size(file_path: &str, new_size: u32) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(file_path)?;
    let mut buffer = [0u8; 4];
    buffer.copy_from_slice(&new_size.to_le_bytes());
    file.seek(SeekFrom::Start(40))?;
    file.write_all(&buffer)?;
    Ok(())
}

pub fn update_sequence_numbers(file_path: &str, primary: u32, secondary: u32) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(file_path)?;
    let mut buffer = [0u8; 4];
    
    buffer.copy_from_slice(&primary.to_le_bytes());
    file.seek(SeekFrom::Start(4))?;
    file.write_all(&buffer)?;
    
    buffer.copy_from_slice(&secondary.to_le_bytes());
    file.seek(SeekFrom::Start(8))?;
    file.write_all(&buffer)?;
    
    Ok(())
}

pub fn update_checksum(file_path: &str, new_checksum: u32) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(file_path)?;
    let mut buffer = [0u8; 4];
    buffer.copy_from_slice(&new_checksum.to_le_bytes());
    file.seek(SeekFrom::Start(508))?;
    file.write_all(&buffer)?;
    Ok(())
}

pub fn check_registry_file(file_path: &str) -> Result<AnalysisResult> {
    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len() as u32;
    let mmap = unsafe { MmapOptions::new().map(&file)? };

    let mut issues = Vec::new();
    let base_offset = 4096; // 0x1000

    // Extract all header fields
    let signature = std::str::from_utf8(&mmap[0..4])?.to_string();
    let primary_seq_num = u32::from_le_bytes(mmap[4..8].try_into()?);
    let secondary_seq_num = u32::from_le_bytes(mmap[8..12].try_into()?);
    let last_written = u64::from_le_bytes(mmap[12..20].try_into()?);
    let major_version = u32::from_le_bytes(mmap[20..24].try_into()?);
    let minor_version = u32::from_le_bytes(mmap[24..28].try_into()?);
    let file_type = u32::from_le_bytes(mmap[28..32].try_into()?);
    let file_format = u32::from_le_bytes(mmap[32..36].try_into()?);
    let root_cell_offset = u32::from_le_bytes(mmap[36..40].try_into()?);
    let hive_bins_size = u32::from_le_bytes(mmap[40..44].try_into()?);
    let clustering_factor = u32::from_le_bytes(mmap[44..48].try_into()?);
    let stored_checksum = u32::from_le_bytes(mmap[508..512].try_into()?);
    let calculated_checksum = calculate_header_checksum(&mmap);
    let measured_hive_bins_size = file_size - base_offset;

    // Validate signature
    if signature != "regf" {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Critical,
            message: format!("Invalid signature: expected 'regf', found '{}'", signature),
            details: Some("The registry file signature is invalid, indicating severe corruption".to_string()),
            fix_type: None,
            fix_data: None,
        });
    }

    // Validate checksum
    if stored_checksum != calculated_checksum {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Critical,
            message: "Header checksum mismatch".to_string(),
            details: Some(format!(
                "Stored: 0x{:08X}, Calculated: 0x{:08X}",
                stored_checksum, calculated_checksum
            )),
            fix_type: Some(FixType::Checksum),
            fix_data: Some(FixData::Checksum(calculated_checksum)),
        });
    }

    // Validate hive bins size
    if hive_bins_size != measured_hive_bins_size {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            message: "Hive bins size mismatch".to_string(),
            details: Some(format!(
                "Stored: {} bytes, Measured: {} bytes",
                hive_bins_size, measured_hive_bins_size
            )),
            fix_type: Some(FixType::HiveBinsSize),
            fix_data: Some(FixData::HiveBinsSize(measured_hive_bins_size)),
        });
    }

    // Validate sequence numbers
    if primary_seq_num != secondary_seq_num {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            message: "Sequence numbers do not match".to_string(),
            details: Some(format!(
                "Primary: {}, Secondary: {}. This may indicate an incomplete write operation.",
                primary_seq_num, secondary_seq_num
            )),
            fix_type: Some(FixType::SequenceNumbers),
            fix_data: Some(FixData::SequenceNumbers(primary_seq_num, primary_seq_num)),
        });
    }

    // Create FileInfo structure
    let file_info = FileInfo {
        path: file_path.to_string(),
        size: file_size,
        signature,
        primary_seq_num,
        secondary_seq_num,
        last_written,
        major_version,
        minor_version,
        file_type,
        file_format,
        root_cell_offset,
        hive_bins_size,
        measured_hive_bins_size,
        clustering_factor,
        stored_checksum,
        calculated_checksum,
    };

    Ok(AnalysisResult {
        issues,
        file_info,
    })
}

pub fn inspect_key(key: &RegKey, path: &str) -> Result<()> {
    for (name, value) in key.enum_values().map(Result::unwrap) {
        println!("{}/{}: {:?}", path, name, value);
    }
    
    for subkey_name in key.enum_keys().map(Result::unwrap) {
        let subkey = key.open_subkey(&subkey_name)?;
        inspect_key(&subkey, &format!("{}/{}", path, subkey_name))?;
    }
    
    Ok(())
}

pub fn file_type_to_string(file_type: u32) -> &'static str {
    match file_type {
        0 => "Primary File",
        1 => "Log/Backup File",
        2 => "Volatile (Memory-based)",
        _ => "Unknown Type",
    }
}

pub fn file_format_to_string(format: u32) -> &'static str {
    match format {
        1 => "Direct Memory Load",
        _ => "Unknown Format",
    }
}
