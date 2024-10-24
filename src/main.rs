use anyhow::{Context, Result, anyhow};
use clap::Parser;
use winreg::enums::*;
use winreg::RegKey;
use std::fs::File;
use std::fs;
use std::io::{self, Write, Seek, SeekFrom};
use memmap::MmapOptions;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    path: Option<String>,
    #[clap(short, long)]
    file: Option<String>,
}

#[derive(Debug, Clone)]
struct ValidationIssue {
    severity: IssueSeverity,
    message: String,
    details: Option<String>,
    fix_type: Option<FixType>,
    fix_data: Option<FixData>,
}

#[derive(Debug, Clone)]
enum FixData {
    HiveBinsSize(u32),
    Checksum(u32),
    SequenceNumbers(u32, u32),
}

#[derive(Debug, Clone, PartialEq)]
enum FixType {
    HiveBinsSize,
    Checksum,
    SequenceNumbers,
}

#[derive(Debug, Clone, PartialEq)]
enum IssueSeverity {
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

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(file_path) = args.file.as_ref() {
        println!("Registry File Analysis");
        println!("=====================");
        check_registry_file(file_path)?;
    } else if let Some(reg_path) = args.path.as_ref() {
        println!("Live Registry Analysis");
        println!("=====================");
        println!("Inspecting registry path: {}", reg_path);
        
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key = hklm.open_subkey(reg_path)
            .with_context(|| format!("Failed to open registry key: {}", reg_path))?;
        
        inspect_key(&key, reg_path)?;
    } else {
        return Err(anyhow!("Either --file or --path must be provided"));
    }
    
    Ok(())
}

fn calculate_header_checksum(data: &[u8]) -> u32 {
    let mut checksum: u32 = 0;
    
    // Process 508 bytes in 4-byte chunks
    for i in (0..508).step_by(4) {
        let chunk = &data[i..i+4];
        let value = u32::from_le_bytes(chunk.try_into().unwrap());
        checksum ^= value;
    }
    
    // Apply special cases according to specification
    if checksum == 0xFFFFFFFF {
        checksum = 0xFFFFFFFE; // -1 -> -2
    } else if checksum == 0 {
        checksum = 1;
    }
    
    checksum
}

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    print!("{} (y/n): ", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_lowercase() == "y")
}

fn backup_file(file_path: &str) -> Result<String> {
    let backup_path = format!("{}.backup", file_path);
    fs::copy(file_path, &backup_path)?;
    Ok(backup_path)
}

fn update_hive_bins_size(file_path: &str, new_size: u32) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(file_path)?;
    let mut buffer = [0u8; 4];
    buffer.copy_from_slice(&new_size.to_le_bytes());
    file.seek(SeekFrom::Start(40))?;
    file.write_all(&buffer)?;
    Ok(())
}

fn update_sequence_numbers(file_path: &str, primary: u32, secondary: u32) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(file_path)?;
    let mut buffer = [0u8; 4];
    
    // Update primary sequence number
    buffer.copy_from_slice(&primary.to_le_bytes());
    file.seek(SeekFrom::Start(4))?;
    file.write_all(&buffer)?;
    
    // Update secondary sequence number
    buffer.copy_from_slice(&secondary.to_le_bytes());
    file.seek(SeekFrom::Start(8))?;
    file.write_all(&buffer)?;
    
    Ok(())
}

fn update_checksum(file_path: &str, new_checksum: u32) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(file_path)?;
    let mut buffer = [0u8; 4];
    buffer.copy_from_slice(&new_checksum.to_le_bytes());
    file.seek(SeekFrom::Start(508))?;
    file.write_all(&buffer)?;
    Ok(())
}

fn prompt_for_fixes(issues: &[ValidationIssue]) -> Result<Vec<FixType>> {
    let fixable_issues: Vec<&ValidationIssue> = issues.iter()
        .filter(|i| i.fix_type.is_some())
        .collect();

    if fixable_issues.is_empty() {
        println!("\nNo fixable issues detected.");
        return Ok(vec![]);
    }

    println!("\nFixable Issues Detected");
    println!("=====================");
    println!("\nWARNING: Making changes to the header will require recalculating the checksum.");
    println!("A backup will be created before making any changes.");
    
    for (i, issue) in fixable_issues.iter().enumerate() {
        println!("\n{}. [{}] {}", i + 1, issue.severity, issue.message);
        if let Some(details) = &issue.details {
            println!("   Details: {}", details);
        }
    }

    println!("\nOptions:");
    println!("1. Fix all issues");
    println!("2. Select specific issues to fix");
    println!("3. Skip all fixes");
    
    print!("\nSelect an option (1-3): ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    match input.trim() {
        "1" => Ok(fixable_issues.iter()
            .filter_map(|i| i.fix_type.clone())
            .collect()),
        "2" => {
            let mut selected_fixes = Vec::new();
            for (i, issue) in fixable_issues.iter().enumerate() {
                if prompt_yes_no(&format!("Fix issue #{}: {}?", i + 1, issue.message))? {
                    if let Some(fix_type) = &issue.fix_type {
                        selected_fixes.push(fix_type.clone());
                    }
                }
            }
            Ok(selected_fixes)
        }
        _ => Ok(vec![]),
    }
}

fn check_registry_file(file_path: &str) -> Result<()> {
    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len() as u32;
    let mmap = unsafe { MmapOptions::new().map(&file)? };

    let mut issues = Vec::new();

    println!("\nFile Information");
    println!("----------------");
    println!("Path: {}", file_path);
    println!("Size: {} bytes (0x{:X})", file_size, file_size);

    // Basic header validation
    println!("\nHeader Validation");
    println!("----------------");

    // 1. Signature Check (0-4)
    let signature = std::str::from_utf8(&mmap[0..4])?;
    if signature != "regf" {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Critical,
            message: format!("Invalid signature: expected 'regf', found '{}'", signature),
            details: Some("The registry file signature is invalid, indicating severe corruption".to_string()),
            fix_type: None,
            fix_data: None,
        });
    } else {
        println!("Signature: Valid ('regf')");
    }

    // Extract header fields
    let primary_seq_num = u32::from_le_bytes(mmap[4..8].try_into()?);
    let secondary_seq_num = u32::from_le_bytes(mmap[8..12].try_into()?);
    let last_written = u64::from_le_bytes(mmap[12..20].try_into()?);
    println!("Last Written Timestamp: 0x{:016X}", last_written);
    
    let major_version = u32::from_le_bytes(mmap[20..24].try_into()?);
    let minor_version = u32::from_le_bytes(mmap[24..28].try_into()?);
    let file_type = u32::from_le_bytes(mmap[28..32].try_into()?);
    let file_format = u32::from_le_bytes(mmap[32..36].try_into()?);
    let root_cell_offset = u32::from_le_bytes(mmap[36..40].try_into()?);
    let hive_bins_size = u32::from_le_bytes(mmap[40..44].try_into()?);
    let clustering_factor = u32::from_le_bytes(mmap[44..48].try_into()?);
    let stored_checksum = u32::from_le_bytes(mmap[508..512].try_into()?);

    // 2. Checksum Validation
    let calculated_checksum = calculate_header_checksum(&mmap);
    println!("\nChecksum Validation");
    println!("------------------");
    println!("Stored Checksum: 0x{:08X}", stored_checksum);
    println!("Calculated Checksum: 0x{:08X}", calculated_checksum);
    
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

    // 3. File Size Validation
    let base_offset = 4096; // 0x1000
    let expected_size = base_offset + hive_bins_size;
    let measured_hive_bins_size = file_size - base_offset;
    println!("\nSize Validation");
    println!("---------------");
    println!("Base Offset: {} bytes (0x{:X})", base_offset, base_offset);
    println!("Stored Hive Bins Size: {} bytes (0x{:X})", hive_bins_size, hive_bins_size);
    println!("Measured Hive Bins Size: {} bytes (0x{:X})", measured_hive_bins_size, measured_hive_bins_size);
    println!("Expected Total Size: {} bytes (0x{:X})", expected_size, expected_size);
    println!("Actual File Size: {} bytes (0x{:X})", file_size, file_size);
    
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

    // 4. Sequence Number Check
    println!("\nSequence Numbers");
    println!("----------------");
    println!("Primary: {}", primary_seq_num);
    println!("Secondary: {}", secondary_seq_num);
    if primary_seq_num != secondary_seq_num {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            message: "Sequence numbers do not match".to_string(),
            details: Some(format!(
                "Primary: {}, Secondary: {}. This may indicate an incomplete write operation.",
                primary_seq_num, secondary_seq_num
            )),
            fix_type: Some(FixType::SequenceNumbers),
            fix_data: Some(FixData::SequenceNumbers(primary_seq_num, primary_seq_num)), // Use primary as the correct value
        });
    }

    // 5. Root Cell Validation
    let absolute_root_offset = base_offset + root_cell_offset;
    println!("\nRoot Cell Validation");
    println!("-------------------");
    println!("Root Cell Offset: 0x{:X}", root_cell_offset);
    println!("Absolute Root Cell Offset: 0x{:X}", absolute_root_offset);
    if absolute_root_offset >= file_size {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Critical,
            message: "Invalid root cell offset".to_string(),
            details: Some(format!(
                "Absolute root cell offset (0x{:X}) is outside file bounds (0x{:X})",
                absolute_root_offset, file_size
            )),
            fix_type: None,
            fix_data: None,
        });
    }

    // 6. Version Check
    println!("\nVersion Information");
    println!("------------------");
    println!("Major Version: {} (Expected: 1)", major_version);
    println!("Minor Version: {} (Expected: 3, 4, 5, or 6)", minor_version);
    if major_version != 1 || !(3..=6).contains(&minor_version) {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            message: "Unexpected version numbers".to_string(),
            details: Some(format!(
                "Found version {}.{}, expected 1.3-1.6",
                major_version, minor_version
            )),
            fix_type: None,
            fix_data: None,
        });
    }

    // 7. File Format Check
    println!("\nFile Format");
    println!("-----------");
    println!("File Type: {} ({})", file_type_to_string(file_type), file_type);
    println!("File Format: {} ({})", file_format_to_string(file_format), file_format);
    println!("Clustering Factor: {}", clustering_factor);
    
    if file_type != 0 {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            message: "Unexpected file type".to_string(),
            details: Some("Expected primary file (0)".to_string()),
            fix_type: None,
            fix_data: None,
        });
    }
    
    if file_format != 1 {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            message: "Unexpected file format".to_string(),
            details: Some("Expected direct memory load (1)".to_string()),
            fix_type: None,
            fix_data: None,
        });
    }

    // Print Analysis Summary
    println!("\nAnalysis Summary");
    println!("----------------");
    if issues.is_empty() {
        println!("✓ No issues detected in the registry file");
    } else {
        println!("Found {} issue(s):", issues.len());
        
        // Group issues by severity
        let critical = issues.iter().filter(|i| matches!(i.severity, IssueSeverity::Critical)).count();
        let warnings = issues.iter().filter(|i| matches!(i.severity, IssueSeverity::Warning)).count();
        let fixable = issues.iter().filter(|i| i.fix_type.is_some()).count();
        
        println!("- {} Critical", critical);
        println!("- {} Warnings", warnings);
        println!("- {} Fixable", fixable);
        
        println!("\nDetailed Issues:");
        for (i, issue) in issues.iter().enumerate() {
            println!("\n{}. [{}] {}", i + 1, issue.severity, issue.message);
            if let Some(details) = &issue.details {
                println!("   Details: {}", details);
            }
            if issue.fix_type.is_some() {
                println!("   Status: Fixable");
            }
        }

        // Handle fixes if there are any fixable issues
        if fixable > 0 {
            let fixes_to_apply = prompt_for_fixes(&issues)?;
            if !fixes_to_apply.is_empty() {
                let backup_path = backup_file(file_path)?;
                println!("\nCreated backup at: {}", backup_path);

                let mut needs_checksum_update = false;

                // Apply selected fixes
                for fix_type in fixes_to_apply {
                    if let Some(issue) = issues.iter().find(|i| i.fix_type.as_ref() == Some(&fix_type)) {
                        match (&fix_type, &issue.fix_data) {
                            (FixType::HiveBinsSize, Some(FixData::HiveBinsSize(new_size))) => {
                                update_hive_bins_size(file_path, *new_size)?;
                                println!("Updated hive bins size to {} bytes", new_size);
                                needs_checksum_update = true;
                            }
                            (FixType::Checksum, Some(FixData::Checksum(new_checksum))) => {
                                update_checksum(file_path, *new_checksum)?;
                                println!("Updated checksum to 0x{:08X}", new_checksum);
                            }
                            (FixType::SequenceNumbers, Some(FixData::SequenceNumbers(primary, secondary))) => {
                                update_sequence_numbers(file_path, *primary, *secondary)?;
                                println!("Updated sequence numbers to Primary: {}, Secondary: {}", primary, secondary);
                                needs_checksum_update = true;
                            }
                            _ => {}
                        }
                    }
                }

                // If we made changes that affect the header, recalculate and update the checksum
                if needs_checksum_update {
                    let file = File::open(file_path)?;
                    let mmap = unsafe { MmapOptions::new().map(&file)? };
                    let new_checksum = calculate_header_checksum(&mmap);
                    update_checksum(file_path, new_checksum)?;
                    println!("Recalculated and updated checksum to 0x{:08X}", new_checksum);
                }
            }
        }

        println!("\nRecommendations:");
        if critical > 0 {
            println!("! CRITICAL: This registry hive shows signs of severe corruption");
            println!("1. DO NOT use this hive file in its current state");
            println!("2. Attempt recovery using Windows Recovery Environment");
            println!("3. Restore from a known good backup if available");
        } else if warnings > 0 {
            println!("1. Run 'chkdsk' to verify disk integrity");
            println!("2. Use Windows' built-in registry repair tools");
            println!("3. Consider creating a backup before making changes");
        }
    }

    Ok(())
}

fn inspect_key(key: &RegKey, path: &str) -> Result<()> {
    for (name, value) in key.enum_values().map(Result::unwrap) {
        println!("{}/{}: {:?}", path, name, value);
    }
    
    for subkey_name in key.enum_keys().map(Result::unwrap) {
        let subkey = key.open_subkey(&subkey_name)?;
        inspect_key(&subkey, &format!("{}/{}", path, subkey_name))?;
    }
    
    Ok(())
}

fn file_type_to_string(file_type: u32) -> &'static str {
    match file_type {
        0 => "Primary File",
        1 => "Log/Backup File",
        2 => "Volatile (Memory-based)",
        _ => "Unknown Type",
    }
}

fn file_format_to_string(format: u32) -> &'static str {
    match format {
        1 => "Direct Memory Load",
        _ => "Unknown Format",
    }
}
