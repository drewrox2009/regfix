use anyhow::{Context, Result, anyhow};
use clap::Parser;
use winreg::enums::*;
use winreg::RegKey;
use std::fs::File;
use memmap::MmapOptions;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    path: Option<String>,
    #[clap(short, long)]
    file: Option<String>,
}

#[derive(Debug)]
struct ValidationIssue {
    severity: IssueSeverity,
    message: String,
    details: Option<String>,
}

#[derive(Debug)]
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
        });
    }

    // 3. File Size Validation
    let base_offset = 4096; // 0x1000
    let expected_size = base_offset + hive_bins_size;
    println!("\nSize Validation");
    println!("---------------");
    println!("Base Offset: {} bytes (0x{:X})", base_offset, base_offset);
    println!("Hive Bins Size: {} bytes (0x{:X})", hive_bins_size, hive_bins_size);
    println!("Expected Total Size: {} bytes (0x{:X})", expected_size, expected_size);
    println!("Actual File Size: {} bytes (0x{:X})", file_size, file_size);
    
    if expected_size != file_size {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            message: "File size mismatch".to_string(),
            details: Some(format!(
                "Expected size {} bytes (0x{:X}), but file is {} bytes (0x{:X})",
                expected_size, expected_size, file_size, file_size
            )),
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
        });
    }
    
    if file_format != 1 {
        issues.push(ValidationIssue {
            severity: IssueSeverity::Warning,
            message: "Unexpected file format".to_string(),
            details: Some("Expected direct memory load (1)".to_string()),
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
        
        println!("- {} Critical", critical);
        println!("- {} Warnings", warnings);
        
        println!("\nDetailed Issues:");
        for (i, issue) in issues.iter().enumerate() {
            println!("\n{}. [{}] {}", i + 1, issue.severity, issue.message);
            if let Some(details) = &issue.details {
                println!("   Details: {}", details);
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
