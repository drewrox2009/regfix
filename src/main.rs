use anyhow::{Context, Result, anyhow};
use clap::Parser;
use winreg::enums::*;
use winreg::RegKey;
use eframe::egui;
use std::fs::File;
use memmap::MmapOptions;

mod types;
mod registry;
mod gui;

use types::*;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to registry key for live analysis
    #[clap(short, long)]
    path: Option<String>,
    
    /// Path to registry file for offline analysis
    #[clap(short, long)]
    file: Option<String>,
    
    /// Force CLI mode instead of GUI
    #[clap(short, long)]
    cli: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // If no arguments are provided or neither --cli nor specific paths are given, start GUI
    if !args.cli && args.path.is_none() && args.file.is_none() {
        let options = eframe::NativeOptions {
            initial_window_size: Some(egui::vec2(800.0, 600.0)),
            ..Default::default()
        };
        return eframe::run_native(
            "Windows Registry Fixer",
            options,
            Box::new(|cc| Box::new(gui::RegistryFixerApp::new(cc)))
        ).map_err(|e| anyhow!("GUI error: {}", e));
    }

    // CLI mode
    if let Some(file_path) = args.file.as_ref() {
        println!("Registry File Analysis");
        println!("=====================");
        let analysis = registry::check_registry_file(file_path)?;
        display_cli_results(&analysis)?;
    } else if let Some(reg_path) = args.path.as_ref() {
        println!("Live Registry Analysis");
        println!("=====================");
        println!("Inspecting registry path: {}", reg_path);
        
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key = hklm.open_subkey(reg_path)
            .with_context(|| format!("Failed to open registry key: {}", reg_path))?;
        
        registry::inspect_key(&key, reg_path)?;
    } else {
        return Err(anyhow!("In CLI mode, either --file or --path must be provided"));
    }
    
    Ok(())
}

fn display_cli_results(analysis: &AnalysisResult) -> Result<()> {
    let file_info = &analysis.file_info;
    
    println!("\nFile Information");
    println!("----------------");
    println!("Path: {}", file_info.path);
    println!("Size: {} bytes (0x{:X})", file_info.size, file_info.size);
    println!("Signature: {}", file_info.signature);
    println!("Last Written: 0x{:016X}", file_info.last_written);
    println!("Version: {}.{}", file_info.major_version, file_info.minor_version);
    println!("Type: {} ({})", registry::file_type_to_string(file_info.file_type), file_info.file_type);
    println!("Format: {} ({})", registry::file_format_to_string(file_info.file_format), file_info.file_format);
    
    if !analysis.issues.is_empty() {
        println!("\nIssues Found:");
        for issue in &analysis.issues {
            println!("\n[{}] {}", issue.severity, issue.message);
            if let Some(details) = &issue.details {
                println!("Details: {}", details);
            }
            if issue.fix_type.is_some() {
                println!("Status: Fixable");
            }
        }

        let fixable_issues: Vec<&ValidationIssue> = analysis.issues.iter()
            .filter(|i| i.fix_type.is_some())
            .collect();

        if !fixable_issues.is_empty() && registry::prompt_yes_no("\nWould you like to fix the issues?")? {
            let backup_path = registry::backup_file(&file_info.path)?;
            println!("Created backup at: {}", backup_path);

            let mut needs_checksum_update = false;

            for issue in fixable_issues {
                if registry::prompt_yes_no(&format!("Fix: {}?", issue.message))? {
                    match (&issue.fix_type, &issue.fix_data) {
                        (Some(FixType::HiveBinsSize), Some(FixData::HiveBinsSize(new_size))) => {
                            registry::update_hive_bins_size(&file_info.path, *new_size)?;
                            println!("Updated hive bins size to {} bytes", new_size);
                            needs_checksum_update = true;
                        }
                        (Some(FixType::Checksum), Some(FixData::Checksum(new_checksum))) => {
                            registry::update_checksum(&file_info.path, *new_checksum)?;
                            println!("Updated checksum to 0x{:08X}", new_checksum);
                        }
                        (Some(FixType::SequenceNumbers), Some(FixData::SequenceNumbers(primary, secondary))) => {
                            registry::update_sequence_numbers(&file_info.path, *primary, *secondary)?;
                            println!("Updated sequence numbers to Primary: {}, Secondary: {}", primary, secondary);
                            needs_checksum_update = true;
                        }
                        _ => {}
                    }
                }
            }

            if needs_checksum_update {
                let file = File::open(&file_info.path)?;
                let mmap = unsafe { MmapOptions::new().map(&file)? };
                let new_checksum = registry::calculate_header_checksum(&mmap);
                registry::update_checksum(&file_info.path, new_checksum)?;
                println!("Recalculated and updated checksum to 0x{:08X}", new_checksum);
            }
        }
    } else {
        println!("\n✓ No issues detected in the registry file");
    }

    Ok(())
}
