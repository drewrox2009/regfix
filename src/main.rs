#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use clap::Parser;
use std::path::PathBuf;
use eframe::egui;
use gui::RegistryFixerApp;
use image::io::Reader as ImageReader;
use std::io::Cursor;

mod gui;
mod registry;
mod types;

/// Windows Registry Fixer
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the registry file to fix
    #[arg(short, long)]
    file: Option<PathBuf>,
}

fn load_icon() -> eframe::IconData {
    let icon_data = include_bytes!("../assets/icon_256x256.ico");
    let image = ImageReader::new(Cursor::new(icon_data))
        .with_guessed_format()
        .unwrap()
        .decode()
        .unwrap()
        .into_rgba8();
    
    let (width, height) = image.dimensions();
    eframe::IconData {
        rgba: image.into_raw(),
        width: width as _,
        height: height as _,
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    if let Some(file_path) = args.file {
        // CLI mode
        match registry::check_registry_file(&file_path.to_string_lossy()) {
            Ok(result) => {
                println!("File: {}", file_path.display());
                println!("Size: {} bytes", result.file_info.size);
                println!("Signature: {}", result.file_info.signature);
                println!("Primary Sequence Number: {}", result.file_info.primary_seq_num);
                println!("Secondary Sequence Number: {}", result.file_info.secondary_seq_num);
                println!("Last Written: 0x{:016X}", result.file_info.last_written);
                println!("Version: {}.{}", result.file_info.major_version, result.file_info.minor_version);
                println!("Hive Bins Size: {} bytes (stored) vs {} bytes (measured)", 
                    result.file_info.hive_bins_size, result.file_info.measured_hive_bins_size);
                println!("Checksum: 0x{:08X} (stored) vs 0x{:08X} (calculated)",
                    result.file_info.stored_checksum, result.file_info.calculated_checksum);
                
                if result.issues.is_empty() {
                    println!("\nNo issues found.");
                } else {
                    println!("\nIssues found:");
                    for issue in result.issues {
                        match issue.severity {
                            types::IssueSeverity::Critical => print!("CRITICAL: "),
                            types::IssueSeverity::Warning => print!("WARNING: "),
                        }
                        println!("{}", issue.message);
                        if let Some(details) = issue.details {
                            println!("  {}", details);
                        }
                    }
                }
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
        Ok(())
    } else {
        // GUI mode
        let native_options = eframe::NativeOptions {
            decorated: false,  // Remove the native window decorations
            min_window_size: Some(egui::vec2(800.0, 600.0)),
            initial_window_size: Some(egui::vec2(800.0, 600.0)),
            centered: true,
            transparent: true,
            icon_data: Some(load_icon()),
            ..Default::default()
        };
        
        // Handle eframe errors separately to avoid Send/Sync issues
        if let Err(e) = eframe::run_native(
            "MDC RegFix",
            native_options,
            Box::new(|cc| Box::new(RegistryFixerApp::new(cc))),
        ) {
            eprintln!("Error running application: {}", e);
            std::process::exit(1);
        }
        Ok(())
    }
}
