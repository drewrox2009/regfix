use anyhow::{Context, Result, anyhow};
use clap::Parser;
use winreg::enums::*;
use winreg::RegKey;
use std::fs::File;
use memmap::MmapOptions;
use std::time::{Duration, UNIX_EPOCH};
use chrono::DateTime;
use chrono::Utc;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    path: Option<String>,
    #[clap(short, long)]
    file: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(file_path) = args.file.as_ref() {
        println!("Checking registry file: {}", file_path);
        check_registry_file(file_path)?;
    } else if let Some(reg_path) = args.path.as_ref() {
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

fn check_registry_file(file_path: &str) -> Result<()> {
    let file = File::open(file_path)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };

    println!("Checking registry file: {}", file_path);
    println!("File size: {} bytes", mmap.len());

    // Check file signature
    let signature = std::str::from_utf8(&mmap[0..4])?;
    if signature != "regf" {
        return Err(anyhow!("Invalid registry file signature: expected 'regf', found '{}'", signature));
    }
    println!("File signature: OK ({})", signature);

    // Print the first 32 bytes for debugging
    println!("First 32 bytes:");
    print_hex_dump(&mmap[0..32]);

    // Extract and print header fields
    let primary_seq_num = u32::from_le_bytes(mmap[4..8].try_into()?);
    let secondary_seq_num = u32::from_le_bytes(mmap[8..12].try_into()?);
    let last_written = u64::from_le_bytes(mmap[12..20].try_into()?);
    let major_version = u32::from_le_bytes(mmap[20..24].try_into()?);
    let minor_version = u32::from_le_bytes(mmap[24..28].try_into()?);
    let file_type = u32::from_le_bytes(mmap[28..32].try_into()?);
    let root_cell_offset = u32::from_le_bytes(mmap[32..36].try_into()?);

    println!("Primary Sequence Number: {}", primary_seq_num);
    println!("Secondary Sequence Number: {}", secondary_seq_num);
    
    // Convert Windows FILETIME to Unix timestamp and format
    match windows_filetime_to_unix_timestamp(last_written) {
        Ok(unix_time) => {
            let datetime = DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(unix_time));
            println!("Last Written: {} UTC", datetime.format("%Y-%m-%d %H:%M:%S"));
        },
        Err(e) => println!("Error converting last written time: {}", e),
    }
    
    println!("Major Version: {}", major_version);
    println!("Minor Version: {}", minor_version);
    println!("File Type: {} ({})", file_type, file_type_to_string(file_type));
    println!("Root Cell Offset: 0x{:X}", root_cell_offset);

    // Validate sequence numbers
    if primary_seq_num != secondary_seq_num {
        println!("Warning: Primary and Secondary Sequence Numbers do not match. The hive might be corrupted.");
    }

    // Check for common corruption patterns
    if let Some(pos) = mmap.windows(4).position(|window| window == b"\0\0\0\0") {
        println!("Warning: Found 4 consecutive null bytes at position 0x{:X}", pos);
        println!("Hex dump around the position:");
        print_hex_dump(&mmap[pos.saturating_sub(16)..std::cmp::min(pos+20, mmap.len())]);
    }

    println!("Basic file structure check completed.");
    Ok(())
}

fn print_hex_dump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:08X}  ", i * 16);
        for byte in chunk.iter() {
            print!("{:02X} ", byte);
        }
        // Pad with spaces if the chunk is less than 16 bytes
        for _ in chunk.len()..16 {
            print!("   ");
        }
        print!(" |");
        for &byte in chunk.iter() {
            if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
                print!("{}", byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

fn inspect_key(key: &RegKey, path: &str) -> Result<()> {
    for (name, value) in key.enum_values().map(Result::unwrap) {
        println!("{}/{}: {:?}", path, name, value);
        // Here you would add logic to check for corruptions and fix them
    }
    
    for subkey_name in key.enum_keys().map(Result::unwrap) {
        let subkey = key.open_subkey(&subkey_name)?;
        inspect_key(&subkey, &format!("{}/{}", path, subkey_name))?;
    }
    
    Ok(())
}

fn windows_filetime_to_unix_timestamp(filetime: u64) -> Result<u64> {
    // Windows FILETIME is in 100-nanosecond intervals since January 1, 1601 UTC
    // Unix timestamp is in seconds since January 1, 1970 UTC
    // The difference is 11644473600 seconds
    const EPOCH_DIFF: u64 = 11644473600;
    let seconds = filetime.checked_div(10_000_000)
        .ok_or_else(|| anyhow!("Invalid FILETIME value"))?;
    seconds.checked_sub(EPOCH_DIFF)
        .ok_or_else(|| anyhow!("FILETIME too old to represent as Unix timestamp"))
}

fn file_type_to_string(file_type: u32) -> &'static str {
    match file_type {
        0 => "Primary",
        1 => "Log/Backup",
        _ => "Unknown",
    }
}
