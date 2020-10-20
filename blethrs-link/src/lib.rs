use blethrs_shared::{Command, CONFIG_MAGIC};
use crc::crc32::{self, Hasher32};
use std::convert::TryFrom;
use std::hash::Hasher;
use std::net::TcpStream;
use std::io::{self, Read, Write};

#[derive(Debug)]
pub enum Error {
    /// Failed to write to the TCP stream.
    Write(io::Error),
    /// Failed to read from the TCP stream.
    Read(io::Error),
    /// Error reported by the bootloader.
    Bootloader(blethrs_shared::Error),
    /// The received response was ill-formatted or contained an unexpected value.
    InvalidResponse,
    /// A mismatch between the written and read-back data occurred.
    ReadMismatch {
        flash_addr: u32,
        wrote: u8,
        read: u8,
    }
}

// Send the given command to the specified address via TCP and check the response.
fn interact(s: &mut TcpStream, cmd_bytes: &[u8]) -> Result<(), Error> {
    s.write(cmd_bytes).map_err(Error::Write)?;
    let mut status = [0u8; 4];
    s.read_exact(&mut status[..]).map_err(Error::Read)?;
    let status_u32 = u32::from_le_bytes(status);
    match blethrs_shared::Error::try_from(status_u32) {
        Ok(blethrs_shared::Error::Success) => Ok(()),
        Ok(e) => return Err(Error::Bootloader(e)),
        Err(_) => return Err(Error::InvalidResponse),
    }
}

/// Submit a request for info about the device and the blethrs build installed.
///
/// Resturns the bytes of what should be a UTF8 string.
pub fn info_cmd(s: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let b = (Command::Info as u32).to_le_bytes();
    interact(s, &b[..])?;
    // TODO: This is a hack to read an unknown amount of data. In reality should take way less time
    // to read back info than this.
    let start = std::time::Instant::now();
    let duration = std::time::Duration::from_secs(1);
    let mut data = vec![];
    s.set_nonblocking(true).ok();
    while start.elapsed() < duration {
        s.read(&mut data).ok();
    }
    s.set_nonblocking(false).ok();
    Ok(data)
}

/// Submit a request to erase a region of the device flash.
pub fn erase_cmd(s: &mut TcpStream, flash_addr: u32, len: u32) -> Result<(), Error> {
    let mut b = vec![];
    b.extend_from_slice(&(Command::Erase as u32).to_le_bytes());
    b.extend_from_slice(&flash_addr.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    interact(s, &b[..])
}

/// Submit a request to read from a region of the device flash.
pub fn read_cmd(s: &mut TcpStream, flash_addr: u32, len: u32) -> Result<Vec<u8>, Error> {
    let mut b = vec![];
    b.extend_from_slice(&(Command::Read as u32).to_le_bytes());
    b.extend_from_slice(&flash_addr.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    interact(s, &b[..])?;

    // Read back the data.
    let mut data = vec![0u8; len as usize];
    s.read_exact(&mut data[..]).map_err(Error::Read)?;
    Ok(data)
}

/// Submit a request to write to a region of the device flash.
///
/// This will attempt to send all data within a single TCP packet, as a result large chunks of data
/// should be first split into chunks (see `write_file`).
pub fn write_cmd(s: &mut TcpStream, flash_addr: u32, data: &[u8]) -> Result<(), Error> {
    let mut b = vec![];
    b.extend_from_slice(&(Command::Write as u32).to_le_bytes());
    b.extend_from_slice(&flash_addr.to_le_bytes());
    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
    b.extend_from_slice(data);
    interact(s, &b[..])
}

/// Submit a request to attempt to boot into the loaded program.
pub fn boot_cmd(s: &mut TcpStream) -> Result<(), Error> {
    let b = (Command::Boot as u32).to_le_bytes();
    interact(s, &b[..])
}

/// Write the given binary file to the specified region in flash.
pub fn write_file(
    stream: &mut TcpStream,
    chunk_size: usize,
    flash_addr: u32,
    mut data: Vec<u8>,
) -> Result<(), Error> {
    // We need to write in multiples of 4 bytes (since writes are word-by-word), so add padding to
    // the end of the data.
    if data.len() % 4 != 0 {
        let padding = 4 - data.len() % 4;
        data.extend(vec![0xFF; padding]);
    }
    let mut segments = data.len() / chunk_size;
    if data.len() % chunk_size != 0 {
        segments += 1;
    }

    log::info!("Erasing (may take a few seconds)...");
    erase_cmd(stream, flash_addr, data.len() as u32)?;

    log::info!("Writing {:.2}kB in {} segments...", data.len() as f32 / 1024.0, segments);
    for (seg_progress, seg_i) in (0..segments).rev().enumerate() {
        let seg_addr = flash_addr + (seg_i * chunk_size) as u32;
        let start = seg_i * chunk_size;
        let end = std::cmp::min(start + chunk_size, data.len());
        let seg_data = &data[start..end];
        write_cmd(stream, seg_addr, seg_data)?;
        log::info!("  {:.2}%", ((seg_progress + 1) * 100) as f32 / segments as f32);
    }

    log::info!("Writing completed successfully. Reading back...");
    for seg_i in 0..segments {
        let seg_addr = flash_addr + (seg_i * chunk_size) as u32;
        let start = seg_i * chunk_size;
        let end = std::cmp::min(start + chunk_size, data.len());
        let seg_data = &data[start..end];
        let r_data = read_cmd(stream, seg_addr, chunk_size as u32)?;
        if seg_data != &r_data[..seg_data.len()] {
            for (i, (&wrote, &read)) in seg_data.iter().zip(&r_data).enumerate() {
                if wrote != read {
                    let flash_addr = seg_addr + i as u32;
                    return Err(Error::ReadMismatch { flash_addr, wrote, read });
                }
            }
        }
        log::info!("  {:.2}%", ((seg_i + 1) * 100) as f32 / segments as f32);
    }

    log::info!("Readback successful.");
    Ok(())
}

/// Write the given device configuration to the specified flash address.
pub fn write_config(
    stream: &mut TcpStream,
    cfg_flash_addr: u32,
    mac: &[u8; 6],
    ip: &[u8; 4],
    gw: &[u8; 4],
    prefix: u8,
) -> Result<(), Error> {
    let mut b = vec![];
    b.extend_from_slice(&CONFIG_MAGIC.to_le_bytes());
    b.extend_from_slice(mac);
    b.extend_from_slice(ip);
    b.extend_from_slice(gw);
    b.push(prefix);
    let padding = 0u8;
    b.push(padding);
    let crc = {
        let polynomial = 0x04C11DB7;
        let init = 0xFFFFFFFF;
        let mut digest = crc32::Digest::new_with_initial(polynomial, init);

        // Cast to u32 words.
        let us: &[u32] = unsafe {
            let len = b.len() / std::mem::size_of::<u32>();
            let u_ptr = b.as_ptr() as *const u32;
            std::slice::from_raw_parts(u_ptr, len)
        };

        // Write them with endianness swapped (copying the python script).
        for &u in us {
            let u = u.reverse_bits();
            digest.write_u32(u);
        }

        digest.sum32()
    };
    b.extend_from_slice(&crc.to_le_bytes());

    log::info!("Erasing old configuration...");
    erase_cmd(stream, cfg_flash_addr, b.len() as u32)?;

    log::info!("Writing new configuration...");
    write_cmd(stream, cfg_flash_addr, &b)?;

    log::info!("Reading back new configuration...");
    let r = read_cmd(stream, cfg_flash_addr, b.len() as u32)?;
    if b != r {
        for (i, (&wrote, &read)) in b.iter().zip(&r).enumerate() {
            if wrote != read {
                let flash_addr = cfg_flash_addr + i as u32;
                return Err(Error::ReadMismatch { flash_addr, wrote, read });
            }
        }
    }

    log::info!("Readback successful.");
    Ok(())
}
