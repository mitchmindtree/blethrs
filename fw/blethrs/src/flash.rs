use core;
use crate::{Error, Result};
use crate::stm32;

pub use blethrs_shared::CONFIG_MAGIC;
pub use blethrs_shared::flash::{SECTOR_ADDRESSES, END, CONFIG, USER};

static mut FLASH: Option<stm32::FLASH> = None;

/// Call to move the flash peripheral into this module
pub fn init(flash: stm32::FLASH) {
    unsafe { FLASH = Some(flash) };
}

/// User configuration.
///
/// - Must live in flash at `flash::CONFIG`.
/// - `magic` must be set to `flash::CONFIG_MAGIC`.
/// - `checksum` must be the CRC32 of the preceeding bytes.
#[derive(Copy,Clone)]
#[repr(C,packed)]
pub struct UserConfig {
    magic: u32,
    pub mac_address: [u8; 6],
    pub ip_address: [u8; 4],
    pub ip_gateway: [u8; 4],
    pub ip_prefix: u8,
    _padding: [u8; 1],
    checksum: u32,
}

impl UserConfig {
    pub fn new(
        mac_address: [u8; 6],
        ip_address: [u8; 4],
        ip_gateway: [u8; 4],
        ip_prefix: u8,
    ) -> Self {
        UserConfig {
            magic: 0,
            mac_address,
            ip_address,
            ip_gateway,
            ip_prefix,
            _padding: [0u8; 1],
            checksum: 0,
        }
    }

    /// Attempt to read the UserConfig from flash.
    ///
    /// This method checks that the `CONFIG_MAGIC` is set, but does *not* check the crc checksum.
    pub fn get_unchecked() -> Option<UserConfig> {
        // Read config from flash
        let cfg = unsafe { *(CONFIG as *const UserConfig) };

        // Check magic is correct
        if cfg.magic != CONFIG_MAGIC {
            None
        } else {
            Some(cfg.clone())
        }
    }

    /// Attempt to read the UserConfig from flash sector 3 at 0x0800_C000.
    /// If a valid config cannot be read, the default one is returned instead.
    pub fn get(crc: &mut stm32::CRC) -> Option<UserConfig> {
        let cfg = Self::get_unchecked()?;

        // Validate checksum
        let adr = CONFIG as *const u32;
        let len = core::mem::size_of::<UserConfig>() / 4;
        crc.cr.write(|w| w.reset().reset());
        for idx in 0..(len - 1) {
            let val = unsafe { *(adr.offset(idx as isize)) };
            crc.dr.write(|w| w.dr().bits(val));
        }
        let crc_computed = crc.dr.read().dr().bits();

        if crc_computed == cfg.checksum {
            Some(cfg.clone())
        } else {
            None
        }
    }
}

/// Try to determine if there is valid code in the user flash at 0x0801_0000.
/// Returns Some(u32) with the address to jump to if so, and None if not.
pub fn valid_user_code() -> Option<u32> {
    let reset_vector: u32 = unsafe { *((USER + 4) as *const u32) };
    if reset_vector >= USER && reset_vector <= END {
        Some(USER)
    } else {
        None
    }
}

/// Check if address+length is valid for read/write flash.
fn check_address_valid(address: u32, length: usize) -> Result<()> {
    if address < CONFIG {
        Err(Error::InvalidAddress)
    } else if address > (END - length as u32 + 1) {
        Err(Error::InvalidAddress)
    } else{
        Ok(())
    }
}

/// Check length is a multiple of 4 and no greater than 1024
fn check_length_valid(length: usize) -> Result<()> {
    if length % 4 != 0 {
        Err(Error::LengthNotMultiple4)
    } else if length > 1024 {
        Err(Error::LengthTooLong)
    } else {
        Ok(())
    }
}

/// Check the specified length matches the amount of data available
fn check_length_correct(length: usize, data: &[u8]) -> Result<()> {
    if length != data.len() {
        Err(Error::DataLengthIncorrect)
    } else {
        Ok(())
    }
}

/// Try to get the FLASH peripheral
fn get_flash_peripheral() -> Result<&'static mut stm32::FLASH> {
    match unsafe { FLASH.as_mut() } {
        Some(flash) => Ok(flash),
        None => Err(Error::InternalError),
    }
}

/// Try to unlock flash
fn unlock(flash: &mut stm32::FLASH) -> Result<()> {
    // Wait for any ongoing operations
    while flash.sr.read().bsy().bit_is_set() {}

    // Attempt unlock
    // TODO: Unsafe required for stm32f1, remove once new version is released.
    #[allow(unused_unsafe)]
    unsafe {
        flash.keyr.write(|w| w.key().bits(0x45670123));
        flash.keyr.write(|w| w.key().bits(0xCDEF89AB));
    }

    // Verify success
    match check::is_unlocked(&flash.cr) {
        true => Ok(()),
        false => Err(Error::FlashError),
    }
}

/// Lock flash
fn lock(flash: &mut stm32::FLASH) {
    #[cfg(feature = "stm32f407")]
    flash.cr.write(|w| w.lock().locked());
    #[cfg(feature = "stm32f107")]
    {
        while flash.sr.read().bsy().bit_is_set() {}
        flash.cr.write(|w| w.lock().set_bit());
    }
}

/// Erase flash sectors that cover the given address and length.
pub fn erase(address: u32, length: usize) -> Result<()> {
    check_address_valid(address, length)?;
    let address_start = address;
    let address_end = address + length as u32;
    for (idx, sector_start) in SECTOR_ADDRESSES.iter().enumerate() {
        let sector_start = *sector_start;
        let sector_end = match SECTOR_ADDRESSES.get(idx + 1) {
            Some(adr) => *adr - 1,
            None => END,
        };
        if (address_start >= sector_start && address_start <= sector_end) ||
           (address_end   >= sector_start && address_end   <= sector_end) ||
           (address_start <= sector_start && address_end   >= sector_end) {
               erase_sector(idx as u8)?;
        }
    }
    Ok(())
}

/// Erase specified sector
fn erase_sector(sector: u8) -> Result<()> {
    if (sector as usize) >= SECTOR_ADDRESSES.len() {
        return Err(Error::InternalError);
    }
    let flash = get_flash_peripheral()?;
    unlock(flash)?;

    // Erase.
    // UNSAFE: We've verified that `sector`<SECTOR_ADDRESSES.len(),
    // which is is the number of sectors.
    #[cfg(feature = "stm32f407")]
    unsafe {
        flash.cr.write(|w| w.lock().unlocked().ser().sector_erase().snb().bits(sector));
        flash.cr.modify(|_, w| w.strt().start());
    }
    #[cfg(feature = "stm32f107")]
    unsafe {
        //flash.cr.modify(|_, w| w.lock().clear_bit().per().set_bit());
        flash.cr.modify(|_, w| w.per().set_bit());
        flash.ar.write(|w| w.far().bits(SECTOR_ADDRESSES[sector as usize]));
        flash.cr.modify(|_, w| w.strt().set_bit());
    }

    // Wait
    while flash.sr.read().bsy().bit_is_set() {}

    #[cfg(feature = "stm32f107")]
    flash.cr.modify(|_, w| w.per().clear_bit());

    // Re-lock flash
    lock(flash);

    if check::erase_err(&flash.sr) {
        Err(Error::EraseError)
    } else {
        // Verify
        #[cfg(feature = "stm32f107")]
        {
            let start = SECTOR_ADDRESSES[sector as usize];
            let end = start + (0x0800 - 1);

            for addr in start..end {
                let write_address = addr as *const u16;
                let verify: u16 = unsafe { core::ptr::read_volatile(write_address) };
                if verify != 0xFFFF {
                    return Err(Error::EraseError);
                }
            }
        }

        Ok(())
    }
}

/// Read from flash.
/// Returns a &[u8] if the address and length are valid.
/// length must be a multiple of 4.
pub fn read(address: u32, length: usize) -> Result<&'static [u8]> {
    check_address_valid(address, length)?;
    check_length_valid(length)?;
    let address = address as *const _;
    unsafe {
        Ok(core::slice::from_raw_parts::<'static, u8>(address, length))
    }
}

/// Write to flash.
/// Returns () on success, None on failure.
/// length must be a multiple of 4.
pub fn write(address: u32, length: usize, data: &[u8]) -> Result<()> {
    check_address_valid(address, length)?;
    check_length_valid(length)?;
    check_length_correct(length, data)?;
    let flash = get_flash_peripheral()?;
    unlock(flash)?;

    // Set parallelism to write in 32 bit chunks, and enable programming.
    // Note reset value has 1 for lock so we need to explicitly clear it.
    flash.cr.write(|w| {
        #[cfg(feature = "stm32f407")]
        let w = w.lock().unlocked().psize().psize32().pg().program();
        #[cfg(feature = "stm32f107")]
        let w = w.lock().clear_bit().pg().set_bit();
        w
    });

    // Write 1 word at a time on stm32f407.
    #[cfg(feature = "stm32f407")]
    let step = core::mem::size_of::<u32>();
    // Write half a word at a time on stm32f107.
    #[cfg(feature = "stm32f107")]
    let step = core::mem::size_of::<u16>();
    for idx in (0..data.len()).step_by(step) {
        #[cfg(feature = "stm32f407")]
        {
            let write_address = (address + idx as u32) as *mut u32;
            let word: u32 =
                  (data[idx]   as u32)
                | (data[idx+1] as u32) << 8
                | (data[idx+2] as u32) << 16
                | (data[idx+3] as u32) << 24;
            unsafe { core::ptr::write_volatile(write_address, word) };
        }

        #[cfg(feature = "stm32f107")]
        {
            // TODO: `FlashWriter` implementation in `stm32f1xx-hal` sets `pg` before each half word and
            // resets it after each half word - do we have to do that? Seems unnecessary?
            let write_address = (address + idx as u32) as *mut u16;
            let hword: u16 = (data[idx] as u16) | (data[idx + 1] as u16) << 8;
            unsafe { core::ptr::write_volatile(write_address, hword) };
        }

        // Wait for write
        while flash.sr.read().bsy().bit_is_set() {}

        // Check for errors
        if check::write_err(&flash.sr) {
            lock(flash);
            return Err(Error::WriteError);
        }
    }

    lock(flash);

    Ok(())
}

#[cfg(feature = "stm32f407")]
mod check {
    pub fn erase_err(sr: &crate::stm32::flash::SR) -> bool {
        sr.read().wrperr().bit_is_set()
    }

    pub fn write_err(sr: &crate::stm32::flash::SR) -> bool {
        let sr = sr.read();
        sr.pgserr().bit_is_set() || sr.pgperr().bit_is_set() ||
        sr.pgaerr().bit_is_set() || sr.wrperr().bit_is_set()
    }

    pub fn is_unlocked(cr: &crate::stm32::flash::CR) -> bool {
        cr.read().lock().is_unlocked()
    }
}

#[cfg(feature = "stm32f107")]
mod check {
    pub fn erase_err(sr: &crate::stm32::flash::SR) -> bool {
        sr.read().wrprterr().bit_is_set()
    }

    pub fn write_err(sr: &crate::stm32::flash::SR) -> bool {
        let sr = sr.read();
        sr.pgerr().bit_is_set() || sr.wrprterr().bit_is_set()
    }

    pub fn is_unlocked(cr: &crate::stm32::flash::CR) -> bool {
        cr.read().lock().bit_is_clear()
    }
}
