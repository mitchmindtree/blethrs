//! Items shared between `blethrs` (firmware) and `blethrs-link` (software).

#![no_std]

#[derive(Debug)]
#[repr(u32)]
pub enum Command {
    Info = 0,
    Read = 1,
    Erase = 2,
    Write = 3,
    Boot = 4,
}

pub struct UnknownValue;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Success = 0,
    InvalidAddress = 1,
    LengthNotMultiple4 = 2,
    LengthTooLong = 3,
    DataLengthIncorrect = 4,
    EraseError = 5,
    WriteError = 6,
    FlashError = 7,
    NetworkError = 8,
    InternalError = 9,
}

pub const CONFIG_MAGIC: u32 = 0x67797870;

#[cfg(feature = "stm32f407")]
pub mod flash {
    /// Start address of each sector in flash
    pub const SECTOR_ADDRESSES: [u32; 12] = [
        0x0800_0000, 0x0800_4000, 0x0800_8000, 0x0800_C000,
        0x0801_0000, 0x0802_0000, 0x0804_0000, 0x0806_0000,
        0x0808_0000, 0x080A_0000, 0x080C_0000, 0x080E_0000,
    ];
    /// Final valid address in flash
    pub const END: u32 = 0x080F_FFFF;
    /// Address of configuration sector. Must be one of the start addresses in SECTOR_ADDRESSES.
    pub const CONFIG: u32 = SECTOR_ADDRESSES[3];
    /// Address of user firmware sector. Must be one of the start addresses in SECTOR_ADDRESSES.
    pub const USER: u32 = SECTOR_ADDRESSES[4];
}

#[cfg(feature = "stm32f107")]
pub mod flash {
    macro_rules! sector_addresses {
        ($($page_ix:expr)*) => {
            [
                $(
                    0x0800_0000 + $page_ix * 0x0800,
                )*
            ]
        };
    }
    /// Start address of each page (aka sector) in flash.
    pub const SECTOR_ADDRESSES: [u32; 128] = sector_addresses!(
        0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
        16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
        32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47
        48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63
        64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79
        80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95
        96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111
        112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127
    );
    /// Final valid address in flash.
    pub const END: u32 = SECTOR_ADDRESSES[SECTOR_ADDRESSES.len() - 1] + (0x0800 - 1);
    /// Address of configuration sector. Must be one of the start addresses in SECTOR_ADDRESSES.
    pub const CONFIG: u32 = SECTOR_ADDRESSES[24];
    /// Address of user firmware sector. Must be one of the start addresses in SECTOR_ADDRESSES.
    pub const USER: u32 = SECTOR_ADDRESSES[25];
}

impl core::convert::TryFrom<u32> for Command {
    type Error = UnknownValue;
    fn try_from(u: u32) -> Result<Self, Self::Error> {
        let cmd = match u {
            0 => Command::Info,
            1 => Command::Read,
            2 => Command::Erase,
            3 => Command::Write,
            4 => Command::Boot,
            _ => return Err(UnknownValue),
        };
        Ok(cmd)
    }
}

impl core::convert::TryFrom<u32> for Error {
    type Error = UnknownValue;
    fn try_from(u: u32) -> Result<Self, Self::Error> {
        let cmd = match u {
            0 => Error::Success,
            1 => Error::InvalidAddress,
            2 => Error::LengthNotMultiple4,
            3 => Error::LengthTooLong,
            4 => Error::DataLengthIncorrect,
            5 => Error::EraseError,
            6 => Error::WriteError,
            7 => Error::FlashError,
            8 => Error::NetworkError,
            9 => Error::InternalError,
            _ => return Err(UnknownValue),
        };
        Ok(cmd)
    }
}
