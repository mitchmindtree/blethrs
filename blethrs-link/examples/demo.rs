use blethrs_link as link;
use blethrs_shared::flash;
use std::io;
use std::path::Path;
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

// The max number of bytes of a binary file to send via TCP at once.
// Should consider your network's MTU.
const CHUNK_SIZE: usize = 512;

fn main() {
    env_logger::init();

    let mut args = std::env::args();

    let ip_addr_s = args.nth(1).expect("expected IP address string");
    let port_s = args.next().expect("expected port string");
    let cmd_s = args.next().expect("expected command string");

    let addr: SocketAddr = format!("{}:{}", ip_addr_s, port_s)
        .parse::<SocketAddrV4>()
        .expect("failed to parse valid socket address")
        .into();

    println!("Connecting to bootloader...");
    let mut stream = connect(&addr).unwrap();
    let data = link::info_cmd(&mut stream).unwrap();
    let s = std::str::from_utf8(&data).unwrap();
    println!("{}", s);

    match &cmd_s[..] {
        "program" => {
            let bin_path_s = args.next().expect("expected path to binary");
            let bin_path = Path::new(&bin_path_s);
            let chunk_size = CHUNK_SIZE;
            let flash_addr = flash::USER;
            let bin_data = std::fs::read(&bin_path).unwrap();
            link::write_file(&mut stream, chunk_size, flash_addr, bin_data).unwrap();
        }
        "configure" => {
            let cfg_flash_addr = flash::CONFIG;
            // TODO: These are just for testing - take these via arguments.
            let ip = [10, 101, 0, 1];
            let mac = [0x00, 0x00, 0xAB, 0xCD, ip[2], ip[3]];
            let gw = [ip[0], ip[1], ip[2], 0];
            let prefix = 16;
            link::write_config(&mut stream, cfg_flash_addr, &mac, &ip, &gw, prefix).unwrap();
        }
        _ => (),
    }

    match &cmd_s[..] {
        "boot" | "program" | "configure" => {
            println!("Sending reboot command...");
            link::boot_cmd(&mut stream).unwrap();
        }
        _ => (),
    }
}

fn connect(addr: &SocketAddr) -> Result<TcpStream, io::Error> {
    let timeout = Duration::from_secs(3);
    let mut attempts = 3;
    loop {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => match e.kind() {
                // Sometimes we get connection refused if the MCU is still busy.
                io::ErrorKind::ConnectionRefused if attempts > 0 => {
                    attempts -= 1;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                _ => return Err(e),
            }
        }
    }
}
