#![no_main]
#![no_std]

use blethrs::stm32;
use blethrs::flash::UserConfig;
use core::convert::TryFrom;
use panic_rtt_target as _;
use rtic::app;
use rtic::cyccnt::U32Ext as CyccntU32Ext;
use rtt_target::{rtt_init_print, rprintln};
use smoltcp::{
    iface::{EthernetInterfaceBuilder, Neighbor, NeighborCache},
    socket::{SocketHandle, SocketSetItem, TcpSocket, TcpSocketBuffer},
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr},
};
use stm32_eth::{
    {EthPins, PhyAddress, RingEntry, RxDescriptor, TxDescriptor},
    hal::gpio::GpioExt,
    hal::rcc::RccExt,
    hal::time::U32Ext as TimeU32Ext,
};

// Pull in build information (from `built` crate).
mod build_info {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

// Default values that may otherwise be configured via flash.
mod default {
    const MAC_ADDR: [u8; 6] = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    const IP_ADDR: [u8; 4] = [10, 101, 0, 1];
    const IP_GATE: [u8; 4] = [IP_ADDR[0], IP_ADDR[1], IP_ADDR[2], 1];
    const IP_PREFIX: u8 = 16;

    pub fn config() -> blethrs::flash::UserConfig {
        blethrs::flash::UserConfig::new(MAC_ADDR, IP_ADDR, IP_GATE, IP_PREFIX)
    }
}

type Eth = stm32_eth::Eth<'static, 'static>;
type EthernetInterface = smoltcp::iface::EthernetInterface<'static, 'static, 'static, &'static mut Eth>;
type SocketSet = smoltcp::socket::SocketSet<'static, 'static, 'static>;

#[cfg(feature = "stm32f407")]
const CYCLE_HZ: u32 = 168_000_000;
#[cfg(feature = "stm32f107")]
const CYCLE_HZ: u32 = 72_000_000;
const ONE_SEC: u32 = CYCLE_HZ;
const ONE_MS: u32 = ONE_SEC / 1_000;
const PORT: u16 = 10101;
const MTU: usize = 1536;

#[app(device = blethrs::stm32, peripherals = true, monotonic = rtic::cyccnt::CYCCNT)]
const APP: () = {
    struct Resources {
        #[init(0)]
        now_ms: u32,
        #[init(None)]
        reset_ms: Option<u32>,
        eth_iface: EthernetInterface,
        sockets: SocketSet,
        server_handle: SocketHandle,
    }

    #[init(schedule = [every_ms, every_sec])]
    fn init(mut cx: init::Context) -> init::LateResources {
        rtt_init_print!();

        let cause = match blethrs::flash::valid_user_code() {
            Some(address) if !blethrs::bootload::should_enter_bootloader(&mut cx.device.RCC) => {
                rprintln!("Loading user program!");
                blethrs::bootload::bootload(&mut cx.core.SCB, address);
                ""
            },
            Some(_addr) => "User indicated",
            None => "Invalid user program",
        };

        rprintln!("Running in bootload mode. Cause: {}.", cause);

        rprintln!("Setup clocks");
        cx.core.DWT.enable_cycle_counter();

        // Enable clock for CRC.
        // TODO: Do this for `stm32f107`?
        #[cfg(feature = "stm32f407")]
        cx.device.RCC.ahb1enr.modify(|_, w| w.crcen().enabled());

        // Need constrained flash for stm32f107 clock freeze method for some reason.
        #[cfg(feature = "stm32f107")]
        let mut flash = blethrs::hal::flash::FlashExt::constrain(cx.device.FLASH);

        #[allow(unused_mut)]
        let mut rcc = cx.device.RCC.constrain();

        #[cfg(feature = "stm32f407")]
        let clocks = rcc.cfgr.sysclk(CYCLE_HZ.hz()).freeze();
        #[cfg(feature = "stm32f107")]
        let clocks = rcc
            .cfgr
            .use_hse(8.mhz())
            .sysclk(CYCLE_HZ.hz())
            .hclk(CYCLE_HZ.hz())
            .pclk1((CYCLE_HZ / 2).hz())
            .freeze(&mut flash.acr);

        rprintln!("Reading user config");
        let cfg = match UserConfig::get(&mut cx.device.CRC) {
            Some(cfg) => cfg,
            None => {
                rprintln!("  No existing configuration. Using default.");
                default::config()
            },
        };

        rprintln!("Setup ethernet");
        #[cfg(feature = "stm32f407")]
        let eth_pins = {
            let gpioa = cx.device.GPIOA.split();
            let gpiob = cx.device.GPIOB.split();
            let gpioc = cx.device.GPIOC.split();
            EthPins {
                ref_clk: gpioa.pa1,
                md_io: gpioa.pa2,
                md_clk: gpioc.pc1,
                crs: gpioa.pa7,
                tx_en: gpiob.pb11,
                tx_d0: gpiob.pb12,
                tx_d1: gpiob.pb13,
                rx_d0: gpioc.pc4,
                rx_d1: gpioc.pc5,
            }
        };
        #[cfg(feature = "stm32f107")]
        let eth_pins = {
            let mut gpioa = cx.device.GPIOA.split(&mut rcc.apb2);
            let mut gpiob = cx.device.GPIOB.split(&mut rcc.apb2);
            let mut gpioc = cx.device.GPIOC.split(&mut rcc.apb2);
            let ref_clk = gpioa.pa1.into_floating_input(&mut gpioa.crl);
            let md_io = gpioa.pa2.into_alternate_push_pull(&mut gpioa.crl);
            let crs = gpioa.pa7.into_floating_input(&mut gpioa.crl);
            let md_clk = gpioc.pc1.into_alternate_push_pull(&mut gpioc.crl);
            let tx_en = gpiob.pb11.into_alternate_push_pull(&mut gpiob.crh);
            let tx_d0 = gpiob.pb12.into_alternate_push_pull(&mut gpiob.crh);
            let tx_d1 = gpiob.pb13.into_alternate_push_pull(&mut gpiob.crh);
            let rx_d0 = gpioc.pc4.into_floating_input(&mut gpioc.crl);
            let rx_d1 = gpioc.pc5.into_floating_input(&mut gpioc.crl);
            EthPins {
                ref_clk,
                md_io,
                md_clk,
                crs,
                tx_en,
                tx_d0,
                tx_d1,
                rx_d0,
                rx_d1,
            }
        };

        let eth = {
            static mut RX_RING: [RingEntry<RxDescriptor>; 8] = [
                RingEntry::<RxDescriptor>::new(),
                RingEntry::<RxDescriptor>::new(),
                RingEntry::<RxDescriptor>::new(),
                RingEntry::<RxDescriptor>::new(),
                RingEntry::<RxDescriptor>::new(),
                RingEntry::<RxDescriptor>::new(),
                RingEntry::<RxDescriptor>::new(),
                RingEntry::<RxDescriptor>::new(),
            ];
            static mut TX_RING: [RingEntry<TxDescriptor>; 2] = [
                RingEntry::<TxDescriptor>::new(),
                RingEntry::<TxDescriptor>::new(),
            ];
            static mut ETH: Option<Eth> = None;
            unsafe {
                let eth = Eth::new(
                    cx.device.ETHERNET_MAC,
                    cx.device.ETHERNET_DMA,
                    &mut RX_RING[..],
                    &mut TX_RING[..],
                    PhyAddress::_0,
                    clocks,
                    eth_pins,
                ).unwrap();
                ETH = Some(eth);
                ETH.as_mut().unwrap()
            }
        };

        eth.enable_interrupt();

        rprintln!("Setup TCP/IP");
        let [a0, a1, a2, a3] = cfg.ip_address;
        let ip_addr = IpCidr::new(IpAddress::v4(a0, a1, a2, a3), cfg.ip_prefix);
        let (ip_addrs, neighbor_storage) = {
            static mut IP_ADDRS: Option<[IpCidr; 1]> = None;
            static mut NEIGHBOR_STORAGE: [Option<(IpAddress, Neighbor)>; 16] = [None; 16];
            unsafe {
                IP_ADDRS = Some([ip_addr]);
                (IP_ADDRS.as_mut().unwrap(), &mut NEIGHBOR_STORAGE)
            }
        };
        let neighbor_cache = NeighborCache::new(&mut neighbor_storage[..]);
        let ethernet_addr = EthernetAddress(cfg.mac_address);
        let eth_iface = EthernetInterfaceBuilder::new(eth)
            .ethernet_addr(ethernet_addr)
            .ip_addrs(&mut ip_addrs[..])
            .neighbor_cache(neighbor_cache)
            .finalize();
        let (server_socket, mut sockets) = {
            static mut RX_BUFFER: [u8; MTU] = [0; MTU];
            static mut TX_BUFFER: [u8; MTU] = [0; MTU];
            static mut SOCKETS_STORAGE: [Option<SocketSetItem>; 2] = [None, None];
            unsafe {
                let server_socket = TcpSocket::new(
                    TcpSocketBuffer::new(&mut RX_BUFFER[..]),
                    TcpSocketBuffer::new(&mut TX_BUFFER[..]),
                );
                let sockets = SocketSet::new(&mut SOCKETS_STORAGE[..]);
                (server_socket, sockets)
            }
        };
        let server_handle = sockets.add(server_socket);

        // Move flash peripheral into flash module
        //
        // NOTE: Safety: blethrs wants to own the FLASH, but at the moment we have to constrain the
        // original `FLASH` in order to freeze the clocks for `STM32F107`. The `stm32f1xx-hal`
        // crate should probably be more flexible here.
        blethrs::flash::init(unsafe { stm32::Peripherals::steal().FLASH });

        // Schedule the `blink` and `every_ms` tasks.
        cx.schedule.every_ms(cx.start + ONE_MS.cycles()).unwrap();
        cx.schedule.every_sec(cx.start + ONE_SEC.cycles()).unwrap();

        rprintln!("Run!");
        init::LateResources { eth_iface, sockets, server_handle }
    }

    #[task(resources = [now_ms, reset_ms], schedule = [every_ms])]
    fn every_ms(mut cx: every_ms::Context) {
        let r = &mut cx.resources;
        *r.now_ms = r.now_ms.wrapping_add(1);

        // Check for a reset countdown.
        if let Some(ref mut ms) = *r.reset_ms {
            *ms = ms.saturating_sub(1);
            if *ms == 0 {
                blethrs::bootload::reset();
            }
        }

        cx.schedule.every_ms(cx.scheduled + ONE_MS.cycles()).unwrap();
    }

    #[task(resources = [now_ms], schedule = [every_sec])]
    fn every_sec(cx: every_sec::Context) {
        rprintln!("TICK: {} ms", cx.resources.now_ms);
        cx.schedule.every_sec(cx.scheduled + ONE_SEC.cycles()).unwrap();
    }

    #[task(binds = ETH, resources = [eth_iface, now_ms, sockets, server_handle, reset_ms])]
    fn eth(mut cx: eth::Context) {
        let r = &mut cx.resources;
        // Clear interrupt flags.
        r.eth_iface.device_mut().interrupt_handler();
        poll_eth_iface(r.eth_iface, r.sockets, *r.server_handle, *r.now_ms, r.reset_ms);
    }

    #[idle]
    fn idle(_: idle::Context) -> ! {
        loop {
            core::sync::atomic::spin_loop_hint();
        }
    }

    extern "C" {
        fn EXTI0();
    }
};

fn build_info() -> blethrs::cmd::BuildInfo<'static> {
    blethrs::cmd::BuildInfo {
        pkg_version: build_info::PKG_VERSION,
        git_version: build_info::GIT_VERSION.expect("no git version found"),
        built_time_utc: build_info::BUILT_TIME_UTC,
        rustc_version: build_info::RUSTC_VERSION,
    }
}

fn poll_eth_iface(
    iface: &mut EthernetInterface,
    sockets: &mut SocketSet,
    server_handle: SocketHandle,
    now_ms: u32,
    reset_ms: &mut Option<u32>,
) {
    rprintln!("poll_eth_iface");
    {
        let mut socket = sockets.get::<TcpSocket>(server_handle);
        handle_tcp(&mut socket, reset_ms);
    }

    let now = Instant::from_millis(now_ms as i64);
    if let Err(e) = iface.poll(sockets, now) {
        rprintln!("An error occurred when polling: {}", e);
    }
}

fn handle_tcp(socket: &mut TcpSocket, reset_ms: &mut Option<u32>) {
    if !socket.is_open() {
        rprintln!("Socket not open - attempting to listen.");
        if let Err(e) = socket.listen(PORT) {
            panic!("failed to listen on port {} of TCP socket: {}", PORT, e);
        }
    }

    if socket.may_recv() ^ socket.may_send() {
        rprintln!("Socket either could not recv ({}) or send ({}). Closing", socket.may_recv(), socket.may_send());
        socket.close();
    }

    if socket.can_recv() {
        rprintln!("Socket can receive! Reading cmd...");
        let mut cmd = [0u8; 4];
        socket.recv_slice(&mut cmd[..]).ok();
        let cmd_u32 = u32::from_le_bytes(cmd);
        match blethrs::cmd::Command::try_from(cmd_u32) {
            Err(_) => rprintln!("Received unknown command: {}", cmd_u32),
            Ok(cmd) => {
                rprintln!("{:?}", cmd);
                let build_info = build_info();
                let reboot = blethrs::cmd::handle_and_respond(cmd, &build_info, socket);
                rprintln!("Command handled.");
                if reboot {
                    rprintln!("Resetting...");
                    *reset_ms = Some(50);
                }
            },
        }
        socket.close();
    } else {
        rprintln!("Socket could not receive: {:?}", socket.state());
    }
}
