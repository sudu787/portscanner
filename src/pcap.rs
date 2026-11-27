//! pcap.rs — just enough libpcap / Npcap for the SYN scanner, loaded at run
//! time (dlopen / LoadLibrary) instead of linked. The binary therefore starts
//! and connect-scans on machines without Npcap; only `--syn` needs it.

use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CStr, CString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

#[repr(C)]
struct PktHdr {
    // `struct timeval`: two C longs on Windows/Linux; on macOS (i64, i32)
    // padded to 16 bytes — same offsets on every 64-bit target.
    _sec: c_long,
    _usec: c_long,
    caplen: u32,
    _len: u32,
}

#[repr(C)]
struct BpfProgram {
    _len: c_uint,
    _insns: *mut c_void,
}

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    _description: *mut c_char,
    addresses: *mut PcapAddr,
    flags: c_uint,
}

#[repr(C)]
struct PcapAddr {
    next: *mut PcapAddr,
    addr: *const u8, // struct sockaddr *
    _netmask: *const u8,
    _broadaddr: *const u8,
    _dstaddr: *const u8,
}

type Pcap = c_void;
const ERRBUF: usize = 256;
const PCAP_IF_LOOPBACK: c_uint = 1;

struct Lib {
    findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int,
    freealldevs: unsafe extern "C" fn(*mut PcapIf),
    open_live: unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut Pcap,
    datalink: unsafe extern "C" fn(*mut Pcap) -> c_int,
    compile: unsafe extern "C" fn(*mut Pcap, *mut BpfProgram, *const c_char, c_int, u32) -> c_int,
    setfilter: unsafe extern "C" fn(*mut Pcap, *mut BpfProgram) -> c_int,
    freecode: unsafe extern "C" fn(*mut BpfProgram),
    next_ex: unsafe extern "C" fn(*mut Pcap, *mut *mut PktHdr, *mut *const u8) -> c_int,
    sendpacket: unsafe extern "C" fn(*mut Pcap, *const u8, c_int) -> c_int,
    geterr: unsafe extern "C" fn(*mut Pcap) -> *mut c_char,
    setnonblock: unsafe extern "C" fn(*mut Pcap, c_int, *mut c_char) -> c_int,
    close: unsafe extern "C" fn(*mut Pcap),
    _lib: libloading::Library,
}

fn load() -> Result<Lib, String> {
    let lib = open_library()?;
    // SAFETY: the signatures match the libpcap API; the Library is stored
    // next to the pointers, so they never outlive it.
    unsafe {
        macro_rules! sym {
            ($name:literal) => {
                *lib.get(concat!($name, "\0").as_bytes())
                    .map_err(|e| format!("{}: {e}", $name))?
            };
        }
        Ok(Lib {
            findalldevs: sym!("pcap_findalldevs"),
            freealldevs: sym!("pcap_freealldevs"),
            open_live: sym!("pcap_open_live"),
            datalink: sym!("pcap_datalink"),
            compile: sym!("pcap_compile"),
            setfilter: sym!("pcap_setfilter"),
            freecode: sym!("pcap_freecode"),
            next_ex: sym!("pcap_next_ex"),
            sendpacket: sym!("pcap_sendpacket"),
            geterr: sym!("pcap_geterr"),
            setnonblock: sym!("pcap_setnonblock"),
            close: sym!("pcap_close"),
            _lib: lib,
        })
    }
}

#[cfg(windows)]
fn open_library() -> Result<libloading::Library, String> {
    use libloading::os::windows::{Library, LOAD_WITH_ALTERED_SEARCH_PATH};
    // Npcap installs into System32\Npcap (WinPcap-compatible mode adds a copy
    // to System32). The altered search path lets wpcap.dll find Packet.dll.
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let npcap = format!(r"{root}\System32\Npcap\wpcap.dll");
    // SAFETY: loading the system packet-capture library runs its initialisers.
    unsafe {
        Library::load_with_flags(&npcap, LOAD_WITH_ALTERED_SEARCH_PATH)
            .or_else(|_| Library::new("wpcap.dll"))
            .map(Into::into)
            .map_err(|_| {
                "SYN scan on Windows needs Npcap (https://npcap.com) — install it, or drop --syn"
                    .to_string()
            })
    }
}

#[cfg(not(windows))]
fn open_library() -> Result<libloading::Library, String> {
    let names: &[&str] = if cfg!(target_os = "macos") {
        &[
            "libpcap.A.dylib",
            "/usr/lib/libpcap.A.dylib",
            "libpcap.dylib",
        ]
    } else {
        &["libpcap.so.1", "libpcap.so.0.8", "libpcap.so"]
    };
    names
        .iter()
        // SAFETY: loading the system libpcap runs its initialisers.
        .find_map(|n| unsafe { libloading::Library::new(n).ok() })
        .ok_or_else(|| {
            "SYN scan needs libpcap (e.g. `apt install libpcap0.8`) — or drop --syn".into()
        })
}

fn lib() -> io::Result<&'static Lib> {
    static LIB: OnceLock<Result<Lib, String>> = OnceLock::new();
    LIB.get_or_init(load)
        .as_ref()
        .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e.clone()))
}

/// `AF_INET6` differs per OS (as seen in libpcap's `sockaddr`s).
const AF_INET6: u16 = if cfg!(windows) {
    23
} else if cfg!(target_os = "macos") {
    30
} else {
    10
};

/// IP address in a `struct sockaddr` (BSDs: `u8 len, u8 family`; else `u16 family`).
///
/// SAFETY: `sa` is null or points to a sockaddr of the family it declares.
unsafe fn sockaddr_ip(sa: *const u8) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let fam = if cfg!(target_os = "macos") {
        *sa.add(1) as u16
    } else {
        u16::from_ne_bytes([*sa, *sa.add(1)])
    };
    match fam {
        2 => Some(Ipv4Addr::from(*(sa.add(4) as *const [u8; 4])).into()),
        f if f == AF_INET6 => Some(Ipv6Addr::from(*(sa.add(8) as *const [u8; 16])).into()),
        _ => None,
    }
}

/// Name of the capture device that owns `src` (the loopback device for a
/// loopback address that no device lists, as with Npcap's loopback adapter).
pub fn device_for(src: IpAddr) -> io::Result<String> {
    let lib = lib()?;
    let mut err = [0 as c_char; ERRBUF];
    let mut devs: *mut PcapIf = std::ptr::null_mut();
    // SAFETY: valid out-pointer and errbuf; the list is freed below.
    if unsafe { (lib.findalldevs)(&mut devs, err.as_mut_ptr()) } != 0 {
        return Err(io::Error::other(cstr(err.as_ptr())));
    }
    let (mut by_addr, mut loopback) = (None, None);
    let mut d = devs;
    // SAFETY: walking the linked lists libpcap returned, before freeing them.
    unsafe {
        while !d.is_null() {
            let name = cstr((*d).name);
            let mut a = (*d).addresses;
            while !a.is_null() {
                if sockaddr_ip((*a).addr) == Some(src) {
                    by_addr.get_or_insert_with(|| name.clone());
                }
                a = (*a).next;
            }
            if (*d).flags & PCAP_IF_LOOPBACK != 0 {
                loopback.get_or_insert(name);
            }
            d = (*d).next;
        }
        (lib.freealldevs)(devs);
    }
    by_addr
        .or(loopback.filter(|_| src.is_loopback()))
        .ok_or_else(|| io::Error::other(format!("no capture device has address {src}")))
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: libpcap strings are NUL-terminated.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// An open capture handle (one thread at a time).
pub struct Capture {
    p: *mut Pcap,
    lib: &'static Lib,
}

// SAFETY: a pcap_t may move between threads; it's never shared.
unsafe impl Send for Capture {}

impl Capture {
    pub fn open(dev: &str) -> io::Result<Self> {
        let lib = lib()?;
        let name = CString::new(dev).map_err(io::Error::other)?;
        let mut err = [0 as c_char; ERRBUF];
        // snaplen 256 (headers only), not promiscuous, 20 ms read timeout.
        // SAFETY: valid C string and errbuf.
        let p = unsafe { (lib.open_live)(name.as_ptr(), 256, 0, 20, err.as_mut_ptr()) };
        if p.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "SYN scan can't open {dev}: {} — run as root / Administrator, or drop --syn",
                    cstr(err.as_ptr())
                ),
            ));
        }
        // Non-blocking: on Linux a blocking read can wait forever once
        // traffic stops (the read timeout only fires after a first packet),
        // and the receiver must notice the end of the scan.
        // SAFETY: live handle, valid errbuf.
        unsafe { (lib.setnonblock)(p, 1, err.as_mut_ptr()) };
        Ok(Self { p, lib })
    }

    /// Link-layer type (`DLT_*`).
    pub fn datalink(&self) -> i32 {
        // SAFETY: live handle.
        unsafe { (self.lib.datalink)(self.p) }
    }

    /// Install a BPF filter (tcpdump syntax).
    pub fn filter(&mut self, expr: &str) -> io::Result<()> {
        let expr = CString::new(expr).map_err(io::Error::other)?;
        let mut prog = BpfProgram {
            _len: 0,
            _insns: std::ptr::null_mut(),
        };
        // SAFETY: live handle, valid program struct; freed after use.
        unsafe {
            if (self.lib.compile)(self.p, &mut prog, expr.as_ptr(), 1, 0xffff_ffff) != 0 {
                return Err(self.error());
            }
            let rc = (self.lib.setfilter)(self.p, &mut prog);
            (self.lib.freecode)(&mut prog);
            if rc != 0 {
                return Err(self.error());
            }
        }
        Ok(())
    }

    /// Next captured frame, or `None` (after a 1 ms pause) if none is waiting.
    pub fn next_frame(&mut self) -> Option<&[u8]> {
        let mut hdr: *mut PktHdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        // SAFETY: live handle; on success libpcap points hdr/data at a frame
        // valid until the next call, which `&mut self` enforces.
        unsafe {
            if (self.lib.next_ex)(self.p, &mut hdr, &mut data) != 1 || data.is_null() {
                std::thread::sleep(std::time::Duration::from_millis(1));
                return None;
            }
            Some(std::slice::from_raw_parts(data, (*hdr).caplen as usize))
        }
    }

    /// Inject one link-layer frame.
    pub fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: live handle, valid buffer.
        if unsafe { (self.lib.sendpacket)(self.p, frame.as_ptr(), frame.len() as c_int) } != 0 {
            return Err(self.error());
        }
        Ok(())
    }

    fn error(&self) -> io::Error {
        // SAFETY: live handle.
        io::Error::other(cstr(unsafe { (self.lib.geterr)(self.p) }))
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // SAFETY: closed exactly once.
        unsafe { (self.lib.close)(self.p) }
    }
}
