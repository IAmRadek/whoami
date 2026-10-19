// AppKit calls raylib does not expose, sent through the Objective-C runtime.
// objc_msgSend must be cast to the exact signature of each message before calling it.
use std::ffi::{CStr, OsStr, c_void};
use std::io;
use std::mem::transmute;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

type Id = *mut c_void;

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const i8) -> Id;
    fn sel_registerName(name: *const i8) -> Id;
    fn objc_msgSend();
}

unsafe extern "C" {
    fn getsockopt(socket: i32, level: i32, name: i32, value: *mut c_void, len: *mut u32) -> i32;
    fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut c_void, size: i32) -> i32;
    fn sysctl(
        name: *mut i32,
        namelen: u32,
        old: *mut c_void,
        oldlen: *mut usize,
        new: *mut c_void,
        newlen: usize,
    ) -> i32;
}

// the pid of the process on the other end of a Unix socket
pub fn peer_pid(socket: &UnixStream) -> Option<i32> {
    const SOL_LOCAL: i32 = 0;
    const LOCAL_PEERPID: i32 = 0x002;

    let mut pid: i32 = 0;
    let mut len = size_of::<i32>() as u32;
    let r = unsafe {
        getsockopt(
            socket.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &mut len,
        )
    };
    if r != 0 {
        eprintln!("whoami: LOCAL_PEERPID: {}", io::Error::last_os_error());
        return None;
    }
    Some(pid)
}

// the current directory of a process
pub fn cwd(pid: i32) -> Option<PathBuf> {
    const PROC_PIDVNODEPATHINFO: i32 = 9;
    // struct proc_vnodepathinfo starts with pvi_cdir, a vnode_info_path:
    // a 152-byte vnode_info, then the path in a MAXPATHLEN buffer
    const PATH_OFFSET: usize = 152;
    const MAXPATHLEN: usize = 1024;
    const SIZE: usize = 2 * (PATH_OFFSET + MAXPATHLEN);

    let mut info = [0u8; SIZE];
    let n = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast(),
            SIZE as i32,
        )
    };
    if n as usize != SIZE {
        eprintln!(
            "whoami: proc_pidinfo for pid {pid} returned {n} of {SIZE} bytes: {}",
            io::Error::last_os_error()
        );
        return None;
    }
    let path = CStr::from_bytes_until_nul(&info[PATH_OFFSET..PATH_OFFSET + MAXPATHLEN]).ok()?;
    Some(PathBuf::from(OsStr::from_bytes(path.to_bytes())))
}

// the command line of a process; KERN_PROCARGS2 gives argc, the executable path,
// NUL padding, then argc NUL-terminated arguments, then the environment
pub fn args(pid: i32) -> Option<Vec<String>> {
    const CTL_KERN: i32 = 1;
    const KERN_PROCARGS2: i32 = 49;

    let mut mib = [CTL_KERN, KERN_PROCARGS2, pid];
    let null = std::ptr::null_mut();
    // the first call gives the buffer size
    let mut len = 0;
    let mut buf = Vec::new();
    for _ in 0..2 {
        buf.resize(len, 0u8);
        let old = if len == 0 {
            null
        } else {
            buf.as_mut_ptr().cast()
        };
        if unsafe { sysctl(mib.as_mut_ptr(), 3, old, &mut len, null, 0) } != 0 {
            eprintln!(
                "whoami: KERN_PROCARGS2 for pid {pid}: {}",
                io::Error::last_os_error()
            );
            return None;
        }
    }
    buf.truncate(len);
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().unwrap()) as usize;
    let mut strings = buf[4..].split(|&b| b == 0).filter(|s| !s.is_empty());
    strings.next()?;
    Some(
        strings
            .take(argc)
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect(),
    )
}

unsafe fn app() -> Id {
    let f: unsafe extern "C" fn(Id, Id) -> Id =
        unsafe { transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe {
        f(
            objc_getClass(c"NSApplication".as_ptr()),
            sel_registerName(c"sharedApplication".as_ptr()),
        )
    }
}

// the messages below take one word-sized argument: an NSInteger, an NSUInteger or an object pointer
unsafe fn send(receiver: Id, selector: &CStr, arg: isize) {
    let f: unsafe extern "C" fn(Id, Id, isize) =
        unsafe { transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { f(receiver, sel_registerName(selector.as_ptr()), arg) }
}

// no Dock icon and no menu bar; call after raylib init, which sets the policy to regular
pub fn set_accessory() {
    const NS_APPLICATION_ACTIVATION_POLICY_ACCESSORY: isize = 1;
    unsafe {
        send(
            app(),
            c"setActivationPolicy:",
            NS_APPLICATION_ACTIVATION_POLICY_ACCESSORY,
        )
    }
}

// hides the app and gives focus back to the previously active app; 0 is a nil sender
pub fn hide() {
    unsafe { send(app(), c"hide:", 0) }
}

// shows the window on the active Space; by default it stays on the Space it was created on,
// and activating the app switches to that Space
//
// # Safety
// `window` must be a live NSWindow, such as raylib's `get_window_handle` returns on macOS
pub unsafe fn move_to_active_space(window: *mut c_void) {
    const NS_WINDOW_COLLECTION_BEHAVIOR_MOVE_TO_ACTIVE_SPACE: isize = 1 << 1;
    unsafe {
        send(
            window,
            c"setCollectionBehavior:",
            NS_WINDOW_COLLECTION_BEHAVIOR_MOVE_TO_ACTIVE_SPACE,
        )
    }
}
