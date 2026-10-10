// AppKit calls raylib does not expose, sent through the Objective-C runtime.
// objc_msgSend must be cast to the exact signature of each message before calling it.
use std::ffi::{CStr, c_void};
use std::mem::transmute;

type Id = *mut c_void;

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const i8) -> Id;
    fn sel_registerName(name: *const i8) -> Id;
    fn objc_msgSend();
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

// both messages below take one word-sized argument: an NSInteger or an object pointer
unsafe fn send(selector: &CStr, arg: isize) {
    let f: unsafe extern "C" fn(Id, Id, isize) =
        unsafe { transmute(objc_msgSend as unsafe extern "C" fn()) };
    unsafe { f(app(), sel_registerName(selector.as_ptr()), arg) }
}

// no Dock icon and no menu bar; call after raylib init, which sets the policy to regular
pub fn set_accessory() {
    const NS_APPLICATION_ACTIVATION_POLICY_ACCESSORY: isize = 1;
    unsafe {
        send(
            c"setActivationPolicy:",
            NS_APPLICATION_ACTIVATION_POLICY_ACCESSORY,
        )
    }
}

// hides the app and gives focus back to the previously active app; 0 is a nil sender
pub fn hide() {
    unsafe { send(c"hide:", 0) }
}
