//! Locks the screen with the private function behind Ctrl-Cmd-Q. It is loaded at run time, so a
//! macOS without it shows an error instead of failing to start.

use std::ffi::c_void;

#[derive(Clone, Copy)]
pub struct Screen(unsafe extern "C" fn() -> i32);

impl Screen {
    pub fn load() -> Option<Self> {
        let path = c"/System/Library/PrivateFrameworks/login.framework/login";
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_LAZY) };
        if handle.is_null() {
            return None;
        }
        let symbol = unsafe { libc::dlsym(handle, c"SACLockScreenImmediate".as_ptr()) };
        if symbol.is_null() {
            return None;
        }
        // The function takes no arguments and returns a status code.
        let lock =
            unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> i32>(symbol) };
        Some(Self(lock))
    }

    pub fn lock(&self) {
        unsafe { (self.0)() };
    }
}

#[cfg(test)]
mod tests;
