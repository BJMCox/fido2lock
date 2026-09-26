//! Reports FIDO devices (HID usage page 0xF1D0) as they appear and disappear. IOKit registry
//! notifications never open a device, so browsers and other key tools keep exclusive access.

use std::ffi::c_void;

use anyhow::{Context, Result, ensure};
use objc2_core_foundation::{
    CFDictionary, CFMutableDictionary, CFNumber, CFRetained, CFRunLoop, CFString,
    kCFRunLoopCommonModes,
};
use objc2_io_kit::{
    IOIteratorNext, IONotificationPort, IOObjectRelease, IORegistryEntryGetRegistryEntryID,
    IOServiceAddMatchingNotification, IOServiceMatching, io_iterator_t, kIOFirstMatchNotification,
    kIOMainPortDefault, kIOTerminatedNotification,
};

use crate::state::{Event, Id};

const FIDO_USAGE_PAGE: i32 = 0xF1D0;

struct Watch {
    handler: fn(Event),
    removed: bool,
}

/// Calls `handler` on the main run loop for every FIDO device, first for those already inserted.
pub fn start(handler: fn(Event)) -> Result<()> {
    unsafe {
        let port = IONotificationPort::create(kIOMainPortDefault);
        ensure!(!port.is_null(), "Cannot watch for security keys");
        let source =
            IONotificationPort::run_loop_source(port).context("Cannot watch for security keys")?;
        // Common modes deliver events while the menu is open, too.
        CFRunLoop::main()
            .context("No main run loop")?
            .add_source(Some(&source), kCFRunLoopCommonModes);
        for (kind, removed) in [
            (kIOFirstMatchNotification, false),
            (kIOTerminatedNotification, true),
        ] {
            // Lives as long as the process, like the notification that points to it.
            let watch: *mut Watch = Box::leak(Box::new(Watch { handler, removed }));
            let mut iterator = 0;
            let status = IOServiceAddMatchingNotification(
                port,
                kind.as_ptr() as _,
                Some(matching()?),
                Some(changed),
                watch.cast(),
                &mut iterator,
            );
            ensure!(
                status == 0,
                "Cannot watch for security keys (IOKit {status:#x})"
            );
            // Reports what is there now, and arms the notification.
            changed(watch.cast(), iterator);
        }
    }
    Ok(())
}

unsafe extern "C-unwind" fn changed(refcon: *mut c_void, iterator: io_iterator_t) {
    let watch = unsafe { &*refcon.cast::<Watch>() };
    loop {
        let service = IOIteratorNext(iterator);
        if service == 0 {
            break;
        }
        let mut id: Id = 0;
        let status = unsafe { IORegistryEntryGetRegistryEntryID(service, &mut id) };
        IOObjectRelease(service);
        if status == 0 {
            (watch.handler)(if watch.removed {
                Event::Removed(id)
            } else {
                Event::Appeared(id)
            });
        }
    }
}

/// IOHIDDevice services whose primary usage page is FIDO's. Each call makes a new dictionary,
/// because IOServiceAddMatchingNotification consumes one.
fn matching() -> Result<CFRetained<CFDictionary>> {
    let dict = unsafe { IOServiceMatching(c"IOHIDDevice".as_ptr()) }
        .context("Cannot build the IOKit match")?;
    let property = CFMutableDictionary::<CFString, CFNumber>::empty();
    property.add(
        &CFString::from_static_str("PrimaryUsagePage"),
        &CFNumber::new_i32(FIDO_USAGE_PAGE),
    );
    let key = CFString::from_static_str("IOPropertyMatch");
    // Both are CF objects, as the dictionary's CF callbacks expect.
    unsafe {
        CFMutableDictionary::set_value(
            Some(&dict),
            (&*key as *const CFString).cast(),
            (&*property as *const CFMutableDictionary<CFString, CFNumber>).cast(),
        )
    };
    Ok(unsafe { CFRetained::cast_unchecked(dict) })
}
