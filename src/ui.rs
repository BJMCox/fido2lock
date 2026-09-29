//! The menu-bar app: the menu, the key-management panels, the worker thread, and the glue between
//! the device watch, the state machine, and the screen lock.

use std::cell::{OnceCell, RefCell};
use std::sync::mpsc;

use anyhow::{Context, Result};
use dispatch2::{DispatchQueue, DispatchTime};
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{
    AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send, sel,
};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSControlStateValueOff, NSControlStateValueOn,
    NSImage, NSMenu, NSMenuDelegate, NSMenuItem, NSPasteboard, NSPasteboardTypeString, NSStatusBar,
    NSStatusItem, NSVariableStatusItemLength, NSWorkspace, NSWorkspaceDidWakeNotification,
    NSWorkspaceWillSleepNotification,
};
use objc2_foundation::{
    NSData, NSDictionary, NSDistributedNotificationCenter, NSNotification, NSNumber, NSObject,
    NSObjectProtocol, NSProcessInfo, NSSize, NSString, NSUserDefaults, ns_string,
};
use objc2_service_management::{SMAppService, SMAppServiceStatus};
use zeroize::Zeroizing;

use crate::config::{self, Config};
use crate::fido::{self, FidoError};
use crate::keys::{self, Key};
use crate::lock::Screen;
use crate::ops;
use crate::panels::{self, Button, Field, Form};
use crate::state::{Action, Check, Event, Outcome, State};
use crate::watch;

const REPOSITORY: &str = "https://github.com/BJMCox/fido2lock";
/// Posted by the terminal commands after they change the key list.
const KEYS_CHANGED: &str = "dev.fido2lock.keys";
const SET_UP_TEXT: &str = "Set up fido2lock with this security key. When you remove an enrolled key, fido2lock locks the screen. Enter a label for the key and its PIN, then touch it. Leave the PIN blank if the key has none.";
const ADD_TEXT: &str = "Insert the new security key. Enter a label for it and its PIN, then touch it. To take out an enrolled key during this, choose Pause first.";
const REMOVE_TEXT: &str = "Check the keys to remove. A removed key no longer arms the lock.";
const DELAY_PROBLEM: &str = "Lock delay must be a whole number of seconds from 0 to 60.";

thread_local! {
    /// The one controller. Device events and worker results find it here, on the main thread.
    static CONTROLLER: OnceCell<Retained<Controller>> = const { OnceCell::new() };
}

fn with_controller(f: impl FnOnce(&Controller)) {
    CONTROLLER.with(|cell| {
        if let Some(controller) = cell.get() {
            f(controller);
        }
    });
}

/// Runs `f` on the main thread. The main queue drains in the run loop's common modes, so results
/// arrive while the menu is open, and nothing polls.
fn on_main(f: impl FnOnce(&Controller) + Send + 'static) {
    DispatchQueue::main().exec_async(move || with_controller(f));
}

/// Runs all security-key work on one long-lived thread. hidapi binds its global HID manager to the
/// run loop of the first thread that uses it. A short-lived thread frees that run loop, and the
/// next device lookup then crashes in IOKit.
struct Worker(mpsc::Sender<Box<dyn FnOnce() + Send>>);

impl Default for Worker {
    fn default() -> Self {
        let (sender, jobs) = mpsc::channel::<Box<dyn FnOnce() + Send>>();
        std::thread::spawn(move || {
            for job in jobs {
                job();
            }
        });
        Self(sender)
    }
}

impl Worker {
    fn run(&self, job: impl FnOnce() + Send + 'static) {
        let _ = self.0.send(Box::new(job));
    }
}

/// A key-management form waiting for input.
struct Setup {
    step: Step,
    form: Form,
}

enum Step {
    /// `first` is Set Up, otherwise Add Security Key. `label` refills the form after a failure.
    Enroll {
        first: bool,
        label: String,
    },
    Remove,
    /// `typed` refills the field after a rejected save.
    Settings {
        typed: Option<String>,
    },
}

/// A flow that needs a chosen security key.
enum Flow {
    Enroll { first: bool, label: String },
    Check,
}

/// An open message panel. `retry` holds the flow that Retry restarts.
struct Message {
    form: Form,
    retry: Option<Flow>,
}

struct Menu {
    status: Retained<NSMenuItem>,
    warning: Retained<NSMenuItem>,
    pause: Retained<NSMenuItem>,
    resume: Retained<NSMenuItem>,
    set_up: Retained<NSMenuItem>,
    manage: Vec<Retained<NSMenuItem>>,
    login: Retained<NSMenuItem>,
    item: Retained<NSStatusItem>,
    armed_icon: Option<Retained<NSImage>>,
    open_icon: Option<Retained<NSImage>>,
    warning_icon: Option<Retained<NSImage>>,
}

struct Inner {
    state: State,
    screen: Option<Screen>,
    worker: Worker,
    menu: Option<Menu>,
    setup: Option<Setup>,
    message: Option<Message>,
    /// The panel that asks for a touch while a flow's job runs.
    touch: Option<Form>,
    /// A flow's job runs on the worker.
    busy: bool,
    /// The security key the current flow uses, chosen before its PIN is asked.
    key: Option<fido::Key>,
    /// The key list at the last check, so a change from elsewhere triggers a recheck.
    last_keys: Option<Vec<Key>>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "Fido2lockController"]
    #[ivars = RefCell<Inner>]
    struct Controller;

    unsafe impl NSObjectProtocol for Controller {}

    unsafe impl NSMenuDelegate for Controller {
        #[unsafe(method(menuWillOpen:))]
        fn menu_will_open(&self, _menu: &NSMenu) {
            self.sync_keys();
            self.refresh_menu();
        }
    }

    impl Controller {
        #[unsafe(method(keysChanged:))]
        fn keys_changed_elsewhere(&self, _notification: &NSNotification) {
            self.sync_keys();
        }

        #[unsafe(method(willSleep:))]
        fn will_sleep(&self, _notification: &NSNotification) {
            self.handle(Event::WillSleep);
        }

        #[unsafe(method(didWake:))]
        fn did_wake(&self, _notification: &NSNotification) {
            self.handle(Event::DidWake);
        }

        #[unsafe(method(openSettings:))]
        fn open_settings(&self, _sender: &AnyObject) {
            self.open_setup(Step::Settings { typed: None }, None);
        }

        #[unsafe(method(pause:))]
        fn pause(&self, _sender: &AnyObject) {
            self.handle(Event::Pause);
        }

        #[unsafe(method(resume:))]
        fn resume(&self, _sender: &AnyObject) {
            self.handle(Event::Resume);
        }

        #[unsafe(method(setUp:))]
        fn set_up(&self, _sender: &AnyObject) {
            self.with_key(Flow::Enroll { first: true, label: "primary".to_owned() });
        }

        #[unsafe(method(addKey:))]
        fn add_key(&self, _sender: &AnyObject) {
            self.with_key(Flow::Enroll { first: false, label: String::new() });
        }

        #[unsafe(method(checkKey:))]
        fn check_key(&self, _sender: &AnyObject) {
            self.with_key(Flow::Check);
        }

        #[unsafe(method(removeKey:))]
        fn remove_key(&self, _sender: &AnyObject) {
            self.open_setup(Step::Remove, None);
        }

        #[unsafe(method(setupSubmit:))]
        fn setup_submit(&self, _sender: &AnyObject) {
            self.submit_setup();
        }

        #[unsafe(method(setupCancel:))]
        fn setup_cancel(&self, _sender: &AnyObject) {
            let setup = self.ivars().borrow_mut().setup.take();
            if let Some(setup) = setup {
                setup.form.take_values();
                setup.form.close();
            }
        }

        #[unsafe(method(messageDismiss:))]
        fn message_dismiss(&self, _sender: &AnyObject) {
            self.close_message();
        }

        #[unsafe(method(messageRetry:))]
        fn message_retry(&self, _sender: &AnyObject) {
            if let Some(flow) = self.close_message() {
                self.with_key(flow);
            }
        }

        #[unsafe(method(createdDone:))]
        fn created_done(&self, _sender: &AnyObject) {
            let login = self.ivars().borrow().message.as_ref().is_some_and(|message| {
                message.form.take_values().first().is_some_and(|value| !value.is_empty())
            });
            self.close_message();
            if login {
                self.set_start_at_login(true);
            }
        }

        #[unsafe(method(toggleLogin:))]
        fn toggle_login(&self, _sender: &AnyObject) {
            self.set_start_at_login(!starts_at_login());
            self.refresh_menu();
        }

        #[unsafe(method(copyDiagnostics:))]
        fn copy_diagnostics(&self, _sender: &AnyObject) {
            let report = self.diagnostics();
            let pasteboard = NSPasteboard::generalPasteboard();
            pasteboard.clearContents();
            pasteboard.setString_forType(&NSString::from_str(&report), unsafe { NSPasteboardTypeString });
            self.alert("Copied diagnostics to the clipboard. They contain no key material.");
        }

        #[unsafe(method(showHelp:))]
        fn show_help(&self, _sender: &AnyObject) {
            self.alert(&help_text());
        }

        #[unsafe(method(showAbout:))]
        fn show_about(&self, _sender: &AnyObject) {
            self.close_message();
            let text = format!(
                "fido2lock {}\nLock your Mac when you remove your FIDO2 security key.\n\nCopyright 2026 Jessica Cox <jmcox@posteo.de>\nLicensed under the Apache License, Version 2.0.",
                env!("CARGO_PKG_VERSION")
            );
            let buttons = [
                Button { title: "OK", action: sel!(messageDismiss:), key: panels::Key::Return },
                Button { title: "Source", action: sel!(openRepository:), key: panels::Key::Escape },
            ];
            let form = panels::form(self.mtm(), self, "About fido2lock", &text, &[], &buttons);
            self.ivars().borrow_mut().message = Some(Message { form, retry: None });
        }

        #[unsafe(method(openRepository:))]
        fn open_repository(&self, _sender: &AnyObject) {
            self.close_message();
            let _ = std::process::Command::new("/usr/bin/open").arg(REPOSITORY).status();
        }

        #[unsafe(method(quit:))]
        fn quit(&self, _sender: &AnyObject) {
            NSApplication::sharedApplication(self.mtm()).terminate(None);
        }
    }
);

impl Controller {
    fn new(mtm: MainThreadMarker, screen: Option<Screen>) -> Retained<Self> {
        let inner = Inner {
            state: State::new(screen.is_some()),
            screen,
            worker: Worker::default(),
            menu: None,
            setup: None,
            message: None,
            touch: None,
            busy: false,
            key: None,
            last_keys: load_keys().ok(),
        };
        let this = Self::alloc(mtm).set_ivars(RefCell::new(inner));
        unsafe { msg_send![super(this), init] }
    }

    /// Feeds an event to the state machine and carries out its action.
    fn handle(&self, event: Event) {
        if matches!(event, Event::Removed(_) | Event::Due(_)) {
            // Read at each removal, so a hand edit applies at once.
            let delay = lock_delay(&load_config());
            self.ivars().borrow_mut().state.set_delay(delay);
        }
        let action = self.ivars().borrow_mut().state.handle(event);
        match action {
            Action::None => {}
            Action::Lock => {
                // Copied out, so no borrow is held if the lock call runs the run loop.
                let screen = self.ivars().borrow().screen;
                if let Some(screen) = screen {
                    screen.lock();
                }
            }
            Action::Check(checks) => {
                for check in checks {
                    self.check_device(check);
                }
            }
            Action::Timer { token, seconds } => {
                let nanos =
                    i64::try_from(seconds.saturating_mul(1_000_000_000)).unwrap_or(i64::MAX);
                let _ = DispatchQueue::main().after(DispatchTime::NOW.time(nanos), move || {
                    with_controller(|controller| controller.handle(Event::Due(token)));
                });
            }
        }
        self.refresh_menu();
    }

    /// Checks every inserted key again if the key list changed since the last look.
    fn sync_keys(&self) {
        let now = load_keys();
        if !keys_changed(self.ivars().borrow().last_keys.as_deref(), &now) {
            return;
        }
        self.ivars().borrow_mut().last_keys = now.ok();
        self.handle(Event::Recheck);
    }

    fn check_device(&self, check: Check) {
        self.ivars().borrow().worker.run(move || {
            let outcome = match keys::path().and_then(|path| keys::load(&path)) {
                Ok(keys) => ops::outcome(ops::identify(&ops::device_key(check.id), &keys)),
                Err(_) => Outcome::Failed,
            };
            on_main(move |controller| controller.handle(Event::Checked(check, outcome)));
        });
    }

    fn busy(&self) -> bool {
        let inner = self.ivars().borrow();
        inner.busy || inner.setup.is_some()
    }

    /// Runs `work` on the worker while a panel shows `touch`, then `then` on the main thread.
    fn run_job<T: Send + 'static>(
        &self,
        touch: Option<&str>,
        work: impl FnOnce() -> T + Send + 'static,
        then: impl FnOnce(&Controller, T) + Send + 'static,
    ) {
        let touch = touch.map(|text| panels::form(self.mtm(), self, "fido2lock", text, &[], &[]));
        let mut inner = self.ivars().borrow_mut();
        inner.touch = touch;
        inner.busy = true;
        inner.worker.run(move || {
            let result = work();
            on_main(move |controller| {
                controller.end_job();
                then(controller, result);
            });
        });
    }

    fn end_job(&self) {
        let touch = {
            let mut inner = self.ivars().borrow_mut();
            inner.busy = false;
            inner.touch.take()
        };
        if let Some(touch) = touch {
            touch.close();
        }
    }

    /// Chooses the security key, then continues with `flow`. One inserted key is used at once.
    /// With several, all blink and the first one touched is used.
    fn with_key(&self, flow: Flow) {
        if self.busy() {
            return;
        }
        self.close_message();
        self.ivars().borrow_mut().key = None;
        self.run_job(None, fido::devices, move |controller, devices| {
            controller.devices_found(flow, devices);
        });
    }

    fn devices_found(&self, flow: Flow, devices: Vec<fido::Device>) {
        if devices.len() > 1 {
            let touch = "Touch the security key you want to use.";
            return self.run_job(
                Some(touch),
                move || fido::select(devices),
                |controller, key| {
                    controller.key_chosen(flow, key);
                },
            );
        }
        self.key_chosen(flow, fido::select(devices));
    }

    fn key_chosen(&self, flow: Flow, key: Result<fido::Key, FidoError>) {
        let key = match key {
            Ok(key) => key,
            Err(error) => return self.show(&error.to_string(), Some(flow)),
        };
        self.ivars().borrow_mut().key = Some(key.clone());
        match flow {
            Flow::Enroll { first, label } => self.open_setup(Step::Enroll { first, label }, None),
            Flow::Check => self.run_job(
                None,
                move || match keys::path().and_then(|path| keys::load(&path)) {
                    Ok(keys) => ops::check_report(&ops::identify(&key, &keys)),
                    Err(error) => format!("{error:#}"),
                },
                |controller, report| controller.alert(&report),
            ),
        }
    }

    /// Shows the form for `step`. `note` explains why the previous input was rejected.
    fn open_setup(&self, step: Step, note: Option<&str>) {
        if self.busy() {
            return;
        }
        self.close_message();
        let labels = enrolled_labels();
        let delay_value = match &step {
            Step::Settings { typed: Some(typed) } => typed.clone(),
            // The panel opens with an invalid file too, so the user can fix it.
            Step::Settings { typed: None } => lock_delay(&load_config()).to_string(),
            _ => String::new(),
        };
        let (message, fields, submit) = match &step {
            Step::Enroll { first, label } => (
                if *first { SET_UP_TEXT } else { ADD_TEXT }.to_owned(),
                vec![Field::plain("Key label", label), Field::secret("PIN")],
                if *first { "Set Up" } else { "Add Key" },
            ),
            Step::Remove => (
                REMOVE_TEXT.to_owned(),
                labels
                    .iter()
                    .enumerate()
                    .map(|(i, label)| Field::check(if i == 0 { "Remove" } else { "" }, label))
                    .collect(),
                "Remove",
            ),
            Step::Settings { .. } => (
                format!(
                    "Seconds between removing an armed key and locking the screen, from 0 to 60. Inserting an enrolled key in that time cancels the lock. fido2lock saves the settings to {}.",
                    config_path_text()
                ),
                vec![Field::plain("Lock delay (s)", &delay_value)],
                "Save",
            ),
        };
        let message = match note {
            Some(note) => format!("{note}\n\n{message}"),
            None => message,
        };
        let buttons = [
            Button {
                title: submit,
                action: sel!(setupSubmit:),
                key: panels::Key::Return,
            },
            Button {
                title: "Cancel",
                action: sel!(setupCancel:),
                key: panels::Key::Escape,
            },
        ];
        let form = panels::form(self.mtm(), self, "fido2lock", &message, &fields, &buttons);
        self.ivars().borrow_mut().setup = Some(Setup { step, form });
    }

    fn submit_setup(&self) {
        let setup = self.ivars().borrow_mut().setup.take();
        let Some(Setup { step, form }) = setup else {
            return;
        };
        let values = form.take_values();
        form.close();
        match step {
            Step::Enroll { first, .. } => {
                let label = values[0].trim().to_owned();
                let pin = Zeroizing::new(values[1].to_string());
                if let Err(error) = keys::check_label(&label) {
                    return self
                        .open_setup(Step::Enroll { first, label }, Some(&format!("{error:#}")));
                }
                let Some(key) = self.ivars().borrow().key.clone() else {
                    return;
                };
                let retry = label.clone();
                self.run_job(
                    Some("Touch your security key."),
                    move || keys::path().and_then(|path| ops::enroll(&path, &key, &label, &pin)),
                    move |controller, result| controller.enrolled(first, retry, result),
                );
            }
            Step::Remove => {
                let labels: Vec<String> = values
                    .iter()
                    .filter(|value| !value.is_empty())
                    .map(|value| value.to_string())
                    .collect();
                if labels.is_empty() {
                    return self.open_setup(Step::Remove, Some("Check a key to remove."));
                }
                match keys::path().and_then(|path| ops::remove(&path, &labels)) {
                    Ok(report) => {
                        self.sync_keys();
                        self.alert(&report);
                    }
                    Err(error) => self.alert(&format!("{error:#}")),
                }
            }
            Step::Settings { .. } => {
                let typed = values[0].to_string();
                let Some(lock_delay) = parse_delay(&typed) else {
                    return self
                        .open_setup(Step::Settings { typed: Some(typed) }, Some(DELAY_PROBLEM));
                };
                match Config::path().and_then(|path| Config { lock_delay }.save(&path)) {
                    Ok(()) => {
                        self.refresh_menu();
                        self.alert("Saved the settings.");
                    }
                    Err(error) => self.open_setup(
                        Step::Settings { typed: Some(typed) },
                        Some(&format!("{error:#}")),
                    ),
                }
            }
        }
    }

    /// After a wrong or missing PIN, the form asks again at once. Any other failure may need
    /// another key, so a message offers Retry, which chooses the key again.
    fn enrolled(&self, first: bool, label: String, result: Result<String>) {
        match result {
            Ok(report) => {
                self.sync_keys();
                if first {
                    self.show_created(&report);
                } else {
                    self.alert(&report);
                }
            }
            Err(error) if fido::retry_pin(&error) => {
                self.open_setup(Step::Enroll { first, label }, Some(&format!("{error:#}")));
            }
            Err(error) => self.show(&format!("{error:#}"), Some(Flow::Enroll { first, label })),
        }
    }

    fn alert(&self, message: &str) {
        self.show(message, None);
    }

    /// Shows a message panel. With `retry`, it offers Retry and Cancel for that flow.
    fn show(&self, message: &str, retry: Option<Flow>) {
        self.close_message();
        let buttons = if retry.is_some() {
            vec![
                Button {
                    title: "Retry",
                    action: sel!(messageRetry:),
                    key: panels::Key::Return,
                },
                Button {
                    title: "Cancel",
                    action: sel!(messageDismiss:),
                    key: panels::Key::Escape,
                },
            ]
        } else {
            vec![Button {
                title: "OK",
                action: sel!(messageDismiss:),
                key: panels::Key::Return,
            }]
        };
        let form = panels::form(self.mtm(), self, "fido2lock", message, &[], &buttons);
        self.ivars().borrow_mut().message = Some(Message { form, retry });
    }

    /// Reports the first key and offers Start at Login while it is off, so one click finishes
    /// the setup.
    fn show_created(&self, report: &str) {
        self.close_message();
        let text = format!("{report} Remove it to lock the screen.");
        let fields = if starts_at_login() {
            Vec::new()
        } else {
            vec![Field::check("", "Start at Login")]
        };
        let buttons = [Button {
            title: "Done",
            action: sel!(createdDone:),
            key: panels::Key::Return,
        }];
        let form = panels::form(self.mtm(), self, "fido2lock", &text, &fields, &buttons);
        self.ivars().borrow_mut().message = Some(Message { form, retry: None });
    }

    /// Closes the message panel and returns the flow it could have retried.
    fn close_message(&self) -> Option<Flow> {
        let message = self.ivars().borrow_mut().message.take()?;
        message.form.close();
        message.retry
    }

    fn set_start_at_login(&self, on: bool) {
        let service = unsafe { SMAppService::mainAppService() };
        let result = unsafe {
            if on {
                service.registerAndReturnError()
            } else {
                service.unregisterAndReturnError()
            }
        };
        if let Err(error) = result {
            self.alert(&format!(
                "Start at Login failed: {}",
                error.localizedDescription()
            ));
        }
    }

    fn diagnostics(&self) -> String {
        let path = keys::path().map_or_else(|e| format!("{e:#}"), |p| p.display().to_string());
        let config_path = config_path_text();
        let inner = self.ivars().borrow();
        let mut lines = vec![
            format!("fido2lock {} diagnostics", env!("CARGO_PKG_VERSION")),
            format!(
                "macOS: {}",
                NSProcessInfo::processInfo().operatingSystemVersionString()
            ),
        ];
        lines.extend(diagnostics_lines(
            &inner.state,
            &load_keys(),
            &path,
            &load_config(),
            &config_path,
            starts_at_login(),
        ));
        lines.join("\n") + "\n"
    }

    fn refresh_menu(&self) {
        let keys = load_keys();
        let config = load_config();
        let inner = self.ivars().borrow();
        let Some(menu) = inner.menu.as_ref() else {
            return;
        };
        let state = &inner.state;
        menu.status.setTitle(&NSString::from_str(&format!(
            "fido2lock {} - {}",
            env!("CARGO_PKG_VERSION"),
            status_text(state, &keys, &config)
        )));
        menu.warning.setHidden(!state.check_failed());
        let armed = !state.armed().is_empty();
        menu.pause.setHidden(state.paused());
        menu.pause.setEnabled(armed && state.can_lock());
        menu.resume.setHidden(!state.paused());
        let count = keys.as_ref().map_or(0, Vec::len);
        menu.set_up.setEnabled(keys.is_ok() && count == 0);
        for item in &menu.manage {
            item.setEnabled(count > 0);
        }
        menu.login.setState(if starts_at_login() {
            NSControlStateValueOn
        } else {
            NSControlStateValueOff
        });
        let warn = !state.can_lock() || keys.is_err() || config.is_err() || state.check_failed();
        let (icon, fallback, description) = if warn {
            (
                &menu.warning_icon,
                "exclamationmark.triangle.fill",
                "fido2lock: needs attention",
            )
        } else if (armed || state.lock_pending()) && !state.paused() {
            (&menu.armed_icon, "lock.fill", "fido2lock: armed")
        } else {
            (&menu.open_icon, "lock.open", "fido2lock: not armed")
        };
        let image = icon.clone().or_else(|| {
            NSImage::imageWithSystemSymbolName_accessibilityDescription(
                &NSString::from_str(fallback),
                Some(&NSString::from_str(description)),
            )
        });
        if let Some(button) = menu.item.button(self.mtm()) {
            button.setImage(image.as_deref());
        }
    }
}

pub fn run() -> Result<()> {
    let mtm = MainThreadMarker::new().context("Run on the main thread")?;
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    let controller = Controller::new(mtm, Screen::load());
    // macOS 26 adds icons to menu items with standard actions, and they break the alignment.
    // The registration domain turns them off for this app only, and a user setting still wins.
    let no_icons = NSDictionary::from_slices(
        &[ns_string!("NSMenuEnableActionImages")],
        &[&*NSNumber::new_bool(false) as &AnyObject],
    );
    // The only value is an NSNumber, which is a property-list object as the call requires.
    unsafe { NSUserDefaults::standardUserDefaults().registerDefaults(&no_icons) };

    let menu = NSMenu::new(mtm);
    let add = |title: &str, action| {
        let item = unsafe {
            NSMenuItem::initWithTitle_action_keyEquivalent(
                NSMenuItem::alloc(mtm),
                &NSString::from_str(title),
                action,
                ns_string!(""),
            )
        };
        unsafe { item.setTarget(Some(&controller)) };
        menu.addItem(&item);
        item
    };
    // Manual enabling keeps the status lines inert without an action.
    menu.setAutoenablesItems(false);
    let status = add("fido2lock - Starting…", None);
    status.setEnabled(false);
    let warning = add("Cannot check a key. See Help…", None);
    warning.setEnabled(false);
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    let pause = add("Pause Until the Key Is Back", Some(sel!(pause:)));
    let resume = add("Resume", Some(sel!(resume:)));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    let set_up = add("Set Up…", Some(sel!(setUp:)));
    let manage = vec![
        add("Add Security Key…", Some(sel!(addKey:))),
        add("Check a Security Key…", Some(sel!(checkKey:))),
        add("Remove Security Key…", Some(sel!(removeKey:))),
    ];
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("Settings…", Some(sel!(openSettings:)));
    let login = add("Start at Login", Some(sel!(toggleLogin:)));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("Copy Diagnostics", Some(sel!(copyDiagnostics:)));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add("Help…", Some(sel!(showHelp:)));
    add("About fido2lock", Some(sel!(showAbout:)));
    add("Quit", Some(sel!(quit:)));

    let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
    menu.setDelegate(Some(ProtocolObject::from_ref(&*controller)));
    item.setMenu(Some(&menu));
    controller.ivars().borrow_mut().menu = Some(Menu {
        status,
        warning,
        pause,
        resume,
        set_up,
        manage,
        login,
        item,
        armed_icon: template_icon(include_bytes!("../assets/menubar.pdf"), "fido2lock: armed"),
        open_icon: template_icon(
            include_bytes!("../assets/menubar-open.pdf"),
            "fido2lock: not armed",
        ),
        warning_icon: template_icon(
            include_bytes!("../assets/menubar-warning.pdf"),
            "fido2lock: needs attention",
        ),
    });
    CONTROLLER.with(|cell| {
        let _ = cell.set(controller.clone());
    });
    unsafe {
        NSDistributedNotificationCenter::defaultCenter().addObserver_selector_name_object(
            &controller,
            sel!(keysChanged:),
            Some(&NSString::from_str(KEYS_CHANGED)),
            None,
        );
    }
    let workspace = NSWorkspace::sharedWorkspace().notificationCenter();
    // The names are AppKit constants, and the controller lives as long as the process.
    unsafe {
        workspace.addObserver_selector_name_object(
            &controller,
            sel!(willSleep:),
            Some(NSWorkspaceWillSleepNotification),
            None,
        );
        workspace.addObserver_selector_name_object(
            &controller,
            sel!(didWake:),
            Some(NSWorkspaceDidWakeNotification),
            None,
        );
    }
    controller.refresh_menu();
    watch::start(|event| with_controller(|controller| controller.handle(event)))?;
    app.run();
    Ok(())
}

/// Tells a running menu-bar app that the terminal changed the key list.
pub fn announce_keys_changed() {
    unsafe {
        NSDistributedNotificationCenter::defaultCenter()
            .postNotificationName_object_userInfo_deliverImmediately(
                &NSString::from_str(KEYS_CHANGED),
                None,
                None,
                true,
            );
    }
}

/// True when the key list reads and differs from `last`. A list that does not read changes
/// nothing until it reads again.
fn keys_changed(last: Option<&[Key]>, now: &Result<Vec<Key>, String>) -> bool {
    match now {
        Ok(now) => last != Some(now.as_slice()),
        Err(_) => false,
    }
}

fn template_icon(pdf: &[u8], description: &str) -> Option<Retained<NSImage>> {
    let pdf = NSData::with_bytes(pdf);
    let image = NSImage::initWithData(NSImage::alloc(), &pdf)?;
    // The menu bar leaves 18 pt of height for an icon. The width follows the drawing.
    let size = image.size();
    image.setSize(NSSize::new(size.width * 18.0 / size.height, 18.0));
    // Template images take the menu bar's color in light mode, dark mode, and when highlighted.
    image.setTemplate(true);
    image.setAccessibilityDescription(Some(&NSString::from_str(description)));
    Some(image)
}

fn load_keys() -> Result<Vec<Key>, String> {
    keys::path()
        .and_then(|path| keys::load(&path))
        .map_err(|error| format!("{error:#}"))
}

fn load_config() -> Result<Config, String> {
    Config::path()
        .and_then(|path| Config::load(&path))
        .map_err(|error| format!("{error:#}"))
}

fn config_path_text() -> String {
    Config::path().map_or_else(|e| format!("{e:#}"), |p| p.display().to_string())
}

/// The delay to use. An invalid settings file locks at once, because a missed lock is worse.
pub fn lock_delay(config: &Result<Config, String>) -> u64 {
    config.as_ref().map_or(0, |config| config.lock_delay)
}

/// The typed lock delay, if it is a whole number of seconds from 0 to 60.
pub fn parse_delay(text: &str) -> Option<u64> {
    text.trim()
        .parse::<u64>()
        .ok()
        .filter(|delay| *delay <= config::MAX_DELAY)
}

fn enrolled_labels() -> Vec<String> {
    load_keys()
        .map(|keys| keys.into_iter().map(|key| key.label).collect())
        .unwrap_or_default()
}

/// The status line after the version, most important state first.
pub fn status_text(
    state: &State,
    keys: &Result<Vec<Key>, String>,
    config: &Result<Config, String>,
) -> String {
    let armed = state.armed();
    if !state.can_lock() {
        "Cannot lock the screen".to_owned()
    } else if let Err(error) = keys {
        // TOML errors add lines with a caret under the fault, which a menu item cannot show.
        error.lines().next().unwrap_or_default().to_owned()
    } else if let Err(error) = config {
        error.lines().next().unwrap_or_default().to_owned()
    } else if keys.as_ref().is_ok_and(Vec::is_empty) {
        "No keys. Choose Set Up…".to_owned()
    } else if state.paused() {
        "Paused until an enrolled key is inserted".to_owned()
    } else if state.lock_pending() {
        "Locking soon. Insert an enrolled key to cancel".to_owned()
    } else if !armed.is_empty() {
        format!("Armed: {}", armed.join(", "))
    } else {
        "Not armed. Insert an enrolled key".to_owned()
    }
}

/// Diagnostics after the version lines. Labels and states only, never credential IDs.
pub fn diagnostics_lines(
    state: &State,
    keys: &Result<Vec<Key>, String>,
    path: &str,
    config: &Result<Config, String>,
    config_path: &str,
    login: bool,
) -> Vec<String> {
    let (list, labels) = match keys {
        Ok(keys) => {
            let labels: Vec<&str> = keys.iter().map(|key| key.label.as_str()).collect();
            let labels = if labels.is_empty() {
                "none".to_owned()
            } else {
                labels.join(", ")
            };
            (format!("{path} (loads)"), labels)
        }
        Err(error) => (error.clone(), "none".to_owned()),
    };
    vec![
        format!("Key list: {list}"),
        format!("Enrolled keys: {labels}"),
        match config {
            Ok(_) => format!("Settings: {config_path} (loads)"),
            Err(error) => format!("Settings: {error}"),
        },
        format!("Lock delay: {} s", lock_delay(config)),
        format!("Status: {}", status_text(state, keys, config)),
        format!(
            "Lock function: {}",
            if state.can_lock() { "found" } else { "missing" }
        ),
        format!("Start at Login: {login}"),
        format!("Inserted FIDO devices: {}", state.present()),
    ]
}

fn starts_at_login() -> bool {
    let status = unsafe { SMAppService::mainAppService().status() };
    status == SMAppServiceStatus::Enabled
}

fn help_text() -> String {
    let exe = std::env::current_exe()
        .map_or_else(|_| "fido2lock".to_owned(), |p| p.display().to_string());
    format!(
        "Set up
Choose Set Up… and enroll your security key. When you remove it, fido2lock locks the screen. Unlock as usual, with your password or Touch ID.

Pause
To take the key out without locking, for example to move it to another port, choose Pause Until the Key Is Back. The lock returns when you insert an enrolled key. Resume ends the pause early.

Lock delay
Settings… sets a delay between removing a key and locking, up to 60 s. Inserting an enrolled key before the delay ends cancels the lock.

Backup keys
Enroll more keys with Add Security Key…. Any enrolled key arms the lock. Check a Security Key… shows whether a key is enrolled.

Problems
The first line of this menu shows problems. \"Cannot check a key\" means a key did not answer, often because another app was using it. Take it out and insert it again. Attach Copy Diagnostics to a bug report.

Terminal
Run {exe} help for the commands."
    )
}

#[cfg(test)]
mod tests;
