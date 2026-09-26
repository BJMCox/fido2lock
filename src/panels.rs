//! Non-activating panels. macOS no longer lets a background accessory app activate itself,
//! so a normal window or alert would open without keyboard focus while another app stays active.
//! A non-activating panel receives keys anyway.

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, Sel};
use objc2::{MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSApplication, NSBackingStoreType, NSButton, NSControlStateValueOn, NSEvent,
    NSEventModifierFlags, NSFloatingWindowLevel, NSImageView, NSPanel, NSResponder,
    NSSecureTextField, NSTextField, NSView, NSWindow, NSWindowStyleMask,
};
use objc2_foundation::{NSObject, NSPoint, NSRect, NSSize, NSString, ns_string};

const WIDTH: f64 = 420.0;
const MARGIN: f64 = 20.0;
/// The app icon on each panel's left, as native alerts show it. A genuine fido2lock prompt is
/// then recognizable at a glance.
const ICON: f64 = 56.0;

define_class!(
    /// A panel that handles Cmd+V, C, X, A, and Z itself. A menu-bar app has no Edit menu,
    /// and an inactive app's menu gets no key equivalents, so paste would do nothing.
    #[unsafe(super(NSPanel, NSWindow, NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "Fido2lockPanel"]
    struct KeyPanel;

    impl KeyPanel {
        #[unsafe(method(performKeyEquivalent:))]
        fn perform_key_equivalent(&self, event: &NSEvent) -> bool {
            // A nil target sends the action along the responder chain to the focused field.
            let handled = edit_action(event).is_some_and(|action| {
                let app = NSApplication::sharedApplication(self.mtm());
                unsafe { app.sendAction_to_from(action, None, None) }
            });
            handled || unsafe { msg_send![super(self), performKeyEquivalent: event] }
        }
    }
);

fn edit_action(event: &NSEvent) -> Option<Sel> {
    if !event
        .modifierFlags()
        .contains(NSEventModifierFlags::Command)
    {
        return None;
    }
    match event.charactersIgnoringModifiers()?.to_string().as_str() {
        "v" => Some(sel!(paste:)),
        "c" => Some(sel!(copy:)),
        "x" => Some(sel!(cut:)),
        "a" => Some(sel!(selectAll:)),
        "z" => Some(sel!(undo:)),
        _ => None,
    }
}

pub struct Field<'a> {
    pub label: &'a str,
    pub kind: Kind<'a>,
}

pub enum Kind<'a> {
    Text {
        value: &'a str,
        secure: bool,
    },
    /// A checkbox titled `title`. Its value is `title` when checked, and empty otherwise.
    Check {
        title: &'a str,
    },
}

impl<'a> Field<'a> {
    pub fn plain(label: &'a str, value: &'a str) -> Self {
        let kind = Kind::Text {
            value,
            secure: false,
        };
        Self { label, kind }
    }

    pub fn secret(label: &'a str) -> Self {
        let kind = Kind::Text {
            value: "",
            secure: true,
        };
        Self { label, kind }
    }

    pub fn check(label: &'a str, title: &'a str) -> Self {
        Self {
            label,
            kind: Kind::Check { title },
        }
    }
}

pub struct Button<'a> {
    pub title: &'a str,
    pub action: Sel,
    pub key: Key,
}

pub enum Key {
    Return,
    Escape,
}

enum Control {
    Text(Retained<NSTextField>),
    Check(Retained<NSButton>),
}

pub struct Form {
    pub panel: Retained<NSPanel>,
    controls: Vec<Control>,
}

impl Form {
    /// Reads every field in order, then clears the text fields, so typed secrets do not linger.
    /// A checked box yields its title.
    pub fn take_values(&self) -> Vec<zeroize::Zeroizing<String>> {
        self.controls
            .iter()
            .map(|control| match control {
                Control::Text(field) => {
                    let value = zeroize::Zeroizing::new(field.stringValue().to_string());
                    field.setStringValue(ns_string!(""));
                    value
                }
                Control::Check(button) => {
                    zeroize::Zeroizing::new(if button.state() == NSControlStateValueOn {
                        button.title().to_string()
                    } else {
                        String::new()
                    })
                }
            })
            .collect()
    }

    pub fn close(&self) {
        self.panel.orderOut(None);
    }
}

/// Builds and shows a panel: `message` on top, one row per field, and `buttons` right-aligned
/// at the bottom. Buttons send their actions to `target`.
pub fn form(
    mtm: MainThreadMarker,
    target: &AnyObject,
    title: &str,
    message: &str,
    fields: &[Field],
    buttons: &[Button],
) -> Form {
    let rect = |x, y, w, h| NSRect::new(NSPoint::new(x, y), NSSize::new(w, h));
    let text_left = MARGIN + ICON + 14.0;
    let text = NSTextField::wrappingLabelWithString(&NSString::from_str(message), mtm);
    text.setPreferredMaxLayoutWidth(WIDTH - text_left - MARGIN);
    let text_height = text.fittingSize().height;
    let head_height = text_height.max(ICON);
    let buttons_height = if buttons.is_empty() { 0.0 } else { 44.0 };
    let height = MARGIN + head_height + 12.0 + fields.len() as f64 * 32.0 + buttons_height + 12.0;

    let mask = NSWindowStyleMask::Titled | NSWindowStyleMask::NonactivatingPanel;
    let panel: Retained<KeyPanel> = unsafe {
        msg_send![
            KeyPanel::alloc(mtm),
            initWithContentRect: rect(0.0, 0.0, WIDTH, height),
            styleMask: mask,
            backing: NSBackingStoreType::Buffered,
            defer: false,
        ]
    };
    let panel: Retained<NSPanel> = Retained::into_super(panel);
    unsafe { panel.setReleasedWhenClosed(false) };
    panel.setTitle(&NSString::from_str(title));
    panel.setLevel(NSFloatingWindowLevel);
    // Panels hide while their app is inactive, and fido2lock never becomes the active app.
    panel.setHidesOnDeactivate(false);
    panel.setBecomesKeyOnlyIfNeeded(false);
    panel.setAutorecalculatesKeyViewLoop(true);
    let content = panel.contentView().expect("panels have a content view");

    let head_top = height - MARGIN;
    if let Some(icon) = NSApplication::sharedApplication(mtm).applicationIconImage() {
        let view = NSImageView::imageViewWithImage(&icon, mtm);
        view.setFrame(rect(MARGIN, head_top - ICON, ICON, ICON));
        content.addSubview(&view);
    }
    text.setFrame(rect(
        text_left,
        head_top - text_height,
        WIDTH - text_left - MARGIN,
        text_height,
    ));
    content.addSubview(&text);
    let mut top = head_top - head_height - 12.0;

    let mut controls = Vec::new();
    let mut first_text = None;
    for field in fields {
        top -= 24.0;
        let label = NSTextField::labelWithString(&NSString::from_str(field.label), mtm);
        label.setFrame(rect(MARGIN, top + 2.0, 110.0, 20.0));
        content.addSubview(&label);
        let control = match &field.kind {
            Kind::Text { value, secure } => {
                let frame = rect(MARGIN + 116.0, top, WIDTH - 2.0 * MARGIN - 116.0, 24.0);
                let text_field: Retained<NSTextField> = if *secure {
                    Retained::into_super(NSSecureTextField::initWithFrame(
                        NSSecureTextField::alloc(mtm),
                        frame,
                    ))
                } else {
                    NSTextField::initWithFrame(NSTextField::alloc(mtm), frame)
                };
                text_field.setStringValue(&NSString::from_str(value));
                content.addSubview(&text_field);
                first_text.get_or_insert_with(|| text_field.clone());
                Control::Text(text_field)
            }
            Kind::Check { title } => {
                let button = unsafe {
                    NSButton::checkboxWithTitle_target_action(
                        &NSString::from_str(title),
                        None,
                        None,
                        mtm,
                    )
                };
                button.setFrame(rect(
                    MARGIN + 116.0,
                    top,
                    WIDTH - 2.0 * MARGIN - 116.0,
                    24.0,
                ));
                content.addSubview(&button);
                Control::Check(button)
            }
        };
        controls.push(control);
        top -= 8.0;
    }

    let mut right = WIDTH - MARGIN + 6.0;
    for button in buttons {
        let control = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str(button.title),
                Some(target),
                Some(button.action),
                mtm,
            )
        };
        let width = control.fittingSize().width.max(90.0);
        right -= width + 6.0;
        control.setFrame(rect(right, 12.0, width, 32.0));
        control.setKeyEquivalent(match button.key {
            Key::Return => ns_string!("\r"),
            Key::Escape => ns_string!("\u{1b}"),
        });
        content.addSubview(&*control as &NSView);
    }

    panel.center();
    panel.makeKeyAndOrderFront(None);
    if let Some(first) = &first_text {
        panel.makeFirstResponder(Some(first));
    }
    Form { panel, controls }
}
