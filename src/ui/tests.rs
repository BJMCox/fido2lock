use super::*;
use crate::config::Config;
use crate::state::{Event, Outcome};

fn fine() -> Result<Config, String> {
    Ok(Config::default())
}

fn key(label: &str) -> Key {
    Key {
        label: label.to_owned(),
        credential: b"c".to_vec(),
    }
}

fn armed(labels: &[&str]) -> State {
    let mut state = State::new(true);
    for (id, label) in labels.iter().enumerate() {
        let id = id as u64 + 1;
        let Action::Check(checks) = state.handle(Event::Appeared(id)) else {
            panic!("no check");
        };
        state.handle(Event::Checked(
            checks[0],
            Outcome::Enrolled((*label).to_owned()),
        ));
    }
    state
}

#[test]
fn the_status_line_names_the_most_important_state() {
    let keys = Ok(vec![key("blue")]);
    assert_eq!(
        status_text(&State::new(false), &keys, &fine()),
        "Cannot lock the screen"
    );
    assert_eq!(
        status_text(
            &State::new(true),
            &Err("Cannot read keys.toml: bad".to_owned()),
            &fine()
        ),
        "Cannot read keys.toml: bad"
    );
    assert_eq!(
        status_text(&State::new(true), &Ok(vec![]), &fine()),
        "No keys. Choose Set Up…"
    );
    assert_eq!(
        status_text(&State::new(true), &keys, &fine()),
        "Not armed. Insert an enrolled key"
    );
    assert_eq!(
        status_text(&armed(&["blue", "green"]), &keys, &fine()),
        "Armed: blue, green"
    );
    let mut paused = armed(&["blue"]);
    paused.handle(Event::Pause);
    assert_eq!(
        status_text(&paused, &keys, &fine()),
        "Paused until an enrolled key is inserted"
    );
}

#[test]
fn diagnostics_list_states_but_no_credentials() {
    let lines = diagnostics_lines(
        &armed(&["blue"]),
        &Ok(vec![key("blue")]),
        "/k/keys.toml",
        &Ok(Config { lock_delay: 5 }),
        "/k/config.toml",
        true,
    );
    assert_eq!(
        lines,
        [
            "Key list: /k/keys.toml (loads)",
            "Enrolled keys: blue",
            "Settings: /k/config.toml (loads)",
            "Lock delay: 5 s",
            "Status: Armed: blue",
            "Lock function: found",
            "Start at Login: true",
            "Inserted FIDO devices: 1",
        ]
    );
    let broken = diagnostics_lines(
        &State::new(false),
        &Err("bad".to_owned()),
        "/k/keys.toml",
        &Err("Invalid settings /k/config.toml: worse".to_owned()),
        "/k/config.toml",
        false,
    );
    assert_eq!(broken[0], "Key list: bad");
    assert_eq!(broken[1], "Enrolled keys: none");
    assert_eq!(
        broken[2],
        "Settings: Invalid settings /k/config.toml: worse"
    );
    assert_eq!(broken[3], "Lock delay: 0 s");
    assert_eq!(broken[5], "Lock function: missing");
}

#[test]
fn a_changed_key_list_triggers_a_recheck() {
    let one = vec![key("blue")];
    assert!(!keys_changed(Some(&one), &Ok(one.clone())));
    assert!(keys_changed(Some(&one), &Ok(vec![])));
    assert!(keys_changed(
        Some(&one),
        &Ok(vec![key("blue"), key("green")])
    ));
    assert!(keys_changed(None, &Ok(vec![])));
    // A broken file changes nothing until it reads again.
    assert!(!keys_changed(Some(&one), &Err("bad".to_owned())));
}

#[test]
fn a_multi_line_error_shows_its_first_line() {
    let keys =
        Err("Cannot read keys.toml: TOML parse error at line 1\n  |\n1 | key = 3".to_owned());
    assert_eq!(
        status_text(&State::new(true), &keys, &fine()),
        "Cannot read keys.toml: TOML parse error at line 1"
    );
}

#[test]
fn the_status_line_shows_a_settings_error_and_a_pending_lock() {
    let keys = Ok(vec![key("blue")]);
    let broken = Err("Invalid settings config.toml: TOML parse error\n  |".to_owned());
    assert_eq!(
        status_text(&armed(&["blue"]), &keys, &broken),
        "Invalid settings config.toml: TOML parse error"
    );
    // The key list error comes first.
    assert_eq!(
        status_text(&State::new(true), &Err("keys bad".to_owned()), &broken),
        "keys bad"
    );
    let mut pending = armed(&["blue"]);
    pending.set_delay(5);
    pending.handle(Event::Removed(1));
    assert_eq!(
        status_text(&pending, &keys, &fine()),
        "Locking soon. Insert an enrolled key to cancel"
    );
}

#[test]
fn the_delay_input_is_a_whole_number_from_0_to_60() {
    assert_eq!(parse_delay(" 5 "), Some(5));
    assert_eq!(parse_delay("0"), Some(0));
    assert_eq!(parse_delay("60"), Some(60));
    for text in ["61", "-1", "", "1.5", "abc"] {
        assert_eq!(parse_delay(text), None, "{text:?}");
    }
}

#[test]
fn an_invalid_settings_file_locks_at_once() {
    assert_eq!(lock_delay(&Ok(Config { lock_delay: 7 })), 7);
    assert_eq!(lock_delay(&Err("bad".to_owned())), 0);
}

#[test]
fn a_pause_during_a_countdown_shows_paused() {
    let keys = Ok(vec![key("blue"), key("green")]);
    let mut state = armed(&["blue", "green"]);
    state.set_delay(30);
    state.handle(Event::Removed(1));
    state.handle(Event::Pause);
    assert_eq!(
        status_text(&state, &keys, &fine()),
        "Paused until an enrolled key is inserted"
    );
}

const ICONS: [&[u8]; 3] = [
    include_bytes!("../../assets/menubar.pdf"),
    include_bytes!("../../assets/menubar-open.pdf"),
    include_bytes!("../../assets/menubar-warning.pdf"),
];

#[test]
fn menu_bar_icons_fill_the_menu_bar_height() {
    for pdf in ICONS {
        let size = template_icon(pdf, "icon").unwrap().size();
        assert_eq!((size.width, size.height), (15.0, 18.0));
    }
}

/// The share of a 30 x 36 px bitmap that AppKit covers when it draws `image` into it.
fn coverage(image: &NSImage) -> f64 {
    use objc2::AllocAnyThread;
    use objc2_app_kit::{NSBitmapImageRep, NSDeviceRGBColorSpace, NSGraphicsContext};
    use objc2_foundation::{NSPoint, NSRect};
    let (w, h) = (30, 36);
    let rep = unsafe {
        NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel(
            NSBitmapImageRep::alloc(), std::ptr::null_mut(), w, h, 8, 4, true, false, NSDeviceRGBColorSpace, 0, 0,
        )
    }
    .unwrap();
    let context = NSGraphicsContext::graphicsContextWithBitmapImageRep(&rep).unwrap();
    NSGraphicsContext::saveGraphicsState_class();
    NSGraphicsContext::setCurrentContext(Some(&context));
    image.drawInRect(NSRect::new(
        NSPoint::new(0.0, 0.0),
        NSSize::new(w as f64, h as f64),
    ));
    NSGraphicsContext::restoreGraphicsState_class();
    let row = rep.bytesPerRow() as usize;
    // SAFETY: the bitmap holds `h` rows of `row` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(rep.bitmapData(), row * h as usize) };
    let covered = bytes
        .chunks(row)
        .flat_map(|line| line[..4 * w as usize].chunks(4))
        .filter(|pixel| pixel[3] > 127)
        .count();
    covered as f64 / (w * h) as f64
}

#[test]
fn menu_bar_icons_draw_their_shape() {
    // rsvg-convert turns an SVG mask into a PDF soft mask, which AppKit draws as nothing.
    for pdf in ICONS {
        let image = template_icon(pdf, "icon").unwrap();
        assert!(coverage(&image) > 0.3);
    }
}
