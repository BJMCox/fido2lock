use super::*;

#[test]
fn ctap_status_text_maps_to_ui_cases() {
    let map = |text: &str| classify(anyhow!("{text}"));
    assert!(matches!(map("FIDO device not found."), FidoError::NoDevice));
    assert!(matches!(
        map("0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid."),
        FidoError::WrongPin { .. }
    ));
    assert!(matches!(
        map("0x32 CTAP2_ERR_PIN_BLOCKED PIN Blocked."),
        FidoError::PinBlocked
    ));
    assert!(matches!(
        map("0x34 CTAP2_ERR_PIN_AUTH_BLOCKED PIN authentication, pinAuth, blocked."),
        FidoError::PinAuthBlocked
    ));
    assert!(matches!(
        map("0x2E CTAP2_ERR_NO_CREDENTIALS    No valid credentials provided."),
        FidoError::NotEnrolled
    ));
    assert!(matches!(
        map("0x3A CTAP2_ERR_ACTION_TIMEOUT Maximum time for user action expired."),
        FidoError::Timeout
    ));
    assert!(matches!(
        map("read err = something else"),
        FidoError::Other(_)
    ));
}

#[test]
fn only_a_wrong_pin_counts_as_one() {
    let bad_pin = anyhow::Error::from(FidoError::WrongPin { retries: Some(2) });
    let other_key = anyhow::Error::from(FidoError::NotEnrolled);
    assert!(wrong_pin(&bad_pin));
    assert!(!wrong_pin(&other_key));
    assert!(!wrong_pin(&anyhow::anyhow!("The key list is gone")));
}

#[test]
fn a_missing_pin_counts_as_a_wrong_pin() {
    let map = |text: &str| classify(anyhow!("{text}"));
    assert!(matches!(
        map("0x36 CTAP2_ERR_PIN_REQUIRED  PIN is required for the selected operation."),
        FidoError::PinRequired
    ));
    assert!(matches!(
        map("CTAP2_ERR_PUAT_REQUIRED"),
        FidoError::PinRequired
    ));
    assert!(wrong_pin(&anyhow::Error::new(FidoError::PinRequired)));
    assert!(!wrong_pin(&anyhow::Error::new(FidoError::Timeout)));
}

#[test]
fn a_device_key_uses_the_hidapi_path() {
    let Key(HidParam::Path(path)) = Key::device(4297189420) else {
        panic!("not a path");
    };
    assert_eq!(path, "DevSrvsID:4297189420");
}

unsafe extern "C" {
    // hidapi's C library, linked through ctap-hid-fido2.
    fn hid_darwin_get_open_exclusive() -> std::ffi::c_int;
}

// Opening a key exclusively would lock browsers and other key tools out of it during every check.
#[test]
fn keys_open_shared_not_exclusive() {
    let _ = devices();
    assert_eq!(unsafe { hid_darwin_get_open_exclusive() }, 0);
}
