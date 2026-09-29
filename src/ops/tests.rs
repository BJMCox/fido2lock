use super::*;

fn key(label: &str, credential: &[u8]) -> Key {
    Key {
        label: label.to_owned(),
        credential: credential.to_vec(),
    }
}

#[test]
fn an_answer_names_the_enrolled_key() {
    let keys = [key("blue", b"1"), key("green", b"2")];
    assert_eq!(
        label_of(Ok(b"2".to_vec()), &keys).unwrap(),
        Some("green".to_owned())
    );
    assert!(label_of(Ok(b"9".to_vec()), &keys).is_err());
    assert_eq!(label_of(Err(FidoError::NotEnrolled), &keys).unwrap(), None);
    assert!(label_of(Err(FidoError::Timeout), &keys).is_err());
}

#[test]
fn results_map_to_outcomes() {
    assert_eq!(
        outcome(Ok(Some("blue".to_owned()))),
        Outcome::Enrolled("blue".to_owned())
    );
    assert_eq!(outcome(Ok(None)), Outcome::Unknown);
    assert_eq!(outcome(Err(FidoError::NoDevice)), Outcome::Failed);
}

#[test]
fn an_empty_list_needs_no_device() {
    let key = device_key(1);
    assert_eq!(identify(&key, &[]).unwrap(), None);
}

#[test]
fn check_reports_read_as_sentences() {
    assert_eq!(
        check_report(&Ok(Some("blue".to_owned()))),
        "This key is enrolled as \"blue\"."
    );
    assert_eq!(check_report(&Ok(None)), "This key is not enrolled.");
    assert_eq!(
        check_report(&Err(FidoError::NoDevice)),
        "Insert your security key."
    );
}

#[test]
fn removal_keeps_the_other_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.toml");
    keys::save(&path, &[key("a", b"1"), key("b", b"2"), key("c", b"3")]).unwrap();
    let report = remove(&path, &["a".to_owned(), "c".to_owned()]).unwrap();
    assert_eq!(report, "Removed \"a\", \"c\".");
    assert_eq!(keys::load(&path).unwrap(), [key("b", b"2")]);
}

#[test]
fn removal_refuses_an_unknown_label_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.toml");
    keys::save(&path, &[key("a", b"1")]).unwrap();
    assert!(remove(&path, &["a".to_owned(), "z".to_owned()]).is_err());
    assert_eq!(keys::load(&path).unwrap(), [key("a", b"1")]);
}

#[test]
fn enrollment_refuses_a_bad_or_taken_label_before_any_device_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.toml");
    keys::save(&path, &[key("blue", b"1")]).unwrap();
    // No device has this entry ID, so reaching the device would fail with another message.
    let absent = device_key(1);
    let taken = format!("{:#}", enroll(&path, &absent, " blue ", "").unwrap_err());
    assert_eq!(taken, "A key labeled \"blue\" is already enrolled.");
    let empty = format!("{:#}", enroll(&path, &absent, "  ", "").unwrap_err());
    assert_eq!(empty, "The key label is empty.");
}

#[test]
fn reports_show_labels_as_typed() {
    let label = "he said \"hi\" 🔑".to_owned();
    assert_eq!(
        check_report(&Ok(Some(label.clone()))),
        "This key is enrolled as \"he said \"hi\" 🔑\"."
    );
    assert_eq!(removed(&[label]), "Removed \"he said \"hi\" 🔑\".");
}

#[test]
fn a_key_that_wants_a_pin_for_the_check_is_unusable() {
    for error in [
        FidoError::PinRequired,
        FidoError::WrongPin { retries: None },
    ] {
        let message = format!("{:#}", not_enrolled_yet(Err(error)).unwrap_err());
        assert_eq!(message, UNUSABLE);
    }
    let taken = format!(
        "{:#}",
        not_enrolled_yet(Ok(Some("blue".to_owned()))).unwrap_err()
    );
    assert_eq!(taken, "This key is already enrolled as \"blue\".");
    assert!(not_enrolled_yet(Ok(None)).is_ok());
    assert!(!fido::retry_pin(
        &not_enrolled_yet(Err(FidoError::PinRequired)).unwrap_err()
    ));
}

#[test]
fn a_device_key_uses_the_hidapi_path() {
    assert_eq!(device_path(4297189420), "DevSrvsID:4297189420");
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    // hidapi's C library, linked through ctap-hid-fido2.
    fn hid_darwin_get_open_exclusive() -> std::ffi::c_int;
}

// Opening a key exclusively would lock browsers and other key tools out of it during every check.
#[cfg(target_os = "macos")]
#[test]
fn keys_open_shared_not_exclusive() {
    let _ = fido::devices();
    assert_eq!(unsafe { hid_darwin_get_open_exclusive() }, 0);
}
