use std::os::unix::fs::PermissionsExt;

use super::*;

fn key(label: &str, credential: &[u8]) -> Key {
    Key {
        label: label.to_owned(),
        credential: credential.to_vec(),
    }
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_missing_file_means_no_keys() {
    let dir = tempfile::tempdir().unwrap();
    assert!(load(&dir.path().join("keys.toml")).unwrap().is_empty());
}

#[test]
fn saved_keys_load_again_with_private_modes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fido2lock/keys.toml");
    let keys = vec![
        key("primary", b"\x01\x02\xff"),
        key("he said \"hi\" 🔑", b"cred"),
        key(&"é".repeat(64), b"x"),
    ];
    save(&path, &keys).unwrap();
    assert_eq!(load(&path).unwrap(), keys);
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    assert!(!path.with_extension("toml.tmp").exists());
}

#[test]
fn saving_replaces_the_list_and_a_stale_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.toml");
    save(&path, &[key("a", b"1")]).unwrap();
    fs::write(path.with_extension("toml.tmp"), "junk").unwrap();
    save(&path, &[key("b", b"2")]).unwrap();
    assert_eq!(load(&path).unwrap(), [key("b", b"2")]);
}

#[test]
fn an_empty_list_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.toml");
    save(&path, &[]).unwrap();
    assert!(load(&path).unwrap().is_empty());
}

#[test]
fn labels_are_trimmed_and_checked() {
    assert_eq!(check_label("  blue key ").unwrap(), "blue key");
    assert!(check_label(&"é".repeat(64)).is_ok());
    for bad in ["", "   ", "a\tb", "a\nb", &"x".repeat(65)] {
        assert!(check_label(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn bad_files_are_rejected() {
    for text in [
        "[[key]]\nlabel = \"a\"\ncredential = \"AQ\"\n[[key]]\nlabel = \"a\"\ncredential = \"Ag\"\n",
        "[[key]]\nlabel = \"a\"\ncredential = \"not base64!\"\n",
        "[[key]]\nlabel = \"a\"\ncredential = \"\"\n",
        "[[key]]\nlabel = \"\"\ncredential = \"AQ\"\n",
        "[[key]]\nlabel = \"a\"\ncredential = \"AQ\"\ncolor = \"red\"\n",
        "key = 3\n",
    ] {
        assert!(parse(text).is_err(), "{text}");
    }
}

#[test]
fn a_bad_file_names_its_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.toml");
    fs::write(&path, "key = 3\n").unwrap();
    let error = format!("{:#}", load(&path).unwrap_err());
    assert!(error.contains("keys.toml"), "{error}");
}
