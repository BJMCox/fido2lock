use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::*;

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn load_text(text: &str) -> Result<Config> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, text).unwrap();
    Config::load(&path)
}

#[test]
fn a_missing_file_means_no_delay() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::load(&dir.path().join("config.toml")).unwrap();
    assert_eq!(config, Config { lock_delay: 0 });
}

#[test]
fn a_valid_file_reads() {
    assert_eq!(load_text("lock_delay = 5\n").unwrap().lock_delay, 5);
    assert_eq!(load_text("").unwrap().lock_delay, 0);
}

#[test]
fn the_delay_is_at_most_60() {
    assert_eq!(load_text("lock_delay = 60\n").unwrap().lock_delay, 60);
    let error = format!("{:#}", load_text("lock_delay = 61\n").unwrap_err());
    assert!(error.starts_with("Invalid settings "), "{error}");
    assert!(
        error.ends_with("lock_delay must be from 0 to 60"),
        "{error}"
    );
}

#[test]
fn other_values_and_keys_are_refused() {
    for text in [
        "lock_delay = -1\n",
        "lock_delay = 1.5\n",
        "lock_delay = \"5\"\n",
        "lock_delay = 5\ncolour = 1\n",
    ] {
        assert!(load_text(text).is_err(), "{text:?}");
    }
}

#[test]
fn saved_settings_load_again_with_private_modes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fido2lock/config.toml");
    let config = Config { lock_delay: 42 };
    config.save(&path).unwrap();
    assert_eq!(Config::load(&path).unwrap(), config);
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    assert!(!path.with_extension("toml.tmp").exists());
    assert!(config.render().contains("from 0 to 60.\nlock_delay = 42\n"));
}

#[test]
fn the_file_sits_next_to_the_key_list() {
    let path = Config::path().unwrap();
    assert_eq!(path.parent(), crate::keys::path().unwrap().parent());
    assert_eq!(path.file_name().unwrap(), "config.toml");
}
