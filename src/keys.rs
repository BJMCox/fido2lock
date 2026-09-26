//! The enrolled keys, kept in keys.toml. The file holds labels and credential IDs, no secrets.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub label: String,
    pub credential: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    key: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    label: String,
    credential: String,
}

pub fn path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join("Library/Application Support/fido2lock/keys.toml"))
}

/// The enrolled keys. A missing file means none.
pub fn load(path: &Path) -> Result<Vec<Key>> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("Cannot read {}", path.display()));
        }
    };
    parse(&text).with_context(|| format!("Cannot read {}", path.display()))
}

fn parse(text: &str) -> Result<Vec<Key>> {
    let file: File = toml::from_str(text)?;
    let mut keys: Vec<Key> = Vec::new();
    for entry in file.key {
        let label = check_label(&entry.label)?;
        ensure!(
            !keys.iter().any(|key| key.label == label),
            "The label {label:?} appears twice"
        );
        let credential = URL_SAFE_NO_PAD
            .decode(entry.credential.trim())
            .ok()
            .filter(|credential| !credential.is_empty())
            .with_context(|| format!("The credential of {label:?} is not base64url"))?;
        keys.push(Key { label, credential });
    }
    Ok(keys)
}

/// The trimmed label, if it is usable.
pub fn check_label(label: &str) -> Result<String> {
    let label = label.trim();
    ensure!(!label.is_empty(), "The key label is empty.");
    ensure!(
        label.chars().count() <= 64,
        "The key label is longer than 64 characters."
    );
    ensure!(
        !label.chars().any(char::is_control),
        "The key label contains a control character."
    );
    Ok(label.to_owned())
}

/// Writes the list through a temporary file, so a crash never leaves half a file.
pub fn save(path: &Path, keys: &[Key]) -> Result<()> {
    let file = File {
        key: keys
            .iter()
            .map(|key| Entry {
                label: key.label.clone(),
                credential: URL_SAFE_NO_PAD.encode(&key.credential),
            })
            .collect(),
    };
    write_private(path, &toml::to_string(&file)?)
}

/// Writes `text` through a temporary file, so a crash never leaves half a file. The folder gets
/// mode 0700 and the file 0600.
pub fn write_private(path: &Path, text: &str) -> Result<()> {
    let folder = path.parent().context("The file has no folder")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(folder)
        .with_context(|| format!("Cannot create {}", folder.display()))?;
    let temp = path.with_extension("toml.tmp");
    // A leftover from a crash would make create_new fail.
    let _ = fs::remove_file(&temp);
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .with_context(|| format!("Cannot write {}", temp.display()))?;
    out.write_all(text.as_bytes())?;
    out.sync_all()?;
    fs::rename(&temp, path).with_context(|| format!("Cannot write {}", path.display()))
}

#[cfg(test)]
mod tests;
