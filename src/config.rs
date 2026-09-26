//! The settings, kept in config.toml next to the key list. A missing file means the defaults.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use crate::keys;

/// The longest lock delay, in seconds.
pub const MAX_DELAY: u64 = 60;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Seconds between removing an armed key and locking the screen.
    #[serde(default)]
    pub lock_delay: u64,
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        Ok(keys::path()?.with_file_name("config.toml"))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Cannot read settings {}", path.display()));
            }
        };
        Self::parse(&text).with_context(|| format!("Invalid settings {}", path.display()))
    }

    fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text)?;
        ensure!(
            config.lock_delay <= MAX_DELAY,
            "lock_delay must be from 0 to 60"
        );
        Ok(config)
    }

    pub fn render(&self) -> String {
        format!(
            "# fido2lock settings. fido2lock reads this file at each key removal.\n\n\
             # Seconds between removing an armed key and locking the screen, from 0 to 60.\n\
             lock_delay = {}\n",
            self.lock_delay
        )
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        keys::write_private(path, &self.render())
    }
}

#[cfg(test)]
mod tests;
