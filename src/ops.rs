//! Enroll, remove, and check, over the key list and a security key. The terminal commands and
//! the menu share these.

use std::path::Path;
use std::time::Duration;

use anyhow::{Result, anyhow, bail, ensure};

use crate::fido::{self, FidoError};
use crate::keys::{self, Key};
use crate::state::Outcome;

/// Another app may hold the key for a moment, so a failed check tries once more after this.
const RETRY: Duration = Duration::from_secs(1);

const UNUSABLE: &str = "This key refuses checks without a touch, for example because it always requires user verification. fido2lock cannot use it.";

/// Picks the security key before its PIN is asked, as the FIDO standard flow does.
pub fn choose_key() -> Result<fido::Key> {
    Ok(fido::select(fido::devices())?)
}

/// Which enrolled key `key` is, if any, asked without a touch or PIN.
pub fn identify(key: &fido::Key, keys: &[Key]) -> Result<Option<String>, FidoError> {
    if keys.is_empty() {
        return Ok(None);
    }
    let credentials: Vec<&[u8]> = keys.iter().map(|k| k.credential.as_slice()).collect();
    let attempt = || label_of(fido::silent_assertion(key, &credentials), keys);
    attempt().or_else(|_| {
        std::thread::sleep(RETRY);
        attempt()
    })
}

fn label_of(answer: Result<Vec<u8>, FidoError>, keys: &[Key]) -> Result<Option<String>, FidoError> {
    match answer {
        Ok(id) => keys
            .iter()
            .find(|key| key.credential == id)
            .map(|key| Some(key.label.clone()))
            .ok_or_else(|| {
                FidoError::Other(anyhow!("The key answered with an unknown credential"))
            }),
        Err(FidoError::NotEnrolled) => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn outcome(result: Result<Option<String>, FidoError>) -> Outcome {
    match result {
        Ok(Some(label)) => Outcome::Enrolled(label),
        Ok(None) => Outcome::Unknown,
        Err(_) => Outcome::Failed,
    }
}

pub fn check_report(result: &Result<Option<String>, FidoError>) -> String {
    match result {
        Ok(Some(label)) => format!("This key is enrolled as \"{label}\"."),
        Ok(None) => "This key is not enrolled.".to_owned(),
        Err(error) => error.to_string(),
    }
}

/// Enrolls `key` under `label` and returns the report. Needs a touch, and the PIN if the key has
/// one.
pub fn enroll(path: &Path, key: &fido::Key, label: &str, pin: &str) -> Result<String> {
    let label = keys::check_label(label)?;
    let mut keys = keys::load(path)?;
    ensure!(
        !keys.iter().any(|k| k.label == label),
        "A key labeled \"{label}\" is already enrolled."
    );
    not_enrolled_yet(identify(key, &keys))?;
    let credential = fido::make_credential(key, pin)?;
    let new = Key {
        label: label.clone(),
        credential,
    };
    // The agent checks without a touch, so a key that refuses that cannot arm the lock.
    if !matches!(identify(key, std::slice::from_ref(&new)), Ok(Some(_))) {
        bail!(UNUSABLE);
    }
    keys.push(new);
    keys::save(path, &keys)?;
    Ok(format!("Enrolled \"{label}\"."))
}

/// Stops enrollment of a key that is already enrolled. A key that wants a PIN even for the check
/// can never arm the lock, so asking for its PIN again would loop.
fn not_enrolled_yet(result: Result<Option<String>, FidoError>) -> Result<()> {
    match result {
        Ok(None) => Ok(()),
        Ok(Some(existing)) => bail!("This key is already enrolled as \"{existing}\"."),
        Err(FidoError::PinRequired | FidoError::WrongPin { .. }) => bail!(UNUSABLE),
        Err(error) => Err(error.into()),
    }
}

pub fn remove(path: &Path, labels: &[String]) -> Result<String> {
    let mut keys = keys::load(path)?;
    for label in labels {
        ensure!(
            keys.iter().any(|k| &k.label == label),
            "No key labeled \"{label}\" is enrolled."
        );
    }
    keys.retain(|k| !labels.contains(&k.label));
    keys::save(path, &keys)?;
    Ok(removed(labels))
}

pub fn removed(labels: &[String]) -> String {
    let labels: Vec<String> = labels.iter().map(|label| format!("\"{label}\"")).collect();
    format!("Removed {}.", labels.join(", "))
}

#[cfg(test)]
mod tests;
