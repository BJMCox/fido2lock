use std::fmt;

use anyhow::anyhow;
use ctap_hid_fido2::fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, HidParam, LibCfg};
use std::sync::{Arc, mpsc};
pub const RP_ID: &str = "fido2lock";

#[derive(Debug)]
pub enum FidoError {
    NoDevice,
    MultipleDevices,
    WrongPin { retries: Option<i32> },
    PinRequired,
    PinBlocked,
    PinAuthBlocked,
    Timeout,
    NotEnrolled,
    Other(anyhow::Error),
}

impl fmt::Display for FidoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDevice => write!(f, "Insert your security key."),
            Self::MultipleDevices => write!(f, "Remove all security keys but one."),
            Self::WrongPin { retries: Some(n) } => write!(f, "Wrong PIN. {n} tries left."),
            Self::WrongPin { retries: None } => write!(f, "Wrong PIN."),
            Self::PinRequired => write!(f, "This key has a PIN. Enter it."),
            Self::PinBlocked => write!(
                f,
                "The FIDO2 PIN is blocked. Only a FIDO2 reset with the vendor's tool recovers the key, and it erases all FIDO2 credentials. Use a backup key."
            ),
            Self::PinAuthBlocked => {
                write!(
                    f,
                    "Too many wrong PINs in a row. Remove and reinsert the security key."
                )
            }
            Self::Timeout => write!(f, "No touch detected. Try again."),
            Self::NotEnrolled => write!(f, "This security key is not enrolled."),
            Self::Other(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for FidoError {}

/// True when `error` is a wrong or missing PIN. Then the same key is asked again, while any other
/// failure may need another key.
pub fn wrong_pin(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<FidoError>(),
        Some(FidoError::WrongPin { .. } | FidoError::PinRequired)
    )
}

/// A plugged-in FIDO device, as the operating system names it.
pub type Device = HidParam;

/// Which plugged-in security key to talk to: the only one, or the one the user touched.
#[derive(Clone)]
pub struct Key(HidParam);

/// The plugged-in FIDO security keys.
pub fn devices() -> Vec<HidParam> {
    ctap_hid_fido2::get_fidokey_devices()
        .into_iter()
        .map(|info| info.param)
        .collect()
}

/// The key to use among `devices`. With one key it is that key. With several, every key blinks
/// until the user touches one (CTAP 2.1 authenticatorSelection), and the others are cancelled.
pub fn select(devices: Vec<HidParam>) -> Result<Key, FidoError> {
    match devices.as_slice() {
        [] => return Err(FidoError::NoDevice),
        [only] => return Ok(Key(only.clone())),
        _ => {}
    }
    let cfg = LibCfg::init();
    let opened: Vec<(HidParam, Arc<FidoKeyHid>)> = devices
        .into_iter()
        .filter_map(|param| {
            let device =
                FidoKeyHidFactory::create_by_params(std::slice::from_ref(&param), &cfg).ok()?;
            Some((param, Arc::new(device)))
        })
        .collect();
    let (sender, touched) = mpsc::channel();
    for (index, (_, device)) in opened.iter().enumerate() {
        let (device, sender) = (Arc::clone(device), sender.clone());
        std::thread::spawn(move || {
            let _ = sender.send((index, device.selection()));
        });
    }
    drop(sender);
    let mut last_error = None;
    for (index, result) in touched {
        match result {
            Ok(()) => {
                // Stops the other keys blinking. A key that already answered ignores the cancel.
                for (other, (_, device)) in opened.iter().enumerate() {
                    if other != index {
                        let _ = device.cancel_selection();
                    }
                }
                return Ok(Key(opened[index].0.clone()));
            }
            Err(error) => last_error = Some(classify(error)),
        }
    }
    // A key without authenticatorSelection (CTAP 2.0) cannot take part, so fall back to one key.
    Err(match last_error {
        Some(FidoError::Timeout) => FidoError::Timeout,
        _ => FidoError::MultipleDevices,
    })
}

impl Key {
    /// The inserted device with IORegistry entry `id`, named as hidapi names it on macOS.
    pub fn device(id: crate::state::Id) -> Self {
        Key(HidParam::Path(format!("DevSrvsID:{id}")))
    }
}

/// Makes a non-resident credential for fido2lock and returns its ID. Needs a touch, and the PIN
/// when the key has one. A blank `pin` asks without one.
pub fn make_credential(key: &Key, pin: &str) -> Result<Vec<u8>, FidoError> {
    let device = open(key)?;
    let challenge = random::<32>()?;
    let user_id = random::<16>()?;
    let user = PublicKeyCredentialUserEntity::new(Some(&user_id), Some(RP_ID), Some(RP_ID));
    let builder = MakeCredentialArgsBuilder::new(RP_ID, &challenge).user_entity(&user);
    let builder = if pin.is_empty() {
        builder.without_pin_and_uv()
    } else {
        builder.pin(pin)
    };
    let attestation = device
        .make_credential_with_args(&builder.build())
        .map_err(|e| with_retries(&device, e))?;
    Ok(attestation.credential_descriptor.id)
}

/// Asks `key`, without a touch or PIN, which of `credentials` it holds, and returns that ID.
pub fn silent_assertion(key: &Key, credentials: &[&[u8]]) -> Result<Vec<u8>, FidoError> {
    let device = open(key)?;
    let challenge = random::<32>()?;
    let mut builder = GetAssertionArgsBuilder::new(RP_ID, &challenge)
        .without_pin_and_uv()
        .without_up();
    for id in credentials {
        builder = builder.add_credential_id(id);
    }
    let assertion = device
        .get_assertion_with_args(&builder.build())
        .map_err(classify)?
        .into_iter()
        .next()
        .ok_or_else(|| FidoError::Other(anyhow!("The key returned no assertion")))?;
    // CTAP lets the key omit the credential ID when the allow list has one entry.
    Ok(match (assertion.credential_id.is_empty(), credentials) {
        (true, [only]) => only.to_vec(),
        _ => assertion.credential_id,
    })
}

fn open(key: &Key) -> Result<FidoKeyHid, FidoError> {
    FidoKeyHidFactory::create_by_params(std::slice::from_ref(&key.0), &LibCfg::init())
        .map_err(classify)
}

fn random<const N: usize>() -> Result<[u8; N], FidoError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes)
        .map_err(|e| FidoError::Other(anyhow!("The random source failed: {e}")))?;
    Ok(bytes)
}

fn with_retries(device: &FidoKeyHid, error: anyhow::Error) -> FidoError {
    match classify(error) {
        FidoError::WrongPin { .. } => FidoError::WrongPin {
            retries: device.get_pin_retries().ok(),
        },
        other => other,
    }
}

/// Maps ctap-hid-fido2's error text, which carries the CTAP status name, to the cases the UI handles.
fn classify(error: anyhow::Error) -> FidoError {
    let text = format!("{error:#}");
    let cases = [
        ("FIDO device not found", FidoError::NoDevice),
        ("Multiple FIDO devices", FidoError::MultipleDevices),
        (
            "CTAP2_ERR_PIN_INVALID",
            FidoError::WrongPin { retries: None },
        ),
        ("CTAP2_ERR_PIN_BLOCKED", FidoError::PinBlocked),
        ("CTAP2_ERR_PIN_AUTH_BLOCKED", FidoError::PinAuthBlocked),
        ("CTAP2_ERR_USER_ACTION_TIMEOUT", FidoError::Timeout),
        // Some authenticators report a touch timeout with this older status name.
        ("CTAP2_ERR_ACTION_TIMEOUT", FidoError::Timeout),
        ("CTAP2_ERR_NO_CREDENTIALS", FidoError::NotEnrolled),
        ("CTAP2_ERR_PIN_REQUIRED", FidoError::PinRequired),
        ("CTAP2_ERR_PUAT_REQUIRED", FidoError::PinRequired),
    ];
    cases
        .into_iter()
        .find(|(needle, _)| text.contains(needle))
        .map_or(FidoError::Other(error), |(_, case)| case)
}

#[cfg(test)]
mod tests;
