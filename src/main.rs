mod config;
mod keys;
mod lock;
mod ops;
mod state;
mod ui;
mod watch;

// The shared kit's modules, at the paths the other modules already use.
use fido2kit::fido;
use fido2kit_mac::panels;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

const USAGE: &str = "usage: fido2lock [enroll-key --label NAME | remove-key --label NAME [--label NAME ...] | check-key | list-keys | completions zsh | help]";
const HELP: &str = "fido2lock: lock your Mac when you remove your FIDO2 security key

Run without arguments to start the menu-bar app.

Commands:
  enroll-key --label NAME                Enroll the inserted security key
  remove-key --label NAME [--label ...]  Remove enrolled keys
  check-key                              Show whether the inserted key is enrolled
  list-keys                              List the labels of the enrolled keys
  completions zsh                        Print the zsh completion script
  help, --help, -h                       Show this help

Keys: ~/Library/Application Support/fido2lock/keys.toml
";
const COMPLETIONS: &str = include_str!("completions.zsh");

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    dispatch(&args)
}

fn dispatch(args: &[&str]) -> Result<()> {
    match args {
        [] => ui::run(),
        ["enroll-key", "--label", label] => enroll_key(label),
        ["remove-key", rest @ ..] => match labels(rest) {
            Some(labels) => remove_keys(&labels),
            None => bail!("{USAGE}\nRun `fido2lock help` for details."),
        },
        ["check-key"] => check_key(),
        ["list-keys"] => list_keys(),
        ["help"] | ["--help"] | ["-h"] => {
            print!("{HELP}");
            Ok(())
        }
        ["completions", "zsh"] => {
            print!("{COMPLETIONS}");
            Ok(())
        }
        _ => bail!("{USAGE}\nRun `fido2lock help` for details."),
    }
}

fn enroll_key(label: &str) -> Result<()> {
    let path = keys::path()?;
    keys::check_label(label)?;
    let key = choose_key()?;
    let report = with_pin(
        "FIDO2 PIN (leave blank if the key has none): ",
        "Touch your security key.",
        |pin| ops::enroll(&path, &key, label, pin),
    )?;
    ui::announce_keys_changed();
    println!("{report}");
    Ok(())
}

/// The labels of `--label NAME` pairs, or `None` if `args` holds anything else.
fn labels(args: &[&str]) -> Option<Vec<String>> {
    if args.is_empty() || !args.len().is_multiple_of(2) {
        return None;
    }
    args.chunks(2)
        .map(|pair| (pair[0] == "--label").then(|| pair[1].to_owned()))
        .collect()
}

fn remove_keys(labels: &[String]) -> Result<()> {
    let report = ops::remove(&keys::path()?, labels)?;
    ui::announce_keys_changed();
    println!("{report}");
    Ok(())
}

fn check_key() -> Result<()> {
    let keys = keys::load(&keys::path()?)?;
    let key = choose_key()?;
    let result = ops::identify(&key, &keys);
    let report = ops::check_report(&result);
    result?;
    println!("{report}");
    Ok(())
}

fn list_keys() -> Result<()> {
    for key in keys::load(&keys::path()?)? {
        println!("{}", key.label);
    }
    Ok(())
}

/// Picks the security key before its PIN is asked, as the FIDO standard flow does. With several
/// keys inserted, the user touches the one to use.
fn choose_key() -> Result<fido::Key> {
    if fido::devices().len() > 1 {
        println!("Touch the security key you want to use.");
    }
    ops::choose_key()
}

/// Asks for the PIN, prints `touch`, and runs `op`. After a wrong or missing PIN it asks again,
/// while the key counts down its tries.
fn with_pin<T>(prompt: &str, touch: &str, op: impl Fn(&str) -> Result<T>) -> Result<T> {
    loop {
        let pin = hidden(prompt)?;
        println!("{touch}");
        match op(&pin) {
            Err(error) if fido::retry_pin(&error) => eprintln!("{error:#}"),
            other => return other,
        }
    }
}

fn hidden(prompt: &str) -> Result<Zeroizing<String>> {
    let text = rpassword::prompt_password(prompt)
        .context("Cannot read a hidden prompt. Run this command in a Terminal window")?;
    Ok(Zeroizing::new(text))
}

#[cfg(test)]
mod tests;
