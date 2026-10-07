//! What fido2lock knows about the inserted keys, and when it locks. It does no IO, so the tests
//! cover every rule.

use std::collections::{BTreeMap, BTreeSet};

/// An IORegistry entry ID. hidapi names the same device `DevSrvsID:<id>`.
pub type Id = u64;

/// Seconds after a wake during which removals wait, because USB devices may reconnect.
pub const WAKE_WINDOW: u64 = 10;

/// Milliseconds an insertion check waits before it talks to the key. Some keys (Token2) switch
/// their smart card interface away from PIV on any FIDO message, so a check during macOS's PIV read
/// at insertion leaves the key without its smart card identity until it is plugged in again.
pub const SETTLE_MS: i64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Enrolled(String),
    Unknown,
    Failed,
}

/// One check of one device. A newer check of the same device makes older results stale, because
/// they may come from an older key list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Check {
    pub id: Id,
    pub generation: u64,
    /// Wait `SETTLE_MS` first, because the key just appeared.
    pub settle: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Appeared(Id),
    /// The key list changed, so every inserted device is checked again.
    Recheck,
    Checked(Check, Outcome),
    Removed(Id),
    Pause,
    Resume,
    WillSleep,
    DidWake,
    /// A timer from `Action::Timer` ended.
    Due(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Check(Vec<Check>),
    Lock,
    /// Feed `Due(token)` after `seconds`.
    Timer {
        token: u64,
        seconds: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    generation: u64,
    /// True while an insertion check is in flight, even if a recheck replaced it.
    inserted: bool,
}

#[derive(Debug, Default)]
pub struct State {
    armed: BTreeMap<Id, String>,
    pending: BTreeMap<Id, Pending>,
    generation: u64,
    failed: BTreeSet<Id>,
    present: BTreeSet<Id>,
    paused: bool,
    can_lock: bool,
    /// Seconds between removing an armed key and locking.
    delay: u64,
    sleeping: bool,
    /// The token of the running wake window.
    wake: Option<u64>,
    /// A removal waits for the wake window to end.
    held: bool,
    /// The token of the running countdown.
    due: Option<u64>,
    tokens: u64,
}

impl State {
    pub fn new(can_lock: bool) -> Self {
        Self {
            can_lock,
            ..Self::default()
        }
    }

    pub fn handle(&mut self, event: Event) -> Action {
        match event {
            Event::Appeared(id) => {
                self.present.insert(id);
                Action::Check(vec![self.start(id, true)])
            }
            Event::Recheck => {
                let ids: Vec<Id> = self.present.iter().copied().collect();
                Action::Check(ids.into_iter().map(|id| self.start(id, false)).collect())
            }
            Event::Checked(check, outcome) => {
                // A result for a device that left, or from an older check, is stale.
                let Some(pending) = self.pending.get(&check.id).copied() else {
                    return Action::None;
                };
                if pending.generation != check.generation {
                    return Action::None;
                }
                self.pending.remove(&check.id);
                self.failed.remove(&check.id);
                match outcome {
                    Outcome::Enrolled(label) => {
                        self.armed.insert(check.id, label);
                        // An enrolled key back in ends a pause and cancels a pending lock. A
                        // recheck of a key that never left does neither.
                        if pending.inserted {
                            self.paused = false;
                            self.due = None;
                            self.held = false;
                        }
                    }
                    // A key that stops answering stays armed: a missed lock is worse than a
                    // surprise one.
                    Outcome::Failed => {
                        self.failed.insert(check.id);
                    }
                    Outcome::Unknown => {
                        self.armed.remove(&check.id);
                    }
                }
                Action::None
            }
            Event::Removed(id) => {
                self.present.remove(&id);
                self.pending.remove(&id);
                self.failed.remove(&id);
                let was_armed = self.armed.remove(&id).is_some();
                if !was_armed || self.paused || !self.can_lock {
                    Action::None
                } else if self.sleeping || self.wake.is_some() {
                    self.held = true;
                    Action::None
                } else {
                    self.countdown()
                }
            }
            Event::Pause => {
                if !self.armed.is_empty() {
                    self.paused = true;
                }
                Action::None
            }
            Event::Resume => {
                self.paused = false;
                Action::None
            }
            Event::WillSleep => {
                self.sleeping = true;
                // The old window's timer can fire after the next wake, before its DidWake.
                self.wake = None;
                Action::None
            }
            Event::DidWake => {
                self.sleeping = false;
                let token = self.token();
                self.wake = Some(token);
                Action::Timer {
                    token,
                    seconds: WAKE_WINDOW,
                }
            }
            Event::Due(token) if self.wake == Some(token) => {
                self.wake = None;
                // A held removal counts as happening now.
                if std::mem::take(&mut self.held) && !self.paused && self.can_lock {
                    self.countdown()
                } else {
                    Action::None
                }
            }
            Event::Due(token) if self.due == Some(token) => {
                self.due = None;
                if !self.paused && self.can_lock {
                    Action::Lock
                } else {
                    Action::None
                }
            }
            // A cancelled or replaced timer.
            Event::Due(_) => Action::None,
        }
    }

    /// Locks now, or starts the countdown. A running countdown keeps its end.
    fn countdown(&mut self) -> Action {
        if self.due.is_some() {
            return Action::None;
        }
        if self.delay == 0 {
            return Action::Lock;
        }
        let token = self.token();
        self.due = Some(token);
        Action::Timer {
            token,
            seconds: self.delay,
        }
    }

    fn token(&mut self) -> u64 {
        self.tokens += 1;
        self.tokens
    }

    fn start(&mut self, id: Id, inserted: bool) -> Check {
        self.generation += 1;
        let generation = self.generation;
        let inserted = inserted || self.pending.get(&id).is_some_and(|p| p.inserted);
        self.pending.insert(
            id,
            Pending {
                generation,
                inserted,
            },
        );
        Check {
            id,
            generation,
            settle: inserted,
        }
    }

    /// The labels of the armed keys, in entry ID order.
    pub fn armed(&self) -> Vec<&str> {
        self.armed.values().map(String::as_str).collect()
    }

    pub fn set_delay(&mut self, seconds: u64) {
        self.delay = seconds;
    }

    /// A countdown runs, or a removal waits for the wake window.
    pub fn lock_pending(&self) -> bool {
        self.due.is_some() || self.held
    }

    pub fn paused(&self) -> bool {
        self.paused
    }

    pub fn can_lock(&self) -> bool {
        self.can_lock
    }

    pub fn check_failed(&self) -> bool {
        !self.failed.is_empty()
    }

    /// The number of inserted FIDO devices.
    pub fn present(&self) -> usize {
        self.present.len()
    }
}

#[cfg(test)]
mod tests;
