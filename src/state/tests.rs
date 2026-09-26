use super::*;

fn enrolled(label: &str) -> Outcome {
    Outcome::Enrolled(label.to_owned())
}

/// Feeds `event` and returns the checks it starts.
fn start(state: &mut State, event: Event) -> Vec<Check> {
    match state.handle(event) {
        Action::Check(checks) => checks,
        other => panic!("expected checks, got {other:?}"),
    }
}

fn finish(state: &mut State, check: Check, outcome: Outcome) -> Action {
    state.handle(Event::Checked(check, outcome))
}

/// A state with key `id` inserted and checked as `label`.
fn armed_with(id: Id, label: &str) -> State {
    let mut state = State::new(true);
    let checks = start(&mut state, Event::Appeared(id));
    finish(&mut state, checks[0], enrolled(label));
    state
}

#[test]
fn an_inserted_device_is_checked() {
    let mut state = State::new(true);
    let checks = start(&mut state, Event::Appeared(7));
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].id, 7);
    assert_eq!(state.present(), 1);
    assert!(state.armed().is_empty());
}

#[test]
fn removing_an_armed_key_locks() {
    let mut state = armed_with(7, "blue");
    assert_eq!(state.armed(), ["blue"]);
    assert_eq!(state.handle(Event::Removed(7)), Action::Lock);
    assert!(state.armed().is_empty());
    assert_eq!(state.present(), 0);
}

#[test]
fn removing_an_unknown_key_does_nothing() {
    let mut state = State::new(true);
    let checks = start(&mut state, Event::Appeared(7));
    finish(&mut state, checks[0], Outcome::Unknown);
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
}

#[test]
fn a_key_removed_before_its_check_never_arms() {
    let mut state = State::new(true);
    let checks = start(&mut state, Event::Appeared(7));
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
    finish(&mut state, checks[0], enrolled("blue"));
    assert!(state.armed().is_empty());
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
}

#[test]
fn a_failed_check_warns_until_the_device_goes() {
    let mut state = State::new(true);
    let checks = start(&mut state, Event::Appeared(7));
    finish(&mut state, checks[0], Outcome::Failed);
    assert!(state.check_failed());
    assert!(state.armed().is_empty());
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
    assert!(!state.check_failed());
}

#[test]
fn pause_stops_the_lock_until_an_enrolled_key_is_inserted() {
    let mut state = armed_with(7, "blue");
    state.handle(Event::Pause);
    assert!(state.paused());
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
    assert!(state.paused());
    let checks = start(&mut state, Event::Appeared(8));
    finish(&mut state, checks[0], enrolled("blue"));
    assert!(!state.paused());
    assert_eq!(state.handle(Event::Removed(8)), Action::Lock);
}

#[test]
fn an_unknown_key_does_not_end_a_pause() {
    let mut state = armed_with(7, "blue");
    state.handle(Event::Pause);
    let checks = start(&mut state, Event::Appeared(8));
    finish(&mut state, checks[0], Outcome::Unknown);
    assert!(state.paused());
}

#[test]
fn pause_needs_an_armed_key_and_resume_ends_it() {
    let mut state = State::new(true);
    state.handle(Event::Pause);
    assert!(!state.paused());
    let mut state = armed_with(7, "blue");
    state.handle(Event::Pause);
    state.handle(Event::Resume);
    assert!(!state.paused());
    assert_eq!(state.handle(Event::Removed(7)), Action::Lock);
}

#[test]
fn a_recheck_checks_every_inserted_device() {
    let mut state = armed_with(7, "blue");
    let checks = start(&mut state, Event::Appeared(9));
    finish(&mut state, checks[0], Outcome::Unknown);
    let ids: Vec<Id> = start(&mut state, Event::Recheck)
        .iter()
        .map(|check| check.id)
        .collect();
    assert_eq!(ids, [7, 9]);
}

#[test]
fn a_recheck_disarms_a_key_that_left_the_list() {
    let mut state = armed_with(7, "blue");
    let checks = start(&mut state, Event::Recheck);
    // Still armed while the check runs.
    assert_eq!(state.armed(), ["blue"]);
    finish(&mut state, checks[0], Outcome::Unknown);
    assert!(state.armed().is_empty());
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
}

#[test]
fn a_recheck_arms_a_newly_enrolled_key_but_keeps_a_pause() {
    let mut state = armed_with(7, "blue");
    let checks = start(&mut state, Event::Appeared(9));
    finish(&mut state, checks[0], Outcome::Unknown);
    state.handle(Event::Pause);
    let checks = start(&mut state, Event::Recheck);
    finish(&mut state, checks[0], enrolled("blue"));
    finish(&mut state, checks[1], enrolled("green"));
    assert_eq!(state.armed(), ["blue", "green"]);
    assert!(state.paused());
}

#[test]
fn a_result_older_than_a_recheck_is_ignored() {
    let mut state = State::new(true);
    let first = start(&mut state, Event::Appeared(7));
    let second = start(&mut state, Event::Recheck);
    // The insertion check read the old list and reports after the recheck started.
    finish(&mut state, first[0], enrolled("blue"));
    assert!(state.armed().is_empty());
    finish(&mut state, second[0], Outcome::Unknown);
    assert!(state.armed().is_empty());
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
}

#[test]
fn a_recheck_during_an_insertion_check_still_ends_a_pause() {
    let mut state = armed_with(7, "blue");
    state.handle(Event::Pause);
    state.handle(Event::Removed(7));
    start(&mut state, Event::Appeared(8));
    let second = start(&mut state, Event::Recheck);
    finish(&mut state, second[0], enrolled("blue"));
    assert!(!state.paused());
}

#[test]
fn a_failed_recheck_keeps_an_armed_key_armed() {
    let mut state = armed_with(7, "blue");
    let checks = start(&mut state, Event::Recheck);
    finish(&mut state, checks[0], Outcome::Failed);
    assert_eq!(state.armed(), ["blue"]);
    assert!(state.check_failed());
    assert_eq!(state.handle(Event::Removed(7)), Action::Lock);
}

#[test]
fn two_armed_keys_lock_on_either_removal() {
    let mut state = armed_with(7, "blue");
    let checks = start(&mut state, Event::Appeared(8));
    finish(&mut state, checks[0], enrolled("green"));
    assert_eq!(state.handle(Event::Removed(8)), Action::Lock);
    assert_eq!(state.armed(), ["blue"]);
}

#[test]
fn nothing_locks_without_the_lock_function() {
    let mut state = State::new(false);
    let checks = start(&mut state, Event::Appeared(7));
    finish(&mut state, checks[0], enrolled("blue"));
    assert!(!state.can_lock());
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
}

#[test]
fn a_result_without_a_pending_check_is_ignored() {
    let mut state = State::new(true);
    let stray = Check {
        id: 7,
        generation: 1,
    };
    finish(&mut state, stray, enrolled("blue"));
    assert!(state.armed().is_empty());
}

/// Feeds `event` and returns the timer it starts.
fn timer(state: &mut State, event: Event) -> (u64, u64) {
    match state.handle(event) {
        Action::Timer { token, seconds } => (token, seconds),
        other => panic!("expected a timer, got {other:?}"),
    }
}

/// Inserts key `id` and checks it as `label`.
fn insert(state: &mut State, id: Id, label: &str) {
    let checks = start(state, Event::Appeared(id));
    finish(state, checks[0], enrolled(label));
}

#[test]
fn a_delay_of_zero_locks_at_once() {
    let mut state = armed_with(7, "blue");
    state.set_delay(0);
    assert_eq!(state.handle(Event::Removed(7)), Action::Lock);
    assert!(!state.lock_pending());
}

#[test]
fn a_delay_locks_when_the_countdown_ends() {
    let mut state = armed_with(7, "blue");
    state.set_delay(5);
    let (token, seconds) = timer(&mut state, Event::Removed(7));
    assert_eq!(seconds, 5);
    assert!(state.lock_pending());
    assert_eq!(state.handle(Event::Due(token)), Action::Lock);
    assert!(!state.lock_pending());
    assert_eq!(state.handle(Event::Due(token)), Action::None);
}

#[test]
fn an_enrolled_key_cancels_the_countdown() {
    let mut state = armed_with(7, "blue");
    state.set_delay(5);
    let (token, _) = timer(&mut state, Event::Removed(7));
    insert(&mut state, 8, "green");
    assert!(!state.lock_pending());
    assert_eq!(state.handle(Event::Due(token)), Action::None);
    assert_eq!(state.armed(), ["green"]);
}

#[test]
fn a_failed_check_does_not_cancel_the_countdown() {
    let mut state = armed_with(7, "blue");
    state.set_delay(5);
    let (token, _) = timer(&mut state, Event::Removed(7));
    let checks = start(&mut state, Event::Appeared(8));
    finish(&mut state, checks[0], Outcome::Failed);
    let checks = start(&mut state, Event::Appeared(9));
    finish(&mut state, checks[0], Outcome::Unknown);
    assert_eq!(state.handle(Event::Due(token)), Action::Lock);
}

#[test]
fn a_second_removal_keeps_the_first_countdown() {
    let mut state = armed_with(7, "blue");
    insert(&mut state, 8, "green");
    state.set_delay(5);
    let (token, _) = timer(&mut state, Event::Removed(7));
    assert_eq!(state.handle(Event::Removed(8)), Action::None);
    assert_eq!(state.handle(Event::Due(token)), Action::Lock);
}

#[test]
fn a_pause_during_the_countdown_stops_the_lock() {
    let mut state = armed_with(7, "blue");
    insert(&mut state, 8, "green");
    state.set_delay(5);
    let (token, _) = timer(&mut state, Event::Removed(7));
    state.handle(Event::Pause);
    assert_eq!(state.handle(Event::Due(token)), Action::None);
}

#[test]
fn a_removal_during_sleep_locks_when_the_wake_window_ends() {
    let mut state = armed_with(7, "blue");
    state.handle(Event::WillSleep);
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
    assert!(state.lock_pending());
    let (wake, seconds) = timer(&mut state, Event::DidWake);
    assert_eq!(seconds, WAKE_WINDOW);
    assert_eq!(state.handle(Event::Due(wake)), Action::Lock);
    assert!(!state.lock_pending());
}

#[test]
fn a_removal_in_the_wake_window_is_held() {
    let mut state = armed_with(7, "blue");
    state.handle(Event::WillSleep);
    let (wake, _) = timer(&mut state, Event::DidWake);
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
    assert_eq!(state.handle(Event::Due(wake)), Action::Lock);
}

#[test]
fn a_key_that_reconnects_on_wake_does_not_lock() {
    let mut state = armed_with(7, "blue");
    state.handle(Event::WillSleep);
    let (wake, _) = timer(&mut state, Event::DidWake);
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
    insert(&mut state, 8, "blue");
    assert!(!state.lock_pending());
    assert_eq!(state.handle(Event::Due(wake)), Action::None);
    // After the window, a removal locks at once again.
    assert_eq!(state.handle(Event::Removed(8)), Action::Lock);
}

#[test]
fn a_held_removal_with_a_delay_starts_the_countdown() {
    let mut state = armed_with(7, "blue");
    state.set_delay(5);
    state.handle(Event::WillSleep);
    state.handle(Event::Removed(7));
    let (wake, _) = timer(&mut state, Event::DidWake);
    let (due, seconds) = timer(&mut state, Event::Due(wake));
    assert_eq!(seconds, 5);
    assert!(state.lock_pending());
    assert_eq!(state.handle(Event::Due(due)), Action::Lock);
}

#[test]
fn a_second_wake_makes_the_first_window_stale() {
    let mut state = armed_with(7, "blue");
    let (first, _) = timer(&mut state, Event::DidWake);
    let (second, _) = timer(&mut state, Event::DidWake);
    assert_ne!(first, second);
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
    assert_eq!(state.handle(Event::Due(first)), Action::None);
    assert!(state.lock_pending());
    assert_eq!(state.handle(Event::Due(second)), Action::Lock);
}

#[test]
fn a_wake_without_sleep_still_ends() {
    let mut state = armed_with(7, "blue");
    let (wake, _) = timer(&mut state, Event::DidWake);
    assert_eq!(state.handle(Event::Due(wake)), Action::None);
    assert_eq!(state.handle(Event::Removed(7)), Action::Lock);
}

#[test]
fn a_held_removal_while_paused_or_unable_to_lock_does_nothing() {
    let mut state = armed_with(7, "blue");
    state.handle(Event::Pause);
    state.handle(Event::WillSleep);
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
    assert!(!state.lock_pending());

    let mut state = State::new(false);
    insert(&mut state, 7, "blue");
    state.handle(Event::WillSleep);
    state.handle(Event::Removed(7));
    let (wake, _) = timer(&mut state, Event::DidWake);
    assert_eq!(state.handle(Event::Due(wake)), Action::None);
}

#[test]
fn an_old_wake_window_ends_nothing_after_a_new_sleep() {
    let mut state = armed_with(7, "blue");
    let (old, _) = timer(&mut state, Event::DidWake);
    state.handle(Event::WillSleep);
    assert_eq!(state.handle(Event::Removed(7)), Action::None);
    assert_eq!(state.handle(Event::Due(old)), Action::None);
    let (wake, _) = timer(&mut state, Event::DidWake);
    assert_eq!(state.handle(Event::Due(wake)), Action::Lock);
}

#[test]
fn a_recheck_of_a_key_that_stayed_does_not_cancel_the_countdown() {
    let mut state = armed_with(7, "blue");
    insert(&mut state, 8, "green");
    state.set_delay(5);
    let (token, _) = timer(&mut state, Event::Removed(7));
    let checks = start(&mut state, Event::Recheck);
    assert_eq!(checks.len(), 1);
    finish(&mut state, checks[0], enrolled("green"));
    assert!(state.lock_pending());
    assert_eq!(state.handle(Event::Due(token)), Action::Lock);
}
