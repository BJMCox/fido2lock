use super::*;

// Resolves the function without calling it: calling it would lock the screen.
#[test]
fn the_lock_function_resolves() {
    assert!(Screen::load().is_some());
}
