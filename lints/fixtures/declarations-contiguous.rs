// Fixture for lints/mod-declarations-contiguous.yml.
// Declarations the rule must report carry a trailing marker; the checker counts them.

pub mod first_run_a;
// A comment inside a run does not split it.
pub mod first_run_b;
#[cfg(test)]
mod first_run_cfg_gated;

mod first_run_c;

use std::fmt;

pub mod second_run; //~ VIOLATION
mod second_run_tail;
