// Fixture for lints/mod-declaration-visibility-order.yml.
// Declarations the rule must report carry a trailing marker; the checker counts them.

pub mod ok_widest_first;
pub(crate) mod ok_restricted_second;

mod ok_private_last;

#[macro_use]
mod ok_macro_use_stays_first;
pub mod ok_after_macro_use;

mod private_before_pub;
pub mod pub_after_private; //~ VIOLATION

pub(crate) mod restricted_before_pub;
pub mod pub_after_restricted; //~ VIOLATION

mod private_before_restricted;
pub(crate) mod restricted_after_private; //~ VIOLATION

mod private_before_super;
pub(super) mod super_after_private; //~ VIOLATION

mod private_before_documented;
// A comment must not hide the predecessor from the rule.
pub mod documented_after_private; //~ VIOLATION
