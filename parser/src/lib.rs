#![cfg_attr(feature = "unstable", feature(core_intrinsics))]

#[macro_use]
extern crate log;
#[macro_use]
extern crate derive_more;

pub mod cond_stmt;
mod mut_input;
pub mod track;


mod fuzz_main;

pub use crate::fuzz_main::fuzz_main;
