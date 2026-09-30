// SPDX-License-Identifier: BSD-3-Clause
#![forbid(unsafe_code)]
#![warn(unused_attributes, unused_imports, unused_mut, unused_must_use)]
#![no_std]
#[cfg(test)]
extern crate std;
// XXX: Change this to deny later on
// As usual, we will use this file to carefully define the API/ what we expose to the user
pub mod constants;
pub mod curve;
pub mod decaf;
mod field;
pub mod ristretto;
pub use field::Scalar;
