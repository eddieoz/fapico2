//! Aggregator crate for the device app set (US-386+).
//!
//! Owns the single source of truth for which CCID apps the device wires behind
//! the AID dispatcher (see [`registry`]). The firmware's device build depends
//! on this crate for the registry; the app dependencies are optional (enabled
//! by the `host` feature) so the device build compiles the registry without the
//! host/virt app stacks. The registry tests run on the host.

#![no_std]

pub mod registry;
