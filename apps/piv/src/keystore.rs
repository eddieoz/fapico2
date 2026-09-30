//! PIV keystore — host/emulation persistence.
//!
//! Stand-in for the C `flash_commit()` + file layer: the PIV state (auth
//! half per US-372, data objects per US-373) is snapshotted as CBOR to the
//! platform secure store, mirroring `apps/fido/src/keystore.rs` (US-322 /
//! FX-409): the write goes to `<path>.tmp` then renames over the target so
//! a crash mid-write never corrupts the snapshot, and a snapshot that
//! exists but cannot be parsed is an error — it is never silently reset.
//!
//! The session half of the state (mgm/PIN auth, pending challenge) is
//! volatile (C `init_piv`) and is cleared on load. Device-side persistence
//! (RP2350 secure partition) is future work.

use crate::PivState;
use fapico2_platform::secure_store::{FileSecureStore, SecureStore};

/// Versioned snapshot key (FX-409).
const PIV_KEYSTORE_SLOT: &[u8] = b"piv.keystore.v1";

#[derive(Debug)]
pub enum PivKeystoreError {
    Io,
    Invalid,
}

pub struct PivKeystore {
    store: FileSecureStore,
}

impl PivKeystore {
    /// Load the snapshot from `path` if present, else start from factory
    /// defaults and persist it. A present-but-unparseable snapshot is an
    /// error (never silently reset, FX-409).
    pub(crate) fn load_or_create(
        path: std::path::PathBuf,
    ) -> Result<(PivState, Self), PivKeystoreError> {
        let store = FileSecureStore::new(path);
        let location = store.path().display().to_string();
        let state = if store.contains(PIV_KEYSTORE_SLOT) {
            let bytes = store
                .read_all(PIV_KEYSTORE_SLOT)
                .map_err(|_| PivKeystoreError::Io)?;
            let mut st: PivState =
                serde_cbor::from_slice(&bytes).map_err(|_| PivKeystoreError::Invalid)?;
            // Session state is volatile (C `init_piv`): clear on load.
            st.has_pwpiv = false;
            st.has_mgm = false;
            st.mgm_challenge = [0; 16];
            st.mgm_challenge_kind = 0;
            st.mgm_challenge_algo = 0;
            st
        } else {
            PivState::default()
        };
        let ks = Self { store };
        // Refresh the snapshot (writes factory defaults on first run).
        ks.persist(&state).map_err(|e| {
            eprintln!("fapico2-piv: initial persist to {location} failed: {e:?}");
            e
        })?;
        Ok((state, ks))
    }

    /// Serialize the state to the secure partition atomically.
    pub(crate) fn persist(&self, st: &PivState) -> Result<(), PivKeystoreError> {
        let bytes = serde_cbor::to_vec(st).map_err(|_| PivKeystoreError::Invalid)?;
        self.store
            .write_all(PIV_KEYSTORE_SLOT, &bytes)
            .map_err(|_| PivKeystoreError::Io)
    }
}
