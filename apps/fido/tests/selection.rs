//! FX-415: authenticatorSelection (CTAP2.1 §6.3, command 0x0B).

use fapico2_fido::app::FidoApp;
use fapico2_fido::keystore::MemoryKeystore;

#[test]
fn test_authenticator_selection_returns_ok() {
    let mut app = FidoApp::with_keystore(MemoryKeystore::new());
    // The reference C firmware auto-accepts selection in emulation; the
    // command must be dispatched (previously unhandled → InvalidCommand).
    let resp = app.process_ctap2(0x0B, &[], [1, 2, 3, 4]);
    assert_eq!(resp, vec![0x00], "authenticatorSelection must return CTAP2_OK");
}
