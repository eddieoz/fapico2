//! US-1557 — `app.rs` and `device_app.rs` agree.
//!
//! ```gherkin
//! Scenario: app.rs and device_app.rs agree
//!   Given a credential enrolled through device_app::FidoApp
//!   And the same sequence driven through app.rs::FidoApp
//!   Then both report the same capacity, remaining count and boundary error
//! ```
//!
//! # Why this file exists at all
//!
//! `AGENTS.md` §1: *"`app.rs` is a twin, not the shipped one. Fixing only
//! `app.rs` passes every host test and changes nothing on hardware — that is
//! not hypothetical; it is how the credential-management dialect work in PR #3
//! went partly wrong."* The size gap is the scale of the risk: `app.rs` is
//! 4,196 lines against `device_app.rs`'s 1,193, and the host twin's keystore
//! (`keystore.rs`, `MemoryKeystore`/`FileKeystore`) is a **completely separate
//! store** with no `KeyRegion` in it at all. Two implementations, two storage
//! backends, one wire protocol, and no test that drives both.
//!
//! # What is asserted, and what is deliberately not
//!
//! **Asserted equal, on the same script, on both twins:**
//!
//! | what | why it must be equal |
//! |---|---|
//! | every status byte | the byte is the whole contract; `AGENTS.md` §4's "derive the claim from the state it describes" only means something if both twins derive the same one |
//! | the CBOR **key set** of each reply | `AGENTS.md` §2 — the PicoForge dialect is binding (`rp=3, rpID=4, totalRps=5`), and the two dialects' key sets *collide*, so "we answered in the sender's dialect" is only half the claim |
//! | the credential and RP counts | a Slots screen that shows the wrong number is the US-1514 symptom |
//! | `remaining`'s *semantics* — `remaining == capacity − existing` after each enrolment | the absolute number differs by construction (see below); the rule must not |
//! | the boundary error byte | `0x28 KEY_STORE_FULL` on both, reached at each twin's own boundary |
//!
//! **Deliberately not asserted equal: the capacity number itself**, and the
//! reason is the point of the story rather than an evasion of it. The device's
//! capacity is [`FIDO_CAPACITY`] — 856, derived from the region's geometry. The
//! host twin's is whatever `MemoryKeystore::with_max_creds` was given, which in
//! a test is chosen to make the test fast and on a board would be a fiction.
//! Comparing them would assert that they differ; skipping them would assert
//! nothing. So [`CredentialBackend`] makes the divergence a **value both twins
//! return**, and [`the_capacity_divergence_is_explicit_not_incidental`] asserts
//! both halves of it.
//!
//! # What the host twin still cannot mirror, stated plainly
//!
//! **Storage.** The host twin cannot reach the key region: `keystore.rs`'s
//! backend has no `KeyRegion`, no `RegionKeys`, and no on-demand read path, and
//! its credentials are host-file CBOR. Standing up a region-backed host twin
//! would be a second storage stack — precisely the accretion `AGENTS.md` §5
//! warns against ("three backends, three protection stories") — and it is not
//! what this story is for. So the wire shapes are mirrored and the storage is
//! declared different, at the type level, and asserted.

mod common;
mod region_boot;

use common::PinClient;
use fapico2_fido::app::FidoApp as HostApp;
use fapico2_fido::cbor::{self, Value};
use fapico2_fido::crypto;
use fapico2_fido::device_keystore::CredentialBackend;
use fapico2_fido::keystore::{Keystore, MemoryKeystore};
use fapico2_platform::keyregion::FIDO_CAPACITY;
use region_boot::Device;

// ---------------------------------------------------------------------------
// One script, two twins
// ---------------------------------------------------------------------------

/// The commands a WebAuthn client actually drives, and which both twins must
/// answer identically.
///
/// A trait rather than two hand-written scripts because the whole claim is
/// that they are *the same script*: a trait makes "the same steps, in the same
/// order, against both" a property the compiler checks rather than a habit two
/// functions have to maintain.
trait Twin {
    /// Enrol one resident credential; returns the CTAP2 status byte.
    fn enroll(&mut self, rp: &str, user: &[u8]) -> u8;
    /// credMgmt `getCredsMetadata` (PicoForge sub-command `0x01`).
    fn get_metadata(&mut self) -> (u8, Vec<u8>);
    /// credMgmt `enumerateRpsBegin` (PicoForge `0x02`).
    fn enumerate_rps_begin(&mut self) -> (u8, Vec<u8>);
    /// credMgmt `enumerateRpsGetNext` (PicoForge `0x03`).
    fn enumerate_rps_next(&mut self) -> (u8, Vec<u8>);
    /// credMgmt `enumerateCredsBegin` (PicoForge `0x04`).
    fn enumerate_creds_begin(&mut self, rp: &str) -> (u8, Vec<u8>);
    /// How many more credentials this twin can take, as it reports them.
    fn capacity(&mut self) -> u32;
    /// Which store answers this twin's capacity questions.
    fn backend(&self) -> CredentialBackend;
    /// Fill to this twin's own boundary and return the refusal's status byte.
    fn enroll_past_the_boundary(&mut self) -> u8;
}

/// One step's observable result: the status byte, the reply's key set, and the
/// counts a client renders.
///
/// The counts are `Option`s because the point of some steps is that a key is
/// *absent* — `enumerateRpsBegin`'s PicoForge reply must not carry key 7, and a
/// tuple that could not express absence would assert nothing about it.
#[derive(Debug, PartialEq, Eq)]
struct Observation {
    step: &'static str,
    status: u8,
    keys: Vec<u64>,
    /// `existingResidentCredentialsCount` from `getMetadata`, else `None`.
    ///
    /// **`remaining` and `total` are deliberately absent.** `total` is the
    /// capacity, and the capacity is the one number the twins legitimately
    /// disagree about — comparing it here would either fail for the right reason
    /// or, worse, be deleted to make the test pass. `remaining`'s *semantics*
    /// are asserted instead, as a delta, by
    /// [`remaining_count_semantics_agree_even_though_the_numbers_do_not`], which
    /// is the property a Slots screen actually depends on.
    existing: Option<u64>,
    /// `totalRps` from `enumerateRpsBegin`, else `None`.
    total_rps: Option<u64>,
    /// `totalCredentials` from `enumerateCredsBegin`, else `None`.
    total_creds: Option<u64>,
}

impl Observation {
    fn new(step: &'static str, status: u8, cbor: &[u8]) -> Self {
        Observation {
            step,
            status,
            keys: region_boot::top_level_keys(cbor),
            existing: if status == 0x00 { region_boot::uint_at(cbor, 1) } else { None },
            total_rps: if status == 0x00 { region_boot::uint_at(cbor, 5) } else { None },
            total_creds: if status == 0x00 { region_boot::uint_at(cbor, 9) } else { None },
        }
    }
}

/// The credential-management request, in PicoForge's exact wire form.
///
/// **Byte-identical on both twins** — the only difference between the two
/// invocations is the pinUvAuthToken it is signed with, and each twin's token
/// is necessarily its own (the ECDH key agreement is per-authenticator). The
/// *protocol* is 2 for both, and the sub-command and parameter layout is
/// PicoForge's: parameters nested under key `0x02` as a bare map, protocol at
/// `0x03`, `pinUvAuthParam` at `0x04`.
///
/// `AGENTS.md` §2: this is binding. `enumerateRpsBegin` is sub-command **`0x02`**
/// here, not CTAP 2.1's `0x01`, and the reply carries `rp=3, rpID=4, totalRps=5`.
fn cm_request(subcommand: u8, token: &[u8], params: Option<Value>) -> Vec<u8> {
    let mut auth_msg: Vec<u8> = vec![subcommand];
    let mut map = vec![(Value::U(0x01), Value::U(subcommand as u64))];
    if let Some(p) = params {
        // PicoForge signs `subCommand ‖ CBOR(subCommandParams)` — except for the
        // two sub-commands whose parameters are empty, which it signs bare.
        if !matches!(subcommand, 0x01 | 0x02) {
            auth_msg.extend_from_slice(&cbor::encode(&p));
        }
        map.push((Value::U(0x02), p));
    }
    map.push((Value::U(0x03), Value::U(2)));
    map.push((
        Value::U(0x04),
        Value::B(crypto::pin_uv_auth_param(2, &token.try_into().unwrap(), &auth_msg)),
    ));
    cbor::encode(&Value::M(map))
}

/// The script: enrol three credentials across two relying parties, then read
/// the counts and the enumerations back.
///
/// Every step's observation is returned so the caller can compare the two
/// twins step by step rather than assert "the last reply looked right".
fn run_script<T: Twin>(twin: &mut T) -> Vec<Observation> {
    let mut out = Vec::new();

    let (status, cbor) = twin.get_metadata();
    out.push(Observation::new("getMetadata/empty", status, &cbor));

    for (i, (rp, user)) in [RP_A, RP_B, RP_A_SECOND].iter().copied().enumerate() {
        let status = twin.enroll(rp, user);
        assert_eq!(
            status, 0x00,
            "step {i}: enrolling a resident credential for {rp} must succeed on both twins"
        );
    }

    let (status, cbor) = twin.get_metadata();
    out.push(Observation::new("getMetadata/three", status, &cbor));

    let (status, cbor) = twin.enumerate_rps_begin();
    out.push(Observation::new("enumerateRpsBegin", status, &cbor));
    let (status, cbor) = twin.enumerate_rps_next();
    out.push(Observation::new("enumerateRpsNext", status, &cbor));
    let (status, cbor) = twin.enumerate_rps_next();
    out.push(Observation::new("enumerateRpsNext/after-last", status, &cbor));

    let (status, cbor) = twin.enumerate_creds_begin(RP_A.0);
    out.push(Observation::new("enumerateCredsBegin", status, &cbor));

    let (status, cbor) = twin.enumerate_creds_begin(RP_B.0);
    out.push(Observation::new("enumerateCredsBegin/second-rp", status, &cbor));

    out
}

/// The two relying parties, and the users under them: **two** credentials under
/// `RP_A` and one under `RP_B`.
///
/// Two, not one, because `enumerateCredsBegin`'s reply must carry a total that
/// is not 1 and an `enumerateRpsNext` must have a second page to serve — with a
/// single RP the next-call status would be the only thing under test.
const RP_A: (&str, &[u8]) = ("rp-a.test", b"user-one");
const RP_B: (&str, &[u8]) = ("rp-b.test", b"user-two");
const RP_A_SECOND: (&str, &[u8]) = ("rp-a.test", b"user-three");

/// The CTAP2 status byte a full store must answer.
///
/// `ctap2.rs`'s `Ctap2Response::KeyStoreFull`. Named here because the gherkin
/// names it, and because "the store said Full" and "the device said 0x28" are
/// two claims — the second is the one a client sees.
const KEY_STORE_FULL: u8 = 0x28;

/// `CTAP2_ERR_NOT_ALLOWED` — `enumerateRpsGetNext` once the pages run out.
const NOT_ALLOWED: u8 = 0x30;

// ---------------------------------------------------------------------------
// The host twin
// ---------------------------------------------------------------------------

/// `app.rs` — the host-only twin, on its own host-file keystore.
struct Host {
    app: HostApp<MemoryKeystore>,
    /// The live `pinUvAuthToken`, carrying every permission the script needs.
    ///
    /// Minted **once**, in [`Host::new`], and used for makeCredential as well
    /// as credMgmt: the applet keeps one live token, so a second mint would
    /// silently invalidate the first and every later credMgmt would answer
    /// `0x33 PIN_AUTH_INVALID` — a failure that reads like a twin divergence
    /// and is not one.
    token: Vec<u8>,
}

impl Host {
    /// A host twin whose keystore holds `capacity` credentials.
    ///
    /// The number is **chosen by the test**, and that is the point of the
    /// whole capacity clause: this is a fixture bound, not a device claim. See
    /// [`the_capacity_divergence_is_explicit_not_incidental`].
    fn new(capacity: usize) -> Self {
        let mut app = HostApp::with_keystore(MemoryKeystore::with_max_creds(capacity));
        let client = PinClient::new(&mut app);
        client.set_pin(&mut app);
        // `mc|ga|cm|lbf|acfg` (0x37): one token for the whole script.
        let token = client.get_token(&mut app, 0x09, Some(0x37), None).expect("mint a token");
        Host { app, token }
    }

    fn cm(&mut self, subcommand: u8, params: Option<Value>) -> (u8, Vec<u8>) {
        let req = cm_request(subcommand, &self.token, params);
        let resp = self.app.process_ctap2(0x0A, &req, [1, 2, 3, 4]);
        assert!(!resp.is_empty(), "credMgmt must answer with at least a status byte");
        (resp[0], resp[1..].to_vec())
    }
}

impl Twin for Host {
    fn enroll(&mut self, rp: &str, user: &[u8]) -> u8 {
        let hash = crypto::sha256(rp.as_bytes());
        // The same token the credMgmt requests use — see [`Host::token`].
        let req = cbor::encode(&Value::M(vec![
            (Value::U(0x01), Value::B(hash.to_vec())),
            (
                Value::U(0x02),
                Value::M(vec![
                    (Value::T("id".to_string()), Value::T(rp.to_string())),
                    (Value::T("name".to_string()), Value::T("RP".to_string())),
                ]),
            ),
            (
                Value::U(0x03),
                Value::M(vec![
                    (Value::T("id".to_string()), Value::B(user.to_vec())),
                    (Value::T("name".to_string()), Value::T("U".to_string())),
                ]),
            ),
            (
                Value::U(0x04),
                Value::A(vec![Value::M(vec![
                    (Value::T("type".to_string()), Value::T("public-key".to_string())),
                    (Value::T("alg".to_string()), Value::N(-7)),
                ])]),
            ),
            (
                Value::U(0x07),
                Value::M(vec![(Value::T("rk".to_string()), Value::Bool(true))]),
            ),
            (
                Value::U(0x08),
                Value::B(crypto::pin_uv_auth_param(2, &mac_key(&self.token), &hash)),
            ),
            (Value::U(0x09), Value::U(2)),
        ]));
        self.app.process_ctap2(0x01, &req, [1, 2, 3, 4])[0]
    }

    fn get_metadata(&mut self) -> (u8, Vec<u8>) {
        self.cm(0x01, None)
    }

    fn enumerate_rps_begin(&mut self) -> (u8, Vec<u8>) {
        self.cm(0x02, None)
    }

    fn enumerate_rps_next(&mut self) -> (u8, Vec<u8>) {
        self.cm(0x03, None)
    }

    fn enumerate_creds_begin(&mut self, rp: &str) -> (u8, Vec<u8>) {
        let hash = crypto::sha256(rp.as_bytes());
        self.cm(0x04, Some(Value::M(vec![(Value::U(0x01), Value::B(hash.to_vec()))])))
    }

    fn capacity(&mut self) -> u32 {
        let ks = self.app.keystore();
        (ks.max_remaining_creds() + ks.cred_count()) as u32
    }

    fn backend(&self) -> CredentialBackend {
        self.app.credential_backend()
    }

    /// Enrol until the host keystore refuses, and return the refusal.
    fn enroll_past_the_boundary(&mut self) -> u8 {
        let mut n = 0u32;
        loop {
            let status = self.enroll("fill.test", format!("u{n}").as_bytes());
            if status != 0x00 {
                return status;
            }
            n += 1;
            assert!(n < 4 * self.capacity() + 16, "the host twin never reached its boundary");
        }
    }
}

// ---------------------------------------------------------------------------
// The device twin
// ---------------------------------------------------------------------------

/// `device_app.rs` + `device_core.rs` — the shipped path, over a real
/// [`fapico2_platform::keyregion::host::FileKeyRegion`].
struct Dev {
    device: Device,
    token: [u8; 32],
    /// Kept alive for the whole test: it owns the published region and
    /// uninstalls it on drop, so dropping it early would silently degrade the
    /// applet to the snapshot and make every region assertion vacuous.
    region: region_boot::InstalledRegion,
}

impl Dev {
    /// Boot the device twin over a fresh secure store.
    ///
    /// The caller must already have installed a key region (the tests hold an
    /// `InstalledRegion` for their whole body) — without one this app reports
    /// [`CredentialBackend::Snapshot`] and every region assertion below is
    /// vacuous.
    fn boot(tag: &str) -> Self {
        let region = region_boot::install(tag);
        let mut device = Device::boot(region_boot::keyed_store());
        device.grant_presence_always();
        device.set_pin(b"1234");
        let token = device.pin_token().expect("set_pin mints a token");
        Dev { device, token, region }
    }

    /// `pinUvAuthParam` for `msg`, under **protocol 2**.
    ///
    /// [`Device::set_pin`] mints the token over protocol 1, and this file signs
    /// with protocol 2 — deliberately, so the request bytes are the same ones
    /// the host twin's `cm_request` builds. `pin_uv_auth_param`'s key derivation
    /// depends only on the protocol argument and the token, never on how the
    /// token was minted, and `crypto::pin_verify_auth` on the device side
    /// accepts either protocol (`device_core.rs`: `if protocol != 1 && protocol
    /// != 2`).
    fn mac(&self, msg: &[u8]) -> Vec<u8> {
        crypto::pin_uv_auth_param(2, &self.token, msg).to_vec()
    }

    /// The `pinUvAuthParam` for one credMgmt request, over `auth_msg`.
    ///
    /// The name says it: the *authenticated* bytes are the caller's, because
    /// PicoForge's rule is "the bare sub-command byte for `getCredsMetadata`
    /// and `enumerateRpsBegin`, `subCommand ‖ CBOR(subCommandParams)` for
    /// everything else" and that rule belongs in the parity script's shape, not
    /// in a second implementation of it here.
    fn cm(&mut self, subcommand: u8, params: Option<Value>) -> (u8, Vec<u8>) {
        let mut auth_msg: Vec<u8> = vec![subcommand];
        if let Some(p) = params.as_ref() {
            if !matches!(subcommand, 0x01 | 0x02) {
                auth_msg.extend_from_slice(&cbor::encode(p));
            }
        }
        // Everything below is the same CBOR the host twin's `cm_request`
        // builds, for the same sub-command and the same parameters — which is
        // the "same script" claim stated at the byte level rather than in a
        // comment about it.
        let mut map = vec![(Value::U(0x01), Value::U(subcommand as u64))];
        if let Some(p) = params {
            map.push((Value::U(0x02), p));
        }
        map.push((Value::U(0x03), Value::U(2)));
        map.push((Value::U(0x04), Value::B(self.mac(&auth_msg))));
        let req = cbor::encode(&Value::M(map));
        self.device.call(0x0A, &req)
    }
}

impl Twin for Dev {
    fn enroll(&mut self, rp: &str, user: &[u8]) -> u8 {
        self.device.make_cred(rp, user).0
    }

    fn get_metadata(&mut self) -> (u8, Vec<u8>) {
        self.cm(0x01, None)
    }

    fn enumerate_rps_begin(&mut self) -> (u8, Vec<u8>) {
        self.cm(0x02, None)
    }

    fn enumerate_rps_next(&mut self) -> (u8, Vec<u8>) {
        self.cm(0x03, None)
    }

    fn enumerate_creds_begin(&mut self, rp: &str) -> (u8, Vec<u8>) {
        let hash = crypto::sha256(rp.as_bytes());
        self.cm(0x04, Some(Value::M(vec![(Value::U(0x01), Value::B(hash.to_vec()))])))
    }

    fn capacity(&mut self) -> u32 {
        FIDO_CAPACITY
    }

    fn backend(&self) -> CredentialBackend {
        self.device.backend()
    }

    /// Fill the region to `FIDO_CAPACITY` **through the store**, then make one
    /// more enrolment through the command path and return its status.
    ///
    /// **Why the fill is not done through makeCredential.** 856 enrolments at
    /// one P-256 keygen + one self-attestation signature + one sector-atomic
    /// commit each is minutes of host CPU, and the *interesting* half — the
    /// command path's own refusal — is the single call after the fill. The fill
    /// itself is `tests/capacity_boundary.rs`'s job and it writes through the
    /// applet's own codec, so the store the command path then refuses against
    /// is the store the device has.
    fn enroll_past_the_boundary(&mut self) -> u8 {
        self.device.fill_region_to_capacity(&self.region);
        // Any RP will do: the refusal comes from the allocator finding no free
        // slot in FIDO's range, which is independent of the RP.
        self.device.make_cred("overflow.test", b"user").0
    }
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// **The gherkin.** The same script on both twins, and every observable step
/// compared — status byte, key set, and counts.
#[test]
fn the_two_twins_answer_the_same_script_identically() {
    let _lock = region_boot::lock();
    let mut host = Host::new(HOST_FIXTURE_CAPACITY);
    let mut dev = Dev::boot("parity");

    let host_steps = run_script(&mut host);
    let dev_steps = run_script(&mut dev);

    assert_eq!(host_steps.len(), dev_steps.len());
    for (h, d) in host_steps.iter().zip(dev_steps.iter()) {
        assert_eq!(h.step, d.step, "the two runs must walk the same script");
        assert_eq!(
            h.status, d.status,
            "step {}: the two twins answered with different status bytes ({:#04x} vs {:#04x})",
            h.step, h.status, d.status
        );
        assert_eq!(
            h.keys, d.keys,
            "step {}: the two twins answered with different CBOR key sets. The PicoForge dialect \
             is binding (AGENTS.md §2): rp=3, rpID=4, totalRps=5, user=6, credential=7, \
             publicKey=8, totalCredentials=9",
            h.step
        );
        assert_eq!(
            h.existing, d.existing,
            "step {}: the two twins reported different credential counts",
            h.step
        );
        assert_eq!(h.total_rps, d.total_rps, "step {}: totalRps differs", h.step);
        assert_eq!(
            h.total_creds, d.total_creds,
            "step {}: totalCredentials differs",
            h.step
        );
    }

    // And the script's own shape, asserted so a change to it cannot quietly
    // reduce it to "both twins answered an error identically".
    fn by_name<'a>(steps: &'a [Observation], name: &str) -> &'a Observation {
        steps.iter().find(|s| s.step == name).unwrap_or_else(|| panic!("step {name}"))
    }
    assert_eq!(
        by_name(&dev_steps, "getMetadata/three").existing,
        Some(3),
        "three credentials were enrolled"
    );
    assert_eq!(
        by_name(&dev_steps, "enumerateRpsBegin").total_rps,
        Some(2),
        "two distinct relying parties"
    );
    assert_eq!(
        by_name(&dev_steps, "enumerateCredsBegin").total_creds,
        Some(2),
        "two credentials under RP_A"
    );
    assert_eq!(
        by_name(&dev_steps, "enumerateRpsNext/after-last").status,
        NOT_ALLOWED,
        "an enumeration past the last page is refused, not served from freed memory"
    );
}

/// The PicoForge key sets, pinned.
///
/// Two dialects' key sets **collide** (`user` is PicoForge's 6 and CTAP2's
/// `largeBlobKey`), so "we answered in the sender's dialect" is only half of
/// the claim; the other half is that this dialect's numbering is the one
/// `python-fido2` 2.2.1 — and therefore `ykman` and Yubico Authenticator —
/// speaks (`AGENTS.md` §2). Asserted on the device twin, because the device is
/// the one that has to be right.
#[test]
fn the_picoforge_dialect_is_pinned_on_both_twins() {
    let _lock = region_boot::lock();
    let mut host = Host::new(HOST_FIXTURE_CAPACITY);
    let mut dev = Dev::boot("parity");

    for (label, steps) in
        [("host", run_script(&mut host)), ("device", run_script(&mut dev))]
    {
        let find = |name: &str| {
            steps.iter().find(|s| s.step == name).unwrap_or_else(|| panic!("step {name}"))
        };
        // getMetadata: existing(1) ‖ remaining(2) ‖ total(3).
        assert_eq!(
            find("getMetadata/three").keys,
            vec![1, 2, 3],
            "{label}: getMetadata's key set"
        );
        // enumerateRpsBegin: rp(3) ‖ rpID(4) ‖ totalRps(5) — **not** CTAP2's
        // 1/2/7, and the presence of 7 would be the wrong dialect entirely.
        assert_eq!(
            find("enumerateRpsBegin").keys,
            vec![3, 4, 5],
            "{label}: enumerateRpsBegin must be PicoForge's rp=3, rpID=4, totalRps=5"
        );
        // enumerateCredsBegin: user(6) ‖ credential(7) ‖ publicKey(8) ‖
        // totalCredentials(9).
        assert_eq!(
            find("enumerateCredsBegin").keys,
            vec![6, 7, 8, 9],
            "{label}: enumerateCredsBegin must be PicoForge's user=6, credential=7, \\
             publicKey=8, totalCredentials=9"
        );
    }
}

/// **The capacity divergence, explicit and asserted rather than incidental.**
///
/// Three claims, and the third is the one that makes the other two mean
/// something:
///
/// 1. each twin reports **which store** answers its capacity questions;
/// 2. only the region-backed one has a device-meaningful capacity, so only it
///    publishes a number ([`CredentialBackend::advertised_capacity`]);
/// 3. **the number the host twin puts on the wire is its own fixture bound** —
///    asserted against the value the test passed in, so a reader can see it is
///    a choice and not a claim. If someone wired the host twin to the region's
///    capacity without also changing its backend, (3) is what fails.
#[test]
fn the_capacity_divergence_is_explicit_not_incidental() {
    let _lock = region_boot::lock();
    // No credentials enrolled: this is about the twins' *starting* claims.
    let mut host = Host::new(HOST_FIXTURE_CAPACITY);
    let mut dev = Dev::boot("parity");

    assert_eq!(
        dev.backend(),
        CredentialBackend::KeyRegion,
        "the device twin's credentials live in the key region, and it must say so"
    );
    assert_eq!(
        host.backend(),
        CredentialBackend::Snapshot,
        "the host twin's credentials live in the host-file keystore, and it must say so — \\
         `keystore.rs` has no KeyRegion, so 'Snapshot' is the truth, not a placeholder"
    );

    assert_eq!(
        CredentialBackend::KeyRegion.advertised_capacity(),
        Some(FIDO_CAPACITY),
        "the region's capacity is a device claim and is published as one"
    );
    assert_eq!(
        CredentialBackend::Snapshot.advertised_capacity(),
        None,
        "the snapshot's bound is a fixture — a test's choice, or a \\
         not-yet-migrated board's format limit — and must never be published as a device \\
         capacity"
    );

    // (3): what each twin actually puts on the wire.
    let (_, host_cbor) = host.get_metadata();
    assert_eq!(
        region_boot::uint_at(&host_cbor, 3),
        Some(HOST_FIXTURE_CAPACITY as u64),
        "the host twin advertises its own keystore bound, which the test chose — this is a \\
         fixture, not the device's capacity"
    );
    let (_, dev_cbor) = dev.get_metadata();
    assert_eq!(
        region_boot::uint_at(&dev_cbor, 3),
        Some(FIDO_CAPACITY as u64),
        "the device twin advertises the derived region capacity"
    );
    assert_ne!(
        region_boot::uint_at(&dev_cbor, 3),
        region_boot::uint_at(&host_cbor, 3),
        "and the two numbers are genuinely different today, which is the divergence this test \
         exists to make visible. If they ever agree it is because the host twin learned to \
         reach a region — at which point this assertion is the one to retire, not the numbers"
    );
}

/// `remaining` means the same thing on both twins, even though it is a different
/// number.
///
/// The rule — `remaining == capacity − existing`, and it falls by exactly one
/// per enrolment — is the property a Slots screen depends on. The absolute
/// value is a fixture on one side and the region's on the other, so the
/// assertion is on the *delta*, which is the part that must not drift.
#[test]
fn remaining_count_semantics_agree_even_though_the_numbers_do_not() {
    let _lock = region_boot::lock();

    fn trace<T: Twin>(twin: &mut T) -> Vec<(u64, u64, u64)> {
        let mut out = Vec::new();
        let (_, cbor) = twin.get_metadata();
        out.push(read_metadata(&cbor));
        for (rp, user) in [(RP_A.0, RP_A.1), (RP_B.0, RP_B.1), (RP_A_SECOND.0, RP_A_SECOND.1)] {
            assert_eq!(twin.enroll(rp, user), 0x00);
            let (_, cbor) = twin.get_metadata();
            out.push(read_metadata(&cbor));
        }
        out
    }

    for (label, trace) in [
        ("host", {
            let mut h = Host::new(HOST_FIXTURE_CAPACITY);
            trace(&mut h)
        }),
        ("device", {
            let mut d = Dev::boot("parity");
            trace(&mut d)
        }),
    ] {
        let empty = trace[0];
        assert_eq!(empty.0, 0, "{label}: an empty store reports no credentials");
        assert_eq!(
            empty.0 + empty.1,
            trace[0].2,
            "{label}: existing + remaining must be the advertised total"
        );
        for (i, w) in trace.windows(2).enumerate() {
            let (before, after) = (w[0], w[1]);
            assert_eq!(after.0, before.0 + 1, "{label}: enrolment {i} was not counted");
            assert_eq!(
                before.1 - after.1,
                1,
                "{label}: enrolment {i} did not reduce remaining by exactly one"
            );
            assert_eq!(
                after.1 + after.0,
                trace[0].2,
                "{label}: existing + remaining must stay the advertised total after enrolment {i}"
            );
        }
    }
}

/// The `pinUvAuthToken` as the fixed-size key `crypto::pin_uv_auth_param`
/// takes, copied out of the caller's `Vec`.
///
/// A `Vec<u8>` cannot be `try_into`'d by reference, and the alternative —
/// cloning per command — would put a second copy of a live session token on the
/// heap for no reason. This is the one place the copy is named.
fn mac_key(token: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&token[..32]);
    out
}

/// `(existing, remaining, total)` from a `getMetadata` reply.
fn read_metadata(cbor: &[u8]) -> (u64, u64, u64) {
    (
        region_boot::uint_at(cbor, 1).expect("existing"),
        region_boot::uint_at(cbor, 2).expect("remaining"),
        region_boot::uint_at(cbor, 3).expect("total"),
    )
}

/// **The boundary error is the same byte on both twins**, at each twin's own
/// boundary, and the refusal leaves nothing behind.
///
/// Split into its own test because it is the only step that is expensive: the
/// device leg fills the key region to [`FIDO_CAPACITY`], which is
/// `tests/capacity_boundary.rs`'s cost and not this file's to pay twice inside
/// the parity script.
///
/// What is *not* asserted equal is the number of enrolments before the
/// refusal, because that number is the capacity, and the capacity is the one
/// thing the twins legitimately disagree about.
#[test]
fn the_boundary_error_is_the_same_byte_on_both_twins() {
    let _lock = region_boot::lock();
    let mut host = Host::new(HOST_FIXTURE_CAPACITY);
    let host_refusal = host.enroll_past_the_boundary();
    assert_eq!(
        host_refusal, KEY_STORE_FULL,
        "the host twin must answer CTAP2_ERR_KEY_STORE_FULL at its own boundary"
    );
    let (_, host_cbor) = host.get_metadata();
    let (host_existing, host_remaining, _) = read_metadata(&host_cbor);
    assert_eq!(
        host_remaining, 0,
        "a full store advertises zero remaining — the wire claim the device does not honour is \
         the defect AGENTS.md §4 is about"
    );

    let mut dev = Dev::boot("parity");
    let dev_refusal = dev.enroll_past_the_boundary();
    assert_eq!(
        dev_refusal, host_refusal,
        "both twins must answer the same status byte at their boundaries: host {host_refusal:#04x}, \
         device {dev_refusal:#04x}"
    );

    let (_, dev_cbor) = dev.get_metadata();
    let (dev_existing, dev_remaining, _) = read_metadata(&dev_cbor);
    assert_eq!(dev_remaining, 0, "and zero remaining, for the same reason");
    assert_eq!(
        dev_existing, FIDO_CAPACITY as u64,
        "the refused enrolment left no partial credential: the index still holds exactly one \
         entry per enrolled credential"
    );
    assert_ne!(
        dev_existing, host_existing,
        "and the two boundaries are genuinely at different depths, which is the divergence this \
         file exists to make visible rather than to assert away"
    );
}

/// The host twin's fixture bound.
///
/// **Chosen by the test, not by the device.** Eight, so the boundary leg is a
/// handful of enrolments rather than a fifth of the suite's runtime, and so the
/// number is unmistakably not [`FIDO_CAPACITY`]. Every assertion that touches it
/// says so.
const HOST_FIXTURE_CAPACITY: usize = 8;
