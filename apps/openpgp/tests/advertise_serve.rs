//! US-962 (I2): the card must advertise exactly the algorithm groups its
//! dispatch actually serves — no more, no less.
//!
//! US-950 made GET DATA FA (Algorithm Information) describe the accept set.
//! It could not, on its own, keep that accept set honest: FA is built from
//! opcard's `AllowedAlgorithms::default_gen()`, while the mechanisms are
//! served by whatever is in front of trussed Core in the *platform* dispatch
//! (`platform/src/trusted_backend/dispatch.rs` `BACKENDS`). Those two lists
//! were wired to different Cargo switches, so they could drift: a build that
//! dropped `Backend::Secp256k1` from `BACKENDS` still listed SECP256K1 in FA
//! and still accepted the attribute with `9000` — every request then fell
//! through to trussed Core, which has no such mechanism.
//!
//! This test reads both sides of the real build it is compiled into and
//! cross-checks them. The "served" side is not transcribed: it is read from
//! `BACKENDS` itself, so the assertion tracks whatever this build actually
//! wired. US-964 had to make that true — the `served_*` helpers used to be
//! `#[cfg]`-gated with a hardcoded `false` fallback, so a build with six
//! backends in the table and every app switch off still reported
//! `served …=false` and passed. Run twice it is a two-sided gate —
//!
//!   * the default build serves all three switched groups and must advertise
//!     all three;
//!   * `cargo test -p fapico2-openpgp --no-default-features --features
//!     "virt,device" --test advertise_serve` (driven by
//!     `tests/scripts/check_advertise_serve_coupling.py`, and by the CI job of
//!     the same name) serves none and must advertise none — and the PUT DATA
//!     gate must refuse each one with `6A80` rather than accept an algorithm
//!     nothing can serve.
//!
//! The device path (`OpcardDispatch` on the host backend) is the one that
//! matters: it is the backend table the RP2350 build uses.
//!
//! US-966 (2026-09-27, after the epic closed): BRAINPOOL_P384R1 left the
//! served set. It is no longer in `GROUPS` — it is in `DEFERRED`, which this
//! test treats as an *asserted absence* from both sides (never in FA, PUT
//! refused `6A80`) and which it **reports on**, so the gate script can see the
//! measurement instead of inferring it from a group that stopped being listed.
//! BRAINPOOL_P512R1 was already in that position and now shares the same list.

use fapico2_openpgp::{OpenPgpApp, OPENPGP_AID};
use fapico2_platform::{
    dispatch::{Dispatcher, MAX_RESPONSE},
    trusted_backend::{
        dispatch::{OpcardDispatch, BACKENDS},
        host::{HostPlatform, HostStore, leak_buf, mount_fs},
        runner::with_backend,
    },
};
use hex_literal::hex;

const SW_OK: u16 = 0x9000;
const SW_WRONG_DATA: u16 = 0x6A80;
const PW3: &[u8] = b"12345678";

// ---------------------------------------------------------------------------
// The serving side, read from the dispatch rather than from a table of ours.
//
// US-964: this used to be `#[cfg(feature = "…-backend")]`-gated, with the
// `not(...)` arm hardcoding `false`. That made "served" a restatement of the
// switch instead of a reading of the table, and the finding it created was the
// reviewer's one-line mutation: re-acquiring `fapico2-platform` with default
// features put six backends in `BACKENDS` of a build whose app switches were
// all off, and the test answered `served secp256k1=false brainpool=false
// rsa=false` — measuring the assumption, not the thing, and passing. The
// functions below therefore read `BACKENDS` by name in *every* configuration
// (`BackendId` and the platform's `Backend` are both `Debug` regardless of
// which variants exist), and `served_*` is cross-checked against `cfg!` below:
// a backend in the table while its advertising switch is off is a hard failure
// in the configuration that *discriminates*, not a silent `false`.
// ---------------------------------------------------------------------------

/// The serving table exactly as this build wired it, as it would print.
fn serving_table() -> Vec<String> {
    BACKENDS.iter().map(|id| format!("{id:?}")).collect()
}

/// Is the software backend `name` in front of trussed Core in *this* build?
/// A real read of `BACKENDS`, not a restatement of a `cfg`.
fn serves(name: &str) -> bool {
    let wanted = format!("Custom({name})");
    BACKENDS.iter().any(|id| format!("{id:?}") == wanted)
}

fn serves_secp256k1() -> bool {
    serves("Secp256k1")
}

fn serves_brainpool() -> bool {
    serves("Brainpool")
}

/// One backend serves all three RSA sizes: opcard's `rsa4096-gen` implies
/// `rsa3072-gen` implies `rsa2048-gen`, and `SoftwareRsa` implements all
/// three mechanisms.
fn serves_rsa() -> bool {
    serves("Rsa")
}

/// What each algorithm group's advertising switch says in *this* build. The
/// app's `secp256k1-backend` / `brainpool-backend` / `rsa-backend` are one
/// switch per group: each turns on both the platform feature that creates the
/// `Backend` variant (and the `BACKENDS` row) and the opcard feature that
/// makes FA name the algorithm (see `apps/openpgp/Cargo.toml`). So the two
/// sides must agree — and where they do not, the *table* is the measurement.
const CFG_SECP256K1: bool = cfg!(feature = "secp256k1-backend");
const CFG_BRAINPOOL: bool = cfg!(feature = "brainpool-backend");
const CFG_RSA: bool = cfg!(feature = "rsa-backend");

/// The backends every configuration carries: trussed-staging, trussed-auth
/// and trussed Core, none of which has an algorithm switch.
const UNSWITCHED_BACKENDS: [&str; 3] = ["Custom(Staging)", "Custom(Auth)", "Core"];

/// US-964: the serving table must contain exactly the unswitched rows plus one
/// row per enabled switch. Read here, in the test, in both configurations —
/// so a table that grew a backend the app no longer advertises fails the build
/// that the gate script runs for exactly this purpose.
#[test]
fn serving_table_matches_the_switches() {
    let table = serving_table();
    let expected = UNSWITCHED_BACKENDS.len()
        + usize::from(CFG_SECP256K1)
        + usize::from(CFG_BRAINPOOL)
        + usize::from(CFG_RSA);
    assert_eq!(
        table.len(),
        expected,
        "the serving table holds {table:?} — {expected} rows were expected: the three \
         unswitched rows plus one per enabled switch (secp256k1={CFG_SECP256K1} \
         brainpool={CFG_BRAINPOOL} rsa={CFG_RSA}). A software backend in the table \
         while its advertising switch is off serves algorithms FA does not name, \
         and a row missing from the table leaves an advertised algorithm unserved \
         (US-962); this is the shape the US-964 reviewer's one-line manifest \
         mutation produced silently"
    );
    for (name, served, cfg) in [
        ("Secp256k1", serves_secp256k1(), CFG_SECP256K1),
        ("Brainpool", serves_brainpool(), CFG_BRAINPOOL),
        ("Rsa", serves_rsa(), CFG_RSA),
    ] {
        assert_eq!(
            served, cfg,
            "`Backend::{name}` is {} the serving table while this build's switch says \
             {cfg} — the two sides of the US-962 coupling have come apart, so `served` \
             could not have been read off the table (table: {table:?})",
            if served { "in" } else { "not in" }
        );
    }
}

// ---------------------------------------------------------------------------
// Algorithm attribute spellings (`types.rs`, as `algo_info` emits them: the
// public-key form under C1/C3, the ECDH form under C2).
// ---------------------------------------------------------------------------

/// An algorithm group, as FA spells it: one attribute per usage tag.
struct Group {
    name: &'static str,
    c1: &'static [u8],
    c2: &'static [u8],
    c3: &'static [u8],
    /// Is the group in front of trussed Core in this build?
    served: fn() -> bool,
}

const GROUPS: &[Group] = &[
    // Served by trussed Core, which both `platform`'s `trussed` and opcard's
    // `trussed-core` enable with p256/p384/p521/ed255/x255 unconditionally.
    // There is no build of this workspace in which they could be advertised
    // without being served, which is why they have no switch.
    Group { name: "P_256", c1: &hex!("132A8648CE3D030107FF"), c2: &hex!("122A8648CE3D030107FF"), c3: &hex!("132A8648CE3D030107FF"), served: || true },
    Group { name: "P_384", c1: &hex!("132B81040022FF"), c2: &hex!("122B81040022FF"), c3: &hex!("132B81040022FF"), served: || true },
    Group { name: "P_521", c1: &hex!("132B81040023FF"), c2: &hex!("122B81040023FF"), c3: &hex!("132B81040023FF"), served: || true },
    Group { name: "ED_25519", c1: &hex!("162B06010401DA470F01FF"), c2: &hex!("122B060104019755010501FF"), c3: &hex!("162B06010401DA470F01FF"), served: || true },
    // The three groups US-962 coupled to their backends.
    // The C2 spelling carries the ECDH `12` prefix; the two 3B curves' C2
    // spellings below likewise.
    Group { name: "SECP256K1", c1: &hex!("132B8104000AFF"), c2: &hex!("122B8104000AFF"), c3: &hex!("132B8104000AFF"), served: serves_secp256k1 },
    Group { name: "BRAINPOOL_P256R1", c1: &hex!("132B2403030208010107FF"), c2: &hex!("122B2403030208010107FF"), c3: &hex!("132B2403030208010107FF"), served: serves_brainpool },
    // US-966: BRAINPOOL_P384R1 used to sit here, gated on the same
    // `serves_brainpool`. It is now in `DEFERRED` below.
    Group { name: "RSA_2048", c1: &hex!("010800002000"), c2: &hex!("010800002000"), c3: &hex!("010800002000"), served: serves_rsa },
    Group { name: "RSA_3072", c1: &hex!("010C00002000"), c2: &hex!("010C00002000"), c3: &hex!("010C00002000"), served: serves_rsa },
    Group { name: "RSA_4096", c1: &hex!("011000002000"), c2: &hex!("011000002000"), c3: &hex!("011000002000"), served: serves_rsa },
];

/// Curves this card deliberately does **not** serve, in any configuration of
/// this workspace, and therefore never advertises and never accepts.
///
/// Pinned from both sides: the attribute must not appear in `GET DATA FA`, and
/// a PUT DATA of it must be refused with `6A80`. This is the US-950/US-962
/// defect class — a mechanism reachable in the allow-list that no backend
/// serves — with the direction reversed: these are mechanisms that are
/// *deliberately* out of the allow-list, and the test's job is to keep them
/// out.
///
/// * `BRAINPOOL_P512R1` — never served (US-944): no bp512 crate exists in the
///   ecosystem, so no backend can implement
///   `Mechanism::BrainpoolP512R1{,Prehashed}`.
/// * `BRAINPOOL_P384R1` — served under US-944/945/946, **deferred by US-966**
///   (2026-09-27) for want of deployment pull, not for a defect: the OpenPGP
///   card spec v3.4 §4.4.3.10 only requires that "at least one of this curves
///   shall be supported" (NIST P-256/384/521 already satisfies that), RFC 8734
///   deprecated Brainpool for TLS 1.3 "because they had little usage … not
///   endorsed by the IETF", and no OpenPGP-card user of P-384r1 was found.
///   P-384r1 signing was never measured on hardware — the 14.47 s US-954
///   failure is a host-side PC/SC transaction ceiling that recurs identically
///   for RSA-4096 GENERATE while a longer 8.19 s NIST-P-384 GENERATE
///   succeeds.
///
/// Note what is *not* modelled here: these are not a fourth switch. There is
/// no `brainpool-p384r1` feature to flip, so no configuration of this
/// workspace can put either curve back — which is what makes the absence
/// below a property of the build rather than of a feature's state.
const DEFERRED: &[(&str, u8, &[u8])] = &[
    ("BRAINPOOL_P384R1", 0xC1, &hex!("132B240303020801010BFF")),
    ("BRAINPOOL_P384R1", 0xC2, &hex!("122B240303020801010BFF")),
    ("BRAINPOOL_P384R1", 0xC3, &hex!("132B240303020801010BFF")),
    ("BRAINPOOL_P512R1", 0xC1, &hex!("132B240303020801010DFF")),
    ("BRAINPOOL_P512R1", 0xC2, &hex!("122B240303020801010DFF")),
    ("BRAINPOOL_P512R1", 0xC3, &hex!("132B240303020801010DFF")),
];

// ---------------------------------------------------------------------------
// APDU plumbing.
// ---------------------------------------------------------------------------

fn apdu(dispatcher: &mut Dispatcher<1>, apdu: &[u8]) -> (Vec<u8>, u16) {
    let mut resp = heapless::Vec::<u8, MAX_RESPONSE>::new();
    dispatcher.dispatch(apdu, &mut resp);
    assert!(resp.len() >= 2, "response too short for {apdu:02x?}");
    let sw = u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]]);
    (resp[..resp.len() - 2].to_vec(), sw)
}

/// One APDU plus GET RESPONSE (INS C0) continuation while the card reports
/// `61XX` — the way scd's apdu.c drains a chunked reply.
fn apdu_read(dispatcher: &mut Dispatcher<1>, first: &[u8]) -> (Vec<u8>, u16) {
    let (mut body, mut sw) = apdu(dispatcher, first);
    while sw & 0xFF00 == 0x6100 {
        let le = (sw & 0xFF) as u8;
        let (chunk, next) = apdu(dispatcher, &[0x00, 0xC0, 0x00, 0x00, le]);
        body.extend_from_slice(&chunk);
        sw = next;
    }
    (body, sw)
}

fn select(dispatcher: &mut Dispatcher<1>) {
    let mut command = vec![0x00, 0xA4, 0x04, 0x00, 0x06];
    command.extend_from_slice(OPENPGP_AID);
    let (_, sw) = apdu(dispatcher, &command);
    assert_eq!(sw, SW_OK, "SELECT must answer 9000, got {sw:04x}");
}

/// Open the admin session the attribute PUTs need. Done once, after the FA
/// read: a second VERIFY would spend another retry.
fn verify_pw3(dispatcher: &mut Dispatcher<1>) {
    let mut verify = vec![0x00, 0x20, 0x00, 0x83, PW3.len() as u8];
    verify.extend_from_slice(PW3);
    let (_, sw) = apdu(dispatcher, &verify);
    assert_eq!(sw, SW_OK, "VERIFY PW3 must answer 9000, got {sw:04x}");
}

/// The `(usage tag, attribute)` records FA carries, strictly parsed: every
/// record must fit inside the body and the records must exactly tile it, so a
/// group that was dropped — or a length that overran — is a failure rather
/// than a shrug. A record is `(tag, attrs)` as `tag(len) attrs`.
fn parse_fa(body: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut records = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let tag = body[at];
        assert!(
            (0xC1..=0xC3).contains(&tag),
            "FA record tag must be C1/C2/C3, got {tag:02x} at {at}"
        );
        let len = *body
            .get(at + 1)
            .unwrap_or_else(|| panic!("FA record at {at} declares no length"));
        let start = at + 2;
        let end = start + len as usize;
        assert!(
            end <= body.len(),
            "FA record at {at} declares {len} bytes, only {} left",
            body.len() - start
        );
        records.push((tag, body[start..end].to_vec()));
        at = end;
    }
    assert!(!records.is_empty(), "FA must carry at least one record");
    records
}

/// Run `f` against a freshly booted app on the device path.
fn on_device_card<F, R>(f: F) -> R
where
    F: FnOnce(&mut Dispatcher<1>) -> R,
{
    let internal = leak_buf(256 * 4096);
    let ram = HostStore::fresh();
    with_backend(
        HostPlatform::with_store(HostStore::new(mount_fs::<256>(internal), ram.efs, ram.vfs)),
        OpcardDispatch::new(),
        "opcard",
        |client| {
            let mut app = OpenPgpApp::new(client);
            let mut dispatcher = Dispatcher::<1>::new();
            assert!(dispatcher.register(&mut app));
            f(&mut dispatcher)
        },
    )
}

// ---------------------------------------------------------------------------
// The invariant.
// ---------------------------------------------------------------------------

/// FA names a group if and only if the dispatch has a backend for it, and the
/// PUT DATA gate accepts the attribute exactly when FA named it.
#[test]
fn fa_advertises_exactly_what_the_dispatch_serves() {
    on_device_card(|dispatcher| {
        select(dispatcher);
        let (body, sw) = apdu_read(dispatcher, &[0x00, 0xCA, 0x00, 0xFA, 0x00]);
        assert_eq!(sw, SW_OK, "GET DATA FA must answer 9000, got {sw:04x}");
        let records = parse_fa(&body);

        let report = (serves_secp256k1(), serves_brainpool(), serves_rsa());
        let advertised: Vec<&str> = GROUPS
            .iter()
            .filter(|g| {
                records
                    .iter()
                    .any(|(t, a)| *t == 0xC1 && a.as_slice() == g.c1)
            })
            .map(|g| g.name)
            .collect();
        println!(
            "US-962 advertise/serve: {} FA records; C1 advertises [{}]; \
             served secp256k1={} brainpool={} rsa={}",
            records.len(),
            advertised.join(", "),
            report.0,
            report.1,
            report.2,
        );

        for group in GROUPS {
            let served = (group.served)();
            for (tag, attr) in [(0xC1u8, group.c1), (0xC2, group.c2), (0xC3, group.c3)] {
                let advertised = records
                    .iter()
                    .any(|(t, a)| *t == tag && a.as_slice() == attr);
                assert_eq!(
                    advertised, served,
                    "{} / tag {tag:02X}: FA advertises={advertised} but the dispatch \
                     serves={served} (serving table: secp256k1={}, brainpool={}, rsa={})",
                    group.name, report.0, report.1, report.2,
                );
            }
        }

        // No record may name an algorithm outside the table above: FA must
        // not have grown a group nobody tracks, which is how a new
        // algorithm would sneak in unserved.
        for (tag, attr) in &records {
            let known = GROUPS.iter().any(|g| {
                (attr.as_slice() == g.c1 || attr.as_slice() == g.c2 || attr.as_slice() == g.c3)
                    && (*tag == 0xC1 || *tag == 0xC2 || *tag == 0xC3)
            }) || DEFERRED
                .iter()
                .any(|(_, t, a)| t == tag && *a == attr.as_slice());
            assert!(
                known,
                "FA carries an untracked record tag {tag:02X} {attr:02X?} — every advertised \
                 algorithm must be listed in GROUPS (or in the pinned DEFERRED absences)"
            );
        }

        // US-966: the deferred curves must not be in FA at all, in *any*
        // configuration. This is measured off the parsed records rather than
        // restated from `DEFERRED`, and the measured value — not a constant
        // — is what gets reported, so the gate script reads the measurement
        // instead of trusting that the group stopped being listed. (A report
        // line that printed `advertised:false` unconditionally would be the
        // US-961/US-964 failure mode wearing a new hat: green, and measuring
        // nothing.)
        let mut deferred_names: Vec<&str> = DEFERRED.iter().map(|(name, _, _)| *name).collect();
        deferred_names.sort_unstable();
        deferred_names.dedup();
        let deferred_measured: Vec<(&str, bool)> = deferred_names
            .into_iter()
            .map(|name| {
                let advertised = DEFERRED.iter().any(|(n, tag, attr)| {
                    *n == name && records.iter().any(|(t, a)| t == tag && a.as_slice() == *attr)
                });
                (name, advertised)
            })
            .collect();
        println!(
            "US-966 deferred/never-served: {}",
            deferred_measured
                .iter()
                .map(|(name, adv)| format!("{name}=advertised:{adv}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        for (name, advertised) in &deferred_measured {
            assert!(
                !advertised,
                "{name} is deferred (US-966 for P-384r1, US-944 for P-512r1) and must not \
                 be advertised in any configuration, but FA carries one of its attributes"
            );
        }

        // The gate agrees with the advertisement, in both directions.
        verify_pw3(dispatcher);
        for group in GROUPS {
            if (group.served)() {
                continue;
            }
            for (tag, attr) in [(0xC1u8, group.c1), (0xC2, group.c2), (0xC3, group.c3)] {
                let mut command = vec![0x00, 0xDA, 0x00, tag, attr.len() as u8];
                command.extend_from_slice(attr);
                let (_, sw) = apdu(dispatcher, &command);
                assert_eq!(
                    sw, SW_WRONG_DATA,
                    "{} / tag {tag:02X}: an unserved algorithm must be refused with 6A80, \
                     not accepted with {sw:04X}",
                    group.name
                );
            }
        }
        // …and the deferred curves are refused in every build, backend or not.
        // US-966: P-384r1 joined P-512r1 here. A deferred curve that the PUT
        // gate still accepted would be a curve the host can write but the card
        // cannot serve — precisely the US-962 defect, reintroduced by
        // subtraction.
        for (name, tag, attr) in DEFERRED {
            let mut command = vec![0x00, 0xDA, 0x00, *tag, attr.len() as u8];
            command.extend_from_slice(attr);
            let (_, sw) = apdu(dispatcher, &command);
            assert_eq!(
                sw, SW_WRONG_DATA,
                "{name} / tag {tag:02X} is deferred and must always be refused with 6A80, \
                 got {sw:04X} — accepting it would let a host store an attribute the \
                 dispatch cannot serve"
            );
        }
    })
}

/// The reporting line the gate script parses, so a human reading CI output can
/// see which configuration was actually measured rather than only that
/// something passed.
#[test]
fn report_this_builds_configuration() {
    println!(
        "US-962 advertise/serve: secp256k1-backend={} brainpool-backend={} rsa-backend={} \
         (backends in the table: {}) table={:?}",
        CFG_SECP256K1,
        CFG_BRAINPOOL,
        CFG_RSA,
        BACKENDS.len(),
        serving_table(),
    );
}
