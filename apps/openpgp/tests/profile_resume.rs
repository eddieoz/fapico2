use fapico2_platform::trusted_backend::host::with_host_backend;

struct TraceClient<C> {
    inner: C,
    reply: Option<Result<trussed_core::api::Reply, trussed_core::Error>>,
    forbid_requests: bool,
}
impl<C: trussed_core::PollClient> trussed_core::PollClient for TraceClient<C> {
    fn request<Rq: trussed_core::api::RequestVariant>(&mut self, request: Rq)
        -> trussed_core::ClientResult<'_, Rq::Reply, Self>
    {
        let request: trussed_core::api::Request = request.into();
        if self.forbid_requests {
            panic!("unexpected request before input refusal: {request:?}");
        }
        let description = format!("{request:?}");
        let typed = Rq::try_from(request).ok().unwrap();
        let reply = trussed_core::try_syscall!(self.inner.request(typed)).map(Into::into);
        if let Err(error) = &reply { eprintln!("{description}: {error:?}"); }
        self.reply = Some(reply);
        Ok(trussed_core::FutureResult::new(self))
    }
    fn poll(&mut self) -> core::task::Poll<Result<trussed_core::api::Reply, trussed_core::Error>> {
        core::task::Poll::Ready(self.reply.take().unwrap())
    }
}
impl<C: trussed_core::PollClient> trussed_core::CryptoClient for TraceClient<C> {}
impl<C: trussed_core::PollClient> trussed_core::FilesystemClient for TraceClient<C> {}
impl<C: trussed_core::PollClient> trussed_core::UiClient for TraceClient<C> {}
impl<C, E> trussed_core::serde_extensions::ExtensionClient<E> for TraceClient<C>
where E: trussed_core::serde_extensions::Extension,
    C: trussed_core::serde_extensions::ExtensionClient<E>,
{
    fn id() -> u8 { C::id() }
}

#[test]
fn installed_profile_is_not_backfilled_on_same_source_resume() {
    for profile in [
        opcard::MigrationProfile { language: b"en", ..Default::default() },
        opcard::MigrationProfile { sex: Some(b'1'), ..Default::default() },
        opcard::MigrationProfile { private_use_1: Some(b"one"), ..Default::default() },
        opcard::MigrationProfile { private_use_2: Some(b"two"), ..Default::default() },
    ] {
        with_host_backend("opcard", |client| {
            let mut options = opcard::Options::default();
            options.storage = trussed_core::types::Location::Internal;
            let mut card = opcard::Card::new(TraceClient { inner: client, reply: None, forbid_requests: false }, options);
            let source = [0x42; 32];
            card.restore_public_metadata_with_profile(
                source, b"Migrated User", 6, 8, None, None, None, None,
                opcard::MigrationProfile::default(),
            ).unwrap();
            let result = card.restore_public_metadata_with_profile(
                source, b"Migrated User", 6, 8, None, None, None, None, profile,
            );
            assert_eq!(result, Ok(()));
            card.restore_public_metadata_with_profile(
                source, b"Migrated User", 6, 8, None, None, None, None,
                opcard::MigrationProfile::default(),
            ).unwrap();
            for (tag, expected) in [(0x5f2d, &b""[..]), (0x5f35, &b"0"[..]),
                (0x0101, &b""[..]), (0x0102, &b""[..])] {
                let apdu = [0, 0xca, (tag >> 8) as u8, tag as u8, 0];
                let mut reply = heapless09::Vec::<u8, 64>::new();
                card.handle(iso7816::command::CommandView::try_from(&apdu[..]).unwrap(),
                    &mut reply).unwrap();
                assert_eq!(reply.as_slice(), expected);
            }
        });
    }
}

#[test]
fn oversized_private_do_is_refused_before_backend_access() {
    for length in [1025, 4096] {
        let oversized = vec![0x61; length];
        for later in [false, true] {
            with_host_backend("opcard", |client| {
                let mut options = opcard::Options::default();
                options.storage = trussed_core::types::Location::Internal;
                let mut card = opcard::Card::new(TraceClient {
                    inner: client, reply: None, forbid_requests: true,
                }, options);
                let profile = opcard::MigrationProfile {
                    language: b"en", sex: Some(b'1'),
                    private_use_1: Some(if later { b"valid earlier DO" } else { &oversized }),
                    private_use_2: Some(if later { &oversized } else { b"valid later DO" }),
                };
                assert_eq!(card.restore_public_metadata_with_profile(
                    [0x42; 32], b"Migrated User", 6, 8, None, None, None, None, profile,
                ), Err(iso7816::Status::ConditionsOfUseNotSatisfied));
            });
        }
    }
}

#[test]
fn matching_same_source_profile_remains_idempotent() {
    for length in [0, 1, 256, 1024] {
        let private = vec![0x61; length];
        with_host_backend("opcard", |client| {
            let mut options = opcard::Options::default();
            options.storage = trussed_core::types::Location::Internal;
            let mut card = opcard::Card::new(TraceClient { inner: client, reply: None, forbid_requests: false }, options);
            for attempt in 0..2 {
                card.restore_public_metadata_with_profile(
                    [0x42; 32], b"Migrated User", 6, 8, None, None, None, None,
                    opcard::MigrationProfile {
                        language: b"en", sex: Some(b'1'),
                        private_use_1: Some(&private), private_use_2: Some(&private),
                    },
                ).unwrap_or_else(|error| panic!("length={length}, attempt={attempt}: {error:?}"));
            }
        });
    }
}
