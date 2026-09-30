//! The "call thyself" syscall runner and the client factories.
//!
//! trussed-core's `syscall!` macro (used by opcard throughout, unmodified)
//! is a busy-spin with no yield point. On the single-core cooperative
//! executor a competing runner task would never be scheduled while opcard
//! spins — a deadlock. The single-core remedy trussed documents is for the
//! client's [`Syscall`](trussed::platform::Syscall) implementation to run
//! the service **inline** ("call thyself"; header of
//! `trussed-0.2.0/src/client.rs`). [`SyscallRunner`] does exactly that: its
//! `syscall()` processes the pending request immediately, in the executor's
//! own task context (controller decision D1).

use trussed::backend::{BackendId, Dispatch};
use trussed::pipe::{ServiceEndpoint, TrussedChannel};
use trussed::platform::Platform;
use trussed::service::Service;
use trussed::types::CoreContext;
use trussed::ClientImplementation;

use super::dispatch::{self, OpcardDispatch};

/// The client type opcard receives (S-721-2: `opcard::Card::new(client, options)`).
///
/// (No bounds on the alias — they live on [`SyscallRunner`]; repeating them
/// here is the `type_alias_bounds` footgun.)
pub type Client<'a, P, D> = ClientImplementation<'a, SyscallRunner<'a, P, D>, D>;

/// The "call thyself" runner: the client's [`Syscall`](trussed::platform::Syscall)
/// implementation. `process` handles one pending request per endpoint (and
/// brackets it with the UI Processing→Idle statuses); `update_ui` gives the
/// UI its refresh hook.
pub struct SyscallRunner<'a, P: Platform, D: Dispatch> {
    service: Service<P, D>,
    ep: ServiceEndpoint<'a, D::BackendId, D::Context>,
}

impl<'a, P: Platform, D: Dispatch> SyscallRunner<'a, P, D> {
    pub fn new(service: Service<P, D>, ep: ServiceEndpoint<'a, D::BackendId, D::Context>) -> Self {
        Self { service, ep }
    }
}

impl<P: Platform, D: Dispatch> trussed::platform::Syscall for SyscallRunner<'_, P, D> {
    fn syscall(&mut self) {
        // `process` takes the endpoint slice by mutable reference; the
        // single endpoint is served in place as a length-1 slice
        // (disjoint-field borrow through `&mut self`).
        self.service.process(core::slice::from_mut(&mut self.ep));
        self.service.update_ui();
    }
}

/// A [`Dispatch`] that also publishes its backend list, so a client endpoint
/// can be built generically.
pub trait Backends: Dispatch {
    /// The backends this dispatch serves, in dispatch order.
    const BACKENDS: &'static [BackendId<Self::BackendId>];
}

impl Backends for OpcardDispatch<'_> {
    const BACKENDS: &'static [BackendId<dispatch::Backend>] = dispatch::BACKENDS;
}

/// Build a backend for the duration of `f` (host seam tests, and any scoped
/// use): the interchange channel lives on the stack, the client borrows it.
///
/// Mirrors `trussed::virt::with_client` minus the std runner thread — the
/// "call thyself" runner makes a thread unnecessary (decision D1).
pub fn with_backend<P, D, R>(
    platform: P,
    dispatch: D,
    client_id: &str,
    f: impl FnOnce(Client<'_, P, D>) -> R,
) -> R
where
    P: Platform,
    D: Backends,
{
    let channel = TrussedChannel::new();
    let (requester, responder) =
        channel.split().expect("trussed channel: a fresh channel must split");
    let ep = ServiceEndpoint::new(
        responder,
        CoreContext::new(
            client_id
                .try_into()
                .expect("trusted backend: client id must be a valid filesystem path"),
        ),
        D::BACKENDS,
    );
    let runner =
        SyscallRunner::new(Service::with_dispatch(platform, dispatch), ep);
    let client: Client<'_, P, D> = ClientImplementation::new(requester, runner, None);
    f(client)
}
