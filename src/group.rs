//! # Request Grouping Mechanism
//!
//! This module provides the [`Group`] structure, which defines the logical boundaries
//! for categorizing and segregating outbound requests.
//!
//! ## Concept
//! A `Group` acts as a multi-dimensional identity for a request. In complex networking
//! stack environments, two requests targeting the same destination may belong to
//! distinct logical groups due to different metadata, security contexts, or
//! routing requirements.
//!
//! ## Logical Segregation
//! By assigning requests to different groups, the system ensures:
//! 1. **Contextual Isolation**: Requests are processed and dispatched within their defined logical
//!    partitions.
//! 2. **Deterministic Identity**: The internal `BTreeMap` ensures that the identity of a group is
//!    stable and invariant to the order in which grouping criteria are applied.
//! 3. **Resource Affinity**: Resource management (such as connection pooling) respects these
//!    boundaries, ensuring that resources are never leaked across different request groups.

use std::{
    collections::{BTreeMap, VecDeque},
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker, ready},
};

use bytes::Bytes;
use http::{Uri, Version};
use http2::ext::{PrefaceFrame, ResponsePosition};
use name::GroupId;
use tokio::sync::{Notify, watch};
use wreq_proto::http2::Control;

use crate::{conn::net::SocketBindOptions, proxy::Matcher, sync::Mutex};

/// How much memory the frames a scope keeps for its first connection, before it opened,
/// may take: those past it go to no connection.
const PENDING_HTTP2_BYTES: usize = 1 << 20;

/// How many requests held, and released, a scope keeps for its first connection, before
/// it opened: as many as a connection remembers (see [`Control::release_request`]), and as
/// many requests' resets (see [`ConnectionScope::send_http2_reset`]).
const PENDING_REQUESTS: usize = 256;

macro_rules! impl_group_variants {
    ($($name:ident $(($ty:ty))?,)*) => {
        #[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
        enum GroupKey {
            $($name,)*
        }

        #[derive(Debug, Clone, Hash, PartialEq, Eq)]
        enum GroupVariant {
            $($name $(($ty))?,)*
        }
    }
}

impl_group_variants! {
    Request(Group),
    Emulate(Group),
    Named(GroupId),
    Uri(Uri),
    Version(Version),
    Proxy(Matcher),
    SocketBind(Option<SocketBindOptions>),
    ServerName(Option<Box<str>>),
    VerifyName(Box<str>),
    AcceptedCertificate([u8; 32]),
    MinDheBits(u16),
    Scope(ScopeRef),
}

/// A logical identifier for request grouping.
///
/// `Group` encapsulates the criteria that define a request's execution context.
/// Requests with non-identical `Group` states are treated as belonging to
/// different logical partitions, preventing unintended interaction or
/// resource sharing between them.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct Group(BTreeMap<GroupKey, GroupVariant>);

impl Group {
    /// Creates a new [`Group`] with a custom string or numeric identifier.
    #[inline]
    pub fn new<N: Into<GroupId>>(name: N) -> Self {
        Group(BTreeMap::from([(
            GroupKey::Named,
            GroupVariant::Named(name.into()),
        )]))
    }

    /// Groups the request by a specific target [`Uri`].
    #[inline]
    pub(crate) fn uri(&mut self, uri: Uri) -> &mut Self {
        self.extend(GroupKey::Uri, GroupVariant::Uri(uri))
    }

    /// Groups the request by its required HTTP [`Version`].
    #[inline]
    pub(crate) fn version(&mut self, version: Option<Version>) -> &mut Self {
        self.extend(GroupKey::Version, version.map(GroupVariant::Version))
    }

    /// Groups the request based on its proxy [`Matcher`] criteria.
    #[inline]
    pub(crate) fn proxy(&mut self, proxy: Option<Matcher>) -> &mut Self {
        self.extend(GroupKey::Proxy, proxy.map(GroupVariant::Proxy))
    }

    /// Groups the request by its resolved socket bind options.
    #[inline]
    pub(crate) fn socket_bind(&mut self, opts: Option<SocketBindOptions>) -> &mut Self {
        self.extend(GroupKey::SocketBind, GroupVariant::SocketBind(opts))
    }

    /// Groups the request by the TLS server name it announces instead of its URI host
    /// (`None`: no name).
    #[inline]
    pub(crate) fn server_name(&mut self, name: Option<Box<str>>) -> &mut Self {
        self.extend(GroupKey::ServerName, GroupVariant::ServerName(name))
    }

    /// Groups the request by the name TLS verifies instead of its URI host while announcing
    /// none.
    #[inline]
    pub(crate) fn verify_name(&mut self, name: Option<Box<str>>) -> &mut Self {
        self.extend(GroupKey::VerifyName, name.map(GroupVariant::VerifyName))
    }

    /// Groups the request by the SHA-256 of the leaf certificate its TLS accepts even when
    /// verification fails.
    #[inline]
    pub(crate) fn accepted_certificate(&mut self, leaf_sha256: Option<[u8; 32]>) -> &mut Self {
        self.extend(
            GroupKey::AcceptedCertificate,
            leaf_sha256.map(GroupVariant::AcceptedCertificate),
        )
    }

    /// Groups the request by the smallest DHE group its TLS accepts.
    #[inline]
    pub(crate) fn min_dhe_bits(&mut self, bits: u16) -> &mut Self {
        self.extend(GroupKey::MinDheBits, GroupVariant::MinDheBits(bits))
    }

    /// Confines the request's connections to a [`ConnectionScope`].
    #[inline]
    pub(crate) fn scope(&mut self, scope: ScopeRef) -> &mut Self {
        self.extend(GroupKey::Scope, GroupVariant::Scope(scope))
    }

    /// Creates a nested request group.
    #[inline]
    pub(crate) fn request(&mut self, group: Group) -> &mut Self {
        self.extend(GroupKey::Request, GroupVariant::Request(group))
    }

    /// Groups the request by its emulation-layer characteristics.
    #[inline]
    pub(crate) fn emulate(&mut self, group: Group) -> &mut Self {
        self.extend(GroupKey::Emulate, GroupVariant::Emulate(group))
    }

    #[inline]
    fn extend<T: Into<Option<GroupVariant>>>(&mut self, id: GroupKey, entry: T) -> &mut Self {
        if let Some(entry) = entry.into() {
            self.0.insert(id, entry);
        }
        self
    }
}

impl From<u64> for Group {
    #[inline]
    fn from(value: u64) -> Self {
        Group::new(value)
    }
}

impl From<&'static str> for Group {
    #[inline]
    fn from(value: &'static str) -> Self {
        Group::new(value)
    }
}

impl From<String> for Group {
    #[inline]
    fn from(value: String) -> Self {
        Group::new(value)
    }
}

impl From<Box<str>> for Group {
    #[inline]
    fn from(value: Box<str>) -> Self {
        Group::new(value)
    }
}

/// Confines the connections requests open to one lifetime: a connection serves only
/// requests of the scope it was opened for, and closes, idle or not, once every clone of
/// the scope is dropped, or it is closed (see [`ConnectionScope::close`]).
#[derive(Clone)]
pub struct ConnectionScope(Arc<(u64, watch::Sender<bool>, Arc<Connections>)>);

/// The HTTP/2 connections open in a scope, each by an id, able to send frames of the
/// caller's choosing, the first connection opened in it, once one is: the [`Control`] of
/// an HTTP/2 one, `None` for an HTTP/1 one, how they end (a [`ConnectionEnd`], 0 until
/// told, else one past it) and the tasks waiting to be told, what the caller sent them
/// before the first opened, which that one sends should it speak HTTP/2 (the frames, unless
/// the caller dropped them, and the requests held, `true`, or released), the tasks waiting
/// for room among those frames, the requests' resets, by request, the SETTINGS parameters
/// sent on, each's latest value, the connections waiting for the scope's close, how their origins
/// end the HTTP/2 ones, and how many HTTP/1 ones are open, told once an origin closed the last,
/// which, in a scope ending with its HTTP/1 origin, leaves it gone for good.
#[derive(Default)]
struct Connections {
    http2: Mutex<Vec<(u64, Control)>>,
    first: watch::Sender<Option<Option<Control>>>,
    end: AtomicU8,
    end_tasks: Mutex<Vec<Waker>>,
    close_tasks: Mutex<Vec<(u64, Waker)>>,
    pending: Mutex<PendingHttp2>,
    pending_dropped: AtomicBool,
    pending_requests: Mutex<PendingRequests>,
    pending_resets: Mutex<VecDeque<(u32, u32)>>,
    settings: Mutex<Vec<(u16, u32)>>,
    pending_tasks: Mutex<Vec<Waker>>,
    origin_ends: OriginEnds,
    http1_open: AtomicUsize,
    http1_origin_closed: Notify,
    ends_with_http1_origin: AtomicBool,
    http1_origin_gone: AtomicBool,
}

/// The frames a scope had its HTTP/2 connections send before its first opened, the memory
/// they take, and whether one past them went to no connection.
#[derive(Default)]
struct PendingHttp2 {
    sends: Vec<Box<dyn Fn(&Control) + Send>>,
    bytes: usize,
    overflowed: bool,
}

impl PendingHttp2 {
    /// Whether it holds as many as it may.
    fn is_full(&self) -> bool {
        self.bytes >= PENDING_HTTP2_BYTES
    }
}

/// The requests held, and released, before a scope's first connection opened, as a
/// connection keeps them (see [`Control::hold_request`]): a release ends a hold, and each
/// past [`PENDING_REQUESTS`] loses its oldest.
#[derive(Default)]
struct PendingRequests {
    held: VecDeque<u32>,
    released: VecDeque<u32>,
}

/// How the origins of a scope's HTTP/2 connections end them, as they do, until the caller
/// takes them (see [`ConnectionScope::http2_origin_ends`]), and whether it did.
#[derive(Default)]
struct OriginEnds {
    ends: Arc<OriginEndsInner>,
    taken: AtomicBool,
}

#[derive(Default)]
struct OriginEndsInner {
    queue: Mutex<OriginEndsQueue>,
    told: Notify,
}

/// The ends told and not yet taken, at most [`ORIGIN_GO_AWAYS`] GOAWAYs waiting before one
/// merges into the last, whether the scope is gone, how many GOAWAYs were told, and what
/// is called with each as it is (see [`Http2OriginEnds::on_go_away`]).
#[derive(Default)]
struct OriginEndsQueue {
    ends: VecDeque<Http2OriginEnd>,
    closed: bool,
    go_aways: u64,
    on_go_away: Option<Box<GoAwayHook>>,
}

/// Called with each GOAWAY's number and positions as it is told.
type GoAwayHook = dyn Fn(u64, &[(u32, ResponsePosition)]) + Send + Sync;

/// How many ends wait to be taken before a GOAWAY told past them merges into a GOAWAY
/// waiting last.
const ORIGIN_GO_AWAYS: usize = 4;

impl OriginEnds {
    fn tell(&self, mut end: Http2OriginEnd) {
        let mut queue = self.ends.queue.lock();
        if let Http2OriginEnd::GoAway {
            number, positions, ..
        } = &mut end
        {
            queue.go_aways += 1;
            *number = queue.go_aways;
            if let Some(on_go_away) = &queue.on_go_away {
                on_go_away(*number, positions);
            }
        }
        let waiting = queue.ends.len();
        match (queue.ends.back_mut(), end) {
            (
                Some(Http2OriginEnd::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                    refused,
                    positions,
                    number,
                }),
                Http2OriginEnd::GoAway {
                    last_stream_id: next_last_stream_id,
                    error_code: next_error_code,
                    debug_data: next_debug_data,
                    refused: next_refused,
                    positions: next_positions,
                    number: next_number,
                },
            ) if waiting >= ORIGIN_GO_AWAYS => {
                *last_stream_id = (*last_stream_id).min(next_last_stream_id);
                *error_code = next_error_code;
                *debug_data = next_debug_data;
                *number = next_number;
                refused.extend(next_refused);
                refused.sort_unstable();
                refused.dedup();
                // A response's earlier position stands.
                for (recorded, position) in next_positions {
                    if !positions.iter().any(|(merged, _)| *merged == recorded) {
                        positions.push((recorded, position));
                    }
                }
            }
            (_, end) => queue.ends.push_back(end),
        }
        drop(queue);
        self.ends.told.notify_one();
    }
}

impl Drop for OriginEnds {
    fn drop(&mut self) {
        self.ends.queue.lock().closed = true;
        self.ends.told.notify_one();
    }
}

/// How the origins of a scope's HTTP/2 connections end them, in the order they do (see
/// [`ConnectionScope::http2_origin_ends`]). Past four waiting to be taken, a GOAWAY merges
/// into a GOAWAY waiting last: that one then names the lower last stream of the two, with
/// this one's error code, debug data and number, the requests either refused, and the
/// positions of either (the waiting one's where both have one).
pub struct Http2OriginEnds(Arc<OriginEndsInner>);

impl Http2OriginEnds {
    /// Calls `go_away` with each GOAWAY's number and positions (see
    /// [`Http2OriginEnd::GoAway`]) as the connection receives it, before the frames it
    /// received after it can be read; GOAWAYs merged are each told so.
    pub fn on_go_away(
        &self,
        go_away: impl Fn(u64, &[(u32, ResponsePosition)]) + Send + Sync + 'static,
    ) {
        self.0.queue.lock().on_go_away = Some(Box::new(go_away));
    }

    /// The next end, once told; `None` once the scope is gone and every end was taken.
    pub async fn recv(&mut self) -> Option<Http2OriginEnd> {
        loop {
            let told = self.0.told.notified();
            {
                let mut queue = self.0.queue.lock();
                if let Some(end) = queue.ends.pop_front() {
                    return Some(end);
                }
                if queue.closed {
                    return None;
                }
            }
            told.await;
        }
    }
}

/// How the origin of one of a scope's HTTP/2 connections ends it, in the order it does (see
/// [`ConnectionScope::http2_origin_ends`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Http2OriginEnd {
    /// It sent a GOAWAY: its last stream, numbered as the scope's requests were recorded on
    /// numbered it (see [`Control::on_go_away`]), its error code and its debug data.
    GoAway {
        /// The last stream it processed.
        last_stream_id: u32,
        /// The error code.
        error_code: u32,
        /// The debug data.
        debug_data: Bytes,
        /// The open requests it carried past that stream, as recorded, which it leaves
        /// unprocessed; those of the scope's other connections went on regardless.
        refused: Vec<u32>,
        /// Where it came in the response to each request it carried up to that stream, as
        /// recorded, whether or not that response was read yet: a client of the origin
        /// gets the frames before that point ahead of it, and those past it after it.
        positions: Vec<(u32, ResponsePosition)>,
        /// How many GOAWAYs the scope's connections sent up to it, it included.
        number: u64,
    },
    /// It broke the protocol: the connection, detecting a connection error in what it
    /// sent, ended with a GOAWAY carrying `error_code` (see
    /// [`Control::on_connection_error`]).
    Failed {
        /// The GOAWAY's error code.
        error_code: u32,
    },
    /// It closed the connection: with TLS's close_notify or not, by a TCP reset or not.
    Closed {
        /// Whether it sent its close_notify.
        close_notify: bool,
        /// Whether it reset the connection.
        reset: bool,
    },
}

/// Called each time the request carrying it (as an extension) is queued on the connection
/// sending it, which sends the requests queued on it in that order.
#[derive(Clone)]
pub struct OnQueued(Arc<dyn Fn() + Send + Sync>);

impl OnQueued {
    /// Calls `queued` each time the request is queued on its connection.
    pub fn new(queued: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(queued))
    }

    pub(crate) fn queued(&self) {
        (self.0)();
    }
}

/// How a [`ConnectionScope`]'s connections end (see [`ConnectionScope::end_with`]). An
/// HTTP/2 one sends no GOAWAY of its own: only those
/// [`ConnectionScope::send_http2_go_away`] sends.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectionEnd {
    /// With TLS's close_notify, then a FIN, once they close.
    #[default]
    Graceful = 0,
    /// With a FIN alone, sending nothing more: no close_notify.
    Fin = 1,
    /// With a TCP reset, sending nothing more.
    Reset = 2,
}

impl Connections {
    fn opened(&self, control: Option<Control>) {
        self.first.send_if_modified(|first| {
            let none = first.is_none();
            if none {
                *first = Some(control);
            }
            none
        });
        self.wake_pending_tasks();
    }

    /// Wakes the tasks waiting for room among the frames kept for the first connection.
    fn wake_pending_tasks(&self) {
        for task in self.pending_tasks.lock().drain(..) {
            task.wake();
        }
    }
}

impl ConnectionScope {
    /// Creates a scope no other scope's requests share connections with.
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let (closed, _) = watch::channel(false);
        ConnectionScope(Arc::new((
            NEXT_ID.fetch_add(1, Ordering::Relaxed),
            closed,
            Arc::default(),
        )))
    }

    pub(crate) fn handle(&self) -> ScopeRef {
        ScopeRef {
            id: self.0.0,
            closed: self.0.1.subscribe(),
            connections: self.0.2.clone(),
        }
    }

    /// The [`Control`] of the first connection opened in this scope, once one is; `None`
    /// when that connection speaks HTTP/1 (no later HTTP/2 one is told).
    pub async fn first_http2(&self) -> Option<Control> {
        let mut first = self.0.2.first.subscribe();
        first
            .wait_for(Option::is_some)
            .await
            .expect("the scope holds the sender")
            .clone()
            .flatten()
    }

    /// Sends a SETTINGS frame of exactly `params`, `(identifier, value)` in order, on each
    /// HTTP/2 connection open in this scope, following the request recorded as `after` (see
    /// [`Control::after_request`]), once the previous one it sent was acknowledged; the
    /// known parameters apply to it on the acknowledgement. Before the scope's first
    /// connection opened, that one sends it, should it speak HTTP/2, as the frames below.
    /// A connection opening in this scope after its first sends their parameters, each's
    /// latest value, right before its first request (see
    /// [`Control::send_before_next_request`]).
    pub fn send_http2_settings(&self, after: u32, params: &[(u16, u32)]) {
        let http2 = self.0.2.http2.lock();
        let sent = params.to_vec();
        let goes = self.on_http2_locked(&http2, after, size_of_val(params), move |control| {
            control
                .after_request(after)
                .send_settings(sent.iter().copied())
        });
        if goes {
            let mut settings = self.0.2.settings.lock();
            for &(id, value) in params {
                match settings.iter_mut().find(|(kept, _)| *kept == id) {
                    Some(kept) => kept.1 = value,
                    None => settings.push((id, value)),
                }
            }
        }
    }

    /// Sends a PING carrying `payload` on each HTTP/2 connection open in this scope,
    /// following the request recorded as `after` (see [`Control::after_request`]).
    pub fn send_http2_ping(&self, after: u32, payload: [u8; 8]) {
        self.on_http2(after, 0, move |control| {
            control.after_request(after).send_ping(payload)
        });
    }

    /// Sends `priority`, a PRIORITY frame numbered as the connection requests were recorded
    /// on numbered streams, on each HTTP/2 connection open in this scope, as it numbers them
    /// (see [`Control::send_priority`]), following the request recorded as `after` (see
    /// [`Control::after_request`]).
    pub fn send_http2_priority(&self, after: u32, priority: &http2::frame::Priority) {
        let priority = priority.clone();
        self.on_http2(after, 0, move |control| {
            control.after_request(after).send_priority(priority.clone())
        });
    }

    /// Sends a PRIORITY_UPDATE frame (RFC 9218) giving `stream_id`, numbered as the
    /// connection requests were recorded on numbered it, the priority `field_value` on each
    /// HTTP/2 connection open in this scope, as it numbers it (see
    /// [`Control::send_priority_update`]), following the request recorded as `after` (see
    /// [`Control::after_request`]).
    pub fn send_http2_priority_update(&self, after: u32, stream_id: u32, field_value: &[u8]) {
        let field_value = field_value.to_vec();
        self.on_http2(after, field_value.len(), move |control| {
            control
                .after_request(after)
                .send_priority_update(stream_id, &field_value)
        });
    }

    /// Sends a WINDOW_UPDATE of `increment` for the connection (`stream_id` 0) or the
    /// request recorded as `stream_id` on each HTTP/2 connection open in this scope, as it
    /// numbers it (see [`Control::send_window_update`]), following the request recorded as
    /// `after` (see [`Control::after_request`]).
    pub fn send_http2_window_update(&self, after: u32, stream_id: u32, increment: u32) {
        self.on_http2(after, 0, move |control| {
            control
                .after_request(after)
                .send_window_update(stream_id, increment)
        });
    }

    /// Sends a frame of a type HTTP/2 doesn't define, of `kind`, `flags` and `payload`, on
    /// the connection (`stream_id` 0) or the request recorded as `stream_id` on each HTTP/2
    /// connection open in this scope, as it numbers it (see [`Control::send_unknown`]),
    /// following the request recorded as `after` (see [`Control::after_request`]).
    pub fn send_http2_unknown(
        &self,
        after: u32,
        kind: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) {
        let payload = payload.to_vec();
        self.on_http2(after, payload.len(), move |control| {
            control
                .after_request(after)
                .send_unknown(kind, flags, stream_id, &payload)
        });
    }

    /// Makes the request recorded as `recorded`, on the HTTP/2 connection of this scope it
    /// was sent on, reset with `error_code` rather than its own should it be dropped before
    /// it ends or reset (see [`Control::cancel_with`]): as its client reset it. Before the
    /// scope's first connection opened, that one is told, should it speak HTTP/2: the first
    /// reset of each request, the oldest past [`PENDING_REQUESTS`] dropped, kept apart from
    /// the frames, so they never wait for room (see [`Self::poll_http2_room`]).
    pub fn send_http2_reset(&self, recorded: u32, error_code: u32) {
        let http2 = self.0.2.http2.lock();
        if self.0.2.first.borrow().is_none() {
            let mut resets = self.0.2.pending_resets.lock();
            if resets.iter().all(|(kept, _)| *kept != recorded) {
                if resets.len() == PENDING_REQUESTS {
                    resets.pop_front();
                }
                resets.push_back((recorded, error_code));
            }
            return;
        }
        for (_, control) in http2.iter() {
            control.cancel_with(recorded, error_code.into());
        }
    }

    /// Tells each HTTP/2 connection open in this scope that the request recorded as
    /// `recorded` won't be sent on it unless it was (see [`Control::release_request`]).
    pub fn release_http2_request(&self, recorded: u32) {
        self.on_http2_request(recorded, false);
    }

    /// Tells each HTTP/2 connection open in this scope that the request recorded as
    /// `recorded` is held before it goes out (see [`Control::hold_request`]).
    pub fn hold_http2_request(&self, recorded: u32) {
        self.on_http2_request(recorded, true);
    }

    /// Drops the frames this scope had its HTTP/2 connections send before its first one
    /// opened, and keeps none from now on: they go to no connection. The requests held or
    /// released before, and the resets of requests, still go to it.
    pub fn drop_http2_pending(&self) {
        let _http2 = self.0.2.http2.lock();
        self.0.2.pending_dropped.store(true, Ordering::Release);
        *self.0.2.pending.lock() = PendingHttp2::default();
        self.0.2.wake_pending_tasks();
    }

    /// Sends a GOAWAY frame of `error_code` and `debug_data` naming `last_stream_id`, a
    /// request's numbered as the connection numbers it (see [`Control::send_go_away`]), on
    /// each HTTP/2 connection open in this scope, following the request recorded as `after`
    /// (see [`Control::after_request`]); they then close without a GOAWAY of their own.
    pub fn send_http2_go_away(
        &self,
        after: u32,
        last_stream_id: u32,
        error_code: u32,
        debug_data: &[u8],
    ) {
        let debug_data = debug_data.to_vec();
        self.on_http2(after, debug_data.len(), move |control| {
            control.after_request(after).send_go_away(
                last_stream_id,
                error_code.into(),
                &debug_data,
            )
        });
    }

    /// Resolves once the origin of an HTTP/1 connection open in this scope closed it, with no
    /// other open: as a client's own connection to it would have closed.
    pub async fn http1_origin_closed(&self) {
        // The permit of a close told while none waited is stale once another opened since.
        loop {
            self.0.2.http1_origin_closed.notified().await;
            if self.0.2.http1_open.load(Ordering::Acquire) == 0 {
                return;
            }
        }
    }

    /// Makes this scope end with its HTTP/1 origin, as a client's own connection to it does:
    /// once the origin closed the last HTTP/1 connection open in it (see
    /// [`Self::http1_origin_closed`]), it opens no other, its requests failing to connect.
    pub fn end_with_http1_origin(&self) {
        self.0
            .2
            .ends_with_http1_origin
            .store(true, Ordering::Release);
    }

    /// Whether this scope, ending with its HTTP/1 origin (see
    /// [`Self::end_with_http1_origin`]), is gone: that origin closed its last HTTP/1
    /// connection.
    pub fn http1_origin_gone(&self) -> bool {
        self.0.2.http1_origin_gone.load(Ordering::Acquire)
    }

    /// How the origins of this scope's HTTP/2 connections end them, as they do: each GOAWAY
    /// they send, then how they close. Taken by the first call, `None` after it.
    pub fn http2_origin_ends(&self) -> Option<Http2OriginEnds> {
        let origin_ends = &self.0.2.origin_ends;
        (!origin_ends.taken.swap(true, Ordering::AcqRel))
            .then(|| Http2OriginEnds(origin_ends.ends.clone()))
    }

    /// Ready once the frames this scope had its HTTP/2 connections send leave room for more
    /// on each (see [`Control::poll_room`]), or, before its first connection opened, among
    /// those it keeps for it: a caller sending its own client's frames on as they arrive
    /// reads no more of them until then, rather than having them queue without bound. While
    /// a request is held before that (see [`Self::hold_http2_request`]), whose release may
    /// wait for frames behind them, such as its body's, those past them go to no connection.
    pub fn poll_http2_room(&self, cx: &mut Context<'_>) -> Poll<()> {
        let http2 = self.0.2.http2.lock();
        if self.0.2.first.borrow().is_none() {
            let full = self.0.2.pending.lock().is_full();
            if !full || !self.0.2.pending_requests.lock().held.is_empty() {
                return Poll::Ready(());
            }
            let mut tasks = self.0.2.pending_tasks.lock();
            if !tasks.iter().any(|task| task.will_wake(cx.waker())) {
                tasks.push(cx.waker().clone());
            }
            return Poll::Pending;
        }
        for (_, control) in http2.iter() {
            ready!(control.poll_room(cx));
        }
        Poll::Ready(())
    }

    /// Resolves once each HTTP/2 connection open in this scope sent the frames this scope had
    /// it send, or ended (see [`Control::sent`]).
    pub async fn http2_sent(&self) {
        let http2 = self.0.2.http2.lock().clone();
        for (_, control) in http2 {
            control.sent().await;
        }
    }

    /// Runs `send`, sending a frame following the request recorded as `after` (see
    /// [`Control::after_request`]) whose payload takes `octets` on the heap, on each HTTP/2
    /// connection open in this scope, or, before the scope's first connection opened, on
    /// that one should it speak HTTP/2. Once one of them sent that request, the others,
    /// which won't, are told so (see [`Control::release_request`]): there it goes at once
    /// rather than waiting for a later request of theirs.
    fn on_http2(&self, after: u32, octets: usize, send: impl Fn(&Control) + Send + 'static) {
        let http2 = self.0.2.http2.lock();
        self.on_http2_locked(&http2, after, octets, send);
    }

    /// [`Self::on_http2`] with the connections (`http2`) locked; whether the frame goes on.
    fn on_http2_locked(
        &self,
        http2: &[(u64, Control)],
        after: u32,
        octets: usize,
        send: impl Fn(&Control) + Send + 'static,
    ) -> bool {
        if self.0.2.first.borrow().is_none() {
            let mut pending = self.0.2.pending.lock();
            if self.0.2.pending_dropped.load(Ordering::Acquire) {
                return false;
            }
            if pending.is_full() {
                if !std::mem::replace(&mut pending.overflowed, true) {
                    warn!(
                        "the HTTP/2 frames sent before the scope's first connection opened, past as many as it keeps, go to no connection"
                    );
                }
                return false;
            }
            pending.bytes +=
                octets + size_of_val(&send) + size_of::<Box<dyn Fn(&Control) + Send>>();
            pending.sends.push(Box::new(send));
            return true;
        }
        if after != 0 && http2.len() > 1 && http2.iter().any(|(_, control)| control.carries(after))
        {
            for (_, control) in http2.iter().filter(|(_, control)| !control.carries(after)) {
                control.release_request(after);
            }
        }
        for (_, control) in http2 {
            send(control);
        }
        true
    }

    /// Tells each HTTP/2 connection open in this scope that the request recorded as
    /// `recorded` is held, or released, or, before the scope's first connection opened,
    /// that one should it speak HTTP/2.
    fn on_http2_request(&self, recorded: u32, held: bool) {
        let http2 = self.0.2.http2.lock();
        if self.0.2.first.borrow().is_none() {
            let mut pending = self.0.2.pending_requests.lock();
            if held {
                // Those waiting for room no longer wait while it is held.
                self.0.2.wake_pending_tasks();
            } else {
                pending.held.retain(|kept| *kept != recorded);
            }
            let kept = if held {
                &mut pending.held
            } else {
                &mut pending.released
            };
            if kept.len() == PENDING_REQUESTS {
                kept.pop_front();
            }
            kept.push_back(recorded);
            return;
        }
        for (_, control) in http2.iter() {
            tell_request(control, recorded, held);
        }
    }

    /// Makes the receive window of the request recorded as `recorded`, on the HTTP/2
    /// connection of this scope it was sent on, grow only by the WINDOW_UPDATEs
    /// [`Self::send_http2_window_update`] sends (see [`Control::mirror_stream_window`]).
    pub fn mirror_http2_stream_window(&self, recorded: u32) {
        // Before the scope's first connection opened, none sent it.
        if self.0.2.first.borrow().is_some() {
            self.on_http2(0, 0, move |control| control.mirror_stream_window(recorded));
        }
    }

    /// Makes this scope's connections end as `end` says: past [`ConnectionEnd::Fin`] or
    /// [`ConnectionEnd::Reset`] they send nothing more, and end so once they close, as they
    /// do once the scope is dropped. An HTTP/2 connection whose origin closed it first
    /// waits a moment for it before closing, else ends with a FIN alone; one closing
    /// otherwise before it ends gracefully.
    pub fn end_with(&self, end: ConnectionEnd) {
        self.0.2.end.store(end as u8 + 1, Ordering::Release);
        for task in self.0.2.end_tasks.lock().drain(..) {
            task.wake();
        }
    }

    /// Closes this scope's connections now, as dropping its last clone does, the requests
    /// still open on them failing: for a scope whose requests' client connection ended,
    /// their streams ending with their connections as that client's did, rather than each
    /// being reset first. They read nothing more, ending as [`Self::end_with`] says, and
    /// those it opens later close at once.
    pub fn close(&self) {
        self.0.1.send_replace(true);
        for (_, task) in self.0.2.close_tasks.lock().drain(..) {
            task.wake();
        }
    }
}

impl Default for ConnectionScope {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ConnectionScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ConnectionScope").field(&self.0.0).finish()
    }
}

/// A [`ConnectionScope`]'s identity and end, held by its requests and connections without
/// keeping it alive.
#[derive(Clone)]
pub(crate) struct ScopeRef {
    id: u64,
    closed: watch::Receiver<bool>,
    connections: Arc<Connections>,
}

/// Tells `control` that the request recorded as `recorded` is held, or released.
fn tell_request(control: &Control, recorded: u32, held: bool) {
    if held {
        control.hold_request(recorded);
    } else {
        control.release_request(recorded);
    }
}

/// An HTTP/2 connection's place among its scope's, which it leaves when dropped.
pub(crate) struct Http2Registration {
    id: u64,
    connections: Arc<Connections>,
}

impl Drop for Http2Registration {
    fn drop(&mut self) {
        self.connections
            .http2
            .lock()
            .retain(|(id, _)| *id != self.id);
    }
}

/// An HTTP/1 connection counted open in its scope until dropped, closed by its origin when
/// `by_origin`.
pub(crate) struct Http1Open {
    connections: Arc<Connections>,
    pub(crate) by_origin: bool,
}

impl Drop for Http1Open {
    fn drop(&mut self) {
        if self.connections.http1_open.fetch_sub(1, Ordering::AcqRel) == 1 && self.by_origin {
            if self
                .connections
                .ends_with_http1_origin
                .load(Ordering::Acquire)
            {
                self.connections
                    .http1_origin_gone
                    .store(true, Ordering::Release);
            }
            self.connections.http1_origin_closed.notify_one();
        }
    }
}

impl ScopeRef {
    /// Makes the scope's HTTP/2 frames go on the connection `control` sends on, until the
    /// registration returned is dropped, and tells it as the scope's first connection
    /// should it be.
    pub(crate) fn register_http2(&self, control: Control) -> Http2Registration {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        control.leave_close_to_caller();
        let connections = Arc::downgrade(&self.connections);
        let failed = connections.clone();
        control.on_connection_error(move |reason| {
            if let Some(connections) = failed.upgrade() {
                connections.origin_ends.tell(Http2OriginEnd::Failed {
                    error_code: reason.into(),
                });
            }
        });
        control.on_go_away(
            move |last_stream_id, reason, debug_data, refused, positions| {
                if let Some(connections) = connections.upgrade() {
                    connections.origin_ends.tell(Http2OriginEnd::GoAway {
                        last_stream_id,
                        error_code: reason.into(),
                        debug_data,
                        refused: refused.to_vec(),
                        positions: positions.to_vec(),
                        number: 0,
                    });
                }
            },
        );
        let mut http2 = self.connections.http2.lock();
        for send in std::mem::take(&mut *self.connections.pending.lock()).sends {
            send(&control);
        }
        // One opening after the first carries the SETTINGS sent on before it, which the
        // first got as they came (see `ConnectionScope::send_http2_settings`).
        let settings = self.connections.settings.lock();
        if self.connections.first.borrow().is_some() && !settings.is_empty() {
            control.send_before_next_request([PrefaceFrame::Settings(settings.clone())]);
        }
        drop(settings);
        // Releases first: a request held again after its release stays held.
        let requests = std::mem::take(&mut *self.connections.pending_requests.lock());
        for recorded in requests.released {
            control.release_request(recorded);
        }
        for recorded in requests.held {
            control.hold_request(recorded);
        }
        for (recorded, error_code) in std::mem::take(&mut *self.connections.pending_resets.lock()) {
            control.cancel_with(recorded, error_code.into());
        }
        http2.push((id, control.clone()));
        self.connections.opened(Some(control));
        drop(http2);
        Http2Registration {
            id,
            connections: self.connections.clone(),
        }
    }

    /// Tells an HTTP/1 connection opened as the scope's first connection, should it be,
    /// dropping what the caller sent its HTTP/2 connections before.
    pub(crate) fn opened_http1(&self) {
        let _http2 = self.connections.http2.lock();
        *self.connections.pending.lock() = PendingHttp2::default();
        *self.connections.pending_requests.lock() = PendingRequests::default();
        self.connections.pending_resets.lock().clear();
        self.connections.opened(None);
    }

    /// How the scope's connections end (see [`ConnectionScope::end_with`]).
    pub(crate) fn end(&self) -> ConnectionEnd {
        self.ended().unwrap_or_default()
    }

    /// How the scope's connections end, once told (see [`ConnectionScope::end_with`]).
    pub(crate) fn ended(&self) -> Option<ConnectionEnd> {
        match self.connections.end.load(Ordering::Acquire) {
            0 => None,
            2 => Some(ConnectionEnd::Fin),
            3 => Some(ConnectionEnd::Reset),
            _ => Some(ConnectionEnd::Graceful),
        }
    }

    /// Wakes `task` once the scope is told how its connections end, unless it was already.
    pub(crate) fn wake_on_end(&self, task: &Waker) -> Option<ConnectionEnd> {
        let mut tasks = self.connections.end_tasks.lock();
        let ended = self.ended();
        if ended.is_none() && !tasks.iter().any(|waiting| waiting.will_wake(task)) {
            tasks.push(task.clone());
        }
        ended
    }

    /// Whether the scope is gone with its HTTP/1 origin (see
    /// [`ConnectionScope::http1_origin_gone`]): it opens no connection.
    pub(crate) fn http1_origin_gone(&self) -> bool {
        self.connections.http1_origin_gone.load(Ordering::Acquire)
    }

    /// Counts an HTTP/1 connection open in the scope, from its connect on, until the
    /// [`Http1Open`] returned is dropped.
    pub(crate) fn http1_opened(&self) -> Http1Open {
        self.connections.http1_open.fetch_add(1, Ordering::AcqRel);
        Http1Open {
            connections: self.connections.clone(),
            by_origin: false,
        }
    }

    /// Tells the scope how the origin of one of its HTTP/2 connections closed it.
    pub(crate) fn origin_closed(&self, close_notify: bool, reset: bool) {
        self.connections.origin_ends.tell(Http2OriginEnd::Closed {
            close_notify,
            reset,
        });
    }

    /// Whether the scope was closed (see [`ConnectionScope::close`]); otherwise wakes `task`,
    /// the latest of the connection `id`'s, once it is, until [`Self::forget_closed`].
    pub(crate) fn poll_closed(&self, id: u64, task: &Waker) -> bool {
        let mut tasks = self.connections.close_tasks.lock();
        if *self.closed.borrow() {
            return true;
        }
        match tasks.iter_mut().find(|(waiting, _)| *waiting == id) {
            Some((_, waiting)) => waiting.clone_from(task),
            None => tasks.push((id, task.clone())),
        }
        false
    }

    /// Wakes the connection `id`'s task at the scope's close no longer (see
    /// [`Self::poll_closed`]).
    pub(crate) fn forget_closed(&self, id: u64) {
        self.connections
            .close_tasks
            .lock()
            .retain(|(waiting, _)| *waiting != id);
    }

    /// Resolves once the scope is dropped or closed.
    pub(crate) async fn closed(mut self) {
        // An error once the sender is gone.
        let _ = self.closed.wait_for(|closed| *closed).await;
    }
}

impl Hash for ScopeRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl PartialEq for ScopeRef {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ScopeRef {}

impl std::fmt::Debug for ScopeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ScopeRef").field(&self.id).finish()
    }
}

mod name {

    /// A group identifier that can be a string or a numeric tag.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub enum GroupId {
        Borrowed(&'static str),
        Owned(Box<str>),
        Number(u64),
    }

    impl From<&'static str> for GroupId {
        #[inline]
        fn from(value: &'static str) -> Self {
            Self::Borrowed(value)
        }
    }

    impl From<String> for GroupId {
        #[inline]
        fn from(value: String) -> Self {
            Self::Owned(value.into_boxed_str())
        }
    }

    impl From<Box<str>> for GroupId {
        #[inline]
        fn from(value: Box<str>) -> Self {
            Self::Owned(value)
        }
    }

    impl From<u64> for GroupId {
        #[inline]
        fn from(value: u64) -> Self {
            Self::Number(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;

    #[test]
    fn test_group_identity_invariance() {
        let mut g1 = Group::default();
        g1.extend(GroupKey::Named, GroupVariant::Named("worker".into()));
        g1.extend(GroupKey::Version, GroupVariant::Version(Version::HTTP_2));

        let mut g2 = Group::default();
        g2.extend(GroupKey::Version, GroupVariant::Version(Version::HTTP_2));
        g2.extend(GroupKey::Named, GroupVariant::Named("worker".into()));

        let mut h1 = DefaultHasher::new();
        g1.hash(&mut h1);

        let mut h2 = DefaultHasher::new();
        g2.hash(&mut h2);

        assert_eq!(
            h1.finish(),
            h2.finish(),
            "Request groups must maintain identical hashes regardless of criteria insertion order"
        );
    }
}
