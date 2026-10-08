//! The transport of a connection confined to a [`ConnectionScope`](crate::ConnectionScope),
//! which ends as the scope says (see [`ConnectionEnd`]).

use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use futures_util::task::AtomicWaker;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
};
use wreq_proto::{
    conn::http2::SendingBodies,
    rt::{Sleep, Timer as _},
};

use super::drain_bound;
use crate::{
    conn::Connection,
    group::{ConnectionEnd, Http1Open, OriginEnd, ScopeRef},
    rt::Timer,
};

/// How long an HTTP/2 connection closing before its scope ended waits for it (see
/// [`ConnectionScope::end_with`](crate::ConnectionScope::end_with)).
const SCOPE_END_WAIT: Duration = Duration::from_secs(2);

/// A connection's transport. Once its scope ends otherwise than [`ConnectionEnd::Graceful`]
/// every read and write of it fails, so the connection sends nothing more, and it closes so
/// once dropped; once its scope is closed it reads nothing more. One not reset still writes
/// what it holds first, an HTTP/2 one the request bodies it still has to send (see
/// [`ScopedIo::draining`]). Dropped, it goes to the
/// receiver [`ScopedIo::new`] returned, if that is still there, with the alert of
/// [`ConnectionEnd::Alert`] it owes its origin, which the receiver sends, and whether it was
/// shut down; without one, the alert goes as far as its socket has room. Aborted (see
/// [`Abort`]), it waits for no read or write more, and resets once dropped should one have
/// waited.
///
/// An HTTP/1 one is counted open in its scope from its connect on (see
/// [`ConnectionScope::http1_origin_closed`](crate::ConnectionScope::http1_origin_closed)).
/// Dropped before its origin ended it, in a scope ending with its HTTP/1 origin that hasn't
/// ended otherwise, it goes to that receiver still counted open, to learn how its origin
/// ends it.
/// An HTTP/2 one tells its scope how its origin closed it, and closes as its scope ends,
/// waiting up to [`SCOPE_END_WAIT`] for that, as the origin's close ends the scope's
/// client soon after; past it, after its origin's close, it closes with a FIN alone.
pub(super) struct ScopedIo<T: Connection + Unpin> {
    /// Its id among its scope's connections waiting for its end or close.
    id: u64,
    io: Option<T>,
    scope: Option<ScopeRef>,
    http1: Option<Http1Open>,
    dropped: Option<oneshot::Sender<Dropped<T>>>,
    http2: bool,
    /// Whether its origin ended its side: a read ended, or failed, or a write failed with
    /// its reset.
    origin_ended: bool,
    timer: Timer,
    /// Bounds its wait for its scope's end, once it started.
    scope_end_wait: Option<Pin<Box<dyn Sleep>>>,
    /// Bounds its writes past its scope's end or close, once they started.
    drain: Option<Pin<Box<dyn Sleep>>>,
    /// Whether it was written to since it was last flushed.
    wrote: bool,
    /// Whether, draining, a flush waited a turn for it to be written to.
    drain_turn: bool,
    /// Whether, draining, it was found to hold nothing more.
    drained: bool,
    /// Whether its transport was shut down (see `poll_shutdown`).
    shut: bool,
    /// Set while its HTTP/1 connection has a request body still to send (see
    /// [`Self::sending_body`]).
    sending_body: Arc<AtomicBool>,
    /// The request bodies its HTTP/2 connection still has to send (see
    /// [`Self::sending_bodies`]).
    sending_bodies: Arc<SendingBodies>,
    abort: Arc<Abort>,
    /// Whether its abort failed a read or write that would have waited.
    aborted: bool,
    ended_first: Arc<EndedFirst>,
}

/// Has a [`ScopedIo`] fail each read and write that would wait from now on, waking the task
/// waiting, for a connection still holding it past its scope's close by the bound of its end.
#[derive(Default)]
pub(super) struct Abort {
    aborted: AtomicBool,
    task: AtomicWaker,
}

impl Abort {
    pub(super) fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        self.task.wake();
    }
}

/// Which ended a [`ScopedIo`]'s connection first, its origin or its scope, failing the
/// requests it still had so (see [`EndedFirst::by_scope`]).
#[derive(Default)]
pub(super) struct EndedFirst(AtomicU8);

impl EndedFirst {
    const ORIGIN: u8 = 1;
    const SCOPE: u8 = 2;

    fn set(&self, by: u8) {
        let _ = self
            .0
            .compare_exchange(0, by, Ordering::AcqRel, Ordering::Acquire);
    }

    /// Notes that its scope ended it, unless its origin had.
    pub(super) fn scope(&self) {
        self.set(Self::SCOPE);
    }

    /// Whether its scope ended it before its origin did: a request failing on it then failed
    /// as its scope ended it (see [`ScopeEnded`](crate::ScopeEnded)).
    pub(super) fn by_scope(&self) -> bool {
        self.0.load(Ordering::Acquire) == Self::SCOPE
    }
}

/// A dropped [`ScopedIo`]'s transport, still counted open in its scope if it is, the fatal
/// alert it owes its origin, if any, and whether it was shut down.
pub(super) type Dropped<T> = (T, Option<Http1Open>, Option<u8>, bool);

/// A new id among a scope's connections, and those being set up, waiting for its end or
/// close (see [`ScopeRef::wake_on_end`]).
pub(super) fn next_id() -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

impl<T: Connection + Unpin> ScopedIo<T> {
    /// Wraps `io`, the transport of a connection confined to `scope`, if any, speaking
    /// HTTP/2 when `http2`, `timer` bounding its wait for the scope's end. `http1` counted it
    /// open in its scope as its connect began, if it might speak HTTP/1.
    pub(super) fn new(
        io: T,
        scope: Option<ScopeRef>,
        http1: Option<Http1Open>,
        http2: bool,
        timer: Timer,
    ) -> (Self, oneshot::Receiver<Dropped<T>>) {
        let (dropped, dropped_rx) = oneshot::channel();
        let scoped = ScopedIo {
            id: next_id(),
            io: Some(io),
            scope,
            http1: http1.filter(|_| !http2),
            dropped: Some(dropped),
            http2,
            origin_ended: false,
            timer,
            scope_end_wait: None,
            drain: None,
            wrote: false,
            drain_turn: false,
            drained: false,
            shut: false,
            sending_body: Arc::default(),
            sending_bodies: Arc::default(),
            abort: Arc::default(),
            aborted: false,
            ended_first: Arc::default(),
        };
        (scoped, dropped_rx)
    }

    /// The flag its HTTP/1 connection keeps set while it has a request body still to send:
    /// draining, it holds more then, though it wrote nothing lately (see `poll_flush`).
    pub(super) fn sending_body(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.sending_body)
    }

    /// The request bodies its HTTP/2 connection still has to send, and whether those
    /// canceled or failing still send what their client sent ([`ScopeRef::finishes`]),
    /// draining then (see [`Self::draining`]).
    pub(super) fn sending_bodies(
        &self,
    ) -> (Arc<SendingBodies>, Arc<dyn Fn() -> bool + Send + Sync>) {
        let scope = self.scope.clone();
        (
            Arc::clone(&self.sending_bodies),
            Arc::new(move || scope.as_ref().is_some_and(ScopeRef::finishes)),
        )
    }

    /// The [`Abort`] of it.
    pub(super) fn abort(&self) -> Arc<Abort> {
        Arc::clone(&self.abort)
    }

    /// The [`EndedFirst`] of it.
    pub(super) fn ended_first(&self) -> Arc<EndedFirst> {
        Arc::clone(&self.ended_first)
    }

    /// `polled`, unless it waits once it was aborted (see [`Abort`]): it then fails, its
    /// task woken as it is aborted.
    fn unless_aborted<R>(
        &mut self,
        cx: &mut Context<'_>,
        polled: Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        if polled.is_ready() || self.scope.is_none() {
            return polled;
        }
        self.abort.task.register(cx.waker());
        if self.abort.aborted.load(Ordering::Acquire) {
            self.aborted = true;
            self.ended_first.scope();
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the connection outlived its scope's deadline",
            )));
        }
        Poll::Pending
    }

    fn io(&mut self) -> io::Result<Pin<&mut T>> {
        // One whose scope ended as `draining` found it hadn't still goes on, as it would
        // have just before, until `draining` sees the end.
        if self.scope.as_ref().is_some_and(|scope| {
            scope.end() != ConnectionEnd::Graceful
                && (self.drained || self.drain.is_some() || !scope.drains())
        }) {
            self.ended_first.scope();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the connection's scope ended it",
            ));
        }
        Ok(Pin::new(self.io.as_mut().expect("taken only once dropped")))
    }

    /// Whether it still writes what it holds, reading nothing until it holds nothing more (see
    /// `poll_flush`): one does once its scope drains ([`ScopeRef::drains`]), up to
    /// [`SCOPED_CLOSE_TIMEOUT`](super::SCOPED_CLOSE_TIMEOUT) or its scope's deadline (see
    /// [`drain_bound`]), so that its origin gets what the client sent before it ended, as it
    /// would directly; an HTTP/2 one only while it has request bodies to send then, which
    /// still send what their client sent, reading on for the WINDOW_UPDATEs they wait for.
    fn draining(&mut self, cx: &mut Context<'_>) -> bool {
        if self.drained || !self.scope.as_ref().is_some_and(ScopeRef::drains) {
            return false;
        }
        if self.http2
            && self.drain.is_none()
            && !(self.scope.as_ref().is_some_and(ScopeRef::finishes)
                && self.sending_bodies.poll_any(cx))
        {
            self.drained = true;
            return false;
        }
        let deadline = self.scope.as_ref().and_then(ScopeRef::drain_deadline);
        let timer = &self.timer;
        let drain = self
            .drain
            .get_or_insert_with(|| drain_bound(timer, deadline));
        drain.as_mut().poll(cx).is_pending()
    }

    /// Its transport to write to (see [`Self::io`] and [`Self::draining`]), none once an
    /// HTTP/1 one drained: an HTTP/2 one closes itself then, reading nothing more.
    fn writer(&mut self, cx: &mut Context<'_>) -> io::Result<Pin<&mut T>> {
        if self.draining(cx) {
            return Ok(Pin::new(self.io.as_mut().expect("taken only once dropped")));
        }
        if self.drained && !self.http2 {
            self.ended_first.scope();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the connection's scope ended it",
            ));
        }
        self.io()
    }

    /// Notes a read (`read`, which filled nothing when `empty`) ending the origin's side, and
    /// how (see [`OriginEnd`]), telling its scope at once.
    fn note_read(&mut self, read: &Poll<io::Result<()>>, empty: bool) {
        let Poll::Ready(read) = read else {
            return;
        };
        match read {
            Ok(()) if empty => {}
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
            // An HTTP/1 one's origin ended its side on any failed read: a TLS close without
            // its close_notify, or its fatal alert, say.
            Err(_) if !self.http2 => {}
            _ => return,
        }
        let io = self.io.as_ref();
        let end = OriginEnd::of_read(read, || io.is_some_and(Connection::close_notify_received));
        self.note_end(end);
    }

    /// Notes a write (`written`) failing with the origin's reset, which ended its side so
    /// before any read did: as `ConnectionReset`, or as `BrokenPipe` where the kernel fails
    /// writes to a reset connection so (macOS).
    fn note_write<R>(&mut self, written: &Poll<io::Result<R>>) {
        if let Poll::Ready(Err(e)) = written
            && matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            )
        {
            self.note_end(OriginEnd::Reset);
        }
    }

    /// Notes how the origin ended its side (`end`), telling its scope at once.
    fn note_end(&mut self, end: OriginEnd) {
        if std::mem::replace(&mut self.origin_ended, true) {
            return;
        }
        self.ended_first.set(EndedFirst::ORIGIN);
        if let (true, Some(scope)) = (self.http2, &self.scope) {
            scope.origin_closed(end == OriginEnd::CloseNotify, end == OriginEnd::Reset);
        }
        if let Some(http1) = &mut self.http1 {
            http1.ended(end);
        }
    }
}

impl<T: AsyncRead + Connection + Unpin> ScopedIo<T> {
    /// Waits for the scope's end, up to [`SCOPE_END_WAIT`], reading what the origin still
    /// sends to learn how it closes. Whether the scope ended.
    fn poll_scope_end(&mut self, cx: &mut Context<'_>, scope: &ScopeRef) -> Poll<bool> {
        loop {
            if scope.wake_on_end(self.id, cx.waker()).is_some() {
                return Poll::Ready(true);
            }
            if self.origin_ended {
                break;
            }
            let mut unread = [0; 4096];
            let mut buf = ReadBuf::new(&mut unread);
            let read = match self.io() {
                Ok(io) => io.poll_read(cx, &mut buf),
                Err(_) => return Poll::Ready(true),
            };
            if read.is_pending() {
                break;
            }
            self.note_read(&read, buf.filled().is_empty());
            if matches!(read, Poll::Ready(Err(_))) {
                self.origin_ended = true;
            }
        }
        let timer = &self.timer;
        let wait = self
            .scope_end_wait
            .get_or_insert_with(|| timer.sleep(SCOPE_END_WAIT));
        wait.as_mut().poll(cx).map(|()| false)
    }
}

impl<T: Connection + Unpin> Drop for ScopedIo<T> {
    fn drop(&mut self) {
        if let Some(scope) = &self.scope {
            scope.forget(self.id);
        }
        let Some(io) = self.io.take() else {
            return;
        };
        let alert = match self.scope.as_ref().map(ScopeRef::end) {
            // Aborted waiting, it couldn't close in time.
            Some(end) if end == ConnectionEnd::Reset || self.aborted => {
                let linger = io
                    .socket()
                    .map(|socket| socket.set_linger(Some(Duration::ZERO)));
                match linger {
                    Some(Ok(())) => {}
                    Some(Err(_e)) => debug!("resetting a scoped connection failed: {}", _e),
                    None => {
                        debug!("a scoped connection over no TCP socket closes rather than resets")
                    }
                }
                None
            }
            // Unless its origin ended its side already.
            Some(ConnectionEnd::Alert(alert)) if !self.origin_ended => Some(alert),
            _ => None,
        };
        let origin_to_end = !self.origin_ended
            && self.scope.as_ref().is_some_and(|scope| {
                scope.ends_with_http1_origin() && scope.end() == ConnectionEnd::Graceful
            });
        let http1 = self.http1.take_if(|_| origin_to_end);
        let Some(dropped) = self.dropped.take() else {
            return;
        };
        // Refused when nothing waits to close it, so it just closes, its alert sent as far as
        // its socket has room: dropped, it can't wait for more.
        if let Err((mut io, _, Some(alert), _)) = dropped.send((io, http1, alert, self.shut)) {
            let mut cx = Context::from_waker(Waker::noop());
            match Pin::new(&mut io).poll_send_fatal_alert(&mut cx, alert) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_e)) => debug!("alerting a scoped connection failed: {}", _e),
                Poll::Pending => debug!("a scoped connection had no room for its alert"),
            }
        }
    }
}

impl<T: AsyncRead + Connection + Unpin> AsyncRead for ScopedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Its scope closed: it reads nothing more, its connection ending as at the origin's
        // close, without a frame more, unless it drains. Seen first, as its scope ended before.
        // An HTTP/1 one, idle or awaiting its response, is woken at its scope's end too, to
        // drain (see `poll_flush`) at once rather than at its next read.
        let closed = self.scope.as_ref().is_some_and(|scope| {
            if !self.http2 {
                scope.wake_on_end(self.id, cx.waker());
            }
            scope.poll_closed(self.id, cx.waker())
        });
        if self.draining(cx) {
            if !self.http2 {
                return Poll::Pending;
            }
            let filled = buf.filled().len();
            let read =
                Pin::new(self.io.as_mut().expect("taken only once dropped")).poll_read(cx, buf);
            let empty = buf.filled().len() == filled && buf.remaining() > 0;
            self.note_read(&read, empty);
            return self.unless_aborted(cx, read);
        }
        if closed {
            self.ended_first.scope();
            return Poll::Ready(Ok(()));
        }
        let filled = buf.filled().len();
        let read = self.io()?.poll_read(cx, buf);
        let empty = buf.filled().len() == filled && buf.remaining() > 0;
        self.note_read(&read, empty);
        self.unless_aborted(cx, read)
    }
}

impl<T: AsyncWrite + AsyncRead + Connection + Unpin> AsyncWrite for ScopedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.wrote = true;
        let written = self.writer(cx)?.poll_write(cx, buf);
        self.note_write(&written);
        self.unless_aborted(cx, written)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.wrote = true;
        let written = self.writer(cx)?.poll_write_vectored(cx, bufs);
        self.note_write(&written);
        self.unless_aborted(cx, written)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.as_ref().is_some_and(T::is_write_vectored)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Draining, one not written to since it was last flushed, even given a turn, holds
        // nothing more, unless its connection has a request body still to send (paced, say):
        // the body's end, or the drain's bound, ends it then.
        if self.draining(cx) {
            let sending = self.sending_bodies.poll_any(cx);
            if std::mem::take(&mut self.wrote)
                || self.sending_body.load(Ordering::Acquire)
                || sending
            {
                self.drain_turn = false;
                // An HTTP/2 one is polled again only as it has more to write: its request
                // bodies sent, it gets a turn, as does an HTTP/1 one sending no body, which
                // its response, unread, won't wake.
                if !sending && (self.http2 || !self.sending_body.load(Ordering::Acquire)) {
                    cx.waker().wake_by_ref();
                }
            } else if !std::mem::replace(&mut self.drain_turn, true) {
                cx.waker().wake_by_ref();
                return self.unless_aborted(cx, Poll::Pending);
            } else {
                self.drained = true;
                if self.http2 {
                    cx.waker().wake_by_ref();
                }
            }
        }
        let flushed = self.writer(cx)?.poll_flush(cx);
        self.note_write(&flushed);
        self.unless_aborted(cx, flushed)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // An HTTP/1 one relaying its client's half-close (see `ReadClosed`) before its scope
        // ends still flushes, reading its response on.
        if self.http2 || self.scope.as_ref().is_some_and(ScopeRef::drains) {
            self.drained = true;
        }
        if let (true, Some(scope)) = (self.http2, self.scope.clone()) {
            let ended = self.poll_scope_end(cx, &scope).map(Ok);
            let ended = std::task::ready!(self.unless_aborted(cx, ended))?;
            if !ended && self.origin_ended {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the origin closed the connection before its scope ended",
                )));
            }
        } else if self
            .scope
            .as_ref()
            .is_some_and(ScopeRef::half_closes_with_fin)
        {
            let mut io = self.io()?;
            std::task::ready!(io.as_mut().poll_flush(cx))?;
            if let Some(socket) = io.socket() {
                let shut = socket.shutdown(std::net::Shutdown::Write);
                self.shut = shut.is_ok();
                return Poll::Ready(shut);
            }
        }
        let shut = self.io()?.poll_shutdown(cx);
        let shut = std::task::ready!(self.unless_aborted(cx, shut));
        self.shut = shut.is_ok();
        Poll::Ready(shut)
    }
}
