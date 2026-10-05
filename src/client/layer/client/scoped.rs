//! The transport of a connection confined to a [`ConnectionScope`](crate::ConnectionScope),
//! which ends as the scope says (see [`ConnectionEnd`]).

use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
};
use wreq_proto::rt::{Sleep, Timer as _};

use crate::{
    conn::Connection,
    group::{ConnectionEnd, Http1Open, OriginEnd, ScopeRef},
    rt::Timer,
};

/// How long an HTTP/2 connection closing before its scope ended waits for it (see
/// [`ConnectionScope::end_with`](crate::ConnectionScope::end_with)).
const SCOPE_END_WAIT: Duration = Duration::from_secs(2);

/// A connection's transport. Once its scope ends with [`ConnectionEnd::Fin`] or
/// [`ConnectionEnd::Reset`] every read and write of it fails, so the connection sends
/// nothing more, and it closes so once dropped; once its scope is closed it reads nothing
/// more. Dropped, it goes to the receiver [`ScopedIo::new`] returned, if that is still there.
///
/// An HTTP/1 one is counted open in its scope from its connect on (see
/// [`ConnectionScope::http1_origin_closed`](crate::ConnectionScope::http1_origin_closed)).
/// Dropped before its origin ended it, in a scope ending with its HTTP/1 origin that hasn't
/// ended otherwise, it goes to that receiver still counted open, to learn how its origin
/// ends it.
/// An HTTP/2 one tells its scope how its origin closed it, and closes as its scope ends,
/// waiting up to [`SCOPE_END_WAIT`] for that, as the origin's close ends the scope's
/// client soon after; past it, after its origin's close, it closes with a FIN alone.
pub(super) struct ScopedIo<T: Connection> {
    /// Its id among its scope's connections waiting for its end or close.
    id: u64,
    io: Option<T>,
    scope: Option<ScopeRef>,
    http1: Option<Http1Open>,
    dropped: Option<oneshot::Sender<(T, Option<Http1Open>)>>,
    http2: bool,
    /// Whether its origin ended its side: a read ended, or failed.
    origin_ended: bool,
    timer: Timer,
    /// Bounds its wait for its scope's end, once it started.
    scope_end_wait: Option<Pin<Box<dyn Sleep>>>,
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
    ) -> (Self, oneshot::Receiver<(T, Option<Http1Open>)>) {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let (dropped, dropped_rx) = oneshot::channel();
        let scoped = ScopedIo {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            io: Some(io),
            scope,
            http1: http1.filter(|_| !http2),
            dropped: Some(dropped),
            http2,
            origin_ended: false,
            timer,
            scope_end_wait: None,
        };
        (scoped, dropped_rx)
    }

    fn io(&mut self) -> io::Result<Pin<&mut T>> {
        if self
            .scope
            .as_ref()
            .is_some_and(|scope| scope.end() != ConnectionEnd::Graceful)
        {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the connection's scope ended it",
            ));
        }
        Ok(Pin::new(self.io.as_mut().expect("taken only once dropped")))
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
        if std::mem::replace(&mut self.origin_ended, true) {
            return;
        }
        let io = self.io.as_ref();
        let end = OriginEnd::of_read(read, || io.is_some_and(Connection::close_notify_received));
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

impl<T: Connection> Drop for ScopedIo<T> {
    fn drop(&mut self) {
        if let Some(scope) = &self.scope {
            scope.forget(self.id);
        }
        let Some(io) = self.io.take() else {
            return;
        };
        if self
            .scope
            .as_ref()
            .is_some_and(|scope| scope.end() == ConnectionEnd::Reset)
        {
            let linger = io
                .socket()
                .map(|socket| socket.set_linger(Some(Duration::ZERO)));
            match linger {
                Some(Ok(())) => {}
                Some(Err(_e)) => debug!("resetting a scoped connection failed: {}", _e),
                None => debug!("a scoped connection over no TCP socket closes rather than resets"),
            }
        }
        let origin_to_end = !self.origin_ended
            && self.scope.as_ref().is_some_and(|scope| {
                scope.ends_with_http1_origin() && scope.end() == ConnectionEnd::Graceful
            });
        let http1 = self.http1.take_if(|_| origin_to_end);
        if let Some(dropped) = self.dropped.take() {
            // Refused when nothing waits to close it, so it just closes.
            let _ = dropped.send((io, http1));
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
        // close, without a frame more.
        if self
            .scope
            .as_ref()
            .is_some_and(|scope| scope.poll_closed(self.id, cx.waker()))
        {
            return Poll::Ready(Ok(()));
        }
        let filled = buf.filled().len();
        let read = self.io()?.poll_read(cx, buf);
        let empty = buf.filled().len() == filled && buf.remaining() > 0;
        self.note_read(&read, empty);
        read
    }
}

impl<T: AsyncWrite + AsyncRead + Connection + Unpin> AsyncWrite for ScopedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.io()?.poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.io()?.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.as_ref().is_some_and(T::is_write_vectored)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.io()?.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let (true, Some(scope)) = (self.http2, self.scope.clone()) {
            let ended = std::task::ready!(self.poll_scope_end(cx, &scope));
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
                return Poll::Ready(socket.shutdown(std::net::Shutdown::Write));
            }
        }
        self.io()?.poll_shutdown(cx)
    }
}
