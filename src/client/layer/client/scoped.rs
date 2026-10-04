//! The transport of a connection confined to a [`ConnectionScope`](crate::ConnectionScope),
//! which ends as the scope says (see [`ConnectionEnd`]).

use std::{
    io::{self, IoSlice},
    pin::Pin,
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
    group::{ConnectionEnd, ScopeRef},
    rt::Timer,
};

/// How long an HTTP/2 connection closing before its scope ended waits for it (see
/// [`ConnectionScope::end_with`](crate::ConnectionScope::end_with)).
const SCOPE_END_WAIT: Duration = Duration::from_secs(2);

/// A connection's transport. Once its scope ends with [`ConnectionEnd::Fin`] or
/// [`ConnectionEnd::Reset`] every read and write of it fails, so the connection sends
/// nothing more, and it closes so once dropped. Dropped, it goes to the receiver
/// [`ScopedIo::new`] returned, if that is still there.
///
/// An HTTP/1 one is counted open in its scope (see
/// [`ConnectionScope::http1_origin_closed`](crate::ConnectionScope::http1_origin_closed)).
/// An HTTP/2 one tells its scope how its origin closed it, and closes as its scope ends,
/// waiting up to [`SCOPE_END_WAIT`] for that, as the origin's close ends the scope's
/// client soon after; past it, after its origin's close, it closes with a FIN alone.
pub(super) struct ScopedIo<T: Connection> {
    io: Option<T>,
    scope: Option<ScopeRef>,
    dropped: Option<oneshot::Sender<T>>,
    http2: bool,
    /// Whether its origin ended its side: a read ended, or failed.
    origin_ended: bool,
    timer: Timer,
    /// Bounds its wait for its scope's end, once it started.
    scope_end_wait: Option<Pin<Box<dyn Sleep>>>,
}

impl<T: Connection + Unpin> ScopedIo<T> {
    /// Wraps `io`, the transport of a connection confined to `scope`, if any, speaking
    /// HTTP/2 when `http2`, `timer` bounding its wait for the scope's end.
    pub(super) fn new(
        io: T,
        scope: Option<ScopeRef>,
        http2: bool,
        timer: Timer,
    ) -> (Self, oneshot::Receiver<T>) {
        let (dropped, dropped_rx) = oneshot::channel();
        if let (false, Some(scope)) = (http2, &scope) {
            scope.http1_opened();
        }
        let scoped = ScopedIo {
            io: Some(io),
            scope,
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

    /// Notes a read (`read`, which filled nothing when `empty`) ending the origin's side,
    /// telling the scope of an HTTP/2 connection how: by a close, with or without its
    /// close_notify, or a reset.
    fn note_read(&mut self, read: &Poll<io::Result<()>>, empty: bool) {
        let reset = match read {
            Poll::Ready(Ok(())) if empty => false,
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset => true,
            // An HTTP/1 one's origin ended its side on any failed read: a TLS close without
            // its close_notify, say.
            Poll::Ready(Err(_)) if !self.http2 => false,
            _ => return,
        };
        if std::mem::replace(&mut self.origin_ended, true) {
            return;
        }
        if let (true, Some(scope)) = (self.http2, &self.scope) {
            let close_notify = !reset
                && self
                    .io
                    .as_ref()
                    .is_some_and(Connection::close_notify_received);
            scope.origin_closed(close_notify, reset);
        }
    }
}

impl<T: AsyncRead + Connection + Unpin> ScopedIo<T> {
    /// Waits for the scope's end, up to [`SCOPE_END_WAIT`], reading what the origin still
    /// sends to learn how it closes. Whether the scope ended.
    fn poll_scope_end(&mut self, cx: &mut Context<'_>, scope: &ScopeRef) -> Poll<bool> {
        loop {
            if scope.wake_on_end(cx.waker()).is_some() {
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
        if let (false, Some(scope)) = (self.http2, &self.scope) {
            scope.http1_closed(self.origin_ended);
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
        if let Some(dropped) = self.dropped.take() {
            // Refused when nothing waits to close it, so it just closes.
            let _ = dropped.send(io);
        }
    }
}

impl<T: AsyncRead + Connection + Unpin> AsyncRead for ScopedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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
        }
        self.io()?.poll_shutdown(cx)
    }
}
