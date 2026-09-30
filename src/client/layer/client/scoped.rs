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

use crate::{
    conn::Connection,
    group::{ConnectionEnd, ScopeRef},
};

/// A connection's transport. Once its scope ends with [`ConnectionEnd::Fin`] or
/// [`ConnectionEnd::Reset`] every read and write of it fails, so the connection sends
/// nothing more, and it closes so once dropped. Dropped, it goes to the receiver
/// [`ScopedIo::new`] returned, if that is still there.
pub(super) struct ScopedIo<T: Connection> {
    io: Option<T>,
    scope: Option<ScopeRef>,
    dropped: Option<oneshot::Sender<T>>,
}

impl<T: Connection + Unpin> ScopedIo<T> {
    /// Wraps `io`, the transport of a connection confined to `scope`, if any.
    pub(super) fn new(io: T, scope: Option<ScopeRef>) -> (Self, oneshot::Receiver<T>) {
        let (dropped, dropped_rx) = oneshot::channel();
        let scoped = ScopedIo {
            io: Some(io),
            scope,
            dropped: Some(dropped),
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
}

impl<T: Connection> Drop for ScopedIo<T> {
    fn drop(&mut self) {
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
        self.io()?.poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Connection + Unpin> AsyncWrite for ScopedIo<T> {
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
        self.io()?.poll_shutdown(cx)
    }
}
