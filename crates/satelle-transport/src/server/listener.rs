use axum::serve::Listener;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(super) struct LimitedTcpListener {
    inner: TcpListener,
    permits: Arc<Semaphore>,
}

impl LimitedTcpListener {
    pub(super) fn new(inner: TcpListener, max_connections: usize) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(max_connections)),
        }
    }
}

impl Listener for LimitedTcpListener {
    type Io = PermitIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let permit = Arc::clone(&self.permits)
                .acquire_owned()
                .await
                .expect("the connection semaphore is never closed");
            match self.inner.accept().await {
                Ok((stream, address)) => {
                    let _ = stream.set_nodelay(true);
                    return (
                        PermitIo {
                            stream,
                            _permit: permit,
                        },
                        address,
                    );
                }
                Err(_) => {
                    drop(permit);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

pub(super) struct PermitIo {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for PermitIo {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for PermitIo {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}
