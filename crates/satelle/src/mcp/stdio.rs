use std::fmt;
use std::io::{self, BufRead};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub(super) const MAX_INPUT_BYTES: usize = 1_048_576;
const FORWARD_BUFFER_BYTES: usize = 64 * 1024;

pub(super) struct BoundedStdio {
    pub(super) reader: DuplexStream,
    pub(super) writer: GuardedStdout,
    framer: JoinHandle<Result<(), FramingError>>,
}

impl BoundedStdio {
    pub(super) fn start() -> Self {
        let (forward_writer, reader) = tokio::io::duplex(FORWARD_BUFFER_BYTES);
        let halted = Arc::new(AtomicBool::new(false));
        let input_halted = halted.clone();
        let framer_halted = halted.clone();
        let (frames, pending_frames) = mpsc::channel(1);
        // A standard input read cannot be cancelled portably. Keep it on a
        // detached OS thread so an RMCP shutdown can abort the async forwarder
        // and let the process exit even when the client leaves stdin open.
        std::thread::spawn(move || {
            if let Err(error) = read_input(&frames) {
                input_halted.store(true, Ordering::Release);
                let _ = frames.blocking_send(Err(error));
            }
        });
        let framer = tokio::spawn(async move {
            let result = forward_frames(forward_writer, pending_frames).await;
            if result.is_err() {
                framer_halted.store(true, Ordering::Release);
            }
            result
        });
        Self {
            reader,
            writer: GuardedStdout {
                inner: tokio::io::stdout(),
                halted,
            },
            framer,
        }
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        DuplexStream,
        GuardedStdout,
        JoinHandle<Result<(), FramingError>>,
    ) {
        (self.reader, self.writer, self.framer)
    }
}

pub(super) struct GuardedStdout {
    inner: tokio::io::Stdout,
    halted: Arc<AtomicBool>,
}

impl AsyncWrite for GuardedStdout {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.halted.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MCP stdout closed after framing failure",
            )));
        }
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

pub(super) async fn stop_framer(
    framer: JoinHandle<Result<(), FramingError>>,
) -> Result<(), FramingError> {
    if !framer.is_finished() {
        framer.abort();
    }
    match framer.await {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(FramingError::Task {
            message: error.to_string(),
        }),
    }
}

#[derive(Debug)]
pub(super) enum FramingError {
    Input { message: String },
    Oversized,
    Forward { message: String },
    Task { message: String },
}

impl fmt::Display for FramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input { message } => write!(formatter, "could not read MCP stdin: {message}"),
            Self::Oversized => write!(
                formatter,
                "MCP input message exceeded the {MAX_INPUT_BYTES}-byte limit before newline"
            ),
            Self::Forward { message } => {
                write!(formatter, "could not forward bounded MCP input: {message}")
            }
            Self::Task { message } => write!(formatter, "MCP input framer failed: {message}"),
        }
    }
}

fn read_input(frames: &mpsc::Sender<Result<Vec<u8>, FramingError>>) -> Result<(), FramingError> {
    let stdin = io::stdin();
    let mut source = stdin.lock();
    let mut line = Vec::with_capacity(FORWARD_BUFFER_BYTES);

    loop {
        let available = source.fill_buf().map_err(|error| FramingError::Input {
            message: error.to_string(),
        })?;
        if available.is_empty() {
            return Ok(());
        }

        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            if line.len() + newline > MAX_INPUT_BYTES {
                return Err(FramingError::Oversized);
            }
            line.extend_from_slice(&available[..=newline]);
            source.consume(newline + 1);
            let frame = std::mem::replace(&mut line, Vec::with_capacity(FORWARD_BUFFER_BYTES));
            if frames.blocking_send(Ok(frame)).is_err() {
                return Ok(());
            }
            continue;
        }

        if line.len() + available.len() > MAX_INPUT_BYTES {
            return Err(FramingError::Oversized);
        }
        line.extend_from_slice(available);
        let consumed = available.len();
        source.consume(consumed);
    }
}

async fn forward_frames(
    mut destination: DuplexStream,
    mut frames: mpsc::Receiver<Result<Vec<u8>, FramingError>>,
) -> Result<(), FramingError> {
    while let Some(frame) = frames.recv().await {
        destination
            .write_all(&frame?)
            .await
            .map_err(|error| FramingError::Forward {
                message: error.to_string(),
            })?;
    }
    Ok(())
}
