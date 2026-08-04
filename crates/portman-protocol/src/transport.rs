//! Length-prefixed JSON framing over the daemon's Unix socket.
//!
//! Each message is a 4-byte big-endian length followed by exactly that many
//! bytes of UTF-8 JSON. No trailing newline. The daemon reads one `Request`
//! per connection, writes one `Response`, and closes the socket.
//!
//! Gated behind the `transport` feature so pure-type consumers of this crate
//! don't pull in tokio.

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Request, Response};

/// Maximum size of a single framed message, in bytes. Anything larger is
/// treated as a protocol error — prevents a bad peer from making us allocate
/// GB of memory before failing.
pub const MAX_FRAME_BYTES: u32 = 1 << 20; // 1 MiB

/// Write one framed message.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: serde::Serialize,
{
    let bytes = serde_json::to_vec(value).context("serializing frame")?;
    let len = u32::try_from(bytes.len()).map_err(|_| anyhow!("frame too large"))?;
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("frame too large: {len} > {MAX_FRAME_BYTES} bytes");
    }
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one framed message.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncReadExt + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("reading frame length")?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("frame too large: {len} > {MAX_FRAME_BYTES} bytes");
    }
    let mut body = vec![0u8; len as usize];
    reader
        .read_exact(&mut body)
        .await
        .context("reading frame body")?;
    serde_json::from_slice(&body).context("deserializing frame")
}

/// Convenience: read one `Request`.
pub async fn read_request<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Request> {
    read_frame(r).await
}

/// Convenience: write one `Response`.
pub async fn write_response<W: AsyncWriteExt + Unpin>(w: &mut W, resp: &Response) -> Result<()> {
    write_frame(w, resp).await
}

/// Convenience: write one `Request`.
pub async fn write_request<W: AsyncWriteExt + Unpin>(w: &mut W, req: &Request) -> Result<()> {
    write_frame(w, req).await
}

/// Convenience: read one `Response`.
pub async fn read_response<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Response> {
    read_frame(r).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Entry, Mode, Source};
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_response() {
        let (mut a, mut b) = duplex(64 * 1024);
        let resp = Response::Entries {
            entries: vec![Entry {
                host: "foo.test".into(),
                target: "10.0.0.1:80".into(),
                source: Source::Container,
                mode: Mode::Http,
                container_id: Some("abc123".into()),
            }],
        };
        write_response(&mut a, &resp).await.unwrap();
        let got: Response = read_frame(&mut b).await.unwrap();
        assert!(matches!(got, Response::Entries { entries } if entries.len() == 1));
    }

    #[tokio::test]
    async fn roundtrip_request() {
        let (mut a, mut b) = duplex(64 * 1024);
        let req = Request::ListEntries;
        write_request(&mut a, &req).await.unwrap();
        let got: Request = read_frame(&mut b).await.unwrap();
        assert!(matches!(got, Request::ListEntries));
    }
}
