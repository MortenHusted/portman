//! IPC server: listens on the Unix socket, handles one request per
//! connection, writes the response, closes.

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use portman_core::paths::socket_path;
use portman_protocol::transport::{read_request, write_response};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

use crate::handlers;
use crate::DaemonState;

/// A client that connects and then says nothing gets this long before the
/// connection is dropped — an idle open socket must not park a task forever.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn run(state: DaemonState) -> Result<()> {
    let path = socket_path()?;
    ensure_parent_dir(&path)?;
    remove_stale_socket(&path)?;

    let listener =
        UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;

    // This socket drives a root daemon (SyncServices spawns processes,
    // SetSecretsCredentials writes the credential store) — it must not be a
    // free local-privilege step. The socket lives in the login user's own
    // Application Support dir, so that directory's owner IS the one user
    // allowed to talk to us (besides root). Group + mode narrow who can
    // connect; the peer-uid check below is the actual gate, since on macOS
    // `staff` spans every local user.
    let owner_uid = fs::metadata(path.parent().context("socket has no parent")?)
        .map(|m| m.uid())
        .context("stat socket dir")?;
    let owner_gid = fs::metadata(path.parent().context("socket has no parent")?)
        .map(|m| m.gid())
        .context("stat socket dir")?;
    let _ = std::os::unix::fs::chown(&path, None, Some(owner_gid));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660))
        .with_context(|| format!("chmod 0660 {}", path.display()))?;
    info!(socket = %path.display(), owner_uid, "ipc server listening");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_client(stream, state, owner_uid).await {
                        warn!(error = %err, "ipc client error");
                    }
                });
            }
            Err(err) => {
                error!(error = %err, "ipc accept failed");
            }
        }
    }
}

async fn handle_client(mut stream: UnixStream, state: DaemonState, owner_uid: u32) -> Result<()> {
    let cred = stream.peer_cred().context("reading peer credentials")?;
    if cred.uid() != 0 && cred.uid() != owner_uid {
        anyhow::bail!(
            "rejecting ipc connection from uid {} (socket owner is {owner_uid})",
            cred.uid()
        );
    }
    let request = tokio::time::timeout(READ_TIMEOUT, read_request(&mut stream))
        .await
        .context("ipc read timed out")??;
    let request = match authenticate_control(
        request,
        state.supervisor.managed_broker(),
        state.dashboard_token.as_deref(),
    ) {
        Ok(request) => request,
        Err(message) => {
            write_response(
                &mut stream,
                &portman_protocol::Response::Err {
                    message: message.into(),
                },
            )
            .await?;
            return Ok(());
        }
    };
    debug!(?request, "ipc request");
    let response = handlers::dispatch(request, &state).await;
    write_response(&mut stream, &response).await?;
    Ok(())
}

fn authenticate_control(
    request: portman_protocol::Request,
    managed: bool,
    token: Option<&str>,
) -> std::result::Result<portman_protocol::Request, &'static str> {
    use portman_protocol::Request;
    use subtle::ConstantTimeEq;
    match request {
        Request::Authenticated {
            token: supplied,
            request,
        } if token.is_some_and(|expected| {
            !expected.is_empty() && bool::from(expected.as_bytes().ct_eq(supplied.0.as_bytes()))
        }) =>
        {
            Ok(*request)
        }
        Request::Authenticated { .. } => Err("control authentication denied"),
        _ if managed => Err("managed broker requires authenticated control envelope"),
        request => Ok(request),
    }
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    Ok(())
}

fn remove_stale_socket(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    };
    if !metadata.file_type().is_socket() {
        anyhow::bail!(
            "refusing to remove non-socket file at {} during IPC startup",
            path.display()
        );
    }
    fs::remove_file(path)
        .with_context(|| format!("removing stale socket at {}", path.display()))?;
    warn!(socket = %path.display(), "removed stale socket file");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("portman-ipc-{name}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn remove_stale_socket_refuses_regular_file() {
        let path = unique_path("regular-file");
        std::fs::write(&path, "not a socket").unwrap();

        let err = remove_stale_socket(&path).unwrap_err();

        assert!(err.to_string().contains("refusing to remove non-socket"));
        assert!(path.exists());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn remove_stale_socket_removes_unix_socket() {
        let path = unique_path("socket");
        let listener = StdUnixListener::bind(&path).unwrap();
        drop(listener);

        remove_stale_socket(&path).unwrap();

        assert!(!path.exists());
    }
    #[test]
    fn managed_control_requires_separate_admin_token() {
        use portman_protocol::{Redacted, Request};
        let envelope = |token: &str| Request::Authenticated {
            token: Redacted(token.into()),
            request: Box::new(Request::Status),
        };
        assert!(authenticate_control(Request::Status, true, Some("host-admin")).is_err());
        assert!(
            authenticate_control(envelope("workspace-token"), true, Some("host-admin")).is_err()
        );
        assert!(authenticate_control(envelope("host-admin"), true, None).is_err());
        assert!(matches!(
            authenticate_control(envelope("host-admin"), true, Some("host-admin")),
            Ok(Request::Status)
        ));
        assert!(matches!(
            authenticate_control(Request::Status, false, None),
            Ok(Request::Status)
        ));
        assert!(!format!("{:?}", envelope("secret-admin-value")).contains("secret-admin-value"));
    }
}
