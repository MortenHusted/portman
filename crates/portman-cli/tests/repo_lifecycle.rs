//! `portman up` / `portman down` against a stand-in daemon. The binary runs
//! with a cleared environment and a temp HOME (and XDG_DATA_HOME), so its
//! socket resolves inside the temp dir and no request can reach a real
//! daemon. The stand-in records every request and answers lifecycle requests
//! from a fixed service table.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Mutex};

use portman_protocol::transport::{read_request, write_response};
use portman_protocol::{Request, Response, ServiceStatusInfo};
use tokio::net::UnixListener;

struct Sandbox {
    home: tempfile::TempDir,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl Sandbox {
    fn start(services: Vec<ServiceStatusInfo>) -> Self {
        // Under /tmp: macOS caps socket paths at 104 bytes, and $TMPDIR plus
        // `Library/Application Support/portman/portman.sock` overruns it.
        let home = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
        let socket = if cfg!(target_os = "macos") {
            home.path()
                .join("Library/Application Support/portman/portman.sock")
        } else {
            home.path().join("data/portman/portman.sock")
        };
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await.unwrap();
                let response = match request {
                    Request::SyncServices { .. } => Response::SyncReport {
                        added: Vec::new(),
                        updated: Vec::new(),
                        removed: Vec::new(),
                        unchanged: Vec::new(),
                    },
                    _ => Response::ServiceStatuses {
                        services: services.clone(),
                    },
                };
                recorded.lock().unwrap().push(request);
                write_response(&mut stream, &response).await.unwrap();
            }
        });
        Self { home, requests }
    }

    /// A config root under the sandbox, as the CLI will see it from inside:
    /// canonical, because the binary resolves its cwd (`/tmp` is a symlink
    /// on macOS).
    fn repo(&self, name: &str, config: &str) -> PathBuf {
        let root = self.home.path().join(name);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("portman.toml"), config).unwrap();
        root.canonicalize().unwrap()
    }

    async fn portman(&self, cwd: &Path, args: &[&str]) -> Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_portman"))
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("HOME", self.home.path())
            .env("XDG_DATA_HOME", self.home.path().join("data"))
            .output()
            .await
            .unwrap()
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn egress_only_up_syncs_without_starting_services() {
    let sandbox = Sandbox::start(Vec::new());
    let repo = sandbox.repo(
        "api",
        r#"
        [secrets.gh]
        provider = "local"
        keys = ["TOKEN"]

        [egress.github]
        host = "github.api.test"
        target = "api.github.com:443"
        secrets = "gh"
        key = "TOKEN"
        tls = true
        "#,
    );

    let output = sandbox.portman(&repo, &["up"]).await;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The daemon reads an empty `ServiceUp` as "every known service", so
    // the sync must be the only request.
    let requests = sandbox.requests();
    assert!(
        matches!(
            requests.as_slice(),
            [Request::SyncServices { services, egress, .. }]
                if services.is_empty() && egress.contains_key("github")
        ),
        "{requests:?}"
    );
}
