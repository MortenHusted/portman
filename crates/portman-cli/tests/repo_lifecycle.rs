//! `portman up` / `portman down` against a stand-in daemon. The binary runs
//! with a cleared environment and a temp HOME (and XDG_DATA_HOME), so its
//! socket resolves inside the temp dir and no request can reach a real
//! daemon. The stand-in records every request and answers lifecycle requests
//! from a fixed service table.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Mutex};

use portman_protocol::transport::{read_request, write_response};
use portman_protocol::{Request, Response, ServiceState, ServiceStatusInfo};
use tokio::net::UnixListener;

struct Sandbox {
    home: tempfile::TempDir,
    requests: Arc<Mutex<Vec<Request>>>,
    services: Arc<Mutex<Vec<ServiceStatusInfo>>>,
}

impl Sandbox {
    fn start() -> Self {
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
        let services = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let reported = services.clone();
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
                        services: reported.lock().unwrap().clone(),
                    },
                };
                recorded.lock().unwrap().push(request);
                write_response(&mut stream, &response).await.unwrap();
            }
        });
        Self {
            home,
            requests,
            services,
        }
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

    /// The service table the stand-in reports from now on.
    fn report(&self, services: Vec<ServiceStatusInfo>) {
        *self.services.lock().unwrap() = services;
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

fn running(name: &str, root: &Path) -> ServiceStatusInfo {
    ServiceStatusInfo {
        name: name.into(),
        root: Some(root.to_path_buf()),
        repo: None,
        config_missing: false,
        state: ServiceState::Ready,
        detail: String::new(),
        pid: Some(4242),
        restarts: 0,
        host: None,
        port: None,
        desired_up: true,
        groups: Vec::new(),
        project: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn egress_only_up_syncs_without_starting_services() {
    let sandbox = Sandbox::start();
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

/// Service names are global: when `demo` already owns `web`, `acme`'s `up`
/// is refused, and `acme`'s `down` must leave `demo`'s `web` running.
#[tokio::test(flavor = "multi_thread")]
async fn down_stops_only_services_this_root_owns() {
    let sandbox = Sandbox::start();
    let demo = sandbox.repo("demo", "[service.web]\nrun = \"serve\"\n");
    let acme = sandbox.repo(
        "acme",
        "[service.web]\nrun = \"serve\"\n\n[service.jobs]\nrun = \"work\"\n",
    );
    sandbox.report(vec![running("web", &demo), running("jobs", &acme)]);

    let output = sandbox.portman(&acme, &["down"]).await;

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let requests = sandbox.requests();
    assert!(
        matches!(
            requests.as_slice(),
            [Request::ServiceStatus, Request::ServiceDown { names }] if names == &["jobs"]
        ),
        "{requests:?}"
    );
    assert!(
        stderr.contains("`web`") && stderr.contains(&demo.display().to_string()),
        "{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn down_sends_no_stop_when_this_root_owns_nothing() {
    let sandbox = Sandbox::start();
    let demo = sandbox.repo("demo", "[service.web]\nrun = \"serve\"\n");
    let acme = sandbox.repo("acme", "[service.web]\nrun = \"serve\"\n");
    sandbox.report(vec![running("web", &demo)]);

    let output = sandbox.portman(&acme, &["down"]).await;

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let requests = sandbox.requests();
    assert!(
        matches!(requests.as_slice(), [Request::ServiceStatus]),
        "{requests:?}"
    );
    assert!(stderr.contains(&demo.display().to_string()), "{stderr}");
}
