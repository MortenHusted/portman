# Code Quality Remediation — TODO

Generated from a full-workspace review on 2026-08-03.

**Baseline at review time** (do not regress): `cargo clippy --workspace --all-targets` clean
(CI enforces `-D warnings` on Linux + macOS), `cargo fmt` clean, 251 tests passing, no
TODO/FIXME debt, `unsafe` confined to netbridge examples with explicit `allow`. Test quality
is strong in supervisor, registry, and service_config — preserve that bar when touching these.

Legend: 🔴 verified bug · 🟡 robustness/design · 🟢 structure/hygiene.
Line numbers reference the tree at review time (`0e4c1ef`).

> **Independently verified 2026-08-03 (session review, tree `cdc3a3a`):** every 🔴 in
> Group 1 confirmed against source, including the exact lines. Spot-checks of Groups
> 2–4 (2.1, 2.2, 3.1–3.7, 4.1) all confirmed; Group 5 facts (2004-line main.rs, 3×
> `display_netbridge_mode`, 2× `wait_for_bridge_state`) exact. One nuance: 4.1's "no
> merge tests assert either behavior" overstates — `local_overlay_patches_and_adds`
> pins omitted-field survival and `overlay_fields_win` pins scalar override; what's
> unpinned is whole-map replacement of `env`/`env_files`/`depends`, and whether that
> is the *wanted* semantics is a product decision, not a bug. 1.2 is a regression
> from this session's `b220e1c` and 1.4's window now also covers the watcher spawn.

---

## Group 1 — Verified bugs (do first; small, surgical, each one testable commit)

- [x] **🔴 1.1 Netbridge: authenticate before recording the peer endpoint** — `crates/portman-netbridge/src/runtime.rs:251`
  - **Why:** `spawn_rx` sets `*endpoint = Some(src)` for *every* received UDP packet, before
    `decapsulate` authenticates it. Combined with the `0.0.0.0` bind (:144), any LAN host can
    send garbage to the listen port and redirect all outbound tunnel frames — a silent bridge
    DoS that survives until the next genuine packet.
  - **Fix:** only record the endpoint after `decapsulate` returns
    `WriteToTunnelV4`/`WriteToNetwork` (i.e. authenticated). Optionally also consider binding
    to the host/colima interface instead of `0.0.0.0`.
  - **Test:** unit test that an unauthenticated datagram does not change the endpoint.

- [x] **🔴 1.2 Netbridge: remove utun names from `OWN_UTUNS` on shutdown** — `runtime.rs:174,876`
  - **Why:** `remember_own_utun` inserts at tunnel start; nothing ever removes. macOS recycles
    utun names — after portman shuts down, the kernel can hand `utun5` to a VPN, and route
    reconciliation (`is_own_utun`, :886) then classifies *their* route as ours and repoints it.
    This violates the repo's core safety rule ("never mutate resources we don't own").
  - **Fix:** `Runtime::shutdown` must remove its `utun_name` from the set. Stronger: verify
    interface identity (e.g. creation-time/generation) rather than trusting bare names.

- [x] **🔴 1.3 Supervisor: replace TOCTOU `expect` with a fallible lookup** — `crates/portman-daemon/src/supervisor.rs:599`
  - **Why:** `up()` does `slots.get_mut(name).expect("target validated above")`, but validation
    happened in `expand_targets` under an *earlier* lock hold. The IPC server spawns one task
    per connection with no request serialization, so a concurrent `SyncServices` that removes
    the service between the two locks makes this `expect` fire — **panicking the root daemon**.
    Every other slot lookup in the file already handles disappearance gracefully.
  - **Fix:** `match slots.get_mut(name) { Some(s) => …, None => continue }`.
  - **Test:** two-task race: `up(name)` while `sync` removes `name` — must not panic.

- [x] **🔴 1.4 Supervisor: make runner-spawn decision + task insert atomic in `up()`** — `supervisor.rs:596-625`
  - **Why:** "is a runner needed?" and `slot.task = Some(task)` happen in separate lock holds
    with `tokio::spawn` in between. Two concurrent `up()` calls (CLI, dashboard Start button,
    and the proxy-502 start path all reach `Runner::start → up()`) both observe `is_finished()`,
    both spawn — two supervisors for one service spawn two children fighting over the same port
    and double-register routes. `run_service` has no singleton guard (verified).
  - **Fix:** take the spawn decision and insert the handle under one lock hold
    (`tokio::spawn` is synchronous and cheap to call inside the critical section).
  - **Test:** concurrent `up()` for the same service → exactly one runner task / one child.

- [x] **🔴 1.5 Doctor: gate legacy-bridge guidance on actual state** — `crates/portman-cli/src/doctor.rs:226-237`
  - **Why:** `render_report` unconditionally prints "Portman did not stop it automatically" plus
    `sudo brew services stop …` / `launchctl bootout …` instructions even on a clean machine
    where no legacy bridge exists and the replacement is `ready`. Users get alarming, wrong
    instructions. Existing tests only cover the legacy-running case.
  - **Fix:** gate those lines on `matches!(report.legacy_bridge, Running{..})`; only print the
    mode/enable hint when `replacement_state` isn't `ready`.
  - **Test:** a fully-ready report asserts no "stop the legacy bridge" text appears.

- [x] **🔴 1.6 IPC hardening: read timeout + peer identity** — `crates/portman-daemon/src/ipc_server.rs:23`, `crates/portman-core/src/ipc.rs:185`
  - **Why:** the socket is `chmod 0o666` and `read_frame` waits forever — any local user can
    drive the root daemon (`SyncServices` spawns processes, `SetSecretsCredentials` writes
    credentials) or park worker threads with a length prefix and no body. Single-user dev box
    mitigates, but this is a root daemon; both are cheap to fix.
  - **Fix:** wrap `read_request` in `tokio::time::timeout` (e.g. 5 s idle → drop connection);
    check peer uid via `getpeereid`, or tighten to `0o660` + group.

## Group 2 — Data safety in file-backed stores

- [x] **🟡 2.1 Mutate-after-persist in stores** — `crates/portman-core/src/static_store.rs:115-119,146-148`, `tls_store.rs:95-99`
  - **Why:** `add`/`remove`/`set_mode` mutate locked in-memory state, then `save()?`. If the
    disk write fails, the error propagates but memory has diverged — and the *next* successful
    save silently persists the previously-failed change.
  - **Fix:** mutate a clone, `save()` the clone, then swap into the guard.

- [x] **🟡 2.2 One shared `atomic_write_json`** — `static_store.rs:180`, `tls_store.rs:116`, `netbridge_state.rs:41`
  - **Why:** three near-duplicate atomic-write implementations with inconsistent durability:
    `netbridge_state` uses `fs::write` + rename **without fsync** (a crash can commit the
    rename with empty/stale content despite the "atomic" doc claim); all three use a fixed
    `<name>.json.tmp` (two concurrent writers in one process clobber each other); none fsyncs
    the directory.
  - **Fix:** one helper (unique tmp name → file fsync → rename → best-effort dir fsync) used
    by all three. Fold into the 2.1 clone-then-swap pattern.

## Group 3 — Concurrency & async hygiene in the daemon

- [x] **🟡 3.1 Make `sync()` atomic** — `supervisor.rs:501-590`
  - **Why:** classification under lock → lock dropped across `stop_and_join().await` → mutation
    re-locks. Two concurrent syncs from different roots can both pass the cross-root
    name-collision check and one silently overwrites the other, violating the "service names
    are global" invariant the code itself asserts (`bail!` at :516).
  - **Fix:** classify + mutate in one lock hold (stop the collected list afterward), or
    serialize sync entry with a `tokio::sync::Mutex`.
  - **Test:** concurrent syncs from two roots — collision must be rejected, not lost.

- [x] **🟡 3.2 Move blocking I/O off the async runtime** — `crates/portman-daemon/src/certs.rs:60-117`, `supervisor.rs:1635-1693`
  - **Why:** cert provisioning shells out to synchronous `mkcert` from async contexts
    (`RouteBinder::register`, two handler paths), and `handle_cert_health` re-runs a blocking
    `mkcert -version` per request; `persist()` does `create_dir_all` + `sync_all()` + rename
    inline, fsyncing on every backoff cycle of a crash-looping service.
  - **Fix:** `spawn_blocking` for mkcert and the persist write (snapshot-then-write shape
    already supports it); cache the `mkcert -version` probe; consider debouncing persist.

- [x] **🟡 3.3 Netbridge pump tasks must not die silently** — `runtime.rs:248-249,293-303`
  - **Why:** `recv_from`/`dev_read` errors make the rx/tx tasks `return` with no log, and every
    `send_to`/`write_all` is `let _ =`. If utun or the socket dies, `Runtime` still looks
    healthy while the reconciler keeps "repairing" routes onto a dead interface.
  - **Fix:** report task death on a `watch`/`mpsc` channel the daemon can poll; at minimum
    `warn!` on first error and on dropped frames.

- [x] **🟡 3.4 Resource sampler fixes** — `crates/portman-daemon/src/resources.rs:232-244,272-273`
  - **Why:** per-container `docker stats` awaited sequentially — with N containers the tick
    grows ~N× stats latency, silently degrading the 5 s sample period; and
    `spawn_blocking(…).await.unwrap_or_default()` turns a sampler panic into silently blank
    service metrics.
  - **Fix:** `futures::future::join_all` the independent per-container stats; match the
    `JoinError` and `warn!` it.

- [x] **🟡 3.5 Narrow the `op` fatal-failure heuristic** — `crates/portman-daemon/src/secrets/onepassword.rs:213-221`
  - **Why:** substring-matching `"credentials"`/`"authentication"` anywhere in stderr means a
    transient "failed to refresh credentials: timeout" becomes fatal, parking the service in
    Failed permanently despite a working restart policy.
  - **Fix:** match structured `op` exit codes or a tighter phrase set.

- [x] **🟡 3.6 Don't persist `pid 0` markers** — `supervisor.rs:1244-1258`
  - **Why:** `child.id().unwrap_or_default()` writes `RunningMarker { pid: 0, pgid: 0 }` if the
    pid is unreadable; `getpgid(0)` means "calling process", so boot reconciliation could
    identity-check the daemon against its own marker. Today only the `pgid <= 1` guard in
    `signal_group` (:1387) prevents a nonsense signal.
  - **Fix:** treat `id() == None` as `Attempt::Failure` instead of recording a zero marker.

- [x] **🟡 3.7 Bound the log-reader tasks** — `supervisor.rs:1407-1416`
  - **Why:** `spawn_line_reader` runs until pipe EOF; a grandchild that escapes the group KILL
    sweep holding stdout keeps the reader alive indefinitely, appending to the log store under
    the old attempt.
  - **Fix:** hold the `JoinHandle`s and abort after `stop_child_group`, or pass a
    `CancellationToken`.

## Group 4 — Semantics & protocol

- [x] **🟡 4.1 Pin overlay-merge semantics for collection fields** — `crates/portman-core/src/service_config.rs:201,207`
  - **Why:** a `portman.local.toml` overlay's `env`/`env_files`/`depends`/service-level
    `groups` **replace** the committed value outright (`overlay.env.or(self.env)`), while
    file-level `groups` union (:96). Adding one env var locally silently drops all committed
    inline env — a surprise for the documented "field-level patch" behavior. No merge tests
    assert either behavior.
  - **Fix:** decide: key-level merge for `env` (append-only overlay) or doc + test pinning
    replacement. The recent `ea37608` commit advertised field-level patching — verify intent.

- [x] **🟡 4.2 De-stringify protocol enums** — `crates/portman-protocol/src/lib.rs` (`ServiceStatusInfo.state` ~:305, `TldInfo.tls_mode`, `bridge_assessment`)
  - **Why:** wire fields are `String` even though core owns the enums (`TlsMode` exists!).
    CLI/TUI/dashboard string-match; new states fail silently. The crate already uses
    `#[serde(default)]` well elsewhere.
  - **Fix:** serialize the existing enums, keep `#[serde(default)]` for back-compat.

- [x] **🟡 4.3 Move framing into `portman-protocol`** — `crates/portman-core/src/ipc.rs`
  - **Why:** the protocol crate is described as "length-prefixed JSON IPC framing shared by
    daemon+CLI" but contains only serde types; the codec lives in core and drags tokio into
    core. Layering smell, and it's the natural home for the 1.6 timeout fix.
  - **Fix:** move `read_frame`/`write_frame` + `MAX_FRAME_BYTES` to protocol behind a
    `transport` feature; split the path helpers into a `paths.rs`.

## Group 5 — Structure (separate reviewable commits)

- [x] **🟢 5.1 Split `cli/main.rs` (2004 lines)** — `crates/portman-cli/src/main.rs:253-2004`
  - **Why:** one file mixes five unrelated domains (~40 handlers). No single function is
    monstrous, but navigation and reviewability suffer, and the ~550-line destructive install
    path (1216-1790) is exactly where a regression bricks an install — yet only `kill_argv`
    and `STRAGGLER_PATTERNS` are tested.
  - **Fix:** `cmd/install.rs` (1216-1790), `cmd/tld.rs` (1033-1215 + `sudo_write`),
    `cmd/services.rs` (557-790), `cmd/bridge.rs` (301-470), `cmd/secrets.rs` (825-880);
    main.rs keeps clap defs + dispatch. Extract argv-building (`release_build_argv`,
    `launchctl_argv`, `uid_from_env`) as pure functions and unit-test them (sudo vs non-sudo,
    uid 0 ignored, fallback 501).

- [x] **🟢 5.2 De-block the TUI event loop** — `crates/portman-cli/src/tui.rs:96-119,337-378`
  - **Why:** the loop awaits `refresh()` inline; `fetch_all` does 5 sequential round-trips,
    each opening a fresh `UnixStream`. A slow/wedged daemon freezes key handling and drawing;
    every mutating key triggers a full refresh.
  - **Fix:** spawn the refresh task, send results over `mpsc` the select-loop drains;
    `tokio::join!` the five fetches inside it.

- [x] **🟢 5.3 TUI render-path allocations** — `tui.rs:1246-1259,2028-2040`
  - **Why:** `render_logs_panel` clones every visible log line into `Line<'static>` each frame
    (300 ms tick + per keystroke when the log pane is focused); `scheme_for` lowercases +
    `format!`s per entry × per TLD × per frame.
  - **Fix:** `view` already borrows `&State` for the draw — borrow into `Line<'a>` instead;
    precompute a host→scheme map once in `refresh`.

- [x] **🟢 5.4 TUI should drive the running binary, not `/usr/local/bin/portman`** — `tui.rs:765-788,832-844`
  - **Why:** `run_tld_add`/`run_tld_remove` exec the *installed* CLI, so a dev-run TUI drives
    a possibly-stale release build, and duplicates the sudo flow from `cmd_tld_add/remove`.
  - **Fix:** `std::env::current_exe()`, or extract the sudo TLD flow into a shared `cmd::tld`
    function both paths call.

- [x] **🟢 5.5 Add `Response::into_ok()` / expect-variant helpers** — `main.rs` (26 sites, e.g. 288-292, 580-586), `tui.rs` (694-699, 809-813)
  - **Why:** the same `Response::Err { message } => bail!(message), other => bail!("unexpected
    response: {other:?}")` boilerplate appears ~29×, and main.rs `request()` adds "Is the
    daemon running?" context while tui.rs `send()` surfaces bare connection errors.
  - **Fix:** helpers in `portman-protocol`; one shared `send` with context used by both.

- [x] **🟢 5.6 Deduplicate helpers** — cross-crate
  - `display_netbridge_mode` ×3 (main.rs:462, tui.rs:1537, doctor.rs:436) → `impl NetbridgeMode { as_str }` in protocol
  - `wait_for_bridge_state` ×2 (main.rs:403, tui.rs:735 — identical 60s loops)
  - `format_bytes`/`format_rate`/`truncate`/`open_browser` ×2 (main.rs:1875+, tui.rs:2067+) → one `cli::fmt` module
  - unix-ms clock helpers ×4 (supervisor.rs:1577, resources.rs:655, log_store.rs:333, …) → one core helper
  - `short()` ×2 (main.rs:584, resources.rs:651)
  - **Why:** drift risk — the two `wait_for_bridge_state` copies and three mode formatters can
    (and will) diverge; fixes land in one copy only.

- [x] **🟢 5.7 Centralize installed-binary path constants** — `main.rs:1255,1319,1435,1670`, `tui.rs:766`, `core/launchd.rs:72`
  - **Why:** `/usr/local/bin/portman-daemon` is hardcoded four times in the CLI plus baked
    into the plist in core — a packaging change must touch N sites consistently.
  - **Fix:** `portman_core::paths::{INSTALLED_DAEMON_BIN, INSTALLED_CLI_BIN}`; derive
    `STRAGGLER_PATTERNS` from the same constants.

- [x] **🟢 5.8 Uniform doctor check shape** — `doctor.rs:91-213`
  - **Why:** each check returns its own bespoke enum via three different shell-out helpers;
    `replacement_state` (352-380) re-derives health independently of rendering.
  - **Fix:** one `CheckOutcome { ok/warn/fail, detail }` checks return and the renderer
    consumes — this also makes 1.5 structurally impossible to regress.

## Group 6 — Hygiene sweep (one small commit)

- [x] **🟢 6.1 Remove unused deps** — `tracing` in `crates/portman-core/Cargo.toml` (verified: zero references in core/src); `thiserror` in workspace `Cargo.toml` (no crate uses it — all error handling is anyhow).
- [x] **🟢 6.2 Remove orphaned screenshots** — `new-dash-{dark,dark2,final,full,inspector,light}.png` (~900 KB at repo root, added in `df98d13`, referenced nowhere). Delete, or move to `docs/` if they're intentional design records — then update `.gitignore` policy for root-level images.
- [x] **🟢 6.3 Delete dead code** — `CertManager::invalidate` (`certs.rs:87-92`, `allow(dead_code)`, no callers); `Keypair::secret_base64` public API in `netbridge/tunnel.rs:128` used only by scratch examples (also: its hand-rolled base64 accepts non-canonical input — `base64` is already a transitive dep).
- [x] **🟢 6.4 Unify launchd/systemd template APIs** — `core/launchd.rs` vs `core/systemd.rs`: asymmetric signatures (launchd's two-step render + placeholder dance vs systemd's direct `sudo_user`) and divergent injected `PATH`s (systemd omits `/sbin`). One `render(bin, log_dir, sudo_user) -> String` + shared `daemon_env()`.
- [x] **🟢 6.5 UDP rx buffer sizing** — `runtime.rs:245`: fixed 2048-byte rx buffer silently truncates oversized datagrams into garbage decapsulations. Size at `u16::MAX` or `warn!` once when `n == buf.len()`.

---

## Suggested commit plan

1. **Commit A — daemon crash bugs:** 1.3, 1.4, 1.6 (+ the concurrent-sync test from 3.1). Supervisor only.
2. **Commit B — netbridge safety:** 1.1, 1.2 (+ 3.3 logging while in the file).
3. **Commit C — CLI correctness:** 1.5 (+ test), 5.8 if done together.
4. **Commit D — IPC hardening:** 1.6 (may land with 4.3 if framing moves).
5. **Commit E — store atomicity:** 2.1 + 2.2 together (one helper fixes three files).
6. **Commits F… — structure:** 5.1–5.7, one per commit, each reviewable in isolation.
7. **Commit Z — hygiene:** group 6 as a single small commit.

## Explicitly not issues (verified, don't "fix")

- Platform stubs (`*_stub.rs`) are intentional cfg-gated non-macOS fallbacks.
- `lock().expect("… poisoned")` posture throughout supervisor is defensible — poisoning means
  a panic already corrupted state; boot reconciliation is the recovery path.
- protocol crate production code: zero unwraps (all 20 sites are test-only); frame codec
  enforces `MAX_FRAME_BYTES` both directions correctly.
- plist generation is not duplicated — CLI correctly delegates to `portman_core::launchd/systemd`.
- No `.unwrap()` on user-input/network paths in the CLI.
