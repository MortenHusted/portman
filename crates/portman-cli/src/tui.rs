//! Terminal UI — primary interactive surface for portman.
//!
//! Layout matches the lazydocker/lazygit convention:
//!   ┌──────────────────────┬───────────────────────────────┐
//!   │ [1] Status           │ [ Detail ]                    │
//!   ├──────────────────────┤   Context for whichever left  │
//!   │ [2] Entries          │   panel is focused.           │
//!   │                      ├───────────────────────────────┤
//!   ├──────────────────────┤ [ Activity ]                  │
//!   │ [3] TLDs             │ Container resource usage.     │
//!   │                      │                               │
//!   └──────────────────────┴───────────────────────────────┘
//!   [ key hints                                           ]
//!
//! Left column = three stacked always-visible panels (Status is compact; the
//! two lists split the remaining space evenly). Right column = detail for
//! the focused left panel. 1/2/3 or Tab to switch focus; j/k/arrows to move
//! inside the focused list. Mutations that need sudo suspend the TUI
//! (leave raw + alternate screen), run the CLI in the parent terminal, then
//! restore.

use std::io::{stdout, Stdout};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures_util::StreamExt;
use portman_protocol::{
    ContainerResourceUsage, Entry, LogLineInfo, Mode, NetbridgeMode, Request,
    ResourceUsageSnapshot, Response, ServiceStatusInfo, Source, TldInfo,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;
use tokio::time::{interval, Instant, Interval};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub(crate) async fn run() -> Result<()> {
    let mut terminal = enter_tui().context("entering TUI")?;
    let result = run_loop(&mut terminal).await;
    let _ = leave_tui(&mut terminal);
    result
}

fn enter_tui() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(out);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn leave_tui(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

async fn run_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    let mut state = State::default();
    let mut events = EventStream::new();
    let mut ticker: Interval = interval(Duration::from_millis(2000));
    // Sub-second cursor polls, active only while the log pane is focused;
    // everything else stays on the 2 s tick.
    let mut log_ticker: Interval = interval(Duration::from_millis(300));

    // Periodic refreshes run in a spawned task and land here — a slow or
    // wedged daemon must never freeze key handling or drawing. One refresh
    // in flight at a time; a tick that finds one running is skipped.
    let (refresh_tx, mut refresh_rx) = tokio::sync::mpsc::channel::<RefreshOutcome>(2);
    let mut refresh_inflight = spawn_refresh(&refresh_tx);

    loop {
        terminal.draw(|f| view(f, &state))?;
        tokio::select! {
            _ = ticker.tick() => {
                if !refresh_inflight {
                    refresh_inflight = spawn_refresh(&refresh_tx);
                }
                if state.logs.is_some() && state.focus != Panel::Logs {
                    poll_logs(&mut state).await;
                }
            }
            Some(outcome) = refresh_rx.recv() => {
                refresh_inflight = false;
                apply_refresh(&mut state, outcome);
            }
            _ = log_ticker.tick(), if state.focus == Panel::Logs => poll_logs(&mut state).await,
            Some(Ok(ev)) = events.next() => {
                if let Event::Key(k) = ev {
                    match handle_key(k, &mut state, terminal).await {
                        Outcome::Quit => break,
                        Outcome::Continue => {}
                    }
                }
            }
        }
    }
    Ok(())
}

/// Kick off one background refresh; returns true (the new in-flight state).
fn spawn_refresh(tx: &tokio::sync::mpsc::Sender<RefreshOutcome>) -> bool {
    let tx = tx.clone();
    tokio::spawn(async move {
        let _ = tx.send(collect_refresh().await).await;
    });
    true
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Default)]
struct State {
    focus: Panel,
    entries: Vec<Entry>,
    tlds: Vec<TldInfo>,
    status: Option<StatusSnapshot>,
    resource_usage: Option<ResourceUsageSnapshot>,
    resource_history: Vec<portman_protocol::ResourceSeries>,
    error: Option<(String, Instant)>,
    entries_sel: ListState,
    tlds_sel: ListState,
    services: Vec<ServiceStatusInfo>,
    services_sel: ListState,
    /// Open log pane (rendered in the detail area; focused via Enter on a
    /// service, closed with Esc).
    logs: Option<LogView>,
    modal: Modal,
    daemon_online: bool,
    /// host -> "http" | "https" | "tcp", derived from entries + TLD TLS
    /// modes on every refresh so the render path is lookup-only.
    schemes: std::collections::HashMap<String, &'static str>,
}

impl State {
    fn scheme_of(&self, entry: &Entry) -> &'static str {
        self.schemes.get(&entry.host).copied().unwrap_or("http")
    }
}

#[derive(Clone)]
struct StatusSnapshot {
    version: String,
    running_since: String,
    dns_port: u16,
    proxy_port: u16,
    tls_port: u16,
    socket_path: String,
    data_dir: String,
    cert_dir: String,
    bridge_assessment: portman_protocol::BridgeAssessment,
    bridge_enabled: bool,
    bridge_mode: NetbridgeMode,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Panel {
    Status,
    #[default]
    Entries,
    Tlds,
    Services,
    /// The log pane. Not part of the Tab cycle — entered with Enter from
    /// Services, left with Esc.
    Logs,
}

impl Panel {
    fn next(self) -> Panel {
        match self {
            Panel::Status => Panel::Entries,
            Panel::Entries => Panel::Tlds,
            Panel::Tlds => Panel::Services,
            Panel::Services => Panel::Status,
            Panel::Logs => Panel::Logs,
        }
    }
    fn prev(self) -> Panel {
        match self {
            Panel::Status => Panel::Services,
            Panel::Entries => Panel::Status,
            Panel::Tlds => Panel::Entries,
            Panel::Services => Panel::Tlds,
            Panel::Logs => Panel::Logs,
        }
    }
}

#[derive(Default)]
enum Modal {
    #[default]
    None,
    AddEntry {
        host: String,
        target: String,
        tcp: bool,
        field: usize,
    },
    AddTld {
        name: String,
        tls: bool,
    },
    ConfirmBridgeDisable,
    Help,
}

enum Outcome {
    Continue,
    Quit,
}

// ---------------------------------------------------------------------------
// Log pane state (pure — exercised directly by tests)
// ---------------------------------------------------------------------------

const LOG_SCROLLBACK_LINES: usize = 2000;

/// Scrollback + cursor state for the log pane. Follow mode is on by
/// default; scrolling up pauses it, returning to the bottom resumes it.
struct LogView {
    service: String,
    /// Last log id seen — advances monotonically with each poll.
    cursor: i64,
    /// True once the initial tail fetch happened.
    primed: bool,
    lines: std::collections::VecDeque<(String, String)>,
    /// Lines scrolled up from the tail; 0 = pinned to the bottom.
    scroll_from_bottom: usize,
    follow: bool,
}

impl LogView {
    fn new(service: String) -> Self {
        Self {
            service,
            cursor: 0,
            primed: false,
            lines: std::collections::VecDeque::new(),
            scroll_from_bottom: 0,
            follow: true,
        }
    }

    fn ingest(&mut self, lines: &[LogLineInfo], last_id: i64) {
        if last_id > self.cursor {
            self.cursor = last_id;
        }
        for line in lines {
            self.lines
                .push_back((line.stream.clone(), line.line.clone()));
        }
        while self.lines.len() > LOG_SCROLLBACK_LINES {
            self.lines.pop_front();
        }
        if !self.follow {
            // Keep the viewport anchored to the same content while new
            // lines land below it.
            self.scroll_from_bottom =
                (self.scroll_from_bottom + lines.len()).min(self.lines.len().saturating_sub(1));
        }
    }

    fn scroll_up(&mut self, n: usize) {
        self.follow = false;
        self.scroll_from_bottom =
            (self.scroll_from_bottom + n).min(self.lines.len().saturating_sub(1));
    }

    fn scroll_down(&mut self, n: usize) {
        self.scroll_from_bottom = self.scroll_from_bottom.saturating_sub(n);
        if self.scroll_from_bottom == 0 {
            self.follow = true;
        }
    }

    fn jump_to_bottom(&mut self) {
        self.scroll_from_bottom = 0;
        self.follow = true;
    }
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

type RefreshOutcome = Result<RefreshData>;

struct RefreshData {
    entries: Vec<Entry>,
    tlds: Vec<TldInfo>,
    status: StatusSnapshot,
    resource_usage: Option<ResourceUsageSnapshot>,
    resource_history: Vec<portman_protocol::ResourceSeries>,
    services: Vec<ServiceStatusInfo>,
}

async fn collect_refresh() -> RefreshOutcome {
    fetch_all().await
}

fn apply_refresh(state: &mut State, outcome: RefreshOutcome) {
    match outcome {
        Ok(data) => {
            state.entries = data.entries;
            state.tlds = data.tlds;
            state.status = Some(data.status);
            state.resource_usage = data.resource_usage;
            state.resource_history = data.resource_history;
            state.services = data.services;
            state.schemes = compute_schemes(&state.entries, &state.tlds);
            state.daemon_online = true;
            clamp_selection(&mut state.entries_sel, state.entries.len());
            clamp_selection(&mut state.tlds_sel, state.tlds.len());
            clamp_selection(&mut state.services_sel, state.services.len());
        }
        Err(_) => {
            state.daemon_online = false;
            state.resource_usage = None;
        }
    }
}

/// Foreground refresh for post-mutation paths: the mutation just awaited
/// IPC anyway, and the caller wants the updated rows before redrawing.
async fn refresh(state: &mut State) {
    apply_refresh(state, collect_refresh().await);
}

async fn fetch_services() -> Result<Vec<ServiceStatusInfo>> {
    match send(Request::ServiceStatus).await? {
        Response::ServiceStatuses { services } => Ok(services),
        Response::Err { message } => anyhow::bail!(message),
        _ => anyhow::bail!("unexpected ServiceStatus response"),
    }
}

/// One cursor poll for the open log pane.
async fn poll_logs(state: &mut State) {
    let Some(view) = &mut state.logs else { return };
    let request = if view.primed {
        Request::LogsQuery {
            service: view.service.clone(),
            after_id: Some(view.cursor),
            limit: 500,
        }
    } else {
        Request::LogsQuery {
            service: view.service.clone(),
            after_id: None,
            limit: 200,
        }
    };
    if let Ok(Response::Logs { lines, last_id }) = send(request).await {
        view.primed = true;
        view.ingest(&lines, last_id);
    }
}

fn clamp_selection(sel: &mut ListState, len: usize) {
    if len == 0 {
        sel.select(None);
    } else if sel.selected().is_none() {
        sel.select(Some(0));
    } else if let Some(i) = sel.selected() {
        if i >= len {
            sel.select(Some(len - 1));
        }
    }
}

async fn fetch_all() -> Result<RefreshData> {
    // Each request opens its own socket connection, so the six round-trips
    // are independent — join them instead of paying their latencies in sequence.
    let (entries, tlds, status, resource_usage, resource_history, services) = tokio::join!(
        fetch_entries(),
        fetch_tlds(),
        fetch_status(),
        fetch_resource_usage(),
        fetch_resource_history(),
        fetch_services(),
    );
    Ok(RefreshData {
        entries: entries?,
        tlds: tlds?,
        status: status?,
        resource_usage: resource_usage.ok(),
        resource_history: resource_history.unwrap_or_default(),
        services: services.unwrap_or_default(),
    })
}

async fn fetch_entries() -> Result<Vec<Entry>> {
    match send(Request::ListEntries).await? {
        Response::Entries { entries } => Ok(entries),
        other => other.unexpected(),
    }
}

async fn fetch_tlds() -> Result<Vec<TldInfo>> {
    match send(Request::TldList).await? {
        Response::Tlds { tlds } => Ok(tlds),
        other => other.unexpected(),
    }
}

/// Retained series for the sparkline column. An older daemon answers `Err`;
/// the column just stays empty.
async fn fetch_resource_history() -> Result<Vec<portman_protocol::ResourceSeries>> {
    match send(Request::ResourceHistory).await? {
        Response::ResourceHistory { series } => Ok(series),
        Response::Err { message } => anyhow::bail!(message),
        _ => anyhow::bail!("unexpected ResourceHistory response"),
    }
}

async fn fetch_status() -> Result<StatusSnapshot> {
    match send(Request::Status).await? {
        Response::Status {
            version,
            running_since,
            dns_port,
            proxy_port,
            tls_port,
            socket_path,
            data_dir,
            cert_dir,
            bridge_assessment,
            bridge_enabled,
            bridge_mode,
            ..
        } => Ok(StatusSnapshot {
            version,
            running_since,
            dns_port,
            proxy_port,
            tls_port,
            socket_path,
            data_dir,
            cert_dir,
            bridge_assessment,
            bridge_enabled,
            bridge_mode,
        }),
        _ => anyhow::bail!("unexpected Status response"),
    }
}

async fn fetch_resource_usage() -> Result<ResourceUsageSnapshot> {
    match send(Request::ResourceUsage).await? {
        Response::ResourceUsage { snapshot } => Ok(snapshot),
        Response::Err { message } => anyhow::bail!(message),
        _ => anyhow::bail!("unexpected ResourceUsage response"),
    }
}

use crate::client::request as send;
use crate::client::wait_for_bridge_state;
use crate::fmt::{
    format_bytes as format_resource_bytes, format_rate as format_resource_rate, open_browser,
    truncate as truncate_for_tui,
};

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

async fn handle_key(
    k: KeyEvent,
    state: &mut State,
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
) -> Outcome {
    // Modal keys.
    match &mut state.modal {
        Modal::Help => {
            if matches!(k.code, KeyCode::Char('?') | KeyCode::Esc | KeyCode::Enter) {
                state.modal = Modal::None;
            }
            return Outcome::Continue;
        }
        Modal::AddEntry {
            host,
            target,
            tcp,
            field,
        } => {
            match k.code {
                KeyCode::Esc => state.modal = Modal::None,
                KeyCode::Enter => {
                    let h = host.clone();
                    let t = target.clone();
                    let mode = if *tcp { Mode::Tcp } else { Mode::Http };
                    state.modal = Modal::None;
                    let res = mutate_add_entry(&h, &t, mode).await;
                    apply_result(state, res);
                    refresh(state).await;
                }
                KeyCode::Tab | KeyCode::Down | KeyCode::Up => {
                    *field = (*field + 1) % 3;
                }
                KeyCode::Backspace if *field < 2 => {
                    let buf = if *field == 0 { host } else { target };
                    buf.pop();
                }
                KeyCode::Char(' ') if *field == 2 => *tcp = !*tcp,
                KeyCode::Char(c) if *field < 2 => {
                    let buf = if *field == 0 { host } else { target };
                    buf.push(c);
                }
                _ => {}
            }
            return Outcome::Continue;
        }
        Modal::AddTld { name, tls } => {
            match k.code {
                KeyCode::Esc => state.modal = Modal::None,
                KeyCode::Enter => {
                    let n = name.clone();
                    let enabled = *tls;
                    state.modal = Modal::None;
                    let res = mutate_tld_add_suspended(terminal, &n, enabled).await;
                    apply_result(state, res);
                    refresh(state).await;
                }
                KeyCode::Tab => *tls = !*tls,
                KeyCode::Backspace => {
                    name.pop();
                }
                KeyCode::Char(c) => name.push(c),
                _ => {}
            }
            return Outcome::Continue;
        }
        Modal::ConfirmBridgeDisable => {
            match k.code {
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => state.modal = Modal::None,
                KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                    state.modal = Modal::None;
                    let res = mutate_bridge(Request::BridgeDisable, false).await;
                    apply_result(state, res);
                    refresh(state).await;
                }
                _ => {}
            }
            return Outcome::Continue;
        }
        Modal::None => {}
    }

    match k.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => return Outcome::Quit,
        KeyCode::Char('?') => state.modal = Modal::Help,
        KeyCode::Tab | KeyCode::Char(']') => state.focus = state.focus.next(),
        KeyCode::BackTab | KeyCode::Char('[') => state.focus = state.focus.prev(),
        KeyCode::Char('1') => state.focus = Panel::Status,
        KeyCode::Char('2') => state.focus = Panel::Entries,
        KeyCode::Char('3') => state.focus = Panel::Tlds,
        KeyCode::Char('4') => state.focus = Panel::Services,
        // Log pane: j/k scroll (up pauses follow), G resumes, Esc closes.
        KeyCode::Esc if state.focus == Panel::Logs => {
            state.logs = None;
            state.focus = Panel::Services;
        }
        KeyCode::Char('j') | KeyCode::Down if state.focus == Panel::Logs => {
            if let Some(view) = &mut state.logs {
                view.scroll_down(1);
            }
        }
        KeyCode::Char('k') | KeyCode::Up if state.focus == Panel::Logs => {
            if let Some(view) = &mut state.logs {
                view.scroll_up(1);
            }
        }
        KeyCode::PageDown if state.focus == Panel::Logs => {
            if let Some(view) = &mut state.logs {
                view.scroll_down(20);
            }
        }
        KeyCode::PageUp if state.focus == Panel::Logs => {
            if let Some(view) = &mut state.logs {
                view.scroll_up(20);
            }
        }
        KeyCode::Char('G') if state.focus == Panel::Logs => {
            if let Some(view) = &mut state.logs {
                view.jump_to_bottom();
            }
        }
        KeyCode::Enter | KeyCode::Char('l') if state.focus == Panel::Services => {
            if let Some(service) = selected_service(state) {
                let name = service.name.clone();
                // Switching services starts a fresh view (cursor + buffer).
                state.logs = Some(LogView::new(name));
                state.focus = Panel::Logs;
                poll_logs(state).await;
            }
        }
        KeyCode::Char('r') => refresh(state).await,
        KeyCode::Char('b') => {
            if state
                .status
                .as_ref()
                .map(|status| status.bridge_enabled)
                .unwrap_or(false)
            {
                state.modal = Modal::ConfirmBridgeDisable;
            } else {
                let res = mutate_bridge(Request::BridgeEnable, true).await;
                apply_result(state, res);
                refresh(state).await;
            }
        }
        KeyCode::Char('j') | KeyCode::Down => move_sel(state, 1),
        KeyCode::Char('k') | KeyCode::Up => move_sel(state, -1),
        KeyCode::Char('g') => select_first(state),
        KeyCode::Char('G') => select_last(state),
        KeyCode::Char('a') => match state.focus {
            Panel::Entries => {
                state.modal = Modal::AddEntry {
                    host: String::new(),
                    target: String::new(),
                    tcp: false,
                    field: 0,
                }
            }
            Panel::Tlds => {
                state.modal = Modal::AddTld {
                    name: String::new(),
                    tls: false,
                }
            }
            Panel::Status | Panel::Services | Panel::Logs => {}
        },
        KeyCode::Char('d') | KeyCode::Char('D') => {
            let res = mutate_remove_current(state, terminal).await;
            apply_result(state, res);
            refresh(state).await;
        }
        KeyCode::Char('t') if state.focus == Panel::Tlds => {
            let res = mutate_toggle_tls_suspended(terminal, state).await;
            apply_result(state, res);
            refresh(state).await;
        }
        KeyCode::Char('o') if state.focus == Panel::Entries => {
            if let Some(entry) = selected_entry(state) {
                if entry.mode == Mode::Tcp {
                    apply_result(
                        state,
                        Err(anyhow::anyhow!(
                            "TCP entry — nothing to open in a browser; use [c] to copy host:port"
                        )),
                    );
                } else {
                    let scheme = state.scheme_of(entry);
                    let _ = open_browser(&format!("{scheme}://{}", entry.host));
                }
            }
        }
        KeyCode::Char('c') if state.focus == Panel::Entries => {
            if let Some(entry) = selected_entry(state) {
                let value = if entry.mode == Mode::Tcp {
                    let port = entry.target.rsplit_once(':').map(|(_, p)| p).unwrap_or("");
                    format!("{}:{port}", entry.host)
                } else {
                    let scheme = state.scheme_of(entry);
                    format!("{scheme}://{}", entry.host)
                };
                let _ = copy_to_clipboard(&value);
            }
        }
        _ => {}
    }
    Outcome::Continue
}

fn move_sel(state: &mut State, delta: i32) {
    let (sel, len) = match state.focus {
        Panel::Entries => (&mut state.entries_sel, state.entries.len()),
        Panel::Tlds => (&mut state.tlds_sel, state.tlds.len()),
        Panel::Services => (&mut state.services_sel, state.services.len()),
        Panel::Status | Panel::Logs => return,
    };
    if len == 0 {
        return;
    }
    let cur = sel.selected().unwrap_or(0) as i32;
    let next = (cur + delta).rem_euclid(len as i32) as usize;
    sel.select(Some(next));
}

fn select_first(state: &mut State) {
    match state.focus {
        Panel::Entries if !state.entries.is_empty() => state.entries_sel.select(Some(0)),
        Panel::Tlds if !state.tlds.is_empty() => state.tlds_sel.select(Some(0)),
        Panel::Services if !state.services.is_empty() => state.services_sel.select(Some(0)),
        _ => {}
    }
}

fn select_last(state: &mut State) {
    match state.focus {
        Panel::Entries if !state.entries.is_empty() => {
            state.entries_sel.select(Some(state.entries.len() - 1))
        }
        Panel::Tlds if !state.tlds.is_empty() => state.tlds_sel.select(Some(state.tlds.len() - 1)),
        Panel::Services if !state.services.is_empty() => {
            state.services_sel.select(Some(state.services.len() - 1))
        }
        _ => {}
    }
}

fn selected_entry(state: &State) -> Option<&Entry> {
    state
        .entries_sel
        .selected()
        .and_then(|i| state.entries.get(i))
}

fn selected_tld(state: &State) -> Option<&TldInfo> {
    state.tlds_sel.selected().and_then(|i| state.tlds.get(i))
}

fn selected_service(state: &State) -> Option<&ServiceStatusInfo> {
    state
        .services_sel
        .selected()
        .and_then(|i| state.services.get(i))
}

fn apply_result(state: &mut State, res: Result<()>) {
    if let Err(e) = res {
        state.error = Some((format!("{e:#}"), Instant::now()));
    } else {
        state.error = None;
    }
}

// ---------------------------------------------------------------------------
// Mutations — suspend the TUI around anything that might prompt for sudo
// so the password dialog + CLI chatter land in the normal terminal
// instead of scrambling the raw-mode buffer.
// ---------------------------------------------------------------------------

fn suspend_ui(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn resume_ui(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    enable_raw_mode()?;
    execute!(terminal.backend_mut(), EnterAlternateScreen)?;
    terminal.hide_cursor()?;
    terminal.clear()?;
    Ok(())
}

async fn mutate_add_entry(host: &str, target: &str, mode: Mode) -> Result<()> {
    let resp = send(Request::AddStatic {
        host: host.to_string(),
        target: target.to_string(),
        mode,
        service: None,
        project: None,
    })
    .await?;
    match resp {
        Response::Ok => Ok(()),
        other => other.unexpected(),
    }
}

/// Set the v1 netbridge state via IPC and wait for status to reflect it.
async fn mutate_bridge(req: Request, desired: bool) -> Result<()> {
    match send(req).await? {
        Response::Ok => wait_for_bridge_state(desired).await,
        other => other.unexpected(),
    }
}

async fn mutate_tld_add_suspended(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    name: &str,
    tls: bool,
) -> Result<()> {
    suspend_ui(terminal)?;
    let result = run_tld_add(name, tls);
    resume_ui(terminal)?;
    result
}

/// The binary the TUI is running from — a dev-run TUI must drive its own
/// build, not a possibly-stale installed release.
fn own_cli_bin() -> Result<std::path::PathBuf> {
    std::env::current_exe().context("resolving the running portman binary")
}

fn run_tld_add(name: &str, tls: bool) -> Result<()> {
    let cli = own_cli_bin()?;
    let mut args: Vec<&str> = vec!["tld", "add", name];
    if tls {
        args.extend(["--tls", "mkcert"]);
    } else {
        args.extend(["--tls", "off"]);
    }
    let status = std::process::Command::new(cli).args(&args).status()?;
    if !status.success() {
        anyhow::bail!("portman tld add failed with {status}");
    }
    Ok(())
}

async fn mutate_toggle_tls_suspended(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &State,
) -> Result<()> {
    let Some(tld) = selected_tld(state) else {
        anyhow::bail!("nothing selected");
    };
    let name = tld.name.clone();
    let turning_on = tld.tls_mode == portman_protocol::TlsMode::Off;
    mutate_tld_add_suspended(terminal, &name, turning_on).await
}

async fn mutate_remove_current(
    state: &mut State,
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
) -> Result<()> {
    match state.focus {
        Panel::Services | Panel::Logs => {
            anyhow::bail!("services are managed by their repo config — `portman down <name>`")
        }
        Panel::Entries => {
            let Some(entry) = selected_entry(state) else {
                anyhow::bail!("nothing selected");
            };
            if entry.source == Source::Container {
                anyhow::bail!("container entries are managed by Docker — `docker stop` to remove");
            }
            let host = entry.host.clone();
            let resp = send(Request::RemoveStatic { host }).await?;
            match resp {
                Response::Ok => Ok(()),
                other => other.unexpected(),
            }
        }
        Panel::Tlds => {
            let Some(tld) = selected_tld(state) else {
                anyhow::bail!("nothing selected");
            };
            let name = tld.name.clone();
            suspend_ui(terminal)?;
            let result = run_tld_remove(&name);
            resume_ui(terminal)?;
            result
        }
        Panel::Status => Ok(()),
    }
}

fn run_tld_remove(name: &str) -> Result<()> {
    let cli = own_cli_bin()?;
    let status = std::process::Command::new(cli)
        .args(["tld", "remove", name])
        .status()?;
    if !status.success() {
        anyhow::bail!("portman tld remove failed with {status}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rendering — lazydocker-style left panels + right detail
// ---------------------------------------------------------------------------

fn view(f: &mut ratatui::Frame<'_>, state: &State) {
    let area = f.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // body
            Constraint::Length(1), // status bar
            Constraint::Length(1), // key hints
        ])
        .split(area);

    // Body: left (panels) · right (detail)
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Min(1)])
        .split(outer[0]);

    // Left: Status (compact) · Entries · TLDs · Services
    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Percentage(38),
            Constraint::Percentage(31),
            Constraint::Percentage(31),
        ])
        .split(body[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(11)])
        .split(body[1]);

    render_status_panel(f, left[0], state);
    render_entries_panel(f, left[1], state);
    render_tlds_panel(f, left[2], state);
    render_services_panel(f, left[3], state);
    if state.logs.is_some() {
        render_logs_panel(f, right[0], state);
    } else {
        render_detail(f, right[0], state);
    }
    render_activity_panel(f, right[1], state);

    render_status_bar(f, outer[1], state);
    render_key_hints(f, outer[2], state);

    match &state.modal {
        Modal::None => {}
        Modal::AddEntry {
            host,
            target,
            tcp,
            field,
        } => render_add_entry(f, area, host, target, *tcp, *field),
        Modal::AddTld { name, tls } => render_add_tld(f, area, name, *tls),
        Modal::ConfirmBridgeDisable => render_confirm_bridge_disable(f, area),
        Modal::Help => render_help(f, area),
    }
}

fn panel_block(title: &str, number: usize, focused: bool) -> Block<'_> {
    let title_spans = Line::from(vec![
        Span::styled(format!(" [{number}] "), Style::default().fg(Color::Gray)),
        Span::styled(
            title.to_string(),
            if focused {
                Style::default().fg(Color::Yellow).bold()
            } else {
                Style::default().fg(Color::Gray)
            },
        ),
        Span::raw(" "),
    ]);
    Block::default()
        .borders(Borders::ALL)
        .border_type(if focused {
            BorderType::Rounded
        } else {
            BorderType::Plain
        })
        .border_style(if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        })
        .title(title_spans)
}

fn render_status_panel(f: &mut ratatui::Frame<'_>, area: Rect, state: &State) {
    let focused = state.focus == Panel::Status;
    let block = panel_block("Status", 1, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines: Vec<Line> = if let Some(s) = &state.status {
        // The main dot is the daemon's own online/offline signal — green
        // whenever we have a Status response. Netbridge health is a separate
        // concern and gets its own colored word on the netbridge line, so a
        // flapped bridge no longer makes portman itself look degraded.
        let (bridge_color, bridge_word) = match s.bridge_assessment.as_str() {
            "healthy" => (Color::Green, "healthy"),
            "routes_missing" => (Color::Yellow, "flapped"),
            // Red, not yellow: the route looks fine and nothing works.
            "tunnel_dead" => (Color::Red, "dead tunnel"),
            "offline" => (Color::Yellow, "docker down"),
            _ => (Color::DarkGray, "unknown"),
        };
        vec![
            Line::from(vec![
                Span::styled("●", Style::default().fg(Color::Green)),
                Span::raw(" running"),
                Span::raw("  "),
                Span::styled(format!("v{}", s.version), Style::default().fg(Color::Gray)),
            ]),
            Line::from(Span::styled(
                format!("  up {}", s.running_since),
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  dns  ", Style::default().fg(Color::Gray)),
                Span::styled(s.dns_port.to_string(), Style::default().bold()),
                Span::styled("  http ", Style::default().fg(Color::Gray)),
                Span::styled(format!(":{}", s.proxy_port), Style::default().bold()),
                Span::styled("  tls ", Style::default().fg(Color::Gray)),
                Span::styled(format!(":{}", s.tls_port), Style::default().bold()),
            ]),
            Line::from(vec![
                Span::styled("  netbridge ", Style::default().fg(Color::Gray)),
                Span::styled(
                    if s.bridge_enabled { "on" } else { "off" },
                    Style::default()
                        .fg(if s.bridge_enabled {
                            Color::Green
                        } else {
                            Color::Gray
                        })
                        .bold(),
                ),
                Span::styled(
                    format!("  {}  ", NetbridgeMode::display_word(s.bridge_mode)),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(bridge_word, Style::default().fg(bridge_color)),
                Span::styled(
                    if s.bridge_enabled {
                        "  [b] disable..."
                    } else {
                        "  [b] enable"
                    },
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![
                Span::styled("●", Style::default().fg(Color::Red)),
                Span::raw(" offline"),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "  daemon not reachable",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "  start with: portman install",
                Style::default().fg(Color::DarkGray),
            )),
        ]
    };
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_entries_panel(f: &mut ratatui::Frame<'_>, area: Rect, state: &State) {
    let focused = state.focus == Panel::Entries;
    let title = format!("Entries ({})", state.entries.len());
    let block = panel_block(&title, 2, focused);
    if state.entries.is_empty() {
        let inner = block.inner(area);
        f.render_widget(block, area);
        let p = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  no entries",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "  press 'a' to add",
                Style::default().fg(Color::Gray),
            )),
        ]);
        f.render_widget(p, inner);
        return;
    }

    let items: Vec<ListItem> = state
        .entries
        .iter()
        .map(|e| {
            let scheme = state.scheme_of(e);
            let src = match e.source {
                Source::Container => "●",
                Source::Static => "◆",
                Source::Service => "▸",
            };
            let src_style = match e.source {
                Source::Container => Style::default().fg(Color::Cyan),
                Source::Static => Style::default().fg(Color::Magenta),
                Source::Service => Style::default().fg(Color::Green),
            };
            let scheme_style = match scheme {
                "https" => Style::default().fg(Color::Green).bold(),
                "tcp" => Style::default().fg(Color::Yellow).bold(),
                _ => Style::default().fg(Color::Gray),
            };
            // Two-line entry: host on top, target on bottom. Reads well at
            // menubar-ish panel widths; grounded visual hierarchy (bold
            // hostname = the thing you type, dim target = where it lands).
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(format!(" {src} "), src_style),
                    Span::styled(format!("{scheme:>5}"), scheme_style),
                    Span::raw("  "),
                    Span::styled(e.host.clone(), Style::default().bold()),
                ]),
                Line::from(vec![
                    Span::raw("         → "),
                    Span::styled(e.target.clone(), Style::default().fg(Color::Gray)),
                ]),
            ])
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" ▶ ");
    let mut sel = state.entries_sel.clone();
    f.render_stateful_widget(list, area, &mut sel);
}

fn render_tlds_panel(f: &mut ratatui::Frame<'_>, area: Rect, state: &State) {
    let focused = state.focus == Panel::Tlds;
    let title = format!("TLDs ({})", state.tlds.len());
    let block = panel_block(&title, 3, focused);
    if state.tlds.is_empty() {
        let inner = block.inner(area);
        f.render_widget(block, area);
        let p = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  no TLDs managed",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "  press 'a' to add",
                Style::default().fg(Color::Gray),
            )),
        ]);
        f.render_widget(p, inner);
        return;
    }

    let items: Vec<ListItem> = state
        .tlds
        .iter()
        .map(|t| {
            let tls_span = if t.tls_mode == portman_protocol::TlsMode::Off {
                Span::styled(" http ", Style::default().fg(Color::Gray))
            } else {
                Span::styled(
                    format!(" {} ", t.tls_mode),
                    Style::default().fg(Color::Green).bold(),
                )
            };
            ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(format!(".{}", t.name), Style::default().bold()),
                Span::raw("  "),
                tls_span,
                Span::raw(" "),
                Span::styled(
                    format!(
                        "{} {}",
                        t.entry_count,
                        if t.entry_count == 1 {
                            "entry"
                        } else {
                            "entries"
                        }
                    ),
                    Style::default().fg(Color::Gray),
                ),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" ▶ ");
    let mut sel = state.tlds_sel.clone();
    f.render_stateful_widget(list, area, &mut sel);
}

fn render_services_panel(f: &mut ratatui::Frame<'_>, area: Rect, state: &State) {
    let focused = state.focus == Panel::Services;
    let block = panel_block("Services", 4, focused);
    if state.services.is_empty() {
        let hint = Paragraph::new(Line::from(Span::styled(
            "  none — `portman up` in a repo with a portman.toml",
            Style::default().fg(Color::Gray),
        )))
        .block(block);
        f.render_widget(hint, area);
        return;
    }
    let items: Vec<ListItem> = state
        .services
        .iter()
        .map(|s| {
            let state_style = match s.state.as_str() {
                "ready" => Style::default().fg(Color::Green),
                "failed" => Style::default().fg(Color::Red).bold(),
                "backoff" => Style::default().fg(Color::Yellow),
                "stopped" => Style::default().fg(Color::DarkGray),
                _ => Style::default().fg(Color::Yellow),
            };
            ListItem::new(Line::from(vec![
                Span::styled("\u{25b8} ", Style::default().fg(Color::Green)),
                Span::styled(truncate_for_tui(&s.name, 26), Style::default().bold()),
                Span::raw("  "),
                Span::styled(s.state.as_str(), state_style),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().bg(Color::DarkGray).bold())
        .highlight_symbol(" ");
    let mut sel = state.services_sel.clone();
    f.render_stateful_widget(list, area, &mut sel);
}

fn render_logs_panel(f: &mut ratatui::Frame<'_>, area: Rect, state: &State) {
    let Some(view) = &state.logs else { return };
    let focused = state.focus == Panel::Logs;
    let title = format!(
        "logs \u{00b7} {} {}",
        view.service,
        if view.follow { "(follow)" } else { "(paused)" }
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(if focused {
            BorderType::Rounded
        } else {
            BorderType::Plain
        })
        .border_style(if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        })
        .title(Span::styled(
            format!(" {title} "),
            if focused {
                Style::default().fg(Color::Yellow).bold()
            } else {
                Style::default().fg(Color::Gray)
            },
        ));
    let inner_height = area.height.saturating_sub(2) as usize;

    // Window: the last `inner_height` lines, shifted up by the scroll offset.
    let total = view.lines.len();
    let end = total.saturating_sub(view.scroll_from_bottom);
    let start = end.saturating_sub(inner_height);
    // Borrowed from `view` — this runs every 300ms tick while the log pane
    // is focused, so per-frame clones of every visible line add up.
    let lines: Vec<Line<'_>> = view
        .lines
        .iter()
        .skip(start)
        .take(end - start)
        .map(|(stream, line)| {
            if stream == "stderr" {
                Line::from(Span::styled(
                    line.as_str(),
                    Style::default().fg(Color::LightRed),
                ))
            } else {
                Line::from(Span::raw(line.as_str()))
            }
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_detail(f: &mut ratatui::Frame<'_>, area: Rect, state: &State) {
    let (title, lines) = match state.focus {
        Panel::Status => detail_status(state),
        Panel::Entries => detail_entry(state),
        Panel::Tlds => detail_tld(state),
        Panel::Services | Panel::Logs => detail_service(state),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(vec![Span::styled(
            format!(" {title} "),
            Style::default().fg(Color::Gray).bold(),
        )]));
    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
}

fn render_activity_panel(f: &mut ratatui::Frame<'_>, area: Rect, state: &State) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(vec![Span::styled(
            " Activity · containers ",
            Style::default().fg(Color::Gray).bold(),
        )]));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = if let Some(snapshot) = &state.resource_usage {
        activity_lines(snapshot, &state.resource_history, inner.height)
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  resource data unavailable",
                Style::default().fg(Color::Gray),
            )),
            Line::from(Span::styled(
                "  restart the daemon after installing this build",
                Style::default().fg(Color::DarkGray),
            )),
        ]
    };
    f.render_widget(Paragraph::new(lines), inner);
}

fn activity_lines(
    snapshot: &ResourceUsageSnapshot,
    history: &[portman_protocol::ResourceSeries],
    height: u16,
) -> Vec<Line<'static>> {
    if snapshot.containers.is_empty() && snapshot.services.is_empty() {
        return vec![
            Line::from(""),
            Line::from(Span::styled(
                "  no running containers or services",
                Style::default().fg(Color::Gray),
            )),
        ];
    }

    let mut lines = vec![
        Line::from(vec![
            // Totals are docker-only; service rows carry their own gauges.
            Span::styled("  docker ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{:.1}% cpu", snapshot.totals.cpu_percent),
                Style::default().bold(),
            ),
            Span::styled("  mem ", Style::default().fg(Color::Gray)),
            Span::styled(
                format_resource_bytes(snapshot.totals.memory_usage_bytes),
                Style::default().bold(),
            ),
            Span::styled("  pids ", Style::default().fg(Color::Gray)),
            Span::styled(
                snapshot.totals.pids_current.to_string(),
                Style::default().bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled("  net ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!(
                    "{}/{}",
                    format_resource_rate(snapshot.totals.network_rx_rate_bytes_per_sec),
                    format_resource_rate(snapshot.totals.network_tx_rate_bytes_per_sec)
                ),
                Style::default().bold(),
            ),
            Span::styled("  io ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!(
                    "{}/{}",
                    format_resource_rate(snapshot.totals.block_read_rate_bytes_per_sec),
                    format_resource_rate(snapshot.totals.block_write_rate_bytes_per_sec)
                ),
                Style::default().bold(),
            ),
        ]),
        Line::from(""),
    ];

    let visible_rows = height.saturating_sub(lines.len() as u16) as usize;
    for row in snapshot.containers.iter().take(visible_rows) {
        lines.push(activity_container_line(row));
    }
    let remaining = visible_rows.saturating_sub(snapshot.containers.len());
    for row in snapshot.services.iter().take(remaining) {
        let spark = history
            .iter()
            .find(|s| s.kind == portman_protocol::SeriesKind::Service && s.key == row.name)
            .map(|s| cpu_sparkline(&s.points, 16))
            .unwrap_or_default();
        lines.push(activity_service_line(row, spark));
    }
    lines
}

/// Bar-glyph sparkline of a series' recent CPU points, newest right.
/// Scaled to the series' own peak — the point is shape, not absolute value,
/// which the gauge column next to it already gives.
fn cpu_sparkline(points: &[portman_protocol::HistoryPoint], width: usize) -> String {
    const BARS: [char; 8] = [
        '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}',
        '\u{2588}',
    ];
    let tail: Vec<f64> = points
        .iter()
        .rev()
        .take(width)
        .rev()
        .map(|p| p.cpu_percent)
        .collect();
    if tail.is_empty() {
        return String::new();
    }
    let max = tail.iter().cloned().fold(f64::EPSILON, f64::max);
    tail.iter()
        .map(|v| BARS[((v / max) * 7.0).round().clamp(0.0, 7.0) as usize])
        .collect()
}

/// A supervised service row alongside the docker containers: same gauges,
/// service-shaped identity.
fn activity_service_line(
    row: &portman_protocol::ServiceResourceUsage,
    spark: String,
) -> Line<'static> {
    let cpu_style = if row.cpu_percent >= 100.0 {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default().fg(Color::Gray)
    };
    Line::from(vec![
        Span::raw("  "),
        Span::styled("\u{25b8}", Style::default().fg(Color::Green)),
        Span::raw(" "),
        Span::styled(truncate_for_tui(&row.name, 24), Style::default().bold()),
        Span::raw("  "),
        Span::styled(format!("{:>5.1}%", row.cpu_percent), cpu_style),
        Span::styled("  ", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{:>8}", format_resource_bytes(row.memory_usage_bytes)),
            Style::default().fg(Color::Gray),
        ),
        Span::styled("  ", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("pids {:>3}", row.pids_current),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled("  ", Style::default().fg(Color::Gray)),
        Span::styled(spark, Style::default().fg(Color::Cyan)),
        Span::styled("  ", Style::default().fg(Color::Gray)),
        Span::styled(
            truncate_for_tui(row.host.as_deref().unwrap_or(""), 36),
            Style::default().fg(Color::DarkGray),
        ),
    ])
}

fn activity_container_line(row: &ContainerResourceUsage) -> Line<'static> {
    let marker = if row.portman_hosts.is_empty() {
        Span::styled("·", Style::default().fg(Color::DarkGray))
    } else {
        Span::styled("●", Style::default().fg(Color::Cyan))
    };
    let cpu_style = if row.cpu_percent >= 100.0 {
        Style::default().fg(Color::Yellow).bold()
    } else {
        Style::default().fg(Color::Gray)
    };
    let detail = if let Some(host) = row.portman_hosts.first() {
        host.clone()
    } else if !row.image.is_empty() {
        row.image.clone()
    } else {
        String::new()
    };

    Line::from(vec![
        Span::raw("  "),
        marker,
        Span::raw(" "),
        Span::styled(
            truncate_for_tui(&activity_container_label(row), 24),
            Style::default().bold(),
        ),
        Span::raw("  "),
        Span::styled(format!("{:>5.1}%", row.cpu_percent), cpu_style),
        Span::styled("  ", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{:>8}", format_resource_bytes(row.memory_usage_bytes)),
            Style::default().fg(Color::Gray),
        ),
        Span::styled("  ", Style::default().fg(Color::Gray)),
        Span::styled(
            format!(
                "r {:>7}",
                format_resource_rate(row.block_read_rate_bytes_per_sec)
            ),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled("  ", Style::default().fg(Color::Gray)),
        Span::styled(
            truncate_for_tui(&detail, 36),
            Style::default().fg(Color::DarkGray),
        ),
    ])
}

fn detail_status(state: &State) -> (&'static str, Vec<Line<'static>>) {
    let lines = if let Some(s) = &state.status {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  portman ", Style::default().fg(Color::Yellow).bold()),
                Span::raw(format!("v{}", s.version)),
                Span::styled(
                    format!("  ·  up {}", s.running_since),
                    Style::default().fg(Color::Gray),
                ),
            ]),
            Line::from(""),
            kv("  dns port   ", s.dns_port.to_string()),
            kv("  http proxy ", format!(":{}", s.proxy_port)),
            kv("  tls proxy  ", format!(":{}", s.tls_port)),
            Line::from(""),
            kv("  socket     ", s.socket_path.clone()),
            kv("  data dir   ", s.data_dir.clone()),
            kv("  cert dir   ", s.cert_dir.clone()),
            Line::from(""),
            kv(
                "  netbridge ",
                format!(
                    "{} ({})",
                    if s.bridge_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    NetbridgeMode::display_word(s.bridge_mode)
                ),
            ),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from("  Daemon offline."),
            Line::from(""),
            Line::from(Span::styled(
                "  sudo launchctl kickstart -k system/dev.portman.daemon",
                Style::default().fg(Color::Gray),
            )),
        ]
    };
    ("Detail · status", lines)
}

fn detail_entry(state: &State) -> (&'static str, Vec<Line<'static>>) {
    let Some(entry) = selected_entry(state) else {
        return (
            "Detail · entry",
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  (no entry selected)",
                    Style::default().fg(Color::Gray),
                )),
            ],
        );
    };
    let scheme = state.scheme_of(entry);
    let tld = tld_of(&entry.host);
    let tld_info = state.tlds.iter().find(|t| t.name == tld);
    let is_tcp = entry.mode == Mode::Tcp;
    let port_part = entry.target.rsplit_once(':').map(|(_, p)| p).unwrap_or("");
    let url = if is_tcp {
        format!("{}:{port_part}", entry.host)
    } else {
        format!("{scheme}://{}", entry.host)
    };

    let flow_second_line = if is_tcp {
        Line::from(vec![
            Span::styled("  DNS resolves to ", Style::default().fg(Color::Gray)),
            Span::styled(entry.target.clone(), Style::default().bold()),
            Span::styled(
                " — your client connects directly (portman stays out of the data path).",
                Style::default().fg(Color::Gray),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("  When you visit ", Style::default().fg(Color::Gray)),
            Span::styled(entry.host.clone(), Style::default().bold()),
            Span::styled(
                ", portman forwards the request to ",
                Style::default().fg(Color::Gray),
            ),
            Span::styled(entry.target.clone(), Style::default().bold()),
            Span::styled(".", Style::default().fg(Color::Gray)),
        ])
    };

    let url_color = match scheme {
        "https" => Color::Green,
        "tcp" => Color::Yellow,
        _ => Color::Gray,
    };
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled(url.clone(), Style::default().bold().fg(url_color)),
        ]),
        Line::from(""),
        flow_second_line,
        Line::from(""),
    ];

    // Metadata — source + TLD
    let source_desc = match entry.source {
        Source::Container => {
            let cid = entry.container_id.clone().unwrap_or_default();
            format!("container  ({cid})")
        }
        Source::Static => "static rule  (added via `portman add`)".to_string(),
        Source::Service => "service  (derived from portman.toml — `portman up`/`down`)".to_string(),
    };
    lines.push(kv("  source      ", source_desc));
    lines.push(kv(
        "  mode        ",
        if is_tcp {
            "tcp  (raw, portman-out-of-path)"
        } else {
            "http  (proxied by Host header)"
        }
        .to_string(),
    ));
    if let Some(t) = tld_info {
        lines.push(kv(
            "  TLD         ",
            format!(
                ".{}  ·  {}",
                t.name,
                if t.tls_mode == portman_protocol::TlsMode::Off {
                    "plain http"
                } else {
                    t.tls_mode.as_str()
                }
            ),
        ));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        if is_tcp {
            "  [c] copy host:port   (no browser — this is raw TCP)"
        } else {
            "  [o] open in browser   [c] copy URL"
        },
        Style::default().fg(Color::Gray),
    )));
    lines.push(Line::from(Span::styled(
        match entry.source {
            Source::Static => "  [d] remove this rule",
            Source::Container => {
                "  container entries follow the container — `docker stop` to remove"
            }
            Source::Service => "  service entries follow the service — `portman down` to remove",
        },
        Style::default().fg(Color::Gray),
    )));
    ("Detail · entry", lines)
}

fn detail_service(state: &State) -> (&'static str, Vec<Line<'static>>) {
    let Some(service) = selected_service(state) else {
        return (
            "Detail · service",
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  no service selected",
                    Style::default().fg(Color::Gray),
                )),
            ],
        );
    };
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                service.name.clone(),
                Style::default().fg(Color::Green).bold(),
            ),
            Span::raw("  "),
            Span::styled(service.state.as_str(), Style::default().bold()),
        ]),
        Line::from(""),
    ];
    if let Some(host) = &service.host {
        lines.push(kv("  host        ", host.clone()));
    }
    if let Some(port) = service.port {
        lines.push(kv("  port        ", port.to_string()));
    }
    if let Some(pid) = service.pid {
        lines.push(kv("  pid         ", pid.to_string()));
    }
    lines.push(kv("  restarts    ", service.restarts.to_string()));
    lines.push(kv(
        "  desired     ",
        if service.desired_up { "up" } else { "down" }.to_string(),
    ));
    if !service.detail.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {}", service.detail),
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  [Enter] live logs",
        Style::default().fg(Color::Gray),
    )));
    ("Detail · service", lines)
}

fn detail_tld(state: &State) -> (&'static str, Vec<Line<'static>>) {
    let Some(tld) = selected_tld(state) else {
        return (
            "Detail · TLD",
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  (no TLD selected)",
                    Style::default().fg(Color::Gray),
                )),
            ],
        );
    };
    let tls_desc = match tld.tls_mode {
        portman_protocol::TlsMode::Off => "plain HTTP (no TLS)",
        portman_protocol::TlsMode::Mkcert => "TLS via mkcert local CA",
        portman_protocol::TlsMode::Le => "TLS via Let's Encrypt",
    };
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  .", Style::default().bold()),
            Span::styled(tld.name.clone(), Style::default().bold()),
        ]),
        Line::from(""),
        kv("  tls mode   ", tls_desc.to_string()),
        kv("  entries    ", tld.entry_count.to_string()),
        kv("  resolver   ", format!("/etc/resolver/{}", tld.name)),
    ];
    if tld.tls_mode != portman_protocol::TlsMode::Off {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  certs auto-issued via mkcert on container start",
            Style::default().fg(Color::Gray),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  [t] toggle TLS   [d] remove",
        Style::default().fg(Color::Gray),
    )));
    ("Detail · TLD", lines)
}

fn kv(k: &str, v: String) -> Line<'static> {
    Line::from(vec![
        Span::styled(k.to_string(), Style::default().fg(Color::Gray)),
        Span::styled(v, Style::default().bold()),
    ])
}

fn render_status_bar(f: &mut ratatui::Frame<'_>, area: Rect, state: &State) {
    let mut spans: Vec<Span<'_>> = Vec::new();
    let color = if state.daemon_online {
        Color::Green
    } else {
        Color::Red
    };
    spans.push(Span::styled(" ● ", Style::default().fg(color)));
    spans.push(Span::styled(
        if state.daemon_online {
            "connected"
        } else {
            "offline"
        }
        .to_string(),
        Style::default().fg(color),
    ));
    if let Some(s) = &state.status {
        spans.push(Span::raw(format!(
            "  ·  dns :{}  ·  http :{}  ·  tls :{}",
            s.dns_port, s.proxy_port, s.tls_port
        )));
    }
    if let Some((err, _)) = &state.error {
        spans.push(Span::raw("  ·  "));
        spans.push(Span::styled(
            format!("error: {err}"),
            Style::default().fg(Color::Red),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_key_hints(f: &mut ratatui::Frame<'_>, area: Rect, state: &State) {
    let hints = match state.focus {
        Panel::Status => " 1/2/3 panel · tab next · r refresh · ? help · q quit ",
        Panel::Entries => {
            " j/k move · a add · d remove · o open · c copy · r refresh · ? help · q quit "
        }
        Panel::Tlds => " j/k move · a add · d remove · t toggle tls · r refresh · ? help · q quit ",
        Panel::Services => " j/k move · enter logs · r refresh · ? help · q quit ",
        Panel::Logs => " k scroll up (pauses follow) · j down · G follow · esc close · q quit ",
    };
    f.render_widget(
        Paragraph::new(Span::styled(
            hints.to_string(),
            Style::default().fg(Color::Gray),
        ))
        .alignment(Alignment::Left),
        area,
    );
}

fn render_add_entry(
    f: &mut ratatui::Frame<'_>,
    area: Rect,
    host: &str,
    target: &str,
    tcp: bool,
    field: usize,
) {
    let modal = centered_rect(area, 76, 18);
    f.render_widget(Clear, modal);
    let mode_label = if tcp { "TCP (raw)" } else { "HTTP (proxied)" };
    let mode_hint = if tcp {
        "            DNS → target IP; clients connect directly (Postgres, MySQL, …)"
    } else {
        "            DNS → 127.0.0.1; portman's :80/:443 proxy forwards by Host header"
    };
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Register a hostname → ip:port route.",
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("  HOSTNAME  "),
            Span::styled(
                format!("{host}{}", if field == 0 { "█" } else { "" }),
                if field == 0 {
                    Style::default().fg(Color::Yellow).bold()
                } else {
                    Style::default()
                },
            ),
        ]),
        Line::from(Span::styled(
            "            what you type in the client (e.g. crm.acme)",
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("  FORWARDS  "),
            Span::styled(
                format!("{target}{}", if field == 1 { "█" } else { "" }),
                if field == 1 {
                    Style::default().fg(Color::Yellow).bold()
                } else {
                    Style::default()
                },
            ),
        ]),
        Line::from(Span::styled(
            "            ip:port on this machine (e.g. 127.0.0.1:3070, 172.17.0.2:5432)",
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("  MODE      "),
            Span::styled(
                mode_label.to_string(),
                if field == 2 {
                    Style::default().fg(Color::Yellow).bold()
                } else {
                    Style::default()
                },
            ),
        ]),
        Line::from(Span::styled(mode_hint, Style::default().fg(Color::Gray))),
        Line::from(""),
        Line::from(Span::styled(
            "  [Tab] next field   [Space] toggle mode   [Enter] add   [Esc] cancel",
            Style::default().fg(Color::Gray),
        )),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(" add static entry ")
        .border_style(Style::default().fg(Color::Yellow));
    f.render_widget(Paragraph::new(lines).block(block), modal);
}

fn render_add_tld(f: &mut ratatui::Frame<'_>, area: Rect, name: &str, tls: bool) {
    let modal = centered_rect(area, 55, 10);
    f.render_widget(Clear, modal);
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("  NAME  ."),
            Span::styled(
                format!("{name}█"),
                Style::default().fg(Color::Yellow).bold(),
            ),
        ]),
        Line::from(vec![
            Span::raw("  TLS   "),
            Span::styled(
                if tls { "[x] mkcert" } else { "[ ] off" }.to_string(),
                Style::default().fg(if tls { Color::Green } else { Color::Gray }),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  [Tab] toggle TLS  [Enter] add (admin)  [Esc] cancel",
            Style::default().fg(Color::Gray),
        )),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(" add TLD ")
        .border_style(Style::default().fg(Color::Yellow));
    f.render_widget(Paragraph::new(lines).block(block), modal);
}

fn render_confirm_bridge_disable(f: &mut ratatui::Frame<'_>, area: Rect) {
    let modal = centered_rect(area, 62, 10);
    f.render_widget(Clear, modal);
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Disable the v1 netbridge?",
            Style::default().fg(Color::Yellow).bold(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  This tears down the Portman tunnel and persists netbridge=off.",
            Style::default().fg(Color::Gray),
        )),
        Line::from(Span::styled(
            "  Containers stay attached to the docker network, but host routes go away.",
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  [y] disable   [n] keep running   [Esc] cancel",
            Style::default().fg(Color::Gray),
        )),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(" confirm netbridge disable ")
        .border_style(Style::default().fg(Color::Yellow));
    f.render_widget(Paragraph::new(lines).block(block), modal);
}

fn render_help(f: &mut ratatui::Frame<'_>, area: Rect) {
    let modal = centered_rect(area, 62, 23);
    f.render_widget(Clear, modal);
    let lines = vec![
        Line::from(""),
        Line::from("  Panels"),
        Line::from("    1 / 2 / 3       focus Status / Entries / TLDs"),
        Line::from("    Tab / Shift-Tab cycle panels forward / backward"),
        Line::from(""),
        Line::from("  Navigation"),
        Line::from("    j / k  or ↑ ↓   move selection"),
        Line::from("    g / G           first / last"),
        Line::from(""),
        Line::from("  Actions"),
        Line::from("    a               add (context-sensitive)"),
        Line::from("    d               delete (static entries / TLDs only)"),
        Line::from("    t               toggle TLS (on selected TLD)"),
        Line::from("    b               enable netbridge; disabling asks for confirmation"),
        Line::from("    o               open URL in browser"),
        Line::from("    c               copy URL to clipboard"),
        Line::from("    r               refresh"),
        Line::from(""),
        Line::from("  [?] or [Esc] to close   ·   [q] to quit"),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(" help ")
        .border_style(Style::default().fg(Color::Yellow));
    f.render_widget(Paragraph::new(lines).block(block), modal);
}

fn centered_rect(area: Rect, width_pct: u16, height: u16) -> Rect {
    // split() returns an Rc<[Rect]> that dies at the end of the expression,
    // so we have to let-bind it before indexing and copying out the Rect.
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(area.height.saturating_sub(height) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);
    let popup = v[1];
    let h = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width_pct) / 2),
            Constraint::Percentage(width_pct),
            Constraint::Percentage((100 - width_pct) / 2),
        ])
        .split(popup);
    h[1]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Rebuilt once per refresh (not per frame): the render path used to
/// lowercase + format! per entry x per TLD on every draw.
fn compute_schemes(
    entries: &[Entry],
    tlds: &[TldInfo],
) -> std::collections::HashMap<String, &'static str> {
    let lowered: Vec<(String, String, bool)> = tlds
        .iter()
        .map(|t| {
            let name = t.name.to_ascii_lowercase();
            let suffix = format!(".{name}");
            (name, suffix, t.tls_mode == portman_protocol::TlsMode::Off)
        })
        .collect();
    entries
        .iter()
        .map(|entry| {
            let scheme = if entry.mode == Mode::Tcp {
                "tcp"
            } else {
                let host = entry.host.to_ascii_lowercase();
                lowered
                    .iter()
                    .find(|(name, suffix, _)| host == *name || host.ends_with(suffix))
                    .map(|(_, _, plain)| if *plain { "http" } else { "https" })
                    .unwrap_or("http")
            };
            (entry.host.clone(), scheme)
        })
        .collect()
}

fn tld_of(host: &str) -> String {
    if let Some(idx) = host.find('.') {
        host[idx + 1..].to_string()
    } else {
        String::new()
    }
}

fn activity_container_label(row: &ContainerResourceUsage) -> String {
    match (&row.compose_project, &row.compose_service) {
        (Some(project), Some(service)) => format!("{project}/{service}"),
        _ if !row.name.is_empty() => row.name.clone(),
        _ => row.id.chars().take(12).collect(),
    }
}

fn copy_to_clipboard(s: &str) -> Result<()> {
    let mut child = std::process::Command::new("pbcopy")
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(s.as_bytes())?;
    }
    child.wait()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use portman_protocol::ContainerResourceUsage;

    use super::*;

    #[test]
    fn activity_label_prefers_compose_project_and_service() {
        let row = ContainerResourceUsage {
            id: "abcdef1234567890".to_string(),
            name: "dev-web-1".to_string(),
            image: "ruby:3.3".to_string(),
            compose_project: Some("dev".to_string()),
            compose_service: Some("web".to_string()),
            ..Default::default()
        };

        assert_eq!(activity_container_label(&row), "dev/web");
    }

    #[test]
    fn resource_bytes_are_compact_binary_units() {
        assert_eq!(format_resource_bytes(512), "512B");
        assert_eq!(format_resource_bytes(1_048_576), "1.0MiB");
    }
}

#[cfg(test)]
mod log_view_tests {
    use super::*;

    fn line(id: i64, text: &str) -> LogLineInfo {
        LogLineInfo {
            id,
            ts_ms: 0,
            stream: "stdout".into(),
            line: text.into(),
        }
    }

    #[test]
    fn cursor_advances_monotonically() {
        let mut view = LogView::new("svc".into());
        view.ingest(&[line(1, "a"), line(2, "b")], 2);
        assert_eq!(view.cursor, 2);
        // A stale / empty poll can never move the cursor backwards.
        view.ingest(&[], 0);
        assert_eq!(view.cursor, 2);
        view.ingest(&[line(3, "c")], 3);
        assert_eq!(view.cursor, 3);
    }

    #[test]
    fn scrollback_is_capped() {
        let mut view = LogView::new("svc".into());
        for i in 0..(LOG_SCROLLBACK_LINES as i64 + 500) {
            view.ingest(&[line(i, &format!("l{i}"))], i);
        }
        assert_eq!(view.lines.len(), LOG_SCROLLBACK_LINES);
        // Oldest lines dropped, newest kept.
        assert_eq!(
            view.lines.back().unwrap().1,
            format!("l{}", LOG_SCROLLBACK_LINES + 499)
        );
    }

    #[test]
    fn switching_services_resets_buffer_and_cursor() {
        let mut view = LogView::new("one".into());
        view.ingest(&[line(9, "old")], 9);
        assert!(!view.lines.is_empty());

        // Opening another service constructs a fresh view (see the Enter
        // handler) — nothing carries over.
        view = LogView::new("two".into());
        assert_eq!(view.service, "two");
        assert_eq!(view.cursor, 0);
        assert!(view.lines.is_empty());
        assert!(view.follow);
        assert!(!view.primed);
    }

    #[test]
    fn scrolling_up_pauses_follow_and_bottom_resumes() {
        let mut view = LogView::new("svc".into());
        for i in 0..10 {
            view.ingest(&[line(i, "x")], i);
        }
        assert!(view.follow);

        view.scroll_up(3);
        assert!(!view.follow);
        assert_eq!(view.scroll_from_bottom, 3);

        // New lines keep the viewport anchored while paused.
        view.ingest(&[line(10, "y"), line(11, "z")], 11);
        assert_eq!(view.scroll_from_bottom, 5);

        view.scroll_down(4);
        assert!(!view.follow);
        view.scroll_down(1);
        assert!(view.follow);
        assert_eq!(view.scroll_from_bottom, 0);

        view.scroll_up(2);
        view.jump_to_bottom();
        assert!(view.follow);
        assert_eq!(view.scroll_from_bottom, 0);
    }

    #[test]
    fn scroll_up_clamps_to_buffer() {
        let mut view = LogView::new("svc".into());
        for i in 0..5 {
            view.ingest(&[line(i, "x")], i);
        }
        view.scroll_up(100);
        assert_eq!(view.scroll_from_bottom, 4);
    }
}
