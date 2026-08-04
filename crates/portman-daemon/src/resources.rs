use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::models::{
    ContainerBlkioStats, ContainerCpuStats, ContainerMemoryStats, ContainerNetworkStats,
    ContainerStatsResponse, ContainerSummary,
};
use bollard::query_parameters::{ListContainersOptionsBuilder, StatsOptionsBuilder};
use futures_util::StreamExt;
use portman_protocol::{
    ContainerResourceUsage, HistoryPoint, ResourceSeries, ResourceUsageSnapshot,
    ResourceUsageTotals, SeriesKind, ServiceResourceUsage,
};
use tokio::sync::Mutex;

use crate::supervisor::RunningGroup;
use crate::DaemonState;

pub(crate) type SharedSamples = Arc<Mutex<HashMap<String, ResourceSample>>>;

pub(crate) fn new_shared_samples() -> SharedSamples {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Persistent sysinfo handle for supervised-service sampling. Keeping one
/// `System` across `collect()` calls makes `cpu_usage()` a delta over the
/// existing poll cadence (TUI 2 s, dashboard 5 s) — same window semantics
/// as the docker sampler (KTD5).
pub(crate) type SharedSystem = Arc<std::sync::Mutex<sysinfo::System>>;

pub(crate) fn new_shared_system() -> SharedSystem {
    Arc::new(std::sync::Mutex::new(sysinfo::System::new()))
}

/// How often the background sampler ticks. Also the resolution of every
/// retained series — clients see values refresh on this clock, whatever their
/// own poll cadence.
pub(crate) const SAMPLE_PERIOD: Duration = Duration::from_secs(5);
/// Points kept per series: 120 × 5s ≈ 10 minutes.
const HISTORY_CAPACITY: usize = 120;

/// Retained sampling state: the latest snapshot (what `ResourceUsage` now
/// answers with) plus a bounded time series per service, container, and the
/// machine-wide total.
///
/// `std::sync::Mutex`, same rationale as `bridge_health::Shared` — the writes
/// are microsecond-scale swaps and the sync IPC handlers read without
/// awaiting.
#[derive(Default)]
pub(crate) struct HistoryState {
    latest: ResourceUsageSnapshot,
    series: BTreeMap<(SeriesKind, String), VecDeque<HistoryPoint>>,
}

pub(crate) type SharedHistory = Arc<std::sync::Mutex<HistoryState>>;

pub(crate) fn new_shared_history() -> SharedHistory {
    Arc::new(std::sync::Mutex::new(HistoryState::default()))
}

/// Latest retained snapshot. What `Request::ResourceUsage` serves — requests
/// never sample, so they can't steal the sampler's delta baselines.
pub(crate) fn latest_snapshot(history: &SharedHistory) -> ResourceUsageSnapshot {
    history
        .lock()
        .expect("history lock poisoned")
        .latest
        .clone()
}

/// All retained series, oldest point first.
pub(crate) fn history_series(history: &SharedHistory) -> Vec<ResourceSeries> {
    let guard = history.lock().expect("history lock poisoned");
    guard
        .series
        .iter()
        .map(|((kind, key), points)| ResourceSeries {
            key: key.clone(),
            kind: *kind,
            points: points.iter().copied().collect(),
        })
        .collect()
}

/// Fold one snapshot into the history: append a point to every live series,
/// evict past capacity, and drop series that have aged out entirely.
fn record_snapshot(state: &mut HistoryState, snapshot: ResourceUsageSnapshot) {
    let t_ms = snapshot.sampled_at_unix_ms;
    let mut push = |kind: SeriesKind, key: &str, cpu: f64, mem: u64| {
        let points = state
            .series
            .entry((kind, key.to_string()))
            .or_insert_with(|| VecDeque::with_capacity(HISTORY_CAPACITY));
        points.push_back(HistoryPoint {
            t_ms,
            cpu_percent: cpu,
            memory_usage_bytes: mem,
        });
        while points.len() > HISTORY_CAPACITY {
            points.pop_front();
        }
    };

    push(
        SeriesKind::Total,
        "total",
        snapshot.totals.cpu_percent,
        snapshot.totals.memory_usage_bytes,
    );
    for c in &snapshot.containers {
        push(
            SeriesKind::Container,
            &c.id,
            c.cpu_percent,
            c.memory_usage_bytes,
        );
    }
    for s in &snapshot.services {
        push(
            SeriesKind::Service,
            &s.name,
            s.cpu_percent,
            s.memory_usage_bytes,
        );
    }

    // A stopped service/container stops getting points; once its newest point
    // falls out of the retention window, drop the whole series rather than
    // pinning a stale tail forever.
    let horizon = t_ms.saturating_sub(SAMPLE_PERIOD.as_millis() as u64 * HISTORY_CAPACITY as u64);
    state
        .series
        .retain(|_, points| points.back().is_some_and(|p| p.t_ms >= horizon));

    state.latest = snapshot;
}

/// Long-running sampler task — the *single* sampling authority. Everything
/// that used to sample on demand (IPC, dashboard, TUI) now reads what this
/// task retained; two samplers sharing the delta baselines would compute CPU
/// over near-zero windows.
///
/// `collect()` is cheap when nothing runs (one `list_containers`, no stats
/// streams, no pgid sweep), so the idle tick is a non-issue.
pub(crate) async fn run_sampler(state: crate::DaemonState, history: SharedHistory) -> Result<()> {
    let mut ticker = tokio::time::interval(SAMPLE_PERIOD);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match collect(&state).await {
            Ok(snapshot) => {
                let mut guard = history.lock().expect("history lock poisoned");
                record_snapshot(&mut guard, snapshot);
            }
            Err(err) => {
                // Docker down is the common cause; keep the last snapshot and
                // series intact rather than publishing zeros.
                tracing::debug!(error = %err, "resource sample skipped");
            }
        }
    }
}

/// Sample the supervised process groups: membership by `getpgid` across
/// sysinfo's pid table (sysinfo exposes no process-group accessor, and
/// parent-link walking undercounts members that reparent), then CPU/RSS
/// summed per matched pid.
fn sample_service_groups(
    system: &mut sysinfo::System,
    groups: &[RunningGroup],
) -> Vec<ServiceResourceUsage> {
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    // pid → pgid, resolved once for the whole table.
    let mut pgid_of: HashMap<sysinfo::Pid, i32> = HashMap::with_capacity(system.processes().len());
    for pid in system.processes().keys() {
        let raw = nix::unistd::Pid::from_raw(pid.as_u32() as i32);
        if let Ok(pgid) = nix::unistd::getpgid(Some(raw)) {
            pgid_of.insert(*pid, pgid.as_raw());
        }
    }

    let mut rows: Vec<ServiceResourceUsage> = groups
        .iter()
        .map(|group| {
            let mut usage = ServiceResourceUsage {
                name: group.name.clone(),
                host: group.host.clone(),
                pid: Some(group.pid),
                ..Default::default()
            };
            for (pid, process) in system.processes() {
                if pgid_of.get(pid) == Some(&group.pgid) {
                    usage.cpu_percent += f64::from(process.cpu_usage());
                    usage.memory_usage_bytes += process.memory();
                    usage.pids_current += 1;
                }
            }
            usage
        })
        .collect();
    rows.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });
    rows
}

pub(crate) async fn collect(state: &DaemonState) -> Result<ResourceUsageSnapshot> {
    let mut filters = HashMap::new();
    filters.insert("status".to_string(), vec!["running".to_string()]);
    let options = ListContainersOptionsBuilder::default()
        .all(true)
        .filters(&filters)
        .build();
    let summaries = state
        .docker
        .list_containers(Some(options))
        .await
        .context("listing running containers")?;

    let previous_samples = state.resource_samples.lock().await.clone();
    let host_index = portman_hosts_by_container_id(&state.registry.list());
    let mut next_samples = HashMap::new();
    let mut rows = Vec::with_capacity(summaries.len());
    let mut sample_window_ms = 0_u64;

    // Every container's `docker stats` is independent — awaited sequentially
    // the tick grew ~N x stats latency and quietly ate into the 5s sample
    // period as the fleet grew.
    let collected = futures_util::future::join_all(summaries.iter().filter_map(|summary| {
        let id = summary.id.as_deref()?;
        let previous = previous_samples.get(id).copied();
        let hosts = portman_hosts_for_container(id, &host_index);
        Some(async move {
            (
                id.to_string(),
                previous,
                collect_container(state, summary, previous, hosts).await,
            )
        })
    }))
    .await;
    for (id, previous, (row, sample)) in collected {
        if let Some(sample) = sample {
            if let Some(previous) = previous {
                sample_window_ms = sample_window_ms.max(
                    sample
                        .sampled_at_unix_ms
                        .saturating_sub(previous.sampled_at_unix_ms),
                );
            }
            next_samples.insert(id, sample);
        }
        rows.push(row);
    }

    *state.resource_samples.lock().await = next_samples;
    rows.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.memory_usage_bytes.cmp(&a.memory_usage_bytes))
            .then_with(|| a.name.cmp(&b.name))
    });

    // Supervised services ride the same on-demand path; the pgid sweep is
    // bounded per-pid work, moved off the reactor.
    let groups = state.supervisor.running_groups();
    let services = if groups.is_empty() {
        Vec::new()
    } else {
        let system = state.service_sampler.clone();
        match tokio::task::spawn_blocking(move || {
            let mut system = system.lock().expect("service sampler lock poisoned");
            sample_service_groups(&mut system, &groups)
        })
        .await
        {
            Ok(rows) => rows,
            Err(err) => {
                // A sampler panic used to become silently blank service
                // metrics; at least say what happened.
                tracing::warn!(%err, "service sampler task failed; service metrics blank this tick");
                Vec::new()
            }
        }
    };

    let totals = totals_for(&rows);
    Ok(ResourceUsageSnapshot {
        sampled_at_unix_ms: crate::now_unix_ms(),
        sample_window_ms,
        container_count: rows.len() as u32,
        totals,
        containers: rows,
        services,
    })
}

async fn collect_container(
    state: &DaemonState,
    summary: &ContainerSummary,
    previous: Option<ResourceSample>,
    portman_hosts: Vec<String>,
) -> (ContainerResourceUsage, Option<ResourceSample>) {
    let id = summary.id.clone().unwrap_or_default();
    let base = ContainerBase::from_summary(summary, portman_hosts);
    let mut stream = state.docker.stats(
        &id,
        Some(
            StatsOptionsBuilder::default()
                .stream(false)
                .one_shot(true)
                .build(),
        ),
    );

    match stream.next().await {
        Some(Ok(stats)) => usage_from_stats(base, stats, previous),
        Some(Err(err)) => (base.error(err.to_string()), None),
        None => (
            base.error("docker stats returned no sample".to_string()),
            None,
        ),
    }
}

fn usage_from_stats(
    base: ContainerBase,
    stats: ContainerStatsResponse,
    previous: Option<ResourceSample>,
) -> (ContainerResourceUsage, Option<ResourceSample>) {
    let (network_rx_bytes, network_tx_bytes) = network_totals(stats.networks.as_ref());
    let (block_read_bytes, block_write_bytes) = block_io_totals(stats.blkio_stats.as_ref());
    let current = stats_sample(
        stats.cpu_stats.as_ref(),
        network_rx_bytes,
        network_tx_bytes,
        block_read_bytes,
        block_write_bytes,
    );
    let sample_window_ms = current
        .zip(previous)
        .map(|(current, previous)| {
            current
                .sampled_at_unix_ms
                .saturating_sub(previous.sampled_at_unix_ms)
        })
        .unwrap_or_default();
    let cpu_percent = current
        .map(|sample| calculate_cpu_percent(sample, previous))
        .unwrap_or_default();
    let (memory_usage_bytes, memory_limit_bytes) = memory_usage(stats.memory_stats.as_ref());
    let pids_current = stats.pids_stats.and_then(|p| p.current);
    let (network_rx_rate_bytes_per_sec, network_tx_rate_bytes_per_sec) = previous
        .map(|previous| {
            (
                counter_rate_per_second(
                    network_rx_bytes,
                    previous.network_rx_bytes,
                    sample_window_ms,
                ),
                counter_rate_per_second(
                    network_tx_bytes,
                    previous.network_tx_bytes,
                    sample_window_ms,
                ),
            )
        })
        .unwrap_or_default();
    let (block_read_rate_bytes_per_sec, block_write_rate_bytes_per_sec) = previous
        .map(|previous| {
            (
                counter_rate_per_second(
                    block_read_bytes,
                    previous.block_read_bytes,
                    sample_window_ms,
                ),
                counter_rate_per_second(
                    block_write_bytes,
                    previous.block_write_bytes,
                    sample_window_ms,
                ),
            )
        })
        .unwrap_or_default();

    (
        ContainerResourceUsage {
            id: base.id,
            name: base.name,
            image: base.image,
            state: base.state,
            portman_hosts: base.portman_hosts,
            compose_project: base.compose_project,
            compose_service: base.compose_service,
            project: base.project,
            cpu_percent,
            memory_usage_bytes,
            memory_limit_bytes,
            network_rx_bytes,
            network_tx_bytes,
            network_rx_rate_bytes_per_sec,
            network_tx_rate_bytes_per_sec,
            block_read_bytes,
            block_write_bytes,
            block_read_rate_bytes_per_sec,
            block_write_rate_bytes_per_sec,
            pids_current,
            error: None,
        },
        current,
    )
}

fn totals_for(rows: &[ContainerResourceUsage]) -> ResourceUsageTotals {
    ResourceUsageTotals {
        cpu_percent: rows.iter().map(|row| row.cpu_percent).sum(),
        memory_usage_bytes: rows.iter().map(|row| row.memory_usage_bytes).sum(),
        network_rx_bytes: rows.iter().map(|row| row.network_rx_bytes).sum(),
        network_tx_bytes: rows.iter().map(|row| row.network_tx_bytes).sum(),
        network_rx_rate_bytes_per_sec: rows
            .iter()
            .map(|row| row.network_rx_rate_bytes_per_sec)
            .sum(),
        network_tx_rate_bytes_per_sec: rows
            .iter()
            .map(|row| row.network_tx_rate_bytes_per_sec)
            .sum(),
        block_read_bytes: rows.iter().map(|row| row.block_read_bytes).sum(),
        block_write_bytes: rows.iter().map(|row| row.block_write_bytes).sum(),
        block_read_rate_bytes_per_sec: rows
            .iter()
            .map(|row| row.block_read_rate_bytes_per_sec)
            .sum(),
        block_write_rate_bytes_per_sec: rows
            .iter()
            .map(|row| row.block_write_rate_bytes_per_sec)
            .sum(),
        pids_current: rows
            .iter()
            .map(|row| row.pids_current.unwrap_or_default())
            .sum(),
    }
}

fn portman_hosts_by_container_id(
    entries: &[portman_protocol::Entry],
) -> HashMap<String, Vec<String>> {
    let mut hosts_by_short_id: HashMap<&str, Vec<String>> = HashMap::new();
    for entry in entries {
        if let Some(id) = entry.container_id.as_deref() {
            hosts_by_short_id
                .entry(id)
                .or_default()
                .push(entry.host.clone());
        }
    }

    hosts_by_short_id
        .into_iter()
        .map(|(id, mut hosts)| {
            hosts.sort();
            (id.to_string(), hosts)
        })
        .collect()
}

fn portman_hosts_for_container(
    container_id: &str,
    hosts_by_short_id: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    hosts_by_short_id
        .iter()
        .find_map(|(short_id, hosts)| {
            if container_id.starts_with(short_id) {
                Some(hosts.clone())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
struct ContainerBase {
    id: String,
    name: String,
    image: String,
    state: String,
    portman_hosts: Vec<String>,
    compose_project: Option<String>,
    compose_service: Option<String>,
    project: Option<String>,
}

impl ContainerBase {
    fn from_summary(summary: &ContainerSummary, portman_hosts: Vec<String>) -> Self {
        let labels = summary.labels.as_ref();
        Self {
            id: summary.id.clone().unwrap_or_default(),
            name: summary
                .names
                .as_ref()
                .and_then(|names| names.first())
                .map(|name| name.trim_start_matches('/').to_string())
                .unwrap_or_else(|| summary.id.as_deref().map(short).unwrap_or("?").to_string()),
            image: summary.image.clone().unwrap_or_default(),
            state: summary
                .state
                .map(|state| state.to_string())
                .unwrap_or_default(),
            portman_hosts,
            compose_project: labels
                .and_then(|l| l.get("com.docker.compose.project"))
                .cloned(),
            compose_service: labels
                .and_then(|l| l.get("com.docker.compose.service"))
                .cloned(),
            project: labels.and_then(|l| l.get("dev.portman.project")).cloned(),
        }
    }

    fn error(self, message: String) -> ContainerResourceUsage {
        ContainerResourceUsage {
            id: self.id,
            name: self.name,
            image: self.image,
            state: self.state,
            portman_hosts: self.portman_hosts,
            compose_project: self.compose_project,
            compose_service: self.compose_service,
            error: Some(message),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResourceSample {
    total_usage: u64,
    system_usage: u64,
    online_cpus: u32,
    network_rx_bytes: u64,
    network_tx_bytes: u64,
    block_read_bytes: u64,
    block_write_bytes: u64,
    sampled_at_unix_ms: u64,
}

fn stats_sample(
    stats: Option<&ContainerCpuStats>,
    network_rx_bytes: u64,
    network_tx_bytes: u64,
    block_read_bytes: u64,
    block_write_bytes: u64,
) -> Option<ResourceSample> {
    let stats = stats?;
    let usage = stats.cpu_usage.as_ref()?;
    let total_usage = usage.total_usage?;
    let system_usage = stats.system_cpu_usage?;
    let online_cpus = stats
        .online_cpus
        .filter(|cpus| *cpus > 0)
        .or_else(|| usage.percpu_usage.as_ref().map(|cpus| cpus.len() as u32))
        .filter(|cpus| *cpus > 0)
        .unwrap_or(1);

    Some(ResourceSample {
        total_usage,
        system_usage,
        online_cpus,
        network_rx_bytes,
        network_tx_bytes,
        block_read_bytes,
        block_write_bytes,
        sampled_at_unix_ms: crate::now_unix_ms(),
    })
}

pub(crate) fn calculate_cpu_percent(
    current: ResourceSample,
    previous: Option<ResourceSample>,
) -> f64 {
    let Some(previous) = previous else {
        return 0.0;
    };
    let cpu_delta = current.total_usage.saturating_sub(previous.total_usage);
    let system_delta = current.system_usage.saturating_sub(previous.system_usage);
    if cpu_delta == 0 || system_delta == 0 {
        return 0.0;
    }

    (cpu_delta as f64 / system_delta as f64) * current.online_cpus as f64 * 100.0
}

pub(crate) fn counter_rate_per_second(current: u64, previous: u64, sample_window_ms: u64) -> f64 {
    if sample_window_ms == 0 || current < previous {
        return 0.0;
    }
    (current - previous) as f64 / (sample_window_ms as f64 / 1000.0)
}

fn memory_usage(stats: Option<&ContainerMemoryStats>) -> (u64, Option<u64>) {
    let Some(stats) = stats else {
        return (0, None);
    };
    (
        memory_working_set(stats.usage.unwrap_or_default(), stats.stats.as_ref()),
        stats.limit,
    )
}

pub(crate) fn memory_working_set(usage: u64, stats: Option<&HashMap<String, u64>>) -> u64 {
    let cache = stats
        .and_then(|stats| {
            stats
                .get("inactive_file")
                .or_else(|| stats.get("total_inactive_file"))
                .or_else(|| stats.get("cache"))
        })
        .copied()
        .unwrap_or_default();
    usage.saturating_sub(cache)
}

pub(crate) fn network_totals(
    networks: Option<&HashMap<String, ContainerNetworkStats>>,
) -> (u64, u64) {
    networks
        .map(|networks| {
            networks.values().fold((0_u64, 0_u64), |(rx, tx), network| {
                (
                    rx + network.rx_bytes.unwrap_or_default(),
                    tx + network.tx_bytes.unwrap_or_default(),
                )
            })
        })
        .unwrap_or_default()
}

pub(crate) fn block_io_totals(stats: Option<&ContainerBlkioStats>) -> (u64, u64) {
    let Some(entries) = stats.and_then(|stats| stats.io_service_bytes_recursive.as_ref()) else {
        return (0, 0);
    };

    entries.iter().fold((0_u64, 0_u64), |(read, write), entry| {
        match entry.op.as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("read") => (read + entry.value.unwrap_or_default(), write),
            Some("write") => (read, write + entry.value.unwrap_or_default()),
            _ => (read, write),
        }
    })
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bollard::models::{ContainerBlkioStatEntry, ContainerBlkioStats, ContainerNetworkStats};
    use portman_protocol::{Entry, Mode, Source};

    use super::*;

    #[test]
    fn cpu_percent_uses_counter_delta_and_online_cpus() {
        let previous = sample(100, 1_000, 4, 1_000);
        let current = sample(300, 2_000, 4, 2_000);

        assert_eq!(calculate_cpu_percent(current, Some(previous)), 80.0);
    }

    #[test]
    fn cpu_percent_is_zero_without_a_previous_sample() {
        let current = sample(300, 2_000, 4, 2_000);

        assert_eq!(calculate_cpu_percent(current, None), 0.0);
    }

    #[test]
    fn memory_working_set_subtracts_inactive_file_without_underflowing() {
        let stats = HashMap::from([("inactive_file".to_string(), 64_u64)]);

        assert_eq!(memory_working_set(256, Some(&stats)), 192);
        assert_eq!(memory_working_set(32, Some(&stats)), 0);
    }

    #[test]
    fn network_totals_sum_all_interfaces() {
        let networks = HashMap::from([
            (
                "eth0".to_string(),
                ContainerNetworkStats {
                    rx_bytes: Some(10),
                    tx_bytes: Some(20),
                    ..Default::default()
                },
            ),
            (
                "eth1".to_string(),
                ContainerNetworkStats {
                    rx_bytes: Some(30),
                    tx_bytes: Some(40),
                    ..Default::default()
                },
            ),
        ]);

        assert_eq!(network_totals(Some(&networks)), (40, 60));
    }

    #[test]
    fn block_io_totals_sum_read_and_write_entries_case_insensitively() {
        let stats = ContainerBlkioStats {
            io_service_bytes_recursive: Some(vec![
                block_entry("Read", 10),
                block_entry("read", 20),
                block_entry("Write", 40),
                block_entry("Sync", 80),
            ]),
            ..Default::default()
        };

        assert_eq!(block_io_totals(Some(&stats)), (30, 40));
    }

    #[test]
    fn counter_rate_uses_sample_window_seconds() {
        assert_eq!(counter_rate_per_second(3_000, 1_000, 2_000), 1_000.0);
        assert_eq!(counter_rate_per_second(1_000, 3_000, 2_000), 0.0);
        assert_eq!(counter_rate_per_second(3_000, 1_000, 0), 0.0);
    }

    #[test]
    fn portman_hosts_match_short_ids_against_full_container_ids() {
        let entries = vec![
            Entry {
                host: "api.test".to_string(),
                target: "172.18.0.4:3000".to_string(),
                source: Source::Container,
                mode: Mode::Http,
                container_id: Some("abcdef123456".to_string()),
                project: None,
            },
            Entry {
                host: "mail.test".to_string(),
                target: "127.0.0.1:1025".to_string(),
                source: Source::Static,
                mode: Mode::Http,
                container_id: None,
                project: None,
            },
        ];
        let index = portman_hosts_by_container_id(&entries);

        assert_eq!(
            portman_hosts_for_container("abcdef1234567890", &index),
            vec!["api.test".to_string()]
        );
    }

    fn block_entry(op: &str, value: u64) -> ContainerBlkioStatEntry {
        ContainerBlkioStatEntry {
            op: Some(op.to_string()),
            value: Some(value),
            ..Default::default()
        }
    }

    fn sample(
        total_usage: u64,
        system_usage: u64,
        online_cpus: u32,
        sampled_at_unix_ms: u64,
    ) -> ResourceSample {
        ResourceSample {
            total_usage,
            system_usage,
            online_cpus,
            network_rx_bytes: 0,
            network_tx_bytes: 0,
            block_read_bytes: 0,
            block_write_bytes: 0,
            sampled_at_unix_ms,
        }
    }
}

#[cfg(test)]
mod service_sampling_tests {
    use super::*;

    /// A spawned multi-process tree (leader + children in one group)
    /// reports pids >= 2 and nonzero memory.
    #[test]
    fn multi_process_group_reports_members_and_memory() {
        use std::os::unix::process::CommandExt as _;

        let mut leader = std::process::Command::new("/bin/sh");
        leader
            .args(["-c", "sleep 5 & sleep 5 & wait"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .process_group(0);
        let mut child = leader.spawn().unwrap();
        let pid = child.id();

        let mut system = sysinfo::System::new();
        let groups = vec![RunningGroup {
            name: "tree".into(),
            host: Some("tree.internal".into()),
            pid,
            pgid: pid as i32,
        }];
        // Poll until the shell has forked its children (slow under load).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let rows = loop {
            let rows = sample_service_groups(&mut system, &groups);
            if rows[0].pids_current >= 2 || std::time::Instant::now() > deadline {
                break rows;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        };

        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.name, "tree");
        assert_eq!(row.host.as_deref(), Some("tree.internal"));
        assert!(
            row.pids_current >= 2,
            "expected the whole group, got {} pids",
            row.pids_current
        );
        assert!(row.memory_usage_bytes > 0);

        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        );
        let _ = child.wait();
    }

    /// No running groups -> no rows (a stopped service has no marker, so it
    /// never reaches the sampler).
    #[test]
    fn no_groups_no_rows() {
        let mut system = sysinfo::System::new();
        assert!(sample_service_groups(&mut system, &[]).is_empty());
    }

    /// A group whose processes are gone still yields its row (the
    /// supervisor considers it running) with zeroed gauges.
    #[test]
    fn dead_group_reports_zeroes() {
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();

        let mut system = sysinfo::System::new();
        let groups = vec![RunningGroup {
            name: "ghost".into(),
            host: None,
            pid,
            pgid: pid as i32,
        }];
        let rows = sample_service_groups(&mut system, &groups);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pids_current, 0);
        assert_eq!(rows[0].memory_usage_bytes, 0);
    }

    fn snapshot_at(t_ms: u64, services: Vec<(&str, f64, u64)>) -> ResourceUsageSnapshot {
        ResourceUsageSnapshot {
            sampled_at_unix_ms: t_ms,
            services: services
                .into_iter()
                .map(|(name, cpu, mem)| ServiceResourceUsage {
                    name: name.into(),
                    cpu_percent: cpu,
                    memory_usage_bytes: mem,
                    ..Default::default()
                })
                .collect(),
            totals: ResourceUsageTotals {
                cpu_percent: 1.0,
                memory_usage_bytes: 100,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn history_appends_in_order_and_evicts_past_capacity() {
        let mut state = HistoryState::default();
        // Two windows past capacity, so eviction has to actually engage.
        let n = HISTORY_CAPACITY as u64 + 40;
        for i in 0..n {
            record_snapshot(&mut state, snapshot_at(i * 5_000, vec![("web", 1.0, 10)]));
        }
        let series = &state.series[&(SeriesKind::Service, "web".to_string())];
        assert_eq!(series.len(), HISTORY_CAPACITY);
        // Oldest first, newest last — the eviction dropped the front.
        assert_eq!(series.back().unwrap().t_ms, (n - 1) * 5_000);
        assert!(series
            .iter()
            .zip(series.iter().skip(1))
            .all(|(a, b)| a.t_ms < b.t_ms));
    }

    #[test]
    fn a_stopped_services_series_ages_out_instead_of_pinning_stale_values() {
        let mut state = HistoryState::default();
        record_snapshot(&mut state, snapshot_at(0, vec![("web", 1.0, 10)]));
        assert!(state
            .series
            .contains_key(&(SeriesKind::Service, "web".to_string())));

        // web stops; ticks continue without it until the retention window has
        // fully passed its last point.
        let window = SAMPLE_PERIOD.as_millis() as u64 * HISTORY_CAPACITY as u64;
        record_snapshot(&mut state, snapshot_at(window + 5_000, vec![]));
        assert!(
            !state
                .series
                .contains_key(&(SeriesKind::Service, "web".to_string())),
            "series should age out, not pin its last value forever"
        );
        // The total series lives on — it got a fresh point.
        assert!(state
            .series
            .contains_key(&(SeriesKind::Total, "total".to_string())));
    }

    #[test]
    fn latest_snapshot_is_what_the_sampler_retained() {
        let history = new_shared_history();
        {
            let mut guard = history.lock().unwrap();
            record_snapshot(&mut guard, snapshot_at(42_000, vec![("web", 3.5, 77)]));
        }
        let snap = latest_snapshot(&history);
        assert_eq!(snap.sampled_at_unix_ms, 42_000);
        assert_eq!(snap.services.len(), 1);
        // And the series endpoint hands the same data back oldest-first.
        let series = history_series(&history);
        assert!(series
            .iter()
            .any(|s| s.kind == SeriesKind::Service && s.key == "web" && s.points.len() == 1));
    }
}
