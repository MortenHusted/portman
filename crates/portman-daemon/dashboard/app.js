const API = '/api';

async function api(path, options = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const data = await res.json();
  if (!res.ok || data.kind === 'err') {
    throw new Error(data.message || res.statusText);
  }
  return data;
}

function el(id) { return document.getElementById(id); }

function esc(text) {
  const div = document.createElement('div');
  div.textContent = String(text ?? '');
  return div.innerHTML;
}

function formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function timeOf(t_ms) {
  const d = new Date(t_ms);
  return d.toTimeString().slice(0, 8);
}

// --- State -----------------------------------------------------------------

let allEntries = [];
let allTlds = [];
let services = [];
let historySeries = [];
let gauges = new Map();          // service name → ServiceResourceUsage
let snapshotTotals = { containers: 0, cpu: 0, mem: 0 };
let selected = null;             // { kind: 'service' | 'container', key }
let containers = [];
const collapsedGroups = new Set();
const expandedGroups = new Set(); // groups with "show more" expanded
let routesExpanded = false;
const ROW_LIMIT = 6;
const ROUTE_LIMIT = 8;

function groupsOf(s) {
  if (s.groups && s.groups.length) return s.groups;
  const base = String(s.root || '').split('/').filter(Boolean).pop();
  return [base || 'ungrouped'];
}

function serviceSeries(name) {
  return historySeries.find(s => s.kind === 'service' && s.key === name);
}

function totalSeries() {
  return historySeries.find(s => s.kind === 'total' && s.key === 'total');
}

// --- Sparklines & charts ---------------------------------------------------

/// Y-domain ceiling. A flat series must not sit on the chart's ceiling —
/// doubling the ceiling centers it; otherwise 8% headroom keeps the peak off
/// the top gridline.
function chartMax(values) {
  const max = Math.max(...values, 1e-9);
  const min = Math.min(...values);
  if (max - min < max * 0.02) return max * 2;
  return max * 1.08;
}

function sparkSvg(values, w, h, accent) {
  if (!values.length) return '';
  const max = chartMax(values);
  const step = values.length > 1 ? w / (values.length - 1) : 0;
  const pts = values
    .map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`)
    .join(' ');
  const cls = accent ? 'spark-accent' : 'spark-muted';
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg"><polyline points="${pts}" fill="none" stroke="${accent ? 'var(--accent)' : 'var(--ink-3)'}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" class="${cls}"/></svg>`;
}

/// Line chart with wash, hairline gridlines, and a pointer-tracked
/// crosshair + tooltip. Values reachable without hover via the scale row.
function renderChart(container, points, pick, fmt) {
  container.innerHTML = '';
  if (!points || points.length < 2) {
    container.innerHTML = '<div class="chart-empty">Collecting samples…</div>';
    return;
  }
  const W = 408, H = 104, PAD = 4;
  const values = points.map(pick);
  const dataMax = Math.max(...values);
  const max = chartMax(values);
  const step = (W - PAD * 2) / (points.length - 1);
  const y = v => H - 8 - (v / max) * (H - 20);
  const x = i => PAD + i * step;
  const line = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  const area = `${x(0).toFixed(1)},${H - 8} ${line} ${x(points.length - 1).toFixed(1)},${H - 8}`;

  container.innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">
      <line class="gridline" x1="0" y1="8" x2="${W}" y2="8"></line>
      <line class="gridline" x1="0" y1="${H / 2}" x2="${W}" y2="${H / 2}"></line>
      <line class="gridline" x1="0" y1="${H - 8}" x2="${W}" y2="${H - 8}"></line>
      <polygon class="wash" points="${area}"></polygon>
      <polyline class="series" points="${line}"></polyline>
      <circle class="dot" r="4" cx="-10" cy="-10"></circle>
    </svg>
    <div class="crosshair" hidden></div>
    <div class="chart-tip" hidden><span class="tip-value"></span><span class="tip-time"></span></div>
    <div class="chart-scale"><span>${timeOf(points[0].t_ms).slice(0, 5)}</span><span>peak ${fmt(dataMax)}</span><span>${timeOf(points[points.length - 1].t_ms).slice(0, 5)}</span></div>`;

  const svg = container.querySelector('svg');
  const crosshair = container.querySelector('.crosshair');
  const tip = container.querySelector('.chart-tip');
  const tipValue = tip.querySelector('.tip-value');
  const tipTime = tip.querySelector('.tip-time');
  const dot = container.querySelector('.dot');

  svg.addEventListener('pointermove', (ev) => {
    const rect = svg.getBoundingClientRect();
    const fx = (ev.clientX - rect.left) / rect.width;
    const i = Math.max(0, Math.min(points.length - 1, Math.round(fx * (points.length - 1))));
    const px = (x(i) / W) * rect.width;
    crosshair.hidden = false;
    crosshair.style.left = px + 'px';
    crosshair.style.height = (rect.height * (H - 12) / H) + 'px';
    dot.setAttribute('cx', x(i));
    dot.setAttribute('cy', y(values[i]));
    tip.hidden = false;
    tipValue.textContent = fmt(values[i]);
    tipTime.textContent = timeOf(points[i].t_ms);
    const tx = Math.max(44, Math.min(rect.width - 44, px));
    tip.style.left = tx + 'px';
    tip.style.top = '2px';
  });
  svg.addEventListener('pointerleave', () => {
    crosshair.hidden = true;
    tip.hidden = true;
    dot.setAttribute('cx', -10);
    dot.setAttribute('cy', -10);
  });
}

// --- Alerts ----------------------------------------------------------------

const alerts = [];
function resetAlerts() { alerts.length = 0; }
function pushAlert(title, bodyHtml, severe) {
  alerts.push(`<div class="alert${severe ? ' severe' : ''}"><span class="alert-title">${esc(title)}</span>${bodyHtml}</div>`);
}
function renderAlerts() { el('alerts').innerHTML = alerts.join(''); }

function targetCollisions(entries) {
  const byTarget = new Map();
  for (const e of entries) {
    if (!byTarget.has(e.target)) byTarget.set(e.target, []);
    byTarget.get(e.target).push(e.host);
  }
  return [...byTarget.entries()]
    .filter(([, hosts]) => hosts.length > 1)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([target, hosts]) => [target, hosts.sort()]);
}

function alertCollisions() {
  const collisions = targetCollisions(allEntries);
  if (!collisions.length) return;
  const items = collisions
    .map(([target, hosts]) =>
      `<li><span class="mono">${esc(target)}</span> — ${hosts.map(h => `<span class="mono">${esc(h)}</span>`).join(', ')}</li>`)
    .join('');
  pushAlert(
    `${collisions.length} target${collisions.length > 1 ? 's' : ''} claimed by more than one hostname`,
    `<div class="alert-body">Only one process can own a port. If these are different apps, every extra hostname is serving whichever app won the bind.</div><ul>${items}</ul>`
  );
}

// --- KPI strip -------------------------------------------------------------

function renderKpis() {
  const states = services.map(s => String(s.state || '').toLowerCase());
  const ready = states.filter(s => s === 'ready').length;
  const troubled = states.filter(s => s === 'backoff' || s === 'failed').length;
  el('kpi-services').textContent = services.length || '0';
  el('kpi-services-note').textContent = services.length
    ? (troubled ? `${ready} ready · ${troubled} ${states.includes('failed') ? 'failed' : 'backoff'}` : `${ready} ready`)
    : '';

  el('kpi-containers').textContent = snapshotTotals.containers;
  el('kpi-containers-note').textContent = snapshotTotals.containers ? 'running' : '';

  el('kpi-hosts').textContent = allEntries.length;
  const wildcards = allEntries.filter(e => e.host.startsWith('*.')).length;
  el('kpi-hosts-note').textContent =
    `${wildcards ? wildcards + ' wildcard · ' : ''}${allTlds.map(t => '.' + t.name).join(' ')}`;

  const svcGauges = [...gauges.values()];
  const cpu = svcGauges.reduce((sum, u) => sum + (u.cpu_percent || 0), 0);
  const mem = svcGauges.reduce((sum, u) => sum + (u.memory_usage_bytes || 0), 0);
  el('kpi-cpu').textContent = cpu.toFixed(1) + '%';
  el('kpi-mem').textContent = formatBytes(mem);

  const total = totalSeries();
  const svcSeriesAll = historySeries.filter(s => s.kind === 'service');
  const sumByT = new Map();
  for (const s of svcSeriesAll) {
    for (const p of s.points) {
      const acc = sumByT.get(p.t_ms) || { cpu: 0, mem: 0 };
      acc.cpu += p.cpu_percent;
      acc.mem += p.memory_usage_bytes;
      sumByT.set(p.t_ms, acc);
    }
  }
  const ordered = [...sumByT.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v);
  const tail = ordered.slice(-13);
  el('kpi-cpu-spark').innerHTML = sparkSvg(tail.map(v => v.cpu), 72, 22, false);
  el('kpi-mem-spark').innerHTML = sparkSvg(tail.map(v => v.mem), 72, 22, false);
  void total;
}

// --- Service groups --------------------------------------------------------

function stateBadge(state) {
  const s = String(state || '').toLowerCase();
  return `<span class="badge ${esc(s)}">${esc(s || '?')}</span>`;
}

function renderGroups() {
  const container = el('service-groups');
  const empty = el('services-empty');
  el('services-count').textContent = services.length ? String(services.length) : '';
  container.innerHTML = '';
  empty.hidden = services.length > 0;
  if (!services.length) return;

  const groups = new Map();
  for (const s of services) {
    for (const g of groupsOf(s)) {
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(s);
    }
  }

  for (const [group, members] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    let cpu = 0, mem = 0;
    for (const m of members) {
      const u = gauges.get(m.name);
      if (u) { cpu += u.cpu_percent || 0; mem += u.memory_usage_bytes || 0; }
    }
    const states = members.map(s => String(s.state || '').toLowerCase());
    const troubled = states.filter(s => s === 'backoff' || s === 'failed').length;
    const chip = troubled
      ? `<span class="badge ${states.includes('failed') ? 'failed' : 'backoff'}">${troubled} ${states.includes('failed') ? 'failed' : 'backoff'}</span>`
      : (states.length && states.every(s => s === 'ready') ? '<span class="badge all-ready">all ready</span>' : '');

    const collapsed = collapsedGroups.has(group);
    const anyUp = members.some(s => s.desired_up);
    const card = document.createElement('div');
    card.className = 'card group';
    card.innerHTML = `
      <div class="group-head" data-group="${esc(group)}">
        <span class="chev">${collapsed ? '▸' : '▾'}</span>
        <span class="group-name">${esc(group)}</span>
        <span class="group-count">${members.length} service${members.length > 1 ? 's' : ''}</span>
        ${chip}
        <div class="grow"></div>
        <button type="button" class="${anyUp ? 'danger' : 'secondary'} tiny group-toggle" data-group="${esc(group)}" data-action="${anyUp ? 'down' : 'up'}">${anyUp ? 'Stop all' : 'Start all'}</button>
        <span class="group-gauges">${cpu.toFixed(1)}% · ${formatBytes(mem)}</span>
      </div>`;

    if (!collapsed) {
      const showAll = expandedGroups.has(group);
      const visible = showAll ? members : members.slice(0, ROW_LIMIT);
      const rows = visible.map(s => {
        const u = gauges.get(s.name);
        const series = serviceSeries(s.name);
        const isSel = selected && selected.kind === 'service' && selected.key === s.name;
        const spark = series
          ? sparkSvg(series.points.slice(-13).map(p => p.cpu_percent), 96, 20, isSel)
          : '';
        const detail = s.detail ? `<div class="svc-detail">${esc(s.detail)}</div>` : '';
        return `
          <tr class="svc-row ${isSel ? 'selected' : ''}" data-service="${esc(s.name)}">
            <td><div class="svc-name">${esc(s.name)}</div>${detail}</td>
            <td>${stateBadge(s.state)}</td>
            <td><div class="svc-host">${esc(s.host || '—')}</div></td>
            <td class="svc-num">${u ? u.cpu_percent.toFixed(1) + '%' : '—'}</td>
            <td class="svc-num">${u ? formatBytes(u.memory_usage_bytes) : '—'}</td>
            <td class="svc-spark">${spark}</td>
            <td class="svc-chev">›</td>
          </tr>`;
      }).join('');
      const more = members.length > ROW_LIMIT && !showAll
        ? `<button type="button" class="show-more" data-group="${esc(group)}">Show ${members.length - ROW_LIMIT} more</button>`
        : '';
      card.insertAdjacentHTML('beforeend', `
        <div class="table-scroll"><table class="svc-table">
          <thead><tr><th>Service</th><th>State</th><th>Host</th><th style="text-align:right">CPU</th><th style="text-align:right">Mem</th><th style="text-align:right">10 min</th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>${more}`);
    }
    container.appendChild(card);
  }

  container.querySelectorAll('.group-head').forEach(head => {
    head.addEventListener('click', (ev) => {
      if (ev.target.closest('button')) return;
      const g = head.dataset.group;
      if (collapsedGroups.has(g)) collapsedGroups.delete(g); else collapsedGroups.add(g);
      renderGroups();
    });
  });
  container.querySelectorAll('.group-toggle').forEach(btn => {
    btn.addEventListener('click', async () => {
      const g = btn.dataset.group;
      const names = services.filter(s => groupsOf(s).includes(g)).map(s => s.name);
      btn.disabled = true;
      btn.textContent = btn.dataset.action === 'down' ? 'Stopping…' : 'Starting…';
      try {
        await api(`/services/${btn.dataset.action}`, {
          method: 'POST',
          body: JSON.stringify({ names }),
        });
        refresh();
      } catch (err) {
        alert(err.message);
        refresh();
      }
    });
  });
  container.querySelectorAll('.show-more').forEach(btn => {
    btn.addEventListener('click', () => {
      expandedGroups.add(btn.dataset.group);
      renderGroups();
    });
  });
  container.querySelectorAll('.svc-row').forEach(row => {
    row.addEventListener('click', () => selectService(row.dataset.service));
    row.addEventListener('dblclick', () => {
      selectService(row.dataset.service);
      setFocus(true);
    });
  });
}

// --- Inspector -------------------------------------------------------------

const logView = { cursor: 0, follow: true, timer: null, service: null };
const LOG_MAX_LINES = 400;

function selectService(name) {
  if (selected && selected.kind === 'service' && selected.key === name) return;
  selected = { kind: 'service', key: name };
  startLogTail(name);
  renderGroups();
  renderContainers();
  renderInspector();
  pushRoute();
}

function selectContainer(id) {
  if (selected && selected.kind === 'container' && selected.key === id) return;
  selected = { kind: 'container', key: id };
  stopLogTail();
  renderGroups();
  renderContainers();
  renderInspector();
  pushRoute();
}

function selectedService() {
  if (!selected || selected.kind !== 'service') return null;
  return services.find(s => s.name === selected.key) || null;
}

function selectedContainer() {
  if (!selected || selected.kind !== 'container') return null;
  return containers.find(c => c.id === selected.key) || null;
}

function renderInspector() {
  if (cfgEditor.open) return; // never clobber a dirty buffer from the poll loop
  el('config-editor').hidden = true;
  const ctr = selectedContainer();
  if (ctr) return renderContainerInspector(ctr);
  const svc = selectedService();
  el('inspector-empty').hidden = !!svc;
  el('inspector').hidden = !svc;
  if (!svc) return;
  el('insp-restart').hidden = false;
  el('insp-toggle').hidden = false;
  el('log-block').hidden = false;

  el('insp-name').textContent = svc.name;
  const state = String(svc.state || '').toLowerCase();
  const badge = el('insp-state');
  badge.textContent = state;
  badge.className = 'badge ' + state;

  el('insp-chips').innerHTML = groupsOf(svc).map(g => `<span class="chip">${esc(g)}</span>`).join('');

  el('insp-config').hidden = !svc.root;

  const toggle = el('insp-toggle');
  const running = svc.desired_up;
  toggle.textContent = running ? 'Stop' : 'Start';
  toggle.className = running ? 'danger' : 'secondary';
  el('insp-restart').disabled = !running;

  const open = el('insp-open');
  if (svc.host && state === 'ready') {
    const scheme = schemeForHost(svc.host);
    open.href = `${scheme}://${svc.host}`;
    open.hidden = false;
  } else {
    open.hidden = true;
  }

  const detail = el('insp-detail');
  detail.hidden = !svc.detail;
  detail.textContent = svc.detail || '';

  const u = gauges.get(svc.name);
  const meta = [
    ['PID', svc.pid ?? '—'],
    ['Restarts', svc.restarts || 0],
    ['Procs', u ? u.pids_current : '—'],
    ['Host', svc.host || '—'],
  ];
  el('insp-meta').innerHTML = meta
    .map(([label, value]) => `<div class="meta"><span class="meta-label">${esc(label)}</span><span class="meta-value">${esc(value)}</span></div>`)
    .join('');

  const series = serviceSeries(svc.name);
  const points = series ? series.points : [];
  el('insp-cpu-now').textContent = u ? `now ${u.cpu_percent.toFixed(1)}%` : '';
  el('insp-mem-now').textContent = u ? `now ${formatBytes(u.memory_usage_bytes)}` : '';
  renderChart(el('chart-cpu'), points, p => p.cpu_percent, v => v.toFixed(1) + '%');
  renderChart(el('chart-mem'), points, p => p.memory_usage_bytes, formatBytes);
}

function formatRate(bps) {
  return formatBytes(Math.round(bps)) + '/s';
}

/// Containers get footprint + charts, not lifecycle buttons — colima/docker
/// own the container lifecycle; portman deliberately doesn't.
function renderContainerInspector(c) {
  el('inspector-empty').hidden = true;
  el('inspector').hidden = false;
  el('insp-restart').hidden = true;
  el('insp-toggle').hidden = true;
  el('insp-config').hidden = true;
  el('log-block').hidden = true;
  el('insp-action-note').textContent = '';
  el('insp-detail').hidden = !c.error;
  el('insp-detail').textContent = c.error || '';

  el('insp-name').textContent = c.name || c.id.slice(0, 12);
  const state = String(c.state || 'running').toLowerCase();
  const badge = el('insp-state');
  badge.textContent = state;
  badge.className = 'badge ' + (state.includes('running') || state.includes('healthy') ? 'ready' : 'backoff');

  const chips = [];
  if (c.image) chips.push(c.image);
  if (c.compose_project) chips.push(c.compose_project);
  el('insp-chips').innerHTML = chips.map(t => `<span class="chip mono">${esc(t)}</span>`).join('');

  const open = el('insp-open');
  const httpHost = (c.portman_hosts || []).find(h => !h.startsWith('*.'));
  if (httpHost) {
    open.href = `${schemeForHost(httpHost)}://${httpHost}`;
    open.hidden = false;
  } else {
    open.hidden = true;
  }

  const meta = [
    ['ID', c.id.slice(0, 12)],
    ['Net ↓ / ↑', `${formatRate(c.network_rx_rate_bytes_per_sec || 0)} · ${formatRate(c.network_tx_rate_bytes_per_sec || 0)}`],
    ['Disk R / W', `${formatRate(c.block_read_rate_bytes_per_sec || 0)} · ${formatRate(c.block_write_rate_bytes_per_sec || 0)}`],
    ['Host', (c.portman_hosts || [])[0] || '—'],
  ];
  el('insp-meta').innerHTML = meta
    .map(([label, value]) => `<div class="meta"><span class="meta-label">${esc(label)}</span><span class="meta-value">${esc(value)}</span></div>`)
    .join('');

  const series = historySeries.find(s => s.kind === 'container' && s.key === c.id);
  const points = series ? series.points : [];
  el('insp-cpu-now').textContent = `now ${c.cpu_percent.toFixed(1)}%`;
  el('insp-mem-now').textContent = `now ${formatBytes(c.memory_usage_bytes)}`
    + (c.memory_limit_bytes ? ` of ${formatBytes(c.memory_limit_bytes)}` : '');
  renderChart(el('chart-cpu'), points, p => p.cpu_percent, v => v.toFixed(1) + '%');
  renderChart(el('chart-mem'), points, p => p.memory_usage_bytes, formatBytes);
}

async function serviceAction(action) {
  const svc = selectedService();
  if (!svc) return;
  const note = el('insp-action-note');
  note.textContent = action === 'restart' ? 'restarting…' : action === 'down' ? 'stopping…' : 'starting…';
  try {
    await api(`/service/${encodeURIComponent(svc.name)}/${action}`, { method: 'POST' });
    note.textContent = '';
    refresh();
  } catch (err) {
    note.textContent = err.message;
  }
}

el('insp-restart').addEventListener('click', () => serviceAction('restart'));
el('insp-toggle').addEventListener('click', () => {
  const svc = selectedService();
  if (!svc) return;
  serviceAction(svc.desired_up ? 'down' : 'up');
});

// --- Containers ------------------------------------------------------------

function renderContainers() {
  const container = el('container-groups');
  const empty = el('containers-empty');
  el('containers-count').textContent = containers.length ? String(containers.length) : '';
  container.innerHTML = '';
  empty.hidden = containers.length > 0;
  if (!containers.length) return;

  const groups = new Map();
  for (const c of containers) {
    const g = c.compose_project || 'standalone';
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(c);
  }

  for (const [group, members] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    let cpu = 0, mem = 0;
    for (const m of members) { cpu += m.cpu_percent || 0; mem += m.memory_usage_bytes || 0; }
    const collapsed = collapsedGroups.has('ctr:' + group);
    const card = document.createElement('div');
    card.className = 'card group';
    card.innerHTML = `
      <div class="group-head" data-group="ctr:${esc(group)}">
        <span class="chev">${collapsed ? '▸' : '▾'}</span>
        <span class="group-name">${esc(group)}</span>
        <span class="group-count">${members.length} container${members.length > 1 ? 's' : ''}</span>
        <div class="grow"></div>
        <span class="group-gauges">${cpu.toFixed(1)}% · ${formatBytes(mem)}</span>
      </div>`;

    if (!collapsed) {
      const rows = members.map(c => {
        const isSel = selected && selected.kind === 'container' && selected.key === c.id;
        const series = historySeries.find(s => s.kind === 'container' && s.key === c.id);
        const spark = series
          ? sparkSvg(series.points.slice(-13).map(p => p.cpu_percent), 96, 20, isSel)
          : '';
        const state = String(c.state || 'running').toLowerCase();
        const ok = state.includes('running') || state.includes('healthy');
        return `
          <tr class="svc-row ${isSel ? 'selected' : ''}" data-container="${esc(c.id)}">
            <td><div class="svc-name">${esc(c.name || c.id.slice(0, 12))}</div></td>
            <td><span class="badge ${ok ? 'ready' : 'backoff'}">${esc(state)}</span></td>
            <td><div class="svc-host">${esc((c.portman_hosts || [])[0] || '—')}</div></td>
            <td class="svc-num">${c.cpu_percent.toFixed(1)}%</td>
            <td class="svc-num">${formatBytes(c.memory_usage_bytes)}</td>
            <td class="svc-spark">${spark}</td>
            <td class="svc-chev">›</td>
          </tr>`;
      }).join('');
      card.insertAdjacentHTML('beforeend', `
        <div class="table-scroll"><table class="svc-table">
          <thead><tr><th>Container</th><th>State</th><th>Host</th><th style="text-align:right">CPU</th><th style="text-align:right">Mem</th><th style="text-align:right">10 min</th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>`);
    }
    container.appendChild(card);
  }

  container.querySelectorAll('.group-head').forEach(head => {
    head.addEventListener('click', () => {
      const g = head.dataset.group;
      if (collapsedGroups.has(g)) collapsedGroups.delete(g); else collapsedGroups.add(g);
      renderContainers();
    });
  });
  container.querySelectorAll('.svc-row').forEach(row => {
    row.addEventListener('click', () => selectContainer(row.dataset.container));
    row.addEventListener('dblclick', () => {
      selectContainer(row.dataset.container);
      setFocus(true);
    });
  });
}

// --- Config editor ----------------------------------------------------------
// Raw TOML, validated and applied server-side by the same resolve `portman up`
// runs. While the editor is open the inspector re-render pauses so the 5s
// refresh can never clobber a dirty buffer.

const cfgEditor = { open: false, root: null, files: {}, active: null, dirty: false };

async function openConfig(root) {
  try {
    const res = await api('/config?root=' + encodeURIComponent(root));
    cfgEditor.open = true;
    cfgEditor.root = root;
    cfgEditor.files = {};
    for (const f of res.files) cfgEditor.files[f.name] = f;
    // Prefer the local overlay when present — that's the personal file.
    cfgEditor.active = cfgEditor.files['portman.local.toml'].present
      ? 'portman.local.toml'
      : 'portman.toml';
    cfgEditor.dirty = false;
    renderConfigEditor();
    pushRoute();
  } catch (e) {
    alert(e.message);
  }
}

function closeConfig() {
  if (cfgEditor.dirty && !confirm('Discard unsaved config changes?')) return;
  cfgEditor.open = false;
  cfgEditor.dirty = false;
  el('config-editor').hidden = true;
  renderInspector();
  pushRoute();
}

function renderConfigEditor() {
  if (!cfgEditor.open) return;
  el('inspector').hidden = true;
  el('inspector-empty').hidden = true;
  el('config-editor').hidden = false;
  el('cfg-root').textContent = cfgEditor.root;
  el('cfg-error').hidden = true;
  el('cfg-status').textContent = '';

  const tabs = el('cfg-tabs');
  tabs.innerHTML = '';
  for (const name of ['portman.toml', 'portman.local.toml']) {
    const f = cfgEditor.files[name];
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'cfg-tab' + (name === cfgEditor.active ? ' active' : '');
    btn.textContent = name + (f && f.present ? '' : ' (new)');
    btn.addEventListener('click', () => {
      if (cfgEditor.dirty && !confirm('Discard unsaved changes to this file?')) return;
      cfgEditor.active = name;
      cfgEditor.dirty = false;
      renderConfigEditor();
    });
    tabs.appendChild(btn);
  }

  const f = cfgEditor.files[cfgEditor.active];
  el('cfg-text').value = f ? f.content : '';
  const note = el('cfg-note');
  note.hidden = !!(f && f.present);
  note.textContent = 'This file does not exist yet — saving creates it.';
}

el('cfg-text').addEventListener('input', () => { cfgEditor.dirty = true; });
el('cfg-back').addEventListener('click', closeConfig);
el('cfg-cancel').addEventListener('click', closeConfig);
el('insp-config').addEventListener('click', () => {
  const svc = selectedService();
  if (svc && svc.root) openConfig(svc.root);
});

el('cfg-save').addEventListener('click', async () => {
  const save = el('cfg-save');
  const errBox = el('cfg-error');
  errBox.hidden = true;
  save.disabled = true;
  el('cfg-status').textContent = 'validating\u2026';
  try {
    const res = await api('/config', {
      method: 'POST',
      body: JSON.stringify({
        root: cfgEditor.root,
        file: cfgEditor.active,
        content: el('cfg-text').value,
      }),
    });
    const parts = [];
    if ((res.updated || []).length) parts.push(`${res.updated.length} updated`);
    if ((res.added || []).length) parts.push(`${res.added.length} added (not started)`);
    if ((res.removed || []).length) parts.push(`${res.removed.length} removed`);
    if (!parts.length) parts.push('no changes');
    cfgEditor.dirty = false;
    el('cfg-status').textContent = 'applied \u00b7 ' + parts.join(' \u00b7 ');
    cfgEditor.files[cfgEditor.active] = {
      name: cfgEditor.active,
      present: true,
      content: el('cfg-text').value,
    };
    el('cfg-note').hidden = true;
    refresh();
  } catch (e) {
    errBox.textContent = e.message;
    errBox.hidden = false;
    el('cfg-status').textContent = '';
  }
  save.disabled = false;
});

// --- Log tail --------------------------------------------------------------

function stopLogTail() {
  if (logView.timer) clearInterval(logView.timer);
  logView.timer = null;
  logView.service = null;
}

function startLogTail(service) {
  if (logView.timer) clearInterval(logView.timer);
  logView.service = service;
  logView.cursor = 0;
  el('log-output').textContent = '';
  pollLogs(true);
  logView.timer = setInterval(() => pollLogs(false), 2000);
}

async function pollLogs(initial) {
  if (!logView.service) return;
  const name = encodeURIComponent(logView.service);
  const path = initial
    ? `/services/${name}/logs?limit=100`
    : `/services/${name}/logs?after=${logView.cursor}&limit=100`;
  try {
    const res = await api(path);
    logView.cursor = res.last_id || logView.cursor;
    if ((res.lines || []).length) {
      const out = el('log-output');
      out.textContent += res.lines.map(l => l.line).join('\n') + '\n';
      const lines = out.textContent.split('\n');
      if (lines.length > LOG_MAX_LINES) {
        out.textContent = lines.slice(lines.length - LOG_MAX_LINES).join('\n');
      }
      if (logView.follow) out.scrollTop = out.scrollHeight;
    }
  } catch {
    /* daemon restart mid-poll — next tick recovers */
  }
}

// --- Focus mode & navigation ----------------------------------------------
// Selection and focus mirror into the URL hash (#svc/<name>, #ctr/<id>,
// + /focus), so the browser's Back button — everyone's first instinct —
// actually walks you back out.

let focused = false;
let applyingRoute = false;

function routeHash() {
  if (cfgEditor.open) return '#cfg/' + encodeURIComponent(cfgEditor.root);
  if (!selected) return '';
  const base = (selected.kind === 'service' ? 'svc/' : 'ctr/') + encodeURIComponent(selected.key);
  return '#' + base + (focused ? '/focus' : '');
}

function pushRoute() {
  if (applyingRoute) return;
  const h = routeHash();
  if (h && location.hash !== h) history.pushState(null, '', h);
}

function applyRoute() {
  applyingRoute = true;
  const cfg = location.hash.match(/^#cfg\/(.+)$/);
  if (cfg) {
    openConfig(decodeURIComponent(cfg[1]));
    applyingRoute = false;
    return;
  }
  if (cfgEditor.open) {
    // Back navigation out of the editor: close without the discard prompt —
    // the browser already moved on.
    cfgEditor.open = false;
    cfgEditor.dirty = false;
    el('config-editor').hidden = true;
  }
  const m = location.hash.match(/^#(svc|ctr)\/([^/]+)(\/focus)?$/);
  if (m) {
    const key = decodeURIComponent(m[2]);
    if (m[1] === 'svc') selectService(key);
    else selectContainer(key);
    setFocus(!!m[3]);
  } else {
    setFocus(false);
    renderInspector();
  }
  applyingRoute = false;
}

window.addEventListener('popstate', applyRoute);

function setFocus(on) {
  focused = on;
  document.querySelector('.layout').classList.toggle('focus', on);
  el('insp-back').hidden = !on;
  el('focus-nav').hidden = !on;
  el('insp-focus').hidden = on;
  if (on) window.scrollTo({ top: 0 });
  pushRoute();
}

// The flattened item order prev/next walks: services first, then containers —
// the same order the page lays them out.
function allItems() {
  return [
    ...services.map(s => ({ kind: 'service', key: s.name })),
    ...containers.map(c => ({ kind: 'container', key: c.id })),
  ];
}

function focusStep(delta) {
  const items = allItems();
  if (!items.length || !selected) return;
  const i = items.findIndex(it => it.kind === selected.kind && it.key === selected.key);
  const next = items[(i + delta + items.length) % items.length];
  if (next.kind === 'service') selectService(next.key);
  else selectContainer(next.key);
}

el('insp-focus').addEventListener('click', () => setFocus(true));
el('insp-back').addEventListener('click', () => setFocus(false));
el('focus-prev').addEventListener('click', () => focusStep(-1));
el('focus-next').addEventListener('click', () => focusStep(1));
document.querySelector('.brand').addEventListener('click', () => setFocus(false));

document.addEventListener('keydown', (ev) => {
  if (ev.target && /^(INPUT|TEXTAREA)$/.test(ev.target.tagName)) return;
  if (ev.key === 'Escape' && focused) setFocus(false);
  if (focused && (ev.key === 'ArrowUp' || ev.key === 'k')) {
    ev.preventDefault();
    focusStep(-1);
  }
  if (focused && (ev.key === 'ArrowDown' || ev.key === 'j')) {
    ev.preventDefault();
    focusStep(1);
  }
});

el('log-expand').addEventListener('click', () => {
  const out = el('log-output');
  const expanded = out.classList.toggle('expanded');
  el('log-expand').textContent = expanded ? 'Collapse' : 'Expand';
  el('log-expand').setAttribute('aria-pressed', String(expanded));
  if (logView.follow) out.scrollTop = out.scrollHeight;
});

el('log-follow').addEventListener('click', () => {
  logView.follow = !logView.follow;
  el('log-follow').setAttribute('aria-pressed', String(logView.follow));
  if (logView.follow) el('log-output').scrollTop = el('log-output').scrollHeight;
});

// --- Routes ----------------------------------------------------------------

function schemeForHost(host) {
  const h = String(host).toLowerCase();
  for (const t of allTlds) {
    if (h === t.name || h.endsWith('.' + t.name)) {
      return t.tls_mode === 'mkcert' || t.tls_mode === 'le' ? 'https' : 'http';
    }
  }
  return 'http';
}

function renderRoutes() {
  const filter = el('entries-filter').value.trim().toLowerCase();
  const entries = [...allEntries].sort((a, b) => a.host.localeCompare(b.host));
  const shown = filter
    ? entries.filter(e => e.host.toLowerCase().includes(filter) || e.target.toLowerCase().includes(filter))
    : entries;
  const limited = routesExpanded || filter ? shown : shown.slice(0, ROUTE_LIMIT);

  el('entries-count').textContent = filter ? `${shown.length} of ${entries.length}` : `${entries.length}`;
  el('entries-empty').hidden = entries.length > 0;

  const collisions = new Map(targetCollisions(allEntries));

  const tbody = el('entries-body');
  tbody.innerHTML = '';
  for (const e of limited) {
    const wildcard = e.host.startsWith('*.');
    const scheme = e.mode === 'tcp' || wildcard ? null : schemeForHost(e.host);
    const hostCell = scheme
      ? `<a class="route-host" href="${scheme}://${esc(e.host)}" target="_blank" rel="noopener">${esc(e.host)}</a>`
      : `<span class="route-host${wildcard ? ' wildcard' : ''}">${esc(e.host)}</span>`;
    const shared = collisions.get(e.target);
    const flag = shared
      ? `<span class="warn-flag" title="Also claimed by: ${esc(shared.filter(h => h !== e.host).join(', '))}">shared</span>`
      : '';
    const removeBtn = e.source === 'static'
      ? `<button type="button" class="danger tiny remove-btn" data-host="${esc(e.host)}">Remove</button>`
      : `<button type="button" class="secondary tiny start-btn" data-host="${esc(e.host)}">Start</button>`;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${hostCell}${flag}</td>
      <td class="col-target"><span class="route-target">${esc(e.target)}</span></td>
      <td class="col-mode"><span class="mode-tag">${esc(e.mode)}</span></td>
      <td class="col-source"><span class="route-source">${esc(e.source)}</span></td>
      <td class="col-actions"><span class="row-actions">${removeBtn}</span></td>`;
    tbody.appendChild(tr);
  }

  const existing = document.querySelector('#routes-card .show-more');
  if (existing) existing.remove();
  if (!routesExpanded && !filter && shown.length > ROUTE_LIMIT) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'show-more';
    btn.textContent = `Show all ${shown.length}`;
    btn.addEventListener('click', () => { routesExpanded = true; renderRoutes(); });
    el('routes-card').insertBefore(btn, el('add-form'));
  }

  tbody.querySelectorAll('.remove-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await api('/static/' + encodeURIComponent(btn.dataset.host), { method: 'DELETE' });
        refresh();
      } catch (err) {
        alert(err.message);
      }
    });
  });
  tbody.querySelectorAll('.start-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = 'Starting…';
      try {
        await api('/services/' + encodeURIComponent(btn.dataset.host) + '/start', { method: 'POST' });
        btn.textContent = 'Started';
        setTimeout(refresh, 2000);
      } catch (err) {
        btn.disabled = false;
        btn.textContent = 'Start';
        alert(err.message);
      }
    });
  });
}

el('entries-filter').addEventListener('input', renderRoutes);

el('add-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const errEl = el('add-error');
  errEl.hidden = true;
  try {
    await api('/static', {
      method: 'POST',
      body: JSON.stringify({
        host: el('add-host').value.trim(),
        target: el('add-target').value.trim(),
        mode: el('add-tcp').checked ? 'tcp' : 'http',
      }),
    });
    el('add-host').value = '';
    el('add-target').value = '';
    el('add-tcp').checked = false;
    refresh();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.hidden = false;
  }
});

// --- Status / footer -------------------------------------------------------

function renderStatus(status) {
  const online = status && status.kind === 'status';
  el('status-dot').className = 'dot ' + (online ? 'online' : 'offline');
  el('status-label').textContent = online ? `online · up ${shortUptime(status.running_since)}` : 'offline';
  if (!online) {
    el('version').textContent = '';
    el('daemon-ports').textContent = '';
    el('bridge-pill').hidden = true;
    return;
  }
  el('version').textContent = 'v' + status.version;
  el('daemon-ports').textContent = `dns :${status.dns_port} · http :${status.proxy_port} · tls :${status.tls_port}`;
  el('dashboard-url').textContent = `http://127.0.0.1:${status.dashboard_port}`;

  const pill = el('bridge-pill');
  const assessment = status.bridge_assessment || 'unknown';
  pill.hidden = false;
  el('bridge-label').textContent = `bridge ${assessment.replace('_', ' ')}`;
  if (assessment !== 'healthy' && assessment !== 'unknown') {
    pushAlert(
      `Bridge ${assessment.replace('_', ' ')}`,
      `<div class="alert-body">mode=${esc(status.bridge_mode)} · enabled=${esc(status.bridge_enabled)}</div>`,
      assessment === 'tunnel_dead'
    );
  }
}

function shortUptime(s) {
  const m = String(s || '').match(/^(\d+h)/);
  return m ? m[1] : String(s || '');
}

function renderFooter(tlds, certs) {
  const parts = tlds.map(t => `.${t.name} · ${t.tls_mode}`);
  if (certs && typeof certs.issued_count === 'number') parts.push(`${certs.issued_count} certs`);
  el('tld-summary').textContent = parts.join(' · ');
}

// --- Refresh loop ----------------------------------------------------------

async function refresh() {
  resetAlerts();
  try {
    const status = await api('/status');
    const [entriesRes, tldsRes, resourcesRes, servicesRes, historyRes, certsRes] = await Promise.all([
      api('/entries'),
      api('/tlds'),
      api('/resources').catch(() => ({ snapshot: {} })),
      api('/services').catch(() => ({ services: [] })),
      api('/resources/history').catch(() => ({ series: [] })),
      api('/certs').catch(() => null),
    ]);
    allEntries = entriesRes.entries || [];
    allTlds = tldsRes.tlds || [];
    services = (servicesRes.services || []).sort((a, b) => a.name.localeCompare(b.name));
    historySeries = historyRes.series || [];
    const snap = resourcesRes.snapshot || {};
    gauges = new Map((snap.services || []).map(u => [u.name, u]));
    containers = (snap.containers || []).slice().sort((a, b) => (a.name || a.id).localeCompare(b.name || b.id));
    snapshotTotals = {
      containers: snap.container_count || 0,
      cpu: (snap.totals || {}).cpu_percent || 0,
      mem: (snap.totals || {}).memory_usage_bytes || 0,
    };

    if (!selected && location.hash) {
      // A deep link (reload, bookmark, shared URL) wins over auto-select.
      applyRoute();
    }
    if (!selected && services.length) {
      // Lead with a troubled service if there is one — that's what you came for.
      const troubled = services.find(s => ['backoff', 'failed'].includes(String(s.state).toLowerCase()));
      selectService((troubled || services[0]).name);
    }

    renderStatus(status);
    alertCollisions();
    renderKpis();
    renderGroups();
    renderContainers();
    renderInspector();
    renderRoutes();
    renderFooter(allTlds, certsRes);
  } catch (err) {
    renderStatus(null);
    pushAlert('Daemon unreachable', `<div class="alert-body">${esc(err.message)}</div>`, true);
  }
  renderAlerts();
}

refresh();
setInterval(refresh, 5000);
