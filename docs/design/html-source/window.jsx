// Main window — NavigationSplitView: Entries · TLDs · About.
// macOS window chrome (traffic lights + title bar status badge).

function PortmanWindow({
  width = 880,
  height = 560,
  status = 'online',
  statusMeta = PM_STATUS.online,
  pane = 'entries',               // entries | tlds | about
  entries = PM_ENTRIES_WINDOW,
  tlds = PM_TLDS,
  // Entries pane
  selection = [],
  search = '',
  sortBy = 'host',
  // TLDs pane
  expandedTld = null,
  // Add TLD form
  addTldOpen = false,
  addTldName = '',
  addTldTls = true,
  addTldWarning = null,           // { kind: 'blocked' | 'advisory', text: string }
  // theming
}) {
  return (
    <div style={{
      width, height,
      borderRadius: 10,
      background: 'var(--pm-windowBg)',
      border: '0.5px solid var(--pm-borderStrong)',
      boxShadow: 'var(--pm-windowShadow)',
      overflow: 'hidden',
      display: 'flex', flexDirection: 'column',
      fontFamily: FONTS.ui,
    }}>
      {/* TITLE BAR */}
      <div style={{
        height: 38,
        background: 'linear-gradient(to bottom, rgba(255,255,255,0.02), transparent)',
        borderBottom: '0.5px solid var(--pm-divider)',
        display: 'flex', alignItems: 'center',
        padding: '0 12px',
        gap: 12,
      }}>
        <TrafficLights/>
        <div style={{ flex: 1, textAlign: 'center', fontSize: 12.5, fontWeight: 600, color: 'var(--pm-textSecondary)' }}>
          portman
        </div>
        {/* right: mini status chip */}
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          padding: '2px 8px 2px 7px', borderRadius: 8,
          background: 'var(--pm-surfaceHover)',
          fontSize: 11, color: 'var(--pm-textSecondary)',
        }}>
          <StatusDot status={status} size={6}/>
          <span>{status === 'online' ? `v${statusMeta.version}` : status}</span>
        </div>
      </div>

      {/* SPLIT VIEW */}
      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {/* Sidebar */}
        <div style={{
          width: 188,
          background: 'var(--pm-sidebarBg)',
          borderRight: '0.5px solid var(--pm-divider)',
          padding: '10px 8px',
          display: 'flex', flexDirection: 'column', gap: 1,
        }}>
          <SidebarItem label="Entries" icon={<Icon.Shippingbox size={13}/>} count={entries.length} active={pane === 'entries'} kbd="1"/>
          <SidebarItem label="TLDs"    icon={<Icon.House size={13}/>}       count={tlds.length}     active={pane === 'tlds'}    kbd="2"/>
          <SidebarItem label="About"   icon={<Icon.Gear size={13}/>}                                 active={pane === 'about'}    kbd="3"/>
          <div style={{ flex: 1 }}/>
          <div style={{
            padding: '8px 10px 4px',
            fontSize: 10.5, color: 'var(--pm-textTertiary)',
            display: 'flex', alignItems: 'center', gap: 6,
          }}>
            <StatusDot status={status} size={6}/>
            <span>{status === 'online' ? `up ${statusMeta.runningSince}` : 'offline'}</span>
          </div>
        </div>

        {/* Detail pane */}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
          {pane === 'entries' && <EntriesPane entries={entries} tlds={tlds} search={search} sortBy={sortBy} selection={selection}/>}
          {pane === 'tlds'    && <TldsPane tlds={tlds} expandedTld={expandedTld} addOpen={addTldOpen} addName={addTldName} addTls={addTldTls} warning={addTldWarning}/>}
          {pane === 'about'   && <AboutPane statusMeta={statusMeta}/>}
        </div>
      </div>
    </div>
  );
}

function TrafficLights() {
  return (
    <div style={{ display: 'flex', gap: 6 }}>
      {[['#FF5F57','#E0443E'],['#FEBC2E','#DEA123'],['#28C840','#1AAB29']].map(([bg,brd],i) => (
        <span key={i} style={{
          width: 12, height: 12, borderRadius: '50%',
          background: bg, boxShadow: `inset 0 0 0 0.5px ${brd}`,
        }}/>
      ))}
    </div>
  );
}

function SidebarItem({ label, icon, count, active, kbd }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '5px 8px', borderRadius: 5,
      background: active ? 'var(--pm-accentSoft)' : 'transparent',
      color: active ? 'var(--pm-accent)' : 'var(--pm-text)',
      fontSize: 12.5, fontWeight: active ? 600 : 500,
      cursor: 'default',
    }}>
      <span style={{ width: 14, display: 'flex', alignItems: 'center', opacity: active ? 1 : 0.7 }}>{icon}</span>
      <span style={{ flex: 1 }}>{label}</span>
      {count != null && (
        <span className="pm-mono" style={{
          fontSize: 10.5, color: active ? 'var(--pm-accent)' : 'var(--pm-textTertiary)',
          background: active ? 'transparent' : 'var(--pm-surfaceHover)',
          padding: '0 5px', borderRadius: 3, fontWeight: 500,
        }}>{count}</span>
      )}
      {kbd && (
        <span style={{
          fontSize: 10, color: 'var(--pm-textTertiary)',
          marginLeft: 2, fontFamily: FONTS.ui,
        }}>⌘{kbd}</span>
      )}
    </div>
  );
}

// ── Entries pane ───────────────────────────────────────────────
function EntriesPane({ entries, tlds, search, sortBy, selection }) {
  const hasSearch = search && search.length > 0;
  const filtered = hasSearch
    ? entries.filter(e => e.host.includes(search) || e.target.includes(search))
    : entries;

  return (
    <>
      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '10px 14px',
        borderBottom: '0.5px solid var(--pm-divider)',
      }}>
        <div style={{
          flex: 1, display: 'flex', alignItems: 'center', gap: 6,
          height: 26, padding: '0 8px', borderRadius: 6,
          background: 'var(--pm-surface)',
          border: '0.5px solid var(--pm-border)',
          fontSize: 12.5,
        }}>
          <Icon.Search size={12}/>
          <span style={{ color: hasSearch ? 'var(--pm-text)' : 'var(--pm-textTertiary)' }}>
            {hasSearch ? search : 'Filter by host or target…'}
          </span>
          <div style={{ flex: 1 }}/>
          <KeyCap>⌘F</KeyCap>
        </div>
        <button style={secondaryBtn}>
          <Icon.Plus size={11}/> Add entry
        </button>
        {selection.length > 0 && (
          <button style={{ ...secondaryBtn, color: 'var(--pm-offline)', borderColor: 'rgba(199,70,58,.35)' }}>
            <Icon.Trash size={11}/> Remove {selection.length}
          </button>
        )}
      </div>

      {/* Table */}
      <div className="pm-scroll" style={{ flex: 1, overflow: 'auto' }}>
        <TableHeader sortBy={sortBy}/>
        {groupByTld(filtered).map(group => (
          <div key={group.tld}>
            <div style={{
              padding: '6px 14px',
              background: 'var(--pm-surfaceHover)',
              borderBottom: '0.5px solid var(--pm-divider)',
              borderTop: '0.5px solid var(--pm-divider)',
              fontSize: 10.5, fontWeight: 600,
              color: 'var(--pm-textSecondary)',
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <span className="pm-mono" style={{ color: 'var(--pm-text)' }}>.{group.tld}</span>
              <span style={{
                fontSize: 9.5, letterSpacing: 0.5, textTransform: 'uppercase',
                padding: '1px 5px', borderRadius: 3,
                background: tlds.find(t => t.name === group.tld)?.tlsMode === 'mkcert' ? 'var(--pm-httpsBg)' : 'var(--pm-httpBg)',
                color: tlds.find(t => t.name === group.tld)?.tlsMode === 'mkcert' ? 'var(--pm-httpsText)' : 'var(--pm-httpText)',
              }}>
                {tlds.find(t => t.name === group.tld)?.tlsMode === 'mkcert' ? 'mkcert' : 'http'}
              </span>
              <span style={{ color: 'var(--pm-textTertiary)', fontWeight: 500 }}>{group.rows.length} {group.rows.length === 1 ? 'entry' : 'entries'}</span>
            </div>
            {group.rows.map((e, i) => (
              <TableRow key={e.host} entry={e} selected={selection.includes(e.host)}/>
            ))}
          </div>
        ))}
      </div>

      {/* Status bar */}
      <div style={{
        height: 24,
        borderTop: '0.5px solid var(--pm-divider)',
        background: 'var(--pm-surfaceHover)',
        display: 'flex', alignItems: 'center',
        padding: '0 14px', gap: 12,
        fontSize: 10.5, color: 'var(--pm-textSecondary)',
      }}>
        <span>{filtered.length} entries</span>
        <span>·</span>
        <span>{filtered.filter(e => e.source === 'container').length} containers</span>
        <span>·</span>
        <span>{filtered.filter(e => e.source === 'static').length} static</span>
        <div style={{ flex: 1 }}/>
        <span>sorted by {sortBy}</span>
      </div>
    </>
  );
}

function TableHeader({ sortBy }) {
  const H = ({ id, children, flex, w }) => (
    <div style={{
      flex: flex, width: w,
      padding: '7px 10px',
      fontSize: 10.5, fontWeight: 600, letterSpacing: 0.3,
      textTransform: 'uppercase',
      color: sortBy === id ? 'var(--pm-text)' : 'var(--pm-textTertiary)',
      display: 'flex', alignItems: 'center', gap: 4,
    }}>
      {children}
      {sortBy === id && <Icon.Chevron size={8} dir="up"/>}
    </div>
  );
  return (
    <div style={{
      display: 'flex', alignItems: 'center',
      borderBottom: '0.5px solid var(--pm-border)',
      position: 'sticky', top: 0,
      background: 'var(--pm-windowBg)',
      zIndex: 1,
    }}>
      <div style={{ width: 30 }}/>
      <H id="scheme" w={56}>Scheme</H>
      <H id="host" flex={1.4}>Host</H>
      <H id="target" flex={1.2}>Target</H>
      <H id="source" w={110}>Source</H>
      <H id="container" w={120}>Container</H>
      <div style={{ width: 48 }}/>
    </div>
  );
}

function TableRow({ entry, selected }) {
  const scheme = entry.cert === 'none' ? 'http' : 'https';
  const isContainer = entry.source === 'container';
  return (
    <div style={{
      display: 'flex', alignItems: 'center',
      borderBottom: '0.5px solid var(--pm-divider)',
      background: selected ? 'var(--pm-rowSelect)' : 'transparent',
      color: 'var(--pm-text)',
      fontSize: 12.5,
    }}>
      <div style={{ width: 30, padding: '8px 10px', display: 'flex', justifyContent: 'center' }}>
        <div style={{
          width: 14, height: 14, borderRadius: 3,
          border: '0.5px solid var(--pm-borderStrong)',
          background: selected ? 'var(--pm-accent)' : 'var(--pm-surface)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'var(--pm-accentText)',
        }}>
          {selected && <Icon.Checkmark size={9}/>}
        </div>
      </div>
      <div style={{ width: 56, padding: '8px 10px' }}>
        <SchemeBadge scheme={scheme} cert={entry.cert}/>
      </div>
      <div className="pm-mono" style={{ flex: 1.4, padding: '8px 10px', fontSize: 12.5, fontWeight: 500 }}>{entry.host}</div>
      <div className="pm-mono" style={{ flex: 1.2, padding: '8px 10px', color: 'var(--pm-textSecondary)' }}>{entry.target}</div>
      <div style={{ width: 110, padding: '8px 10px', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--pm-textSecondary)' }}>
        {isContainer ? <Icon.Shippingbox size={12}/> : <Icon.Laptop size={12}/>}
        <span style={{ fontSize: 12 }}>{isContainer ? 'container' : 'static'}</span>
      </div>
      <div className="pm-mono" style={{ width: 120, padding: '8px 10px', color: 'var(--pm-textTertiary)', fontSize: 11.5 }}>
        {entry.containerID ? entry.containerID.slice(0, 10) : '—'}
      </div>
      <div style={{ width: 48, padding: '8px 6px', display: 'flex', gap: 2 }}>
        <button title="Open" style={iconBtn}><Icon.ExternalLink size={11}/></button>
        {!isContainer && <button title="Remove" style={iconBtn}><Icon.Trash size={12}/></button>}
      </div>
    </div>
  );
}

function groupByTld(entries) {
  const m = new Map();
  entries.forEach(e => {
    if (!m.has(e.tld)) m.set(e.tld, []);
    m.get(e.tld).push(e);
  });
  return Array.from(m.entries()).map(([tld, rows]) => ({ tld, rows }));
}

const secondaryBtn = {
  height: 26, padding: '0 10px', borderRadius: 6,
  display: 'inline-flex', alignItems: 'center', gap: 5,
  fontSize: 12, fontWeight: 500,
  background: 'var(--pm-surface)',
  color: 'var(--pm-text)',
  border: '0.5px solid var(--pm-borderStrong)',
  cursor: 'pointer', fontFamily: FONTS.ui,
};

// ── TLDs pane ──────────────────────────────────────────────────
function TldsPane({ tlds, expandedTld, addOpen, addName, addTls, warning }) {
  const anyTls = tlds.some(t => t.tlsMode === 'mkcert');
  return (
    <>
      <div style={{
        padding: '10px 14px',
        borderBottom: '0.5px solid var(--pm-divider)',
        display: 'flex', alignItems: 'center', gap: 8,
      }}>
        <div style={{ fontSize: 12.5, fontWeight: 600 }}>Top-level domains</div>
        <div style={{ fontSize: 11, color: 'var(--pm-textTertiary)' }}>{tlds.length} managed</div>
        <div style={{ flex: 1 }}/>
        <button style={{ ...secondaryBtn, ...(addOpen && { background: 'var(--pm-accentSoft)', color: 'var(--pm-accent)', borderColor: 'transparent' }) }}>
          <Icon.Plus size={11}/> Add TLD
        </button>
      </div>

      <div className="pm-scroll" style={{ flex: 1, overflow: 'auto', padding: '10px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
        {addOpen && (
          <AddTldForm name={addName} tls={addTls} warning={warning}/>
        )}

        {tlds.map(tld => (
          <TldCard key={tld.name} tld={tld} expanded={expandedTld === tld.name}/>
        ))}

        {anyTls && (
          <div style={{
            marginTop: 8,
            padding: '12px 14px',
            background: 'var(--pm-surface)',
            border: '0.5px solid var(--pm-border)',
            borderRadius: 8,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <Icon.Lock size={12}/>
              <span style={{ fontSize: 12.5, fontWeight: 600 }}>Certificate health</span>
              <span style={{ fontSize: 10.5, color: 'var(--pm-online)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <Icon.Checkmark size={10}/> mkcert root CA trusted
              </span>
            </div>
            <div style={{ display: 'flex', gap: 24, fontSize: 11.5, color: 'var(--pm-textSecondary)' }}>
              <div>
                <div style={{ color: 'var(--pm-textTertiary)', fontSize: 10.5, letterSpacing: 0.4, textTransform: 'uppercase', fontWeight: 600 }}>Certs issued</div>
                <div className="pm-mono" style={{ fontSize: 14, color: 'var(--pm-text)', marginTop: 2 }}>14</div>
              </div>
              <div>
                <div style={{ color: 'var(--pm-textTertiary)', fontSize: 10.5, letterSpacing: 0.4, textTransform: 'uppercase', fontWeight: 600 }}>CA location</div>
                <div className="pm-mono" style={{ fontSize: 11.5, color: 'var(--pm-text)', marginTop: 2 }}>~/Library/…/portman/certs/rootCA.pem</div>
              </div>
              <div style={{ flex: 1 }}/>
              <button style={secondaryBtn}><Icon.Refresh size={11}/> Regenerate all</button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

function TldCard({ tld, expanded }) {
  const isTls = tld.tlsMode === 'mkcert';
  return (
    <div style={{
      background: 'var(--pm-surface)',
      border: '0.5px solid var(--pm-border)',
      borderRadius: 8,
      overflow: 'hidden',
    }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '10px 14px',
      }}>
        <Icon.Chevron size={10} dir={expanded ? 'down' : 'right'}/>
        <span className="pm-mono" style={{ fontSize: 13, fontWeight: 600 }}>.{tld.name}</span>
        <span style={{
          fontSize: 10, letterSpacing: 0.5, textTransform: 'uppercase', fontWeight: 600,
          padding: '2px 6px', borderRadius: 3,
          background: isTls ? 'var(--pm-httpsBg)' : 'var(--pm-httpBg)',
          color: isTls ? 'var(--pm-httpsText)' : 'var(--pm-httpText)',
        }}>{isTls ? 'mkcert' : 'plain http'}</span>
        <span style={{ fontSize: 11, color: 'var(--pm-textTertiary)' }}>
          {tld.entryCount} {tld.entryCount === 1 ? 'entry' : 'entries'}
        </span>
        {isTls && tld.caTrusted && (
          <span style={{ fontSize: 11, color: 'var(--pm-online)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <Icon.Checkmark size={10}/> CA trusted
          </span>
        )}
        <div style={{ flex: 1 }}/>
        <button style={{ ...iconBtn, width: 24, height: 24 }}><Icon.Trash size={12}/></button>
      </div>
      {expanded && (
        <div style={{
          borderTop: '0.5px solid var(--pm-divider)',
          padding: '12px 14px',
          background: 'var(--pm-surfaceHover)',
          display: 'flex', alignItems: 'center', gap: 14,
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12, fontWeight: 600 }}>TLS via mkcert</div>
            <div style={{ fontSize: 11, color: 'var(--pm-textSecondary)', marginTop: 2 }}>
              Issues locally-trusted certs for every <span className="pm-mono">*.{tld.name}</span> host. Requires <span className="pm-mono">mkcert -install</span> once.
            </div>
          </div>
          <Toggle on={isTls}/>
        </div>
      )}
    </div>
  );
}

function Toggle({ on }) {
  return (
    <div style={{
      width: 30, height: 18, borderRadius: 9,
      background: on ? 'var(--pm-accent)' : 'var(--pm-borderStrong)',
      position: 'relative', transition: 'background .15s',
    }}>
      <div style={{
        position: 'absolute', top: 1.5, left: on ? 13.5 : 1.5,
        width: 15, height: 15, borderRadius: '50%',
        background: '#fff',
        boxShadow: '0 1px 3px rgba(0,0,0,.2)',
        transition: 'left .15s',
      }}/>
    </div>
  );
}

function AddTldForm({ name, tls, warning }) {
  return (
    <div style={{
      background: 'var(--pm-surface)',
      border: `1px solid ${warning?.kind === 'advisory' ? 'var(--pm-warning)' : 'var(--pm-accent)'}`,
      borderRadius: 8, padding: 14,
    }}>
      <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 8 }}>Add top-level domain</div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 10 }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 9.5, letterSpacing: 0.4, fontWeight: 600, textTransform: 'uppercase', color: 'var(--pm-textTertiary)', marginBottom: 3 }}>Name</div>
          <div style={{
            height: 28, borderRadius: 6,
            border: '1.2px solid var(--pm-accent)',
            boxShadow: '0 0 0 3px var(--pm-accentSoft)',
            padding: '0 9px',
            display: 'flex', alignItems: 'center',
            fontFamily: FONTS.mono, fontSize: 13,
            background: 'var(--pm-windowBg)',
          }}>
            <span style={{ color: 'var(--pm-textTertiary)' }}>.</span>
            <span style={{ color: 'var(--pm-text)' }}>{name}</span>
            <span className="pm-caret" style={{ color: 'var(--pm-accent)' }}/>
          </div>
        </div>
        <div style={{ width: 160 }}>
          <div style={{ fontSize: 9.5, letterSpacing: 0.4, fontWeight: 600, textTransform: 'uppercase', color: 'var(--pm-textTertiary)', marginBottom: 3 }}>TLS (mkcert)</div>
          <div style={{ height: 28, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Toggle on={tls}/>
            <span style={{ fontSize: 12, color: 'var(--pm-textSecondary)' }}>
              {tls ? 'https for every host' : 'plain http'}
            </span>
          </div>
        </div>
        <button style={secondaryBtn}>Cancel</button>
        <button style={{ ...secondaryBtn, background: 'var(--pm-accent)', color: 'var(--pm-accentText)', borderColor: 'transparent' }}>Add</button>
      </div>
      {warning && (
        <div style={{
          marginTop: 10,
          padding: '8px 10px',
          background: warning.kind === 'blocked' ? 'var(--pm-offlineSoft)' : 'var(--pm-warningSoft)',
          color: warning.kind === 'blocked' ? 'var(--pm-offline)' : 'var(--pm-warning)',
          borderRadius: 5,
          fontSize: 11.5, lineHeight: 1.4,
          display: 'flex', alignItems: 'flex-start', gap: 8,
        }}>
          <div style={{ marginTop: 1 }}><Icon.Warning size={11}/></div>
          <div style={{ color: 'var(--pm-text)' }}>{warning.text}</div>
        </div>
      )}
    </div>
  );
}

// ── About pane ─────────────────────────────────────────────────
function AboutPane({ statusMeta }) {
  const s = statusMeta || PM_STATUS.online;
  return (
    <div className="pm-scroll" style={{ flex: 1, overflow: 'auto', padding: '24px 28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 24 }}>
        <div style={{
          width: 54, height: 54, borderRadius: 12,
          background: 'var(--pm-accentSoft)',
          color: 'var(--pm-accent)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: '0.5px solid var(--pm-border)',
        }}>
          <Icon.Anchor size={26}/>
        </div>
        <div>
          <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: -0.3 }}>portman</div>
          <div style={{ fontSize: 12, color: 'var(--pm-textSecondary)', marginTop: 2 }}>
            Local DNS + HTTP(S) proxy for container and host dev.
          </div>
          <div className="pm-mono" style={{ fontSize: 11, color: 'var(--pm-textTertiary)', marginTop: 4 }}>
            v{s.version} · up {s.runningSince}
          </div>
        </div>
      </div>

      <Section title="Status">
        <KV k="Version" v={`v${s.version}`} mono/>
        <KV k="Running since" v={s.runningSince}/>
        <KV k="DNS port"      v={String(s.dnsPort)} mono/>
        <KV k="HTTP proxy"    v={`:${s.proxyPortHttp}`} mono/>
        <KV k="HTTPS proxy"   v={`:${s.proxyPortHttps}`} mono/>
      </Section>

      <Section title="Paths">
        <PathRow label="Socket"  path={s.socketPath}/>
        <PathRow label="Config"  path={s.configPath}/>
        <PathRow label="Certs"   path={s.certsPath}/>
      </Section>

      <div style={{ marginTop: 24, display: 'flex', gap: 8, fontSize: 11.5 }}>
        <button style={secondaryBtn}><Icon.ExternalLink size={11}/> GitHub repo</button>
        <button style={secondaryBtn}><Icon.ExternalLink size={11}/> Docs</button>
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{
        fontSize: 10.5, fontWeight: 600, letterSpacing: 0.5,
        textTransform: 'uppercase', color: 'var(--pm-textTertiary)',
        marginBottom: 6,
      }}>{title}</div>
      <div style={{
        background: 'var(--pm-surface)',
        border: '0.5px solid var(--pm-border)',
        borderRadius: 8,
        overflow: 'hidden',
      }}>{children}</div>
    </div>
  );
}

function KV({ k, v, mono }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center',
      padding: '8px 12px',
      borderBottom: '0.5px solid var(--pm-divider)',
      fontSize: 12,
    }}>
      <span style={{ color: 'var(--pm-textSecondary)', width: 130 }}>{k}</span>
      <span className={mono ? 'pm-mono' : ''} style={{ color: 'var(--pm-text)' }}>{v}</span>
    </div>
  );
}

function PathRow({ label, path }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center',
      padding: '8px 12px',
      borderBottom: '0.5px solid var(--pm-divider)',
      fontSize: 12, gap: 10,
    }}>
      <span style={{ color: 'var(--pm-textSecondary)', width: 70 }}>{label}</span>
      <span className="pm-mono" style={{ flex: 1, color: 'var(--pm-text)', fontSize: 11.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{path}</span>
      <button title="Reveal in Finder" style={{ ...iconBtn, width: 24, height: 24 }}>
        <Icon.Reveal size={12}/>
      </button>
    </div>
  );
}

Object.assign(window, { PortmanWindow });
