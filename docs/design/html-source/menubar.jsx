// Menubar popover — 340–380pt wide, macOS MenuBarExtra .window style.
// Renders every popover state from props. Stateless re: data; parent controls which state.

function PortmanMenubar({
  width = 360,
  status = 'online',            // online | offline | starting | unknown
  statusMeta = PM_STATUS.online,
  entries = PM_ENTRIES_HAPPY,
  tlds = PM_TLDS_MENUBAR,
  // state-specific flags
  addFormOpen = false,
  addFormHost = 'api.foo',
  addFormTarget = '127.0.0.1:',
  addFormError = null,          // string | null
  hoverForce = null,            // { host, kind: 'copy' | 'copy-trash' | 'cert-error' }
  disconnectedMode = 'dim',     // 'dim' | 'hide'
  showTldChip = true,
}) {
  const entriesByTld = {};
  entries.forEach(e => { (entriesByTld[e.tld] = entriesByTld[e.tld] || []).push(e); });
  const tldOrder = Array.from(new Set(entries.map(e => e.tld)));

  const isOffline = status === 'offline';
  const isStarting = status === 'starting';
  const isEmpty = status === 'online' && entries.length === 0;
  const showEntries = !isOffline || disconnectedMode === 'dim';

  return (
    <div style={{
      width,
      borderRadius: 10,
      background: 'var(--pm-popoverBg)',
      backdropFilter: 'blur(40px) saturate(180%)',
      WebkitBackdropFilter: 'blur(40px) saturate(180%)',
      border: '0.5px solid var(--pm-borderStrong)',
      boxShadow: 'var(--pm-popoverShadow)',
      overflow: 'hidden',
      fontFamily: FONTS.ui,
    }}>
      {/* HEADER */}
      <div style={{
        padding: '10px 12px 10px 12px',
        display: 'flex', alignItems: 'center', gap: 8,
        borderBottom: '0.5px solid var(--pm-divider)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, flex: 1, minWidth: 0 }}>
          <span style={{ color: 'var(--pm-text)', display: 'flex', alignItems: 'center' }}>
            <Icon.PortmanMark size={15}/>
          </span>
          <span style={{ fontSize: 13, fontWeight: 600, letterSpacing: -0.1, color: 'var(--pm-text)' }}>portman</span>
          <span className="pm-mono" style={{ fontSize: 10.5, color: 'var(--pm-textTertiary)', marginTop: 1 }}>
            {statusMeta?.version ? `v${statusMeta.version}` : ''}
          </span>
        </div>

        {/* Status chip */}
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          padding: '3px 8px 3px 7px',
          borderRadius: 10,
          background: 'var(--pm-surfaceHover)',
          fontSize: 11,
          color: 'var(--pm-textSecondary)',
        }}>
          <StatusDot status={status} pulse={isStarting}/>
          <span style={{ fontWeight: 500 }}>
            {status === 'online' && 'connected'}
            {status === 'offline' && 'daemon offline'}
            {status === 'starting' && 'starting'}
            {status === 'unknown' && 'connecting'}
          </span>
        </div>

        <button title="Refresh (⌘R)" style={{ ...iconBtn, width: 22, height: 22, marginLeft: 2 }}>
          <Icon.Refresh size={12}/>
        </button>
      </div>

      {/* OFFLINE: big start button area */}
      {isOffline && (
        <div style={{ padding: '14px 12px 12px' }}>
          <div style={{
            display: 'flex', alignItems: 'flex-start', gap: 10,
            padding: '10px 11px', borderRadius: 8,
            background: 'var(--pm-offlineSoft)',
            border: '0.5px solid rgba(199,70,58,.22)',
          }}>
            <div style={{ marginTop: 1, color: 'var(--pm-offline)' }}>
              <Icon.Warning size={13}/>
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--pm-text)' }}>Daemon isn't running</div>
              <div style={{ fontSize: 11.5, color: 'var(--pm-textSecondary)', marginTop: 2, lineHeight: 1.4 }}>
                Last seen {statusMeta?.lastSeen || 'recently'}. DNS resolution and the HTTP(S) proxy are unavailable until it's back.
              </div>
            </div>
          </div>
          <button style={{
            marginTop: 10, width: '100%', height: 30,
            background: 'var(--pm-accent)', color: 'var(--pm-accentText)',
            border: 'none', borderRadius: 7,
            fontSize: 13, fontWeight: 600, cursor: 'pointer',
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 7,
            fontFamily: FONTS.ui,
            boxShadow: '0 1px 0 rgba(0,0,0,.06), inset 0 1px 0 rgba(255,255,255,.18)',
          }}>
            <Icon.Lock size={11}/>
            Start daemon
            <span style={{ opacity: 0.75, marginLeft: 2, fontSize: 10.5, fontWeight: 500 }}>· needs admin</span>
          </button>
        </div>
      )}

      {/* STARTING: spinner panel */}
      {isStarting && (
        <div style={{ padding: '20px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div className="pm-spin" style={{
              width: 15, height: 15, borderRadius: '50%',
              border: '1.5px solid var(--pm-warningSoft)',
              borderTopColor: 'var(--pm-warning)',
            }}/>
            <div>
              <div style={{ fontSize: 12.5, fontWeight: 600 }}>Starting daemon…</div>
              <div style={{ fontSize: 11.5, color: 'var(--pm-textSecondary)', marginTop: 1 }}>
                Authenticating with launchctl…
              </div>
            </div>
          </div>
          <div style={{
            marginTop: 12, padding: '8px 10px', borderRadius: 6,
            background: 'var(--pm-surfaceHover)',
            fontSize: 11, color: 'var(--pm-textSecondary)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <Icon.Lock size={10}/>
            <span>macOS will ask for your password.</span>
          </div>
        </div>
      )}

      {/* ENTRIES */}
      {!isStarting && !isEmpty && showEntries && (
        <div style={{
          maxHeight: 340, overflowY: 'auto',
          padding: '6px 4px 4px',
          opacity: isOffline ? 0.45 : 1,
          pointerEvents: isOffline ? 'none' : 'auto',
          filter: isOffline ? 'saturate(0.6)' : 'none',
        }} className="pm-scroll">
          {tldOrder.map((tld, i) => (
            <div key={tld} style={{ marginBottom: i === tldOrder.length - 1 ? 0 : 6 }}>
              {/* TLD section header */}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '4px 10px 4px 10px',
              }}>
                <span className="pm-mono" style={{
                  fontSize: 10.5, fontWeight: 600, letterSpacing: 0.2,
                  color: 'var(--pm-textSecondary)',
                  textTransform: 'lowercase',
                }}>.{tld}</span>
                <span style={{
                  fontSize: 9.5, letterSpacing: 0.5, textTransform: 'uppercase',
                  color: 'var(--pm-textTertiary)', fontWeight: 600,
                  padding: '1px 5px', borderRadius: 3,
                  background: (tlds.find(t => t.name === tld)?.tlsMode === 'mkcert') ? 'var(--pm-httpsBg)' : 'var(--pm-httpBg)',
                  color: (tlds.find(t => t.name === tld)?.tlsMode === 'mkcert') ? 'var(--pm-httpsText)' : 'var(--pm-httpText)',
                }}>{(tlds.find(t => t.name === tld)?.tlsMode === 'mkcert') ? 'TLS' : 'HTTP'}</span>
                <span style={{
                  fontSize: 10.5, color: 'var(--pm-textTertiary)',
                  marginLeft: 'auto',
                }}>{entriesByTld[tld].length}</span>
              </div>
              {entriesByTld[tld].map((e, j) => {
                const isHoverForced = hoverForce && hoverForce.host === e.host;
                return (
                  <EntryRow
                    key={e.host}
                    entry={e}
                    hoverForce={!!isHoverForced}
                    showTooltip={isHoverForced && hoverForce.kind === 'cert-error' ? 'cert-error' : null}
                  />
                );
              })}
            </div>
          ))}
        </div>
      )}

      {/* EMPTY state */}
      {isEmpty && !addFormOpen && (
        <div style={{ padding: '18px 18px 14px', textAlign: 'center' }}>
          <HarborIllustration/>
          <div style={{ fontSize: 13, fontWeight: 600, marginTop: 8 }}>No hosts registered</div>
          <div style={{ fontSize: 11.5, color: 'var(--pm-textSecondary)', marginTop: 3, lineHeight: 1.45 }}>
            Add one below, or in a terminal:<br/>
            <span className="pm-mono" style={{ fontSize: 11, color: 'var(--pm-text)' }}>portman add crm.test 127.0.0.1:3000</span>
          </div>
        </div>
      )}

      {/* OFFLINE + hide mode */}
      {isOffline && disconnectedMode === 'hide' && (
        <div style={{ padding: '4px 14px 14px', fontSize: 11, color: 'var(--pm-textTertiary)' }}>
          Entries will return when the daemon is back online.
        </div>
      )}

      {/* ADD FORM */}
      {addFormOpen && (
        <AddEntryForm
          host={addFormHost}
          target={addFormTarget}
          error={addFormError}
        />
      )}

      {/* FOOTER */}
      <div style={{
        borderTop: '0.5px solid var(--pm-divider)',
        padding: '6px 6px 6px 6px',
        display: 'flex', alignItems: 'center', gap: 4,
      }}>
        {!addFormOpen && (
          <button style={{
            height: 26, padding: '0 9px 0 7px', borderRadius: 6,
            display: 'inline-flex', alignItems: 'center', gap: 5,
            fontSize: 12, fontWeight: 500,
            background: 'transparent', border: 'none', cursor: 'pointer',
            color: 'var(--pm-text)',
            fontFamily: FONTS.ui,
          }}>
            <Icon.Plus size={11}/>
            Add…
          </button>
        )}

        <div style={{ flex: 1 }}/>

        {showTldChip && !addFormOpen && (
          <div className="pm-mono" style={{
            fontSize: 10.5, color: 'var(--pm-textTertiary)',
            padding: '0 6px',
            display: 'flex', alignItems: 'center', gap: 6,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {tlds.map((t, i) => (
              <React.Fragment key={t.name}>
                {i > 0 && <span style={{ opacity: 0.5 }}>·</span>}
                <span>.{t.name}<span style={{ opacity: 0.6 }}> {t.tlsMode === 'mkcert' ? '(tls)' : '(http)'}</span></span>
              </React.Fragment>
            ))}
          </div>
        )}

        <button style={{
          height: 26, padding: '0 9px', borderRadius: 6,
          display: 'inline-flex', alignItems: 'center', gap: 5,
          fontSize: 12, fontWeight: 500,
          background: 'transparent', border: 'none', cursor: 'pointer',
          color: 'var(--pm-textSecondary)',
          fontFamily: FONTS.ui,
        }}>
          Open window…
          <KeyCap>⌘0</KeyCap>
        </button>

        <button title="Quit portman (⌘Q)" style={{ ...iconBtn, width: 26, height: 26 }}>
          <span style={{ fontSize: 11, color: 'var(--pm-textSecondary)' }}>⌘Q</span>
        </button>
      </div>
    </div>
  );
}

function AddEntryForm({ host, target, error }) {
  return (
    <div style={{
      borderTop: '0.5px solid var(--pm-divider)',
      background: 'var(--pm-surfaceHover)',
      padding: '10px 12px 10px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <span style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--pm-text)' }}>Add entry</span>
        <span style={{ fontSize: 10.5, color: 'var(--pm-textTertiary)' }}>static · this machine</span>
      </div>
      <div style={{ display: 'flex', gap: 6 }}>
        <Field label="host" value={host} focused={true} mono monospace placeholder="crm.sofus"/>
        <span style={{ alignSelf: 'center', color: 'var(--pm-textTertiary)', fontSize: 12 }}>→</span>
        <Field label="target" value={target} mono monospace placeholder="127.0.0.1:3070"/>
      </div>
      {error && (
        <div style={{
          marginTop: 8, display: 'flex', alignItems: 'flex-start', gap: 6,
          padding: '6px 8px', borderRadius: 5,
          background: 'var(--pm-warningSoft)',
          color: 'var(--pm-warning)',
          fontSize: 11.3, lineHeight: 1.4,
        }}>
          <div style={{ marginTop: 1 }}><Icon.Warning size={11}/></div>
          <div style={{ color: 'var(--pm-text)' }}>
            TLD <span className="pm-mono" style={{ color: 'var(--pm-warning)' }}>.foo</span> isn't managed. Open the main window, or run{' '}
            <span className="pm-mono" style={{ color: 'var(--pm-text)' }}>portman tld add foo</span>.
          </div>
        </div>
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8 }}>
        <div style={{ flex: 1 }}/>
        <button style={{
          height: 22, padding: '0 9px', borderRadius: 5,
          fontSize: 11.5, background: 'transparent', border: '0.5px solid var(--pm-borderStrong)',
          color: 'var(--pm-textSecondary)', fontFamily: FONTS.ui, cursor: 'pointer',
          display: 'inline-flex', alignItems: 'center', gap: 5,
        }}>
          Cancel <KeyCap>esc</KeyCap>
        </button>
        <button style={{
          height: 22, padding: '0 10px', borderRadius: 5,
          fontSize: 11.5, fontWeight: 600, background: 'var(--pm-accent)',
          color: 'var(--pm-accentText)', border: 'none', cursor: 'pointer',
          fontFamily: FONTS.ui,
          display: 'inline-flex', alignItems: 'center', gap: 5,
        }}>
          Add <KeyCap>⏎</KeyCap>
        </button>
      </div>
    </div>
  );
}

function Field({ label, value, focused, mono, placeholder }) {
  return (
    <div style={{ flex: 1, minWidth: 0 }}>
      <div style={{
        fontSize: 9.5, letterSpacing: 0.4, fontWeight: 600, textTransform: 'uppercase',
        color: 'var(--pm-textTertiary)', marginBottom: 2, paddingLeft: 2,
      }}>{label}</div>
      <div style={{
        height: 24, borderRadius: 5,
        background: 'var(--pm-surface)',
        border: focused ? '1.2px solid var(--pm-accent)' : '0.5px solid var(--pm-borderStrong)',
        boxShadow: focused ? '0 0 0 3px var(--pm-accentSoft)' : 'none',
        padding: '0 7px',
        display: 'flex', alignItems: 'center',
        fontSize: 12,
        fontFamily: mono ? FONTS.mono : FONTS.ui,
        color: 'var(--pm-text)',
      }}>
        {value ? value : <span style={{ color: 'var(--pm-textTertiary)' }}>{placeholder}</span>}
        {focused && <span className="pm-caret" style={{ color: 'var(--pm-accent)' }}/>}
      </div>
    </div>
  );
}

// Tiny harbor illustration — the "one moment of playfulness" for empty state.
function HarborIllustration() {
  return (
    <svg width="84" height="56" viewBox="0 0 84 56" fill="none" style={{ margin: '0 auto', display: 'block' }}>
      <defs>
        <linearGradient id="pm-water" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="var(--pm-accent)" stopOpacity="0.08"/>
          <stop offset="1" stopColor="var(--pm-accent)" stopOpacity="0"/>
        </linearGradient>
      </defs>
      {/* water */}
      <rect x="0" y="38" width="84" height="18" fill="url(#pm-water)"/>
      <path d="M2 42 Q 8 40 14 42 T 26 42 T 38 42 T 50 42 T 62 42 T 74 42 T 82 42" stroke="var(--pm-accent)" strokeOpacity="0.35" strokeWidth="0.8" fill="none"/>
      <path d="M2 48 Q 8 46 14 48 T 26 48 T 38 48 T 50 48 T 62 48 T 74 48 T 82 48" stroke="var(--pm-accent)" strokeOpacity="0.22" strokeWidth="0.8" fill="none"/>

      {/* anchor */}
      <g stroke="var(--pm-text)" strokeWidth="1.3" fill="none" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="42" cy="14" r="2.6"/>
        <path d="M42 16.6V38"/>
        <path d="M35 22h14"/>
        <path d="M28 30a14 14 0 0 0 28 0"/>
      </g>

      {/* little boat, far right */}
      <g stroke="var(--pm-textSecondary)" strokeWidth="1" fill="none" strokeLinecap="round" strokeLinejoin="round" opacity="0.7">
        <path d="M64 38 L 78 38 L 76 42 L 66 42 Z"/>
        <path d="M71 38 V 32"/>
        <path d="M71 32 L 76 37"/>
      </g>
    </svg>
  );
}

Object.assign(window, { PortmanMenubar, AddEntryForm, HarborIllustration });
