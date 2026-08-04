// Shared atoms — status dots, badges, buttons, keyboard chips.

function StatusDot({ status, size = 7, pulse = false }) {
  const colorVar = {
    online: 'var(--pm-online)',
    offline: 'var(--pm-offline)',
    starting: 'var(--pm-warning)',
    unknown: 'var(--pm-textTertiary)',
  }[status] || 'var(--pm-textTertiary)';
  return (
    <span
      className={pulse ? 'pm-pulse' : ''}
      style={{
        display: 'inline-block', width: size, height: size, borderRadius: '50%',
        background: colorVar,
        boxShadow: `0 0 0 3px ${colorVar.replace('var(--pm-', 'var(--pm-').replace(')', 'Soft)')}`,
      }}
    />
  );
}

function SchemeBadge({ scheme, cert }) {
  if (scheme === 'http') {
    return (
      <span className="pm-mono" style={{
        fontSize: 10, fontWeight: 500, letterSpacing: 0.2,
        padding: '2px 6px', borderRadius: 4,
        background: 'var(--pm-httpBg)', color: 'var(--pm-httpText)',
        textTransform: 'lowercase',
      }}>http</span>
    );
  }
  // https
  const amber = cert === 'pending' || cert === 'error';
  const bg = amber ? 'var(--pm-warningSoft)' : 'var(--pm-httpsBg)';
  const fg = amber ? 'var(--pm-warning)' : 'var(--pm-httpsText)';
  return (
    <span className="pm-mono" style={{
      fontSize: 10, fontWeight: 500, letterSpacing: 0.2,
      padding: '2px 6px', borderRadius: 4,
      background: bg, color: fg,
      display: 'inline-flex', alignItems: 'center', gap: 4,
      textTransform: 'lowercase',
    }}>
      https
      {amber && <span style={{ width: 5, height: 5, borderRadius: '50%', background: fg, display: 'inline-block' }}/>}
    </span>
  );
}

function KeyCap({ children }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      minWidth: 15, height: 15, padding: '0 4px',
      fontSize: 10.5, fontFamily: FONTS.ui, fontWeight: 500,
      color: 'var(--pm-textSecondary)',
      background: 'var(--pm-surfaceHover)',
      border: '0.5px solid var(--pm-border)',
      borderRadius: 3,
    }}>{children}</span>
  );
}

function TinyBtn({ children, onClick, title, variant = 'ghost', style = {} }) {
  const base = {
    height: 22, padding: '0 8px', borderRadius: 5,
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 5,
    fontSize: 12, fontFamily: FONTS.ui, fontWeight: 500,
    border: 'none', cursor: 'pointer',
    color: 'var(--pm-text)',
  };
  const styles = {
    ghost: { ...base, background: 'transparent', color: 'var(--pm-textSecondary)' },
    soft:  { ...base, background: 'var(--pm-surfaceHover)' },
    accent:{ ...base, background: 'var(--pm-accent)', color: 'var(--pm-accentText)' },
    outline:{ ...base, background: 'transparent', border: '0.5px solid var(--pm-borderStrong)' },
  }[variant];
  return <button title={title} onClick={onClick} style={{ ...styles, ...style }}>{children}</button>;
}

// Row with optional hover state "forced on" via hoverForce prop (for static mockups).
function EntryRow({ entry, hoverForce = false, showTooltip = null, onCopy, onTrash, onOpen }) {
  const [hover, setHover] = React.useState(false);
  const isHover = hover || hoverForce;

  const scheme = entry.cert === 'none' ? 'http' : 'https';
  const isContainer = entry.source === 'container';

  return (
    <div
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        position: 'relative',
        display: 'grid',
        gridTemplateColumns: 'auto 1fr auto auto',
        gridColumnGap: 8,
        alignItems: 'center',
        padding: '5px 12px 5px 12px',
        borderRadius: 6,
        cursor: 'default',
        background: isHover ? 'var(--pm-rowHover)' : 'transparent',
      }}
    >
      {/* Scheme badge */}
      <div style={{ width: 48 }}>
        <SchemeBadge scheme={scheme} cert={entry.cert}/>
      </div>

      {/* Host + (below) target */}
      <div style={{ minWidth: 0 }}>
        <div className="pm-mono" style={{
          fontSize: 12.5, fontWeight: 500, color: 'var(--pm-text)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{entry.host}</div>
        <div className="pm-mono" style={{
          fontSize: 10.5, color: 'var(--pm-textTertiary)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          marginTop: 1,
        }}>{entry.target}{isContainer && <span style={{ marginLeft: 6, opacity: 0.7 }}>· {entry.containerID?.slice(0, 6)}</span>}</div>
      </div>

      {/* Source glyph */}
      <div
        title={isContainer ? `container ${entry.containerID?.slice(0,10)}` : 'static (portman add)'}
        style={{
          color: 'var(--pm-textTertiary)',
          display: 'flex', alignItems: 'center',
          width: 16, height: 16, justifyContent: 'center',
        }}
      >
        {isContainer ? <Icon.Shippingbox size={13}/> : <Icon.Laptop size={13}/>}
      </div>

      {/* Hover actions */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 2,
        opacity: isHover ? 1 : 0,
        transition: 'opacity .12s',
        width: entry.source === 'static' ? 44 : 22,
      }}>
        <button title="Copy URL" style={iconBtn}>
          <Icon.Copy size={12}/>
        </button>
        {entry.source === 'static' && (
          <button title="Remove" style={iconBtn}>
            <Icon.Trash size={12}/>
          </button>
        )}
      </div>

      {/* Cert error tooltip */}
      {showTooltip === 'cert-error' && (
        <div style={{
          position: 'absolute', bottom: '100%', left: 48, marginBottom: 4,
          background: 'var(--pm-popoverSolid)',
          border: '0.5px solid var(--pm-borderStrong)',
          boxShadow: 'var(--pm-popoverShadow)',
          borderRadius: 6, padding: '6px 9px',
          fontSize: 11.5, color: 'var(--pm-text)',
          maxWidth: 260, zIndex: 3, lineHeight: 1.35,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2, color: 'var(--pm-warning)' }}>
            <Icon.Warning size={11}/>
            <span style={{ fontWeight: 600, fontSize: 11.5 }}>Certificate not trusted</span>
          </div>
          <div style={{ color: 'var(--pm-textSecondary)' }}>
            mkcert root CA isn't installed. Run{' '}
            <span className="pm-mono" style={{ color: 'var(--pm-text)' }}>mkcert -install</span>.
          </div>
        </div>
      )}
    </div>
  );
}

const iconBtn = {
  width: 20, height: 20, borderRadius: 4,
  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
  background: 'transparent', border: 'none', cursor: 'pointer',
  color: 'var(--pm-textSecondary)',
};

Object.assign(window, { StatusDot, SchemeBadge, KeyCap, TinyBtn, EntryRow, iconBtn });
