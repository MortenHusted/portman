// Minimal SF-Symbol-ish inline icons. Hand-drawn to feel like SF Symbols
// at ~13–16px. All take size + color via currentColor.

const Icon = {
  Shippingbox: ({ size = 14 }) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 5.5 8 2.5l6 3v6L8 14.5l-6-3v-6Z"/>
      <path d="m2 5.5 6 3 6-3"/>
      <path d="M8 8.5V14.5"/>
      <path d="M5 4l6 3"/>
    </svg>
  ),
  Laptop: ({ size = 14 }) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="4" width="10" height="7" rx="1"/>
      <path d="M1.5 12h13"/>
    </svg>
  ),
  House: ({ size = 14 }) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2.5 7 8 2.5 13.5 7v6.5H2.5V7Z"/>
      <path d="M6.5 13.5V9.5h3v4"/>
    </svg>
  ),
  Copy: ({ size = 13 }) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <rect x="5" y="5" width="8" height="9" rx="1.5"/>
      <path d="M3 11V3.5A1.5 1.5 0 0 1 4.5 2H10"/>
    </svg>
  ),
  Trash: ({ size = 13 }) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 4.5h10"/>
      <path d="M6 4.5V3.2A.7.7 0 0 1 6.7 2.5h2.6a.7.7 0 0 1 .7.7V4.5"/>
      <path d="M4.5 4.5 5 13a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1l.5-8.5"/>
    </svg>
  ),
  Plus: ({ size = 12 }) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round">
      <path d="M8 3.5v9M3.5 8h9"/>
    </svg>
  ),
  Refresh: ({ size = 12 }) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"/>
      <path d="M13.5 3v3H10.5"/>
    </svg>
  ),
  Chevron: ({ size = 10, dir = 'down' }) => {
    const r = { down: 0, up: 180, right: -90, left: 90 }[dir];
    return (
      <svg width={size} height={size} viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" style={{ transform: `rotate(${r}deg)` }}>
        <path d="m2 4 3 3 3-3"/>
      </svg>
    );
  },
  Search: ({ size = 13 }) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="7" cy="7" r="4.2"/>
      <path d="m10.2 10.2 3 3"/>
    </svg>
  ),
  Lock: ({ size = 11 }) => (
    <svg width={size} height={size} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2.5" y="5.5" width="7" height="5" rx="1"/>
      <path d="M4 5.5V4a2 2 0 0 1 4 0v1.5"/>
    </svg>
  ),
  ExternalLink: ({ size = 11 }) => (
    <svg width={size} height={size} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4.5 2.5H3a.5.5 0 0 0-.5.5v6a.5.5 0 0 0 .5.5h6a.5.5 0 0 0 .5-.5V7.5"/>
      <path d="M7 2.5h2.5V5"/>
      <path d="m5 7 4.5-4.5"/>
    </svg>
  ),
  Reveal: ({ size = 12 }) => (
    <svg width={size} height={size} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 4h3l1 1.2h6V11H2V4Z"/>
    </svg>
  ),
  Gear: ({ size = 12 }) => (
    <svg width={size} height={size} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="7" cy="7" r="1.6"/>
      <path d="M7 1.5v1.2M7 11.3v1.2M2.4 2.4l.9.9M10.7 10.7l.9.9M1.5 7h1.2M11.3 7h1.2M2.4 11.6l.9-.9M10.7 3.3l.9-.9"/>
    </svg>
  ),
  Checkmark: ({ size = 11 }) => (
    <svg width={size} height={size} viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d="m2.5 6.5 2.5 2.5 5-6"/>
    </svg>
  ),
  Warning: ({ size = 11 }) => (
    <svg width={size} height={size} viewBox="0 0 12 12" fill="currentColor">
      <path d="M5.1 1.6a1 1 0 0 1 1.8 0l4.3 7.9a1 1 0 0 1-.9 1.5H1.7a1 1 0 0 1-.9-1.5l4.3-7.9Z" opacity=".18"/>
      <path d="M5.1 1.6a1 1 0 0 1 1.8 0l4.3 7.9a1 1 0 0 1-.9 1.5H1.7a1 1 0 0 1-.9-1.5l4.3-7.9Z" fill="none" stroke="currentColor" strokeWidth="1.1"/>
      <path d="M6 4.5v3M6 8.6v.4" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" fill="none"/>
    </svg>
  ),
  Dot: ({ size = 6, color }) => (
    <svg width={size} height={size} viewBox="0 0 6 6"><circle cx="3" cy="3" r="3" fill={color || 'currentColor'}/></svg>
  ),
  Anchor: ({ size = 20 }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="5" r="1.6"/>
      <path d="M12 6.6V21"/>
      <path d="M8 10h8"/>
      <path d="M4 15a8 8 0 0 0 16 0"/>
      <path d="M4 15h2M20 15h-2"/>
    </svg>
  ),
  PortmanMark: ({ size = 14 }) => (
    // A simplified port/harbor mark — anchor ring + pier
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="4.5" r="1.4"/>
      <path d="M8 5.9V13.5"/>
      <path d="M5.6 8.2h4.8"/>
      <path d="M2.5 11a5.5 5.5 0 0 0 11 0"/>
    </svg>
  ),
  Sidebar: ({ size = 13 }) => (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3">
      <rect x="2" y="3" width="12" height="10" rx="1.5"/>
      <path d="M6 3v10"/>
    </svg>
  ),
};

Object.assign(window, { Icon });
