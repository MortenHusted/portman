// Portman design tokens — Linear/Tailscale-flavored, monochrome with warm accent.
// Light + dark both first-class. Emulating macOS materials in HTML.

const PORTMAN_TOKENS = {
  light: {
    // Backgrounds — layered like macOS vibrancy
    popoverBg: 'rgba(246, 245, 243, 0.82)',       // vibrancy over desktop
    popoverSolid: '#F6F5F3',
    windowBg: '#F6F5F3',
    sidebarBg: 'rgba(241, 239, 236, 0.72)',
    surface: '#FFFFFF',
    surfaceRaised: '#FFFFFF',
    surfaceHover: 'rgba(0, 0, 0, 0.035)',
    surfacePress: 'rgba(0, 0, 0, 0.06)',

    // Borders & separators
    border: 'rgba(0, 0, 0, 0.08)',
    borderStrong: 'rgba(0, 0, 0, 0.14)',
    divider: 'rgba(0, 0, 0, 0.06)',

    // Text
    text: '#1A1816',
    textSecondary: 'rgba(26, 24, 22, 0.62)',
    textTertiary: 'rgba(26, 24, 22, 0.42)',
    textDisabled: 'rgba(26, 24, 22, 0.28)',

    // Accent — warm amber/copper. Used sparingly for interactive affordances.
    accent: '#C96442',
    accentHover: '#B85636',
    accentSoft: 'rgba(201, 100, 66, 0.12)',
    accentText: '#FFFFFF',

    // Status — muted, never shouty
    online: '#3D9A6B',           // calm green
    onlineSoft: 'rgba(61, 154, 107, 0.12)',
    offline: '#C7463A',          // calm red
    offlineSoft: 'rgba(199, 70, 58, 0.10)',
    warning: '#C78B3A',          // calm amber
    warningSoft: 'rgba(199, 139, 58, 0.12)',
    pending: '#C78B3A',

    // Scheme badges
    httpBg: 'rgba(0, 0, 0, 0.055)',
    httpText: 'rgba(26, 24, 22, 0.58)',
    httpsBg: 'rgba(61, 154, 107, 0.13)',
    httpsText: '#2F7A56',

    // Row hover / selection
    rowHover: 'rgba(0, 0, 0, 0.035)',
    rowSelect: 'rgba(201, 100, 66, 0.10)',

    // Shadows
    popoverShadow: '0 12px 40px rgba(0,0,0,0.18), 0 0 0 0.5px rgba(0,0,0,0.08)',
    windowShadow: '0 24px 60px rgba(0,0,0,0.22), 0 0 0 0.5px rgba(0,0,0,0.10)',
  },

  dark: {
    popoverBg: 'rgba(32, 31, 30, 0.78)',
    popoverSolid: '#1F1E1D',
    windowBg: '#1B1A19',
    sidebarBg: 'rgba(26, 25, 24, 0.72)',
    surface: '#262523',
    surfaceRaised: '#2B2A28',
    surfaceHover: 'rgba(255, 255, 255, 0.05)',
    surfacePress: 'rgba(255, 255, 255, 0.09)',

    border: 'rgba(255, 255, 255, 0.08)',
    borderStrong: 'rgba(255, 255, 255, 0.14)',
    divider: 'rgba(255, 255, 255, 0.06)',

    text: '#F1EEE9',
    textSecondary: 'rgba(241, 238, 233, 0.62)',
    textTertiary: 'rgba(241, 238, 233, 0.40)',
    textDisabled: 'rgba(241, 238, 233, 0.24)',

    accent: '#E07A58',
    accentHover: '#EC8863',
    accentSoft: 'rgba(224, 122, 88, 0.16)',
    accentText: '#1A1816',

    online: '#56B885',
    onlineSoft: 'rgba(86, 184, 133, 0.15)',
    offline: '#E0695C',
    offlineSoft: 'rgba(224, 105, 92, 0.14)',
    warning: '#E0A95A',
    warningSoft: 'rgba(224, 169, 90, 0.15)',
    pending: '#E0A95A',

    httpBg: 'rgba(255, 255, 255, 0.06)',
    httpText: 'rgba(241, 238, 233, 0.58)',
    httpsBg: 'rgba(86, 184, 133, 0.14)',
    httpsText: '#7FCBA2',

    rowHover: 'rgba(255, 255, 255, 0.045)',
    rowSelect: 'rgba(224, 122, 88, 0.14)',

    popoverShadow: '0 12px 40px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.08)',
    windowShadow: '0 24px 60px rgba(0,0,0,0.55), 0 0 0 0.5px rgba(255,255,255,0.10)',
  },
};

const FONTS = {
  ui: '-apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro", system-ui, sans-serif',
  mono: '"SF Mono", "JetBrains Mono", ui-monospace, Menlo, monospace',
};

// Inject global font + desktop wallpaper styles once
if (typeof document !== 'undefined' && !document.getElementById('pm-globals')) {
  const s = document.createElement('style');
  s.id = 'pm-globals';
  s.textContent = `
    .pm-mono { font-family: ${FONTS.mono}; font-feature-settings: "ss01", "cv11"; }
    .pm-ui { font-family: ${FONTS.ui}; }
    .pm-scroll::-webkit-scrollbar { width: 8px; height: 8px; }
    .pm-scroll::-webkit-scrollbar-track { background: transparent; }
    .pm-scroll::-webkit-scrollbar-thumb { background: rgba(128,128,128,.25); border-radius: 4px; border: 2px solid transparent; background-clip: padding-box; }
    .pm-scroll::-webkit-scrollbar-thumb:hover { background: rgba(128,128,128,.4); background-clip: padding-box; border: 2px solid transparent; }

    /* Focus ring */
    .pm-focus:focus-visible { outline: 2px solid var(--pm-accent); outline-offset: 1px; }

    /* Desktop wallpapers for the artboard backdrop */
    .pm-desk-light {
      background:
        radial-gradient(1200px 800px at 20% 0%, #f8d9b8 0%, transparent 55%),
        radial-gradient(900px 700px at 100% 100%, #e8bfa8 0%, transparent 60%),
        linear-gradient(160deg, #f2c595 0%, #c88a72 100%);
    }
    .pm-desk-dark {
      background:
        radial-gradient(1200px 800px at 20% 0%, #3a2a28 0%, transparent 55%),
        radial-gradient(900px 700px at 100% 100%, #2a1f1e 0%, transparent 60%),
        linear-gradient(160deg, #1f1715 0%, #0e0a09 100%);
    }

    /* blinking caret */
    @keyframes pmCaret { 0%,49%{opacity:1} 50%,100%{opacity:0} }
    .pm-caret::after { content:""; display:inline-block; width:1px; height:1em; background:currentColor; margin-left:1px; vertical-align:-2px; animation: pmCaret 1s steps(2) infinite; }

    /* subtle dot pulse */
    @keyframes pmPulse { 0%,100%{opacity:.45} 50%{opacity:1} }
    .pm-pulse { animation: pmPulse 1.4s ease-in-out infinite; }

    @keyframes pmSpin { to { transform: rotate(360deg); } }
    .pm-spin { animation: pmSpin 0.9s linear infinite; }
  `;
  document.head.appendChild(s);
}

// ThemeProvider — sets CSS variables on a wrapper div
function PMTheme({ mode = 'light', children, style = {} }) {
  const t = PORTMAN_TOKENS[mode];
  const cssVars = {};
  for (const k in t) cssVars[`--pm-${k}`] = t[k];
  cssVars['--pm-font-ui'] = FONTS.ui;
  cssVars['--pm-font-mono'] = FONTS.mono;
  return (
    <div
      className="pm-ui"
      style={{
        ...cssVars,
        color: t.text,
        fontFamily: FONTS.ui,
        fontSize: 13,
        lineHeight: 1.35,
        WebkitFontSmoothing: 'antialiased',
        MozOsxFontSmoothing: 'grayscale',
        ...style,
      }}
    >
      {children}
    </div>
  );
}

Object.assign(window, { PORTMAN_TOKENS, FONTS, PMTheme });
