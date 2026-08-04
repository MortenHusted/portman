# portman — macOS UI design brief (v0.2)

Design both surfaces of portman's macOS UI: the menubar popover **and** a main window that opens on demand. Deliver visual mockups, a working SwiftUI artifact that previews every state from mock data, and short decision notes.

## Product in one paragraph

portman is an OSS local DNS + HTTP(S) proxy for Mac developers. It auto-registers hostnames for Docker containers (via `dev.portman.host` / `dev.portman.port` labels) and for apps running directly on the host (via `portman add`). Users hit `http://crm.test` or `https://api.acme` in a browser and it just works — no `/etc/hosts`, no port-forwarding. Multiple TLDs coexist (`.test`, `.acme`, `.crm`, whatever the user registers). Each TLD is either plain HTTP or TLS via `mkcert`. Positioned against OrbStack minus the container-runtime lock-in. Dev tool for terminal people.

Reference aesthetics: **Tailscale menubar** (calm, compact), **Raycast** (density, keyboard-first), **Linear** (restraint, monochrome chrome, color reserved for meaning). **Not** Docker Desktop's dashboard.

## Two surfaces, different roles

**Menubar popover** — a glance surface that occasionally mutates. Opens on icon click. Four interactions, nothing more:
1. Start the daemon if it's down (triggers native macOS admin dialog via launchctl)
2. Add a static rule via an inline form
3. Remove a static rule via a hover-revealed trash button
4. Open the main window (link at the bottom)

**Main window** — richer management surface. Opens on demand (menubar "Open…" link, or `⌘ 0`). Everything heavier lives here:
- Entries table with filter + sort, batch remove
- TLD management (add / remove / toggle TLS)
- Status detail (dns port, proxy port, version, running since, config paths)
- Optional: log tail from the daemon

**Both** share the same data source and mutation paths; the window isn't modal, isn't blocking, and the menubar keeps working when it's open.

**Out of scope for this design:** in-app settings / preferences pane (there are none — config lives in CLI + filesystem), `install` / `uninstall` flows (CLI-only), a sidebar in the menubar, marketing heros, onboarding tutorials.

## Data model the UI renders

**Entry** (primary row type, from the daemon's IPC `ListEntries`):
```swift
struct Entry {
    var host: String            // "crm.test"
    var target: String          // "172.19.0.4:3000"
    var source: Source          // .container | .static
    var containerID: String?    // short id, nil for static
}
enum Source { case container, `static` }
```

**TLD** (from daemon's `TldList` + local `tls.json`):
```swift
struct TLD {
    var name: String            // "test" (no leading dot)
    var tlsMode: TlsMode        // .off | .mkcert | .le(future)
    var entryCount: Int         // derived
}
```

**Derived per-entry display fields** (the UI computes these from Entry + TLD):
```swift
var scheme: "http" | "https"   // from the entry's TLD tlsMode
var certStatus: .none | .ready | .pending | .error(String)
```
`certStatus` is only meaningful when scheme == https. The daemon doesn't surface this today; recommend in your decision notes whether it should be added to the IPC protocol or stay UI-derived. (For this design, treat it as UI-derived from "cert file exists on disk in `~/Library/Application Support/portman/certs/<host>.{pem,key}`" + optional lightweight state.)

**Daemon status:**
```swift
enum DaemonStatus {
    case unknown          // brief, at app launch before first poll
    case offline          // socket connect failed
    case online(version: String, runningSince: String, dnsPort: UInt16)
    case starting         // we just fired launchctl kickstart, awaiting online
}
```

## Interactions — menubar popover

**Header (always visible):**
- `portman` wordmark + version (subtle, monospace for version)
- Daemon status: colored dot (green/red/amber) + short label
- When `offline`: **Start daemon** button, prominent. Click triggers NSAppleScript → `launchctl kickstart -k system/dev.portman.daemon` with admin-privileges prompt.
- Refresh button (`⌘ R`)

**Entries section:**
- TLD grouping: **designer's call** (sectioned vs flat with TLD column). Justify in decision notes.
- Each row:
  - Scheme badge — `http` neutral, `https` happy when cert is `.ready`, amber dot when `.pending` or `.error`
  - **Hostname** — SF Mono, the row's hero
  - Source glyph — container (`shippingbox`) vs static (`house` or `laptopcomputer`). Icon-only + tooltip on hover.
  - Target `ip:port` — SF Mono, secondary (smaller, muted)
  - On hover: copy-URL + (for `source == .static`) trash button
  - Click anywhere neutral on the row → open `scheme://host` in default browser
- Empty state (daemon online, zero entries): friendly but terse, point at `portman add <host> <target>` in the CLI **and** show the inline Add form as the primary affordance.

**Footer:**
- `Add…` button → expands an **inline** form (not a sheet, not a new window):
  - `host` field (placeholder: `crm.acme`)
  - `target` field (placeholder: `127.0.0.1:3070`)
  - Submit (`⏎`) + Cancel (`⎋`)
  - Inline validation: if the host's TLD isn't registered, show `TLD .foo isn't managed — open the main window or run portman tld add foo`. Menubar does **not** register TLDs (needs sudo; deliberately CLI / window only).
- Tiny read-only TLD strip: `.test (mkcert) · .acme (http)`
- **Open window…** link
- **Quit** button (`⌘ Q`)

## Interactions — main window

**Layout:** `NavigationSplitView`. Sidebar lists three sections: **Entries**, **TLDs**, **About**. Detail pane on the right. Window title bar carries the daemon status badge on the right (a quieter version of the menubar's header).

**Entries pane:**
- Search / filter field at the top (filters by host or target substring)
- Native `Table` with sortable columns: Host · Target · Source · Container ID · Scheme
- Multi-select → batch remove (static entries only; container entries skipped with a one-line note)
- Add entry affordance (same inline-form pattern as the menubar, or a sheet if denser)

**TLDs pane:**
- Each row: `.tld-name` · TLS mode badge · entry count · actions
- Actions: toggle TLS (mkcert) on/off; remove TLD
- **Add TLD** button at the top: form with `name` + `TLS (mkcert)` toggle. Inline warnings for problematic names (`.local` blocked, `.internal` / `.dev` get advisories).
- Cert health panel visible when any TLD has TLS on: mkcert CA install status, count of certs issued, "regenerate all" action.

**About pane:**
- Daemon version, running since, dns port, proxy port, tls port
- File paths (socket, config, certs) — each with a "reveal in Finder" button
- Link to the GitHub repo

**Docked vs detached:** window is a standard macOS window. Close button hides it; app stays running (menubar still present). Reopened on-demand.

## States to design (render all of these)

**Menubar popover (6):**

1. **Happy path** — connected, 6–8 entries spread across `.test` (mkcert) and `.acme` (http). Mix of container + static. One entry `pending` cert, rest `ready`.
2. **Empty, connected** — zero entries. Inline Add form is the primary affordance.
3. **Daemon disconnected** — big Start button prominent. Show last-known entries greyed / dimmed, or hide them? Justify your choice in decision notes.
4. **Daemon starting** — spinner, "Authenticating with launchctl…" state.
5. **Add form open** — hostname field focused, a TLD validation error visible ("`.foo` isn't managed…").
6. **Hover states** — one static row hover (copy + trash), one container row hover (only copy), one https entry with cert `.error` (amber dot + tooltip pointing at `mkcert -install`).

**Main window (4):**

7. **Entries pane, many rows** — 20+ entries, scrolling, columns sorted by TLD.
8. **TLDs pane** — `.test (mkcert, 8 entries, CA trusted)` and `.acme (http, 3 entries)`. One row expanded to show the toggle.
9. **Add TLD form** — TLS toggle on, warning shown because user typed `internal` ("Apple intercepts `.internal` on recent macOS — this may not reliably take effect").
10. **About pane** — paths with reveal buttons, status detail.

## Visual direction

- **Native macOS.** `.regularMaterial` where appropriate, vibrancy, **light + dark mode both first-class**.
- `MenuBarExtra { … }.menuBarExtraStyle(.window)` for the popover. Width ~340–380pt; height adapts with a max then scrolls.
- **Dense but not cramped.** Dev-tool density. SF Mono for hostnames, targets, TLD strip, version strings. SF Pro for chrome.
- **Calm palette.** Accent color reserved for interactive affordances. Source differentiation is mostly via icon + tooltip; color is an assist, not a shout.
- Scheme badge: `https` is a happy green/teal when the cert is ready (users opted in; they should feel good about it). `http` is neutral grey. Amber only for `pending` or `error`.
- SF Symbols preferred throughout. Avoid the Docker whale (trademark + the product isn't Docker-specific).
- One tiny moment of playfulness allowed — probably in an empty state illustration or the app icon. Resist sprinkling. Chrome stays serious.

## What not to do

- Sidebar in the **menubar popover** (flat).
- A "Settings" / preferences pane (config is CLI + filesystem).
- Colorful pill badges everywhere.
- Emoji in the chrome.
- Modal sheets for the menubar popover.
- "Install" / "Uninstall" buttons (CLI-only flows).
- A marketing hero anywhere.

## Technical constraints

- **Swift Package** (`swift build`). No Xcode project. Minimize deps — ideally zero beyond what ships with macOS.
- **SwiftUI**, `MenuBarExtra` with `.window` style + a `Window` scene for the main window. macOS 13+ baseline; using macOS 14+ features is fine if it makes the UI noticeably nicer (say so in your notes).
- Data arrives over a **Unix socket** at `~/Library/Application Support/portman/portman.sock` using 4-byte big-endian length-prefix JSON frames. Requests/responses exist: `ListEntries`, `Status`, `AddStatic`, `RemoveStatic`, `TldList`, `TldAdd`, `TldRemove`.
- **Mutations** shell out to `/usr/local/bin/portman` (the CLI) with `Process`. The CLI handles sudo elevation for `/etc/resolver/` + launchctl. The UI layer **does not** touch privileges directly.
- Daemon start/restart: shell out to `launchctl kickstart -k system/dev.portman.daemon` via `NSAppleScript` "do shell script with administrator privileges" so the macOS admin dialog appears.
- Menubar runs as a **user LaunchAgent**, daemon as a **system LaunchDaemon** — already installed by `portman install`.
- The app is launched with `NSApp.setActivationPolicy(.accessory)` (no Dock icon).

## Deliverables

1. **Visual mockups** for at minimum the four "hero" states — happy-path menubar, disconnected menubar, entries-pane window with many rows, TLDs-pane window. Ideally all ten states listed above. Light + dark mode for at least the hero states.
2. **Working SwiftUI implementation** — a small file set that renders every state from mock data. Include a preview picker (or sidebar) that flips between states so the review can step through them without real daemon state.
3. **Decision notes** — short paragraphs on each:
   - **TLD grouping in the menubar:** sectioned vs flat with a column, and why
   - **Scheme / cert badge treatment:** what `https + ready` looks like, what `pending` and `error` look like, and how the happy state avoids feeling alarmist
   - **Disconnected state:** dim-entries vs hide-entries, and why
   - **Menubar vs window split:** what tipped each affordance into one surface vs the other
   - **`certStatus` in the IPC protocol:** should we add it to the `Entry` response, or keep it UI-derived? Your recommendation.
   - **What you'd warn me about if I tried to ship this** — three things max.

## Existing reality to respect

- We already have a working menubar popover (Phase 8–10) and a daemon (Phases 1–7). This brief is to *redesign* the surfaces, not start from scratch. If an existing affordance is kept as-is with a visual refresh, that's fine — say so.
- The CLI is the canonical interface. Everything the UI does must be achievable from the terminal without the UI installed. The UI is quality-of-life.
- Users of this tool are Rails / Node / Go / DB-container developers. Keyboard shortcuts matter. `⌘` key affordances preferred over mouse-heavy flows where it doesn't hurt discoverability.
