# Design

Visual system for the vpn.io desktop tray client. Concept: **"Quiet Signal"** —
a calm, instrument-like panel organized around one large connection indicator;
state reads instantly by color + shape + word, everything else stays quiet.

Reference implementation: [`docs/ui/mockup.html`](ui/mockup.html) — open it in a
browser (append `?theme=dark` to preview dark). It renders all five states and
the import sheet in both themes, and is the source of truth for these tokens.
The shipping Wails front-end should reuse the same CSS custom properties.

- **Register:** product (design serves the task)
- **Aesthetic:** refined minimalism, Apple-faithful *before* iOS 26 ("Liquid
  Glass"). System SF typography, neutral surfaces, 8-pt grid, soft shadows,
  10–12px radii, calm accents, motion only as signal.
- **Themes:** light + dark, first-class, follow the OS preference.
- **Form factor:** a fixed-width (~360px) menu-bar / tray popover. Width is
  fixed; the popover grows in height with content.

---

## Color

All color is token-driven via CSS custom properties on `:root` (light) and
`:root[data-theme="dark"]`. Never hard-code a color in a component.

### Surfaces, text, lines

| Token | Light | Dark | Role |
|---|---|---|---|
| `--c-window` | `#f5f5f7` | `#1c1c1e` | popover body (the menu-bar material) |
| `--c-surface` | `#ffffff` | `#2c2c2e` | raised controls / wells |
| `--c-fill` | `rgba(118,118,128,.08)` | `rgba(118,118,128,.20)` | quiet control fill (inputs, rows, quiet buttons) |
| `--c-fill-strong` | `rgba(118,118,128,.14)` | `rgba(118,118,128,.32)` | hover on quiet fill |
| `--c-text` | `#1d1d1f` | `#f5f5f7` | primary text |
| `--c-text-2` | `#636368` | `#a1a1a6` | secondary / **informational** text (≥4.5:1) |
| `--c-text-3` | `#86868b` | `#8e8e93` | tertiary / **decorative** (icons, chevrons; ≥3:1) |
| `--c-separator` | `rgba(60,60,67,.12)` | `rgba(84,84,88,.55)` | hairlines on surfaces |
| `--c-border` | `rgba(0,0,0,.06)` | `rgba(255,255,255,.10)` | outer popover hairline |
| `--c-on-accent` | `#ffffff` | `#ffffff` | text on a filled accent button |

### Accent (system blue) — three roles, intentionally split

System blue at full strength (`#007AFF`/`#0A84FF`) is below 4.5:1 against white
*as text* and behind white button labels. So blue is split by role; this keeps
the live indicator a true system blue (a graphic, where 3:1 applies) while text
and buttons stay AA-legible.

| Token | Light | Dark | Role | Contrast |
|---|---|---|---|---|
| `--c-accent` | `#007aff` | `#0a84ff` | indicator / spinner / focus ring (graphic only) | ≥3:1 |
| `--c-accent-fill` | `#0067d6` | `#0a6fdc` | filled primary-button background | white ≥4.5:1 |
| `--c-accent-tint` | `rgba(0,122,255,.10)` | `rgba(10,132,255,.18)` | connecting-state orb wash | — |
| `--c-link` | `#0067d6` | `#4aa3ff` | accent used **as text** (row actions) | ≥4.5:1 |

### Semantic state colors

One color per tunnel state. Each is always paired with a glyph + word, so it is
never the sole carrier of meaning.

| State | Token / tint | Light | Dark | Glyph |
|---|---|---|---|---|
| disconnected | `--c-idle` / `--c-idle-tint` | `#8e8e93` | `#8e8e93` | shield (outline) |
| connecting | `--c-accent` / `--c-accent-tint` | `#007aff` | `#0a84ff` | shield (faint) + spinner |
| connected | `--c-good` / `--c-good-tint` | `#2fa84f` | `#32d158` | shield + check |
| reconnecting | `--c-warn` / `--c-warn-tint` | `#e08600` | `#ff9f0a` | spinner + retry arrow |
| failed | `--c-bad` / `--c-bad-tint` | `#e0352b` | `#ff453a` | shield + exclamation |

Tints are the same hue at low alpha (10–18%), used for the orb wash and the
error notice background. The per-state color + tint are resolved once on the
tray root via `data-state` and reused through `--st` / `--st-tint`:

```css
.tray[data-state="connected"] { --st: var(--c-good); --st-tint: var(--c-good-tint); }
/* …one line per state… */
```

`--c-good` / `--c-bad` are used only as **icon/ring/tint**, never as small body
text. For destructive *text* (the Disconnect label on a quiet fill) use the
AA-tuned `--c-danger-text` (`#c9271d` light / `#ff6961` dark, ≥4.5:1 on fill).

### Contrast policy (WCAG AA)

- Informational text ≥ 4.5:1; large text (≥18.66px, or ≥14px bold) and graphic
  indicators ≥ 3:1. Verified in both themes for every pair in `mockup.html`.
- The `--c-text-2` / `--c-text-3` split *is* the policy: anything a user must
  read uses `text-2`; `text-3` is reserved for decorative glyphs and chevrons.
- **Documented exception:** input placeholder text uses `--c-text-3` (below
  4.5:1). This is safe because every field carries a persistent visible
  `<label>` above it — the placeholder is supplementary example text, never the
  accessible name. Do not place a field's only label in its placeholder.

---

## Typography

One family, weight + scale for hierarchy. The system SF stack is a deliberate
brand choice (Apple-faithful), not a fallback.

```
--font:      -apple-system, "SF Pro Text", "SF Pro Display", "Segoe UI", system-ui, sans-serif
--font-mono: "SF Mono", ui-monospace, "Menlo", "Consolas", monospace   /* server addr, timer */
```

| Token | Size | Typical use |
|---|---|---|
| `--fs-caption2` | 11px | dense meta |
| `--fs-caption` | 12px | field labels, hints, group labels |
| `--fs-foot` | 13px | secondary lines, inputs, small buttons |
| `--fs-body` | 14px | base |
| `--fs-head` | 15px | sheet title, primary button label |
| `--fs-title` | 17px | (reserved) |
| `--fs-state` | 21px | the big connection-state label |
| `--fs-timer` | 26px | session timer |

Weights: `--fw-reg 400`, `--fw-med 500`, `--fw-semi 600`, `--fw-bold 700`.
Negative tracking on larger sizes (state label `-0.022em`, headings `-0.01em`).
The session timer uses `font-variant-numeric: tabular-nums` so digits don't
jitter as they tick.

---

## Spacing — 8-pt grid

Half-steps (2/4/6) exist for control internals; section rhythm stays on 8.

| Token | px |  | Token | px |
|---|---|---|---|---|
| `--s-1` | 2 | | `--s-6` | 16 |
| `--s-2` | 4 | | `--s-7` | 20 |
| `--s-3` | 6 | | `--s-8` | 24 |
| `--s-4` | 8 | | `--s-9` | 32 |
| `--s-5` | 12 | | `--s-10` | 40 |

Popover inset: `--s-7` (20px) horizontal. Title bar height 44px.

## Radii

| Token | px | Use |
|---|---|---|
| `--r-xs` | 6 | inner chevrons, tiny chips |
| `--r-sm` | 8 | inputs, credential rows, quiet buttons |
| `--r-md` | 10 | primary button, error notice |
| `--r-lg` | 12 | the popover window |
| `--r-pill` | 980 | (reserved for pills/toggles) |

## Shadows / elevation

| Token | Use |
|---|---|
| `--shadow-popover` | the floating popover: hairline ring + soft drop shadow (heavier in dark) |
| `--shadow-control` | subtle lift on the filled primary button |

Soft, low-spread shadows only. No glow, no colored shadows.

## Control sizes

| Token | px | Use |
|---|---|---|
| `--h-action` | 44 | hero toggle button (Connect/Disconnect/…) |
| `--h-control` | 36 | secondary buttons, inputs |
| `--orb` | 124 | the connection-state indicator diameter |

Hit targets are ≥36px tall (hero 44px). Icon buttons are 30×30 visually but the
title bar gives them clearance.

---

## Components

- **Tray popover** (`.tray`) — fixed 360px, `--r-lg` corners, `--shadow-popover`,
  `--c-window` background, `overflow: hidden`. Root carries `data-state` which
  drives all per-state color.
- **Title bar** (`.titlebar`) — 44px, the window **drag region** in Wails
  (`-webkit-app-region: drag`; interactive children opt out with `no-drag`).
  Holds the profile chip (left) and an icon button (right).
- **Profile chip** (`.profile`) — a button: an 8px state-colored dot (mirrors
  the tunnel state) + name + a disclosure chevron. Single profile today; the
  chevron is where a profile switcher attaches later.
- **State indicator** (`.orb`) — 124px circle, `--st-tint` wash, a 1.5px inner
  hairline ring in `--st`, a 50px state glyph in `--st`. Connecting /
  reconnecting overlay a thin rotating arc (`.orb__spin`) with the shield glyph
  dimmed to ~0.55 behind it.
- **State label** (`.state-label`) — `--fs-state`, semibold; `role="status"`
  `aria-live="polite"`. Optional sub-line (`.state-sub`) for the server address
  (mono) or a short hint.
- **Session timer** (`.timer`) — `--fs-timer`, tabular, shown only when
  connected. Kept out of the live region (would announce every second).
- **Primary action** (`.btn`) — full-width. Variants: `--primary`
  (accent-fill + white, the call to action), `--quiet` (fill + ink, for
  Disconnect/Cancel), `--quiet.--danger` (Disconnect's red label),
  `--sm` (36px, for sheets). Press: `scale(.985)`. Disabled: 0.5 opacity,
  non-interactive.
- **Error notice** (`.notice`) — `--c-bad-tint` background, `--c-bad` icon, a
  bold one-line summary + the literal error string in primary ink. No
  side-stripe.
- **Input** (`.input`) — 36px, `--c-fill`, transparent border that becomes
  `--c-accent` on focus (background lifts to `--c-surface`). Always preceded by
  a visible `.field__label`.
- **Credential row** (`.cred`) — a file-picker row (icon + role + hint +
  action). `.is-set` turns the icon green, adds a green border, and shows
  "verified" in neutral text — green is never the only signal.
- **Advanced disclosure** (`<details>`) — native, holds MTU + TUN name; rotates
  its chevron on open.

Every interactive control has default / hover / active / focus-visible /
disabled. The same control vocabulary is used across both screens.

## Icons

Inline SVG, stroke-based, 1.5–1.7px stroke, round caps/joins, `currentColor`
(so they inherit state color). The **shield** is the throughline metaphor
(VPN = protection); its inner mark and color change per state (outline / check /
exclamation / spinner). Settings = gear, Back = chevron-left, file = document.
~18–20px in chrome, 50px for the orb glyph. Keep one consistent stroke family;
don't mix filled and outline styles. Decorative SVGs should be
`aria-hidden="true" focusable="false"` in the shipped build.

## Motion

Quiet by default; motion only conveys state.

- Tokens: `--dur-1 120ms` (hover/press), `--dur-2 200ms` (controls),
  `--dur-3 320ms` (state cross-fade). Easing `--ease: cubic-bezier(.32,.72,0,1)`
  (ease-out; no bounce, no elastic).
- The only looping animation is the indeterminate progress arc (`.orb__spin`,
  ~1.9s in the orb, ~1.6s in the Cancel button), shown solely while connecting /
  reconnecting. It rotates at constant (linear) speed; the long period is what
  keeps the sweep smooth and calm. Easing is intentionally avoided — easing a
  full-circle loop stutters once per turn, whereas constant speed reads fluid.
- **Reduced motion** (`prefers-reduced-motion: reduce`): the arc stops
  (`.orb__spin` stays as a static accent at 0.6 opacity) and transitions
  collapse to ~1ms. State remains fully legible without any animation.

---

## Implementation notes (Wails)

- The front-end binds to the helper's IPC contract (`internal/ipc`,
  `internal/helper`): `data-state` ∈ {disconnected, connecting, connected,
  reconnecting, failed}; the server line shows `StatusResponse.Server`; the
  timer counts from `SinceUnix`; the error notice shows `LastError`; the import
  sheet collects `ConnectRequest` (server, optional server_name, CA/cert/key
  PEM, optional MTU + tun_name).
- `-webkit-app-region: drag` on the title bar is Wails-specific window dragging;
  keep interactive children `no-drag`.
- Theme: follow the OS via `prefers-color-scheme`; `data-theme` on the root
  forces a theme (the mockup uses `?theme=` only for screenshots).
- A native menu-bar vibrancy/material can sit *behind* `--c-window`; the opaque
  token is the reliable fallback and what these contrast numbers assume.
- The mockup is also the **a11y reference**, not just a visual one: it ships the
  full wiring to copy into the real component tree — `<label for>`↔`<input id>`
  association, `aria-hidden="true" focusable="false"` on every decorative SVG,
  `type="button"` on all buttons, the sheet title as an `<h1>`, the profile chip
  as `aria-haspopup="menu"`/`aria-expanded`, a focus-visible ring on every
  control, and `role="status"`/`aria-live="polite"` on the state label (the
  per-second timer kept out of it). Keep these when porting to Wails.
