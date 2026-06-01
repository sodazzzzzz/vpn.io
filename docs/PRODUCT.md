# Product

## Register

product

## Users

The person who runs the VPN. vpn.io is self-hosted and personal: the same
individual owns the server, issues their own client credentials, and runs the
desktop client on their own machines (macOS, Windows, Linux). They are
technically capable but do not want to drive a live tunnel from a terminal for
everyday use. On any given day the job is small and frequent: open the tray,
see at a glance whether traffic is protected, and toggle the connection.

## Product Purpose

A desktop tray client for a self-hosted VPN. A privileged background helper owns
the tunnel; this front-end runs as the logged-in user and drives it
(connect / disconnect / status) over local IPC. The UI's whole job is to answer
two questions instantly — *am I protected right now?* and *how do I change
that?* — and to get out of the way. Success is: credentials imported once, and
from then on connecting is a single, obvious action with honest, legible state.

## Brand Personality

Calm, trustworthy, precise. Three words: **quiet, instrument, honest.** It
should feel like a well-made system utility, not a consumer "privacy" product
selling reassurance. State is reported plainly (including failure), never
dramatized. The voice is plain and specific: button labels are verb + object
("Connect", "Disconnect", "Add profile"), errors say what actually happened
("tls: handshake timeout after 10s") rather than "Oops, something went wrong".

## Anti-references

- **iOS 26 / "Liquid Glass."** No translucent glass slabs, no specular
  highlights, no heavy blur as decoration. The reference is Apple *before* that
  era: SF typography, neutral surfaces, soft shadows, restraint.
- **Loud commercial VPN apps** (animated globes, world maps, neon gradients,
  "you are protected!" hero theater, gamified speed dials).
- **AI-slop tells**: purple/indigo gradients on white, gradient text,
  glassmorphism by default, identical icon-heading-text card grids,
  decorative motion.
- **Dashboard sprawl.** This is a single-purpose utility, not an analytics
  console; resist adding charts, metrics walls, or settings the task doesn't
  need.

## Design Principles

1. **One state, unmistakable.** At any moment the connection state is the
   loudest thing on screen and readable in under a second — by color, shape, and
   word together, never color alone.
2. **One primary action.** Exactly one hero control (Connect / Disconnect /
   Cancel / Try again, depending on state). Everything else is quieter.
3. **Honest status.** Show real state including connecting, reconnecting, and
   failure with the actual reason. Never imply protection that isn't there.
4. **Quiet by default, motion only as signal.** Animation appears only to
   convey a transitional state (a spinner while connecting); nothing moves for
   decoration.
5. **Earned familiarity.** Use platform-standard affordances (system type,
   standard controls, a menu-bar popover). The tool should disappear into the
   task; surprise is a cost, not a feature.

## Accessibility & Inclusion

- **Target: WCAG 2.1 AA.** Informational text meets ≥4.5:1 contrast; large
  text and graphical indicators meet ≥3:1. Verified for both light and dark
  themes (see DESIGN.md → Color).
- **Never color-only.** Every state pairs its color with a distinct glyph and a
  text label, so the five tunnel states are distinguishable with color-vision
  deficiency or in grayscale.
- **Reduced motion.** `prefers-reduced-motion` removes the spinners; state stays
  fully legible without animation.
- **Keyboard + screen reader.** Every control is focusable with a visible focus
  ring; icon-only buttons carry text labels; the state label is a polite live
  region so a screen reader announces transitions (the per-second session timer
  is deliberately kept out of that live region).
- **Light and dark** are first-class and follow the OS preference.
