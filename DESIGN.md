---
name: D2K — Ведомость
description: Local router control panel set as a warm paper-and-ink ledger with one signal colour for live search.
colors:
  signal: "#e8470f"
  signal-ink: "#b8360a"
  signal-wash: "#f8d9c9"
  ok: "#1d6b47"
  ok-wash: "#d5e6d6"
  ok-bright: "#8fdcb2"
  warn: "#8d5a06"
  warn-wash: "#f1e1bd"
  bad: "#b02a17"
  bad-wash: "#f3d3cb"
  focus: "#1f48d6"
  mast-ground: "#24251f"
  mast-ink: "#f6f3eb"
  mast-muted: "#c1bdaf"
  mast-rule: "#656457"
  mast-danger: "#ff967b"
  mast-focus: "#b6c6ff"
  paper: "#f6f3eb"
  paper-2: "#eae5d8"
  paper-3: "#ddd7c8"
  ink: "#17160f"
  ink-2: "#57534a"
  ink-3: "#6f6a5f"
  rule: "#cdc6b5"
  rule-strong: "#17160f"
  kraft: "#d6b98a"
  kraft-2: "#c3a170"
  kraft-3: "#a9844f"
  kraft-ink: "#3b2a12"
  hole: "#17160f"
  manila: "#f1e3bf"
  manila-ring: "#d8c08a"
  tree-line: "#a9844f"
typography:
  display:
    fontFamily: "Onest, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "clamp(44px, 6.4vw, 88px)"
    fontWeight: 780
    lineHeight: 0.98
    letterSpacing: "-.035em"
  headline:
    fontFamily: "Onest, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "clamp(34px, 3vw, 42px)"
    fontWeight: 750
    lineHeight: 1.05
    letterSpacing: "-.03em"
  title:
    fontFamily: "Onest, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "clamp(24px, 2.6vw, 34px)"
    fontWeight: 700
    lineHeight: 1.12
    letterSpacing: "-.02em"
  lede:
    fontFamily: "Onest, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "19px"
    fontWeight: 400
    lineHeight: 1.5
  body:
    fontFamily: "Onest, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "\"ss01\", \"cv11\", \"tnum\""
  label:
    fontFamily: "Onest, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "12.5px"
    fontWeight: 600
    lineHeight: 1.3
  data:
    fontFamily: "JetBrains Mono, ui-monospace, SF Mono, Menlo, monospace"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: 1.6
rounded:
  focus: "4px"
  cell: "5px"
  plan: "10px"
  card: "14px"
  band: "18px"
  pill: "999px"
spacing:
  gutter: "clamp(16px, 3vw, 40px)"
  xs: "6px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  sheet: "48px"
components:
  button:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "0 16px"
    height: "44px"
  button-hover:
    backgroundColor: "{colors.paper-2}"
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.paper}"
    rounded: "{rounded.pill}"
    height: "44px"
  button-danger:
    backgroundColor: "transparent"
    textColor: "{colors.bad}"
    rounded: "{rounded.pill}"
    height: "44px"
  button-danger-hover:
    backgroundColor: "{colors.bad-wash}"
  button-confirm:
    backgroundColor: "{colors.bad}"
    textColor: "#ffffff"
    rounded: "{rounded.pill}"
    height: "44px"
  tag-live:
    backgroundColor: "{colors.signal-wash}"
    textColor: "{colors.signal-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "2px 9px"
  tag-ok:
    backgroundColor: "{colors.ok-wash}"
    textColor: "{colors.ok}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "2px 9px"
  filter-field:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    rounded: "{rounded.pill}"
    padding: "0 16px"
    height: "48px"
  family-card:
    backgroundColor: "{colors.paper-2}"
    textColor: "{colors.ink}"
    rounded: "{rounded.card}"
    padding: "22px 22px 20px"
  family-card-applied:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.paper}"
    rounded: "{rounded.card}"
    padding: "22px 22px 20px"
  slot-cell-on:
    backgroundColor: "{colors.signal}"
    rounded: "{rounded.cell}"
    size: "22px"
  tunnel-band:
    backgroundColor: "{colors.paper-2}"
    textColor: "{colors.ink}"
    rounded: "{rounded.band}"
    padding: "28px 32px"
---

# Design System: D2K — Ведомость

## Overview

**Creative North Star: "Ведомость"**

The panel is a printed ledger: warm paper, near-black ink, hairline rules, and Swiss editorial type in Onest. It reads top to bottom as one sheet: the masthead states what the engine is doing, «Сейчас» says it again as a big headline, then the catalogue (families, boxes), the Telegram tunnel and diagnostics follow as ruled sections. Density is that of a well-set report: generous section spacing, tight tabular rows inside.

Colour is information, not decoration. One orange signal belongs to live search activity; green means confirmed or applied; red means stop or failure. Everything else is paper and ink in two themes (light and dark), switched by `prefers-color-scheme` on `:root` tokens. Fonts are self-hosted (Onest, JetBrains Mono, OFL) and the panel works fully offline on the router.

**Key Characteristics:**
- Warm paper ground, ink text, 1px rules as the main structure.
- Onest for all language; JetBrains Mono only for machine data.
- One signal colour, reserved for the live search.
- Flat: depth comes from tone (paper / paper-2 / ink), never from shadows.
- Motion only where something actually progresses.

## Colors

Paper and ink with a single hot accent and two semantic states, each state paired with a wash for tags and notices.

### Primary
- **Signal Orange** (signal): live search activity only: the live lamp and its pulse, occupied measurement slots, the phase track's fill and current step, the highlighted word of the headline while a search runs, the active nav dot, the D2K mark block, text selection, the filter caret. `signal-ink` is its text-safe form on paper; `signal-wash` is the ring around the current phase step and the background of live tags («перепроверяется»).

### Secondary
- **Confirmed Green** (ok, ok-wash, ok-bright): confirmed or applied only: ok lamp, finished searches (track fill and step turn green), "applied" tags, passed diagnostic stages. `ok-bright` is the applied tag on the dark applied family card.
- **Stop Red** (bad, bad-wash): engine stopped, lost link, failed stages, the danger and confirm-stop buttons.
- **Caution Amber** (warn, warn-wash): stale snapshot, exceptions inside a family, warning facts and notices.
- **Focus Blue** (focus): keyboard focus outline only; deliberately outside the semantic palette.

### Neutral
- **Ledger Paper** (paper): page ground and the filter field. **Paper-2** is the tonal surface for family cards, the tunnel band, hover fills and info notices. **Paper-3** is the deepest paper step.
- **Ink** (ink): text, primary buttons, the applied family card. **Ink-2** for secondary text and ledes, **Ink-3** for tertiary metadata, timestamps and idle lamps.
- **Rule** (rule) for hairlines between rows; **Rule-strong** (equal to ink) under the masthead, between sections and under table headers.

Dark theme swaps every token in place (paper #171914, ink #eeeae0, signal #ff6a33, ok #5cc493, bad #f07a63, warn #e2a948, focus #8aa4ff; full set in the sidecar). Components never hard-code a theme.

### Named Rules
**The One Signal Rule.** Orange means "a search is running right now". If nothing is being searched, no orange is on screen except the mark.

**The Earned Green Rule.** Green appears only for a measured confirmation or an applied plan. Installed is not done; never green a state the engine has not confirmed.

## Typography

**Display Font:** Onest (with system-ui, -apple-system, Segoe UI, sans-serif)
**Body Font:** Onest
**Label/Mono Font:** JetBrains Mono (with ui-monospace, SF Mono, Menlo) for data only

**Character:** A Swiss editorial sans set heavy and tight for headlines, plain and roomy for prose; a monospace that appears only where the text is something a machine would read back.

### Hierarchy
- **Display** (statement): the «Сейчас» headline, max 14ch, balanced wrap; the state word inside it takes the tone colour.
- **Headline**: section titles, paired with a one-sentence explanation in ink-2 in a two-column sheet head.
- **Title**: search target names; family names (26px/720), box names (22px/720) and the tunnel state word (40px/760) sit on the same heavy, negatively tracked voice.
- **Lede** (19px): the explanatory paragraph under the statement, max 62ch.
- **Body** (16px/1.5): prose and rows, with `ss01`, `cv11` and tabular numerals everywhere.
- **Label** (12.5–13px, 600–650): tags, table headers, phase-track steps, box sub-headings. Sentence case, no uppercase tracking.
- **Data** (mono, .86em inline; 12.5px/1.6 in plan bodies): plan text, IPs, paths, plan ids, host name, commit hash.

### Named Rules
**The Mono Is Data Rule.** JetBrains Mono marks a value the user might copy or compare (plan, address, path, id). Labels, numbers in prose and headings stay in Onest.

## Layout

A centred frame (max 1440px, gutter clamp(16px, 3vw, 40px)) with a 220px sticky section index on the left and a single reading column. Sections ("sheets") stack with 48px top padding and a strong rule between them. Sheet heads are a two-column grid: title left, explanation right (max 60ch).

Responsive: under 1360px a box article collapses to one column with a two-column aside; under 1080px the index becomes a sticky horizontal strip of pill links below the masthead; under 820px the masthead wraps to two rows, sheet heads and diagnostics go single-column and the bindings table becomes stacked rows; under 640px masthead buttons become 44px icon-only circles (except confirm/cancel), the phase track shows only the current step's label and the statement drops to 42px.

## Elevation & Depth

Flat, with one material exception: crates (boxes) are physical kraft objects and carry a soft offset shadow and a paper label sticker. Elsewhere depth is tonal: paper, paper-2 surfaces, and the inverted ink card for applied families. The masthead is opaque olive ink in both themes. Only the narrow-screen index strip uses a translucent paper surface with background blur. A `--shadow` token is declared but not used by any component; do not reach for it.

### Named Rules
**The Ruled Ledger Rule.** Separate with 1px rules and tone, not shadows or boxes. Most content is rows on the page, not cards.

## Shapes

Two families of form. Controls are pills (999px): buttons, tags, the filter field, narrow-screen index links. Containers are softly rounded: plan disclosures 10px, family cards and empty states 14px, the tunnel band 18px; slot cells 5px. Rows, tables and sections have no corners at all, only rules. Lamps and track dots are circles. Icons are inline SVG strokes (2px, round caps).

## Components

### Buttons
- **Shape:** pill, 44px tall, 600 14px label, optional 16px stroke icon.
- **Default:** transparent with an ink outline; hover fills paper-2; active nudges down 1px.
- **Primary:** ink fill, paper text; hover mixes a little signal into the ink.
- **Ghost:** rule-coloured outline (secondary actions, cancel).
- **Danger → Confirm:** «Остановить» is a red outline. Pressing it swaps the controls in place for a solid red «Остановить движок?» and a ghost «Отмена». No modal; the second press stops.
- **Busy:** the icon spins; disabled turns ink-3 on transparent.

### Masthead
Sticky, opaque olive ink, ruled below. Mark + 800-weight «D2K» wordmark + mono host name (the theme name «Ведомость» is internal and never shown in the interface); then the engine lamp with a one-line state; then the controls. The lamp is idle (ink-3), ok, live (signal with an expanding ring pulse), warn or bad.

### Statement and slots («Сейчас»)
Display headline whose state word takes the tone colour (signal while searching, green when idle and well, red when stopped or unlinked), the lede, then a ruled strip of measurement slot cells: empty outlined squares, filled signal when occupied, with counts beside them.

### Search row (signature)
Ruled row: large target title, meta line (protocol, mono address, tags), a right-aligned clock, the current phase sentence with a signal dot, and the phase track. The track mirrors the original's phase vocabulary (Очередь, Форма, Распознаём, Свойства, Планы, Проверка, Подтверждено; a separate voice track: Замер голоса, Приём стоит, Ждём ответа). Past steps are filled ink-3, the current step is signal with a wash ring and bold label, and the fill bar scales with `transform` (0.7s ease-out). A finished search turns fill and dot green. Rows arrive with an 8px rise and fade.

### Family cards
Auto-fill grid (min 300px). Paper-2 card for known families; an applied family inverts to ink with paper text and the bright-green applied tag. Exceptions inside a family list in amber; the plan id sits at the foot in mono.

### Crates (boxes)
Each catalogue box is a collapsed kraft crate (`details`): an isometric box icon (taped lid when closed, flaps up when open), the box number, its first measured signal, protocol tags and «обновлена …», and a paper shipping label with the mono id, the target count and plan count. Kraft tokens (`kraft`, `kraft-2`, `kraft-3`, `kraft-ink`) belong to crates only. Crates start collapsed; a catalogue filter opens the crates that match. Inside, a dashed seam separates the lid from the box article below.

### Family tags
Each domain family is a manila luggage tag hanging by a string from its row's rail (each row has its own rail segment; tags tilt slightly and straighten on hover). The tag has chamfered top corners, a reinforced eyelet, the centred `*.suffix`, protocol and IP tags, an ink stamp («Применяется» in green, or a dashed grey «Не подтверждено»), a tree of evidence domains with exceptions in amber, and a dashed foot with the plan id and the boxes that carry that plan as kraft buttons; a button scrolls to that crate, opens it and flashes its outline. Tags swing into place the first time the section is on screen. Tokens `manila`, `manila-ring`, `tree-line` belong to tags only.

### Box article (inside a crate)
Two columns: aside (name, mono id, dates, measured signals as a ruled list, plans as `details` disclosures with a mono `pre` body and a rotating chevron) and a bindings table (fixed layout, strong header rule, disabled bindings struck through, «перепроверяется» as a live tag). Names already covered by a family are folded into a closing «… покрыты семействами» disclosure, not listed as rows.

### Telegram tunnel band
A separate paper-2 band (18px radius) stating the tunnel as its own service: lamp, a 40px state word, its own actions, a line drawing of the tunnel, and a note. Its state never mixes with the engine's. The drawing is an ink-stroke tube with ribs between «Этот роутер» (router with antennas and status LEDs) and «Ретранслятор» (relay disc). One drawing persists across states; every state change animates from what is on screen. Connected: live traffic — small requests out on the upper lane, bursts of 1–4 larger replies back on the lower one with uneven gaps; ribs and mouths glow green near passing packets; the router's send/receive LEDs flicker. Connecting: amber waves from the antennas, an amber probe enters the tube lighting the ribs it passes and fades unanswered; retries wait longer and reach further; a dashed amber ring turns around the relay. Connecting → connected: the probe reaches the relay, it pulses and answers, the entrance pulses, ribs light green left to right, then the first packets leave. Stopped: packets in flight drain, LEDs go out, a red gate drops with a bounce and the tube dims; leaving stopped lifts the gate first. Not configured: a dotted sketch with a faint, breathing relay outline. Reduced motion: one clear still frame per state.

### Updates
One ruled ledger row, not a statement: lamp, a 20px state sentence with the installed version and the last check in ink-3 below it, and the actions right-aligned (primary «Установить сейчас» only when a compatible release is shown, ghost «Проверить»). Under it, thin ruled rows appear only when they carry something: «Что изменилось в …» as a chevron disclosure, a 4px ink progress bar while downloading, the restart warning, and the night-install checkbox with its window on one line. The lamp turns green only after a fresh signed check confirmed the installed release is current; amber and red follow the problem tone. Without an updater (flat installation, or a panel without the update API) the section is one calm idle row, «Автообновление не подключено», with no actions and no alarm badge in the index; only a failed request to a present updater reads as a failure.

### Diagnostics
Two columns: stages (stroke check/cross icons in ok/bad/ink-3 with a sentence each) and facts (a ruled `dl`, mono for values, warn/bad tone on problem values). A muted colophon closes the page.

### Tags, filter, notices, empty states
Type sizes are set in rem (16px root), so the browser's default font size scales the whole panel. Tags are 24px pills with a wash background per tone (mute = outline only). The filter is a 48px pill search field with a stroke magnifier and signal caret. Connection notices are full-width washed bands under the masthead. Empty states are a dashed rule box with 14px corners. A stale snapshot dims `main` to 55% and desaturates it.

### Motion
Motion is driven by GSAP 3 (`/assets/gsap.js`, served by the panel itself: core, Flip, MotionPath, DrawSVG). It always follows a real state change:
- first render: statement, lede, slot cells and the first rows rise in once;
- headline: a changed count rolls; a changed sentence lifts out and drops in;
- slot cells pop in with a back-out ease when measurements start; freed cells fade from signal;
- search rows: new rows rise in; a finished or vanished row slides out and the rest close the gap with Flip (only when the list actually changed);
- phase track: a signal puck travels to the new step (0.9s), dots light as it passes, the puck pulses on arrival; the phase sentence swaps;
- crates: tape tears (DrawSVG), lid lifts, flaps swing up with a back-out ease, the label wiggles, the body unfolds and its rows stagger in; closing runs it in reverse and clears all inline styles;
- tunnel: per-state scenes above; the endless loop runs at 30 fps and only while the band is on screen and the tab is visible.

`prefers-reduced-motion: reduce` turns every GSAP scene off (states apply at once, crates open natively) and CSS animations off. Without GSAP the panel still works, with short CSS transitions as a fallback.

## Do's and Don'ts

### Do:
- **Do** keep orange for live search activity: lamp, slots, phase track, live tags.
- **Do** use green only for confirmed or applied states, red for stop and failure, amber for stale and exceptions.
- **Do** set machine data (plans, IPs, paths, ids) in JetBrains Mono and everything else in Onest.
- **Do** separate content with 1px rules and paper tones; reserve the inverted ink card for applied families.
- **Do** define every colour as a `:root` token with a dark-theme counterpart.
- **Do** keep two-step stop inline: danger outline, then solid red confirm with a ghost cancel.
- **Do** honour `prefers-reduced-motion` for every new animation, and pause any endless loop off screen.

### Don't:
- **Don't** use the signal colour for faults, warnings, connecting services or decoration.
- **Don't** add shadows, modals or a second accent colour.
- **Don't** load fonts or assets from the network; the panel must work offline.
- **Don't** put labels, headings or prose in the monospace face.
- **Don't** add uppercase letter-spaced kickers above section titles; the sheet head is title plus explanation.

## Demonstration refinement — 2026-10-02

The structure and all service actions are preserved. The desktop section index uses an ink-filled active row; mobile retains horizontal pills. The measurement strip starts with a 2px ink rule. Family plan identifiers have their own hairline separator; exceptions use amber ink on an amber wash. Section headings grow from 34px to 42px. Both themes were inspected with real router data; five widths and service commands were checked against the isolated C fixture.
