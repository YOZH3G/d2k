---
name: D2K — Слайдоскоп
description: A local control panel with tactile slides on a goldenrod ground.
colors:
  paper: "#eab71f"
  ink: "#152321"
  glass: "#192b29"
  cream: "#f3ebce"
  line: "#716325"
  focus: "#ae321c"
  connected: "#36b782"
  confirmed: "#a1d69c"
  evidence: "#315d46"
  divider: "#c4be9d"
  rail-base: "#0a110f"
  neighboring-phase: "#a0a3a3"
  right-confirmed: "#60b590"
typography:
  display:
    fontFamily: "Slide, sans-serif"
    fontSize: "clamp(42px, calc(1080px / var(--name-length, 9)), 126px)"
    fontWeight: 700
    lineHeight: 1.03
    letterSpacing: "-.03em"
  title:
    fontFamily: "Slide, sans-serif"
    fontSize: "28px"
    lineHeight: 1.15
  body:
    fontFamily: "system-ui, -apple-system, sans-serif"
    fontSize: "16px"
    lineHeight: 1.5
  detail:
    fontFamily: "system-ui, -apple-system, sans-serif"
    fontSize: "14px"
  control-desktop:
    fontFamily: "Slide, sans-serif"
    fontSize: "21px"
    fontWeight: 500
    lineHeight: 1.4
  neighboring-phase-desktop:
    fontFamily: "Slide, sans-serif"
    fontSize: "calc(var(--unit) * 1.8)"
    fontWeight: 300
    letterSpacing: ".025em"
  left-target-desktop:
    fontFamily: "Slide, sans-serif"
    fontSize: "calc(var(--unit) * 4.4)"
    fontWeight: 500
    letterSpacing: "0"
rounded:
  square: "0"
  control-desktop: "4px"
spacing:
  tight: "8px"
  compact: "12px"
  standard: "16px"
  spacious: "24px"
components:
  control-desktop:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    typography: "{typography.control-desktop}"
    rounded: "{rounded.control-desktop}"
    padding: "10px 14px"
  control-hover:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.cream}"
  result-card:
    backgroundColor: "{colors.cream}"
    textColor: "{colors.ink}"
    rounded: "{rounded.square}"
    padding: "{spacing.spacious}"
  filter:
    backgroundColor: "{colors.cream}"
    textColor: "{colors.ink}"
    rounded: "{rounded.square}"
    padding: "12px 16px"
    width: "min(420px, 100%)"
  stage-current:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.cream}"
  navigation-active:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
---

# Design System: D2K — Слайдоскоп

## Overview

**Creative North Star: "Слайдоскоп"**

A goldenrod work surface holds overlapping dark glass slides and a pale selected slide. Condensed local Oswald lettering follows their oblique geometry; the shared gold holder gives the search objects a physical relationship. Saved families occupy a second rack. The feel is tactile and energetic while status language stays calm and exact.

This records the current implementation in `internal/web/assets/index.html`, `panel.css`, and `panel.js`, not a completion certificate. The user-approved visual authority is `.impeccable/mocks/decision/final-slides.png`. The current review captures are `.impeccable/review/integrated-desktop.png`, `integrated-mobile.png`, and `integrated-tablet.png`. The authoritative `.impeccable/build/state.json` keeps the hero fidelity gate OPEN/FAILED at 81% (score 0.8146), unforced. The user-authorized finite correction pass is implemented: left domain/phase rotation and offsets, first-family width, and tool vertical alignment now reflect the requested adjustments. The final scoped ship verdict resolves all four residual fixes with no attributable regression; prior named geometric hard vetoes cleared. No whole-interface pass or completion is claimed.

`PRODUCT.md` owns product truth. Its older “style not yet approved” sentence predates the accepted Slidoscope direction and is recorded as context drift, not visual authority. The panel is deployed at `http://192.168.1.1:8090` and consumes the real local C API. Field captures `.impeccable/review/router-desktop.png`, `router-common.png`, `router-tablet.png`, and `router-mobile.png` record that installed panel using read-only GET requests. Live searches changed naturally during capture: desktop shows standby with zero searches, while mobile shows one search. The integrated preview captures use fixture data and remain composition evidence; neither set proves general internet availability. No whole-surface finish pass is claimed.

**Key Characteristics:**

- Goldenrod ground, dark glass planes, and a pale selected slide.
- Condensed offline typography and oblique physical geometry.
- Shared holders for active searches and saved families.
- Event-driven motion and persistent, separate service controls.

## Colors

The paper accent fills the environment; ink and cream supply readable polarity on the layered surfaces.

### Primary

- **Goldenrod paper** (`paper`): page ground, active navigation, and the fixed controls surface. A repeating local ground texture adds material variation.
- **Dark glass** (`glass`): the material reference for dark search and family planes. Raster assets contain tonal variation rather than a single flat fill.

### Secondary

- **Connected green** (`connected`): the local connection indicator.
- **Confirmed green** (`confirmed`): confirmation text on desktop dark search planes.
- **Evidence green** (`evidence`): filled evidence-meter segments.
- **Rust focus** (`focus`): keyboard focus outline.
- **Right confirmation green** (`right-confirmed`): the right desktop slide's explicit confirmation label.

### Neutral

- **Ink** (`ink`): primary text, navigation surface, selected stage, and button hover.
- **Cream** (`cream`): pale selected material, result cards, inputs, and text on dark surfaces.
- **Olive line** (`line`): section rules.
- **Muted divider** (`divider`): result-row separators and empty evidence segments.
- **Rail black** (`rail-base`): neutral dark foundation for the textured navigation rail.
- **Neighboring phase gray** (`neighboring-phase`): the left desktop slide's phase label.

**The Evidence Rule.** Color accompanies explicit state text; green is never a standalone claim that the internet works.

## Typography

**Display Font:** local Oswald, registered as `Slide`, with sans-serif fallback. The variable font is served at `/assets/oswald.ttf`, with weights 200–700 and `font-display: swap`.

**Body Font:** system UI with the platform fallback stack. Technical details use readable body text; headings, navigation, slide labels, family labels, and controls use Slide.

The selected target is the dominant text object. Its desktop size responds to target length; the implementation also compresses it horizontally. These composition adjustments describe this hero only and are not a license to distort text in all future components.

### Hierarchy

- **Display:** selected desktop target uses the frontmatter display role. Compact targets use `clamp(24px, calc(420px / var(--name-length, 9)), 44px)` at line-height 1.2, including mobile; names wrap rather than clipping.
- **Title:** result headings use 28px. Page and rack headings have separate responsive condensed treatments.
- **Body:** the body role is the general reading baseline.
- **Detail:** the detail role supports dates, diagnostics, filters, and result metadata.
- **Control:** desktop service buttons use the control-desktop role; mobile buttons currently use 14px with a 44px minimum target height.

**The Offline Type Rule.** Keep the display font bundled locally; no remote font service is required to read or operate the panel.

## Layout

The frame is centered with a maximum width of 1920px and a minimum body width of 320px. Desktop outer padding is 12px vertically and 16px horizontally. The dark navigation rail sticks near the top; service controls stay fixed near the bottom.

Above 1100px, the hero uses a viewport-scaled unit capped at 19.2px. Three overlapping, independently transparent slide planes share one holder. The selected plane sits centrally, dark neighboring planes sit behind, and a narrow text column flanks each side. The family rack follows beneath. Status, metrics, full results, and diagnostics continue in document flow below the composition.

At 1100px and below, only the selected search plane is visible and previous/next buttons expose the others. Both tablet (701–1100px) and mobile (700px and below) use the vertical sequence: heading, current search, saved families, status, metrics, results, and diagnostics. The pager sits beside the search heading with two 44px square controls. The family rack scrolls horizontally; tablet family items occupy 45% of its width. Mobile navigation uses three text destinations and two icon destinations. Fixed controls stack Telegram and D2K and reserve bottom page space; the narrowest layout (360px and below) puts restart and restore on separate full-width rows.

The 8/12/16/24px spacing vocabulary is reused across controls, metadata, results, and disclosures. Exact hero percentages, transforms, and fixed heights are implementation-specific and remain subject to the open fidelity review; do not promote them to universal layout rules.

## Elevation & Depth

Depth comes primarily from authored material images, overlap, and the shared holder. The production hero uses `slide-left.webp`, `slide-center.webp`, `slide-right.webp`, and `slide-holder.webp` as independently composed alpha assets. `ground.webp` and `family-rack.webp` establish the surrounding material. The rail keeps visible local ground stock in a grayscale pseudo-element, blended with soft-light over rail black; its neutral treatment avoids carrying the page's goldenrod hue into the dark rail. Their textures and lighting cannot be reproduced faithfully by filling a generic rounded card.

Open desktop slide details use a soft shadow (`0 12px 28px #14201c50`) above the plane. The non-desktop controls inherit a subtle upward shadow (`0 -6px 20px #342b2615`); desktop controls explicitly remove it.

**The Shared Holder Rule.** Preserve the physical relationship among slides and their common support rather than assigning each slide an unrelated floating panel.

## Shapes

Oblique planes and the diagonal brand mark are the signature geometry. Rectangular fields and result panels remain square. Desktop service buttons have modest rounded corners, outlined with a two-pixel ink border. Circular dots identify connection state. Native disclosure summaries use inline SVG document and arrow icons; system text glyphs are not the icon vocabulary.

The decorative planes sit in CSS pseudo-elements so labels and controls remain HTML. Their raster silhouettes, not a generic CSS border radius, define the hero shape.

The bundled SVG favicon reduces the diagonal three-slash brand to a dark tile with a small corner radius, goldenrod and cream strokes, and a muted slate third stroke. The HTML declares its local `/assets/favicon.svg` path; keep the mark readable at browser-tab size.

## Components

### Navigation

A dark sticky rail contains the brand, local connection status, three section links, and search/settings icon links. Active and hovered text links invert onto goldenrod. Desktop active and passive link frames are oblique, separated by subtle rules; counter-skewed inner spans keep the lettering upright. Mobile icon destinations keep accessible names when their text is hidden.

### Service controls

Outlined transparent buttons become ink with cream text on hover. Disabled controls reduce opacity and retain native disabled behavior. D2K actions and Telegram remain visibly separate within the fixed control area. Button targets have a 44px minimum height. Keyboard focus uses a three-pixel rust outline with a five-pixel offset.

The Telegram title includes the locally rendered paper-plane SVG alongside its explicit service name; the icon identifies the independent tunnel rather than changing its status meaning. Diagnostic presence, absence, and connection-error marks use inline check, minus, and cross SVG paths with the shared stroke vocabulary, paired with explicit text.

### Search slides

The selected slide is pale with ink text; neighboring slides are dark with cream text. Selection is expressed by native buttons with `aria-pressed`. Numbered selection tabs pair the index with an explicit label; the selected number is goldenrod on ink. The four stage cells are an ordered list; `aria-current="step"` identifies the active stage. Confirmed searches pair state text with an inline circular check icon; the selected plane uses evidence green while dark desktop planes use confirmed green. Off-rack slides are hidden and inert. Previous/next buttons provide access to the collection, including compact layouts.

Motion follows real changes: arrival and advancement use 440ms; confirmation uses 620ms; explicit selection uses 520ms. A confirmation can transfer an inert, aria-hidden visual clone into the matching visible family in 660ms. The first snapshot produces no synthetic arrival events. The CSS light sweep lasts 620ms. Hidden documents do not perform these update animations and pause polling.

Desktop neighboring phase labels use the neighboring-phase-desktop role; the selected phase retains stronger emphasis. The left target uses zero letter-spacing so punctuation does not acquire artificial gaps. Its target, protocol context, and phase have independent anchors; the right confirmation label is fitted separately. Family titles also use zero letter-spacing, with title and protocol lines moved upward independently. Brand and tool alignment, framed navigation width, and these text transforms are hero-specific corrections recorded in the sidecar, not universal text rules.

Reduced motion removes CSS sweeps, smooth scrolling, and selection translation; event updates use a short 120ms opacity change instead of travel. The easing and duration inventory lives in the sidecar.

### Saved families and disclosures

Families sit together in their own dark rack. Outlined S1/S2/S3 index tabs identify the visible positions and are decorative (`aria-hidden`), not status claims. Protocol and address-family context stays visible while native details/summary reveals evidence; inactive or unconfirmed application states remain explicit. Desktop expanded disclosures switch to cream and ink, constrain their height, and scroll. Decoration does not intercept input.

### Results and filter

Cream result panels contain bordered rows, target identities, evidence meters, and copy actions. The filter has a visible label, an explicit accessible name, a square cream field, and an ink border. Evidence meters include a textual accessible label; protocol and address-family distinctions remain text.

### Loading and unavailable states

The main region carries polite live announcements and an initial busy state. Loading and connection failures use cream surfaces and direct status wording. A failed refresh disables stale service buttons; missing data is not rendered as measured zero. This documents implemented affordances, not a completed accessibility audit.

### Desktop standby

When the linked engine has no active searches, the desktop rack keeps its existing pale central plane and shared holder. Calm status text sits inside that plane, clear of the left heading and right caption; no synthetic search, stage cells, or activity animation is introduced. The same decorative support also frames unavailable search data, whose wording remains explicit. At compact widths the empty message stays in normal document flow. This pattern describes an idle search collection, not measured success for every site.

## Do's and Don'ts

### Do:

- Do preserve goldenrod ground, pale selected slide, dark neighbors, and their shared holder.
- Do use locally bundled Oswald and inline SVG icons.
- Do retain explicit state text, native controls, visible focus, and reduced-motion behavior.
- Do keep Telegram control and state distinct from D2K.
- Do review the actual responsive composition against the approved reference before declaring fidelity passed.

### Don't:

- Don't replace authored slide materials with generic rounded cards.
- Don't describe fixture screenshots as live router or network evidence.
- Don't promote unresolved hero compression, region proportions, or open fidelity findings into universal design rules.
- Don't claim the scoped finish-review verdict closes the active goal or passes the whole interface.
