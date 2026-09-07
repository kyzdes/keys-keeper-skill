---
name: Keys Keeper native macOS companion
description: Native activity inspection and access to the existing Keys Keeper window.
colors:
  copper-light: "rgb(67% 27% 16%)"
  copper-dark: "rgb(85% 46% 31%)"
typography:
  metric:
    fontFamily: "system-ui"
    fontSize: "30pt"
    fontWeight: 600
  title:
    fontFamily: "system-ui"
    fontSize: "16pt"
    fontWeight: 600
  headline:
    fontFamily: "system-ui"
    fontSize: "14pt"
    fontWeight: 500
  body:
    fontFamily: "system-ui"
    fontSize: "13pt"
    fontWeight: 400
  label:
    fontFamily: "system-ui"
    fontSize: "12pt"
    fontWeight: 400
  micro:
    fontFamily: "system-ui"
    fontSize: "11pt"
    fontWeight: 400
rounded:
  panel: "12pt"
spacing:
  tight: "2pt"
  row-inset: "5pt"
  inline: "8pt"
  group: "10pt"
  support: "12pt"
  section: "14pt"
  panel-inset: "20pt"
components:
  activity-panel:
    rounded: "{rounded.panel}"
    padding: "{spacing.panel-inset}"
    width: "356pt"
  vault-toggle:
    padding: "5pt 0"
  refresh-button:
    size: "26pt"
  statistic-row:
    typography: "{typography.body}"
    padding: "5pt 0"
  footer-navigation:
    typography: "{typography.label}"
  activity-metric:
    typography: "{typography.metric}"
---

# Design System: Keys Keeper native macOS companion

## Overview

**Creative North Star: "Keys Keeper native macOS utility"**

This is a native extension of the incumbent Keys Keeper identity. Copper and the key symbol supply product recognition; AppKit material, system text, and native controls supply the surrounding visual language. The direction is descriptive of the built utility, with no new brand metaphor.

The panel uses compact, readable groups to show attributed activity and provide access to the existing vault window. It separates totals, unknown sources, and failures without decorative cards or marketing content. Those choices describe this native surface and do not prescribe a redesign of the web admin.

**Key Characteristics:**

- Copper identity within native macOS materials and controls.
- A prominent count with aligned, quieter supporting statistics.
- One primary window action and lightweight utility actions.
- Explicit loading, unavailable, empty, and incomplete states.

This document records [KeysKeeper.swift](KeysKeeper.swift), informed by [PRODUCT.md](../../../PRODUCT.md) and [MACOS-MENUBAR.md](../../../docs/MACOS-MENUBAR.md). The committed [installed-app capture](../../../docs/images/macos-menubar.png) verifies the empty dark state after local midnight. Earlier local captures verified the populated dark state and the unavailable state with a copper active button. Light appearance and remaining states are source-defined. Values below are native points. `system-ui` denotes SwiftUI `.system` on macOS, not a new web font stack.

The companion sidecar contains browser-renderable illustrations only. Their HTML/CSS, system-color substitutions, and interaction effects approximate native controls; they are not normative web styles or pixel-accurate AppKit specimens. No synthesized color ramp, fixed material color, or fixed native shadow is recorded as a token.

## Colors

The palette uses one copper accent alongside macOS semantic colors and materials.

### Primary

- **Copper for light appearance** (`colors.copper-light`) and **copper for dark appearance** (`colors.copper-dark`) are selected by SwiftUI's color scheme. The key symbol uses the selected accent, and the primary button receives it through `.tint(accent)`.
- The source's fractional sRGB channels are preserved as CSS percentages in the frontmatter. The native implementation remains authoritative.

### Neutral

- Default foreground styling supplies primary text. SwiftUI `.secondary` supplies supporting labels, helper copy, and row icons.
- `NSVisualEffectView.Material.popover`, with `.behindWindow` blending and `.active` state, supplies the panel material. The enclosing `NSPanel` is clear and nonopaque.
- Native dividers and `.link` buttons retain their platform color behavior. The incomplete-journal label uses SwiftUI `.orange` as a semantic warning, without redefining an RGB value.

**The Native Resolution Rule.** Preserve semantic foregrounds, material, and native button styles; a color sampled from one screenshot is not a reusable palette token.

Captured states include both a neutral gray prominent bezel and an active copper button. Preserve the native style and tint request so AppKit resolves the current control state.

## Typography

**Text family:** SwiftUI `.system`, using the macOS system face. The large metric also uses `.rounded`; this is a native numeric treatment, not a separate display brand.

The hierarchy grows from small supporting copy to a single readable count. No custom line height or tracking is set. Font rendering, native control typography where not overridden, and baseline metrics remain platform-managed.

### Hierarchy

- **Metric** (`typography.metric`): the attributed-agent count, rounded design, monospaced digits.
- **Title** (`typography.title`): the Keys Keeper product name.
- **Headline** (`typography.headline`): the label beside the main count.
- **Body** (`typography.body`): statistic rows; numeric values change to medium weight and use monospaced digits.
- **Label** (`typography.label`): scope, date interval, footer actions, and status messages.
- **Micro** (`typography.micro`): the counting explanation and primary action's keyboard hint. The shortcut hint has the source's reduced opacity.

**The Stable Digits Rule.** Keep metric and row values monospaced so a refresh changes the number without changing its digit rhythm.

## Layout

The activity surface is a single fixed-width column, defined by `components.activity-panel`. A leading-aligned stack contains the identity header, baseline-aligned metric, agent rows, supporting totals, explanation, and actions. Spacers align numeric values and secondary actions to the trailing edge. `statistic-row` repeats the same vertical inset for every row; the primary button adds its recorded content padding inside the native bezel.

Header identity and scope use a tight vertical pair. Group and section spacing distinguish related rows from the actions. Long explanatory and status text is allowed to wrap vertically. The view uses its fitting height; the panel is resized on opening and when statistics change.

The panel anchors beneath a visible status item, with a fallback near the current screen's upper trailing corner. Positioning keeps horizontal screen margins. Native window bounds cap its height; there is no implemented scrolling list or responsive breakpoint system to inherit from this build.

The existing web admin remains inside a resizable native window with saved frame placement. Its window layout and web design are outside this directory's token scope.

## Elevation & Depth

Depth comes from the active AppKit popover material and the native panel shadow (`NSPanel.hasShadow = true`). The panel sits at `.popUpMenu` level and clips its material to the panel shape. There is no custom shadow offset, blur, opacity, or animation curve in the source. Dividers separate content groups without adding nested raised containers.

**The Platform Depth Rule.** Let AppKit resolve material and elevation for the current appearance; do not turn the screenshot's gray backing or shadow into a fixed surface recipe.

## Shapes

The panel has a rounded outer silhouette, using `rounded.panel`, with no custom border. The primary action uses native `.borderedProminent` geometry; refresh uses `.borderless`; footer actions use `.link`. Their bezel radii, hit rendering, hover, focus, and pressed treatments are not manually defined by this implementation.

Icons are SF Symbols. `key.horizontal` appears in the panel identity and as a template status-item image. Functional icons include `arrow.clockwise`, `terminal`, `macwindow`, `rectangle.compress.vertical`, and `exclamationmark.triangle`. No font-glyph icon substitute is part of the native system.

## Components

### Activity panel

A retained, borderless `NSPanel` presents the compact activity surface. It can become key, dismisses on Escape or loss of key status, and opens from the menu bar icon or Command-Shift-K. Its native material remains active. On first launch, this panel is the initial surface.

### Status item and main metric

The menu bar pairs a template key symbol with today's attributed-agent count. The tooltip supplies the attributed and total counts. The panel repeats the attributed count with a local-day label; unavailable data shows an em dash rather than a stale number.

### Statistic rows

Rows use secondary labels, trailing medium-weight numeric values, and optional secondary SF Symbols for agents. Agent rows precede a divider and aggregate rows. The desktop row appears only when nonzero. Unknown sources remain explicitly labelled; failures have their own row. Empty attributed activity is a wrapping text message, not a fabricated agent row.

### Primary window action

The full-width action uses `.borderedProminent` with the selected copper tint. It reads “Открыть Keys Keeper” or “Скрыть окно” according to window visibility, switches its window symbol accordingly, and shows the Command-O hint. During an open request it reads “Открываем…” and is disabled. Hover, focus, and pressed appearance are native.

Showing an existing valid window reuses its current page and unfinished input. Hiding or closing that window retains it; the menu bar companion continues running. The action also dismisses the activity panel.

### Refresh and footer actions

Refresh is a borderless SF Symbol button with a named accessibility label and help text. It requests new statistics; opening the panel also refreshes them, and an active timer refreshes every 15 seconds. These are data updates, not animation tokens.

The footer pairs the native links “Журнал обращений” and “Выйти”. The first opens the existing audit page; the second quits the companion. Command-Q remains available. The native app menu also exposes the window and statistics actions, so access is not dependent on a visible menu bar item.

### Status and failure feedback

Initial loading pairs a small native progress indicator with secondary text. An unavailable summary replaces the count with an em dash and offers an explicit refresh instruction. Incomplete data keeps the available statistics visible and adds an orange warning label with an SF Symbol. Opening failure uses a native alert with retry and close actions.

## Do's and Don'ts

### Do:

- **Do** preserve the copper accent and native key-symbol identity.
- **Do** use macOS semantic text, material, controls, and focus behavior for this companion.
- **Do** keep values aligned with monospaced digits and retain distinct labels for attributed, unknown, total, and failed activity.
- **Do** retain visible feedback for loading, unavailable, empty, and incomplete statistics.
- **Do** preserve the current page and unfinished input when hiding and showing the existing valid vault window.

### Don't:

- **Don't** replace native materials, shadow, or control states with screenshot-derived fixed CSS values.
- **Don't** treat the sidecar's HTML/CSS illustrations as a web design system or evidence of native interaction testing.
- **Don't** imply that an unavailable count is zero or that an unknown caller has an identified agent.
- **Don't** add marketing ornament, a new brand metaphor, or competing primary actions to this compact activity panel.
- **Don't** generalize this panel's fixed geometry into a rule for the web admin or other product surfaces.
