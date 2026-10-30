# vpnCAT — Brand book (concept v0.1)

> **Status:** Proposed visual source of truth for [redesign issue #666](https://github.com/devops-igor/amnezia-nexus/issues/666), pending final visual/design approval. Product naming and migration are tracked separately by [#658](https://github.com/devops-igor/amnezia-nexus/issues/658).

## Name and positioning

- **Product:** **vpnCAT** (typeset lower-case `vpn` + upper-case `CAT`)
- **CAT acronym:** **Censorship-Aware Tunneling** — use this exact expansion, not Cross-protocol Adaptive Transit.
- **Tagline:** **One gateway. Many paths.**
- **Short description:** A self-hosted VPN gateway that manages multiple backend routes and transport protocols to keep connections available when a path is blocked or unavailable.
- **Architectural accuracy:** Currently distinguish **AmneziaWG client ingress** from supported **AWG, VLESS+REALITY and NaiveProxy egress/backend** paths; the name does not imply all protocols are supported for client ingress. A blocked ingress endpoint cannot be rescued merely by changing egress.

## Personality and voice

**Friendly, clever, dependable, practical, adventurous.** The astronaut cat makes networking feel approachable; the product surfaces remain precise. Explain what failed, what can be done, and what consequences an action has. Prefer accessible language over memes in security-sensitive operations. No claims of guaranteed anonymity, universal censorship circumvention, perfect failover, or zero downtime.

Examples:
- Welcome: “Ready for launch? Add your first backend.”
- Empty list: “No routes yet. Add a backend to begin.”
- Degraded: “This backend isn't responding. Existing sessions may need to reconnect.”
- Danger: “Delete this backend? This can interrupt active connections.” (Do not decorate warnings with celebratory mascot art.)

## Logo and mascot

- **Master mascot:** [assets/mascot.svg](assets/mascot.svg) — a custom illustrated yellow kitten with a cyan orbital helmet, purple outline and white/pale-blue suit, against a blue starfield; designed for vpnCAT.
- **Horizontal wordmark:** [assets/wordmark.svg](assets/wordmark.svg) — a graphic lockup with a subtitle and tagline.
- **Favicon / small mark:** [assets/favicon.svg](assets/favicon.svg) — simplified cat-helmet silhouette optimized for small sizes.
- Export raster assets from master vectors as needed; do **not** upscale favicon for a hero.
- Small icons must omit most facial features. Keep clear space >= 1/4 icon width. Never distort, rotate the wordmark, add unapproved gradients or rely on text in the favicon.
- Use mascot prominently on **login, setup, welcome and selected empty states**; avoid repeating on dense routing/diagnostic cards.
- Decorative stars, tiny satellites, moons and orbit lines are reserved for headers, onboarding and campaign art, not telemetry charts.
- Require a 1-color and dark-background variant before the identity is considered final.

## Palette

| Token | Value | Purpose |
|---|---|---|
| Deep Space | `#2D2B6F` | Ink, dark outlines, headings |
| Sky Blue | `#5B9DF6` | Brand accent and primary interaction |
| Warm Yellow | `#FFD84D` | Cheerful highlights, stars |
| Cosmic Purple | `#8A5CF6` | Secondary accent |
| Soft Coral | `#FF8DA1` | Cheeks, illustrations and subtle highlights |
| Mint Teal | `#00D2D0` | Extra accent for illustrations, **not automatically success** |
| Light Canvas | `#F1F5F9` | Light-mode canvas |
| Dark Canvas | `#10192F` | Dark-mode canvas |
| Dark Text | `#233145` | Content typography on light surfaces |

**Implementation note:** The palette is an artistic source; it is **not yet a contrast-certified semantic token system**. Test WCAG 2.2 AA on actual backgrounds (4.5:1 regular text; 3:1 large text and relevant UI). Create separate approved `--status-danger/success/warning/info` and focus tokens and theme-adjusted variants. Never confuse the mascot's pink or mint with fault severity.

## Typography

- **Display / heading:** Nunito Sans (or another approved, licensed soft-rounded sans), bold; use it for the logotype only if typography is licensed and visually tested.
- **Interface and tables:** Inter, normal/medium/semibold, with comfortably readable numbers.
- **Configuration/logs:** a developer-focused monospace face such as JetBrains Mono.
- Self-host approved font subset(s). No Google Fonts/CDN runtime dependency. Verify script coverage for English, Russian, Persian, French and Chinese; allow appropriately selected locale-specific fallbacks.

## Layout and components

- Clear two-level hierarchy: high-signal summary and primary actions first; diagnostics progressively disclosed below.
- 8px-based spacing scale, round but controlled radii (small controls 8–10px, cards 12–16px); 1px boundaries, sparse shadows.
- Mobile layout should adapt **tables to cards/details** rather than force excessive horizontal scroll.
- Provide consistent components for nav, table/filter/sort, form, modal, drawer, confirmation, status chip, skeleton, stale-data, error, empty state and QR/config export.
- Visualize the same backend protocol/status identity everywhere. Never invent data or show “healthy” when telemetry is unavailable.
- Minimum target widths for review: 320, 375, 768, 1024 and 1440px.

## Theme and accessibility

- Both light and dark modes are first-class. Retain the user's explicit saved preference.
- Fully support `en`, `ru`, `fr`, `fa` (RTL) and `zh`.
- Keyboard-first navigation, 44px touch targets where feasible, discernible focus, semantic labels, reduced motion and screen-reader alerts for async operations.
- Decorative illustrations must use empty alt text; meaningful brand illustrations must have accurate text alternatives. Critical alerts must communicate meaning with words and icons, not color alone.

## Asset governance

- These SVG masters are **new vpnCAT concept assets authored for this project**. The user-provided artwork is a style reference; no third-party binary was copied into this repository. Do not ship assets bearing another artist's copyright mark as finalized brand masters without an independently verified right to use them.
- Retain source SVGs; review them for unsafe XML/external refs and render consistently in GitHub and browser. Asset license should follow the project's chosen policy and be documented with release materials.
- Approve source/derivatives, final lettering, colors, size variants and rights before replacing the production favicon.
- Every UI implementation PR should point to this book; modifications require a versioned brand-book update and visual review.

## Proposed design review checklist

- [ ] Product name, acronym and tagline rendered correctly.
- [ ] Logo and mascot original assets approved, include ownership/licensing provenance.
- [ ] Dark/light, desktop/mobile, 5 locales and RTL verified.
- [ ] Contrast and typography audited; operations remain legible without illustrations.
- [ ] Security-critical UI and diagnostics do not sacrifice accuracy to mascots or color.
- [ ] Storybook or equivalent component previews match implemented tokens.
- [ ] No regressions in Go sessions, auth, API or VPN functionality.

## Related tickets

- [#658 — project rename / documentation](https://github.com/devops-igor/amnezia-nexus/issues/658)
- [#666 — design system and portal redesign](https://github.com/devops-igor/amnezia-nexus/issues/666)
- [#631 — multi-protocol backend support](https://github.com/devops-igor/amnezia-nexus/issues/631)
