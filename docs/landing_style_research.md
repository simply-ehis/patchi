# Landing Style Research — Company to Copy for Patchi

**Date:** 2026-08-28
**Goal:** pick one company style to copy for Patchi's public landing (external marketing, not the localhost Mission Control).
**Constraint:** research, don't invent — score options, pick highest overall.

---

## 1. Candidates Scored (capability, quality, fit for Patchi, distinctiveness)

Patchi = AI-powered code security & quality agent colony, CLI + web, developer-first, security trust required.

| Candidate | What it is | Dark style | Accent | Typography | Best for | Fit for Patchi | Risk |
|---|---|---|---|---|---|---|---|
| **Linear** | Issue tracker for eng teams. Dark-only marketing, `canvas #010102`, 4-step surface ladder `#0f1011→#191a1b`, hairline `#23252a`, single lavender `#5e6ad2`, no gradients, no shadows, 8px cards, Inter Variable 510/590, −3px tracking at 80px, pill CTA 9999. | Near-black, hairline hierarchy | Lavender single | Inter/Geist | Productivity/dev-tool speed | ⭐⭐⭐⭐ High craft, but generic clone risk; no security signal | Cloned by everyone after 2021 — "Linear-clone" look |
| **Vercel / Geist** | Hosting for Next.js. Monochrome `ink #171717` on `fafafa`, no accent, Geist Sans+Mono 400/500/600 max, pill 100px marketing / 6px app, stacked shadows (1px inset + 4-12% opacity), mesh gradient only at hero (cyan/blue/pink/amber fused) | White primary, black dark band | None (ink IS brand) | Geist | Infra/deployment minimalism | ⭐⭐ Minimal, cold; security trust low | Reads as empty for marketing |
| **Snyk** | Code security devtool (closest to Patchi). Pure black `#000000` canvas, near-black `#181818` cards, white display, Geist + Geist Mono (1.68px tracked eyebrow), inverted white-on-black primary button, multi-hue inside charts (purple `#c481f3`, mint/cyan/pink/gold), purple glow shadow `rgba(68,28,153)`, generous 80px rhythm, 160px hero break | Pure black | Purple + inverted white | Geist | Security devtool trust | ⭐⭐⭐⭐⭐ Direct analog (agents, compliance, supply chain) | Pure black harsh, purple clashes with Patchi orange |
| **Wiz** | Cloud security platform. Security Graph, toxic combos, attack paths, compliance heatmaps, lens role views, vertical nav, funnel + heatmap dashboards. Relationship-first, blast radius, progressive disclosure 5 levels (dashboard→raw data) | Dark (GitHub-like #0d1117) | Blue/purple | Inter | Cloud posture / enterprise | ⭐⭐⭐⭐ Best IA for Patchi's Brain Map + Red Team + Council, but cloud not code | Enterprise weight, not marketing minimal |

**Scores (1-5):**

|  | Linear | Vercel | Snyk | Wiz |
|---|---|---|---|---|
| Security trust | 2 | 2 | **5** | 5 |
| Developer tool credibility | 5 | 5 | 5 | 4 |
| AI / agentic feel | 3 | 4 | 5 | 4 |
| Landing minimalism | 5 | 5 | 4 | 3 |
| Differentiation (not clone) | 2 | 2 | 3 | 4 |
| **Overall for Patchi** | 3.4 | 3.6 | **4.6** | 4.0 |

---

## 2. Recommendation: Copy **Snyk** as primary, with Linear discipline grafted

**One sentence:** *Snyk's security-engineering voice with Linear's surface restraint — pure-black canvas, white display, inverted CTA, purple-glow depth, but with Patchi's orange #C8621A replacing purple and hairline surfaces instead of heavy shadows.*

**Why Snyk wins for Patchi:**
- Patchi IS Snyk-like: 54 security agents, supply chain, compliance, fix generation — not generic productivity (Linear) or hosting (Vercel). Snyk's "security should feel like autocomplete" + dev-first trust maps 1:1 to Patchi's "CLI ↔ Web 1:1, auto-fix safe".
- Snyk's marketing artifacts are **product UI fragments inside dark cards** (analytics dashboards, PR panes, integration grids) — perfect for showing Patchi's Brain Map (Konva graph), Council deliberation, Attack Timeline, Live Test browser pool without illustration.
- Purple glow + inverted button is ownable for security; Patchi can own the same with orange glow (`rgba(200,98,26,0.25)`) + inverted white CTA.

**What to steal from each:**

- **From Snyk (80%):**
  - Canvas `#000000`, surface `#181818`, 4px buttons / 8-12px cards, Geist Sans headline + Geist Mono eyebrow (1.68px, 700).
  - Inverted primary: `bg #ffffff / text #000000` ("Get Started", "Book demo") — pops hardest on black.
  - Product mockup cards: show real Patchi UI (Mission Control grid, Brain Map, Council) inside dark cards with light inner surfaces + multi-hue chart accents.
  - Dotted hero texture + purple/orange glow on elevated mockups.
  - Generous vertical rhythm: 80px bands, 160px hero break, allow white type + CTA to carry each band.
  - Footer: multi-column Platform/Resources/Knowledge/Company/Why Patchi + wordmark + newsletter.

- **From Linear (15%):**
  - Single-accent restraint: one orange, not purple+mint+cyan everywhere. Chrome stays monochrome; color lives in charts/fragments.
  - Surface ladder + hairline borders (`#181818` card on `#000000` floor, 1px `rgba(255,255,255,0.05)`), not heavy shadows.
  - Negative tracking on display (−2.4px at 48px) and 510/590 weights, not bold 700.
  - Keyboard-first hints (⌘K) — Patchi has `⌘K` command palette + WS feed.

- **From Wiz (5% IA, not visual):**
  - Graph as data model → Wiz Security Graph = Patchi Brain (import graph + layers). Copy **attack path linear narrative** over full graph hairball, toxic-combo surfacing, blast radius.
  - Progressive disclosure 5 levels (aggregate → issue list → issue detail with attack path → resource graph → raw).
  - Compliance heatmap + funnel (vuln lifecycle) for future `/compliance` page.

---

## 3. What the Landing Should NOT Copy

- ❌ Linear's lavender `#5e6ad2` — keep Patchi orange `#C8621A` (warm, distinct from Snyk purple).
- ❌ Vercel's monochrome nihilism — Patchi needs security trust + warmth.
- ❌ Wiz's enterprise dashboard density on marketing site — keep marketing sparse, put density inside mockup cards.
- ❌ Light mode on marketing — stay dark-first (app is dark), but ensure WCAG contrast.

---

## 4. Design Tokens — Patchi Landing (derived)

**Inspired by Snyk + Linear, adapted for Patchi:**

```css
:root {
  /* Canvas */
  --canvas: #000000;
  --surface-dark: #181818;
  --surface-elevated: #1A1A1A; /* matches app style.css */
  --surface-light: #F2EDD6; /* for inner mockup light panels */
  --border: rgba(255,255,255,0.08);
  --border-strong: rgba(255,255,255,0.14);

  /* Brand */
  --ink: #FFFFFF;
  --ink-secondary: #8B949E;
  --body: #8B949E;
  --accent: #C8621A; /* Patchi orange — replaces Snyk purple */
  --accent-hover: #A8501A;
  --accent-glow: rgba(200,98,26,0.25); /* for mockup shadow */

  /* Semantic */
  --critical: #FF4D6D;
  --high: #FF8C42;
  --medium: #FACC15;
  --low: #4ADE80;

  /* Type */
  --font-sans: "Geist", "Inter", -apple-system, sans-serif;
  --font-mono: "Geist Mono", "JetBrains Mono", monospace;
  --display-weight: 600;
  --mono-tracking: 1.68px;

  /* Radii */
  --r-sm: 4px;
  --r-md: 8px;
  --r-lg: 12px;
  --r-pill: 9999px;

  /* Rhythm */
  --band: 80px;
  --band-hero: 160px;

  /* Shadow */
  --glow: 0 8px 32px rgba(200,98,26,0.18), inset 0 0 0 1px rgba(255,255,255,0.08);
}
```

**Typography (Geist fallback to Inter):**
- Display (h1 56-64px, 600, −2.4px, line 1:1)
- Title (h2 32-40px, 600, −1.2px)
- Body 15px/24px, secondary 13px, micro 12px/16px (mono for eyebrows)

**Components to copy verbatim (from Snyk DESIGN.md, retokened):**
- `button-primary` inverted (#fff/#000, 16px/700, 16×24 pad, 4px)
- `hero-band` (black canvas, centered display + sub + body + row of CTAs, floating mockup)
- `feature-card` 3-up (#181818, 12px, 24px pad, embedded UI fragment on top, title + body)
- `product-mockup-card` (#181818, 8px, 16px pad, inner light surface)
- `footer` black with 5-column links + wordmark + newsletter

---

## 5. Sources

- Snyk DESIGN.md via duply.ai (alpha) — pure black, Geist, inverted CTA, glow.
- Linear DESIGN.md via shadcn.io — #010102, lavender single, surface ladder, hairline.
- Geist design system — Vercel (`vercel.com/geist`), Geist Sans/Mono, restraint.
- Wiz blog + portal research — Security Graph, attack path, Lens, heatmap/funnel, dual query modes.
- Patchi app tokens — `static/style.css` (#0A0A0A etc) + `static/dashboard_v2.css` (#0d1117 + #58a6ff) — to unify, not fork.

---

## 6. Decision Log

- Chose **Snyk** over Linear because Patchi's wedge is security + quality, not productivity — trust > velocity. Linear is beautiful but every devtool already clones it; Snyk is less cloned and more credible for buyer (security team).
- Hybrid avoids "Linear-clone" trap flagged in designsystems.one research.
- Keeps Patchi orange as single accent instead of adopting Snyk purple — brand continuity.
- IA graft from Wiz gives the landing a story Patchi actually has (Brain Graph → Toxic Combo → Attack Path → Council Fix → Live Verify) that Linear/Vercel have no analog for.

