# Landing Spec — Patchi Public Landing (Snyk × Linear)

**Copies:** Snyk (security-engineering voice) + Linear surface discipline
**Canvas:** `#000000` black, cards `#181818`, orange `#C8621A` single accent
**Type:** Geist (fallback Inter) + Geist Mono, 600 max weight, −2.4px display
**Route:** `/landing` (public) — distinct from `/` Mission Control (localhost app). `/` stays localhost dashboard; landing is marketing preview, linkable from `p web --help` and topbar.

---

## 1. Page Architecture (7 bands, 80px rhythm, 160px hero break)

Borrowed from Snyk's `hero-band` → `feature-card` 3-up → `product-mockup-card` → footer, with Wiz IA graft.

```
[ Nav — Snyk glass header ]
[ Hero — 160px break, centered, floating mockup ]
[ Social proof — logos / stats ]
[ 3-up Feature Cards — why Patchi ]
[ Product Band A — Brain Graph (Wiz Security Graph) ]
[ Product Band B — Red Team + Council (attack → synthesis) ]
[ Product Band C — Live Tests + Fix Verify ]
[ How it works — CLI ↔ Web 1:1 ]
[ Freemium — pricing strip ]
[ Footer — 5 columns ]
```

---

## 2. Nav (Snyk nav-bar, Linear pill)

- Left: `PATCHI` wordmark (Geist 14px, orange, letter-spacing 2px) + `Security Dashboard` sub
- Center: links `Product` `Security` `Docs` `GitHub` — muted `#8B949E`, hover `#FFFFFF`
- Right: `⌘K` ghost (circle+kbd hint like Mission Control) + `Get Started` inverted primary (`#FFFFFF`/`#000000`, 4px, 16px 700, 16×24) — Snyk's signature inverted CTA.

---

## 3. Hero (Snyk hero-band, Linear display)

- **Eyebrow:** mono `Geist Mono 12px 700 1.68px` → `AI-POWERED • AGENT COLONY • 54 AGENTS`
- **H1:** `Patchi finds what scanners miss` — Geist Display 56px/600/−2.4px, white, centered, line 1:1. Second line in orange `#C8621A` → `and fixes what's safe`.
- **Sub:** `CLI agent colony + Mission Control web. One scan, 334 security domains, real browser attacks. 1:1 CLI ↔ Web — the web is a fancy wrapper.` — Inter 15px/24px, `#8B949E`, max 640px.
- **CTAs:** row centered, gap 12px: `[ Get Started — inverted ]` `[ `p scan` → copy code block ]` — code block uses `Geist Mono 13px` on `#181818`.
- **Floating mockup:** product mockup card below hero, `background #181818, radius 12px, pad 16px, glow 0 8px 32px rgba(200,98,26,0.18)`. Inside: light inner mockup showing Mission Control grid (thumbnail of brain map + health + agent feed). Dotted texture behind (Snyk hero texture).
- **Badge:** top-right of mockup `Health 80/B • 12 files • 3 routes` — mimics Patchi's real health badge.

---

## 4. Social Proof (Linear minimal)

- Thin band, `border-top 1px rgba(255,255,255,0.08)`, centered `“Trusted by teams who ship at record speed”` 12px mono, then 5 logo placeholders (gray 60% opacity) or metrics: `54 agents` `334 domains` `17 sigma rules` `1300+ tests`.

---

## 5. Feature Cards — 3-up (Snyk feature-card)

Each `bg #181818, radius 12px, pad 24px, border hairline`. Top embeds small UI fragment (not illustration):

- **Card 1 — “You're shipping risk at record speed”** — icon scan glyph, fragment: import graph thumbnail, title `Static → Live`, body `From import graph to real browser DAST. Semgrep + Gitleaks + OSV + Playwright + your agents.`.
- **Card 2 — “Attackers are accelerating”** — Red Team glyph, fragment: attack timeline dot (success/blocked/failed like Wiz), body `100+ YAML scenarios, safe mode, auto-fix verification.`
- **Card 3 — “Your AI features are now attack vectors”** — Council glyph, body `8 personas deliberate in parallel, synthesize, produce action plan with tool calls + confirmation gates.`

---

## 6. Product Band A — Brain (Wiz graph, Linear surface)

**Layout:** 2-col (text left, mockup right) alternating. `padding 80px`, gap 48px.

- **Label:** `BRAIN` mono orange
- **H2:** `The Brain is the database` — 32px/600/−1.2px, white
- **Body:** `AST scanning across 9 languages, import graph, symbol graph, layers. Wiz modeled security as a graph; Patchi models your code as one. Every file, route, dependency mapped. Click any node → full context.`
- **Bullets:** `Layered brain (L1 modules → L4 project)` `Tap-to-spawn (max 5 ants, 10s cooldown)` `Blast radius`
- **Mockup right:** layered brain canvas (draggable nodes screenshot) + Konva brain map inset. Glow orange.

---

## 7. Product Band B — Red Team + Council (Wiz attack path + Snyk mockup)

**Layout:** mockup left, text right (alternating).

- **Label:** `RED TEAM & COUNCIL` mono
- **H2:** `Attack, deliberate, fix — then verify`
- **Body:** `Red Team replays SQLi/XSS/SSRF/Auth. Council (Architect + Security Officer + Test Engineer…) debates, reaches consensus, emits tool calls.`
- **Attack timeline graphic:** vertical `::before` 2px line, dots colored `success=red`, `blocked=green`, `failed=gray` (from dashboard_v2.css). Show 3 events.
- **Council synthesis mockup:** persona cards (`border-left 3px accent`) + confidence bars + synthesis box `rgba(200,98,26,0.06)`.

---

## 8. Product Band C — Live Tests (Snyk product-mockup-card)

**Layout:** text left, browser frame right.

- **Label:** `LIVE TESTS`
- **H2:** `Your app, actually running`
- **Body:** `Browser pool, stress (load/spike/soak/breakpoint), screenshots, video — streamed over WebSocket. Not synthetic — real Playwright.`
- **Browser frame:** `border #181818, radius 12px, toolbar #21262d`, viewport 16:10 checker pattern, screenshot img, metric cards 3-up (`p50 latency`, `throughput`, `error %`).

---

## 9. How it Works — CLI ↔ Web 1:1 (Linear steps, Vercel code block)

Centered `How it works` H2 + 3 steps:

1. `p init` → 2. `p scan` → 3. `p web` (or `p fix`)

Show split code + web parity table:

| CLI | Web |
|---|---|
| `p scan` | `POST /api/scan` + agent feed WS |
| `p fix` | `Review` → risk-gated apply |
| `p web --project ../other` | header project switcher |

Mono command blocks, copy button (Linear).

---

## 10. Freemium Strip (Snyk pricing-card retokened)

Centered, `bg #181818`, `border rgba(255,255,255,0.08)`, `pad 32px`.

- **Eyebrow:** `FREEMIUM • PRE-1.0.0`
- **H3:** `Free for personal & teams <3, enterprise ≥3`
- **Body:** `Peak stable at v1.0.0 — ~0.4.0 remains. Pin .patchi formats as best-effort.`
- **CTA:** inverted `Contact idemudiaehis6@gmail.com` + `Read LICENSE`

---

## 11. Footer (Snyk footer)

`bg #000000`, `text #8B949E`, `Geist Mono 12px` meta, 5 columns:

- **Platform:** Scan, Fix, Council, Red Team, Live Tests
- **Resources:** Docs, web-cli-parity, PATCHI_V2_UPGRADE_PLAN, BUILD_MAP
- **Knowledge:** Security, Testing, Brain
- **Company:** License, CHANGELOG, AGENT_FEEDBACK
- **Why Patchi:** Charter, Assurance, DAST

Bottom: `PATCHI` wordmark + `Patched & Dispatched` newsletter strip (email input + `Subscribe` inverted) + `© 2026 Patchi`.

---

## 12. Tokens & Components (reused, not invented)

Already defined in `landing_style_research.md`. Landing imports:
- `dashboard_v2.css` variables (for mockup cards)
- plus new `landing.css` that composes Snyk tokens:

```css
.landing { --canvas:#000; --surface:#181818; --ink:#fff; --accent:#C8621A; }
.landing .hero-band { padding:80px 20px; text-align:center; }
.landing .feature-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:24px; }
.landing .product-mockup-card { background:var(--surface); border-radius:8px; padding:16px; box-shadow: var(--glow); }
.landing .btn-primary { background:var(--ink); color:var(--canvas); padding:16px 24px; border-radius:4px; font:700 16px Geist; }
```

**Interaction:**
- `⌘K` opens command palette (reuse `dashboard_v2.js` modal) — demonstrates pallet.
- Mockup cards have hover `border-color: var(--accent)`.
- Code blocks copy on click + toast `Copied`.
- Inverted CTA hover `background: #f0f0f0`.

**Responsive:**
- Hero mockup hides texture below 800px.
- 3-up → 1-col at 768px (`grid-2/3/4 → 1fr` like style.css).
- 2-col product bands stack at 900px.

---

## 13. Implementation Checklist

- [ ] Create `patchi/web/templates/landing.html` — standalone (no base.html) like Snyk, but sharing header style with Mission Control for brand continuity.
- [ ] Create `patchi/web/static/landing.css` — tokens + hero/feature/mockup/footer, imports Geist via `https://fonts.googleapis.com/css2?family=Geist...` fallback to Inter.
- [ ] Add route `GET /landing` in `routes/dashboard.py` (or new `routes/landing.py`) → render `landing.html` with minimal context (stats from `health.compute`, `get_brain`).
- [ ] Wire `app.py` to include `landing_router`.
- [ ] Add nav link: Mission Control header `Get Started` → `/landing`, landing nav `Open Mission Control` → `/` (when running locally).
- [ ] Verify responsive + 22/22 e2e still passes (landing adds one more check, doesn't break existing).
- [ ] Screenshot checklist: hero, 3-up, Brain, Council, Live Tests, CLI strip, footer — compare to Snyk's dot texture + Linear's hairlines.

---

## 14. Copy Deck (for `landing.html`)

Use exact strings from sections 3-10 above. Keep voice: confident, engineering-grade, sentence-case durations, no marketing fluff. Emphasize `1:1 CLI ↔ Web`, `verified not assumed`, `agents don't auto-fix without risk gate`.

---

## 15. Not Doing

- No light mode toggle (dark-first like Linear).
- No pricing calculator (freemium simple).
- No blog / docs expansion (reuse existing `docs/`).
- No auth / hosted billing on landing (hosted is experimental, link to `/hosted` inside app).

