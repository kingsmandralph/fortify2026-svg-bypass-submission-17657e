# nithub /event/_next/image — SVG type-check bypass + XInclude reachability

**Finding slug:** `nithub-event-image-svg-bypass`
**Program:** Fortify 2026 Security Challenge (Exploit Forge Academy)
**Asset:** `https://nithub.unilag.edu.ng/event/` (in-scope per challenge brief)
**Severity (self):** Medium (50 points)
**Status:** drafted, LIVE-REPRODUCED 2026-11-25 ~13:19–13:23 UTC
**Submission file:** `targets/fortify-2026/reports/nithub-event-image-svg-bypass.fortify.md`

## One-line

Unauthenticated `/event/_next/image` Next.js Image Optimization endpoint accepts an SVG prefixed with `<!--ftypavif-->`, classifies it as AVIF, and renders it server-side via `sharp`/`libvips`/`librsvg` — bypassing the SVG rejection — with XInclude `data:` processing (CVE-2026-96889 precondition) live.

## Confirmed primitives (live, non-destructive)

| # | Claim | Evidence |
|---|---|---|
| 1 | Optimizer live | `/event/_next/image?url=/event/icon.png&w=64&q=75` → `200 image/png` |
| 2 | SVG-as-SVG rejected | External jsdelivr `.svg` URL → `400 "image type is not allowed"` |
| 3 | `<!--ftypavif-->`-prefixed SVG accepted & rasterized | 64×64 output, 2776 green pixels, 1099 blue pixels, 0 red; matches attacker SVG |
| 4 | Server-side fetch attribution | webhook log: `196.45.48.143` UA=`node` fetched cb_bypass URL at `13:22:45` |
| 5 | XInclude `data:` processed | 158-byte WebP, 1023 magenta pixels from inner `data:` SVG |
| 6 | Library is modern bundled `librsvg` ≥2.60.0 | Behavioral fingerprint (prior session) |

## Deliberately NOT done (RoE compliance)

- CVE-2026-96889 UAF reproducer not fired. Public PoC is a crash reproducer; firing it would DoS the shared optimizer and violate Fortify 2026 RoE §1.2 and §1.4.
- No bulk traffic, no account creation, no state mutation on target.

## Severity reasoning

Medium, not High or Critical. Confirmed = bypass + attacker-bytes-to-native-parser + XInclude `data:` reach. Unconfirmed = actual RCE via CVE-2026-96889 (patch level of deployed `librsvg` is not externally readable). Holding at Medium per Fortify RoE §2 anti-inflation guidance and global `CLAUDE.md` rule 13 (SSRF/parser-exposure findings need demonstrated sensitive-data impact to go High; here we have reachability without demonstrated exec).

## Reproduction

See `reports/nithub-event-image-svg-bypass.fortify.md` §E.8 for the full PoC script and §E.1–E.5 for step-by-step curl commands.

## Artifacts

In `poc/`:

- `bypass_output.jpeg` — rasterized attacker SVG (bypass proof)
- `xinclude_data_output.webp` — rasterized output with magenta pixels from inner `data:` (XInclude proof)
- `h_*.txt` — raw HTTP response headers for each test
- `webhook_requests.json` — server-side fetch attribution

## Open items / escalation path (NOT to execute under this RoE)

- Confirm `librsvg` patch level against a disposable replica running the same `@img/sharp-libvips` prebuilt — only way to settle CVE-2026-96889 exploitability externally. Out of scope here.
- CVE IDs (`CVE-2026-119347`, `CVE-2026-96889`) are cited from the researcher's prior intelligence pass; cross-verify against current NVD/GHSA before final submission.
