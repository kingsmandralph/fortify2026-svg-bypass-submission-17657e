# Fortify 2026 Security Challenge — Submission

**Target:** `https://nithub.unilag.edu.ng/event/_next/image` (in-scope per challenge brief)
**Vulnerability:** Unauthenticated SVG type-check bypass in the Next.js Image Optimization API — attacker-controlled SVG rasterized server-side by `librsvg`; XInclude `data:` processing (CVE-2026-96889 precondition) reachable
**Severity (self-assessed):** Medium (50 points)
**Reporter:** kingsmandralph · submission for Exploit Forge Academy judges
**Date:** 2026-11-25

## What to look at first

| File | What it is |
|---|---|
| `Fortify2026_Nithub_Event_SVG_Bypass.pdf` | **Primary submission — 7-page PDF** with Finding-at-a-Glance, flowchart, and full 7-section write-up |
| `Fortify2026_Nithub_SVG_Bypass_PoC.mp4` | **67-second video walkthrough** — slide-by-slide explanation of the bypass |
| `report.md` | PDF source (Markdown) |
| `research-notes.md` | Internal research README |
| `target-scope-and-roe.md` | Scope + RoE binding reference |
| `poc/` | Raw artifacts: raster outputs, HTTP response headers, server-side fetch attribution log, flowchart |

## Evidence of non-destructive discipline

The CVE-2026-96889 use-after-free reproducer was **deliberately not fired** — the only public PoC is a crash reproducer, and executing it would DoS the shared Nithub optimizer, violating Fortify 2026 RoE §1.2 ("Do not disrupt application availability") and §1.4 ("Do not execute destructive actions"). The report establishes a confirmed, non-destructive defect (SVG type-check bypass + attacker-bytes-to-native-parser reachability + XInclude `data:` processing) and names the RCE escalation path without asserting it.

## Reproducing the finding

The PoC script in the PDF (§E.8, "Reproduction script") is self-contained. It needs `pip install pillow`, a webhook.site token (or any attacker-controlled HTTP host that can serve `image/svg+xml`), and will:

1. Confirm the baseline optimizer is live.
2. Fire the `<!--ftypavif-->`-prefixed SVG and decode the returned raster — expect 64×64 image with green and blue pixels.
3. Fire the XInclude `data:` test and decode — expect 64×64 image with magenta pixels from the inner `data:` SVG.

**Do not** substitute the public CVE-2026-96889 UAF reproducer for either payload; it is a crash reproducer and will DoS the optimizer.

---

*This repository will be archived or deleted after Fortify 2026 judging completes.*
