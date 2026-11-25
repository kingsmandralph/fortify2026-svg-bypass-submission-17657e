# Fortify 2026 — In-flight Report Index

| Finding | Report file | Severity | Status | Platform | Submitted | Notes |
|---|---|---|---|---|---|---|
| nithub `/event/_next/image` SVG bypass + XInclude reachability | `nithub-event-image-svg-bypass.fortify.md` | Medium (50) | **DRAFTED, LIVE-REPRODUCED, awaiting submission approval** | Fortify 2026 | — | Non-destructive discipline enforced; CVE-2026-96889 UAF deliberately not fired per RoE §1.2 / §1.4 |

## Submission queue

1. `nithub-event-image-svg-bypass.fortify.md` — ready for submission approval. Needs:
   - Human review of the seven-section report
   - Cross-verify CVE IDs (`CVE-2026-119347`, `CVE-2026-96889`) against NVD/GHSA
   - Attach artifacts from `findings/nithub-event-image-svg-bypass/poc/` if the submission channel supports attachments
   - Explicit go-ahead before sending (per `feedback-explicit-permission-per-vendor-email` discipline)

## Not submitted (yet)

- `/event` Server Action `get` SSRF (the earlier finding) — currently a capability note (fetches public URLs only; no sensitive-data exfil demonstrated). Under Fortify 2026's non-exploitation RoE this may still be submittable at Low–Medium if cleanly written up. Decision pending.
