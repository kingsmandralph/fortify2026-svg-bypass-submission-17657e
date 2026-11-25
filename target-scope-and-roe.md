# Fortify 2026 Security Challenge — Target Scope & RoE

**Program:** Fortify 2026 Security Challenge
**Judge/Triage:** Exploit Forge Academy
**Format:** Competition-style challenge; non-exploitation security assessment
**Onboarded:** 2026-11-25

## In-scope assets

- `https://web.cubbes.app`
- `https://utme-test.gocacademy.live/`
- `https://nithub.unilag.edu.ng/audio`
- `https://nithub.unilag.edu.ng/event`
- `https://nithub.unilag.edu.ng/forms`

## Rules of Engagement (verbatim-derived, binding)

1. **Non-exploitation assessment.** Identify and document vulnerabilities **without exploiting them**.
2. Do not modify, delete, manipulate, or access sensitive user data (except your own).
3. Do not disrupt application availability or interfere with other users' activities.
4. Stay strictly within scope.
5. Do not execute destructive actions to demonstrate full exploitability; if demonstrating impact against another user is required, do so only against a second account you own.

## Severity & scoring

| Severity | Points |
|---|---|
| Critical | 100 |
| High | 75 |
| Medium | 50 |
| Low | 20 |

Judges independently re-triage severity. **Do not inflate.** Over-severity hurts overall score.

## Required report sections (seven, exact)

1. Vulnerability Title
2. Vulnerability Description
3. Affected Component
4. Severity Level
5. Impact
6. Evidence (non-invasive; screenshots, obs, req/resp)
7. Remediation

## Scoring axes (judges assess)

- Finding validity / relevance
- Severity accuracy
- Supporting evidence quality
- Clarity of impact
- Practicality of remediation
- Report structure, professionalism, completeness

## Hunt status

| Finding | Asset | Severity | Status |
|---|---|---|---|
| `nithub-event-image-svg-bypass` | nithub.unilag.edu.ng/event | Medium | drafted, LIVE-REPRODUCED 2026-11-25 |
| (prior) `/event` Server Action `get` SSRF | nithub.unilag.edu.ng/event | TBD | discussed, not drafted (capability-only — see §5 impact note) |

## Attack-surface notes (pre-recon, from scope alone)

- `nithub.unilag.edu.ng/event` — Next.js SPA with React Server Actions, Image Optimization API; confirmed server-side SVG rendering via sharp/libvips/librsvg; rich surface for image-parser bugs, SSRF via image `url=`, Server Action auth/validation bugs.
- `nithub.unilag.edu.ng/forms`, `/audio` — sibling apps on same host, co-hosted via nginx; potentially share backends or fetch-primitives.
- `web.cubbes.app` — unexplored.
- `utme-test.gocacademy.live` — unexplored; "utme-test" naming suggests exam / assessment subsystem, high EV for auth / grading-logic / IDOR.

## Guardrails specific to this engagement

- **Never fire** crash reproducers for library CVEs on the live endpoints — would DoS the shared optimizer.
- Keep probe rate modest; this is a competition, other participants are actively hitting the same endpoints.
- No bulk account creation; use own accounts only.
- Evidence = HTTP response text + decoded output analysis; screenshots optional but useful for the judge.
