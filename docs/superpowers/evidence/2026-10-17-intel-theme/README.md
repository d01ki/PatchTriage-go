# Intelligence theme verification

Design: [2026-10-17 specification](../../specs/2026-10-17-intel-theme-design.md) and approved B mockup. Verification completed 2026-10-18 with Chrome on Windows, Python Playwright, and Go 1.27.0.

## Results

- `go vet ./...`: PASS. `go test -count=1 ./...`: all 13 packages PASS; [output](go-test.log).
- Embedded font tests cover all five WOFF2 files, MIME type, cache policy, missing files, traversal, and absence of session cookies on successful font responses.
- [Browser results](verification.json): 1440, 1000, and 390 px have no page-level horizontal overflow, no requests outside 127.0.0.1, and no console errors. All five local fonts return 200.
- Desktop tabs remain sticky while the decision pane scrolls: pane and tab top both 78 px at scrollTop 452. At 1000 and 390 px the existing responsive page-scroll behavior is preserved.
- At every width: box/ribbon filters, clear, Enter/Space, CVE navigation to Decision path, arrow/Home/End tab navigation, dialog selects and Escape pass.
- SSVC save/rerun persistence, target creation with context, upload readiness, and fixture upload/run on the offline demo pass. Live external-provider execution is outside this offline browser check.
- Font-failure fallback keeps readable content and produces no JavaScript page error. Expected resource errors in this deliberately failing scenario are separate from the zero-error normal runs.
- [Contrast calculations](contrast.json) and [rendered text audit](text-audit.json): primary text meets 4.5:1. Muted text is at least 5.45:1; outcome badge text at least 5.37:1; gradient button text at least 5.38:1. Raw dim/Defer tokens are not used as primary text colors.
- Screenshots were visually inspected against the approved B mockup: dark navy surfaces, restrained blue-to-cyan controls, local Plex typography, and outcome-only result colors match the intended appearance.
- Exact design tokens and LF encoding checked. No changes to report output, CLI, API JSON, JavaScript state management, or `testdata/golden`.

## Implementation decisions

The specification and contrast requirement take precedence where the implementation plan differs:

- Primary gradient buttons use dark `--bg` text. White would give only 3.68:1 on blue and 1.81:1 on cyan.
- Defer text mixes its unchanged outcome token with `--ink` (70% Defer); the original token remains the geometry color. Empty flow labels and inherited low-contrast labels use `--mut`; leaf text is not faded with geometry.
- Selected tabs use the cyan border without glow, following the specification's restricted glow use. Intermediate flow borders use `--line2` rather than an extra hard-coded color.
- Task 4 needed one additional desktop fix despite commit 895322c: the result's `overflow:hidden` ancestor prevented actual sticky behavior. Desktop-only `overflow:visible` restores it; the responsive page-scroll arrangement is retained.
- An inline favicon removes the browser's automatic favicon 404 without network dependencies. CVE links avoid wrapping; noninteractive upload-ready text uses neutral ink.

## Screenshots

| Screen | 1440 px | 1000 px | 390 px |
| --- | --- | --- | --- |
| Landing | [View](1440-landing.png) | [View](1000-landing.png) | [View](390-landing.png) |
| Overview | [View](1440-overview.png) | [View](1000-overview.png) | [View](390-overview.png) |
| Decision path | [View](1440-path.png) | [View](1000-path.png) | [View](390-path.png) |
| Actions | [View](1440-actions.png) | [View](1000-actions.png) | [View](390-actions.png) |
| Evidence | [View](1440-evidence.png) | [View](1000-evidence.png) | [View](390-evidence.png) |
| Review | [View](1440-review.png) | [View](1000-review.png) | [View](390-review.png) |
| Input dialog | [View](1440-dialog.png) | [View](1000-dialog.png) | [View](390-dialog.png) |

[Desktop sticky tabs after scrolling](1440-sticky.png).
