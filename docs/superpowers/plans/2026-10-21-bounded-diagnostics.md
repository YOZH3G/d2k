# Optional bounded diagnostics — implementation plan

Goal: local opt-in history of search outcomes and RAM, without changing search decisions or learned catalog.
Approved scope: owner requested diagnostic tool and panel, explicitly requires off switch and bounded memory.
Architecture: controller-owned fixed-capacity rings allocated only while enabled; main-thread callbacks for scheduler and HTTP outcomes; minute procfs samples; atomic bounded JSON in private /tmp directory. Existing panel exposes same-origin POST toggle and GET report; no separate service, upload, restart, or flash writes. Reboot disables collection. Disable clears history. No algorithm/resource-budget changes.
Limits: 64 outcomes, 120 minute samples, ring allocation <=128 KiB, report <=256 KiB, atomic files <=512 KiB; panel bounded read <=256 KiB. Unknown measurements remain null. Include process IDs to distinguish restarts; RSS is not leak diagnosis. Callback uses machine outcome, not log parsing. No full config/secrets/packet payloads in export; targets are personal data and UI states this.

- [x] Regression tests: disabled allocation, repeated enable/disable, rollover, sample interval, procfs unavailable, bounded export and escaping.
- [x] C collector, structural counters and search hooks (TCP/QUIC/voice + HTTP).
- [x] Panel toggle/report with same-origin checks, local state, readable summary and download.
- [x] Integration/CLI tests, core/datapath/detect/panel checks, sanitizer and release linkage.
- [x] Handoff with exact revision, limits and remaining field validation. No publication/router deployment in this task.
