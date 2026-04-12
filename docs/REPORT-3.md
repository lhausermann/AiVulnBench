# REPORT-3: Anthropic Source Notes for Firefox Dataset Entries

## Purpose

This note preserves the external source material that was important when we upgraded
the Firefox entries in [`data/vulnerability_dataset.json`](/Users/hozr/Documents/dev/intelligent-security/fluf/data/vulnerability_dataset.json)
from report-only references to runnable benchmark cases.

## Material Sources

### Anthropic + Mozilla collaboration post

Source:
- [Anthropic: Mozilla Firefox security collaboration](https://www.anthropic.com/news/mozilla-firefox-security)

Why it matters:
- This is the public primary source tying Anthropic's Firefox review to the
  three CVEs we track in the dataset.
- It establishes the public framing for the Firefox 147 to 148 remediation
  window and confirms that the work came from a focused review of the Firefox
  JavaScript engine.

Dataset use:
- motivated inclusion of the Firefox entries as real-world cases
- supported the `source_urls` provenance for:
  - `mozilla-firefox-wasm-jit-type-confusion-cve-2026-2796`
  - `mozilla-firefox-javascript-engine-use-after-free-cve-2026-2797`
  - `mozilla-firefox-javascript-engine-use-after-free-cve-2026-2765`

### Anthropic exploit analysis for CVE-2026-2796

Source:
- [Anthropic RED: Reverse engineering Claude's CVE-2026-2796 exploit](https://red.anthropic.com/2026/exploit/)

Why it matters:
- This post explicitly connects the Firefox work to `CVE-2026-2796`.
- It states that Opus 4.6 found 22 Firefox vulnerabilities over two weeks and
  explains that the exploit work happened in a constrained testing environment.
- It is the most concrete public discussion tying the Firefox case to exploit
  evaluation rather than only bug finding.

Dataset use:
- reinforced that `CVE-2026-2796` should stay in the real-world dataset rather
  than the benchmark-control dataset
- supported keeping the Firefox benchmark narrative aligned with a file-level
  vulnerability-finding benchmark rather than claiming real-world weaponization

## Public Resolution Notes Used in the Dataset

The public reports were not enough on their own to make the Firefox entries
runnable. To make them benchmarkable, we paired those reports with public
upstream repository history and bug IDs mentioned in our local reports.

Resolved public fix commits:
- `CVE-2026-2796` -> `acbf8b9c045b57e11002bbdc88f8ca32c50ed503`
- `CVE-2026-2797` -> `5ee70a500bee2f4d2f72abcdf238fe4c911a074c`
- `CVE-2026-2765` -> `670eb2adbc70900fb1077437e452e698b0aaf488`

Resolved public file targets:
- `CVE-2026-2796` -> `js/src/wasm/WasmInstance.cpp`
- `CVE-2026-2797` -> `js/src/gc/GCRuntime.h`, `js/src/gc/Marking.cpp`,
  `js/src/gc/Sweeping.cpp`, `js/src/gc/WeakMap-inl.h`
- `CVE-2026-2765` -> `js/src/builtin/AtomicsObject.cpp`

Public repository links:
- [mozilla-firefox/firefox commit acbf8b9c045b57e11002bbdc88f8ca32c50ed503](https://github.com/mozilla-firefox/firefox/commit/acbf8b9c045b57e11002bbdc88f8ca32c50ed503)
- [mozilla-firefox/firefox commit 5ee70a500bee2f4d2f72abcdf238fe4c911a074c](https://github.com/mozilla-firefox/firefox/commit/5ee70a500bee2f4d2f72abcdf238fe4c911a074c)
- [mozilla-firefox/firefox commit 670eb2adbc70900fb1077437e452e698b0aaf488](https://github.com/mozilla-firefox/firefox/commit/670eb2adbc70900fb1077437e452e698b0aaf488)

Bug IDs referenced in local report material:
- [Bugzilla 2013165](https://bugzilla.mozilla.org/show_bug.cgi?id=2013165)
- [Bugzilla 2013561](https://bugzilla.mozilla.org/show_bug.cgi?id=2013561)
- [Bugzilla 2013562](https://bugzilla.mozilla.org/show_bug.cgi?id=2013562)
