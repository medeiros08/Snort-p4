# Compilation Robustness on External Rulesets

**Date:** 2026-10-01
**Scope:** compile-level only. The static pipeline compiled each ruleset,
from rule to P4Runtime plan. No ruleset in this document was run against
traffic, Snort or BMv2, so nothing here measures detection, preservation or
selectivity.

## 1. Purpose

The evaluation uses one ruleset: the Snort 3 Community ruleset, 4,017 rules.
This document records what the compiler does with rulesets it was not
developed against. Two questions:

- Does it compile them?
- When it refuses, does it refuse for a reason Snort 3 would also refuse?

It does not widen the evaluated scope of the paper. The single-ruleset
limitation stands; this is evidence that the pipeline is not tuned to one
file.

## 2. Inputs and reproduction

`scripts/rig_rulesets_externos.sh` recreates the four inputs on the rig and
records the sha256 of each:

| Input | Source | Syntax |
|---|---|---|
| `snort2_ubuntu` | `/etc/snort/rules/*.rules` of Ubuntu package `snort-rules-default 2.9.15.1-6build1`, 73 files concatenated in name order | Snort 2 |
| `snort2_ubuntu_convertido` | the same, converted by the `snort2lua` of the Snort 3.12.2.0 installation | Snort 3 |
| `snort3_sensitive_data` | `sensitive_data.rules` shipped with Snort 3.12.2.0 | Snort 3 |
| `snort3_file_magic` | `file_magic.rules` shipped with Snort 3.12.2.0 | Snort 3 |

`tests/analyze_external_rulesets.py` compiles them on the Windows machine
with `compiler/run_static_pipeline.py --limpar` and the active `cicids2017`
variable profile, and checks each sha256 against the rig record (all four
match). The summary is versioned at `output/analysis/rulesets_externos.json`.
The full per-run artifacts are not versioned.

The script's run on 2026-10-01 produced inputs byte-identical to those
prepared by hand on 2026-09-29 for the first, unversioned test.

## 3. Results

| Ruleset | Active rules | Outcome | EXACT / NECESSARY / UNSUPPORTED | Final P4 entries |
|---|---:|---|---|---:|
| Community (evaluated, for reference) | 4,017 | compiles | 0 / 4,003 / 14 | 331 |
| `snort3_sensitive_data` | 25 | compiles | 0 / 25 / 0 | 1 |
| `snort3_file_magic` | 219 | refused at stage 1: 219 parse failures | — | — |
| `snort2_ubuntu_convertido` | 3,935 | refused before compiling (§4.2) | — | — |
| … without the rules of §4.1 | 3,887 | compiles | 10 / 3,869 / 8 | 333 |
| `snort2_ubuntu` | 3,948 | refused before compiling (§4.2) | — | — |
| … without the rules of §4.1 | 3,900 | compiles | 10 / 3,881 / 9 | 335 |

**Cleaning.** `--limpar` removed the following from the Snort 2 files. No
`gid:sid` was repeated among the active rules that remained.

| File | Comments | Commented-out rules | Blank lines |
|---|---:|---:|---:|
| converted | 3,708 | 153 | 0 |
| raw | 1,449 | 140 | 565 |

## 4. Every refusal coincides with Snort 3

### 4.1 Undefined variables

- **What happened.** 48 rule lines, under 27 distinct sids, use
  `$SHELLCODE_PORTS` (43 lines) or `$AIM_SERVERS` (5). These variables
  belong to Snort 2. The effective `ips.variables` of Snort 3.12.2.0 with
  this configuration does not define them, as the `snort --dump-config-text`
  run behind `tests/check_profile_vs_snort.py` shows.
- **What Snort does.** On the rig, Snort 3 rejects such a rule with
  `FATAL: PortVar Lookup failed on '$SHELLCODE_PORTS'`.
- **What the compiler does.** It leaves the predicate UNASSESSED, and
  `validate_semantic_manifest.py` rejects the manifest. The analysis removes
  those lines, records the removal, and compiles the rest.

### 4.2 Repeated `gid:sid` with a different protocol

- **What happened.** Sid 647 appears twice, once over TCP and once over UDP.
- **What Snort does.** Snort 3 rejects that with `ParseError`
  (`src/parser/parse_rule.cc`, `mergeDuplicateOtn`, tag 3.12.2.0).
- **What the compiler does.** `--limpar` refuses the same way, instead of
  picking one of the two.
- **Why the reduced runs compile.** The two occurrences of sid 647 are among
  the `$SHELLCODE_PORTS` rules of §4.1, so removing those rules removes the
  conflict as well.

### 4.3 `file_id` rules

The 219 rules of `file_magic.rules` are `file_id (...)` rules. They classify
file types and do not describe traffic. The parser does not accept them, and
the pipeline gate stops at stage 1 on `summary.failures: 219`.

## 5. Snort 2 syntax is detected, and does not change the P4 predicates

- **Detection.** `compiler/snort2_syntax.py` flags options Snort 3 no longer
  accepts (`docs/vendor/snort3/doc/upgrade/snort_upgrade.text:432-470`).
  - Raw Snort 2 file: 3,272 of the 3,900 compiled rules are flagged. The most
    common marks are `nocase;` (3,335), `uricontent` (2,215) and a standalone
    `distance` (1,905).
  - Converted file: 2 rules are flagged, both false positives of §7.
- **Effect on the predicates.** Over the 3,887 rules common to the raw and
  converted files:
  - **0** classification differences;
  - **0** differences in the set of final P4 entries each rule contributes.

  The 13 rules present only in the raw file are those `snort2lua` failed to
  convert.

This is expected, because the P4 predicates come from the rule header, and
the header syntax is the same in Snort 2 and Snort 3. Content and other
payload options are delegated to Snort. In Snort 2 syntax, however, their
buffer attribution in the IR is unreliable. For example, in
`content:"x"; http_uri;` the `http_uri` applies to the preceding content in
Snort 2 and to the following one in Snort 3. That is why the executor warns.

## 6. EXACT appears for the first time

Both Snort 2 files produce 10 EXACT rules. The evaluated Community ruleset
has none. All 10 consist of a header with no detection option, for example
`alert udp any any -> 255.255.255.255 161`.

Equivalence to the header is plausible for such rules, and the manifest
invariants (EXACT with no delegated or fallback predicate) hold. **It has not
been verified against Snort.** This document does not claim that any EXACT
classification has been validated.

## 7. Parser defect found

In the converted file, `reference:url,support.microsoft.com/default.aspx?scid=kb\;EN-US\;q138268`
is split at the escaped `\;`. This produces bogus option names (`EN-US\`,
`q138268`) in 2 rules.

- **Impact on the evaluated results:** none. The Community ruleset contains
  no `\;`, and `reference` is metadata that never reaches a predicate.
- **Status:** recorded here, not fixed.

## 8. Use in the manuscript

At most, one sentence in the threats to validity: the static pipeline
compiled two external rulesets, and every refusal coincided with a Snort 3
refusal. The single evaluated ruleset, profile and dataset remain the
limitation for every traffic-based result.
