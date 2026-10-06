# Manuscript Consistency Audit After the `snort3` Switch

Date: 2026-10-06. Scope: the three manuscripts as rewritten in Phase C of
`HEADER_SEMANTICS_DEFAULT_SUPERSESSION.md` (commit `b0575f3`):

- `paper/IDS_P4/main.tex`
- `paper/IDS_P4_PT/artigo.tex`
- `paper/IDS_P4_SBRC/artigo.tex`, whose body is generated from the PT
  version by `montar.py`

## 1. Method

Two passes, run in parallel.

### Number check

`tests/check_manuscript_numbers.py` recomputes 538 values from the artifacts
that support them, records the source of each, and scans every number in
the three `.tex` files against them. Its output is
`output/analysis/manuscript_number_audit.json`.

- **Sources:** manifests, backend, strong partition, trace metrics, BMv2
  replays, campaigns, attribution, audits, and external rulesets.
- **What the scan covers:** body, captions, tables and abstracts. English
  and Portuguese number formats are both handled.

A number that matches no fact, and is not on the list of structural numbers,
is reported. The list covers versions, years, profile ports and layout
values. Seeded wrong values (18.31, 94.886, 3,997, 236, 92,299, 1.101.458)
are all reported.

The check proves that each number exists in some artifact, not that it is
cited in the right place. That correspondence is the second pass.

### Claim-level review

An independent reviewer read `main.tex` from start to finish against the
artifacts. I re-read the PT version claim by claim. Every finding below was
re-verified against the data before being applied.

## 2. Findings and corrections

### Definite errors

1. **Introduction: "2,931 service-based rules among" the 3,996 Necessary.**
   - Only 2,924 are Necessary; the other 7 are now Unsupported.
   - Corrected to 2,924.
2. **Service-based counts were scoped to the wrong set.** "Of the 4,017
   rules, 2,928 declare a service option … 1,060 use no option…".
   - These counts cover the 4,003 rules the earlier compilation classified
     Necessary. Over all 4,017 rules, 2,930 declare `service`; the two extra
     are service-style Unsupported rules.
   - The sentence now scopes the counts to the 4,003 and states that the 14
     earlier Unsupported rules include no service-based rule. So 2,931 holds
     over the whole ruleset.
3. **Candidate-set limitations: "under the earlier one two of them were
   prefiltered".**
   - In the earlier strong run, all 606 flush-ACK HTTP rules were
     prefiltered. The two were the ones whose acknowledgment was marked
     no-match: 604 CONFIRMADO and 2 DEPENDENCIA_DE_ESTADO in
     `resultado_strong.jsonl`.
   - Corrected.
4. **Grouping: "within half a percentage point of the entry-level
   reduction".**
   - False for protocol plus port on Brute Force, where the gap is
     0.597 points.
   - Now "within 0.6 percentage points", and "within 0.11 points" over the
     full ruleset. The latter was 0.12; the true maximum is 0.110.

### Precision and wording, all applied

| # | Issue | Correction |
|---|---|---|
| 5 | The grouping "service" key is the entry's port values (`port_family`), not Snort's identified service. This clashed with the paper's point about ports. | Renamed "protocol plus port" in the text and table, and defined. |
| 6 | "The strong-discriminator policy leaves them to fallback" | "all but five of them" (SIDs 309, 1133, 1415, 1416, 45983 stay P4-eligible). |
| 7 | Payload-negative accounting mixed prefiltered and fallback rules | Excess measured on the 134 confirmed rules (130 / 4); the other 866 reported apart (788 candidate, 78 no-match). |
| 8 | "The traces exercise no retained predicate" | "No observed alert belongs to a P4-eligible rule", so the candidate sets are untested. Applied in `main.tex` (3 places) and the PT version. |
| 9 | "Moves selectivity rather than coverage" | "Costs mostly selectivity": seven rules lose coverage. Applied in `main.tex` and the PT version. |
| 10 | "Confirmed on BMv2" for the header-evaluation model | "Confirmed in a data-plane test": Snort's alerts confirm the model, and BMv2 gives the verdicts. Applied in `main.tex` and the PT version. |
| 11 | The alert-preservation caption did not say the split came from the earlier compilation's partitions | Caption says so. |
| 12 | The environment versions were stated for "the frozen results" | Checked on the rig that ran Phase B: Snort 3.12.2.0, p4c 1.2.4.2 (`624c6be80`), BMv2 1.15.0-68f4a978, Python 3.10.12, Ubuntu 22.04.5. Reworded to "all data-plane and Snort results". |
| 13 | The alert-packet replays used 20 ms, not 2 ms (`intervalo_s` 0.02) | Methodology, PT version and supersession §6.2 corrected. |
| 14a | The campaign cases were generated against the 331-entry plan | The header-negative wording now refers to "the plan installed when the cases were generated". |
| 14b | The 14 Unsupported rules were excluded by the generator, not "admit no witness" | Corrected. The text now also notes that SIDs 56583 and 56584, newly Unsupported, alerted in the campaign. |
| 15 | User-mode `alert http` rules were said to be compiled "with their full header", but their service protocol is delegated | "From their header with its ports". Applied in `main.tex` and the PT version. |

Two more points came from another session working on the same repository:

| # | Issue | Correction |
|---|---|---|
| 16 | The environment paragraph named no rig, and no Phase B file recorded the tool versions | Versions recorded in `output/analysis/fase_b_snort3/versoes_ferramentas.txt`, captured after the runs on the same WSL rig. The paragraph now says Ubuntu 22.04 "under WSL 2". |
| 17 | The campaign's refusal reasons overlap: 14 + 193 + 44 + 1,654 = 1,905 > 1,875. "The rest" had listed only content and header reasons. | Now "each of the other 221 is Unsupported, has content the generator cannot place, or has a header it cannot resolve; a rule can have more than one of these reasons". |

The PT version also had two issues of its own:

- Its abstract attributed the off-port misses to the whole earlier
  compilation, rather than to one of its plans.
- Its RQ1 omitted the TCP key that service-based rules with `flags` keep.

## 3. State after the audit

| Version | Pages | Overfull | Undefined | Unknown numbers |
|---|---|---|---|---|
| `main.tex` | 45 | 0 | 0 | 0 |
| PT | 7 | 0 | 0 | 0 |
| SBRC | 14 | 0 | 0 | 0 |

The SBRC version keeps the template's cosmetic underfull boxes, and its
abstract and resumo have 10 lines each.

The reviewer fully checked the following against the artifacts, with no
further finding:

- abstract, introduction and contributions;
- §4.5 and all SID lists;
- the methodology metrics;
- RQ1–RQ4 and every table cell, including `tab:compilations`;
- the threats, conclusion, appendix and all cross-references.
