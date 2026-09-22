# IR Content-Whitespace Supersession

## 1. Purpose and status

The semantic IR (`semantic_manifest.json`) recorded the text of 121 `content`
patterns in 110 rules without their leading or trailing whitespace, although
that whitespace lies inside the quotes of the source rule and is part of the
pattern Snort matches. The defect was found by the end-to-end campaign
(`output/campaign/`), repaired in commit `b931dd2`, and the working IR at
`output/semantic_manifest.json` was regenerated.

The two profile snapshots were left untouched, as the frozen-artifact
convention requires. This document declares what they supersede and what
they do not:

- `output/profiles/cicids2017/artifacts/semantic_manifest.json`
- `output/profiles/controlled/artifacts/semantic_manifest.json`

**Status:** the `content` pattern text in both snapshot IRs is
**SUPERSEDED** for the 110 rules listed by the procedure in §8.
Nothing else in the snapshots is superseded by this document. No P4 entry,
install plan, rule split, classification count, or data-plane measurement
changes (§4.3).

## 2. The defect

`compiler/parser.py` `parse_option` returns `value.strip().strip('"')`: it
removes whitespace *outside* the quotes, then the quotes. Any whitespace left
in the value is therefore inside the quotes, and is pattern content.
`compiler/option_normalizer.py` then applied `.strip()` a second time, in
`split_content_value` and in `remove_final_quote`, and removed that content.

| Source rule | IR before `b931dd2` | IR after |
|---|---|---|
| sid 1789, `content:"USERHOST "` | `USERHOST` | `USERHOST ` |
| sid 811, `content:" /HTTP/1.",fast_pattern,nocase` | `/HTTP/1.` | ` /HTTP/1.` |
| sid 1639, `content:" \|3A\|.DCC SEND",distance 0,...` | `\|3A\|.DCC SEND` | ` \|3A\|.DCC SEND` |

Of the 121 affected patterns, 56 lost trailing whitespace, 48 lost leading
whitespace, and 17 lost both. All 110 affected rules are classified
`NECESSARY`.

The repair removes both `.strip()` calls. The regression test is
`test_whitespace_inside_quotes_is_content` in
`tests/test_option_normalizer.py`.

## 3. Timeline

| When | Artifact | Event |
|---|---|---|
| 2026-08-25 20:04 UTC | `output/profiles/*/build_report.json` (`built_at_utc`) | profile snapshots built, with the whitespace-stripping normalizer |
| 2026-09-09 | commit `ce45f97` | snapshots committed as part of the frozen baseline |
| 2026-09-22 17:28 -0300 | commit `21e0dd0` | campaign v3 leaves 7 port-range cases vacuous; the investigation identifies the defect |
| 2026-09-22 17:55 -0300 | commit `b931dd2` | normalizer repaired; working IR regenerated; campaign v4 |
| 2026-09-22 | this document | supersession declared for the snapshot IRs |

## 4. Evidence

### 4.1 Scope was measured on both snapshots

The repaired normalizer was re-applied to each snapshot's recorded
`parsed_rule` options and compared with the recorded
`detection_predicates[].value.pattern`. The result is the same for both
profiles: 121 options, 110 rules, all `NECESSARY`. Pattern text does not
depend on the variable profile, so this agreement is expected.

### 4.2 The IR diff is confined to pattern text

The pipeline was re-run in the order `compiler/build_profile.py` uses: the
eight Python steps plus `generate_p4runtime_install.py`. The regenerated
`output/semantic_manifest.json` was then compared field by field against the
previous version (`21e0dd0`):

- Top-level fields: none changed.
- Rules changed: 110.
- Changed fields: `delegated[].value.pattern` (121) and
  `detection_predicates[].value.pattern` (121). No other field changed.

| IR | sha256 |
|---|---|
| before, `21e0dd0` = snapshot `cicids2017` | `499ae907460d2c6f70c395570e481bfdaacce20d7f8b3e259a371b62ec117447` |
| after, `b931dd2` | `cfceee73b06066caf044118ae0994d8528e4813685e07f95ace3baf1b08f4707` |
| snapshot `controlled` (unchanged) | `c74042c42ad5c813fb4bb7ce66a628af80d77e8815003eb1a68f0fa7b13b01a1` |

### 4.3 No P4 artifact changed

Every artifact the re-run produces downstream of the IR is byte-identical
(sha256) to the committed version and to the `cicids2017` snapshot:

- `p4_entries.json`, `p4_entries_expanded.json`, `p4runtime_entries.json`
- `backend_validation.json`
- `p4_install_entries.json`, `p4runtime_install_plan.json`
- `snort_candidate.rules`, `snort_unsupported.rules`,
  `snort_experiment_split.json`

This is what should be observed. `content` is never lowered to a P4 key; it
is delegated to Snort, which evaluates the original rule text. None of the
entry-generation stages reads `pattern`. The only readers are
`compiler/analyze_content_modifiers.py`, `tests/campaign_witness.py`, and
two unit tests.

The strength of this claim differs between the two profiles:

- **`cicids2017`: re-verified.** The pipeline was re-run and the outputs
  compared by hash.
- **`controlled`: inferred, not re-run.** The inference rests on the same
  static argument (no entry-generation stage reads `pattern`) and on the
  identical 121-pattern scope from §4.1.

### 4.4 The defect had an observable effect

Snort 3.12.2.0 on the rig did not alert on witnesses built from the stripped
patterns. It did alert on witnesses built from the source text, for sids
1639, 1640, 1789 and 1790.

The campaign witness generator had inherited the IR text. On the same
1000-case sample, it moved as follows:

| Campaign | Vacuous cases | Change |
|---|---|---|
| v3, `21e0dd0` | 65 | — |
| v4, `b931dd2` | 40 | 10 recovered by this repair; 15 by an unrelated generator repair (absolute `offset` placement) |

No case lost its alert, and the v4 run under the strong-discriminator plan
produced 0 `VIOLACAO`.

## 5. What is superseded and what is not

| Artifact or claim | Status |
|---|---|
| `content` pattern text for the 110 rules, in both snapshot IRs | **SUPERSEDED** by `output/semantic_manifest.json` at `b931dd2` |
| Any other field of the snapshot IRs | unchanged by this document |
| P4 entries, install plans, and rule splits of both profiles | **VALID**: byte-identical after the repair (§4.3) |
| `semantic_counts` in `build_report.json` (`NECESSARY` 4003, `UNSUPPORTED` 14) | **VALID**: classification does not depend on pattern text, and no classification field changed (§4.2) |
| Data-plane measurements in `output/analysis/` and `output/experiments/` | **VALID**: they consume P4 entries, not pattern text |
| Campaigns `output/campaign/piloto` to `e2e_1000_v3` | **VALID as recorded**. Their witnesses for the affected rules used stripped text, so some cases were vacuous; vacuity is counted separately and never as success. v4 is the first campaign built from the repaired IR. |

## 6. Manuscript impact

No number in `paper/IDS_P4/main.tex` depends on pattern text. However,
`main.tex:109` lists among the contributions "a compilation manifest that
records preserved and delegated predicates". For 110 rules, the recorded
text of delegated `content` predicates was not the source text until
`b931dd2`.

The claim holds for the repaired manifest. If the manuscript describes the
manifest as a faithful record, the evaluated artifact should be the one at
or after `b931dd2`. `main.tex` was not edited by this document.

## 7. Related observations outside this document's scope

- The same `.strip()` exists in the private copy of the split logic in
  `compiler/analyze_content_modifiers.py`. That script only prints
  diagnostic examples to the console, its counts concern modifiers and not
  pattern text, and it writes no committed artifact. It was not changed.
- The snapshots also predate the P4 parser packet-domain repair of
  2026-09-01 (`PARSER_DOMAIN_RECONCILIATION.md`):
  - `output/profiles/cicids2017/artifacts/ids_prefilter.json` contains no
    `packet_domain_fallback` action; `output/ids_prefilter.json` contains
    it six times.
  - `ids_prefilter.json` and `ids_prefilter.p4info.txt` therefore differ
    from the working copies. They are compiler (`p4c`) outputs and were not
    touched here.

  This is a pre-existing difference, not an effect of this repair. It
  confirms that the snapshots are a record of the 2026-08-25 build, not of
  the current compiler.

## 8. Reproduction

The affected rules can be listed by re-applying the repaired normalizer to a
snapshot's recorded options:

```python
import json, sys
sys.path.insert(0, "compiler")
from option_normalizer import normalize_content

ir = json.load(open("output/profiles/cicids2017/artifacts/semantic_manifest.json", encoding="utf-8"))
affected = sorted(
    r["rule_id"]
    for r in ir["rules"]
    if any(
        recorded != normalize_content(str(o["value"]))["pattern"]
        for recorded, o in zip(
            [(p.get("value") or {}).get("pattern")
             for p in r.get("detection_predicates") or []
             if p.get("source_option") == "content"],
            [o for o in r["parsed_rule"]["options"] if o["name"] == "content"],
        )
    )
)
print(len(affected))   # 110
```

The P4 invariance of §4.3 is reproduced by re-running the pipeline stages
listed in `compiler/build_profile.py` (`PYTHON_STEPS`, then
`generate_p4runtime_install.py`) and comparing the outputs with `git diff`.
