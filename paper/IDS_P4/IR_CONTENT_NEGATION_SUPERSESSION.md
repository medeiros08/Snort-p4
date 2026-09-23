# IR Content-Negation Supersession

## 1. Purpose and status

The semantic IR recorded two `content` options as negated although they are
not. In both, the pattern text begins with `!` *inside* the quotes, where it
is part of the pattern. The defect was found by the end-to-end campaign while
investigating the 40 vacuous cases of `e2e_1000_v4`, and was repaired in
`compiler/option_normalizer.py`. The working IR at
`output/semantic_manifest.json` was regenerated.

This is the second IR-fidelity repair found by the campaign. The first,
whitespace inside `content` quotes, is recorded in
`IR_CONTENT_WHITESPACE_SUPERSESSION.md`.

**Status:** in both profile snapshot IRs, the `negated` flag and the pattern
text of the two options in §2 are **SUPERSEDED**:

- `output/profiles/cicids2017/artifacts/semantic_manifest.json`
- `output/profiles/controlled/artifacts/semantic_manifest.json`

The same two options are also superseded in `output/semantic_manifest.json`
as committed at `b931dd2` and `e9b4967`. Nothing else is superseded by this
document. No P4 entry, install plan, rule split, classification count, or
data-plane measurement changes (§4).

## 2. The defect

In Snort 3, negation is a `!` *outside* the quotes: `content:!"abc"`.
`compiler/parser.py` `parse_option` returns `value.strip().strip('"')`, which
removes the opening quote only when the value begins with it. A real negation
therefore always reaches the normalizer as `!"abc`.

The normalizer accepted that form, but also treated *any* leading `!` as
negation. A leading `!` with no quote after it can only have been inside the
quotes, so it is pattern content. The repair recognizes negation only when
`!` is followed, after optional whitespace, by a quote. The regression test
is `test_bang_inside_quotes_is_content` in `tests/test_option_normalizer.py`.

| sid | Source rule | Before: `negated`, `pattern` | After |
|---|---|---|---|
| 1843 | `content:"!@\|23\|",depth 3` | `true`, `@\|23\|` | `false`, `!@\|23\|` |
| 28982 | `content:"!dl http://",fast_pattern,nocase` | `true`, `dl http://` | `false`, `!dl http://` |

Both rules are `NECESSARY`, and both classifications are unchanged.

## 3. Scope was measured against the source text

Every `content` option in the IR was compared with the source rule text,
using both its negation and its pattern:

- **Before the repair:** exactly these 2 options diverged. All 400 real
  negations in the ruleset were recorded correctly.
- **After the repair:** 0 options diverge.

Together with the whitespace repair, the IR now records every `content`
option exactly as written in the source rule.

## 4. Evidence

### 4.1 The IR diff is confined to the two options

The pipeline was re-run in the order `compiler/build_profile.py` uses: the
eight Python steps plus `generate_p4runtime_install.py`. The regenerated IR
was then compared field by field with `e9b4967`:

- Top-level fields: none changed.
- Rules changed: 1843 and 28982.
- Changed fields: `delegated[].value.negated`, `delegated[].value.pattern`,
  `detection_predicates[].value.negated`, and
  `detection_predicates[].value.pattern`, 2 each. No other field changed.

| IR | sha256 |
|---|---|
| before, `e9b4967` (= `b931dd2`) | `cfceee73b06066caf044118ae0994d8528e4813685e07f95ace3baf1b08f4707` |
| after | `7d34be6ba52f9f4983fa17f114716dce49b7f4825efa2309790b5b7d548a4a6f` |

### 4.2 No P4 artifact changed

These artifacts are byte-identical (sha256) to `e9b4967`:

- `p4_entries.json`, `p4_entries_expanded.json`, `p4runtime_entries.json`
- `backend_validation.json`
- `p4_install_entries.json`, `p4runtime_install_plan.json`
- `snort_candidate.rules`, `snort_unsupported.rules`,
  `snort_experiment_split.json`

This is expected, as for the whitespace repair: `content` is delegated to
Snort, which evaluates the source rule, and no entry-generation stage reads
the negation flag or the pattern. For the `controlled` snapshot, P4
invariance is inferred from the same argument, not re-run.

### 4.3 The defect had an observable effect

The campaign witness generator inherited the IR. For sid 28982 it built a
witness without `!dl http://`, because the IR said that string must be
absent. Snort 3.12.2.0 on the rig did not alert on it. A witness carrying
both `JOIN |3A|#` and `!dl http://` did alert. Sid 1843 is not in the
campaign sample.

## 5. What is superseded and what is not

| Artifact or claim | Status |
|---|---|
| `negated` and pattern text of the two options in §2, in both snapshot IRs and in `output/semantic_manifest.json` at `b931dd2`/`e9b4967` | **SUPERSEDED** by the IR regenerated with this repair |
| Any other field of those IRs | unchanged by this document |
| P4 entries, install plans, rule splits, classification counts | **VALID** (§4.2) |
| Data-plane measurements and campaigns up to `e2e_1000_v4` | **VALID as recorded**. The only campaign effect is that sid 28982 was vacuous, and vacuity is counted separately, never as success. |

## 6. Manuscript impact

No number in `paper/IDS_P4/main.tex` depends on these two options.
`IR_CONTENT_WHITESPACE_SUPERSESSION.md` §6 says that the manifest's claim to
record delegated predicates holds for the manifest at or after `b931dd2`.
With this document, that holds fully for the manifest regenerated with the
negation repair; at `b931dd2` it held except for these two options.
