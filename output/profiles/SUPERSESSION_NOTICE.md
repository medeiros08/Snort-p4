# Notice: partially superseded snapshot IRs

The snapshots below are frozen records of the 2026-08-25 profile build and
are intentionally left unchanged:

- `cicids2017/artifacts/semantic_manifest.json`
- `controlled/artifacts/semantic_manifest.json`

Two IR-fidelity defects affect both of them. Their P4 entries, install plans,
and rule splits are unaffected, and were verified byte-identical after each
repair.

1. **Whitespace.** The text of 121 `content` patterns in 110 rules is missing
   leading or trailing whitespace that belongs to the pattern. It is
   superseded by `output/semantic_manifest.json` as of commit `b931dd2`.
   Details: `paper/IDS_P4/IR_CONTENT_WHITESPACE_SUPERSESSION.md`.
2. **Negation.** Two `content` options (sids 1843 and 28982) whose pattern
   begins with `!` inside the quotes are recorded as negated. They are
   superseded by the IR regenerated with the negation repair. Details:
   `paper/IDS_P4/IR_CONTENT_NEGATION_SUPERSESSION.md`.
