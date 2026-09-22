# Notice: partially superseded snapshot IRs

The snapshots below are frozen records of the 2026-08-25 profile build and
are intentionally left unchanged:

- `cicids2017/artifacts/semantic_manifest.json`
- `controlled/artifacts/semantic_manifest.json`

In both, the text of 121 `content` patterns in 110 rules is missing
leading or trailing whitespace that belongs to the pattern. That text is
superseded by `output/semantic_manifest.json` as of commit `b931dd2`. The
P4 entries, install plans, and rule splits are unaffected, and were verified
byte-identical after the repair.

Details, evidence, and the list of affected rules:
`paper/IDS_P4/IR_CONTENT_WHITESPACE_SUPERSESSION.md`.
