# Final Closing-Pass Changelog

## Scope

No experiment, traffic replay, policy retuning, compiler/P4/rules/profile
change, frozen-artifact regeneration, title change, RQ change, or frozen-value
change was performed.

## `main.tex` changes made before the hard stop

1. Added the subsection `Predicate-Level Soundness of Partial Compilation` to
   formalize the intended `r => p_r` relation.
2. Qualified EXACT as a semantic classifier class and clarified that the P4
   prototype uses the common `send_to_ids` candidate action.
3. Added the compilation-semantics table covering verified header, list,
   direction, flag, fallback, delegated, and service-rule handling.
4. Added backend prose covering Cartesian list expansion, bidirectional
   orientation expansion, CIDR/port/flag normalization, TCP-flag lowering,
   P4Runtime encoding, identical-match deduplication, and provenance union.
5. Replaced methodology wording that could imply trace-based EXACT validation
   with the actual legacy component-test scope; preserved `EXACT = 0` for the
   frozen Community ruleset.
6. Added the frozen-artifact explanation of the 14 UNSUPPORTED rules and a
   qualitative account of common NECESSARY causes.

## Hard stop and post-blocker handling

The final parser audit found that `p4/ids_prefilter.p4` uses a fixed 20-byte
IPv4 header before L4 extraction, while the offline matcher advances by the
packet's IHL. This can break `r => p_r` for IPv4-options traffic. In accordance
with the requested hard-stop rule:

- no further scientific change was made to `main.tex`;
- the fallback-aware secondary metric, alert-diversity qualification, and
  reproducibility additions were documented only in
  `FINAL_SCIENTIFIC_CLOSING_AUDIT.md`;
- the earlier `SEMANTIC_SOUNDNESS_AUDIT.md` conclusion is explicitly marked as
  superseded in the final audit rather than silently overwritten;
- no frozen artifact or held-out result was regenerated.

## Audit and mechanical outputs

- Created `SEMANTIC_SOUNDNESS_AUDIT.md` during the pre-blocker static review.
- Created `FINAL_SCIENTIFIC_CLOSING_AUDIT.md` with the blocker, static
  counterexample, verified transformations, conservative frozen-data
  calculation, alert diversity, reproducibility facts, reviewer assessment,
  and `NOT_READY` recommendation.
- Created this `FINAL_CHANGELOG.md`.
- Rebuilt `main.pdf` mechanically: 29 pages, 373,568 bytes, exit status 0,
  zero fatal errors, zero undefined citations/references, and zero overfull
  boxes greater than 10 pt.
