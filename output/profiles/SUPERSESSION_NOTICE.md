# Notice: partially superseded snapshots

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

## Pre-correction data plane in both snapshots

Added 2026-09-27. `cicids2017/artifacts/ids_prefilter.json` and
`controlled/artifacts/ids_prefilter.json` (sha256 `41b6215bb5fb3931…`), and
the `ids_prefilter.p4info.txt` next to each (`cabd74fb7642d848…`), are
byte-identical to `output/historical/ipv4_packet_domain_guard_pre_correction/`.
They are the program **without** the IPv4 packet-domain gate of 2026-09-01.
Do not start BMv2 from them: use `output/ids_prefilter.json`
(`f5167adc69e8ae05…`) and `output/ids_prefilter.p4info.txt`
(`0d60057afb6f34e9…`), which the frozen post-correction results used. Details:
`paper/IDS_P4/PARSER_DOMAIN_RECONCILIATION.md`; this was finding C2 of
`docs/review/2026-09-11_analise_completa.md`.

## Service-based rules

Added 2026-09-27. The predicates in every manifest and P4 artifact here, and
in `output/`, constrain header ports and protocol for the 2,931 service-based
NECESSARY rules: 2,928 declare `service:`, and three receive services from
their DCE options (a count revised the same day from 2,928). Snort 3 does not check those fields once it has
identified a matching service, so for these rules the predicates are
necessary conditions only on traffic Snort evaluates with the full header.
The artifacts are left unchanged. Details:
`paper/IDS_P4/SERVICE_BASED_HEADER_FINDING.md`.
