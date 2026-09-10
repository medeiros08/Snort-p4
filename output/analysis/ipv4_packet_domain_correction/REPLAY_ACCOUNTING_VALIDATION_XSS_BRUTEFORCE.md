# XSS and Brute Force AF_PACKET Replay Accounting Validation

## Scope

This document completes the post-correction replay accounting started in
`REPLAY_ACCOUNTING_VALIDATION.md`, which covered only the SQLi window. It
records measurement reliability for the XSS and held-out Brute Force replays
executed against the corrected IPv4 packet-domain pipeline.

No experiment was re-executed for this document, no classifier semantics were
changed, and no frozen result was regenerated. Every value below is read from
the artifacts already present in `replays/` and from
`selectivity_revalidation.json` / `heldout_bruteforce_revalidation.json`.

## Counter layout

`compiler/read_prefilter_counters.py` reports the three indirect-counter
indices defined by `p4/ids_prefilter.p4`:

| Index | Category | Meaning |
|---:|---|---|
| 0 | `P4_CANDIDATE` | installed predicate matched inside the supported packet domain |
| 1 | `P4_NO_MATCH` | inside the supported packet domain, no installed predicate matched |
| 2 | `PACKET_DOMAIN_FALLBACK` | outside the supported domain (non-IPv4, `IHL != 5`, fragment/reserved flags, truncation, parser error); conservatively delegated as a candidate |

## Common preconditions verified for both replays

- Pipeline installed with `compiler/install_p4runtime.py`: 331 planned
  entries, 331 written, 331 read back, `Installation status: VALID`
  (`xss_install.log`, `bruteforce_install.log`).
- Counters read as **zero** in all three indices immediately before each
  sender started (`xss_before.txt`, `bruteforce_before.txt`), so absolute
  values equal deltas for these runs.
- Idle audits before each replay observed a zero delta across all three
  indices (`xss_idle_t0/t1.txt`, `bruteforce_idle_t0/t1.txt`), so no
  out-of-window traffic contaminated the counts.
- Sender is `tests/replay_pcap_raw.py` (AF_PACKET raw, captured Ethernet
  bytes, no Scapy reserialization). `bruteforce_sender.stderr` is empty, so
  no `send()` call raised.

## XSS window

Artifacts: `xss_before.txt`, `xss_after.txt`, `xss_sender.txt`,
`xss_install.log`, `xss_idle_t0.txt`, `xss_idle_t1.txt`.

| Measure | Value |
|---|---:|
| Sender frames (`Input packets`) | 191,848 |
| BMv2 `P4_CANDIDATE` delta | 189,076 |
| BMv2 `P4_NO_MATCH` delta | 0 |
| BMv2 `PACKET_DOMAIN_FALLBACK` delta | 2,772 |
| BMv2 total delta | 191,848 |
| Offline supported-domain candidate | 189,076 |
| Offline no-match | 0 |
| Offline packet-domain fallback | 2,772 |
| Elapsed | 235.10 s (~816 frames/s) |

Every category and the total agree exactly, and the BMv2 total equals the
sender count. The 2,772 fallback frames match the offline
parser-ineligible population for this trace (ARP 1,660, IPv6 820,
EtherType 0x01bb 179, EtherType 0x01bc 110, LLDP 3); the XSS trace contains
no direct-IPv4 frame with options or fragmentation.

**Status: ACCOUNTING_VALID.**

## Held-out Brute Force window

Artifacts: `bruteforce_before.txt`, `bruteforce_after.txt`,
`bruteforce_sender.txt`, `bruteforce_sender.stderr`,
`bruteforce_install.log`, `bruteforce_idle_t0.txt`, `bruteforce_idle_t1.txt`.

| Measure | Value |
|---|---:|
| Sender frames (`Input packets`) | 1,108,658 |
| BMv2 `P4_CANDIDATE` delta | 1,101,372 |
| BMv2 `P4_NO_MATCH` delta | 0 |
| BMv2 `PACKET_DOMAIN_FALLBACK` delta | 7,199 |
| BMv2 total delta | 1,108,571 |
| Offline supported-domain candidate | 1,101,459 |
| Offline no-match | 0 |
| Offline packet-domain fallback | 7,199 |
| Elapsed | 1,404.82 s (~789 frames/s) |

The offline classification is internally complete: 1,101,459 + 7,199 =
1,108,658, exactly the PCAP population. The BMv2 total is 87 frames lower
than the sender count, and the entire shortfall is in the `P4_CANDIDATE`
category.

### Interpretation of the 87-frame shortfall

- Loss relative to the sender population: 87 / 1,108,658 = **0.007847%**.
- Candidate-category agreement: 1,101,372 / 1,101,459 = **99.992101%**.
- `PACKET_DOMAIN_FALLBACK` agrees **exactly** (7,199 = 7,199), including the
  16 direct-IPv4 frames with fragmentation or reserved flags that the
  corrected pipeline routes to fallback.
- `P4_NO_MATCH` is **0** in both the data plane and the offline classifier.

The shortfall is therefore a **transport-layer measurement loss between the
AF_PACKET socket and the BMv2 ingress pipeline**, not a classification
disagreement. `replay_pcap_raw.py` counts a frame as sent once `send()`
returns without raising; frames accepted by the kernel can still be dropped
in the veth queue or on the BMv2 receive path during a 23-minute, ~789
frames/s run. The SQLi accounting document records the same class of
measurement-layer problem (kernel drops, MTU) being corrected without any
change to frame contents or classifier semantics.

No conclusion in the frozen held-out result depends on the 87 frames:

1. The offline classifier covers the complete 1,108,658-frame population and
   is the source of the reported selectivity and candidate-set statistics.
2. `P4_NO_MATCH` is zero in the data plane, so no missing frame can convert
   into an unobserved no-match; the reported global candidate rate of 100%
   of parser-eligible packets is a ceiling that missing frames cannot raise
   or lower in direction.
3. Data-plane/offline correspondence for every packet-domain class is
   independently established by the controlled guard suite
   (`output/analysis/ipv4_packet_domain_guard_test.json`, 11/11 PASS,
   including IPv4 options, first fragment, non-initial fragment, truncated
   IPv4 and truncated TCP).

**Status: ACCOUNTING_PARTIAL** — category-consistent and quantitatively
bounded, but not frame-exact like SQLi and XSS.

### What a frame-exact Brute Force rerun requires

The following was **not** executed and is the remaining work to promote this
window to `ACCOUNTING_VALID`:

1. Re-run `tests/replay_pcap_raw.py` on the unchanged Brute Force PCAP after
   a fresh pipeline install, with a larger inter-frame delay (`--inter`) or
   an increased `txqueuelen` on the veth pair, to remove queue-level drops.
2. Record `before`/`after` counter deltas and an idle audit as in this
   document, and confirm
   `sender frames == P4_CANDIDATE + P4_NO_MATCH + PACKET_DOMAIN_FALLBACK`.
3. Confirm the resulting candidate delta equals the offline value of
   1,101,459 for the supported domain and 7,199 for fallback.

Until then, quantitative held-out claims should cite the offline classifier
(complete population) as the primary source, with the data-plane replay as
corroborating evidence at 99.99% frame agreement.

## Summary

| Window | Sender frames | BMv2 total | Candidate | No-match | Fallback | Status |
|---|---:|---:|---:|---:|---:|---|
| SQLi | 35,274 | 35,274 | 34,924 | 0 | 350 | ACCOUNTING_VALID |
| XSS | 191,848 | 191,848 | 189,076 | 0 | 2,772 | ACCOUNTING_VALID |
| Brute Force (held-out) | 1,108,658 | 1,108,571 | 1,101,372 | 0 | 7,199 | ACCOUNTING_PARTIAL (87 frames, 0.0078%) |

The SQLi row is reproduced from `REPLAY_ACCOUNTING_VALIDATION.md` and is not
re-derived here.
