# SQLi AF_PACKET Replay Accounting Validation

## Status

**ACCOUNTING_VALID** for the corrected SQLi replay. This document records only
measurement reliability; it does not change P4 classification, policy, or the
frozen experimental configuration.

## Superseded attempt

The first post-correction SQLi attempt sent 35,274 frames, while absolute BMv2
counters read 34,924 `P4_CANDIDATE`, 0 `P4_NO_MATCH`, and 354
`PACKET_DOMAIN_FALLBACK` (35,278 total). Its `tcpdump` capture contained only
10,731 frames, with 64,822 received by the filter and 52,689 kernel drops.
That attempt is **INVALID / SUPERSEDED** for quantitative accounting.

The first sender failure (`EMSGSIZE`) was corrected at the measurement layer by
setting the four veth MTUs to 65,535. No frame contents or classifier semantics
were changed.

## Counter reset and idle audit

`compiler/install_p4runtime.py` uses `VERIFY_AND_COMMIT` followed by table
installation. A before/after check demonstrated that pipeline installation
reset all three indirect-counter indices to zero. The prior controlled tests
had exercised counters, so absolute values were not a valid replay metric.

All replay results therefore use counter deltas. A 10-second idle test after a
fresh installation observed a zero delta for candidate, no-match, and fallback.
The four extra fallback events in the invalid attempt are consequently
consistent with residual/out-of-window state, not SQLi classification.

## Small deterministic replay

The first 1,000 frames of the unchanged SQLi PCAP were replayed through
`tests/replay_pcap_raw.py --limit 1000 --inter 0.001`.

| Category | BMv2 delta | Offline classifier |
|---|---:|---:|
| P4_CANDIDATE | 977 | 977 |
| P4_NO_MATCH | 0 | 0 |
| PACKET_DOMAIN_FALLBACK | 23 | 23 |
| Total | 1,000 | 1,000 |

## Full SQLi replay

The complete unchanged SQLi trace was replayed after a fresh pipeline install
with counter deltas measured before and after the sender.

| Measure | Value |
|---|---:|
| Sender frames | 35,274 |
| BMv2 P4_CANDIDATE delta | 34,924 |
| BMv2 P4_NO_MATCH delta | 0 |
| BMv2 PACKET_DOMAIN_FALLBACK delta | 350 |
| BMv2 total delta | 35,274 |
| Offline selective-domain candidate | 34,924 |
| Offline no-match | 0 |
| Offline packet-domain fallback | 350 |

The total and every category agree exactly. This is the authoritative SQLi
replay accounting result.

## Capture observation

The replacement `tcpdump` used `-B 65536 -s 0 -U` and recorded 69,104 packets,
with 69,542 received by filter and zero kernel drops. It observes both sides of
the veth path and therefore is not a one-frame-per-sender-frame counter. Host
capture is retained as a secondary diagnostic only; AF_PACKET sender count and
BMv2 counter deltas are the primary accounting evidence.
