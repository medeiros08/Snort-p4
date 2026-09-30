# Replay Validation on the Corrected Data Plane

## 1. Purpose and status

Two data-plane measurements were still missing after the IPv4 packet-domain
correction of 2026-09-01 (`CODEX_HANDOFF.md` §15, item 3):

1. **Alert packets.** The P4 columns of the alert-preservation table were
   measured on BMv2 only with the pre-correction program, and sent with
   Scapy's `sendp`.
2. **Brute Force window.** The frame-exact replay of the full held-out window
   was `ACCOUNTING_PARTIAL`: 87 of 1,108,658 frames never reached the switch
   (`../ipv4_packet_domain_correction/REPLAY_ACCOUNTING_VALIDATION_XSS_BRUTEFORCE.md`).

Both were run on the rig with the corrected program. **All four
measurements are `ACCOUNTING_VALID`:**

- every frame sent was counted by the switch;
- each category equals the offline classifier value;
- the idle audits saw no traffic.

**This supersedes:**

- the `ACCOUNTING_PARTIAL` status of the Brute Force window;
- the qualification that the alert-packet P4 columns were measured only
  before the packet-domain gate.

The earlier documents and their data are kept unchanged.

## 2. Protocol

Script: `scripts/rig_replay_pos_correcao.sh`. It follows `CODEX_HANDOFF.md`
§11, the protocol under which SQLi and XSS reconciled. For each measurement:

1. **Fresh switch.** `scripts/setup_bmv2.sh down` and `up`, with
   `output/ids_prefilter.json`.
2. **Larger queues.** `txqueuelen` 10000 on the four veth.
3. **Plan installed.** `compiler/install_p4runtime.py` installs the
   331-entry plan and zeroes the counters: 331 entries written, 331 read
   back in every run.
4. **Idle audit.** Counters read at t0 and t1, 10 s apart.
5. **Replay.** Counters read before; the captured bytes replayed with
   `tests/replay_pcap_raw.py` (AF_PACKET, no reserialization) into `veth1`;
   10 s for the switch to drain; counters read after.

Two settings differ from the earlier Brute Force run, and both target the
earlier diagnosis of queue-level drops at about 789 frames/s:

- `txqueuelen` raised from 1000 to 10000;
- a 2 ms inter-frame delay. The window took 2,985 s of sender time, about
  371 frames/s.

Accounting: `tests/analyze_replay_pos_correcao.py`, run on the Windows
machine, reads only deltas and checks

    frames sent == P4_CANDIDATE + P4_NO_MATCH + PACKET_DOMAIN_FALLBACK

It then compares each category with the offline classifier. The result is
in `resultado.json`.

## 3. Inputs

| Artifact | sha256 |
|---|---|
| `output/ids_prefilter.json` (corrected program) | `f5167adc69e8ae053d4496a7b3a17715aff0e483c6d7aa27aadd13c99f005992` |
| `output/ids_prefilter.p4info.txt` | `0d60057afb6f34e904f7b8fb2f0a1d6af3e8b2959fedfdadeea9b6916acdf6f4` |
| `output/p4runtime_install_plan.json` (331 entries) | `d75589838c41d6d6a0d6bbd6a381c2f14b9bc9c0dfd156836f536cd541347939` |
| SQLi candidate-alert packets | `c36ded14ad9b04b9c423016681660e10882b027dbca027a2354b5a4aa26d28c0` |
| XSS candidate-alert packets | `f61950609991ebe20bf525981ea987144e02c9893dfe7aeef54b1eb59ef4ab30` |
| Brute Force candidate-alert packets | `ed00df639af5e83d215e20cde9d5d77ddb1b7056884de555fa638856a0ece830` |
| Brute Force window, `thursday_web_bruteforce.pcap` | `c41480e5d9494ab56325c9b53d23301b0c182230ee1cf6af50f5489010d5edeb` |

- **Program.** It is the post-correction program named in
  `output/profiles/SUPERSESSION_NOTICE.md`.
- **Alert-packet pcaps.** They are the same files used by the offline
  rederivation (`../alert_preservation_offline_post_correction.json`).
- **Brute Force window.** It was cut on this machine by
  `tests/cut_cicids2017_windows.py`. The cut record
  (`output/datasets/cicids2017_windows_offline_cut.json`) matches the
  dataset record: 1,108,658 packets, 1,196,560,691 captured bytes, same
  first and last timestamps.

## 4. Results

| Measurement | Frames sent | Counted | Candidate | No-match | Fallback | Offline expected (cand. / no-match / fallback) | Status |
|---|---:|---:|---:|---:|---:|---|---|
| SQLi alert packets | 150 | 150 | 150 | 0 | 0 | 150 / 0 / 0 | ACCOUNTING_VALID |
| XSS alert packets | 528 | 528 | 528 | 0 | 0 | 528 / 0 / 0 | ACCOUNTING_VALID |
| Brute Force alert packets | 2,391 | 2,391 | 2,391 | 0 | 0 | 2,391 / 0 / 0 | ACCOUNTING_VALID |
| Brute Force window | 1,108,658 | 1,108,658 | 1,101,459 | 0 | 7,199 | 1,101,459 / 0 / 7,199 | ACCOUNTING_VALID |

All four idle audits had a zero delta on the three indices.

### Replay status across all runs

| Window | Replay | Status |
|---|---|---|
| SQLi | full window, earlier run | ACCOUNTING_VALID |
| XSS | full window, earlier run | ACCOUNTING_VALID |
| Brute Force | full window, this run | **ACCOUNTING_VALID** (was ACCOUNTING_PARTIAL) |
| SQLi, XSS, Brute Force | alert packets on the corrected program, this run | ACCOUNTING_VALID |

## 5. Caveats

- **Timestamps.** The `gerado_em` values in each `ambiente.txt` come from
  the WSL clock, which lagged real time when the runs started (it reported
  2026-09-29 for runs made on 2026-09-30). They do not order these runs
  against other artifacts; the hashes above identify the inputs.
- **Pauses.** The WSL virtual machine paused at least once during the
  Brute Force window: the sender's elapsed time is 2,985 s, far less than
  the wall-clock span. The sender and the switch pause together, and the
  accounting is exact, so the pause did not affect the counts.
- **No tcpdump.** No capture ran during these measurements. The counter
  deltas are the primary evidence, as in the earlier documents.
