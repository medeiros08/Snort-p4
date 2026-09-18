# Vendored reference corpus

Gerado por `scripts/fetch_reference_docs.sh` em 2026-09-18T19:31:30Z.

O corpus em si nao e versionado (regeneravel). Este manifesto e,
porque fixa o commit de onde cada citacao de documentacao saiu.

Os pins reproduzem o toolchain da secao de metodologia — Snort++
3.12.2.0, p4c 1.2.4.2 (SHA 624c6be80), simple_switch_grpc 1.15.0
(build 68f4a978) — e nao o branch default de cada projeto, que esta
a frente do ambiente avaliado.

| Fonte | Pin | Commit resolvido | Data do commit | Arvores | Por que este ref |
|---|---|---|---|---|---|
| [snort3](https://github.com/snort3/snort3.git) | `3.12.2.0` | `14aeb09f5a08` | 2026-04-23T14:38:57-04:00 | `doc` | tag da versao 3.12.2.0 validada no rig |
| [p4-spec](https://github.com/p4lang/p4-spec.git) | `P4-16-v1.2.4` | `6536ac447522` | 2023-05-15T21:38:36-04:00 | `p4-16/spec` | ultimo release de spec anterior ao build do p4c |
| [p4c](https://github.com/p4lang/p4c.git) | `624c6be8076881e9af1e2f7d7691bc6c4416f4b1` | `624c6be80768` | 2023-08-09T00:19:28-04:00 | `p4include docs` | build exato do p4c 1.2.4.2 do rig |
| [bmv2](https://github.com/p4lang/behavioral-model.git) | `68f4a978f465fd76e98fcdecb762981843fb7310` | `68f4a978f465` | 2025-09-25T16:04:07-05:00 | `docs targets/simple_switch` | build exato do simple_switch_grpc 1.15.0 do rig |
| [p4runtime](https://github.com/p4lang/p4runtime.git) | `v1.4.1` | `36e8b46e4065` | 2024-10-21T13:39:17-07:00 | `docs/v1 proto` | ultimo release anterior ao build do BMv2 |
