# Appendix Profile Audit

## Scope

Only the `Experimental Snort Variable Profile` appendix in `main.tex` was
replaced. No experiment, source code, frozen result, or other manuscript
section was changed.

## Active Profile and Cross-Check

The active profile is `cicids2017`.

| File | Cross-check result |
|---|---|
| `config/active_profile.json` | Identifies `cicids2017`, `HOME_NET=192.168.10.0/24`, the profile source, generated variable file, generated Snort configuration, and `snort_default_file_magic_disabled=true`. |
| `config/profiles/cicids2017.json` | Defines the documented network and port variables. |
| `config/snort_variables.json` | Matches every profile variable and value. |
| `config/snort3_experiment.lua` | Is generated for `cicids2017`; sets the same network/port values and applies `file_inspect = { }` after including the standard Snort configuration. |

All cross-checked values are consistent; no profile divergence was found.

## Variables Documented

The appendix table records the exact frozen names and values for:

- `HOME_NET`, `EXTERNAL_NET`, `HTTP_SERVERS`, `SQL_SERVERS`,
  `SMTP_SERVERS`, `TELNET_SERVERS`, and `SIP_SERVERS`;
- `HTTP_PORTS`, `ORACLE_PORTS`, `FILE_DATA_PORTS`, `SIP_PORTS`,
  `SSH_PORTS`, and `FTP_PORTS`.

It identifies the profile JSON, resolved variables JSON, generated Snort Lua
configuration, and the 4,017-rule evaluation scope.

## Qualification Added

The appendix states that this is an experimental profile, not an official
canonical Snort configuration. It also states that semantic classification and
selectivity measurements depend on the network and service-port definitions,
with a cross-reference in meaning to the threats-to-validity discussion.

## `file_magic` Status

`config/active_profile.json` records
`snort_default_file_magic_disabled=true`. The generated
`config/snort3_experiment.lua` includes standard `snort.lua` and immediately
sets `file_inspect = { }`, with an explicit comment that this prevents loading
the default `file_magic.rules`. The appendix records this isolation and the
resulting intended 4,017-community-rule ruleset scope.

## Methodology Cross-Reference

The Experimental Methodology retains the valid reference
`Appendix~\ref{app:snort-profile}`. The appendix label remains
`app:snort-profile`.

## Reproducibility Issue Remaining

The profile itself is now documented. The remaining manuscript-level task is
to compile with an available LaTeX toolchain; no `pdflatex` executable is
available in the current environment.
