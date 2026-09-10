# Snort 3 Language Support Matrix

This document records the relationship between the Snort 3 rule
language, the compiler intermediate representation, and the current
P4 backend.

The matrix distinguishes:

- validity in Snort 3;
- parsing support;
- semantic representation in the IR;
- backend capability;
- fallback behavior.

A construct being valid in Snort does not imply that it is directly
representable in P4.

---

## Status Legend

| Status | Meaning |
|---|---|
| SUPPORTED | Fully represented by the current component |
| PARTIAL | Only a subset is currently represented |
| DELEGATED | Preserved semantically but evaluated by Snort |
| EXPANDED | Compiled into multiple backend predicates/entries |
| FALLBACK | Cannot be represented safely by the current backend |
| UNSUPPORTED | Not yet implemented |
| OUT_OF_SCOPE | Explicitly outside the current prototype scope |

---

# 1. Rule Header Types

| Snort construct | Snort 3 | Parser / IR | P4 backend | Semantic treatment |
|---|---|---|---|---|
| Traditional rule | SUPPORTED | SUPPORTED | PARTIAL | PRESERVED / DELEGATED |
| Service rule | SUPPORTED | UNSUPPORTED | UNSUPPORTED | FALLBACK |
| File rule | SUPPORTED | UNSUPPORTED | UNSUPPORTED | FALLBACK |
| File identification rule | SUPPORTED | UNSUPPORTED | UNSUPPORTED | OUT_OF_SCOPE |

Traditional rule:

```text
action protocol src_ip src_port direction dst_ip dst_port