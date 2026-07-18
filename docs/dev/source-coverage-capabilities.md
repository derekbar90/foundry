# Source coverage capability matrix

This document records the first supported boundary for `forge coverage --instrument-source`.
Unsupported selected inputs fail the command unless the user explicitly passes `--allow-partial`.

| Surface | Status | Behavior |
| --- | --- | --- |
| Solidity 0.8.0 and newer | Supported | Rewritten after compiler-version and import resolution. |
| Solidity before 0.8.0 | Partial only | Left unchanged and reported as an unsupported compiler input. |
| Vyper | Partial only | Never passed to the Solidity parser or rewriter. |
| Standalone Yul | Partial only | Never receives Solidity syntax. |
| Inline assembly/Yul | Partial only | Solidity around the block is preserved; Yul inventory items are reported incomplete. |
| Optimizer | Supported | The pure probe call remains observable by the EVM inspector. |
| `viaIR` / `--ir-minimum` | Supported | Instrumented resolved inputs retain the requested compiler pipeline. |
| `pure` and `view` functions/modifiers | Supported | Probe interfaces are declared `pure`; source mutability is not changed. |
| `if` / `else` | Supported | Condition evaluation is preserved and branch entries are collected. |
| `for`, `while`, and `do/while` | Supported | Unbraced bodies are wrapped; `for` updates are lowered with targeted `continue` handling. |
| `require` | Supported | A boolean-returning probe preserves short-circuit evaluation and the original value. |
| `try` / `catch` | Supported | Attempt and entered-clause probes map to canonical items. |
| Multiple modifier placeholders | Supported | No placeholder or function mutability is removed. |
| Table, fuzz, and invariant execution | Supported | Source hits merge through every existing result path. |

The runtime protocol is internal and fixed to:

- `coverageHit(bytes32)` for function and statement entry.
- `coverageBranch(bytes32,bytes32,bool) returns (bool)` for value-preserving boolean probes.
- Exact-length, canonical ABI decoding; malformed and unknown IDs are ignored without mutation or
  panic.

Probe IDs are namespaced by a digest of the resolved compiler input and normalized logical source
path. Compiler-assigned source IDs are report-local only and are not used as cross-job identity.

Canonical analysis also emits typed `ProbeSite` metadata for every instrumentable inventory item.
The source rewriter claims those exact sites and registers their canonical item IDs directly; it
does not create a second inventory or infer execution from containing source ranges. Unclaimed
sites make the report partial.

`for` update expressions are lowered into statement position at normal body fallthrough and at
continues targeting that loop. This preserves void- and tuple-valued updates, while breaks, returns,
and reverts continue to skip the update. Typed empty catch clauses receive statement-entry probes.

Partial coverage can only be emitted through the summary and debug reporters. LCOV and bytecode
reporters reject partial input before tests run because those formats cannot represent omitted or
unsupported source inputs.
