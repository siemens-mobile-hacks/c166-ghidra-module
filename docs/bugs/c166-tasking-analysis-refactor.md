# Systemic C166 TASKING Classic Large analysis refactor

Date: 2026-08-18.

Status: implemented; synthetic and real-M55 headless tests pass.

## Decision

The refactor was justified. The problem was not a single incorrect heuristic,
but the analysis architecture: several independently scheduled analyzers
modified the same `ANALYSIS` signatures, and the result of one pass became
input evidence for the next. Auto Analysis order, saved-database state, and a
second run could therefore change the classification of the same word pair
between a scalar, `void *`, and `fpointer`.

A separate addressing defect amplified the problem. DPP is an ordinary
architectural register, but some injectors read a persisted value from
`ProgramContext`. A stale constant-propagation result could consequently enter
new decompiler p-code after the code or analysis order had changed.

## Adopted architecture

### One explicitly selected ABI

The module supports only TASKING C166 Classic Large. Both supported processor
specifications declare:

```xml
<property key="c166.abi" value="tasking-classic-large"/>
```

`C166ArchitectureProfile` is the single profile check. Legacy and non-TASKING
languages were removed from `ldefs`, the build, and pattern constraints. The
analysis does not infer the ABI from the processor name, compiler ID, presence
of a userop, or properties of an already recovered prototype.

### One owner of automatic type inference

`C166TaskingTypeInferenceAnalyzer` is the only Ghidra-registered analyzer that
changes TASKING parameter types, return types, and variadic call-site
overrides. It executes a fixed sequence:

1. normalize ABI types;
2. bootstrap known variadic prototypes;
3. classify code pointers versus scalars;
4. classify far data pointers;
5. infer far-pointer returns;
6. finalize variadic call sites.

Specialized logic lives in ordinary `*Phase` classes that do not implement the
Ghidra `Analyzer` extension point. They do not appear in Auto Analysis and
cannot be enabled or scheduled independently. A headless test verifies this
with the real `ClassSearcher`, not only default-enable flags.

### Evidence priority

The following contract applies:

1. user-defined and imported signatures are not overwritten;
2. an actual word pair passed to a far-indirect call is strong code evidence;
3. an actual C166 paged load/store is strong data evidence and may repair only
   a generic analyzer-owned `fpointer`;
4. a packed 32-bit operation or an independent rectangle of word pairs is
   scalar evidence and prevents pointer inference;
5. a constant is code-pointer evidence only when it resolves exactly to the
   entry of an existing function, and only after scalar checks;
6. when evidence conflicts and neither side has stronger semantic proof, no
   type is guessed.

This removes circular reasoning of the form “the pair already has type
`fpointer`, therefore it is used as a code pointer.” Direct paged data use is
derived from the listing independently of the current `HighSymbol`.

### Unified C166 data-address formation

`C166PagedAddressEmitter` now emits p-code for direct operands,
register-plus-offset addressing, and switch-table loads:

- `EXTS` takes priority and preserves the full 16-bit offset;
- `EXTP` uses a 14-bit offset;
- the upper two bits of the logical address select the DPP register;
- when a function writes a DPP, `DPP0..DPP3` remains a live varnode in p-code;
- reset mapping `DPP0..DPP3 = 0,1,2,3` is used only when the function does not
  explicitly write the selected DPP;
- a persisted DPP value from `ProgramContext` is no longer a source of
  decompiler p-code.

`GetPagedOffset`, `RegOffsetAddr`, and `SwitchLoad` use the same emitter.
`C166AddressAnalyzer` no longer persists computed DPP values as long-lived
context that can contaminate a later analysis.

## Resolved real M55 v91 defects

### `FUN_34b662`

With `DPP0 = 0xb`, near operands `0x2c8` and `0x2cc` now resolve to
`0x02c2c8` and `0x02c2cc`. The `sys_open` call uses the mutable global far
pointer at `0x02c2cc:0x02c2ce`; the false flash constant `0xb1420` is gone.
The fourth argument remains the original stack object without mask
`0xffff3fff`.

### `FUN_34b230`

Stores to the near range `0x2c0..0x2d4` resolve to writable RAM at
`0x02c2c0..0x02c2d4`. The decompiler no longer reports writes to read-only
`0x0002c0..0x0002d4` or removes reachable blocks because of them.

### Auto Structure

`FUN_34b662` recovers the four-byte global far pointer at
`0x02c2c8:0x02c2ca`, and the Auto Structure GUI command works for every token
of the indexed variable. `FUN_9b4e9c` still recovers a structure of length
`0x44` with fields at offsets `0x40` and `0x42`.

## Regression strategy

- 119 synthetic functions cover positive, negative, ambiguous,
  scalar/data/function, and forwarding cases;
- after the unified pass, code and data phases are run separately and the full
  analysis is repeated; the signature snapshot must remain unchanged;
- the direct-DPP test contains deliberately stale `ProgramContext` and verifies
  that live `mov DPP0,#0xb` still selects `0x02c2cc`;
- deliberately stale simultaneous EXTS/EXTP context verifies the common
  EXTS-first override contract in every address-formation path;
- a switch test verifies that `mov r4,[r4]; jmpi [r4]` retains live `DPP1` in
  injected p-code;
- the complete suite runs for C167CR and C167CS;
- the real-M55 test runs headless against a read-only saved database and checks
  `FUN_34b230`, `FUN_34b662`, `FUN_9b4e9c`, and the GUI-command path;
- patched-Ghidra x86-64 and ARM controls must preserve upstream Auto Structure
  behavior.

## Implementation limitation

The internal phases have not been rewritten as pure immutable collectors with
one atomic signature commit. Instead, their mutations are enclosed by one
scheduler-visible coordinator, a fixed priority order, and an idempotence test.
This is substantially less risky than rewriting several thousand lines of
decompiler tracing at once and already removes the observed order dependency.
A separate evidence ledger should be introduced only for a new confirmed class
of conflicts and only with real-firmware fixtures.
