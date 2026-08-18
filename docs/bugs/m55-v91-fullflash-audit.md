# Siemens M55 v91 full-flash audit

Final audit date: 2026-08-17.

## Summary

The primary C166/TASKING Large defects found during the first pass were fixed
in the module and confirmed by reanalyzing the saved real-world database:

- the far-indirect dispatcher receives the `call_far_indirect` injection;
- integer and floating-point runtime helpers receive ABI models;
- far data pointers and far function pointers are no longer conflated;
- returned far data pointers are reconstructed in `R5:R4`;
- a single data value that happens to match a function entry point no longer
  contaminates callers through interprocedural function-pointer forwarding;
- variadic calls such as `snprintf` receive the correct argument layout.

After the fixes, 28,339 of 28,431 functions decompile successfully (99.68%).
The remaining 92 failures do not indicate a new regression in the C166 module
or `ghidra-patched`: representative failures reproduce with the official
upstream decompiler, including after analyzer-generated parameters are
removed. They should be tracked separately as generic decompiler or false-flow
problems.

## Target and methodology

- Image: `/home/azq2/Documents/Siemens/egold/M55_v91.bin`.
- SHA-256: `6abf9f1e77a89edc76d29e49b0bbaad979db74bc887108d45f7d72deacf04db1`.
- Size: 14 MiB, mapped at `0x200000..0xffffff`.
- Language ID: `C166:LE:16:tasking-classic-large`.
- Compiler spec: `tasking-classic-large`.
- Ghidra: 12.1.2 DEV with the current C166 module installed locally.
- ABI: TASKING Classic Large, tables 3-14 and 3-15 in
  `ST10 C Cross-Compiler User's Manual.pdf`.
- Saved verification project: `/tmp/c166-m55-fresh.xtRvYd/M55Fresh.gpr`.

A full Auto Analysis pass was run on a fresh project. After applying the fixes,
the following sequence was run on the same saved database:

```text
C166TaskingRuntimeAnalyzer
C166CodePointerPhase
C166FarPointerPhase
C166CodePointerPhase
C166PointerReturnPhase
```

`C166FullFlashDecompilerAudit.java` then decompiled every function with a
15-second timeout and collected warnings and characteristic artifacts. The
complete final pass took 466 seconds.

## Final figures

| Category | First pass | Final pass | Assessment |
|---|---:|---:|---|
| Total functions in inventory | 28,490 | 28,431 | saved database was cleared of false functions and stale state |
| Successfully decompiled | 28,387 | 28,339 | 99.68% of the current set |
| Hard error or timeout | 103 | 92 | improvement; remainder is mostly upstream core/flow behavior |
| Split global pointer | 15 | 9 | substantially reduced |
| `extraout_RH4/RL4` occurrence | 104 | 95 | heuristic conflates char returns with arbitrary extraout uses |
| Pointer built from `extraout`/`unaff` | 507 | 358 | substantially reduced |
| Unmapped formal variable | 270 | 264 | generic decompiler warning, not necessarily an ABI error |
| Unrecovered control flow/jump table | 90 | 90 | unchanged |
| `halt_baddata`/`code_r0x`/`BADSPACEBASE` | 57 | 58 | mostly false or incomplete flow |
| Pointer built from `CONCAT`/`ZEXT` | 200 | 221 | broad heuristic; includes valid near/byte operations |
| Manual extraction of a global pointer's high word | 197 | 210 | broad heuristic, not proof of a defect |
| Overlapping globals warning | 6,618 | 6,615 | normal overlay symbols of different widths |
| Call-fixup injection warning | 265 | 2,542 | expected increase: runtime and dispatcher fixups are now applied |

The first-pass and final-pass values are not a strict benchmark because the set
of automatically created functions changed after the fixes. They remain useful
as a directional comparison and as a list of concrete addresses for retesting.

## Confirmed fixes

### 1. Far-indirect dispatcher and runtime helpers

`FUN_a26154` is recognized from its strict `push r5; push r4; rets`
implementation, receives `call_far_indirect`, and is not analyzed as an
ordinary C function with parameters in `R12..R15`.

The runtime helpers `FUN_f5fec6`, `FUN_f5ff60`, and `FUN_f65ade` receive exact
models for 32-bit multiplication, division, and remainder. This removed the
previous pointer over-inference and allowed `FUN_217328`, which failed during
the first pass, to decompile.

The final real-program runtime pass reported two recognized dispatchers and
raised no exceptions while traversing the complete database.

### 2. Far-pointer returns in `R5:R4`

Under the TASKING ABI, a far data pointer is returned as the page offset in
`R4` and the page number in `R5`. Return inference now checks subsequent data
use, conflicts with far-indirect code use, and preservation of the pair through
ABI-preserved registers.

The real headless regression confirmed that:

- `FUN_9bb936` returns a data pointer in `R5:R4`;
- `FUN_9b0678` returns a data pointer in `R5:R4`;
- `FUN_2590ce` returns a data pointer in `R5:R4`;
- split-return cast and `CONCAT` artifacts are gone from `FUN_242066` and
  `FUN_259214`.

### 3. False function-pointer propagation

In the fresh database, `FUN_9bc42a` incorrectly received four `fpointer`
parameters even though its first two parameters are object data pointers and
only the last two are allocator callbacks.

Diagnostics identified the exact chain:

```text
one call to FUN_9ab3d0
  slot 4: 0x25:0x3d0e -> FUN_253d0e
  slot 6: 0x25:0x3d7c -> FUN_253d7c
          |
          v
false trusted root on FUN_9ab3d0
          |
          v
semantic forwarding into slots 0/2 of FUN_9bc42a
```

For `FUN_9bc42a`, genuine direct code evidence existed only for stack slots
4/6, with 56 and 57 call-site occurrences respectively. Slots 0/2 appeared
solely through forwarding from the two one-off coincidences in `FUN_9ab3d0`.

A single exact-entry constant is now sufficient for a local callee type, but it
is not a root for reverse interprocedural propagation. Forwarding requires
repeated exact-entry occurrences, an actual far-indirect use, or an
authoritative USER_DEFINED/IMPORTED callback type.

On the saved contaminated database, the first code-pointer pass removed 177
unsubstantiated stale `fpointer` types; the propagated count fell from 294 to
87. After the complete cycle, the signature is:

```c
FUN_9bc42a(void *object1, void *object2,
           fpointer alloc_cb, fpointer free_cb)
```

### 4. PAGE:OFFSET and variadic calls

Register-mode `EXTP` is now recognized even when it has a composite operand, so
the page and offset are associated with one far data pointer. The previously
failing `FUN_c35672` is no longer in the decompilation failure list.

`FUN_747f44` and its `snprintf` call are covered by a real headless test: the
format pointer and variadic stack arguments no longer displace each other, and
the isolated `strlen` is not a lost call argument.

## Remaining classes

### 1. The 92 decompilation failures

The remainder contains several distinct classes:

- `Symbol $$undef... extends beyond the end of the address space`;
- `Overlapping input varnodes`;
- branches into undefined, uninitialized, or out-of-range memory;
- one timeout in `FUN_750de0`, whose body resembles a false function in data.

`FUN_224334` fails with `$$undef00000006` in exactly the same way with both the
current patched decompiler and the official Ghidra 12.1.2 PUBLIC decompiler.

`FUN_3f324e` also fails with `Overlapping input varnodes` in both decompilers.
Its storage map itself contains no overlap:

```text
R13:R12, R14, R15, Stack[0]:2, Stack[2]:2
```

Trying an ABI-correct `Stack[0]:4` pair, and then removing all formal
parameters, did not eliminate the core error; without parameters it changed to
`$$undef`. A pointer-analyzer fix therefore cannot solve this case. No core
workaround was added: it would require a separate minimal reproducer and strict
architecture gating, otherwise the risk to ARM and other architectures would
be unjustified.

### 2. `extraout_RH4` is not a split far-pointer return counter

This audit heuristic is too broad. For example, `FUN_376ec6` and `FUN_b2ed74`
clearly finish by writing `RL4`; under the ABI this is a `char` return, while an
unknown prototype makes the decompiler construct
`CONCAT11(extraout_RH4, RL4)`. In `FUN_9fc000`, `extraout_RH4` is instead a
value left after a low-level call or interrupt-like flow inside a `void`
function.

The remaining 95 matches therefore cannot be automatically converted into
pointer returns. A safe, separate follow-up project would be conservative
byte-return inference over all exit paths and caller uses, checked against the
ABI rule `char -> RL4`.

### 3. Nine split-global-pointer matches

Some are genuine PAGE:OFFSET expressions that the decompiler displays in
parts but computes correctly. `FUN_252a94` illustrates a more complex case:
internal decompiler prototype recovery prints more stack words than the saved
seven-parameter signature of `FUN_370ffe`. The function still decompiles, and
`FUN_370ffe` already has far-pointer parameters.

This is not grounds for forcibly changing the type: different branches use the
values differently, and a broad heuristic would create new data/function
pointer false positives.

### 4. Warnings that are not standalone defects

- The 6,615 overlapping globals are expected `_DAT_*` symbols over `DAT_*`
  symbols of different widths in the same physical RAM.
- The 2,542 call-fixup injection warnings confirm that the dispatcher and
  runtime models are being applied.
- Most `warning-other` entries are `Removing unreachable block`, `Treating
  indirect jump as call`, and `Type propagation algorithm not settling`; they
  are an inventory for manual control-flow analysis, not proof of an ABI bug.
- The 264 unmapped-formal warnings require case-by-case review. Parameters
  cannot be removed in bulk because many are register-bank placeholders before
  genuine TASKING ABI stack arguments.

## Verification

The following checks were run:

```text
./tools/test-tasking-abi.sh
/opt/ghidra/support/analyzeHeadless ... C166M55CodePointerHeadlessTest.java
/opt/ghidra/support/analyzeHeadless ... C166M55FarPointerMigrationHeadlessTest.java
/opt/ghidra/support/analyzeHeadless ... C166M55ReturnPointerHeadlessTest.java
/opt/ghidra/support/analyzeHeadless ... C166M55TaskingRuntimeHeadlessTest.java
/opt/ghidra/support/analyzeHeadless ... C166M55VariadicHeadlessTest.java
/opt/ghidra/support/analyzeHeadless ... C166FullFlashDecompilerAudit.java
./tools/test-patched-decompiler.sh
./install-local.sh
```

At the time of this audit, the synthetic suite passed for:

- `C166:LE:16:tasking-classic-large`;
- `C166:CS:LE:16:tasking-classic-large`;
- the legacy `C166:LE:16:default:tasking` control.

A new negative test verifies that one exact function entry retains a local
callback type without converting the wrapper's data pointer into `fpointer`.
The complete real M55 regression was rerun read-only with the final locally
installed build. The original full-analysis result remains saved in the
headless project.
