# TASKING Classic Large nested-call, return, and variadic inference

Date: 2026-08-18.

Status: implemented and verified with generic synthetic tests and a disposable
copy of the real program database.

## User-visible failure

Before the fix, M55 v91 `FUN_3c32dc` decompiled with three related ABI
failures:

```c
uVar1 = FUN_39b5a4(param_1);
__s = FUN_39bcf8(CONCAT22(extraout_r5 +
    (uint)(0xfffb < CONCAT11(extraout_RH4,uVar1)),
    CONCAT11(extraout_RH4,uVar1) + 4), "apmms_bws/mms_dv.c");
sprintf(__s, "%s%03d", (char *)param_1,
    (char *)((ulong)param_1 >> 0x10));
return (char)__s;
```

The listing proves the intended TASKING Classic Large ABI data flow:

- `FUN_39b5a4` returns a 32-bit scalar in `R5:R4`; it zero-extends the
  16-bit `strlen` result by assigning zero to `R5`.
- The caller adds four to that scalar with `add R12,#4` and `addc R13,#0`.
- `FUN_39bcf8` receives that 32-bit size in `R13:R12`, a far source-file
  pointer in `R15:R14`, and the line number `0x52c` on the user stack.
- Before `sprintf`, the original far `param_1` saved in the callee-preserved
  pair `R7:R6` is pushed as one four-byte optional argument. The 16-bit
  `param_2` is pushed after it as a separate optional argument.
- `FUN_3c32dc` returns the far allocation pointer in `R5:R4`.

The expected result is equivalent to:

```c
char *FUN_3c32dc(char *name, int id)
{
    char *s = FUN_39bcf8(FUN_39b5a4(name) + 4,
        "apmms_bws/mms_dv.c", 0x52c);
    if (s != NULL) {
        sprintf(s, "%s%03d", name, id);
    }
    return s;
}
```

The names are illustrative. In the TASKING C166 ABI, `int` is 16 bits.

## ABI contract

The normative source is:

`/home/azq2/Documents/DIY/Siemens/C166/ST10 C Cross-Compiler User's Manual.pdf`

Tables 3-14 and 3-15 define the rules used here:

- `R0` is the user stack pointer;
- `R1-R5`, `R10`, and `R11` are caller-clobbered temporary/return registers;
- `R6-R9` are callee-preserved C register variables;
- `R12-R15` carry fast parameters;
- `long` and `float` return in `R5:R4`, low word first;
- far and huge pointers also return in `R5:R4`, offset first;
- a far pointer cannot therefore be inferred from pair width alone.

The implementation remains gated exclusively by the
`c166.abi=tasking-classic-large` processor property. It must not change any
non-C166 or non-TASKING program.

## Root causes

### Stack recovery stops at every call

`C166TaskingCallArguments` scans backward from a call and currently stops at
an intervening call. TASKING permits an outer call argument to remain on the
user stack while inner calls compute later register arguments. In
`FUN_3c32dc`, the line number for `FUN_39bcf8` is pushed before the nested call
to `FUN_39b5a4`, so the existing scan loses it.

The correct boundary is the exact number of words removed by the target
call's immediate `add R0,#bytes`. Backward recovery must model balanced stack
effects, cross calls without treating them as stack writes, and reject paths
containing an unknown or unbalanced `R0` mutation.

### Return inference handles pointers but not 32-bit scalars

`C166PointerReturnPhase` tracks `R5:R4` only to typed pointer formals and paged
memory operations. It has no positive scalar evidence. Consequently
`FUN_39b5a4` retains an undersized return type and Ghidra invents
`extraout_RH4` and `extraout_r5` for the remaining bits.

Return inference must classify the shared ABI pair from semantic uses:

- a concrete function-pointer formal or far-indirect dispatch is code-pointer
  evidence;
- a concrete data-pointer formal or paged memory access is data-pointer
  evidence;
- a concrete four-byte non-pointer formal or paired 32-bit arithmetic is
  scalar evidence;
- conflicting categories leave the signature unchanged and emit a console
  diagnostic;
- `USER_DEFINED` and `IMPORTED` signatures are never overwritten.

Unknown signedness remains `undefined4`; the analyzer must not invent `long`,
`unsigned long`, or `float` without separate evidence.

### Variadic recovery loses incoming far-pointer identity

Cleanup proves that the `sprintf` call has three optional stack words, but the
setup fallback recognizes a pointer only when the two words are adjacent
direct memory loads. It does not retain the identity of an incoming typed far
pointer copied into `R6:R7`, kept across calls, and later pushed.

Each recovered word must retain a semantic origin: typed source object or
formal parameter, source byte offset, and pointer type where known. Adjacent
words may be joined only when they are offsets 0 and 2 of the same four-byte
pointer origin. Adjacent unrelated scalars remain separate words.

## Implementation plan

1. Replace the call barrier in stack argument recovery with a bounded,
   balanced `R0` model driven by exact caller cleanup.
2. Extend `R5:R4` return tracing into a three-way code/data/scalar evidence
   classifier and make the update conservative under ambiguity.
3. Preserve typed four-byte origins while tracing register copies, including
   incoming parameters kept in `R6-R9`, and use those origins when grouping
   optional stack words.
4. Run return classification to a bounded fixed point inside the single
   scheduler-visible TASKING analyzer so one corrected signature can inform
   downstream callers in the same analysis run.
5. Rebuild stale analyzer-owned variadic overrides when their word layout does
   not match the recovered semantic grouping; a second run must be a no-op.
6. Keep every change in the C166 module and behind
   `C166ArchitectureProfile.isTaskingClassicLarge` unless a genuine generic
   Ghidra defect is independently proven.

## Strong test specification

### Synthetic positive fixtures

1. Reproduce the complete `FUN_3c32dc` call shape: push an outer stack
   argument, execute an inner call, prepare `R12-R15`, execute the outer call,
   and clean exactly one word. Assert that the outer callee gains the third
   parameter and the push is not lost.
2. Return a zero-extended 16-bit value in `R5:R4`; copy it to another pair,
   apply `add/addc`, and pass it to a typed four-byte scalar formal. Assert an
   `undefined4` return and no pointer type.
3. Return `R5:R4` and consume it as a typed data pointer. Assert a four-byte
   data-pointer return and no scalar classification.
4. Return `R5:R4` and use it as an exact far-indirect target. Assert an
   `fpointer` classification and no data/scalar classification.
5. Copy an incoming typed far pointer to `R6:R7`, cross an intervening call,
   push both words, push one independent scalar, and call a typed variadic
   function. Assert one four-byte pointer optional argument followed by one
   two-byte scalar argument.
6. Run the complete coordinator once and assert decompiled C has no split
   PAGE/OFFSET arguments, `CONCAT` reconstruction, or `extraout_RH4/R5` for
   the fixture.

### Synthetic negative and ambiguity fixtures

1. Put an unknown write to `R0`, an unmatched cleanup, or a control-flow merge
   between a push and a call. Assert that no stack argument is recovered.
2. Put a complete nested call frame and cleanup between the target push and
   target call. Assert that only the still-live target word is recovered.
3. Put saved-register pushes below the exact target argument count. Assert
   that prologue/local saves are never classified as arguments.
4. Push two adjacent independent 16-bit scalars, including values that happen
   to form a valid RAM or function address. Assert that they remain scalars.
5. Feed the same returned pair to both a data-pointer and scalar consumer, or
   to both data and code consumers. Assert no inferred return type and one
   console-only conflict report.
6. Give the producer only `R4`, or make one return path omit `R5`. Assert that
   the analyzer does not widen the return merely because callers expose an
   `extraout` register.
7. Mark a conflicting signature `USER_DEFINED` and `IMPORTED`. Assert byte-for-
   byte signature preservation.

### Idempotence and stale-state fixtures

1. Seed an analyzer-owned word-wise variadic override, run the coordinator,
   and assert replacement by the semantic pointer/scalar layout.
2. Snapshot every affected function signature and prototype override, run the
   coordinator again, and assert that the snapshot is identical.
3. Run the internal code, data, return, and variadic phases again in different
   orders and assert that no proven classification is downgraded or flipped.

### Architecture controls

1. Run the same analyzer classes against a non-C166 language and a C166
   program without the TASKING Classic Large property. Assert `canAnalyze`
   is false and no signature, override, reference, or datatype changes.
2. Retain the existing ARM and x86 patched-Ghidra controls unchanged; this
   module-only fix must not require a Ghidra core patch.

### Real-program headless acceptance

Run against a disposable copy of the saved real database, not a hand-written
listing fragment:

1. Deliberately seed the currently broken `ANALYSIS` signatures and stale
   variadic override, then run the unified analyzer.
2. Assert `FUN_39b5a4` returns a four-byte non-pointer type.
3. Assert `FUN_39bcf8` has the register-pair size, far file pointer, and one
   16-bit stack line parameter.
4. Assert `FUN_3c32dc` takes one far pointer plus one 16-bit scalar and returns
   a far data pointer.
5. Assert its `sprintf` override contains exactly one far pointer optional
   argument followed by one 16-bit scalar.
6. Decompile all three functions and their representative caller. Reject
   `extraout_RH4`, `extraout_r5`, PAGE extraction from `param_1`, split pointer
   trials, missing line number, and `CONCAT`-based size reconstruction.
7. Re-run the analyzer and repeat the assertions to prove persistence and
   idempotence.

## Verification

- `./tools/test-tasking-abi.sh` passes for both TASKING Classic Large C166
  language variants. The generic nested-call fixture recovers the one live
  fixed stack word on the first pass and none on the idempotence pass.
- `GHIDRA_INSTALL_DIR=/opt/ghidra ./tools/test-patched-decompiler.sh` passes
  the C166 decompiler matrix and the unchanged x86-64 and ARM controls.
- `C166NestedCallInferenceHeadlessTest.java` passes against a disposable copy
  of the saved real program. It replaces the seeded `undefined6` variadic
  override, recovers two missing fixed stack words across the tested call
  graph, classifies the scalar and data-pointer returns, and makes no further
  signature or override changes on the second pass.
