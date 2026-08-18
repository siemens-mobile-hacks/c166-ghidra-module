# M55 v91: 32-bit scalar pairs misclassified as `fpointer`

Investigation date: 2026-08-17.

Status: fixed in the C166 module and verified by a complete headless run against
the real M55 v91 database. No Ghidra core changes were required.

## Summary

Several ordinary 32-bit integer arguments in M55 v91 were assigned the
`fpointer` type. This was not merely cosmetic: the false type changed the ABI
layout of formal parameters, shifted the register/stack boundary, and damaged
the decompiler's data flow.

At least three cases were confirmed:

- two stack arguments of `FUN_26cee4` are 32-bit scalar values, not callbacks;
- the offset and length in `FUN_26cd1c` were incorrectly represented as
  `fpointer`;
- the sole argument of the allocation wrapper `FUN_c58cb6` is a 32-bit size,
  despite being stored as `fpointer`. The function has at least 100 call xrefs
  shown by MCP, so the defect affected a large amount of decompiled output.

The common pattern is that two 16-bit words form one 32-bit value that happens
to equal the start address of an existing function. Exact-entry evidence was
incorrectly allowed to outweigh evidence of scalar use.

## Verification context

- Program: `M55_v91.bin`.
- Open Ghidra object: `/Siemens/EGOLD/M55_v91.bin`.
- Language/compiler: C166, TASKING Classic Large Memory Model.
- Primary function investigated: `FUN_26cee4` at `0x26cee4`.
- Method: saved signatures, decompilation, listing, and call xrefs were checked
  in the current GUI database through MCP.
- ABI source used for the subsequent fix:
  `/home/azq2/Documents/DIY/Siemens/C166/ST10 C Cross-Compiler User's Manual.pdf`.

The initial state was recorded without modifying the database. After the fix
was implemented, the test reproduced the same defective signatures before
running the analyzers; the verification results are documented below.

## Defect 1: `FUN_26cee4`

### Saved signature

```c
undefined1 __tasking_c166_classic FUN_26cee4(
    undefined2 param_1,
    undefined2 param_2,
    undefined2 param_3,
    undefined2 param_4,
    fpointer param_5,
    fpointer param_6);
```

This describes four 16-bit parameters and two function pointers. The listing
at every inspected call site shows a different physical layout:

| Argument | Storage | Observed form |
|---|---|---|
| 1 | `R12` | 16-bit scalar |
| 2 | `R13` | 16-bit scalar |
| 3 | `R14` | 16-bit scalar |
| 4 | `Stack[0]:4` | 32-bit scalar |
| 5 | `Stack[4]:4` | 32-bit scalar |

After three register words, the next four-byte argument cannot fit entirely in
`R15`, so the TASKING ABI places it on the stack. `R15` is an unused hole in
this layout, not a separate `param_4`.

### Recursive call

In the range `0x26d052..0x26d074`, the function pushes two word pairs, sets
`R12`, `R13`, and `R14`, calls itself, and then releases eight bytes:

```asm
mov  r7,[r0+#0x9e]
mov  r13,[r0+#0xa0]
mov  [-r0],r13
mov  [-r0],r7
mov  r14,[r0+#0x9e]
mov  r15,[r0+#0xa0]
mov  [-r0],r15
mov  [-r0],r14
mov  r12,r6
mov  r13,r9
mov  r14,#2
calls FUN_26cee4
add  r0,#8
```

This is physically three register words followed by two 32-bit stack values.
Neither stack pair is called indirectly or used as a code address.

### Inspected external calls

Direct call xrefs are present at `0xc95dc4`, `0xc96456`, `0xc976f6`,
`0xc97918`, `0xc97a08`, `0xc97e60`, and `0xc97ee6`; the recursive call is at
`0x26d070`.

Representative setups include:

- before `0xc97918`, one local 32-bit pair and `0:0` are passed;
- before `0xc97ee6`, a 32-bit size and the value `4:0` are passed;
- before `0xc95dc4`, `0x10:0` and `0:0` are passed;
- before `0xc96456`, `R9:R8` and a zero-extended scalar field are passed.

Every call is followed by an eight-byte cleanup. The defective decompilation
turns these values into expressions such as `(fpointer)0x4`, `(fpointer)0x10`,
and `(fpointer)ZEXT24(...)`.

### Expected signature direction

Considering only the ABI and observed uses, the correct form should be close
to:

```c
undefined1 FUN_26cee4(int, int, int, uint32_t, uint32_t);
```

The names and signedness of the last two arguments are not established. The
essential requirement is that each remains one four-byte scalar rather than an
`fpointer` or two independent `undefined2` values.

## Defect 2: `FUN_26cd1c`

### Saved signature

```c
undefined1 __tasking_c166_classic FUN_26cd1c(
    undefined2 param_1,
    undefined2 param_2,
    fpointer param_3,
    void *param_4,
    fpointer param_5);
```

The wrapper code gives the parameters the following semantics:

- `param_3` is passed to the scalar `offset` parameter of `sys_lseek` and is a
  32-bit file offset in `R15:R14`;
- `param_4` is a genuine far data pointer to a buffer;
- `param_5` is a 32-bit stack length, not a function address.

The call at `0xc97e70..0xc97e90` pushes `4:0` as the length and the far address
of a local buffer, sets a zero offset in `R15:R14`, and releases eight bytes
after the call. The call at `0xc95dd4..0xc95df6` similarly passes `0x10:0` as
the length.

The correct semantic form is therefore closer to:

```c
undefined1 FUN_26cd1c(int fd_like, int arg,
                      uint32_t offset, void *buffer, uint32_t length);
```

Exact names, signedness, and any narrowing of the length inside the wrapper
require further investigation. The absence of function-pointer semantics is
already proven.

## Defect 3: `FUN_c58cb6`

### Saved signature

```c
undefined1 __tasking_c166_classic FUN_c58cb6(fpointer param_1);
```

The function saves `R13:R12`, sets `R14 = 0`, and forwards the original pair to
the allocator core `FUN_c58ce6`:

```asm
push  r8
push  r12
push  r13
mov   r14,#0
calls FUN_c58ce6
```

The start of `FUN_c58ce6` performs a 32-bit subtraction with `sub/subc`:

```asm
sub   r12,#0x3fec
subc  r13,#0
```

This is a direct scalar use of the `R13:R12` pair. The argument is an
allocation size, not a callback. Calls were broadly printed as:

```c
FUN_c58cb6((fpointer)(ulong)size);
```

MCP returned the first 100 xrefs and reached its output limit, so the actual
number of calls may be higher. Even one false prototype here contaminates a
large amount of decompiled output.

## Defect 4: the far pass removes proven callback types

The initial scalar fix exposed the opposite regression when analyzers were run
in sequence: the code-pointer pass correctly assigned `fpointer`, after which
the complete far-data pass replaced some of those parameters with `void *` or
two `undefined2` values.

Two distinct genuine code-use paths were confirmed in the real M55 database:

- `FUN_740b28` saves its incoming pairs, restores them into `R5:R4`, and calls
  the TASKING far-indirect dispatcher `FUN_a26154`; both first parameters are
  callbacks;
- the fourth parameter of `FUN_9bc42a` travels through a forwarding chain into
  `FUN_9057dc`, where `R15:R14` is copied to `R5:R4` immediately before the
  same dispatcher.

These are not coincidences with a function entry point: both cases have a
reachable indirect call. The error had three parts:

1. Semantic code-use evidence was not retained separately from weaker
   exact-entry evidence.
2. Tracing stopped at a basic-block boundary even when a callback had been
   safely saved on the user stack or in callee-saved `R6-R9`.
3. The far pass could not distinguish a generic analyzer-owned `fpointer`
   proven by indirect use from an old incorrect type.

Section 3.7 of the TASKING manual explicitly marks `R6-R9` as “saved by
callee.” A strong semantic tracer may therefore follow these registers across
a call, but it must reject the value after any explicit redefinition. Ordinary
speculative constant inference does not receive this exemption.

## Defect 5: cleanup changes the target through a thunk

The complete headless run found another reason the corrected `FUN_9057dc`
reverted to `FUN_9057dc(void *, undefined2, undefined2)`. Immediately before
cleanup, both its signature and semantic evidence were correct:

```c
FUN_9057dc(void *, fpointer);
```

The change occurred while another function, `FUN_92c0c6`, was being processed.
The saved database confirmed that it is a thunk to `FUN_9057dc`:

```text
92c0c6 isThunk=true target=9057dc
```

In Ghidra, `FunctionDB.updateFunction()` delegates an update on a thunk to its
ultimate target. The thunk has no semantic-evidence slot of its own, so cleanup
considered the inherited generic `fpointer` unsubstantiated. In attempting to
split it on `FUN_92c0c6`, cleanup actually split the parameter of `FUN_9057dc`.

This is not a defect in four-byte function-pointer storage and does not require
a Ghidra core patch. Every C166 analyzer signature-repair pass must skip
thunks: their signature belongs to the target and may be changed only using
evidence from that target.

## Control functions

`FUN_26cda4` and `FUN_26ce2c` have a layout closer to reality:

```c
undefined1 FUN_x(undefined2, undefined2,
                 undefined2 offset_lo, undefined2 offset_hi,
                 void *buffer, undefined2 length);
```

Their decompilation combines `offset_lo/offset_hi` with `CONCAT22` for
`sys_lseek`, preserves the real far data pointer to the buffer, and does not
turn the scalar length into a callback. This is control evidence that adjacent
code genuinely distinguishes file offsets, buffers, and lengths; the
`fpointer` in `FUN_26cd1c` does not describe the API family.

## Impact

A false `fpointer` causes several problems at once:

1. The decompiler prints scalar constants and sizes as function addresses.
2. Interprocedural propagation can carry the false callback type into wrappers
   and callers.
3. In TASKING Classic Large, a four-byte type affects register-versus-stack
   allocation. Incorrectly replacing a scalar pair with two `undefined2`
   parameters creates a fictitious argument in `R15` and shifts the real stack
   arguments.
4. The recursive call to `FUN_26cee4` no longer matches its own signature,
   producing `_2_2_`, `ZEXT24`, and disconnected values.
5. For the frequently called `FUN_c58cb6`, the error spreads across many
   allocation call sites.

## Suspected cause

This section records the hypothesis formed from inspecting the database and
the analyzer at the time, rather than a final diagnosis from an instrumented
trace.

`C166CodePointerPhase` treated a `SEGMENT:OFFSET` pair as strong
function-pointer evidence when the computed address exactly matched the start
of an existing function. Constants, offsets, lengths, and sizes can match by
accident. Existing constraints filtered some data pointers and pairs of
independently changing word positions, but did not recognize positive 32-bit
scalar use such as:

- paired `add/addc`, `sub/subc`, and similar arithmetic;
- passing a pair into an already typed 32-bit scalar parameter;
- repeatedly forwarding one pair as a size, offset, or count;
- the TASKING spill rule under which a four-byte argument is placed wholly on
  the stack when only `R15` remains available.

The repair path presented a separate risk: removing a false generic pointer
and then splitting it into two `undefined2` parameters corrects the type
category but can leave the ABI layout wrong. These cases require one four-byte
scalar type (`undefined4`, `uint32_t`, `ulong`, or a signed variant after
semantic verification).

## Fix requirements

The fix must not be an M55 address whitelist. It must classify the same
four-byte storage into one of four categories:

- two independent 16-bit scalars: two `undefined2` parameters;
- one 32-bit scalar: one four-byte integer type;
- far data pointer: `void *` or a concrete data pointer;
- far code pointer: `fpointer`, only with proven code use.

Minimum constraints:

- activation only for C166 with `tasking-classic-large`;
- an exact function entry alone must not outweigh strong scalar-use evidence;
- an existing imported or user-defined function-pointer type must not be
  removed without contradictory evidence;
- a genuine callback forwarded into a far-indirect call must remain
  `fpointer`;
- a genuine far data pointer must remain a data pointer;
- the decision must follow the formal TASKING Large ABI layout, including the
  inability to place only part of a four-byte argument in the last free 16-bit
  register.

## Verification plan

1. Add synthetic tests for all four categories, including register spill after
   three 16-bit arguments.
2. Cover scalar evidence from `sub/subc` and from passing a value into a typed
   `uint32_t` argument.
3. Add a negative test in which an exact function-entry constant used as a
   size or offset does not become `fpointer`.
4. Add a positive test in which an exact function entry that actually reaches
   a far-indirect call remains `fpointer`.
5. Run the complete `tools/test-tasking-abi.sh` suite with the historical
   legacy C166/C167 controls used at the time of this investigation.
6. Install the built module with `install-local.sh`.
7. Repeat headless analysis of the real M55 v91 image and inspect at least
   `FUN_26cee4`, `FUN_26cd1c`, `FUN_c58cb6`, and the listed call sites.
8. Compare the full before/after decompilation by the number of new pointer
   types and confirm that genuine callbacks are retained.

## Acceptance criteria

- `FUN_26cee4` retains three register scalar arguments and two unified
  four-byte stack scalar values, with no fictitious `R15` parameter.
- In `FUN_26cd1c`, offset and length are not `fpointer`, while the buffer
  remains a far data pointer.
- `FUN_c58cb6` accepts a 32-bit size without an `fpointer` cast in every
  inspected caller.
- Repeated analyzer runs are idempotent and do not restore the false types.
- The historical C166 legacy controls pass without behavior changes.
- Any Ghidra core change, if one is ever required, is strictly gated to C166
  with `tasking-classic-large` and does not affect ARM or other architectures.

## Implemented fix

The fix is entirely in the C166 module and is activated by the analyzer's
existing C166 plus `tasking-classic-large` restriction.

- Pairs used by `add/addc` or `sub/subc` are treated as one 32-bit scalar
  storage when both words conservatively trace to adjacent incoming ABI slots.
- Scalar evidence propagates backward through direct calls into already typed
  integer parameters, including integer typedefs from the runtime archive.
- Stack values have a separate scalar-only fallback based on the calculated
  TASKING frame delta. Speculative exact-entry inference remains block-local;
  only an already proven semantic dispatcher or forwarding path receives the
  fallback.
- Incoming register values may cross a basic-block boundary only if the linear
  function prefix contains neither a definition of the register nor a call
  that could clobber it. Calls do not clobber `R6-R9` under the TASKING
  saved-by-callee ABI.
- A false generic `fpointer` with proven packed-scalar use is replaced by one
  `undefined4`, not two `undefined2` parameters.
- TASKING rule 3.6 is honored: when a four-byte argument does not fit after
  three word arguments, it goes entirely on the stack and the false `R15`
  placeholder is removed.
- Reconstruction of pushed stack arguments is bounded by the exact size of the
  immediate caller cleanup, `add r0,#bytes`, so saved registers below the
  arguments do not become fictitious parameters.
- Proven use of a pair as the target of the TASKING far-indirect dispatcher is
  published separately from exact-entry evidence and retained between the code
  and far analyzers. Read-only headless operation uses a transient marker on
  the same `Program` object; ordinary databases additionally persist the
  marker in program options.
- The strong semantic tracer follows validation branches, restored incoming
  user-stack slots, and callee-saved `R6-R9`, but only while no observed path
  redefines the value.
- Proven dispatcher use is traced within the function body instead of using a
  global `BasicBlockModel`. This retains immediately preceding `mov`
  instructions and avoids an expensive whole-image block lookup.
- Cleanup of false generic `fpointer` types and packed-scalar repair skip
  thunks. Ghidra delegates thunk updates to the target, while evidence from an
  alias function must not rewrite the target signature. A synthetic test
  reproduces this contract, and the real-program control uses
  `FUN_92c0c6 -> FUN_9057dc`.

## Verification results

At the time of this investigation, the complete `tools/test-tasking-abi.sh`
suite passed for:

- `C166:LE:16:tasking-classic-large`;
- the legacy `C166:LE:16:default:tasking` control;
- `C166:CS:LE:16:tasking-classic-large`;
- code-pointer and far-pointer positive, negative, ambiguity, and idempotence
  fixtures.

The real-program harness was also corrected for two false failures found
during verification:

- the call-site check at `0x6f30aa` permits the remaining third and fourth
  arguments of `FUN_99b53a`, while still requiring the first two separate
  values `1, 0x2c3` and rejecting the false packed pointer `0xb0c001`;
- `0xc394dc` is treated as an instruction address inside the real
  `AT_SayResult`, not as an artificial entry point for a new function in the
  middle of an existing body.

The real headless test opens the saved M55 v91 database read-only, reproduces
the old false `fpointer` signatures, and runs the runtime, code-pointer, and
complete far-pointer analyzers. The final forms are:

```c
FUN_26cee4(undefined2, undefined2, undefined2, undefined4, undefined4);
FUN_26cd1c(undefined2, undefined2, undefined4, void *, undefined4);
FUN_c58cb6(undefined4);
```

The storages for `FUN_26cee4` are `R12`, `R13`, `R14`, `Stack[0]:4`, and
`Stack[4]:4`; the fictitious `R15` parameter is gone. The complete far-pointer
pass does not restore false pointers. Real callback controls in `FUN_9b0678`,
`FUN_9bb936`, `FUN_9bc42a`, `FUN_29ffde`, `FUN_25901a`, `FUN_2590ce`,
`FUN_740b28`, and `FUN_9057dc` are preserved. `FUN_242066` continues to
decompile with `FUN_253d0e` and `FUN_253d7c`, without the erroneous PAGE:OFFSET
addresses `0x97d0e` and `0x97d7c`.

The verified build was installed with `install-local.sh`. Ghidra must be
restarted to load it.
