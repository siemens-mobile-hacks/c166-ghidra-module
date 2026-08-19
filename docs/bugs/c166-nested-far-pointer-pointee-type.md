# C166 Nested Far-Pointer Pointee Type Preservation

## Status

Fixed in the patched decompiler and covered by synthetic, negative,
cross-architecture, and real-program headless tests. The complete patch stack
was also reapplied in a clean temporary clone and matched the compiled/tested
source byte-for-byte. The current module build is installed locally.

## Symptom

The outer recovered structure contains a typed field:

```c
struct astruct_4 {
    short field2_0x2;       // +0x02
    GBS_MSG *field3_0x4;    // +0x04
};
```

`FUN_35b82a` loads the field's `OFFSET` and `PAGE` words separately and then
reads words at offsets `+0x04` and `+0x06` from the pointed-to object. Even
when `GBS_MSG` contains valid fields at both offsets, the decompiler emits:

```c
if (((undefined2 *)param_2->field3_0x4)[2] == 0x193) {
    iVar7 = ((undefined2 *)param_2->field3_0x4)[3];
}
```

The expected first access is a structure member:

```c
if (param_2->field3_0x4->submess == 0x193) {
```

The second access reads the low word of `data0`, so a scalar/pointer-width cast
may remain there and is not by itself a defect.

## ABI constraints

The TASKING C166/ST10 C Cross-Compiler User's Manual is authoritative. In the
Large Memory Model:

- `short` and `int` are two bytes;
- a normal far data pointer is four bytes;
- the physical return/register representation is `OFFSET` in the low word and
  `PAGE` in the high word.

Consequently, the complete SGOLD message layout is:

```c
typedef struct GBS_MSG {
    short pid_from;  // +0x00
    short msg;       // +0x02
    int submess;     // +0x04
    void *data0;     // +0x06, four-byte far pointer
    void *data1;     // +0x0a, four-byte far pointer
} GBS_MSG;           // sizeof = 0x0e
```

## Root cause

`recoverC166FarPointerLoadPair()` in the patched decompiler synthesizes one
four-byte `LOAD` from adjacent two-byte `OFFSET/PAGE` loads. It used only
`inferC166FarPointerType()`, which falls back to the terminal memory operation.
For a word read through the reconstructed pointer, that fallback produces an
`undefined2 *`. It also locked that provisional type on the synthetic `LOAD`,
so a later pass could not replace it with the declared `GBS_MSG *` source-field
type. The problem is visible in the real function because the outer pointer is
spilled to and restored from the stack before the nested field is loaded.

## Fix plan

1. Add a C166-specific source-type recovery helper for adjacent far-pointer
   loads.
2. First inspect the source address type. If it points to a complete four-byte
   far data pointer, preserve that loaded pointer type.
3. Otherwise reduce the source address to its typed root plus constant byte
   offset and descend through the root pointee type to an exact field boundary.
4. Accept the recovered field type only when it is a four-byte far data pointer
   using the active `farpointer="yes"` segment definition; reject code pointers,
   interior-field offsets, scalars, and ambiguous paths.
5. Retain terminal `LOAD/STORE` inference only as a fallback when no declared
   source-field type exists.
6. Lock only an authoritative declared source-field type. Leave terminal-use
   inference unlocked so normal type propagation can refine it on a later pass.
7. Trace the reversed `PIECE(OFFSET, PAGE)` form produced by a TASKING stack
   spill back to its original typed PAGE:OFFSET pair.
8. Keep the entire transformation gated by the exact processor property
   `c166.abi=tasking-classic-large`.

## Regression requirements

### Synthetic positive case

- Create a typed outer structure containing a `GBS_MSG *` field at `+0x04`.
- Emit the real adjacent `OFFSET/PAGE` load sequence followed by a word load at
  `GBS_MSG.submess` (`+0x04`).
- Require decompiler output to contain `->submess` and reject casts of the
  nested field to `undefined2 *`, representation masks, `CONCAT`, and
  `segment()`.

### Negative controls

- Adjacent scalar words must not become pointers.
- Function pointers must not become data pointers.
- A source address selecting the interior of a pointer field must not provide
  a whole-pointer type.
- Untyped adjacent loads must retain the existing terminal-use fallback.

### Real-program headless case

- Run the development decompiler against a disposable copy of the real
  `M55_v91.bin` database.
- Install the complete ABI-correct `GBS_MSG` definition and type the nested
  field as `GBS_MSG *` inside the test transaction.
- Require `FUN_35b82a` to render the `+0x04` comparison with `->submess`.
- Decompile twice and require identical output without a type-propagation
  settling warning.

### Cross-architecture controls

- Run the existing x86-64 and ARM decompiler/Auto Structure controls.
- Verify that the new helper is unreachable without the exact C166 ABI
  property.

## Verification result

- Synthetic nested-field decompilation:
  `return owner->message->submess;`
- Declared four-byte scalar and function-pointer fields stayed non-data-pointer
  expressions.
- The existing C166 decompiler matrix passed.
- The x86-64 and ARM Auto Structure controls passed.
- Real `FUN_35b82a` decompiled identically twice and now contains:
  `uVar1 = param_2->field3_0x4->submess;`
- The complete `0001` through `0008` patch series applies cleanly to upstream
  Ghidra 12.1.2, and every patched file matches the source used to build the
  tested development decompiler.
