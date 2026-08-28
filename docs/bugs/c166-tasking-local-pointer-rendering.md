# TASKING Local Far-Pointer and Wide-String Recovery

## Status

Implemented and verified. The switch recovery, local far-pointer rendering,
aggregate layout propagation, stack-local typing, and split far-pointer return
handling are covered by focused synthetic tests and a read-only copy of the
real project.

## Original behavior

The function constructs a local wide string and later passes it through several
typed consumers. The register-level pointer classification is correct:

- `param_1` is a far data pointer in `R13:R12`.
- `param_2` is a 16-bit scalar in `R14`.
- `FUN_9056d8` returns a far data pointer in `R5:R4`.
- `0xe413`, `0x2f6`, `0x5ab`, and `9` remain scalars.
- The bounded `JMPI` table is control flow, not a function pointer.

The remaining decompiler output was nevertheless misleading:

```c
int *descriptor;

descriptor = FUN_9056d8(
    (void *)((uint)local_header_bytes & 0x3fff),
    (void *)((uint)local_body_bytes & 0x3fff),
    0x26);
```

Assembly and callee behavior prove that the six-byte first local is a compact
wide-string header, the 76-byte second local is a 38-element `uint16_t` body,
and the returned value points to the header. `FUN_905708` stores the body far
pointer at offset zero and the capacity at offset four. `FUN_905a92` consumes
the same object as a wide-string descriptor, rather than as an `int` array.

The two output arguments passed to `FUN_224108` are also individual 16-bit
locals, not byte arrays. A related callee, `FUN_2e8484`, loads a returned far
pointer as two words but still exposes a redundant unused high-word temporary
in decompiled C.

## Desired output

The exact type name is secondary to correct layout and data flow. With an
appropriate compact descriptor type, the relevant code should be equivalent
to:

```c
struct LocalWideString {
    uint16_t *body;
    uint16_t capacity;
};

struct LocalWideString local_string;
uint16_t local_body[38];
uint16_t selector;
uint16_t auxiliary;
struct LocalWideString *string;

string = CreateLocalWideString(&local_string, local_body, 38);
FUN_224108(&selector, &auxiliary);
```

No representation-only `& 0x3fff` expression should remain around a proven
R0-relative stack address after its `DPP2:OFFSET` pair has been reconstructed.

## Implemented solution

1. `C166AggregateLayoutPhase` propagates a concrete automatically recovered
   structure through exact parameter aliases and direct return aliases. It
   requires all return paths to agree and preserves concrete four-byte pointer
   fields while refining the aggregate.
2. `C166LocalObjectTypePhase` retypes an exact stack object only when a direct
   call passes its complete address to a concrete, four-byte, non-function
   pointer parameter. It preserves locked, user-defined, and non-weak types.
   Width-specific undefined pointees are represented with a stable unsigned
   integer of the same width.
3. The far-pointer phase shares aggregate-pointer evidence with scalar-pair
   classification. Stored aggregate pointers and semantically proven function
   pointers can no longer be split back into unrelated scalar words.
4. Signature convergence now accepts preserved multiword parameters outside
   newly inferred pairs, eliminating no-op rewrite loops.
5. The patched decompiler suppresses the representation-only `& 0x3fff` only
   for proven stack `PTRSUB` values inside a C166 `SEGMENTOP`. Split return
   PAGE/OFFSET phi nodes are rejoined only when every leaf is either a zero
   pointer or an adjacent word-load pair.
6. Both shared-core changes are gated by the exact processor property
   `c166.abi=tasking-classic-large`.

## Verification

- The focused returned-layout/alias fixture covers recursive wrapper aliases,
  aggregate pointer-field initialization, concrete pointer-field preservation,
  exact stack objects, arrays, and width-specific undefined pointees.
- The complete TASKING ABI suite passes for C166 LE and C167CS.
- Patched-decompiler tests pass for C166, including the split-return fixture.
- Shared-core controls pass unchanged for x86-64 and ARMv8.
- A full, independent copy of the real project was analyzed read-only. The
  second inference pass made no signature or local-type changes and every
  far-pointer call-graph component converged.
- Live Ghidra MCP with the installed core reconstructs the bounded nested
  switch in `FUN_2e6276` as cases 0 through 4. The active project was not
  reanalyzed or modified merely for verification.

The verified real-project result is equivalent to:

```c
astruct_4 *descriptor;
uint selector;
uint auxiliary;
astruct_4 local_string;
uint local_body[38];

descriptor = FUN_9056d8(&local_string, local_body, 0x26);
FUN_224108(&selector, &auxiliary);
```

## Acceptance criteria

- Local stack addresses decompile as ordinary local addresses without explicit
  page masks.
- The descriptor and its body are distinct typed objects with correct sizes.
- The value returned by `FUN_9056d8` aliases the local descriptor and remains a
  far data pointer through every consumer.
- `FUN_224108` receives two typed 16-bit output addresses.
- `FUN_2e8484` returns one coherent far pointer with no unused high-word
  artifact.
- Function pointers and scalar pairs are unchanged.
- x86, ARM, and non-TASKING C166 behavior remains identical to upstream.
