# TASKING Local Far-Pointer and Wide-String Recovery

## Status

Planned. Switch recovery in `FUN_2e6276` is fixed and verified, but its local
data-pointer presentation and inferred object types still need systematic
work.

## Observed behavior

The function constructs a local wide string and later passes it through several
typed consumers. The register-level pointer classification is correct:

- `param_1` is a far data pointer in `R13:R12`.
- `param_2` is a 16-bit scalar in `R14`.
- `FUN_9056d8` returns a far data pointer in `R5:R4`.
- `0xe413`, `0x2f6`, `0x5ab`, and `9` remain scalars.
- The bounded `JMPI` table is control flow, not a function pointer.

The remaining decompiler output is nevertheless misleading:

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

## Implementation plan

1. Add focused headless fixtures for two R0-relative locals passed as complete
   `DPP2:OFFSET` pairs. Assert that the decompiler retains the local-address
   identity and suppresses the representation-only offset mask.
2. Trace the pointer join from the TASKING stack-address p-code through input
   type propagation. Determine whether the mask survives in the module's p-code
   emitter or in shared decompiler cast/mask simplification.
3. Fix the narrowest responsible layer. Any shared Ghidra change must be gated
   by the exact `c166.abi=tasking-classic-large` processor property and include
   x86 and ARM controls.
4. Add descriptor-layout evidence based on the stores at offsets zero, two, and
   four and the repeated typed consumers. Do not infer a named structure from a
   function name or firmware address.
5. Retype the six-byte header and 76-byte body only when their sizes, stores,
   returned alias, and downstream uses agree. Preserve user-defined types.
6. Add a split-return fixture matching `FUN_2e8484` and remove the redundant
   high-word temporary without changing the `R5:R4` far-pointer result.
7. Re-run the focused synthetic tests, the full TASKING ABI suite, and a
   read-only independent copy of the real project containing `FUN_2e6276`.
   Verify that the original project hashes remain unchanged and inspect the
   installed result through live Ghidra MCP.

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
