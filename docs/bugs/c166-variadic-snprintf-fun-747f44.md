# C166 variadic `snprintf` call in `FUN_747f44`

## Symptom

In the M55 v91 database, the call at `0x748042` is decompiled with shuffled
fixed arguments and split far pointers:

```c
snprintf(0x2d, 0x1711972, destination_offset, DPP1, ...);
```

The declaration of `snprintf` itself is already correct for TASKING Classic
large:

```c
int snprintf(char *s, size_t maxlen, char *format, ...);
```

## ABI reconstruction

The instructions immediately before the call establish:

- `R13:R12` — the destination far pointer, built from `DPP1` and
  `(R0 + 0x3c) & 0x3fff`;
- `R14 = 0x2d` — the 16-bit `size_t` buffer length;
- stack words `0x171:0x1972` — the fixed format far pointer, resolving to
  physical address `0x5c5972`;
- the following four stack bytes — the far-pointer vararg stored at
  the pointer object at physical `0x5c596e` (logical DPP0 offset `0x196e`);
- sixteen promoted byte varargs after that.

The post-call `add R0,#0x28` confirms 40 stack bytes: four for the fixed format
pointer, four for the pointer vararg, and `16 * 2` for the promoted bytes.

## Root cause

`C166VariadicCallPhase` can repair this exact call when it examines
`FUN_747f44`. During incremental automatic analysis, however, it kept only
callers whose own bodies intersected the changed address set. If the
typed variadic target (`snprintf`) is the changed function, its callers are
discarded even though a callee signature change invalidates every call-site
prototype override.

This leaves the raw Ghidra variadic recovery in place until the user manually
runs the analyzer as a full-program One Shot.

A whole-function review exposed two additional independent problems:

- stale analysis had joined the scalar `flags` and `mode` words in R14/R15 as
  one generic data pointer, even though the pair is forwarded to two scalar
  parameters of `sys_open`;
- the compiler spec declared a zero-sized return-address record in the user
  stack. Ghidra interprets a zero-sized effect record as making the entire
  stack space unaffected by calls. It consequently discarded the value written
  by `strlen` even though the address of that four-byte length object is passed
  to `FUN_743766`.

The TASKING manual identifies R0 as the user-stack pointer. Normal `CALLS`
return state belongs to the C166 system stack; the optional user-stack return
mechanism is a separate calling model. The large-model compiler spec therefore
must not invent a return address in the R0-backed stack.

## Fix plan

1. Treat a changed typed variadic target as affecting all of its direct
   callers, while retaining the existing caller-body filter for ordinary
   incremental changes.
2. Keep the behavior strictly gated by the existing C166 plus
   `tasking-classic-large` `canAnalyze` check.
3. Add a regression using the `FUN_747f44` stack layout and an incremental set
   containing only `snprintf`, proving that the caller still receives an
   override.
4. Verify the reconstructed destination, `0x2d` size, physical format pointer
   `0x5c5972`, one pointer vararg, and sixteen scalar varargs.
5. Run the synthetic suite and a representative M55 v91 headless check, then
   install the rebuilt extension locally.

## Acceptance criteria

The call must decompile in this argument order:

```c
snprintf(destination, 0x2d, (char *)0x5c5972,
         PTR_5c596e, byte_0, byte_1, /* ... */, byte_15);
```

It must not contain raw `0x1711972`, split destination OFFSET/PAGE arguments,
or a split `PTR_5c596e` vararg.

## Resolution

Implemented in `C166VariadicCallPhase`:

- an incrementally changed typed variadic callee now invalidates all of its
  direct callers;
- cleanup-derived fallback overrides are initially word-wise and are refined
  only after the CALL inputs have been aligned with the fixed signature;
- optional pointer recovery is restricted to optional CALL inputs, never the
  fixed destination/format inputs;
- recovered optional types retain their original argument order and an input
  cannot be consumed twice as both a joined pointer and a narrowed pointer.
- saved overrides which joined two promoted byte arguments into a four-byte
  pointer are split again only when their p-code still proves the two scalar
  promotions; a genuine `SEGMENTOP(PAGE, OFFSET)` pointer is retained;
- far-pointer inference does not extend an already declared variadic function:
  recovered values after its fixed prefix belong to individual call sites, not
  to the function's formal parameter list.

The far-pointer analyzer also splits a stale generic analysis pointer when the
same two words are proven to feed two consecutive, concretely typed scalar
parameters of a TASKING callee. The repair remains gated to C166 plus
`tasking-classic-large`.

The zero-sized user-stack return-address record was removed from
`c166_tasking_classic_large.cspec`. With ordinary call effects restored,
Ghidra's existing stack-alias analysis retains the two stores that zero-extend
the `strlen` result before its address is passed onward; no Ghidra core change
is required.

The exact `FUN_747f44` instruction sequence is covered by the synthetic
decompiler suite. `C166M55VariadicHeadlessTest.java` additionally imports the
real `M55_v91.bin` at base `0x200000` and verifies call `0x748042`.

Verified whole-function output has signature
`int FUN_747f44(char *, ushort flags, ushort mode)`, assigns `strlen` to the
four-byte length object passed to `FUN_743766`, and has the destination first,
`0x2d` second, the format at `0x5c5972` third, one `PTR_5c596e` pointer vararg,
and sixteen promoted byte varargs. Both `tools/test-patched-decompiler.sh` and
`tools/test-tasking-abi.sh` passes for both supported C167CR/C167CS TASKING
Classic Large profiles; the patched-decompiler suite also keeps ARM and x86
controls green.
The same assertions also pass after a complete 28,165-function M55 headless
analysis, and a second run leaves all 117 typed variadic overrides unchanged.
