# M55 v91: near addresses resolve without the active DPP

Investigation date: 2026-08-18.

Status: fixed and verified headless against the saved M55 database.

## Summary

In `FUN_34b662` and `FUN_34b230`, Ghidra treated 16-bit near operands
`0x2c0..0x2d4` as physical addresses `0x0002c0..0x0002d4`. The code sets
`DPP0 = 0xb` immediately before these accesses, so the real physical addresses
are in `0x02c2c0..0x02c2d4`.

The error caused at least two externally different decompiler failures:

1. the global path far pointer was folded to the false constant `0xb1420`;
2. initialization of the same globals was treated as writes to read-only
   memory, after which the decompiler removed reachable blocks from
   `FUN_34b230`.

## Address translation

Both cases use DPP0:

```asm
mov  DPP0,#0xb
...
mov  r12,0x2cc
mov  r13,0x2ce
```

The upper two bits of near addresses `0x2cc` and `0x2ce` are zero, selecting
`DPP0`. A C166 data address uses a 14-bit offset:

```text
physical = (DPP0 << 14) | (near & 0x3fff)

(0x0b << 14) | 0x02cc = 0x02c2cc
(0x0b << 14) | 0x02ce = 0x02c2ce
```

The global far-pointer word pair therefore resides at physical addresses
`0x02c2cc:0x02c2ce`, not `0x0002cc:0x0002ce`.

The open M55 database maps `RAM_HIGH` over `0x010000..0x1fffff`, which includes
`0x02c2cc`. Reading that address returns bytes `84 06 28 00`. Their concrete
value must not be folded into a constant because `FUN_34b230` rewrites the pair
dynamically.

## Defect 1: false path `0xb1420` in `FUN_34b662`

Observed decompilation:

```c
iVar1 = sys_open((char *)0xb1420, 1, 0x180, auStack_e);
```

The actual setup is:

```asm
34b67a  mov  DPP0,#0xb
34b680  mov  r12,0x2cc
34b684  mov  r13,0x2ce
34b688  mov  r14,#1
34b68a  mov  r15,#0x180
34b68e  calls sys_open
```

`R13:R12` contains the four-byte far-pointer value loaded from
`0x02c2cc:0x02c2ce`. It is the first `path` argument; `R14` and `R15` are
separate 16-bit `flags` and `mode` arguments. The final far pointer to a
two-byte local status/error object is passed on the stack.

The constant `0xb1420` is reproducibly derived from unrelated bytes at the
incorrect address `0x0002cc`:

```text
bytes at 0x0002cc: 20 54 2c 20
OFFSET = 0x5420 & 0x3fff = 0x1420
PAGE   = 0x202c & 0x03ff = 0x002c
address = (0x2c << 14) | 0x1420 = 0xb1420
```

Expected semantic form:

```c
iVar1 = sys_open(path_ptr, 1, 0x180, (uint16_t *)auStack_e);
```

Here `path_ptr` is the mutable global far pointer stored at
`0x02c2cc:0x02c2ce`. The name is illustrative; final symbol naming is not part
of the fix.

## Source of the global path pointer

`FUN_34b230` builds a path in a local buffer, allocates memory through the
provided allocation callback, and copies the string:

```c
char path_buffer[128];

FUN_34c114(path_buffer);
path_ptr = malloc_cb(strlen(path_buffer) + 1);
strcpy(path_ptr, path_buffer);
```

The allocator result is returned in `R5:R4` and stored by:

```asm
34b2f8  mov  0x2cc,r4
34b2fc  mov  0x2ce,r5
```

With `DPP0 = 0xb`, these are stores to `0x02c2cc` and `0x02c2ce`.

## Defect 2: destruction of `FUN_34b230`

The broken decompilation was:

```c
/* WARNING: Function: FUN_a26154 replaced with injection: call_far_indirect */
/* WARNING: Removing unreachable block (ram,0x34b264) */
/* WARNING: Removing unreachable block (ram,0x34b272) */
/* WARNING: Removing unreachable block (ram,0x34b2d0) */
/* WARNING: Removing unreachable block (ram,0x34b304) */
/* WARNING: Removing unreachable block (ram,0x34b348) */
/* WARNING: Removing unreachable block (ram,0x34b34a) */
/* WARNING: Removing unreachable block (ram,0x34b302) */
/* WARNING: Removing unreachable block (ram,0x34b2cc) */

undefined2 FUN_34b230(void)
{
    FUN_86f4b2(&DAT_035ce6);
    /* WARNING: Read-only address (ram,0x0002c0) is written */
    /* ... equivalent warnings for 0x2c2..0x2d4 ... */
    return 0;
}
```

The function actually accepts four 16-bit words forming two far
function-pointer pairs: the allocation callback in `R13:R12` and the free
callback in `R15:R14`. It stores them and its working globals in physical RAM:

| Near operand | Physical address with `DPP0=0xb` | Purpose |
|---:|---:|---|
| `0x2c0:0x2c2` | `0x02c2c0:0x02c2c2` | allocation callback |
| `0x2c4:0x2c6` | `0x02c2c4:0x02c2c6` | free callback |
| `0x2c8:0x2ca` | `0x02c2c8:0x02c2ca` | allocated record array |
| `0x2cc:0x2ce` | `0x02c2cc:0x02c2ce` | allocated path string |
| `0x2d0` | `0x02c2d0` | record count |
| `0x2d2` | `0x02c2d2` | record multiplier/size field |
| `0x2d4` | `0x02c2d4` | initialization status |

The false read-only warnings show that high p-code/dataflow used the near
operand as the final physical address. Constant propagation then read unrelated
bytes from `0x0002c0..0x0002d4`, proved false conditions, and removed actually
reachable blocks. The missing parameters and reduction to `return 0` were
consequences of the same addressing error.

## Confirmed root cause

Direct near LOAD/STORE, register-plus-offset, and switch loads used separate
address-formation paths. Some injectors read DPP from persisted
`ProgramContext`, making the result analysis-order dependent and allowing a
stale value to replace the executing `mov DPP0,#0xb`.

The fix is in the C166 module: all three paths use
`C166PagedAddressEmitter`, while a mutable DPP remains a live register varnode
in decompiler p-code. Ghidra core was not changed for this defect.

If a future core patch becomes necessary, it must be enabled only by the exact
`c166.abi=tasking-classic-large` marker and must not affect ARM, x86, or any
other architecture.

## Implemented fix and verification

1. Raw and decompiler p-code for `34b67a..34b68e` and `34b2f2..34b2fc`
   localized the DPP loss to separate p-code injectors and persisted context.
2. A synthetic fixture with deliberately stale `DPP0=0` proves that executing
   `mov DPP0,#0xb` selects `0x02c2cc`; another fixture covers switch loads.
3. Direct, register-offset, and switch addressing use the shared
   `C166PagedAddressEmitter`, including DPP1..DPP3 and EXTP/EXTS support.
4. A read-only real-M55 headless regression checks `FUN_34b662` without
   `0xb1420` or masking of the stack far-pointer argument.
5. The same regression checks the full body of `FUN_34b230`, absence of
   low-address read-only warnings, and references to physical `0x02c2c*`
   globals.
6. Auto Structure is checked at physical `0x02c2c8` and `0x02c2cc`, including
   the real GUI-command path.
7. The ABI suite passes for C167CR/C167CS; the patched-decompiler suite passes
   for C166, x86-64, and ARM. Ghidra core remains unchanged for the DPP fix.
8. The final module build was installed locally through `install-local.sh`.

## Acceptance criteria

- `FUN_34b662` passes the global far-pointer value from
  `0x02c2cc:0x02c2ce` to `sys_open`, not constant `0xb1420`;
- `FUN_34b230` retains its real body and ABI parameters;
- no read-only warning references incorrect addresses
  `0x0002c0..0x0002d4`;
- xrefs and automatically created data objects point into physical `RAM_HIGH`;
- an unknown or mutable DPP is not replaced with a speculative constant;
- behavior on every other architecture remains unchanged.
