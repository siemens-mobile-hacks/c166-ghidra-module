# C166 Ghidra Module

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **Ghidra** extension for disassembling and decompiling **Infineon C166/C167** microcontroller binaries. Features advanced support for C166's segmented memory model including DPP (Data Page Pointer) address translation and switch table analysis.

This repository is a fork maintained specifically to support the **TASKING
Classic ABI**, with a focus on its **Large Memory Model**.

> [!IMPORTANT]
> Use this module with [ghidra-patched](https://github.com/siemens-mobile-hacks/ghidra-patched/releases).
> Stock Ghidra does not preserve resolved TASKING large-model far pointers correctly, causing broken addresses, strings, symbols, and decompiler navigation.

## Differences from [Upstream](https://github.com/keyhana/c166-ghidra-module)

- Incrementally extends the static call graph from new code, with a full-program One Shot, and safely creates missing call targets.
- Resolves EXTP-backed switch tables without falling back to an incorrect DPP page.
- Recovers bounded TASKING local jump tables from their guarded scaled-index
  load sequence, preserving duplicate destinations so the decompiler emits
  numeric case values instead of branch addresses.
- Treats memory-mapped DPP0-DPP3 accesses as the architectural registers, so
  constant propagation no longer invents unrelated `Ram00fe00` globals.
- Adds conservative TASKING function-start patterns for broader automatic code discovery.
- Adds a TASKING C166 Classic 7.5 large-model ABI with true four-byte C pointers.
- Supports only TASKING Classic Large and selects all ABI-specific behavior
  through the exact `c166.abi=tasking-classic-large` processor-spec property.
- Runs data-pointer, function-pointer, scalar, return, and variadic type
  inference under one analyzer with a fixed evidence order; specialized phases
  are ordinary non-analyzer classes and cannot appear as independent Auto
  Analysis entries.
- Recovers analyzer-owned scalar return widths from `RL4`/`R4` and incoming
  word parameters from live `R12`–`R15` reads while preserving user-defined,
  pointer, stack-based, and variadic signatures.
- Forms direct, register-offset, and switch-table data addresses through one
  DPP/EXTP/EXTS p-code emitter, preserving DPP writes as live register dataflow
  and typed register-mode EXTP addresses as far-pointer operations instead of
  exposing page-shift arithmetic.
- Infers far-pointer parameters and global far-pointer objects from documented
  DPP0/EXTP page-and-offset data flow, including four-byte pointer values already
  rejoined by the patched decompiler, repeated typed call sites, and adjacent
  object-field stores whose typed consumer later dereferences the stored pair.
- Recovers compact aggregate layouts behind analyzer-owned far-data pointers,
  preserves concrete pointer fields, and propagates the layout through exact
  parameter and returned-value aliases.
- Retypes exact-size analyzer-owned user-stack objects from concrete direct-call
  pointer parameters, including arrays and stable word-sized scalar outputs,
  while preserving user-defined or conflicting local types.
- Joins constant far code-pointer arguments as four-byte function pointers
  when their `SEGMENT:OFFSET` encoding names an executable function entry,
  while requiring repeated or semantic evidence before propagating that type
  backwards through wrappers.
- Distinguishes TASKING packed 32-bit scalar pairs from far callbacks, keeps
  semantic callback evidence stable across analyzer passes, and avoids changing
  callback target signatures indirectly through thunks.
- Classifies values returned in the documented R5/R4 pair as far data
  pointers, far function pointers, or four-byte scalars from explicit producer
  writes, complete callee-saved forwarded returns, and proven downstream use,
  while preserving user/imported signatures.
- Recognizes TASKING far-indirect dispatchers, applies their call fixup, and
  removes stale analyzer-owned C parameters from the dispatcher itself.
- Models TASKING Classic Large `double` and aggregate results as caller-stack
  blocks whose near pointer is returned in R4, without a hidden input parameter.
- Models recognized TASKING Classic double and 32-bit integer runtime helpers
  so user-stack operands, arithmetic results, and preserved registers remain
  connected in decompiler data flow.
- Models R0 as the TASKING user stack without a fictitious return-address
  record, preserving initialized locals whose far address is passed to a call.
- Recovers fixed user-stack parameters prepared across balanced nested calls
  from exact caller cleanup without crossing ambiguous stack or control flow.
- Repairs typed TASKING variadic call sites incrementally, including fixed far
  pointers spilled to the user stack, far-pointer arguments preserved through
  R6-R9 in the `...` portion, and stale pointer-shaped pairs of promoted scalar
  varargs, while preserving the declared fixed variadic prefix.
- Provides `install-local.sh` for atomic local extension updates with backups.

## Features

### Core Functionality
- **Full Instruction Set** — All C166 instructions including extended, multiplication/division
- **DPP Address Translation** — Automatic resolution of 16-bit addresses to 24-bit physical addresses
- **EXTP/EXTS Support** — Extended page and segment override handling
- **Switch Table Analysis** — Automatic switch detection
- **Call Graph Discovery** — Extends the graph from newly disassembled code; a full One Shot scans every function
- **Function Start Patterns** — Conservative TASKING prologue detection after C166 return instructions

### Included Scripts

| Script | Keybinding | Description |
|--------|------------|-------------|
| `AddISRLabels.java` | `Ctrl+Shift+I` | Label interrupt vector table and handlers |
| `CreateDPPReference.java` | `Ctrl+Shift+D` | Manually create DPP-resolved data references |
| `C166SwitchOverride.java` | `Ctrl+Shift+S` | Force switch table recognition in decompiler |

## C166 Memory Model

C166 uses a segmented memory architecture:

```
16-bit pointer → 24-bit physical address

Formula: physical = (DPP << 14) | (offset & 0x3FFF)

DPP0: 0x0000-0x3FFF
DPP1: 0x4000-0x7FFF
DPP2: 0x8000-0xBFFF
DPP3: 0xC000-0xFFFF
```

The module attempts to resolve these translations automatically, though manual intervention may be needed in some cases.

## Installation

1. **Download** the latest `.zip` from [Releases](https://github.com/siemens-mobile-hacks/c166-ghidra-module/releases)
2. **Install** in Ghidra: `File` → `Install Extensions...` → `+` → Select `.zip`
3. **Restart** Ghidra

### Building from Source

```bash
# Set Ghidra installation path
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Build extension
./gradlew buildExtension

# Output: dist/ghidra_*_c166-ghidra-module.zip
```

The patched Ghidra distribution required by the TASKING far-pointer model is
maintained in [siemens-mobile-hacks/ghidra-patched](https://github.com/siemens-mobile-hacks/ghidra-patched).

For local development, after installing the extension once, rebuild and replace
the installed extension with:

```bash
./install-local.sh
```

The script uses `GHIDRA_INSTALL_DIR` (default: `/opt/ghidra`) to select the
matching Ghidra user directory. Override `GHIDRA_USER_DIR` when needed. Restart
Ghidra after replacement because processor modules are loaded once per process.
The previous extension is saved under `ExtensionBackups`.

## Usage Tips

Automatic analysis limits Call Graph and TASKING Type Inference processing to
newly changed code. To rescan the whole program, clear the current selection
and run the corresponding action under `Analysis` → `One Shot`.

### Switch Tables Not Detected?
1. Place cursor on `jmpi` instruction
2. Press `Ctrl+Shift+S` to run switch override script
3. Script finds table offset and max case automatically

### Wrong Data References?
1. Place cursor on instruction with memory operand
2. Press `Ctrl+Shift+D` to create DPP-resolved reference
3. Script prompts for DPP value if unknown

## Compiler and Calling Conventions

For firmware built by **TASKING C166 Classic 7.5 in the large model**, select
language `C166:LE:16:tasking-classic-large` (or the corresponding
`C166:CS:LE:16:tasking-classic-large` C167CS variant) and compiler ID
`tasking-classic-large` when importing the binary. Its default calling
convention is `__tasking_c166_classic`. The separate language ID is required
because Ghidra attaches segmented-pointer semantics to a processor spec rather
than to an individual compiler spec.
Functions left at Ghidra's `default` or `unknown` convention use this model
automatically; assigning `__stdcall` manually is not required.

ABI source: [TASKING C166/ST10 Classic v7.5 manuals](https://www.tasking.com/support/c166-classic/MAN_PDF_V7.5.ZIP), sections 3.2.1.6, 3.5, 3.15, and 3.16.5.

| Language / compiler ID | Convention | Word parameters | 32-bit / far-pointer storage | Default C pointer |
|------------------------|------------|-----------------|------------------------------|-------------------|
| `C166:LE:16:tasking-classic-large` / `tasking-classic-large` | `__tasking_c166_classic` | R12, R13, R14, R15 | Any consecutive register pair, then adjacent stack words | 4 bytes |

In Ghidra join notation the most significant register is printed first. Thus
`R14/R13` means that TASKING's low word is in R13 and its high word is in R14.
Classic returns `char` in RL4, 16-bit values in R4, and 32-bit values or far
pointers in R5/R4. R0 is the downward-growing user-stack pointer.

The new compiler spec also models the Classic spill rule: once an argument does
not fit in the remaining parameter registers, it and all following arguments
use the user stack. Fixed parameters of variadic functions still use registers;
only the `...` portion is forced to the stack. Floating-point and aggregate
arguments are stack-passed. `double` and aggregate results use caller-provided
user-stack storage; the callee returns its near pointer in R4 without receiving
a hidden input parameter.

TASKING **VX**, Keil C166, and other Classic memory models use different ABIs
and are not supported by this module. Do not import them as
`tasking-classic-large`.

TASKING Classic's **huge** memory model is also distinct and is not modeled by
this language. Large-model default pointers are `_far` `PAGE:OFFSET` values
with a 14-bit offset; huge-model default pointers are `_huge` `SEGMENT:OFFSET`
values with a 16-bit offset. Do not use `tasking-classic-large` for huge-model
firmware.

The four-byte pointer size fixes C type layout and parameter/return storage.
Far data pointers contain `PAGE:OFFSET`, where the physical address is
`((page & 0x3ff) << 14) | (offset & 0x3fff)`. Constant far pointers passed to
correctly typed functions are resolved to physical addresses, so a call such as
`strcmp(input, far_string)` can decompile as `strcmp(input, "text")` when the
target is defined as string data in a read-only memory block. This is driven by
the pointer type and segmented-address model, not by function names, firmware
addresses, or string contents.

The far-data phase of **C166 TASKING Type Inference** joins an argument pair only
when decompiler data flow proves that its high word supplies PAGE and its low
word supplies OFFSET to a DPP0/EXTP paged access. It supports all documented
positions R12/R13, R13/R14, and R14/R15, plus adjacent stack words after the
register bank is proven exhausted. It retains other live register/stack inputs,
propagates typed pointers through direct and identity tail calls, refines
`void *` to `char *` from typed data flow, and joins adjacent global words only
when their PAGE:OFFSET use is proven. Function names, firmware addresses,
string contents, and constant values are not evidence. The TASKING data-type
analyzer also normalizes imported `size_t` to the compiler's 16-bit
`unsigned int`. This includes replacing the incompatible 32-bit
`size_t.conflict` introduced by Ghidra's generic C library archive and updating
dependent prototypes such as `snprintf`.

The patched Ghidra distribution converts typed PAGE:OFFSET joins through the
standard segmented-pointer operation and suppresses representation-only
24-to-32-bit pointer conversions. This removes raw `CONCAT22`/`ZEXT34` output;
for example, a resolved call becomes `takes_string("text")`. The module uses one
canonical `segmentop` and no synthetic call registers. Its auxiliary
`__tasking_c166_classic_vararg_*` models are generated only for conservative
call-site overrides and are not calling conventions users need to select.

Ghidra may initially recover a typed variadic call as individual 16-bit words.
The variadic phase of **C166 TASKING Type Inference** creates conservative call-site
prototype overrides when the declared fixed parameters consume R12-R15; this
repairs calls such as `sprintf(dst, "%d", value)` and uses the same far-pointer
types recovered for its fixed parameters. A fixed parameter which spills after
a failed register join also exhausts the register bank, so layouts such as
`snprintf(dst, size, format, value)` are recovered correctly. Existing generated
overrides with obsolete argument widths are replaced automatically. Assign the
function's typed signature first, then rerun Auto Analyze if it was assigned
after the initial analysis. Calls for which unused parameter registers make the
argument count ambiguous are deliberately left unchanged.

## Supported Processors

- Infineon C167CR
- Infineon C167CS

## Known Limitations

- Generic TASKING Classic `PAGE:OFFSET` pointer arithmetic is not fully modeled
- TASKING Classic huge-model `SEGMENT:OFFSET` pointers are not yet supported
- Variadic calls with unused parameter registers remain ambiguous without additional type information

## Project Structure

```
GhidraInfineon/
├── data/languages/       # SLEIGH processor definitions
├── src/main/java/        # Analyzers and PCode injectors
├── ghidra_scripts/       # User scripts
└── agents.md             # Detailed technical documentation
```

See [`agents.md`](agents.md) for comprehensive technical documentation.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Fork, branch, and submit a PR.
