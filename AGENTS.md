# Repository Agent Instructions

## ABI and scope

- Treat `/home/azq2/Documents/DIY/Siemens/C166/ST10 C Cross-Compiler User's Manual.pdf`
  as the authoritative ABI reference and follow the TASKING Classic Large
  Memory Model exactly.
- Gate Ghidra core behavior with the exact processor property
  `c166.abi=tasking-classic-large`.
- Ghidra core fixes must not change ARM, x86, or any other architecture.

## Verification

- Investigate complex problems in headless Ghidra before reporting them fixed.
- Cover fixes with focused synthetic tests and, when applicable, the real
  Ghidra database that reproduced the problem.
- Include non-C166 architecture controls for changes to shared Ghidra code.
- Show a concise before/after example at the end of every completed fix.

## Local installation

- After every implementation change, always install the result into the active
  local Ghidra before reporting completion.
- For module changes, run `./install-local.sh`.
- For `ghidra-patched` core changes, install the rebuilt affected native/core
  artifacts as well; installing only the extension JAR is insufficient.
- Back up replaced core artifacts, verify the installed file hashes, and check
  the real function through live Ghidra MCP after installation. Restart Ghidra
  when an already-running process still holds an older artifact.

## Commits and releases

- Commit only when the user explicitly requests it.
- Before a commit, review the complete diff, run `git diff --check`, and update
  the README only with relevant differences from upstream.
- When the user requests a release, use this order: commit, push, annotated
  tag, push the tag.
