# Process Lasso HiDPI patcher — assembly-authored edition

The injected x86-64 routines in `patch.py` are written as Intel-syntax assembly and assembled at runtime with `keystone-engine`.

The old hand-authored payload is retained only as `fixtures/hidpi_code_legacy.bin`. Its SHA-256 is pinned in the tests, and every assembly block that existed in the previous payload must still assemble byte-for-byte to its corresponding legacy range. The new layout blocks are independently assembled with GNU binutils during development and their byte hashes are pinned as a second assembler check.

The original Process Lasso hook-site bytes remain literal fixtures rather than generated assembly. They are build-lock fingerprints: the patcher refuses to modify any executable whose bytes do not exactly match the analyzed build.

## HiDPI layout fix

The first HiDPI build scaled the two fixed `Bitsum_LoadDisplay` windows from their 96-DPI width of 60 px, but left two upstream layout reservations at 65 px (`60 + 5`). At DPI values above 96, the windows therefore became wider than the space reserved for them and could overlap the variable-width processor display.

This revision scales all of the related geometry from the main window DPI:

- fixed load-display width: 60 px
- fixed load-display reservation: 65 px (`60 + 5`)
- narrow-window visibility threshold: 160 px (`100 + 60`)
- gap between the two fixed load displays: 5 px
- gap between the variable processor display and its neighbor: 5 px

At 96 DPI the patched reservation branches are intentionally equivalent to the original branches.

The previous payload contained one unreachable trampoline at offsets `0x280..0x2d2`. Nothing patched into Process Lasso referenced it and it had no unwind entry. This version intentionally removes it; unused space is filled with `INT3` (`0xcc`).

## Run

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s . -v
python patch.py ProcessLasso.exe
```

For the tests that verify the original executable's hook sites and deterministic full rebuild, either put `ProcessLasso.exe` beside the patcher or set:

```sh
PROCESS_LASSO_EXE=/path/to/ProcessLasso.exe python -m unittest discover -s . -v
```
