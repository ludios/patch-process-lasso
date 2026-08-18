All the commit messages in this repo are slop: I did not write them.

To help your clanker out, copy ProcessLasso.exe and pl_rsrc_english.dll to this directory before prompting.

Thanks,
Ivan

# Process Lasso HiDPI patcher

`patch.py` patches ProcessLasso.exe to support DPI scaling.

## Run

The patcher shells out to the GNU binutils toolchain (`as`, `ld`, `objcopy`) to assemble the injected routines, so those must be on `PATH`. There are no Python package dependencies.

```sh
python3 -m unittest discover -s . -v
python3 patch.py ProcessLasso.exe
```

For the tests that verify the original executable's hook sites and deterministic full rebuild, either put `ProcessLasso.exe` beside the patcher or set:

```sh
PROCESS_LASSO_EXE=/path/to/ProcessLasso.exe python3 -m unittest discover -s . -v
```
