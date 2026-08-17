// Model-output: GPT-5.6-Sol

# Process Lasso 18.2.3.42: tab-strip HiDPI follow-up report

## Scope and build lock

This is a static, read-only analysis of the authorized `ProcessLasso.exe` on host `zclank`. I read
`patch.py` and `ProcessLasso_GUI_MAP.md` in full before tracing these sites. I did not modify the
executable and did not run the patcher.

- PE: x64 PE32+, preferred image base `0x140000000`, `DYNAMIC_BASE`
- expected and observed SHA-256:
  `3bfdbad16ddf47e2e9d303294c9f6de90eb90f6856bc0126e27bc1bd30e4e884`
- `.hidpi` RVA/VA: `0x280000` / preferred `0x140280000`
- `.text` conversion used below: `file_offset = RVA - 0x0c00`
- `nm -C ProcessLasso.exe` reports no symbols; names below are descriptive patch names

The recommended changes are:

1. Hook the main `SystemParametersInfoW(SPI_GETNONCLIENTMETRICS)` call at RVA `0x04c855` and route
   it through a new `.hidpi+0x0820` wrapper. Obtain DPI from the already-live notification HWND at
   `app+0x878`, then call `SystemParametersInfoForDpi` with that DPI. This reuses all existing
   resolver strings and helpers.
2. Make each magnifying-glass `Static` square by setting its width equal to its computed inner
   height (`client_height - 4`) and moving its left edge to keep it right-aligned. The existing
   `SS_REALSIZECONTROL` style then scales the square HICON into a square destination instead of the
   current 16-by-taller-than-16 rectangle. This uses two small, call-free layout trampolines plus one
   equal-length in-place width store; no DPI helper is needed.

All injected control transfers and data references in the proposed font wrapper are rel32 or
RIP-relative. It contains no preferred-VA immediate and needs no `.hidpi` base relocation.

## Problem A: DPI-scale the main UI font

### Font construction and lifecycle

The containing initializer begins at RVA `0x04c750` and ends at `0x04d62a`. Its exception metadata
is `(begin=0x04c750, end=0x04d62a, unwind=0x202718)`; `objdump -p` identifies the parent unwind
record as version 1 with `UNW_FLAG_UHANDLER`.

The relevant code is:

```asm
14004c82c  c7 45 70 f8 01 00 00     mov dword ptr [rbp+0x70],0x1f8
14004c844  45 33 c9                 xor r9d,r9d
14004c847  4c 8d 45 70              lea r8,[rbp+0x70]
14004c84b  ba f8 01 00 00           mov edx,0x1f8
14004c850  b9 29 00 00 00           mov ecx,0x29            ; SPI_GETNONCLIENTMETRICS
14004c855  ff 15 6d 34 18 00        call qword ptr [rip+0x18346d]
                                                            ; IAT 0x1401cfcc8, SystemParametersInfoW
14004c85b  0f 10 85 88 00 00 00    movups xmm0,[rbp+0x88]  ; ncm+0x18, lfCaptionFont
             ...                    ; copy LOGFONTW to [rbp+0x10]
14004c8a8  48 8d 4d 10              lea rcx,[rbp+0x10]
14004c8ac  ff 15 16 29 18 00        call qword ptr [rip+0x182916]
                                                            ; IAT 0x1401cf1c8, CreateFontIndirectW
14004c8b2  48 89 83 c8 04 00 00     mov [rbx+0x4c8],rax     ; main UI HFONT
```

The requested hook slice is therefore:

| Item | Value |
|---|---:|
| Hook RVA | `0x04c855` |
| Raw file offset | `0x04bc55` |
| Original bytes | `ff 15 6d 34 18 00` |
| Original instruction | `call qword ptr [rip+0x18346d]` |
| Original continuation | RVA `0x04c85b` |

The main HWND is too late for this hook:

```asm
14004c9ff  ff 15 9b 31 18 00        call qword ptr [rip+0x18319b] ; CreateWindowExW
14004ca05  48 89 83 70 08 00 00     mov [rbx+0x870],rax
```

Static xrefs do not show a later opportunity to rebuild this font:

- RVA `0x0db999` is the only direct call found to `0x04c750`.
- Apart from constructor zero-initialization at `0x04b832`, the only substantive write found to this
  app object's `+0x4c8` is the `CreateFontIndirectW` result at `0x04c8b2`.
- No path found recreates `app+0x4c8` for `WM_DPICHANGED`.

This means “wait until `app+0x870` exists” is not a viable solution without designing a separate
font-recreation path.

### A usable HWND does exist: `app+0x878`

The caller creates/obtains a current-process hidden notification window before it invokes the main
initializer:

```asm
1400db900  e8 6b e1 ff ff           call 0x1400d9a70
             ...
1400db988  48 8b 05 49 f9 14 00     mov rax,[rip+0x14f949] ; global 0x14022b2d8
1400db98f  48 89 83 78 08 00 00     mov [rbx+0x878],rax
1400db996  48 8b cb                 mov rcx,rbx
1400db999  e8 b2 0d f7 ff           call 0x14004c750
```

If global `0x14022b2d8` is initially null, function `0x0d9a70` creates the window at `0x0d9b29`.
The class and title strings are `ProcessLasso_Notification_Class` and
`ProcessLasso_Notification_Window`. Its WndProc receives the created HWND in `r15` and records it
during `WM_CREATE`:

```asm
1400d8401  4c 89 3d d0 2e 15 00     mov [rip+0x152ed0],r15 ; global 0x14022b2d8
```

The subsequent load/store at `0x0db988..0x0db98f` therefore gives `app+0x878` a live HWND before the
font query. A hidden window remains a valid input to `GetDpiForWindow`.

### DPI-source decision

| Candidate | Result |
|---|---|
| `GetDpiForWindow(app+0x870)` | Reject: `+0x870` is still null at `0x04c855`. |
| Re-run/rebuild later | Reject for this minimal patch: only one direct initializer call and no later `+0x4c8` rebuild were found. |
| `GetDpiForSystem()` | Viable, but needs another dynamic API-name string/resolution path and is sensitive to the calling thread's DPI-awareness context. |
| `GetDpiForWindow(app+0x878)` | Recommended: the HWND is already live and it reuses the existing `get_dpi` helper and fallback. |

`GetDpiForSystem` would be a reasonable fallback design if runtime inspection disproves the
notification-window assumption. It returns the actual system DPI to a DPI-aware thread (and 96 to
an unaware thread), per Microsoft's
[`GetDpiForSystem` documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdpiforsystem).
That alternative would require adding the ASCII string `GetDpiForSystem\0`; the recommended design
does not add a string.

The recommended choice deliberately provides startup/system-monitor scaling rather than live
per-monitor font rebuilding. That satisfies the stated requirement and will make this shared font
larger app-wide. Correctly changing the font again when the main window crosses monitors would
require a `WM_DPICHANGED` recreation-and-redistribution design, which is separate from this hook.

### Proposed `patch.py` additions

The existing last assembly block ends at `.hidpi+0x0816`; the current `HIDPI_CODE_SIZE = 0x900`
already has room for this `0x91`-byte block at `+0x0820..+0x08b1`.

```python
HIDPI_SYMBOL_OFFSETS = {
    # existing entries ...
    "main_system_parameters_info": 0x0820,
}

PATCH_SITES = {
    # existing entries ...
    "main_system_parameters_info": (
        0x04C855,
        bytes.fromhex("ff156d341800"),
    ),
}

UNWIND_PARENT_MAIN_INIT = (0x04C750, 0x04D62A, 0x202718)
```

The `AssemblyBlock` is intentionally the same call shape and size as the existing graph
`system_parameters_info` block:

```python
AssemblyBlock(
    "main_system_parameters_info",
    0x0820,
    0x08B1,
    r"""
sub rsp, 0x60
mov dword ptr [rsp + 0x30], ecx
mov qword ptr [rsp + 0x38], rdx
mov qword ptr [rsp + 0x40], r8
mov qword ptr [rsp + 0x48], r9
mov rcx, qword ptr [rbx + 0x878]          # live notification HWND
call 0x140280000                          # rel32 call to get_dpi
mov dword ptr [rsp + 0x50], eax
lea rcx, [rip - 0x45e]                    # L"user32.dll" at .hidpi+0x03f0
call qword ptr [rip - 0xb1134]            # IAT GetModuleHandleW, RVA 0x1cf720
test rax, rax
je fallback
mov rcx, rax
lea rdx, [rip - 0x3b1]                    # "SystemParametersInfoForDpi" at +0x04b2
call qword ptr [rip - 0xb1131]            # IAT GetProcAddress, RVA 0x1cf738
test rax, rax
je fallback
mov ecx, dword ptr [rsp + 0x30]
mov rdx, qword ptr [rsp + 0x38]
mov r8, qword ptr [rsp + 0x40]
mov r9, qword ptr [rsp + 0x48]
mov r10d, dword ptr [rsp + 0x50]
mov dword ptr [rsp + 0x20], r10d          # fifth arg: dpi
call rax                                  # address returned by GetProcAddress
jmp done
fallback:
mov ecx, dword ptr [rsp + 0x30]
mov rdx, qword ptr [rsp + 0x38]
mov r8, qword ptr [rsp + 0x40]
mov r9, qword ptr [rsp + 0x48]
call qword ptr [rip - 0xb0be0]            # IAT SystemParametersInfoW, RVA 0x1cfcc8
done:
add rsp, 0x60
jmp 0x14004c85b                           # rel32 jump to original continuation
""",
),
```

The source-level numeric destinations on the two direct `call`/`jmp` lines are assembled as rel32;
they are not loaded into a register or embedded as 64-bit addresses. The dynamically returned API
pointer in `rax` is also ASLR-safe because it comes from `GetProcAddress` at runtime.

Add chained unwind coverage:

```python
("main_system_parameters_body", 0x0820, 0x08A8, 0x60, UNWIND_PARENT_MAIN_INIT),
("main_system_parameters_tail", 0x08A8, 0x08B1, 0x00, UNWIND_PARENT_MAIN_INIT),
```

The first range covers the outstanding `sub rsp,0x60`; the tail starts at the balancing
`add rsp,0x60`.

### Fifth argument and stack shape

At the original hook, the first four arguments are already in `rcx`, `rdx`, `r8`, and `r9`:

```text
uiAction = 0x29
uiParam  = 0x1f8
pvParam  = &NONCLIENTMETRICS
fWinIni  = 0
```

The wrapper saves those registers, obtains/saves DPI, restores the four original arguments, then
writes DPI to `[rsp+0x20]`, the Windows x64 ABI slot for argument five, immediately before
`call rax`. `SystemParametersInfoForDpi` explicitly accepts that fifth DPI argument and supports
`SPI_GETNONCLIENTMETRICS`; see Microsoft's
[`SystemParametersInfoForDpi` documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfofordpi).
The fallback restores the same four arguments and calls the original four-argument
`SystemParametersInfoW` IAT entry.

`sub rsp,0x60` supplies shadow/local space and preserves the call-site alignment because it is a
multiple of 16. The existing `get_dpi` helper preserves nonvolatile registers and returns 96 if the
HWND/API resolution is unavailable.

### Explicit ASLR displacement audit

The hook replacement itself is:

```text
hook next RVA       = 0x04c855 + 5 = 0x04c85a
trampoline RVA      = 0x280820
rel32               = 0x280820 - 0x04c85a = +0x233fc6
replacement bytes   = e9 c6 3f 23 00 90
```

Every injected in-module reference is calculated from the next instruction's RIP:

| Instruction | Next RVA | Target RVA | Calculation | disp32 bytes |
|---|---:|---:|---:|---|
| `call get_dpi` at `.hidpi+0x083e` | `0x280843` | `0x280000` | `0x280000 - 0x280843 = -0x843` | `bd f7 ff ff` |
| `lea user32` at `+0x0847` | `0x28084e` | `0x2803f0` | `0x2803f0 - 0x28084e = -0x45e` | `a2 fb ff ff` |
| IAT `GetModuleHandleW` at `+0x084e` | `0x280854` | `0x1cf720` | `0x1cf720 - 0x280854 = -0xb1134` | `cc ee f4 ff` |
| `lea` SPI-for-DPI name at `+0x085c` | `0x280863` | `0x2804b2` | `0x2804b2 - 0x280863 = -0x3b1` | `4f fc ff ff` |
| IAT `GetProcAddress` at `+0x0863` | `0x280869` | `0x1cf738` | `0x1cf738 - 0x280869 = -0xb1131` | `cf ee f4 ff` |
| fallback IAT `SystemParametersInfoW` at `+0x08a2` | `0x2808a8` | `0x1cfcc8` | `0x1cfcc8 - 0x2808a8 = -0xb0be0` | `20 f4 f4 ff` |
| final `jmp` at `+0x08ac` | `0x2808b1` | `0x04c85b` | `0x04c85b - 0x2808b1 = -0x234056` | `aa bf dc ff` |

The loader adds the same ASLR slide to source and target, so each difference remains invariant.
There is no `mov reg,0x140...` and no need for `.hidpi` relocations.

### What receives this font

The patch changes the `LOGFONTW` used to create `app+0x4c8`. The setup path explicitly sends that
HFONT with `WM_SETFONT` (`0x30`) to:

```asm
14005008d  mov rcx,[rdi+0x8d0]   ; upper SysTabControl32
1400500ac  mov rcx,[rdi+0x8a8]   ; lower SysTabControl32
1400500cb  mov rcx,[rdi+0x970]   ; upper Edit
1400500ea  mov rcx,[rdi+0x940]   ; lower Edit
```

It also sends it to `+0x920`, `+0x790`, `+0x798`, and `+0x7a0`, so some incidental app-wide font
growth is expected and acceptable under the task requirements. A larger tab font also lets the
native, non-owner-drawn tab items use the new vertical space.

One uncertainty should be retained in the implementation review: this explicit `WM_SETFONT` run
does **not** visibly include the six overlaid Button HWND fields (`+0x900`, `+0x8f8`, `+0x9a0`,
`+0x958`, `+0x968`, `+0x8c8`). They may obtain suitable theme/default fonts by another path, but
that is not proven by the font-send sequence above. Before claiming that the font hook fixes every
button caption, compare `WM_GETFONT` for those HWNDs against `app+0x4c8` at runtime. If they differ
and the captions remain small, the direct follow-up is to send `WM_SETFONT(app+0x4c8, TRUE)` to
those live buttons after creation. That is independent of the SPI hook.

## Problem B: magnifying-glass aspect ratio

### Control ownership and paint path

The magnifying glass is not rendered by the executable's GDI+ stretch call. Each Edit contains a
native `Static` child that owns a shell stock search HICON:

| Bar | Edit creation / field | Edit subclass | Icon Static creation / field | Control ID |
|---|---|---|---|---:|
| Lower | RVA `0x04e0d8`, `app+0x940` | RVA `0x0e9330` | RVA `0x04e274`, `app+0x9b0` | `0x87f9` |
| Upper | RVA `0x04e165`, `app+0x970` | RVA `0x0e94b0` | RVA `0x04e2cd`, `app+0x9a8` | `0x87fa` |

Both Edits are class `Edit`, style `0x52800080`, and are subclassed with `SetWindowSubclass` at
`0x04e113` / `0x04e1a0`. Their subclass procedures handle keyboard/notification/color behavior,
but `WM_PAINT` (`0x000f`) goes to `DefSubclassProc`; neither procedure draws the glass.

The stock icon helper is RVA `0x107c90`:

```asm
140107cca  c7 44 24 20 20 02 00 00  mov dword ptr [rsp+0x20],0x220 ; cbSize
140107cd2  ba 01 01 00 00           mov edx,0x101 ; SHGSI_ICON | SHGSI_SMALLICON
140107cd7  8b cb                    mov ecx,ebx   ; SHSTOCKICONID
140107cd9  ff 15 f1 7b 0c 00        call qword ptr [rip+0xc7bf1]
                                                         ; SHGetStockIconInfo, IAT 0x1401cf8d0
140107ce1  48 0f 44 7c 24 28        cmove rdi,[rsp+0x28] ; HICON
```

It is called with `ecx=0x16` (`SIID_FIND`) at RVA `0x04e06f`, and the returned HICON is stored at
`app+0x4d0`. That same handle is installed into both Statics with `STM_SETIMAGE` (`0x170`) at
`0x04e2e9` and `0x04e305`:

```asm
14004e2dd  4c 8b 87 d0 04 00 00     mov r8,[rdi+0x4d0]
14004e2e4  ba 70 01 00 00           mov edx,0x170
14004e2e9  48 8b 8f b0 09 00 00     mov rcx,[rdi+0x9b0]
14004e2f0  ff 15 3a 1a 18 00        call qword ptr [rip+0x181a3a] ; SendMessageW
             ...
14004e2f9  4c 8b 87 d0 04 00 00     mov r8,[rdi+0x4d0]
14004e300  ba 70 01 00 00           mov edx,0x170
14004e305  48 8b 8f a8 09 00 00     mov rcx,[rdi+0x9a8]
14004e30c  ff 15 1e 1a 18 00        call qword ptr [rip+0x181a1e] ; SendMessageW
```

There is no subclass installed on either Static, so native Static-control painting is the final draw
path.

### Why `GdipDrawImageRectI` is unrelated

The sole executable call to IAT `0x1401cfee8` is:

```asm
14005fb68  8b 8d fc 03 00 00        mov ecx,[rbp+0x3fc] ; height
14005fb6e  8b 95 f8 03 00 00        mov edx,[rbp+0x3f8] ; width
14005fb74  48 8b 85 10 04 00 00     mov rax,[rbp+0x410] ; GDI+ image wrapper
             ...
14005fb8c  45 8b cf                 mov r9d,r15d         ; y
14005fb8f  45 8b c5                 mov r8d,r13d         ; x
14005fb92  48 8b d6                 mov rdx,rsi           ; image
14005fb95  48 8b cf                 mov rcx,rdi           ; graphics
14005fb98  ff 15 4a 03 17 00        call qword ptr [rip+0x17034a]
                                                         ; GdipDrawImageRectI
```

| Item | Value |
|---|---:|
| Call RVA | `0x05fb98` |
| Raw file offset | `0x05ef98` |
| Original bytes | `ff 15 4a 03 17 00` |
| Containing helper | RVA `0x05fa30` |
| Caller found | RVA `0x05e60a`, inside graph renderer `0x05be30..0x05e8ef` |

Its source object is a graph-renderer member at `+0x410`, and the only direct call xref found is in
the graph render path. It has no xref to the Edit/Static HWND fields or the `SIID_FIND` HICON. It
should not be patched for this problem.

### Exact Static styles

The two `Static` children are created with identical style immediates:

```asm
14004e262  41 b9 43 09 00 50        mov r9d,0x50000943 ; lower, parent app+0x940
14004e274  ff 15 26 19 18 00        call [CreateWindowExW]
             ...
14004e2bb  41 b9 43 09 00 50        mov r9d,0x50000943 ; upper, parent app+0x970
14004e2cd  ff 15 cd 18 18 00        call [CreateWindowExW]
```

The low style bits are:

```text
0x003  SS_ICON
0x040  SS_REALSIZECONTROL
0x100  SS_NOTIFY
0x800  SS_REALSIZEIMAGE
```

There is no `SS_CENTERIMAGE` (`0x200`). Microsoft's
[`Static Control Styles` documentation](https://learn.microsoft.com/en-us/windows/win32/controls/static-control-styles)
specifies that `SS_REALSIZECONTROL` stretches/shrinks an icon to the control rectangle when
`SS_CENTERIMAGE` is absent, allowing the X and Y dimensions to change independently. With
`SS_CENTERIMAGE`, the icon is centered without resizing and can be clipped if larger than the
control.

### Exact destination-size computation

The upper layout queries the enlarged Edit client and positions `app+0x9a8` as follows:

```asm
1400511be  48 8b 8f 70 09 00 00     mov rcx,[rdi+0x970]
1400511c9  ff 15 d1 ea 17 00        call [GetClientRect]
1400511cf  8b 45 98                 mov eax,[rbp-0x68]   ; right
1400511d2  44 8b 4d 94              mov r9d,[rbp-0x6c]   ; top
1400511d6  ff c8                    dec eax              ; right-1
1400511de  41 83 c1 02              add r9d,2            ; y=top+2
1400511e9  44 8d 40 f0              lea r8d,[rax-0x10]   ; x=(right-1)-16
1400511ed  8b 45 9c                 mov eax,[rbp-0x64]   ; bottom
1400511f0  83 c0 fe                 add eax,-2           ; bottom-2
140051200  41 2b c1                 sub eax,r9d          ; cy=client height-4
140051220  89 44 24 28              mov [rsp+0x28],eax   ; cy
140051224  c7 44 24 20 10 00 00 00  mov [rsp+0x20],0x10 ; cx=16
14005122c  ff 15 56 e9 17 00        call [SetWindowPos]  ; HWND app+0x9a8
```

The lower layout does the same for `app+0x9b0`, deriving the same fixed width via subtraction:

```asm
1400519a9  48 8b 09                 mov rcx,[rcx]        ; app+0x940
1400519b0  ff 15 ea e2 17 00        call [GetClientRect]
1400519b6  8b 4d 98                 mov ecx,[rbp-0x68]   ; right
1400519bd  ff c9                    dec ecx              ; right-1
1400519bf  8b 45 9c                 mov eax,[rbp-0x64]   ; bottom
1400519c2  41 83 c1 02              add r9d,2            ; y=top+2
1400519c6  83 c0 fe                 add eax,-2           ; bottom-2
1400519d6  44 8d 41 f0              lea r8d,[rcx-0x10]   ; x=(right-1)-16
1400519e7  41 2b c1                 sub eax,r9d          ; cy=client height-4
1400519ea  41 2b c8                 sub ecx,r8d          ; cx=16
140051a07  89 44 24 28              mov [rsp+0x28],eax   ; cy
140051a0b  89 4c 24 20              mov [rsp+0x20],ecx   ; cx
140051a16  ff 15 6c e1 17 00        call [SetWindowPos]  ; HWND app+0x9b0
```

The build-locked bytes and raw offsets for the decisive size instructions are:

| Bar / role | RVA | Raw offset | Original bytes | Meaning |
|---|---:|---:|---|---|
| Upper x | `0x0511e9` | `0x0505e9` | `44 8d 40 f0` | right-align a fixed 16 px width |
| Upper height | `0x051200` | `0x050600` | `41 2b c1` | `cy = client height - 4` |
| Upper width | `0x051224` | `0x050624` | `c7 44 24 20 10 00 00 00` | `cx = 16` |
| Lower x | `0x0519d6` | `0x050dd6` | `44 8d 41 f0` | right-align a fixed 16 px width |
| Lower height | `0x0519e7` | `0x050de7` | `41 2b c1` | `cy = client height - 4` |
| Lower width | `0x0519ea` | `0x050dea` | `41 2b c8` | `cx = 16` |

At 96 DPI, the 22-pixel Edit cell yields an inner icon rectangle approximately 16 pixels high, so
the 16-pixel width is square. After the bar patch, the Edit cell bottom is
`MulDiv(22,dpi,96)`—33 pixels at 144 DPI—while the icon width remains exactly 16. `GetClientRect`
sees the taller Edit and `cy=client_height-4` grows, but `cx` does not. The native Static then obeys
`SS_REALSIZECONTROL` and stretches the square HICON independently into the roughly 16-by-29
destination. That is the direct cause of the horizontal squish.

### Why changing only the Static style is insufficient

Adding `SS_CENTERIMAGE` would stop distortion, but it is not robust here. `SHGSI_SMALLICON` selects
the icon using the `SM_CXSMICON`/`SM_CYSMICON` system metrics, as documented for
[`SHGetStockIconInfo`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shgetstockiconinfo),
and those dimensions may exceed 16 at elevated DPI. The Static would still be only 16 pixels wide,
so a centered native-size HICON could be clipped horizontally. Removing `SS_REALSIZECONTROL` has
the same size mismatch. The minimal robust fix is to make the destination square while retaining
the existing stretch behavior.

### Recommended square-geometry patch

Use the already-computed `cy = client_height - 4` as both dimensions, then recompute
`x = (right - 1) - cy`. The Edit width is unchanged; only the right-aligned icon child grows inward
by the same amount its height grew. The HICON is drawn into a square rectangle, so the existing
native `SS_REALSIZECONTROL` path cannot change its aspect ratio.

The font block proposed above ends at `.hidpi+0x08b1`. Both call-free geometry blocks fit inside the
existing `HIDPI_CODE_SIZE = 0x900`:

```python
HIDPI_SYMBOL_OFFSETS.update({
    "upper_search_icon_square": 0x08C0,
    "lower_search_icon_square": 0x08E0,
})

PATCH_SITES.update({
    "upper_search_icon_square": (
        0x051200,
        bytes.fromhex("412bc1782d"),       # sub eax,r9d; js 0x140051232
    ),
    "lower_search_icon_square": (
        0x0519E7,
        bytes.fromhex("412bc1412bc8"),     # sub eax,r9d; sub ecx,r8d
    ),
})
```

Upper block, `.hidpi+0x08c0..+0x08df` (31 bytes):

```python
AssemblyBlock(
    "upper_search_icon_square",
    0x08C0,
    0x08DF,
    r"""
sub eax, r9d                               # side = client bottom-2 - (top+2)
js 0x140051232                             # preserve original invalid-height exit
mov r8d, dword ptr [rdi + 0xc18]           # right-1 cached at 0x0511d8
sub r8d, eax                               # x = (right-1) - side
mov dword ptr [rdi + 0xc10], r8d           # replace fixed-16 cached x
jmp 0x140051205                            # resume with original coordinate tests
""",
),
```

The upper `SetWindowPos` still has a separate fixed-width stack store. Replace it in place with the
square side left live in `eax`:

```python
"upper_search_icon_width": (
    0x051224,
    bytes.fromhex("c744242010000000"),
    "mov dword ptr [rsp + 0x20], eax\n" + "\n".join("nop" for _ in range(4)),
),
```

That reassembles to the equal-length replacement bytes
`89 44 24 20 90 90 90 90`.

Lower block, `.hidpi+0x08e0..+0x08fd` (29 bytes):

```python
AssemblyBlock(
    "lower_search_icon_square",
    0x08E0,
    0x08FD,
    r"""
sub eax, r9d                               # side = client bottom-2 - (top+2)
mov r8d, dword ptr [rdi + 0xc28]           # right-1 cached at 0x0519c9
sub r8d, eax                               # x = (right-1) - side
mov dword ptr [rdi + 0xc20], r8d           # replace fixed-16 cached x
mov ecx, eax                               # SetWindowPos cx = cy = side
test ecx, ecx                              # recreate SF consumed by original js
jmp 0x1400519ed                            # original validity tests and SetWindowPos
""",
),
```

The complete hook-site table is:

| Site | RVA | Raw offset | Original bytes | Replacement bytes |
|---|---:|---:|---|---|
| Upper geometry hook | `0x051200` | `0x050600` | `41 2b c1 78 2d` | `e9 bb f6 22 00` |
| Upper width store | `0x051224` | `0x050624` | `c7 44 24 20 10 00 00 00` | `89 44 24 20 90 90 90 90` |
| Lower geometry hook | `0x0519e7` | `0x050de7` | `41 2b c1 41 2b c8` | `e9 f4 ee 22 00 90` |

Both hooks replace whole instructions. The lower trampoline returns with `eax=ecx=side`, `r8d=x`,
and flags from `test ecx,ecx`, exactly matching the values/negative-width condition expected at the
original `js` at `0x0519ed`. The upper trampoline explicitly performs the overwritten negative-
height branch, then returns at `0x051205` with `eax=side` and the corrected `r8d=x`.

Add call-free chained ranges under the existing `UNWIND_PARENT_MAIN_LAYOUT`:

```python
("upper_search_icon_square", 0x08C0, 0x08DF, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
("lower_search_icon_square", 0x08E0, 0x08FD, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
```

No stack adjustment or call occurs in either block.

The B-side rel32 audit is:

| Instruction | Next RVA | Target RVA | Calculation | disp32 bytes |
|---|---:|---:|---:|---|
| Upper hook `jmp` | `0x051205` | `0x2808c0` | `0x2808c0 - 0x051205 = +0x22f6bb` | `bb f6 22 00` |
| Upper trampoline `js` at `+0x08c3` | `0x2808c9` | `0x051232` | `0x051232 - 0x2808c9 = -0x22f697` | `69 09 dd ff` |
| Upper return `jmp` at `+0x08da` | `0x2808df` | `0x051205` | `0x051205 - 0x2808df = -0x22f6da` | `26 09 dd ff` |
| Lower hook `jmp` | `0x0519ec` | `0x2808e0` | `0x2808e0 - 0x0519ec = +0x22eef4` | `f4 ee 22 00` |
| Lower return `jmp` at `+0x08f8` | `0x2808fd` | `0x0519ed` | `0x0519ed - 0x2808fd = -0x22ef10` | `f0 10 dd ff` |

These are all rel32 differences between module RVAs. There are no IAT/data references and no
absolute VA. The loader's ASLR slide cancels from every difference.

At these layout points, `app+0x970` (upper Edit) and `app+0x940` (lower Edit) are live HWNDs suitable
for the existing `get_dpi` helper; the outer tab HWNDs `+0x8d0` and `+0x8a8` are live as well. The
recommended geometry derives its side directly from each Edit's actual client rectangle and needs
no DPI call.

## Residual uncertainties and targeted runtime checks

1. **Initial DPI source:** break at the new `+0x0820` block and verify `app+0x878 != NULL` and that
   `GetDpiForWindow(app+0x878)` matches the desired startup DPI at 100/150/200%. If it does not,
   switch to a dynamic `GetDpiForSystem` resolver using the new ASCII name noted above.
2. **No live font rebuild:** set an API breakpoint on `CreateFontIndirectW` at `0x04c8ac` or a data
   breakpoint on `app+0x4c8`, then drag the main window between monitors. Static analysis predicts
   one startup creation and no update on `WM_DPICHANGED`.
3. **Button font ownership:** query `WM_GETFONT` on all six overlaid Button HWNDs and compare with
   `app+0x4c8`. If the values differ and the captions are still small, add explicit `WM_SETFONT`
   sends after button creation.
4. **Square Static result:** at 125/150/200%, inspect both `app+0x9a8` and `app+0x9b0`. Confirm
   `client_width == client_height`, the right edge remains anchored, the glass is undistorted, and
   the enlarged child does not cover Edit text. If its visual size is still wrong, trace a
   DPI-appropriate stock-icon acquisition while keeping the destination square.
