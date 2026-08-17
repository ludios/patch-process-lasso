# Process Lasso 18.2.3.42 x64 — GUI / rendering reverse-engineering map

This is a build-specific map of the rendering, layout, custom-control, graph, and GUI-settings code discovered while making the Per-Monitor-V2 HiDPI patch.

The purpose is to let a future reverse-engineering session begin from known anchors instead of rediscovering the GUI from scratch. Addresses below are for the **original, unmodified** executable unless explicitly stated otherwise.

## Build identity

| Item | Value |
|---|---|
| Product version | `18.2.3.42` |
| Architecture | PE32+, x86-64 |
| Preferred image base | `0x140000000` |
| Original `ProcessLasso.exe` SHA-256 | `3bfdbad16ddf47e2e9d303294c9f6de90eb90f6856bc0126e27bc1bd30e4e884` |
| `pl_rsrc_english.dll` SHA-256 | `6018d6c6fd52687d8dea853a06195ac389493afd814d311f773c9eb4c3e576ae` |

Do not assume these addresses survive an update. Prefer the re-identification recipes near the end of this document.

### Confidence notation

- **Confirmed** — directly established from instructions, window-class registration/creation, settings-load code, or API call semantics.
- **Strong inference** — structure/function role is clear, but a human-readable original symbol/name is unavailable.
- **Tentative** — useful lead that still needs another xref or runtime observation before patching against it.

## PE layout and address conventions

Original sections:

| Section | RVA / VMA | Raw file offset | Raw/virtual size |
|---|---:|---:|---:|
| `.text` | `0x001000` / `0x140001000` | `0x000400` | `0x1cdbb4` |
| `.rdata` | `0x1cf000` / `0x1401cf000` | `0x1ce000` | `0x53282` |
| `.data` | `0x223000` / `0x140223000` | `0x221400` | `0x6600` |
| `.pdata` | `0x230000` / `0x140230000` | `0x227a00` | `0xd1b8` |
| `.fptable` | `0x23e000` / `0x14023e000` | `0x234c00` | `0x100` |
| `.rsrc` | `0x23f000` / `0x14023f000` | `0x234e00` | `0x3e340` |
| `.reloc` | `0x27e000` / `0x14027e000` | `0x273200` | `0x1348` |

For `.text` in this build:

```text
file_offset = RVA - 0x1000 + 0x400
            = RVA - 0x0c00
```

Use RVAs, not preferred VAs, when correlating profiler results. ASLR can move the module at runtime.

The original Authenticode certificate is a terminal file overlay beginning at raw offset `0x274600`. The HiDPI patcher deliberately replaces that no-longer-valid signature blob with a new RX `.hidpi` section at RVA `0x280000`.

The original RT_MANIFEST resource-data entry is at raw file offset `0x235970`; it originally describes manifest data at RVA `0x27cf08`, size `0x433`.

---

# Fast orientation: start with these functions

| Role | RVA | Preferred VA | Raw file offset | Confidence |
|---|---:|---:|---:|---|
| Main GUI/control creation region | `0x04dcb0` | `0x14004dcb0` | `0x04d0b0` | Confirmed |
| Top graph height helper | `0x050870` | `0x140050870` | `0x04fc70` | Strong inference |
| Main-window layout function | `0x0509f0` | `0x1400509f0` | `0x04fdf0` | Confirmed by control positioning |
| Top usage-graph renderer | `0x05be30` | `0x14005be30` | `0x05b230` | Confirmed |
| Process-list subclass proc | `0x0e9140` | `0x1400e9140` | `0x0e8540` | Confirmed by installation |
| Tab-control subclass proc | `0x0e9630` | `0x1400e9630` | `0x0e8a30` | Confirmed by installation |
| Top graph subclass proc | `0x0e9be0` | `0x1400e9be0` | `0x0e8fe0` | Confirmed |
| CPU-core graph WndProc | `0x0fc710` | `0x1400fc710` | `0x0fbb10` | Confirmed by class registration |
| CPU-core graph create/init | `0x0fc960` | `0x1400fc960` | `0x0fbd60` | Confirmed |
| Load-display label subclass proc | `0x0177b0` | `0x1400177b0` | `0x016bb0` | Confirmed by installation |
| Load-display composite layout | `0x017810` | `0x140017810` | `0x016c10` | Confirmed |
| Load-display show/hide | `0x017a20` | `0x140017a20` | `0x016e20` | Confirmed |
| Load-display redraw | `0x017a70` | `0x140017a70` | `0x016e70` | Confirmed |
| Load-value setter | `0x017a90` | `0x140017a90` | `0x016e90` | Confirmed |
| Load-value getter | `0x017aa0` | `0x140017aa0` | `0x016ea0` | Confirmed |
| Load-display brush rebuild | `0x017ab0` | `0x140017ab0` | `0x016eb0` | Confirmed |
| `Bitsum_LoadDisplay` WndProc | `0x15fdf0` | `0x14015fdf0` | `0x15f1f0` | Confirmed |
| `LoadBarsClassName` WndProc | `0x15ff90` | `0x14015ff90` | `0x15f390` | Confirmed |
| Load-display tooltip setup | `0x160220` | `0x140160220` | `0x15f620` | Strong inference |

If a profile shows a hot `ProcessLasso.exe+0x...` address, compare its RVA against this table first.

---

# Main application / GUI object

A large application-state object is used throughout these paths. The top graph renderer receives it directly; a global pointer to it is read from `0x14022b358` in the graph subclass proc.

The same object contains HWNDs, persistent graph settings, runtime GUI flags, layout coordinates, colors, and graph-history containers.

## Known GUI fields

Offsets are relative to this main/app object.

| Offset | Meaning | Confidence / evidence |
|---:|---|---|
| `+0x580` | CPU-core-utilization graph object | Confirmed: `lea r15,[rdi+0x580]`, then registered/initialized as `Bitsum_CPUCoreUtilizationGraph` |
| `+0x790` | First `Bitsum_LoadDisplay` composite object | Confirmed: passed to creation/layout/show helpers |
| `+0x810` | Second fixed load-display object/handle region | Strong inference from main-layout calls |
| `+0x870` | Main/root HWND | Confirmed: parent of major controls; passed to `GetClientRect` |
| `+0x880` | Top usage-graph HWND | Confirmed: created as `Static`, subclassed with `0x1400e9be0` |
| `+0x888` | Main process-list `SysListView32` HWND | Confirmed |
| `+0x8a8` | Lower command-bar `SysTabControl32` HWND | Confirmed: created `0x04e047`, subclassed `0x0e9c60` |
| `+0x8b8` | Bottom `msctls_statusbar32` HWND (10 parts) | Confirmed: created `0x04e46d`; `SB_SETPARTS` at `0x04e48f` |
| `+0x8d0` | Upper command-bar / main `SysTabControl32` HWND | Confirmed |
| `+0x920` | Child `Static` under top graph | Confirmed |
| `+0x940` | GUI/control HWND used by graph-subclass command routing | Strong inference |
| `+0x9b0` | HWND receiving forwarded messages in graph-related subclass code | Strong inference |
| `+0x9c0` | Main content/layout left coordinate | Strong inference |
| `+0x9c4` | Main content/layout top coordinate | Strong inference |
| `+0x9c8` | Mutable right edge available to graph/fixed widgets | Strong inference; central to HiDPI fixes |
| `+0x9cc` | Adjacent cached boundary used by graph/layout | Strong inference |
| `+0x9d8` | Original/right-side boundary used while placing fixed displays | Strong inference |
| `+0xad0..+0xafc` | Cached fixed-load-display geometry | Strong inference |
| `+0x4c10..+0x4c18` | Graph-history vector-ish storage; renderer indexes records of size `0x68` | Strong inference |

The main object is large enough that an automatically reconstructed structure is worthwhile. In Ghidra/IDA, create a partial struct and add only fields with good evidence; do not assume unobserved gaps.

---

# Persistent graph settings: exact object offsets

These mappings are especially useful because they are anchored by literal configuration-key strings and explicit stores in the settings load path around `0x140124e20..0x140125545`.

| Config key | Main/app object field | Load-path evidence |
|---|---:|---:|
| `ShowGraphResponsiveness` | byte `+0x3215` | store at `0x140125081` |
| `ShowGraphCPU` | byte `+0x3216` | store at `0x14012502a` |
| `ShowGraphProBalanceEvents` | byte `+0x3217` | store at `0x14012512f` |
| `ShowGraphMemoryLoad` | byte `+0x3218` | store at `0x1401250d8` |
| `ShowGraphLegend` | byte `+0x3219` | store at `0x140124ec7` |
| `GraphShowTooltips` | byte `+0x321a` | store at `0x140124f1e` |
| `ShowGraphSelectedProcessesCPUHistory` | byte `+0x321b` | store at `0x140125186` |
| `ShowGraphGPU` | byte `+0x321c` | store at `0x1401251dd` |
| `GraphGPUShowAllLines` | byte `+0x3230` | store at `0x14012530d` |
| `GraphGPUCombinedWidget` | byte `+0x3231` | store at `0x140125368` |
| `GPUCollectMode` | dword `+0x3234` | store at `0x1401253d3`; clamped to `0..2` |
| `GraphAntiAliasing` | byte `+0x3238` | store at `0x140125436` |
| `ShowCPUCoreUtilGraphs` | byte `+0x3239` | store at `0x140124fcc` |
| `ProBalanceCountersOnGraph` | byte `+0x323a` | store at `0x14012548d` |
| `ShowGraphLicenseName` | byte `+0x323b` | store at `0x1401254e8` |
| `ShowPowerProfile` | byte `+0x3240` | store at `0x14012553f` |

There is a corresponding serialization/export path around `0x14011d6f9..0x14011dc54` that reads the same fields and references the same strings. When porting to a new build, finding both the load and save xrefs is a good sanity check.

`ShowGraphLicenseName` is the setting used by **Graph Components → Licensee Name**. Its built-in default is false. The earlier hard-force patch modified the loader result immediately before the `mov byte ptr [rdi+0x323b],al`, but using the UI setting is preferable.

---

# Main GUI/control creation (`0x14004dcb0`)

This function is one of the best places to orient a fresh reverse-engineering session. It contains long runs of `CreateWindowExW`, followed by stores of returned HWNDs into `[rdi+offset]`, and then subclass installation.

Known examples:

| Creation site | Class | Parent | Stored field | Subclass proc |
|---:|---|---|---:|---:|
| `0x14004dd21` | `Static` @ `0x1401e3b50` | main `+0x870` | `+0x880` | `0x1400e9be0` |
| `0x14004dda1` | `SysTabControl32` @ `0x1401e3b60` | main `+0x870` | `+0x8d0` | `0x1400e9630` |
| `0x14004de0f` | `Static` | graph `+0x880` | `+0x920` | none seen here |
| `0x14004de64` | `SysListView32` @ `0x1401e3b80` | main `+0x870` | `+0x888` | `0x1400e9140` |
| `0x14004dedd` | `SysListView32` | main `+0x870` | `+0x988` | follows immediately afterward |

The calls at IAT `0x1401cf128` and `0x1401cf130` are COMCTL32 ordinal imports corresponding to `SetWindowSubclass` and `DefSubclassProc`, respectively. This makes subclass-proc discovery much easier than treating those IAT slots as unknown functions.

### Re-identification trick

After an update, search for the sequence:

```text
CreateWindowExW(..., L"Static", ...)
store HWND into a large object's field
SetWindowSubclass(hwnd, callback, 0, 0)
```

The top graph is distinctive because its window is also copied to global `0x14022b148` in this build.

---

# Top usage graph

## Window/subclass path

The top graph HWND is main object `+0x880`.

Its subclass procedure is `0x1400e9be0`. The important path is unusually clean:

```text
WM_PAINT (0x000f)
  BeginPaint(hwnd, &ps)
  renderer(main_app_object, paint_hdc, global_byte_at_0x14022b0d3)
  EndPaint(hwnd, &ps)
  DefSubclassProc(...)
```

Concrete instructions:

```asm
0x1400e9bff  cmp  edx,0x0f
0x1400e9c09  call [BeginPaint]
0x1400e9c0f  movzx r8d,byte ptr [0x14022b0d3]
0x1400e9c1a  mov rcx,qword ptr [0x14022b358]
0x1400e9c21  call 0x14005be30
0x1400e9c2e  call [EndPaint]
0x1400e9c54  jmp  [DefSubclassProc]
```

This is the strongest single anchor for rediscovering the renderer after an update: find the subclass proc installed on the top `Static`, then follow its `WM_PAINT` call.

The following function at `0x1400e9c60` handles additional graph-related messages/commands, including `WM_ERASEBKGND` (`0x14`), command routing (`0x111`), and custom/menu message handling. It is adjacent but is **not** the paint bridge above.

## Renderer (`0x14005be30 .. 0x14005e8ef`)

This is the large top usage-chart/dashboard renderer.

Confirmed/high-value observations:

- It receives the main/app object in `RCX` and an HDC in `RDX`.
- It checks GUI state and graph-component flags before drawing each series/overlay.
- It uses both classic GDI and GDI+.
- GDI+ calls include `GdipDrawCurve2I`, `GdipFillRectangleI`, and smoothing-mode manipulation.
- Text/font work uses `CreateFontIndirectW`, `DrawTextW`/text APIs, colors, and brushes.
- It maintains/caches graph fonts globally at `0x14022d558` and `0x14022d560` after deriving a `LOGFONT` from non-client metrics.
- The original font setup calls `SystemParametersInfoW(SPI_GETNONCLIENTMETRICS=0x29, cbSize=0x1f8, ...)` at `0x14005bf46`.
- The HiDPI patch redirects that site to `SystemParametersInfoForDpi`, using the graph window's current DPI when available.
- Historical graph samples are traversed as records of size `0x68` from vector-like state around main object `+0x4c10..+0x4c18`.
- Literal 10-pixel horizontal/sample/grid spacing appears in this renderer (for example around `0x14005c859`). That spacing was **not** part of the current HiDPI patch and is a candidate if graph density ever looks physically wrong.

Runtime draw flags observed directly inside this renderer include bytes at main object `+0x415d`, `+0x4160`, and `+0x4163`. Their exact semantic mapping to named persistent settings has not been proven here; do not equate them blindly with the `+0x321x` persistent config fields.

### Current HiDPI renderer hooks

| Purpose | RVA | Original bytes / role |
|---|---:|---|
| DPI-aware non-client metrics | `0x05bf46` | replaces call through `SystemParametersInfoW` IAT |
| Dashboard/card rectangle geometry | `0x05d59c` | scales original `5`, `22`, `15`, `22`-ish pixel literals |
| Dashboard/card text offsets | `0x05d61c` | scales original `13` and `17` pixel offsets |

If a future build changes the dashboard cards but preserves the general renderer, search near the text-drawing path for small literal offsets clustered immediately before rectangle/text API calls.

---

# Main layout (`0x1400509f0 .. 0x1400521be`)

This function positions the top graph, fixed GPU/RAM-style displays, CPU-core graph, tabs/list views, and other main-window children.

At entry it obtains the client rectangle of main HWND `+0x870` and calls the graph-height helper at `0x140050870`.

The HiDPI work established an important invariant in the original layout:

```text
fixed display width = 60 px
inter-widget gap    =  5 px
reserved slot       = 65 px
minimum threshold   = 100 + 60 = 160 px
```

The first patch scaled the 60-pixel child windows without scaling the 65-pixel upstream reservations, producing the CPU/GPU overlap seen at HiDPI. The v2 patch scales the entire set coherently.

## Original geometry sites

| Site | Original logical meaning |
|---:|---|
| RVA `0x050a36` | outer/main graph margin, 5 px |
| RVA `0x050a72` | fixed-display reservation #1: test 160-ish availability, reserve 65 px |
| RVA `0x050ab2` | fixed-display reservation #2: same |
| RVA `0x050ad4` | reserve/check 100 px before fitting graph |
| RVA `0x050adc` | graph-to-neighbor gap, 5 px |
| RVA `0x050b2e` | first fixed display width, 60 px |
| RVA `0x050b4e` | first fixed display X = right - 60; then calls `0x140017810` on `main+0x790` |
| RVA `0x050c1e` | 5 px gap before second fixed display |
| RVA `0x050c35` | second fixed display X = right - 60 |
| RVA `0x050c4d` | second fixed display width, 60 px |
| RVA `0x050cf3` | CPU/core graph neighbor gap, 5 px |

Two additional values written before the first composite layout call are `158` and `5` at main object `+0xa48` and `+0xa40`. Their exact semantic names remain unresolved; treat them as leads, not patch targets.

## Graph-height helper (`0x140050870 .. 0x1400509f0`)

This helper derives a top-graph/dashboard height from processor topology/count information. It contains count-dependent constants roughly equivalent to:

- smaller topology: `22`
- medium topology: `14`
- large topology: `10`
- a later minimum based on a `60`-pixel term

The current HiDPI patch hooks the final `cmp/cmovb` at RVA `0x0509dd` and DPI-scales the resulting height, rather than rewriting every internal branch constant.

A useful re-find signature is the tail containing an `imul ..., 0x3c` (`60`) followed shortly by `cmp eax,ecx` / `cmovb eax,ecx`.

---

# `Bitsum_LoadDisplay` and vertical load bars

These custom controls are the most useful anchors for the CPU/GPU/RAM-style bar region.

## Class strings

| String | Raw string offset | Preferred VA |
|---|---:|---:|
| `Bitsum_LoadDisplay` | `0x1dd030` | `0x1401de030` |
| `LoadBarsClassName` | `0x1dd058` | `0x1401de058` |

They are registered around `0x14004e940..0x14004ea80`:

- `Bitsum_LoadDisplay` WndProc = `0x14015fdf0`
- `LoadBarsClassName` WndProc = `0x14015ff90`

The first composite is created around `0x14004eae7..0x14004ec5b`, using main object `+0x790` as its state structure.

## Composite state structure at `main+0x790`

Known layout:

| Offset within composite | Meaning | Confidence |
|---:|---|---|
| `+0x00` | wrapper `Bitsum_LoadDisplay` HWND | Confirmed |
| `+0x08` | `Button` child HWND used for label/text | Confirmed |
| `+0x10` | `LoadBarsClassName` child HWND | Confirmed |
| `+0x18` | tooltip HWND | Strong inference from `0x140160220` |
| `+0x20` | string-like tooltip text storage | Strong inference |
| `+0x40` | HBRUSH created from color `+0x64` | Confirmed |
| `+0x48` | HBRUSH created from color `+0x68` | Confirmed |
| `+0x50` | HBRUSH created from color `+0x6c` | Confirmed |
| `+0x58` | HBRUSH created from color `+0x70` | Confirmed |
| `+0x64` | COLORREF | Confirmed |
| `+0x68` | COLORREF | Confirmed |
| `+0x6c` | COLORREF | Confirmed |
| `+0x70` | COLORREF | Confirmed |
| `+0x74` | current load percentage, DWORD | Confirmed |

`0x140017ab0` rebuilds the four brushes and associates one with the wrapper/load-bars class.

`0x140017a90` is a compact setter:

```asm
mov eax,dword ptr [rcx+0x74]   ; old value
mov dword ptr [rcx+0x74],edx   ; new percentage
ret
```

`0x140017aa0` simply returns `[rcx+0x74]`.

## Composite layout helper (`0x140017810`)

This helper positions all three HWNDs.

High-level flow:

1. Position wrapper HWND `+0x00` with `SetWindowPos`.
2. `GetClientRect(wrapper)`.
3. Stretch/position label child `+0x08`.
4. Measure label/font metrics using its DC/current font.
5. Position bar child `+0x10` beneath/adjacent to the text.

There are still literal `20` and `10` pixel values in this helper (around `0x1400178c5`, `0x1400178d6`, `0x1400178e2`, `0x14001797b`, `0x1400179ae`, etc.). They were not required for the current visual fix, but are high-value candidates if internal load-display spacing looks wrong at another DPI.

Other helpers:

- `0x140017a20(struct,bool)` — `ShowWindow` on HWNDs at `+0`, `+8`, and `+0x10`.
- `0x140017a70(struct)` — redraw wrapper with `RedrawWindow(..., flags=0x181)`.
- `0x140160220(...)` — tooltip creation/configuration for the composite.

## Actual bar paint path (`LoadBarsClassName` WndProc `0x14015ff90`)

`WM_PAINT` lands at `0x140160028`.

The paint path is worth remembering for performance work because it performs classic per-paint software double-buffering:

```text
GetWindowLongPtrW(hwnd, 0) -> composite state
GetClientRect(hwnd)
BeginPaint
CreateCompatibleDC(paint_hdc)
CreateCompatibleBitmap(paint_hdc, width, height)
SelectObject(bitmap)
filled_height = height * state->load_percent / 100
FillRect(bottom portion, brush state+0x40)
FillRect(top portion,    brush state+0x50)
BitBlt(memory_dc -> paint_hdc)
restore object
DeleteObject(bitmap)
DeleteDC(memory_dc)
EndPaint
```

The percentage calculation is visible at `0x1401600a9..0x1401600dc` and reads `state+0x74`.

**Performance lead:** the DC and compatible bitmap are allocated/deallocated on every `WM_PAINT`. If WPR/WPA points at `0x14015ff90..0x14016017d`, this allocation pattern is an obvious optimization candidate (persistent backbuffer, DIB section, or direct fill depending on flicker requirements).

The wrapper `Bitsum_LoadDisplay` WndProc at `0x14015fdf0` handles state setup, control-color/background behavior, notifications, and delegation. The child `LoadBarsClassName` proc is the direct vertical-bar painter.

---

# Tab-strip command bars (upper / lower)

The two horizontal "button bars" are **not** status bars: they are two `SysTabControl32`
composites, each a native tab strip (a couple of left-hand tab items) with named `Button`
children overlaid on the right. They are the widgets that render too short at HiDPI because their
height is a hardcoded logical-pixel constant in the main layout, never DPI-scaled.

| Bar | Outer `SysTabControl32` | Creation | HWND field | Overlaid `Button` children (ID / HWND field) |
|---|---|---:|---:|---|
| Upper (above process list) | tabs `All processes` / `Active processes` | `0x04dda1` | `+0x8d0` | Show/Hide graph `0x9de2`/`+0x900`, Edit Rules `0x890d`/`+0x8f8`, Pause `0x8077`/`+0x9a0` (Edit `+0x970`) |
| Lower (below the list region) | tab `Actions log` | `0x04e047` | `+0x8a8` | View Log `0x870b`/`+0x958`, Insights `0x8718`/`+0x968`, Buy Now `0x0fa4`/`+0x8c8` (conditional) (Edit `+0x940`, Static `+0x9b0`) |

`+0x8b8` is the genuine bottom `msctls_statusbar32` (10 parts, `SBARS_SIZEGRIP`) and is unrelated
to these bars. The `SB_SETMINHEIGHT`-looking send at `0x0fe2a3` is actually `PBM_GETPOS` in a
progress-bar subclass — a message-number collision (`0x408`), not a status-bar height set.

## Height sites in main layout (all logical px, un-scaled in the original)

| RVA | Original | Meaning |
|---:|---|---|
| `0x050da8` | `lea eax,[r9+0x20]` → `mov [rdi+0xa6c],eax` | upper strip bottom = y + **32**; `+0xa6c` feeds the process-list top |
| `0x050dce` | `mov [rsp+0x28],0x20` | upper strip `cy` = **32** (SetWindowPos, HWND `+0x8d0`) |
| `0x050e50` | `mov [rdi+0xbac],0x16` | upper child cell bottom = **22** (Edit `+0x970`) |
| `0x050e8e` | `mov [rdi+0xacc],0x16` | upper child cell bottom = **22** (`+0x900`; propagated to Edit Rules/Pause via `+0xab4..+0xabc` / `+0xc04..+0xc0c`) |
| `0x0518bc` | `lea eax,[r9+0x20]` → `mov [rdi+0xa14],r9d` (cached y) | lower strip bottom = y + **32**; `+0xa1c` (next store) feeds downstream |
| `0x0518e3` | `mov [rsp+0x28],0x20` | lower strip `cy` = **32** (SetWindowPos, HWND `+0x8a8`) |
| `0x05192d` / `0x051bb5` / `0x051dc5` / `0x051ff4` | `mov [rdi+0x{b4c,b7c,b9c,a5c}],0x16` | lower child cell bottoms = **22** (Edit/View Log/Insights/Buy Now) |

Each child `SetWindowPos.cy` is computed as `rectangle_bottom - rectangle_top`, so scaling the
`0x16` bottom stores scales every child cell. The tabs are **not** `TCS_OWNERDRAWFIXED` and no
`TCM_SETITEMSIZE`/`TCM_SETPADDING` is sent; the native tab item sizes to its font, but the outer
window is still clamped by the explicit `cy=32`. (`0x0e9a67` sends `TCM_HITTEST` `0x130d`, not
`TCM_SETPADDING` — that message is `0x132b`.)

The HiDPI patch scales `32` and `22` by `MulDiv(·, dpi, 96)`: two trampolines (`upper_bar_height`
at `0x050da8`, `lower_bar_height` at `0x0518bc`) call a shared `bar_metrics` helper, keep the scaled
32 live in `r10d` for the patched `cy` stores, and pre-write the scaled 22 into the child-bottom
fields so the original `0x16` stores can be NOP'd. See the patch-site map below.

## Search boxes and the magnifying-glass icons

Each strip's search box is a native `Edit` (upper `app+0x970`, lower `app+0x940`, class `Edit`,
style `0x52800080`, subclassed at `0x0e94b0` / `0x0e9330`). The magnifying glass is a **child
`Static`** (upper `app+0x9a8` created `0x04e2cd`, lower `app+0x9b0` created `0x04e274`, style
`0x50000943` = `SS_ICON|SS_REALSIZECONTROL|SS_NOTIFY|SS_REALSIZEIMAGE`). Both hold the `SIID_FIND`
shell stock icon (`SHGetStockIconInfo` helper at `0x107c90`, HICON cached at `app+0x4d0`, installed
with `STM_SETIMAGE` at `0x04e2e9`/`0x04e305`). Because the style lacks `SS_CENTERIMAGE`,
`SS_REALSIZECONTROL` stretches the square HICON to the control rect. The layout gives that rect a
fixed `cx=16` but a height of `client_height-4`; once the Edit cell height is DPI-scaled the rect
becomes tall-and-narrow and the glass squishes. The `*_search_icon_square` patches recompute the
right-aligned x from cached `right-1` (`app+0xc18` upper / `app+0xc28` lower) and set `cx = cy`.
The GDI+ `GdipDrawImageRectI` (`0x05fb98`) is the *graph* image draw and is unrelated to the glass.

## Main-UI font (`app+0x4c8`)

Built once during init at `0x04c855` (`SystemParametersInfoW(SPI_GETNONCLIENTMETRICS)` →
`CreateFontIndirectW` on `lfCaptionFont`), stored at `app+0x4c8`, and distributed by `WM_SETFONT`
around `0x050082` to the tabs (`+0x8d0`/`+0x8a8`), search Edits (`+0x970`/`+0x940`), `+0x920`, and
the fixed load displays (`+0x790`/`+0x798`/`+0x7a0`/`+0x810`). It was **not** DPI-scaled, so the bar
text stayed 96-DPI-small. `main_system_parameters_info` redirects `0x04c855` to
`SystemParametersInfoForDpi` using the DPI of the hidden notification window `app+0x878` (the main
window `app+0x870` is created later at `0x04ca05`, so it is null at font-build time). The app has no
`WM_DPICHANGED` handler and never rebuilds this font, so this provides startup/system-DPI scaling.

# CPU-core utilization graph

Class string:

```text
Bitsum_CPUCoreUtilizationGraph
```

- raw string offset: `0x1ea428`
- preferred VA: `0x1401eb428`

The class is registered around `0x14004eefa..0x14004ef65` with WndProc `0x1400fc710`.

Main app object `+0x580` is passed as the CPU-core graph object. Initialization calls:

```text
0x1400fc960(object = main+0x580, parent = main+0x870)
0x1400fd5b0(object)
```

`0x1400fc960` creates the `Bitsum_CPUCoreUtilizationGraph` child HWND and stores it at graph-object `+0x170`.

The WndProc `0x1400fc710` handles standard window messages plus custom messages around `0x8001..0x8003`. It uses state retrieved from window/class extra bytes and routes updates into helpers around `0x1400fd110`, `0x1400fd1e0`, and `0x140100050`.

The main layout function later positions/hides this object using helpers around:

- `0x1400fcef0` — positioning/layout path
- `0x1400fd5b0` — initialize/prepare/refresh path
- `0x1400fd6d0` — hide/disable-like path

A related format string at `0x1401eb468` is:

```text
Node %u, Logical CPU %u
```

If the CPU-core visualization needs more reverse engineering, start in `0x1400fc710..0x140100xxx` and follow custom-message handlers rather than looking only for a conventional `WM_PAINT` branch.

---

# Graph/menu/resource breadcrumbs

Many GUI strings are in `pl_rsrc_english.dll`, not directly beside the rendering code. Useful raw UTF-16 string offsets in that DLL:

| String | Raw offset |
|---|---:|
| `Show Graph` | `0x756a2` |
| `Graph Components` | `0x756ba` |
| `CPU Core Graphs` | `0x756e0` |
| `Graph Legend` | `0x7570a` |
| `CPU Use` | `0x7572e` |
| `Memory Load` | `0x75782` |
| `GPU Use` | `0x7579e` |
| `System Responsiveness` | `0x7584e` |
| `Licensee Name` | `0x758d8` |
| `Graph: Background` | `0x75b48` |
| `Graph: Grid` | `0x75b70` |
| `Graph: Text` | `0x75b8c` |
| `Graph: CPU` | `0x75ba8` |
| `Graph: Responsiveness` | `0x75bc2` |
| `Graph: Memory` | `0x75bf2` |
| `Graph: GPU Utilization` | `0x75c52` |
| `Graph Anti-Aliasing` | `0x75d8c` |
| `Processor Use` | `0x1dd76c` |
| `Responsiveness` | `0x1dd788` |
| `Memory Load` | `0x1dd7a6` |
| `GPU Use` | `0x1ddca2` |

Useful config-key strings in the EXE itself cluster around raw offsets `0x1ed558..0x1ed7f8`:

```text
ShowGraphResponsiveness
ShowGraphCPU
ShowGraphLegend
ShowCPUCoreUtilGraphs
ShowGraphGPU
ShowGraphSelectedProcessesCPUHistory
ShowGraphProBalanceEvents
ShowGraphMemoryLoad
GPUCollectMode
GraphGPUCombinedWidget
GraphGPUShowAllLines
ShowPowerProfile
ShowGraphLicenseName
ProBalanceCountersOnGraph
GraphAntiAliasing
```

String xrefs are generally more update-resistant than byte signatures.

---

# Relevant imported APIs / IAT landmarks

These addresses are IAT slots in the original build, not function VAs in system DLLs.

## USER32 / COMCTL32

| IAT VA | API / role |
|---:|---|
| `0x1401cf128` | COMCTL32 ordinal 410 — `SetWindowSubclass` |
| `0x1401cf130` | COMCTL32 ordinal 413 — `DefSubclassProc` |
| `0x1401cfa08` | `MoveWindow` |
| `0x1401cfa60` | `ShowWindow` |
| `0x1401cfa68` | `GetWindowLongPtrW` |
| `0x1401cfa78` | `GetClassLongPtrW` |
| `0x1401cfb78` | `GetDC` |
| `0x1401cfb80` | `IsWindowVisible` |
| `0x1401cfb88` | `SetWindowPos` |
| `0x1401cfb98` | `FillRect` |
| `0x1401cfba0` | `CreateWindowExW` |
| `0x1401cfbc8` | `RegisterClassExW` |
| `0x1401cfca0` | `GetClientRect` |
| `0x1401cfcb0` | `DrawTextW` |
| `0x1401cfcc8` | `SystemParametersInfoW` |
| `0x1401cfce8` | `InvalidateRect` |
| `0x1401cfd08` | `BeginPaint` |
| `0x1401cfd10` | `EndPaint` |
| `0x1401cfd28` | `SetWindowLongPtrW` |
| `0x1401cfd30` | `SendMessageW` |

## GDI32

| IAT VA | API |
|---:|---|
| `0x1401cf168` | `BitBlt` |
| `0x1401cf170` | `CreateCompatibleBitmap` |
| `0x1401cf178` | `SelectObject` |
| `0x1401cf180` | `CreateCompatibleDC` |
| `0x1401cf1a0` | `DeleteDC` |
| `0x1401cf1a8` | `TextOutW` |
| `0x1401cf1b0` | `GetTextExtentPoint32W` |
| `0x1401cf1b8` | `SetBkMode` |
| `0x1401cf1c0` | `DeleteObject` |
| `0x1401cf1c8` | `CreateFontIndirectW` |
| `0x1401cf1d8` | `SetTextColor` |
| `0x1401cf1e8` | `CreateSolidBrush` |

## GDI+

Notable IAT slots include:

```text
0x1401cfed8  GdipCreateFromHDC
0x1401cfef0  GdipDrawCurve2I
0x1401cff00  GdipFillRectangleI
0x1401cfe88  GdipSetSmoothingMode
```

Xrefs to these calls are a productive way to enumerate custom renderers.

## HiDPI patch helper imports

The patcher did **not** add a new import directory. Its `.hidpi` helper dynamically resolves modern USER32 routines via existing imports:

```text
0x1401cf720  GetModuleHandleW
0x1401cf738  GetProcAddress
0x1401cf688  MulDiv
```

It resolves `GetDpiForWindow` and `SystemParametersInfoForDpi` at runtime and falls back conservatively if unavailable.

---

# Current HiDPI patch-site map

These are the build-lock sites in `patch_process_lasso_hidpi.py`. They are useful landmarks even if a future session does not use the patcher.

| Name | RVA | What it fixes |
|---|---:|---|
| `graph_height` | `0x0509dd` | DPI-scale computed top-graph height |
| `main_margins` | `0x050a36` | DPI-scale 5px outer layout margins |
| `fixed_load_reservation_1` | `0x050a72` | scale 160px threshold and 65px reservation |
| `fixed_load_reservation_2` | `0x050ab2` | same for second fixed display |
| `graph_threshold` | `0x050ad4` | scale 100px graph minimum reservation |
| `graph_gap` | `0x050adc` | scale 5px graph gap |
| `load1_width` | `0x050b2e` | scale 60px fixed-display width |
| `load1_x` | `0x050b4e` | use scaled width in right-aligned X calculation |
| `load2_gap` | `0x050c1e` | scale 5px inter-display gap |
| `load2_x` | `0x050c35` | use scaled width for second display X |
| `upper_bar_height` | `0x050da8` | scale upper tab-strip 32px height + its 22px child cells |
| `lower_bar_height` | `0x0518bc` | scale lower tab-strip 32px height + its 22px child cells |
| `processor_gap` | `0x050cf3` | scale 5px CPU/core-neighbor gap |
| `system_parameters_info` | `0x05bf46` | use `SystemParametersInfoForDpi` for graph font metrics |
| `card_rect` | `0x05d59c` | scale dashboard/card rectangle offsets |
| `card_text` | `0x05d61c` | scale dashboard/card text offsets |
| `main_system_parameters_info` | `0x04c855` | DPI-scale the main-UI font (`SystemParametersInfoForDpi`, HWND `app+0x878`) |
| `upper_search_icon_square` | `0x051200` | make the upper search-glass `Static` square (right-aligned) |
| `lower_search_icon_square` | `0x0519e7` | make the lower search-glass `Static` square (right-aligned) |

`PATCH_SITES` are `jmp`-into-`.hidpi` trampolines. A second group, `INPLACE_PATCH_SITES`, rewrites
sites in place with equal-length assembly instead of jumping:

| Name | RVA | What it does |
|---|---:|---|
| `load2_width` | `0x050c4d` | reuse the scaled width already in `r10d` |
| `upper_bar_cy` | `0x050dce` | `mov [rsp+0x28],r10d` (scaled 32) for SetWindowPos |
| `lower_bar_cy` | `0x0518e3` | same for the lower strip |
| `upper_child_bac` / `upper_child_acc` | `0x050e50` / `0x050e8e` | NOP the 22px stores (trampoline pre-writes scaled) |
| `lower_child_{b4c,b7c,b9c,a5c}` | `0x05192d` / `0x051bb5` / `0x051dc5` / `0x051ff4` | NOP the 22px stores |
| `upper_search_icon_width` | `0x051224` | `mov [rsp+0x20],eax` (square side) instead of fixed 16px cx |

The patched `.hidpi` section is at RVA `0x280000` (`HIDPI_CODE_SIZE` is now `0xa00`). Symbol offsets:

```text
+0x0000  get_dpi helper
+0x0050  graph_height
+0x0090  main_margins
+0x0100  graph_threshold
+0x0160  graph_gap
+0x01c0  load1_width
+0x0200  load1_x
+0x0220  load2_x
+0x02e0  card_rect
+0x0380  card_text
+0x0420  system_parameters_info
+0x04e0  fixed_load_reservation_1
+0x0580  fixed_load_reservation_2
+0x0620  load2_gap
+0x0680  processor_gap
+0x0700  bar_metrics helper (returns scaled 32 in eax, scaled 22 in edx)
+0x0760  upper_bar_height
+0x07b0  lower_bar_height
+0x0820  main_system_parameters_info (main-UI font DPI redirect)
+0x08c0  upper_search_icon_square
+0x08e0  lower_search_icon_square
```

`bar_metrics` has its own standalone `RUNTIME_FUNCTION` (like `get_dpi`); the bar-height and
`main_system_parameters_info` trampolines chain body/suffix into their function's parent
(`UNWIND_PARENT_MAIN_LAYOUT` and `UNWIND_PARENT_MAIN_INIT` respectively); the call-free search-icon
trampolines chain into `UNWIND_PARENT_MAIN_LAYOUT` with no stack frame.

The injected x86-64 is authored as Intel-syntax assembly and assembled by the GNU binutils toolchain (`as`, `ld`, `objcopy`). Original hook-site bytes are retained as immutable build fingerprints.

---

# Performance-oriented map

When profiling rendering with WPR/WPA, the following ranges are the first ones worth recognizing.

## `0x05be30..0x05e8ef` — top usage graph

Potential cost characteristics:

- wide-area GDI+/GDI drawing;
- curve drawing and fills every graph repaint;
- sample traversal proportional to visible/history width;
- text/cards/legend work in same large renderer;
- HiDPI increases physical pixel area considerably.

If the top chart is the bottleneck, split CPU samples by offsets within this function before changing anything. A hot GDI+ child frame does not necessarily mean the whole renderer needs rewriting; identify the exact calling block.

## `0x15ff90..0x16017d` — fixed load-bar painter

Particularly suspicious because each `WM_PAINT` does:

```text
CreateCompatibleDC
CreateCompatibleBitmap
SelectObject
FillRect x2
BitBlt
DeleteObject
DeleteDC
```

If this range is hot, caching the backing surface is the obvious first experiment.

## `0x017810..0x017a1c` — load-display layout/text measurement

This obtains a DC and measures text while laying out the composite. It should normally be a resize/layout cost, not a constant repaint cost. If it is unexpectedly hot during idle graph updates, investigate who is repeatedly relaying out the controls.

## `0x0fc710..0x100xxx` — CPU-core graph/update path

Use custom-message xrefs (`0x8001..0x8003`) to distinguish update traffic from rendering work.

## Mapping an unsymbolized WPA sample

If WPA gives:

```text
ProcessLasso.exe+0x5c123
```

that `0x5c123` is already the useful RVA. Disassemble around:

```sh
objdump -d -M intel \
  --start-address=0x14005c0e0 \
  --stop-address=0x14005c180 \
  ProcessLasso.exe
```

If a debugger gives an absolute runtime address instead, subtract the runtime module base first; do not subtract the preferred base unless ASLR happened to leave it unchanged.

---

# How to rediscover this map after a Process Lasso update

Prefer semantic anchors in this order.

## 1. Fingerprint the new build first

Record:

```sh
sha256sum ProcessLasso.exe pl_rsrc_english.dll
objdump -h ProcessLasso.exe
```

Never reuse an old raw offset merely because a nearby function looks similar.

## 2. Find custom class strings

```sh
strings -el -t x ProcessLasso.exe | grep -E \
  'Bitsum_LoadDisplay|LoadBarsClassName|Bitsum_CPUCoreUtilizationGraph'
```

Convert each string to a VA via the PE section table, then find RIP-relative xrefs.

- xref passed into `RegisterClassExW` gives the WndProc;
- xref passed into `CreateWindowExW` gives creation/object-field code.

This is the best route back to the fixed load displays and CPU-core graph.

## 3. Recover the top usage graph from GUI creation

Find `CreateWindowExW` calls for a `Static` child followed by a `SetWindowSubclass` call. Identify the one stored in the main object and used near the top of the layout.

Follow its subclass proc's `WM_PAINT` branch:

```text
BeginPaint -> one large internal call -> EndPaint
```

That internal call is the usage-graph renderer.

## 4. Recover graph settings from config-key strings

```sh
strings -el -t x ProcessLasso.exe | grep -E \
  'ShowGraph|GraphGPU|GraphAntiAliasing|ProBalanceCountersOnGraph'
```

Find each string's load-path xref, then look shortly after the parse/compare call for:

```asm
sete al
mov byte ptr [object + OFFSET], al
```

This recovers named fields with very high confidence. Cross-check against the serialization path that reads `[object+OFFSET]` and references the same key.

## 5. Recover main layout from HWND field xrefs

Once the top graph HWND and load-display object offsets are known, find a function that:

- calls `GetClientRect(main_hwnd)`;
- calls `SetWindowPos` repeatedly;
- references graph HWND + load-display fields + CPU-core graph object;
- contains the characteristic fixed-display geometry around `60`, `65`, `100`, `160`, and `5`.

That is the main layout function.

## 6. Find rendering code by API xrefs

Good API anchors:

```text
BeginPaint / EndPaint
GdipDrawCurve2I
GdipFillRectangleI
BitBlt
CreateCompatibleBitmap
FillRect
CreateFontIndirectW
DrawTextW / TextOutW
```

The combination of class-string xrefs and graphics-API xrefs is usually much more reliable than binary pattern matching alone.

## 7. Diff old/new functions structurally

Once an old semantic function is identified in the new build, compare:

- called APIs;
- object-field offsets;
- immediate geometry constants;
- nearby class/config/resource-string xrefs;
- control-flow shape.

Only after those agree should an old patch concept be ported.

---

# x64 binary-patching rules learned here

These matter because a GUI patch that “works” can still be structurally broken.

1. **Build-lock everything.** Verify the complete original SHA-256 and every overwritten instruction sequence.
2. **Patch whole instructions only.** Never land a jump in the middle of an instruction.
3. **Respect Microsoft x64 volatile registers.** Calls can clobber `RAX`, `RCX`, `RDX`, `R8`, `R9`, `R10`, `R11`, and XMM volatile registers. Several layout hooks have live coordinates across the hook point.
4. **Maintain 16-byte stack alignment before calls** and reserve the required 32-byte shadow space.
5. **Do not ignore unwind metadata.** Injected code that adjusts `RSP`, saves nonvolatile state, or makes calls should have valid `RUNTIME_FUNCTION`/`UNWIND_INFO` coverage if you want exceptions/debuggers/profilers to unwind correctly.
6. **Do not create RWX sections.** The current `.hidpi` section is RX.
7. **Expect Authenticode invalidation.** Any binary modification invalidates the vendor signature.
8. **Avoid adding imports when dynamic resolution is sufficient.** The current patch uses existing `GetModuleHandleW`/`GetProcAddress` imports for modern DPI APIs.
9. **Prefer semantic assembly over opcode blobs.** Current injected code is assembled with GNU binutils and regression-tested against the previous live machine code.
10. **Treat runtime GUI flags and persisted settings as separate until proven otherwise.** The renderer has runtime flags near `+0x415d`, while named config fields are around `+0x3215`; there may be synchronization/derived-state logic between them.
11. **Never embed an absolute VA in injected code.** The module is `DYNAMIC_BASE`/ASLR (see the manifest and `DllCharacteristics`), and the patcher emits no `.hidpi` relocations. Reach the IAT or any in-module target only via RIP-relative (`call/jmp qword ptr [rip - disp]`, `lea [rip + disp]`) or rel32 (`call/jmp 0x140280xxx`) addressing. An absolute `mov rax, 0x1401cfxxx; call [rax]` keeps the preferred VA after the loader rebases the module, so it faults at runtime — a crash that never appears in a static hash/disassembly check.

Current unwind parents used by the patcher:

```text
RVA 0x050870..0x0509f0  unwind RVA 0x20295c  graph-height helper
RVA 0x0509f0..0x0521be  unwind RVA 0x202978  main layout
RVA 0x05be30..0x05e8ef  unwind RVA 0x20348c  graph renderer
```

The patcher relocates/extends `.pdata` and emits chained unwind metadata for trampoline ranges rather than leaving injected call frames invisible to the Windows unwinder.

---

# Known unresolved areas / good next targets

These are deliberately called out so a future session does not mistake inference for fact.

- Exact semantic names of runtime bytes around main object `+0x415d..+0x4164` are not mapped to the persistent `ShowGraph*` settings yet.
- Main object `+0x4186` controls visibility of the first fixed load-display composite; it is likely the GPU-side widget from layout behavior, but this should be confirmed by tracing the corresponding menu command/state update.
- Main object `+0x4164` participates in visibility of the second fixed display; likely related to RAM/memory display, but confirm before modifying.
- Main object `+0xa40` / `+0xa48` receive literals `5` / `158` near load-display layout; their field meanings are unknown.
- The CPU-core graph's actual hot drawing primitive path has not been fully decomposed; custom-message handlers are the better next entry point than hunting only for `WM_PAINT`.
- The top graph's repeated 10-pixel sample/grid spacing has not been DPI-scaled. It currently looks acceptable but is a known logical-pixel remnant.
- The renderer's `0x68`-byte history record layout has not been field-mapped.
- The six overlaid command **buttons** (`+0x900`, `+0x8f8`, `+0x9a0`, `+0x958`, `+0x968`, `+0x8c8`) are standard `BS_PUSHBUTTON`s (style `0x50000000`) and are **not** in the `WM_SETFONT` distribution at `0x050082`, so they do not receive `app+0x4c8`. Whether the `main_system_parameters_info` font fix enlarges their captions therefore depends on what default font they resolve; if their captions stay small after that patch, the follow-up is to send `WM_SETFONT(app+0x4c8, TRUE)` to those live button HWNDs after creation (needs a runtime `WM_GETFONT` check to confirm).

---

# Minimal tool commands used to build this map

Disassemble a narrow region rather than dumping the whole executable:

```sh
objdump -d -M intel \
  --start-address=0x14005be30 \
  --stop-address=0x14005c000 \
  ProcessLasso.exe
```

Inspect imports/sections:

```sh
objdump -p ProcessLasso.exe
objdump -h ProcessLasso.exe
```

Find UTF-16 strings with raw offsets:

```sh
strings -el -t x ProcessLasso.exe | less
strings -el -t x pl_rsrc_english.dll | less
```

Useful first grep:

```sh
strings -el -t x ProcessLasso.exe | grep -E \
  'Bitsum_|ShowGraph|GraphGPU|GraphAntiAliasing|LoadBars'
```

When a string's preferred VA is known, GNU `objdump` comments RIP-relative references with the resolved target, so a crude xref search is often sufficient:

```sh
objdump -d -M intel ProcessLasso.exe | grep -i '1401ee588'
```

For serious work, import the PE into Ghidra/IDA and rename the anchors in the first table immediately.

---

# Suggested initial renames in a disassembler

These are descriptive names, not recovered vendor symbols:

```text
0x14004dcb0  app_create_main_controls
0x140050870  compute_top_graph_height
0x1400509f0  app_layout_main_window
0x14005be30  render_top_usage_graph
0x1400e9140  process_list_subclass_proc
0x1400e9630  main_tab_subclass_proc
0x1400e9be0  top_graph_subclass_proc
0x1400fc710  cpu_core_graph_wndproc
0x1400fc960  cpu_core_graph_create
0x1400177b0  load_display_label_subclass_proc
0x140017810  load_display_layout
0x140017a20  load_display_show
0x140017a70  load_display_redraw
0x140017a90  load_display_set_value
0x140017aa0  load_display_get_value
0x140017ab0  load_display_rebuild_brushes
0x14015fdf0  load_display_wndproc
0x14015ff90  load_bars_wndproc
0x140160220  load_display_setup_tooltip
```

A future session that establishes a better semantic name should update this document rather than preserving an old guess for compatibility.
