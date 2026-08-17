#!/usr/bin/env python3
# Model-output: Claude Fable 5
# Model-output: GPT-5.6-Sol
"""Patch the exact Process Lasso build supplied on 2026-08-17 for Per-Monitor V2 HiDPI."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

EXPECTED_SHA256 = "3bfdbad16ddf47e2e9d303294c9f6de90eb90f6856bc0126e27bc1bd30e4e884"
EXPECTED_IMAGE_BASE = 0x140000000
EXPECTED_NEW_SECTION_RVA = 0x280000
EXPECTED_CERTIFICATE_OFFSET = 0x274600
MANIFEST_DATA_ENTRY_OFFSET = 0x235970
LEGACY_HIDPI_CODE_SIZE = 0x4CD
HIDPI_CODE_SIZE = 0xA00
HIDPI_CODE_BASE_VA = EXPECTED_IMAGE_BASE + EXPECTED_NEW_SECTION_RVA

USER32_DLL_OFFSET = 0x03F0
GET_DPI_FOR_WINDOW_NAME_OFFSET = 0x0406
SYSTEM_PARAMETERS_INFO_FOR_DPI_NAME_OFFSET = 0x04B2

HIDPI_SYMBOL_OFFSETS = {
    "graph_height":           0x0050,
    "main_margins":           0x0090,
    "graph_threshold":        0x0100,
    "graph_gap":              0x0160,
    "load1_width":            0x01C0,
    "load1_x":                0x0200,
    "load2_x":                0x0220,
    "card_rect":              0x02E0,
    "card_text":              0x0380,
    "system_parameters_info": 0x0420,
    "fixed_load_reservation_1": 0x04E0,
    "fixed_load_reservation_2": 0x0580,
    "load2_gap": 0x0620,
    "processor_gap": 0x0680,
    "upper_bar_height": 0x0760,
    "lower_bar_height": 0x07B0,
    "main_system_parameters_info": 0x0820,
    "upper_search_icon_square": 0x08C0,
    "lower_search_icon_square": 0x08E0,
    "upper_search_margin": 0x0930,
    "lower_search_margin": 0x0970,
}

PATCH_SITES = {
    "graph_height":           (0x0509DD, bytes.fromhex("3bc10f42c1")),
    "main_margins":           (0x050A36, bytes.fromhex("448b4c24444532f6448b4424404183c1058b5424484183c00583c2fb44898fc4090000448be8448987c00900008997c8090000")),
    "graph_threshold":        (0x050AD4, bytes.fromhex("8d419c413bc5")),
    "graph_gap":              (0x050ADC, bytes.fromhex("412bcd83c1fb898fc8090000")),
    "load1_width":            (0x050B2E, bytes.fromhex("41b93c000000")),
    "load1_x":                (0x050B4E, bytes.fromhex("488d8f900700008d50c4")),
    "load2_x":                (0x050C35, bytes.fromhex("8d50c4488b8710080000")),
    "upper_bar_height":       (0x050DA8, bytes.fromhex("418d412089876c0a0000")),
    "lower_bar_height":       (0x0518BC, bytes.fromhex("418d412044898f140a0000")),
    "system_parameters_info": (0x05BF46, bytes.fromhex("ff157c3d1700")),
    "card_rect":              (0x05D59C, bytes.fromhex("8b4c246083c1058b54246483c205448b45c04183c0164403c1458d680f448b4d90440faf4dc44183c1164403ca")),
    "card_text":              (0x05D61C, bytes.fromhex("8b5c246483c30d8b74246083c611")),
    "fixed_load_reservation_1": (0x050A72, bytes.fromhex("8d429c83f83c7e0b83c2bf8997c8090000eb0341b601")),
    "fixed_load_reservation_2": (0x050AB2, bytes.fromhex("8d429c83f83c7e0b8d4abf898fc8090000eb0341b401")),
    "load2_gap":              (0x050C1E, bytes.fromhex("8b87d00a000083e805")),
    "processor_gap":          (0x050CF3, bytes.fromhex("412bc083c20589442420")),
    "main_system_parameters_info": (0x04C855, bytes.fromhex("ff156d341800")),
    "upper_search_icon_square":    (0x051200, bytes.fromhex("412bc1782d")),
    "lower_search_icon_square":    (0x0519E7, bytes.fromhex("412bc1412bc8")),
    "upper_search_margin":         (0x04E177, bytes.fromhex("41b900001000")),
    "lower_search_margin":         (0x04E0EA, bytes.fromhex("41b900001000")),
}

# In-place instruction replacements that do not trampoline into `.hidpi`. Each maps a
# build-locked original slice to assembly that must reassemble to exactly the same length,
# leaving the surrounding code untouched. Unlike `PATCH_SITES`, these do not jump away: they
# either reuse a register that a nearby trampoline leaves live, or NOP a now-dead hardcoded
# store whose field a trampoline has already rewritten with a DPI-scaled value.
_NOP3 = "\n".join("nop" for _ in range(3))
_NOP10 = "\n".join("nop" for _ in range(10))
INPLACE_PATCH_SITES = {
    # Fixed load-display #2 width: reuse the DPI-scaled width already in r10d (from load1_width).
    "load2_width": (0x050C4D, bytes.fromhex("41b93c000000"), "mov r9d, r10d\n" + _NOP3),
    # Outer tab-strip `cy` argument to SetWindowPos: use the scaled 32 its trampoline left in r10d.
    "upper_bar_cy": (0x050DCE, bytes.fromhex("c744242820000000"), "mov dword ptr [rsp + 0x28], r10d\n" + _NOP3),
    "lower_bar_cy": (0x0518E3, bytes.fromhex("c744242820000000"), "mov dword ptr [rsp + 0x28], r10d\n" + _NOP3),
    # Overlaid child-cell heights (originally 22 px). The bar-height trampolines pre-write
    # DPI-scaled values into these fields, so the original constant stores must be neutralized
    # or they would clobber the scaled values back to 22.
    "upper_child_bac": (0x050E50, bytes.fromhex("c787ac0b000016000000"), _NOP10),
    "upper_child_acc": (0x050E8E, bytes.fromhex("c787cc0a000016000000"), _NOP10),
    "lower_child_b4c": (0x05192D, bytes.fromhex("c7874c0b000016000000"), _NOP10),
    "lower_child_b7c": (0x051BB5, bytes.fromhex("c7877c0b000016000000"), _NOP10),
    "lower_child_b9c": (0x051DC5, bytes.fromhex("c7879c0b000016000000"), _NOP10),
    "lower_child_a5c": (0x051FF4, bytes.fromhex("c7875c0a000016000000"), _NOP10),
    # Upper search-icon Static width: use the square side its trampoline leaves live in eax
    # instead of the fixed 16 px, so the stretched HICON keeps a 1:1 aspect ratio.
    "upper_search_icon_width": (0x051224, bytes.fromhex("c744242010000000"), "mov dword ptr [rsp + 0x20], eax\n" + _NOP3 + "\nnop"),
}

UNWIND_PARENT_GRAPH_HEIGHT = (0x050870, 0x0509F0, 0x20295C)
UNWIND_PARENT_MAIN_LAYOUT  = (0x0509F0, 0x0521BE, 0x202978)
UNWIND_PARENT_GRAPH_RENDERER = (0x05BE30, 0x05E8EF, 0x20348C)
UNWIND_PARENT_MAIN_INIT = (0x04C750, 0x04D62A, 0x202718)
UNWIND_PARENT_MAIN_CREATE = (0x04DCB0, 0x050868, 0x202818)

HIDPI_CHAINED_RANGES = (
    ("graph_height_prefix",    0x0050, 0x0055, 0x00, UNWIND_PARENT_GRAPH_HEIGHT),
    ("graph_height_body",      0x0055, 0x007B, 0x30, UNWIND_PARENT_GRAPH_HEIGHT),
    ("graph_height_suffix",    0x007B, 0x0084, 0x00, UNWIND_PARENT_GRAPH_HEIGHT),
    ("main_margins_body",      0x0090, 0x00BF, 0x30, UNWIND_PARENT_MAIN_LAYOUT),
    ("main_margins_suffix",    0x00BF, 0x00F9, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("graph_threshold_body",   0x0100, 0x0142, 0x40, UNWIND_PARENT_MAIN_LAYOUT),
    ("graph_threshold_suffix", 0x0142, 0x0153, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("graph_gap_body",         0x0160, 0x01A2, 0x40, UNWIND_PARENT_MAIN_LAYOUT),
    ("graph_gap_suffix",       0x01A2, 0x01B7, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("load1_width_body",       0x01C0, 0x01F1, 0x30, UNWIND_PARENT_MAIN_LAYOUT),
    ("load1_width_suffix",     0x01F1, 0x01FA, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("load1_x",                0x0200, 0x0211, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("load2_x_body",           0x0220, 0x0261, 0x40, UNWIND_PARENT_MAIN_LAYOUT),
    ("load2_x_suffix",         0x0261, 0x0277, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("card_rect_body",         0x02E0, 0x0345, 0x40, UNWIND_PARENT_GRAPH_RENDERER),
    ("card_rect_suffix",       0x0345, 0x0379, 0x00, UNWIND_PARENT_GRAPH_RENDERER),
    ("card_text_body",         0x0380, 0x03CA, 0x40, UNWIND_PARENT_GRAPH_RENDERER),
    ("card_text_suffix",       0x03CA, 0x03E1, 0x00, UNWIND_PARENT_GRAPH_RENDERER),
    ("system_parameters_body", 0x0420, 0x04A8, 0x60, UNWIND_PARENT_GRAPH_RENDERER),
    ("system_parameters_tail", 0x04A8, 0x04B1, 0x00, UNWIND_PARENT_GRAPH_RENDERER),
    ("fixed_load_reservation_1_body",   0x04E0, 0x054E, 0x40, UNWIND_PARENT_MAIN_LAYOUT),
    ("fixed_load_reservation_1_suffix", 0x054E, 0x0566, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("fixed_load_reservation_2_body",   0x0580, 0x05F6, 0x40, UNWIND_PARENT_MAIN_LAYOUT),
    ("fixed_load_reservation_2_suffix", 0x05F6, 0x0610, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("load2_gap_body",                 0x0620, 0x065C, 0x30, UNWIND_PARENT_MAIN_LAYOUT),
    ("load2_gap_suffix",               0x065C, 0x066A, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("processor_gap_body",             0x0680, 0x06DC, 0x40, UNWIND_PARENT_MAIN_LAYOUT),
    ("processor_gap_suffix",           0x06DC, 0x06EC, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("upper_bar_height_body",          0x0760, 0x078C, 0x30, UNWIND_PARENT_MAIN_LAYOUT),
    ("upper_bar_height_suffix",        0x078C, 0x07AD, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("lower_bar_height_body",          0x07B0, 0x07E6, 0x30, UNWIND_PARENT_MAIN_LAYOUT),
    ("lower_bar_height_suffix",        0x07E6, 0x0816, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("main_system_parameters_body",    0x0820, 0x08A8, 0x60, UNWIND_PARENT_MAIN_INIT),
    ("main_system_parameters_tail",    0x08A8, 0x08B1, 0x00, UNWIND_PARENT_MAIN_INIT),
    ("upper_search_icon_square",       0x08C0, 0x08DF, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("lower_search_icon_square",       0x08E0, 0x08FD, 0x00, UNWIND_PARENT_MAIN_LAYOUT),
    ("upper_search_margin_body",       0x0930, 0x094C, 0x30, UNWIND_PARENT_MAIN_CREATE),
    ("upper_search_margin_tail",       0x094C, 0x0955, 0x00, UNWIND_PARENT_MAIN_CREATE),
    ("lower_search_margin_body",       0x0970, 0x098C, 0x30, UNWIND_PARENT_MAIN_CREATE),
    ("lower_search_margin_tail",       0x098C, 0x0995, 0x00, UNWIND_PARENT_MAIN_CREATE),
)


@dataclass(frozen=True)
class AssemblyBlock:
    """One injected x86-64 routine assembled at a fixed offset.

    Attributes:
        name: Stable symbolic name used by tests and diagnostics.
        offset: Byte offset from the beginning of the `.hidpi` section.
        end_offset: Exclusive byte offset expected after assembly.
        source: Intel-syntax x86-64 assembly. Lines may contain `#` comments.
    """

    name: str
    offset: int
    end_offset: int
    source: str


HIDPI_ASSEMBLY_BLOCKS = (
    AssemblyBlock(
        "get_dpi",
        0x0000,
        0x0043,
        r"""
push rbx
sub rsp, 0x20
mov rbx, rcx
lea rcx, [rip + 0x3e1]                    # L"user32.dll"
call qword ptr [rip - 0xb08f5]            # IAT GetModuleHandleW @ 0x1401cf720
test rax, rax
je fallback
mov rcx, rax
lea rdx, [rip + 0x3e2]                    # "GetDpiForWindow"
call qword ptr [rip - 0xb08f2]            # IAT GetProcAddress @ 0x1401cf738
test rax, rax
je fallback
mov rcx, rbx
call rax                                  # GetDpiForWindow(hwnd)
test eax, eax
jne done
fallback:
mov eax, 0x60                             # USER_DEFAULT_SCREEN_DPI
done:
add rsp, 0x20
pop rbx
ret
""",
    ),
    AssemblyBlock(
        "graph_height",
        0x0050,
        0x0084,
        r"""
cmp eax, ecx
cmovb eax, ecx
sub rsp, 0x30
mov dword ptr [rsp + 0x20], eax
mov rcx, qword ptr [r13 + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, dword ptr [rsp + 0x20]
mov r8d, 0x60
call qword ptr [rip - 0xb09f3]            # IAT MulDiv @ 0x1401cf688
add rsp, 0x30
jmp 0x1400509e2                           # original continuation
""",
    ),
    AssemblyBlock(
        "main_margins",
        0x0090,
        0x00F9,
        r"""
sub rsp, 0x30
mov dword ptr [rsp + 0x20], eax
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0x5
mov r8d, 0x60
call qword ptr [rip - 0xb0a2f]            # MulDiv(5, dpi, 96)
mov r10d, eax
mov r11d, dword ptr [rsp + 0x20]
add rsp, 0x30
mov r9d, dword ptr [rsp + 0x44]
xor r14b, r14b
mov r8d, dword ptr [rsp + 0x40]
add r9d, r10d
mov edx, dword ptr [rsp + 0x48]
add r8d, r10d
sub edx, r10d
mov dword ptr [rdi + 0x9c4], r9d
mov r13d, r11d
mov dword ptr [rdi + 0x9c0], r8d
mov dword ptr [rdi + 0x9c8], edx
jmp 0x140050a69                           # original continuation
""",
    ),
    AssemblyBlock(
        "graph_threshold",
        0x0100,
        0x0153,
        r"""
sub rsp, 0x40
mov dword ptr [rsp + 0x20], ecx
mov dword ptr [rsp + 0x24], r8d
mov dword ptr [rsp + 0x28], r9d
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0x64
mov r8d, 0x60
call qword ptr [rip - 0xb0aa9]            # MulDiv(100, dpi, 96)
mov r10d, eax
mov ecx, dword ptr [rsp + 0x20]
mov r8d, dword ptr [rsp + 0x24]
mov r9d, dword ptr [rsp + 0x28]
add rsp, 0x40
mov eax, ecx
sub eax, r10d
cmp eax, r13d
jmp 0x140050ada                           # original continuation
""",
    ),
    AssemblyBlock(
        "graph_gap",
        0x0160,
        0x01B7,
        r"""
sub rsp, 0x40
mov dword ptr [rsp + 0x20], ecx
mov dword ptr [rsp + 0x24], r8d
mov dword ptr [rsp + 0x28], r9d
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0x5
mov r8d, 0x60
call qword ptr [rip - 0xb0b09]            # MulDiv(5, dpi, 96)
mov r10d, eax
mov ecx, dword ptr [rsp + 0x20]
mov r8d, dword ptr [rsp + 0x24]
mov r9d, dword ptr [rsp + 0x28]
add rsp, 0x40
sub ecx, r13d
sub ecx, r10d
mov dword ptr [rdi + 0x9c8], ecx
jmp 0x140050ae8                           # original continuation
""",
    ),
    AssemblyBlock(
        "load1_width",
        0x01C0,
        0x01FA,
        r"""
sub rsp, 0x30
mov dword ptr [rsp + 0x20], ecx
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0x3c
mov r8d, 0x60
call qword ptr [rip - 0xb0b5f]            # MulDiv(60, dpi, 96)
mov r10d, eax
mov r9d, eax
mov ecx, dword ptr [rsp + 0x20]
add rsp, 0x30
jmp 0x140050b34                           # original continuation
""",
    ),
    AssemblyBlock(
        "load1_x",
        0x0200,
        0x0211,
        r"""
lea rcx, [rdi + 0x790]                    # Bitsum_LoadDisplay #1
mov edx, eax
sub edx, r10d
jmp 0x140050b58                           # original continuation
""",
    ),
    AssemblyBlock(
        "load2_x",
        0x0220,
        0x0277,
        r"""
sub rsp, 0x40
mov dword ptr [rsp + 0x20], eax
mov dword ptr [rsp + 0x24], ecx
mov dword ptr [rsp + 0x28], r8d
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0x3c
mov r8d, 0x60
call qword ptr [rip - 0xb0bc8]            # MulDiv(60, dpi, 96)
mov r10d, eax
mov r11d, dword ptr [rsp + 0x20]
mov ecx, dword ptr [rsp + 0x24]
mov r8d, dword ptr [rsp + 0x28]
add rsp, 0x40
mov edx, r11d
sub edx, r10d
mov rax, qword ptr [rdi + 0x810]
jmp 0x140050c3f                           # original continuation
""",
    ),
    AssemblyBlock(
        "card_rect",
        0x02E0,
        0x0379,
        r"""
sub rsp, 0x40
mov rcx, qword ptr [r15 + 0x880]
call 0x140280000                           # get_dpi(hwnd)
mov dword ptr [rsp + 0x20], eax
mov ecx, 0x5
mov edx, dword ptr [rsp + 0x20]
mov r8d, 0x60
call qword ptr [rip - 0xb0c81]            # MulDiv(5, dpi, 96)
mov dword ptr [rsp + 0x24], eax
mov ecx, 0x16
mov edx, dword ptr [rsp + 0x20]
mov r8d, 0x60
call qword ptr [rip - 0xb0c9a]            # MulDiv(22, dpi, 96)
mov dword ptr [rsp + 0x28], eax
mov ecx, 0xf
mov edx, dword ptr [rsp + 0x20]
mov r8d, 0x60
call qword ptr [rip - 0xb0cb3]            # MulDiv(15, dpi, 96)
mov r10d, dword ptr [rsp + 0x24]
mov r11d, dword ptr [rsp + 0x28]
add rsp, 0x40
mov ecx, dword ptr [rsp + 0x60]
add ecx, r10d
mov edx, dword ptr [rsp + 0x64]
add edx, r10d
mov r8d, dword ptr [rbp - 0x40]
add r8d, r11d
add r8d, ecx
lea r13d, [r8 + rax]
mov r9d, dword ptr [rbp - 0x70]
imul r9d, dword ptr [rbp - 0x3c]
add r9d, r11d
add r9d, edx
jmp 0x14005d5c9                           # original continuation
""",
    ),
    AssemblyBlock(
        "card_text",
        0x0380,
        0x03E1,
        r"""
sub rsp, 0x40
mov rcx, qword ptr [r15 + 0x880]
call 0x140280000                           # get_dpi(hwnd)
mov dword ptr [rsp + 0x20], eax
mov ecx, 0xd
mov edx, dword ptr [rsp + 0x20]
mov r8d, 0x60
call qword ptr [rip - 0xb0d21]            # MulDiv(13, dpi, 96)
mov dword ptr [rsp + 0x24], eax
mov ecx, 0x11
mov edx, dword ptr [rsp + 0x20]
mov r8d, 0x60
call qword ptr [rip - 0xb0d3a]            # MulDiv(17, dpi, 96)
mov r10d, dword ptr [rsp + 0x24]
mov r11d, eax
add rsp, 0x40
mov ebx, dword ptr [rsp + 0x64]
add ebx, r10d
mov esi, dword ptr [rsp + 0x60]
add esi, r11d
jmp 0x14005d62a                           # original continuation
""",
    ),
    AssemblyBlock(
        "system_parameters_info",
        0x0420,
        0x04B1,
        r"""
sub rsp, 0x60
mov dword ptr [rsp + 0x30], ecx
mov qword ptr [rsp + 0x38], rdx
mov qword ptr [rsp + 0x40], r8
mov qword ptr [rsp + 0x48], r9
mov rcx, qword ptr [r15 + 0x880]
call 0x140280000                           # get_dpi(hwnd)
mov dword ptr [rsp + 0x50], eax
lea rcx, [rip - 0x5e]                     # L"user32.dll"
call qword ptr [rip - 0xb0d34]            # IAT GetModuleHandleW
test rax, rax
je fallback
mov rcx, rax
lea rdx, [rip + 0x4f]                     # "SystemParametersInfoForDpi"
call qword ptr [rip - 0xb0d31]            # IAT GetProcAddress
test rax, rax
je fallback
mov ecx, dword ptr [rsp + 0x30]
mov rdx, qword ptr [rsp + 0x38]
mov r8, qword ptr [rsp + 0x40]
mov r9, qword ptr [rsp + 0x48]
mov r10d, dword ptr [rsp + 0x50]
mov dword ptr [rsp + 0x20], r10d           # fifth arg: dpi
call rax                                  # SystemParametersInfoForDpi(...)
jmp done
fallback:
mov ecx, dword ptr [rsp + 0x30]
mov rdx, qword ptr [rsp + 0x38]
mov r8, qword ptr [rsp + 0x40]
mov r9, qword ptr [rsp + 0x48]
call qword ptr [rip - 0xb07e0]            # IAT SystemParametersInfoW
done:
add rsp, 0x60
jmp 0x14005bf4c                           # original continuation
""",
    ),
    AssemblyBlock(
        "fixed_load_reservation_1",
        0x04E0,
        0x0566,
        r"""
sub rsp, 0x40
mov dword ptr [rsp + 0x20], edx
mov dword ptr [rsp + 0x24], r8d
mov dword ptr [rsp + 0x28], r9d
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0x41                             # 65 px = 60 px display + 5 px gap
mov r8d, 0x60
call qword ptr [rip - 0xb0e89]            # MulDiv(65, dpi, 96)
mov dword ptr [rsp + 0x2c], eax
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0xa0                             # original 100 + 60 minimum-space test
mov r8d, 0x60
call qword ptr [rip - 0xb0eac]            # MulDiv(160, dpi, 96)
mov r11d, eax
mov r10d, dword ptr [rsp + 0x2c]
mov edx, dword ptr [rsp + 0x20]
mov r8d, dword ptr [rsp + 0x24]
mov r9d, dword ptr [rsp + 0x28]
add rsp, 0x40
cmp edx, r11d
jle no_room
sub edx, r10d
mov dword ptr [rdi + 0x9c8], edx
jmp done
no_room:
mov r14b, 1
done:
jmp 0x140050a88                           # original continuation
""",
    ),
    AssemblyBlock(
        "fixed_load_reservation_2",
        0x0580,
        0x0610,
        r"""
sub rsp, 0x40
mov dword ptr [rsp + 0x20], ecx
mov dword ptr [rsp + 0x24], edx
mov dword ptr [rsp + 0x28], r8d
mov dword ptr [rsp + 0x2c], r9d
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0x41                             # 65 px = 60 px display + 5 px gap
mov r8d, 0x60
call qword ptr [rip - 0xb0f2d]            # MulDiv(65, dpi, 96)
mov dword ptr [rsp + 0x30], eax
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0xa0                             # original 100 + 60 minimum-space test
mov r8d, 0x60
call qword ptr [rip - 0xb0f50]            # MulDiv(160, dpi, 96)
mov r11d, eax
mov r10d, dword ptr [rsp + 0x30]
mov ecx, dword ptr [rsp + 0x20]
mov edx, dword ptr [rsp + 0x24]
mov r8d, dword ptr [rsp + 0x28]
mov r9d, dword ptr [rsp + 0x2c]
add rsp, 0x40
cmp edx, r11d
jle no_room
mov ecx, edx
sub ecx, r10d
mov dword ptr [rdi + 0x9c8], ecx
jmp done
no_room:
mov r12b, 1
done:
jmp 0x140050ac8                           # original continuation
""",
    ),
    AssemblyBlock(
        "load2_gap",
        0x0620,
        0x066A,
        r"""
sub rsp, 0x30
mov dword ptr [rsp + 0x20], ecx
mov dword ptr [rsp + 0x24], r8d
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0x5
mov r8d, 0x60
call qword ptr [rip - 0xb0fc4]            # MulDiv(5, dpi, 96)
mov r10d, eax
mov ecx, dword ptr [rsp + 0x20]
mov r8d, dword ptr [rsp + 0x24]
add rsp, 0x30
mov eax, dword ptr [rdi + 0xad0]
sub eax, r10d
jmp 0x140050c27                           # original continuation
""",
    ),
    AssemblyBlock(
        "processor_gap",
        0x0680,
        0x06EC,
        r"""
sub rsp, 0x40
mov qword ptr [rsp + 0x20], rcx
mov dword ptr [rsp + 0x28], edx
mov dword ptr [rsp + 0x2c], r8d
mov dword ptr [rsp + 0x30], r9d
sub eax, r8d
mov dword ptr [rsp + 0x34], eax
mov rcx, qword ptr [rdi + 0x870]
call 0x140280000                           # get_dpi(hwnd)
mov edx, eax
mov ecx, 0x5
mov r8d, 0x60
call qword ptr [rip - 0xb1035]            # MulDiv(5, dpi, 96)
mov r10d, eax
mov rcx, qword ptr [rsp + 0x20]
mov edx, dword ptr [rsp + 0x28]
mov r8d, dword ptr [rsp + 0x2c]
mov r9d, dword ptr [rsp + 0x30]
mov r11d, dword ptr [rsp + 0x34]
add rsp, 0x40
add edx, r10d
mov eax, r11d
mov dword ptr [rsp + 0x20], r11d
jmp 0x140050cfd                           # original continuation
""",
    ),
    AssemblyBlock(
        "bar_metrics",
        0x0700,
        0x0744,
        # The two MulDiv calls are RIP-relative through the IAT (like get_dpi), not an absolute
        # `mov rax, imm64`: the module is DYNAMIC_BASE, so an absolute IAT address would not be
        # relocated at load and would fault under ASLR. The displacements are specific to this
        # block being assembled at 0x140280700; the pinned test hash guards that placement.
        r"""
sub rsp, 0x38
call 0x140280000                           # get_dpi(hwnd in rcx) -> eax = dpi
mov dword ptr [rsp + 0x20], eax            # save dpi
mov ecx, 0x20
mov edx, eax                               # dpi
mov r8d, 0x60
call qword ptr [rip - 0xb1098]             # MulDiv(32, dpi, 96) via IAT 0x1401cf688
mov dword ptr [rsp + 0x24], eax            # save scaled 32
mov ecx, 0x16
mov edx, dword ptr [rsp + 0x20]            # dpi
mov r8d, 0x60
call qword ptr [rip - 0xb10b1]             # MulDiv(22, dpi, 96) via IAT 0x1401cf688 -> eax
mov edx, eax                               # out: scaled 22
mov eax, dword ptr [rsp + 0x24]            # out: scaled 32
add rsp, 0x38
ret
""",
    ),
    AssemblyBlock(
        "upper_bar_height",
        0x0760,
        0x07AD,
        r"""
sub rsp, 0x30
mov dword ptr [rsp + 0x20], edx            # live strip width
mov dword ptr [rsp + 0x24], r9d            # live strip y
mov rcx, qword ptr [rdi + 0x8d0]           # upper tab-strip HWND
call 0x140280700                           # bar_metrics -> eax=scaled32, edx=scaled22
mov r10d, eax                              # scaled 32, live to the cy replacement at 0x050dce
mov r11d, edx                              # scaled 22
mov edx, dword ptr [rsp + 0x20]            # restore width
mov r9d, dword ptr [rsp + 0x24]            # restore y
add rsp, 0x30
mov dword ptr [rdi + 0xbac], r11d          # Edit +0x970 cell bottom
mov dword ptr [rdi + 0xacc], r11d          # Button +0x900 cell bottom (propagated to Edit Rules/Pause)
mov eax, r9d
add eax, r10d
mov dword ptr [rdi + 0xa6c], eax           # cached strip bottom = y + scaled 32 (process-list top reads this)
test edx, edx                              # recreate the sign flag consumed by the original js
jmp 0x140050db2                            # original continuation
""",
    ),
    AssemblyBlock(
        "lower_bar_height",
        0x07B0,
        0x0816,
        r"""
sub rsp, 0x30
mov dword ptr [rsp + 0x20], ecx            # live strip width
mov dword ptr [rsp + 0x24], r8d            # live strip x
mov dword ptr [rsp + 0x28], r9d            # live strip y
mov rcx, qword ptr [rdi + 0x8a8]           # lower tab-strip HWND
call 0x140280700                           # bar_metrics -> eax=scaled32, edx=scaled22
mov r10d, eax                              # scaled 32, live to the cy replacement at 0x0518e3
mov r11d, edx                              # scaled 22
mov ecx, dword ptr [rsp + 0x20]            # restore width
mov r8d, dword ptr [rsp + 0x24]            # restore x
mov r9d, dword ptr [rsp + 0x28]            # restore y
add rsp, 0x30
mov dword ptr [rdi + 0xb4c], r11d          # Edit +0x940 cell bottom
mov dword ptr [rdi + 0xb7c], r11d          # View Log +0x958 cell bottom
mov dword ptr [rdi + 0xb9c], r11d          # Insights +0x968 cell bottom
mov dword ptr [rdi + 0xa5c], r11d          # Buy Now +0x8c8 cell bottom
mov eax, r9d
add eax, r10d
mov dword ptr [rdi + 0xa14], r9d           # replay overwritten cached-y store
test ecx, ecx                              # recreate the sign flag consumed by the original js
jmp 0x1400518c7                            # original cached-bottom store: mov [rdi+0xa1c],eax
""",
    ),
    AssemblyBlock(
        "main_system_parameters_info",
        0x0820,
        0x08B1,
        # DPI-scale the main-UI font: redirect SystemParametersInfoW(SPI_GETNONCLIENTMETRICS) at
        # 0x04c855 to SystemParametersInfoForDpi. The main window (app+0x870) does not exist yet at
        # this init point, but the hidden notification window (app+0x878) is already live and is a
        # valid GetDpiForWindow input. Same call shape as the graph `system_parameters_info` block;
        # reuses the same user32.dll / SystemParametersInfoForDpi data strings. All references are
        # rel32 / RIP-relative (ASLR-safe); the returned API pointer comes from GetProcAddress.
        r"""
sub rsp, 0x60
mov dword ptr [rsp + 0x30], ecx
mov qword ptr [rsp + 0x38], rdx
mov qword ptr [rsp + 0x40], r8
mov qword ptr [rsp + 0x48], r9
mov rcx, qword ptr [rbx + 0x878]           # live hidden notification-window HWND
call 0x140280000                           # get_dpi(hwnd)
mov dword ptr [rsp + 0x50], eax
lea rcx, [rip - 0x45e]                      # L"user32.dll" at .hidpi+0x03f0
call qword ptr [rip - 0xb1134]             # IAT GetModuleHandleW, RVA 0x1cf720
test rax, rax
je fallback
mov rcx, rax
lea rdx, [rip - 0x3b1]                      # "SystemParametersInfoForDpi" at .hidpi+0x04b2
call qword ptr [rip - 0xb1131]             # IAT GetProcAddress, RVA 0x1cf738
test rax, rax
je fallback
mov ecx, dword ptr [rsp + 0x30]
mov rdx, qword ptr [rsp + 0x38]
mov r8, qword ptr [rsp + 0x40]
mov r9, qword ptr [rsp + 0x48]
mov r10d, dword ptr [rsp + 0x50]
mov dword ptr [rsp + 0x20], r10d           # fifth arg: dpi
call rax                                   # SystemParametersInfoForDpi(...)
jmp done
fallback:
mov ecx, dword ptr [rsp + 0x30]
mov rdx, qword ptr [rsp + 0x38]
mov r8, qword ptr [rsp + 0x40]
mov r9, qword ptr [rsp + 0x48]
call qword ptr [rip - 0xb0be0]             # IAT SystemParametersInfoW, RVA 0x1cfcc8
done:
add rsp, 0x60
jmp 0x14004c85b                            # original continuation
""",
    ),
    AssemblyBlock(
        "upper_search_icon_square",
        0x08C0,
        0x08DF,
        # Make the upper search-glass Static square. At the hook, eax=bottom-2, r9d=top+2; the
        # original `sub eax,r9d` yields the icon side (client height - 4). Recompute the right-aligned
        # x = (right-1) - side using the cached right-1 (app+0xc18), leaving it in r8d (the SetWindowPos
        # X register) and updating the cached x (app+0xc10). The paired in-place width patch at
        # 0x051224 stores this side as cx, so cx == cy and SS_REALSIZECONTROL cannot distort the icon.
        r"""
sub eax, r9d                               # side = (bottom-2) - (top+2)
js 0x140051232                             # preserve the original invalid-height exit
mov r8d, dword ptr [rdi + 0xc18]           # cached right-1
sub r8d, eax                               # x = (right-1) - side
mov dword ptr [rdi + 0xc10], r8d           # keep cached x consistent
jmp 0x140051205                            # resume at the original x/y validity tests
""",
    ),
    AssemblyBlock(
        "lower_search_icon_square",
        0x08E0,
        0x08FD,
        # Lower search-glass Static, same square geometry. The hook replaces `sub eax,r9d; sub ecx,r8d`
        # (cy and the fixed-16 cx). Compute side=cy in eax, x=(right-1)-side in r8d from cached right-1
        # (app+0xc28), set cx=side in ecx, and recreate the sign flag the original js at 0x0519ed reads.
        r"""
sub eax, r9d                               # side = (bottom-2) - (top+2)
mov r8d, dword ptr [rdi + 0xc28]           # cached right-1
sub r8d, eax                               # x = (right-1) - side
mov dword ptr [rdi + 0xc20], r8d           # keep cached x consistent
mov ecx, eax                               # cx = side (== cy)
test ecx, ecx                              # recreate the sign flag consumed by the original js
jmp 0x1400519ed                            # original validity tests + SetWindowPos
""",
    ),
    AssemblyBlock(
        "search_margin",
        0x0900,
        0x0924,
        # Shared helper for the two search-Edit right margins. Input rcx = Edit HWND; returns in eax
        # MulDiv(22, dpi, 96) - 6, which matches the DPI-scaled search-icon width (client_height - 4
        # for a 1px-border Edit). RIP-relative MulDiv (ASLR-safe); displacement is specific to 0x0900.
        r"""
sub rsp, 0x28
call 0x140280000                           # get_dpi(hwnd in rcx) -> eax = dpi
mov edx, eax                               # dpi
mov ecx, 0x16                              # 22 (original Edit cell height / margin base)
mov r8d, 0x60
call qword ptr [rip - 0xb1294]             # MulDiv(22, dpi, 96) via IAT 0x1401cf688
sub eax, 6                                 # scaled icon width = scaled cell height - border(2) - 4
add rsp, 0x28
ret
""",
    ),
    AssemblyBlock(
        "upper_search_margin",
        0x0930,
        0x0955,
        # Scale the upper search Edit's EM_SETMARGINS right margin to match the DPI-scaled icon.
        # Replaces `mov r9d, 0x100000` (MAKELONG(0,16)); rax holds the just-created Edit HWND and must
        # survive for the following `mov rcx,rax`. Build lParam = MAKELONG(0, scaled_margin) in r9d.
        r"""
sub rsp, 0x30
mov qword ptr [rsp + 0x20], rax            # save Edit HWND (consumed by the original mov rcx,rax)
mov rcx, rax
call 0x140280900                           # search_margin(hwnd) -> eax = scaled right margin
shl eax, 16                                # MAKELONG(0, margin)
mov r9d, eax                               # lParam
mov rax, qword ptr [rsp + 0x20]            # restore Edit HWND
add rsp, 0x30
jmp 0x14004e17d                            # original continuation (mov r8d,2 ; ...)
""",
    ),
    AssemblyBlock(
        "lower_search_margin",
        0x0970,
        0x0995,
        # Lower search Edit right margin, same as upper; continuation is the lower site's next insn.
        r"""
sub rsp, 0x30
mov qword ptr [rsp + 0x20], rax            # save Edit HWND
mov rcx, rax
call 0x140280900                           # search_margin(hwnd) -> eax = scaled right margin
shl eax, 16                                # MAKELONG(0, margin)
mov r9d, eax                               # lParam
mov rax, qword ptr [rsp + 0x20]            # restore Edit HWND
add rsp, 0x30
jmp 0x14004e0f0                            # original continuation (mov r8d,2 ; ...)
""",
    ),
)


@dataclass(frozen=True)
class Section:
    """A PE section required for RVA/file-offset translation.

    Attributes:
        name: Section name with trailing NUL bytes removed.
        virtual_size: Mapped size requested by the PE section header.
        virtual_address: RVA at which the section is mapped.
        raw_size: File-backed size of the section.
        raw_offset: File offset of the section's first byte.
    """

    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int


@dataclass(frozen=True)
class PeLayout:
    """PE header offsets and alignment values used by this patch.

    Attributes:
        pe_offset: File offset of the PE signature.
        optional_offset: File offset of the PE32+ optional header.
        section_table_offset: File offset of the section-header array.
        section_count: Number of original PE sections.
        section_alignment: In-memory section alignment.
        file_alignment: On-disk section alignment.
        image_base: Preferred image base.
        size_of_headers: File-backed PE-header size.
        exception_directory_offset: File offset of the exception data-directory entry.
        security_directory_offset: File offset of the Authenticode data-directory entry.
        sections: Parsed original section headers.
    """

    pe_offset: int
    optional_offset: int
    section_table_offset: int
    section_count: int
    section_alignment: int
    file_alignment: int
    image_base: int
    size_of_headers: int
    exception_directory_offset: int
    security_directory_offset: int
    sections: tuple[Section, ...]


BINUTILS_TOOLS = ("as", "ld", "objcopy")
ELF_MAGIC = b"\x7fELF"


def strip_assembly_comments(source: str) -> str:
    """Remove human-readable `#` comments before assembling.

    Args:
        source: Intel-syntax assembly source that may contain trailing `#` comments.

    Returns:
        Assembly source containing only labels and instructions.
    """
    lines = []
    for source_line in source.splitlines():
        instruction = source_line.split("#", 1)[0].strip()
        if instruction:
            lines.append(instruction)
    return "\n".join(lines)


def run_binutils_step(command: list[str]) -> None:
    """Run one GNU binutils command, raising with its diagnostics on failure.

    Args:
        command: Full argument vector to execute; `command[0]` is the tool name.

    Raises:
        ValueError: If the tool exits non-zero, carrying its captured stderr.
    """
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError(f"{command[0]} failed: {result.stderr.strip()}")


def assemble_x86_64(source: str, address: int) -> bytes:
    """Assemble Intel-syntax x86-64 source at a fixed virtual address with GNU binutils.

    The source is assembled with `as`, located at `address` with `ld` so absolute branch
    targets resolve to correct rel32 displacements, and reduced to raw machine code with
    `objcopy`. This reproduces the position-dependent encoding expected at `address`.

    Args:
        source: Assembly source. Local labels are allowed; `#` comments are stripped first.
        address: Virtual address of the first emitted instruction, used for relative branches.

    Returns:
        Exact machine-code bytes of the assembled `.text` section.
    """
    assert 0 <= address < 1 << 64
    missing = [tool for tool in BINUTILS_TOOLS if shutil.which(tool) is None]
    if missing:
        raise RuntimeError(
            f"Cannot assemble x86-64: missing GNU binutils tool(s) {', '.join(missing)} on PATH. "
            "Install binutils (for example, add `binutils` to your Nix environment)."
        )
    program = ".intel_syntax noprefix\n.text\n" + strip_assembly_comments(source) + "\n"
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        source_path, object_path = work / "block.s", work / "block.o"
        linked_path, binary_path = work / "block.elf", work / "block.bin"
        source_path.write_text(program)
        run_binutils_step(["as", "--64", "-o", str(object_path), str(source_path)])
        if object_path.read_bytes()[:4] != ELF_MAGIC:
            raise RuntimeError(
                "This patcher requires an ELF-targeted GNU binutils: absolute branch "
                "targets are resolved through ELF relocations during `ld -Ttext`. The "
                f"assembler at {shutil.which('as')} produced a non-ELF object, so a COFF "
                "toolchain such as MSYS2/MinGW is not supported; use Linux/NixOS binutils."
            )
        run_binutils_step(["ld", f"-Ttext=0x{address:x}", "-e", "0", "-o", str(linked_path), str(object_path)])
        run_binutils_step(["objcopy", "-O", "binary", "--only-section=.text", str(linked_path), str(binary_path)])
        return binary_path.read_bytes()


def place_bytes(buffer: bytearray, occupied: bytearray, offset: int, content: bytes, label: str) -> None:
    """Place non-overlapping content into the generated code/data image.

    Args:
        buffer: Mutable `.hidpi` code/data image.
        occupied: One-byte-per-position overlap bitmap corresponding to `buffer`.
        offset: Destination offset in `buffer`.
        content: Bytes to place.
        label: Human-readable component name for diagnostics.
    """
    assert len(buffer) == len(occupied)
    end_offset = offset + len(content)
    if not 0 <= offset <= end_offset <= len(buffer):
        raise ValueError(f"{label}: range 0x{offset:x}..0x{end_offset:x} is outside the code image")
    if any(occupied[offset:end_offset]):
        raise ValueError(f"{label}: overlaps another generated code/data component")
    buffer[offset:end_offset] = content
    occupied[offset:end_offset] = b"\x01" * len(content)


def assemble_hidpi_code() -> bytes:
    """Assemble all live HiDPI trampolines and place their referenced strings.

    Returns:
        Complete `.hidpi` executable-code prefix. Unused gaps are filled with `INT3` bytes.
    """
    code = bytearray(b"\xCC" * HIDPI_CODE_SIZE)
    occupied = bytearray(HIDPI_CODE_SIZE)
    for block in HIDPI_ASSEMBLY_BLOCKS:
        block_va = HIDPI_CODE_BASE_VA + block.offset
        machine_code = assemble_x86_64(block.source, block_va)
        expected_size = block.end_offset - block.offset
        if len(machine_code) != expected_size:
            raise ValueError(
                f"{block.name}: assembled 0x{len(machine_code):x} bytes, expected 0x{expected_size:x}; "
                "instruction sizes changed"
            )
        place_bytes(code, occupied, block.offset, machine_code, block.name)
    data_items = (
        (USER32_DLL_OFFSET, "user32.dll".encode("utf-16le") + b"\0\0", "user32.dll"),
        (GET_DPI_FOR_WINDOW_NAME_OFFSET, b"GetDpiForWindow\0", "GetDpiForWindow"),
        (SYSTEM_PARAMETERS_INFO_FOR_DPI_NAME_OFFSET, b"SystemParametersInfoForDpi\0", "SystemParametersInfoForDpi"),
    )
    for offset, content, label in data_items:
        place_bytes(code, occupied, offset, content, label)
    return bytes(code)


def align_up(value: int, alignment: int) -> int:
    """Round an integer upward to an alignment boundary.

    Args:
        value: Byte count or address to align.
        alignment: Positive power-of-two PE alignment.

    Returns:
        The smallest aligned integer greater than or equal to `value`.
    """
    assert alignment > 0 and alignment & (alignment - 1) == 0
    return (value + alignment - 1) & ~(alignment - 1)


def sha256_hex(data: bytes | bytearray) -> str:
    """Calculate a SHA-256 digest.

    Args:
        data: Complete file bytes.

    Returns:
        Lowercase hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest()


def parse_pe(data: bytes | bytearray) -> PeLayout:
    """Parse the small subset of PE32+ headers needed by the patcher.

    Args:
        data: Complete executable bytes.

    Returns:
        Header offsets, alignments, image base, and section metadata.
    """
    if data[:2] != b"MZ":
        raise ValueError("Input is not an MZ executable")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("Input does not contain a PE signature")
    machine, section_count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    if machine != 0x8664:
        raise ValueError(f"Expected x86-64 PE machine 0x8664, got 0x{machine:04x}")
    optional_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic != 0x20B:
        raise ValueError(f"Expected PE32+ optional header, got magic 0x{magic:04x}")
    image_base        = struct.unpack_from("<Q", data, optional_offset + 24)[0]
    section_alignment = struct.unpack_from("<I", data, optional_offset + 32)[0]
    file_alignment    = struct.unpack_from("<I", data, optional_offset + 36)[0]
    size_of_headers   = struct.unpack_from("<I", data, optional_offset + 60)[0]
    exception_directory_offset = optional_offset + 112 + 3 * 8
    security_directory_offset  = optional_offset + 112 + 4 * 8
    section_table_offset = optional_offset + optional_size
    sections: list[Section] = []
    for index in range(section_count):
        offset = section_table_offset + index * 40
        raw_name = bytes(data[offset:offset + 8]).split(b"\0", 1)[0]
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        sections.append(Section(raw_name.decode("ascii", "replace"), virtual_size, virtual_address, raw_size, raw_offset))
    return PeLayout(
        pe_offset=pe_offset,
        optional_offset=optional_offset,
        section_table_offset=section_table_offset,
        section_count=section_count,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        image_base=image_base,
        size_of_headers=size_of_headers,
        exception_directory_offset=exception_directory_offset,
        security_directory_offset=security_directory_offset,
        sections=tuple(sections),
    )


def rva_to_file_offset(layout: PeLayout, rva: int) -> int:
    """Translate an RVA that belongs to an existing section into a file offset.

    Args:
        layout: Parsed PE layout.
        rva: Relative virtual address in the original image.

    Returns:
        File offset containing the requested RVA.
    """
    for section in layout.sections:
        extent = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + extent:
            delta = rva - section.virtual_address
            if delta >= section.raw_size:
                raise ValueError(f"RVA 0x{rva:x} has no file-backed bytes")
            return section.raw_offset + delta
    raise ValueError(f"RVA 0x{rva:x} is outside existing sections")


def make_manifest() -> bytes:
    """Build the replacement application manifest.

    Returns:
        UTF-8 XML resource declaring legacy per-monitor awareness and PerMonitorV2.
    """
    xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency><dependentAssembly><assemblyIdentity type="Win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/></dependentAssembly></dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="highestAvailable" uiAccess="false"/></requestedPrivileges></security></trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application>
    <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/><supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/><supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/><supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/><supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
  </application></compatibility>
  <asmv3:application xmlns:asmv3="urn:schemas-microsoft-com:asm.v3"><asmv3:windowsSettings>
    <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
    <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2, PerMonitor</dpiAwareness>
  </asmv3:windowsSettings></asmv3:application>
</assembly>'''
    return b"\xef\xbb\xbf" + xml.encode("utf-8")


def verify_slice(data: bytes | bytearray, offset: int, expected: bytes, label: str) -> None:
    """Refuse to patch when a supposedly known instruction/resource slice differs.

    Args:
        data: Mutable or immutable executable bytes.
        offset: File offset to verify.
        expected: Exact bytes expected at that offset.
        label: Human-readable patch-site name for errors.
    """
    actual = bytes(data[offset:offset + len(expected)])
    if actual != expected:
        raise ValueError(f"{label}: expected {expected.hex()} at 0x{offset:x}, found {actual.hex()}")


def make_rel32_jump(source_va: int, target_va: int, replaced_size: int) -> bytes:
    """Assemble an x86-64 near jump and pad the overwritten region with NOPs.

    Args:
        source_va: Virtual address of the first byte being replaced.
        target_va: Virtual address of the trampoline entry point.
        replaced_size: Number of original bytes overwritten; must be at least five.

    Returns:
        A replacement byte sequence exactly `replaced_size` bytes long.
    """
    if replaced_size < 5:
        raise ValueError("A rel32 JMP needs at least five bytes")
    jump = assemble_x86_64(f"jmp 0x{target_va:x}", source_va)
    if len(jump) != 5:
        raise ValueError(f"Expected a five-byte near JMP, Keystone emitted {len(jump)} bytes")
    padding_size = replaced_size - len(jump)
    if padding_size == 0:
        return jump
    padding = assemble_x86_64("\n".join("nop" for _ in range(padding_size)), source_va + len(jump))
    if len(padding) != padding_size:
        raise ValueError(f"Expected {padding_size} one-byte NOPs, Keystone emitted {len(padding)} bytes")
    return jump + padding


def append_aligned(buffer: bytearray, content: bytes, alignment: int, pad_byte: int = 0) -> int:
    """Append content at an aligned offset and return that offset.

    Args:
        buffer: Mutable payload being constructed.
        content: Bytes to append after alignment padding.
        alignment: Positive power-of-two alignment for the content start.
        pad_byte: Byte value used for alignment padding.

    Returns:
        Offset within `buffer` at which `content` begins.
    """
    assert 0 <= pad_byte <= 0xFF
    offset = align_up(len(buffer), alignment)
    buffer.extend(bytes((pad_byte,)) * (offset - len(buffer)))
    buffer.extend(content)
    return offset


def make_get_dpi_unwind_info() -> bytes:
    """Build x64 unwind metadata for the injected `get_dpi` helper.

    Returns:
        UNWIND_INFO describing `push rbx; sub rsp, 0x20`.
    """
    version_and_flags = 0x01
    prolog_size       = 0x05
    unwind_code_count = 0x02
    frame_register    = 0x00
    alloc_small       = bytes((0x05, 0x32))
    push_rbx          = bytes((0x01, 0x30))
    return bytes((version_and_flags, prolog_size, unwind_code_count, frame_register)) + alloc_small + push_rbx


def make_leaf_alloc_unwind_info(alloc_size: int) -> bytes:
    """Build x64 unwind metadata for an injected helper whose only prologue op allocates stack.

    Used by helpers reached via `call` whose entire prologue is a single four-byte
    `sub rsp, alloc_size` (imm8) and which save no nonvolatile registers, so one
    `UWOP_ALLOC_SMALL` fully describes the frame.

    Args:
        alloc_size: Bytes reserved by `sub rsp, alloc_size`; a multiple of 8 in `[0x10, 0x80]`.

    Returns:
        A 4-byte-aligned UNWIND_INFO record for the helper.
    """
    assert 0x10 <= alloc_size <= 0x80 and alloc_size % 8 == 0
    op_info           = (alloc_size - 8) // 8
    version_and_flags = 0x01
    prolog_size       = 0x04
    unwind_code_count = 0x01
    frame_register    = 0x00
    alloc_small       = bytes((0x04, (op_info << 4) | 0x02))   # UWOP_ALLOC_SMALL at prolog offset 4
    padding           = bytes((0x00, 0x00))                    # pad the 6-byte record to a 4-byte boundary
    return bytes((version_and_flags, prolog_size, unwind_code_count, frame_register)) + alloc_small + padding


def make_chained_unwind_info(stack_size: int, parent: tuple[int, int, int]) -> bytes:
    """Build chained x64 unwind metadata for an injected trampoline range.

    Args:
        stack_size: Temporary stack allocation active in this range, or zero after it has been restored.
        parent: Original RUNTIME_FUNCTION `(begin_rva, end_rva, unwind_rva)` to chain into.

    Returns:
        A 4-byte-aligned UNWIND_INFO record with `UNW_FLAG_CHAININFO`.
    """
    assert len(parent) == 3
    assert stack_size == 0 or stack_size in (0x30, 0x40, 0x60)
    if stack_size == 0:
        header_and_codes = bytes((0x21, 0x00, 0x00, 0x00))
    else:
        op_info = (stack_size - 8) // 8
        assert 0 <= op_info <= 15
        header_and_codes = bytes((0x21, 0x04, 0x01, 0x00, 0x04, (op_info << 4) | 0x02, 0x00, 0x00))
    return header_and_codes + struct.pack("<III", *parent)


def build_hidpi_payload(
    original: bytes,
    layout: PeLayout,
    new_section_rva: int,
    manifest: bytes,
) -> tuple[bytes, int, int, int]:
    """Build injected code, manifest, unwind metadata, and a relocated exception table.

    Args:
        original: Complete original executable bytes.
        layout: Parsed PE layout for the original executable.
        new_section_rva: RVA at which the new `.hidpi` section will be mapped.
        manifest: Replacement application manifest bytes.

    Returns:
        `(payload, manifest_offset, exception_table_offset, exception_table_size)`.
    """
    exception_rva, exception_size = struct.unpack_from("<II", original, layout.exception_directory_offset)
    if exception_size == 0 or exception_size % 12 != 0:
        raise ValueError(f"Unexpected x64 exception-directory size 0x{exception_size:x}")
    exception_file_offset = rva_to_file_offset(layout, exception_rva)
    original_exception_table = original[exception_file_offset:exception_file_offset + exception_size]
    if len(original_exception_table) != exception_size:
        raise ValueError("Original exception table is truncated")
    original_runtime_functions = {
        struct.unpack_from("<III", original_exception_table, offset)
        for offset in range(0, exception_size, 12)
    }
    for parent in (
        UNWIND_PARENT_GRAPH_HEIGHT,
        UNWIND_PARENT_MAIN_LAYOUT,
        UNWIND_PARENT_GRAPH_RENDERER,
        UNWIND_PARENT_MAIN_INIT,
        UNWIND_PARENT_MAIN_CREATE,
    ):
        if parent not in original_runtime_functions:
            raise ValueError(f"Expected parent RUNTIME_FUNCTION {parent!r} is absent")
    hidpi_code = assemble_hidpi_code()
    payload = bytearray(hidpi_code)
    manifest_offset = append_aligned(payload, manifest, 16, 0xCC)
    unwind_offsets: dict[tuple[int, tuple[int, int, int]], int] = {}
    get_dpi_unwind_offset = append_aligned(payload, make_get_dpi_unwind_info(), 4)
    new_runtime_functions: list[tuple[int, int, int]] = [
        (new_section_rva + 0x0000, new_section_rva + 0x0043, new_section_rva + get_dpi_unwind_offset)
    ]
    blocks_by_name = {block.name: block for block in HIDPI_ASSEMBLY_BLOCKS}
    for helper_name, alloc_size in (("bar_metrics", 0x38), ("search_margin", 0x28)):
        helper_block = blocks_by_name[helper_name]
        helper_unwind_offset = append_aligned(payload, make_leaf_alloc_unwind_info(alloc_size), 4)
        new_runtime_functions.append((
            new_section_rva + helper_block.offset,
            new_section_rva + helper_block.end_offset,
            new_section_rva + helper_unwind_offset,
        ))
    for label, begin_offset, end_offset, stack_size, parent in HIDPI_CHAINED_RANGES:
        if not 0 <= begin_offset < end_offset <= len(hidpi_code):
            raise ValueError(f"{label}: unwind range is outside the injected code")
        key = (stack_size, parent)
        unwind_offset = unwind_offsets.get(key)
        if unwind_offset is None:
            unwind_info = make_chained_unwind_info(stack_size, parent)
            unwind_offset = append_aligned(payload, unwind_info, 4)
            unwind_offsets[key] = unwind_offset
        new_runtime_functions.append((
            new_section_rva + begin_offset,
            new_section_rva + end_offset,
            new_section_rva + unwind_offset,
        ))
    new_runtime_functions.sort(key=lambda item: item[0])
    for previous, current in zip(new_runtime_functions, new_runtime_functions[1:]):
        if previous[1] > current[0]:
            raise ValueError(f"Injected RUNTIME_FUNCTION ranges overlap: {previous!r} / {current!r}")
    original_last_begin = struct.unpack_from("<I", original_exception_table, exception_size - 12)[0]
    if original_last_begin >= new_runtime_functions[0][0]:
        raise ValueError("Cannot append injected RUNTIME_FUNCTION entries while preserving sort order")
    new_exception_entries = b"".join(struct.pack("<III", *entry) for entry in new_runtime_functions)
    exception_table = original_exception_table + new_exception_entries
    exception_table_offset = append_aligned(payload, exception_table, 4)
    return bytes(payload), manifest_offset, exception_table_offset, len(exception_table)


def patch_exception_directory(data: bytearray, layout: PeLayout, exception_rva: int, exception_size: int) -> None:
    """Point the PE exception directory at the relocated table containing injected unwind entries.

    Args:
        data: Mutable executable bytes.
        layout: Parsed original PE layout containing the exception-directory field offset.
        exception_rva: RVA of the replacement RUNTIME_FUNCTION table.
        exception_size: Size in bytes of the replacement table.
    """
    assert exception_size > 0 and exception_size % 12 == 0
    struct.pack_into("<II", data, layout.exception_directory_offset, exception_rva, exception_size)


def add_hidpi_section(data: bytearray, layout: PeLayout, payload: bytes) -> tuple[int, int]:
    """Replace the terminal Authenticode certificate with a new RX `.hidpi` section.

    Args:
        data: Mutable executable bytes.
        layout: Parsed PE layout for the original executable.
        payload: Trampoline code followed by manifest and unwind data.

    Returns:
        `(new_section_rva, new_section_raw_offset)` for subsequent patching.
    """
    cert_offset, cert_size = struct.unpack_from("<II", data, layout.security_directory_offset)
    if cert_offset != EXPECTED_CERTIFICATE_OFFSET:
        raise ValueError(f"Unexpected certificate offset 0x{cert_offset:x}")
    if cert_offset + cert_size != len(data):
        raise ValueError("Expected the Authenticode certificate to be the terminal file overlay")
    last = max(layout.sections, key=lambda section: section.virtual_address)
    new_rva = align_up(last.virtual_address + max(last.virtual_size, last.raw_size), layout.section_alignment)
    if new_rva != EXPECTED_NEW_SECTION_RVA:
        raise ValueError(f"Unexpected next section RVA 0x{new_rva:x}")
    raw_offset = cert_offset
    raw_size = align_up(len(payload), layout.file_alignment)
    virtual_size = len(payload)
    new_header_offset = layout.section_table_offset + layout.section_count * 40
    if new_header_offset + 40 > layout.size_of_headers:
        raise ValueError("No room remains in the PE headers for another section")
    del data[cert_offset:]
    data.extend(payload)
    data.extend(b"\0" * (raw_size - len(payload)))
    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".hidpi\0\0",
        virtual_size,
        new_rva,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    data[new_header_offset:new_header_offset + 40] = section_header
    struct.pack_into("<H", data, layout.pe_offset + 6, layout.section_count + 1)
    new_size_of_image = align_up(new_rva + virtual_size, layout.section_alignment)
    struct.pack_into("<I", data, layout.optional_offset + 56, new_size_of_image)
    old_size_of_code = struct.unpack_from("<I", data, layout.optional_offset + 4)[0]
    struct.pack_into("<I", data, layout.optional_offset + 4, old_size_of_code + raw_size)
    struct.pack_into("<II", data, layout.security_directory_offset, 0, 0)
    struct.pack_into("<I", data, layout.optional_offset + 64, 0)
    return new_rva, raw_offset


def patch_manifest_resource(data: bytearray, manifest_rva: int, manifest: bytes) -> None:
    """Point RT_MANIFEST resource ID 1 at the relocated manifest in `.hidpi`.

    Args:
        data: Mutable executable bytes.
        manifest_rva: RVA at which the replacement XML begins.
        manifest: Replacement manifest bytes, used to set resource size.
    """
    expected = struct.pack("<IIII", 0x27CF08, 0x433, 0, 0)
    verify_slice(data, MANIFEST_DATA_ENTRY_OFFSET, expected, "RT_MANIFEST data entry")
    struct.pack_into("<IIII", data, MANIFEST_DATA_ENTRY_OFFSET, manifest_rva, len(manifest), 0, 0)


def apply_code_patches(data: bytearray, layout: PeLayout, new_section_rva: int) -> None:
    """Install trampoline jumps and in-place instruction replacements at the patch sites.

    `PATCH_SITES` entries redirect a hook site to its `.hidpi` trampoline with a rel32 jump.
    `INPLACE_PATCH_SITES` entries rewrite a site in place with equal-length assembly, either
    reusing a register a trampoline leaves live or neutralizing a now-dead hardcoded store.

    Args:
        data: Mutable executable bytes.
        layout: Parsed original PE layout for RVA translation and image base.
        new_section_rva: RVA of the newly added `.hidpi` section.
    """
    for name, (site_rva, expected) in PATCH_SITES.items():
        site_offset = rva_to_file_offset(layout, site_rva)
        verify_slice(data, site_offset, expected, name)
        site_va = layout.image_base + site_rva
        symbol_offset = HIDPI_SYMBOL_OFFSETS[name]
        target_va = layout.image_base + new_section_rva + symbol_offset
        replacement = make_rel32_jump(site_va, target_va, len(expected))
        if len(replacement) != len(expected):
            raise AssertionError(f"{name}: replacement length changed")
        data[site_offset:site_offset + len(expected)] = replacement
    for name, (site_rva, expected, replacement_source) in INPLACE_PATCH_SITES.items():
        site_offset = rva_to_file_offset(layout, site_rva)
        verify_slice(data, site_offset, expected, name)
        site_va = layout.image_base + site_rva
        replacement = assemble_x86_64(replacement_source, site_va)
        if len(replacement) != len(expected):
            raise AssertionError(
                f"{name}: in-place replacement is 0x{len(replacement):x} bytes, expected 0x{len(expected):x}"
            )
        data[site_offset:site_offset + len(expected)] = replacement


def patch_process_lasso(input_path: Path, output_path: Path) -> tuple[str, str]:
    """Create the HiDPI-patched executable from the exact supported Process Lasso build.

    Args:
        input_path: Path to the original unmodified `ProcessLasso.exe`.
        output_path: Destination for the patched executable.

    Returns:
        `(original_sha256, patched_sha256)` for display and independent verification.
    """
    original = input_path.read_bytes()
    original_hash = sha256_hex(original)
    if original_hash != EXPECTED_SHA256:
        raise ValueError(
            "This patcher is deliberately build-locked. "
            f"Expected SHA-256 {EXPECTED_SHA256}, got {original_hash}."
        )
    data = bytearray(original)
    layout = parse_pe(data)
    if layout.image_base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"Unexpected image base 0x{layout.image_base:x}")
    manifest = make_manifest()
    payload, manifest_offset_in_section, exception_table_offset, exception_table_size = build_hidpi_payload(
        original,
        layout,
        EXPECTED_NEW_SECTION_RVA,
        manifest,
    )
    new_section_rva, _ = add_hidpi_section(data, layout, payload)
    patch_manifest_resource(data, new_section_rva + manifest_offset_in_section, manifest)
    patch_exception_directory(data, layout, new_section_rva + exception_table_offset, exception_table_size)
    apply_code_patches(data, layout, new_section_rva)
    output_path.write_bytes(data)
    return original_hash, sha256_hex(data)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Namespace containing the input executable and optional output path.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="original ProcessLasso.exe")
    parser.add_argument("output", nargs="?", type=Path, help="patched output path")
    return parser.parse_args()


def main() -> None:
    """Patch the requested executable and print hashes/paths."""
    args = parse_args()
    output_path = args.output or args.input.with_name(args.input.stem + ".hidpi" + args.input.suffix)
    original_hash, patched_hash = patch_process_lasso(args.input, output_path)
    print(f"original SHA-256: {original_hash}")
    print(f"patched  SHA-256: {patched_hash}")
    print(f"wrote: {output_path}")


if __name__ == "__main__":
    main()
