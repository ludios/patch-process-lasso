#!/usr/bin/env python3
"""Patch the exact Process Lasso build supplied on 2026-08-17 for Per-Monitor V2 HiDPI."""

from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

EXPECTED_SHA256 = "3bfdbad16ddf47e2e9d303294c9f6de90eb90f6856bc0126e27bc1bd30e4e884"
EXPECTED_IMAGE_BASE = 0x140000000
EXPECTED_NEW_SECTION_RVA = 0x280000
EXPECTED_CERTIFICATE_OFFSET = 0x274600
MANIFEST_DATA_ENTRY_OFFSET = 0x235970

HIDPI_CODE = bytes.fromhex(
    "534883ec204889cb488d0de1030000ff150bf7f4ff4885c0741e4889c1488d15e2030000ff150ef7f4ff4885c074094889d9ffd085c07505b8600000004883c4205bc366662e0f1f840000000000669039c80f42c14883ec3089442420498b8d"
    "70080000e897ffffff89c28b4c242041b860000000ff150df6f4ff4883c430e95e09ddff66662e0f1f840000000000904883ec3089442420488b8f70080000e85cffffff89c2b90500000041b860000000ff15d1f5f4ff4189c2448b5c242048"
    "83c430448b4c24444530f6448b4424404501d18b5424484501d04429d244898fc40900004589dd448987c00900008997c8090000e97009ddff0f1f80000000004883ec40894c2420448944242444894c2428488b8f70080000e8e2feffff89c2"
    "b96400000041b860000000ff1557f5f4ff4189c28b4c2420448b442424448b4c24284883c44089c84429d04439e8e98709ddff66662e0f1f84000000000066904883ec40894c2420448944242444894c2428488b8f70080000e882feffff89c2"
    "b90500000041b860000000ff15f7f4f4ff4189c28b4c2420448b442424448b4c24284883c4404429e94429d1898fc8090000e93109ddff660f1f8400000000004883ec30894c2420488b8f70080000e82cfeffff89c2b93c00000041b8600000"
    "00ff15a1f4f4ff4189c24189c18b4c24204883c430e93a09ddff660f1f440000488d8f9007000089c24429d2e94709ddff66662e0f1f8400000000000f1f40004883ec4089442420894c24244489442428488b8f70080000e8c3fdffff89c2b9"
    "3c00000041b860000000ff1538f4f4ff4189c2448b5c24208b4c2424448b4424284883c4404489da4429d2488b8710080000e9c809ddff660f1f8400000000004883ec30498b8f80080000e870fdffff894424208b4d108b54242041b8600000"
    "00ff15e1f3f4ff8945108b4d148b54242041b860000000ff15cbf3f4ff894514488d4d10ff15feeef4ff4883c430e916bdddff66662e0f1f84000000000066904883ec40498b8f80080000e810fdffff89442420b9050000008b54242041b860"
    "000000ff157ff3f4ff89442424b9160000008b54242041b860000000ff1566f3f4ff89442428b90f0000008b54242041b860000000ff154df3f4ff448b542424448b5c24284883c4408b4c24604401d18b5424644401d2448b45c04501d84101"
    "c8458d2c00448b4d90440faf4dc44501d94101d1e950d2ddff0f1f80000000004883ec40498b8f80080000e870fcffff89442420b90d0000008b54242041b860000000ff15dff2f4ff89442424b9110000008b54242041b860000000ff15c6f2"
    "f4ff448b5424244189c34883c4408b5c24644401d38b7424604401dee949d2ddff66662e0f1f8400000000000f1f40007500730065007200330032002e0064006c006c000000476574447069466f7257696e646f770090660f1f840000000000"
    "4883ec60894c243048895424384c894424404c894c2448498b8f80080000e8bdfbffff89442450488d0da2ffffffff15ccf2f4ff4885c074364889c1488d154f000000ff15cff2f4ff4885c074218b4c2430488b5424384c8b4424404c8b4c24"
    "48448b5424504489542420ffd0eb198b4c2430488b5424384c8b4424404c8b4c2448ff1520f8f4ff4883c460e99bbaddff9053797374656d506172616d6574657273496e666f466f7244706900"
)

HIDPI_SYMBOL_OFFSETS = {
    "graph_height":    0x0050,
    "main_margins":    0x0090,
    "graph_threshold": 0x0100,
    "graph_gap":       0x0160,
    "load1_width":     0x01C0,
    "load1_x":         0x0200,
    "load2_x":         0x0220,
    "system_parameters_info": 0x0420,
    "card_rect":       0x02E0,
    "card_text":       0x0380,
}

PATCH_SITES = {
    "graph_height": (0x0509DD, bytes.fromhex("3bc10f42c1")),
    "main_margins": (0x050A36, bytes.fromhex("448b4c24444532f6448b4424404183c1058b5424484183c00583c2fb44898fc4090000448be8448987c00900008997c8090000")),
    "graph_threshold": (0x050AD4, bytes.fromhex("8d419c413bc5")),
    "graph_gap": (0x050ADC, bytes.fromhex("412bcd83c1fb898fc8090000")),
    "load1_width": (0x050B2E, bytes.fromhex("41b93c000000")),
    "load1_x": (0x050B4E, bytes.fromhex("488d8f900700008d50c4")),
    "load2_x": (0x050C35, bytes.fromhex("8d50c4488b8710080000")),
    "load2_width": (0x050C4D, bytes.fromhex("41b93c000000")),
    "system_parameters_info": (0x05BF46, bytes.fromhex("ff157c3d1700")),
    "card_rect": (0x05D59C, bytes.fromhex("8b4c246083c1058b54246483c205448b45c04183c0164403c1458d680f448b4d90440faf4dc44183c1164403ca")),
    "card_text": (0x05D61C, bytes.fromhex("8b5c246483c30d8b74246083c611")),
}

UNWIND_PARENT_GRAPH_HEIGHT = (0x050870, 0x0509F0, 0x20295C)
UNWIND_PARENT_MAIN_LAYOUT = (0x0509F0, 0x0521BE, 0x202978)
UNWIND_PARENT_GRAPH_RENDERER = (0x05BE30, 0x05E8EF, 0x20348C)

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
    ("system_parameters_body", 0x0420, 0x04A8, 0x60, UNWIND_PARENT_GRAPH_RENDERER),
    ("system_parameters_tail", 0x04A8, 0x04B1, 0x00, UNWIND_PARENT_GRAPH_RENDERER),
    ("card_rect_body",         0x02E0, 0x0345, 0x40, UNWIND_PARENT_GRAPH_RENDERER),
    ("card_rect_suffix",       0x0345, 0x0379, 0x00, UNWIND_PARENT_GRAPH_RENDERER),
    ("card_text_body",         0x0380, 0x03CA, 0x40, UNWIND_PARENT_GRAPH_RENDERER),
    ("card_text_suffix",       0x03CA, 0x03E1, 0x00, UNWIND_PARENT_GRAPH_RENDERER),
)


@dataclass(frozen=True)
class Section:
    """A PE section required for RVA/file-offset translation."""

    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int


@dataclass(frozen=True)
class PeLayout:
    """PE header offsets and alignment values used by this patch."""

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


def align_up(value: int, alignment: int) -> int:
    """Round an integer upward to an alignment boundary.

    Args:
        value: Byte count or address to align.
        alignment: Positive power-of-two PE alignment.

    Returns:
        The smallest aligned integer greater than or equal to value.
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
    security_directory_offset = optional_offset + 112 + 4 * 8
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
    """Build an x86-64 near JMP plus NOP padding.

    Args:
        source_va: Virtual address of the first byte being replaced.
        target_va: Virtual address of the trampoline entry point.
        replaced_size: Number of original bytes overwritten; must be at least five.

    Returns:
        A replacement byte sequence exactly replaced_size bytes long.
    """
    if replaced_size < 5:
        raise ValueError("A rel32 JMP needs at least five bytes")
    displacement = target_va - (source_va + 5)
    if not -(1 << 31) <= displacement < (1 << 31):
        raise ValueError("Trampoline is outside rel32 range")
    return b"\xE9" + struct.pack("<i", displacement) + b"\x90" * (replaced_size - 5)


def append_aligned(buffer: bytearray, content: bytes, alignment: int, pad_byte: int = 0) -> int:
    """Append content at an aligned offset and return that offset.

    Args:
        buffer: Mutable payload being constructed.
        content: Bytes to append after alignment padding.
        alignment: Positive power-of-two alignment for the content start.
        pad_byte: Byte value used for alignment padding.

    Returns:
        Offset within buffer at which content begins.
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
    return bytes.fromhex("0105020005320130")


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
    for parent in (UNWIND_PARENT_GRAPH_HEIGHT, UNWIND_PARENT_MAIN_LAYOUT, UNWIND_PARENT_GRAPH_RENDERER):
        if parent not in original_runtime_functions:
            raise ValueError(f"Expected parent RUNTIME_FUNCTION {parent!r} is absent")

    payload = bytearray(HIDPI_CODE)
    manifest_offset = append_aligned(payload, manifest, 16, 0xCC)
    unwind_offsets: dict[tuple[int, tuple[int, int, int]], int] = {}
    get_dpi_unwind_offset = append_aligned(payload, make_get_dpi_unwind_info(), 4)
    new_runtime_functions: list[tuple[int, int, int]] = [
        (new_section_rva + 0x0000, new_section_rva + 0x0043, new_section_rva + get_dpi_unwind_offset)
    ]
    for label, begin_offset, end_offset, stack_size, parent in HIDPI_CHAINED_RANGES:
        if not (0 <= begin_offset < end_offset <= len(HIDPI_CODE)):
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
        payload: Trampoline code followed by the relocated manifest.

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
    """Install trampoline jumps and the one compact register-to-register replacement.

    Args:
        data: Mutable executable bytes.
        layout: Parsed original PE layout for RVA translation and image base.
        new_section_rva: RVA of the newly added `.hidpi` section.
    """
    for name, (site_rva, expected) in PATCH_SITES.items():
        site_offset = rva_to_file_offset(layout, site_rva)
        verify_slice(data, site_offset, expected, name)
        if name == "load2_width":
            replacement = bytes.fromhex("4589d1909090")
        else:
            symbol_offset = HIDPI_SYMBOL_OFFSETS[name]
            source_va = layout.image_base + site_rva
            target_va = layout.image_base + new_section_rva + symbol_offset
            replacement = make_rel32_jump(source_va, target_va, len(expected))
        assert len(replacement) == len(expected)
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
    patch_exception_directory(
        data,
        layout,
        new_section_rva + exception_table_offset,
        exception_table_size,
    )
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
