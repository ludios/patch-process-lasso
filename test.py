#!/usr/bin/env python3
# Model-output: Claude Fable 5
"""Regression tests for the assembly-authored Process Lasso HiDPI patch."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
FIXTURE_PATH = PROJECT_ROOT / "fixtures" / "hidpi_code_legacy.bin"
LEGACY_FIXTURE_SHA256 = "51f35d96033d951af65decef14ece59960ee3f222802d7f55002cc13e9c3aa97"
ORIGINAL_EXE = Path(os.environ.get("PROCESS_LASSO_EXE", PROJECT_ROOT / "ProcessLasso.exe"))

sys.path.insert(0, str(PROJECT_ROOT))
import patch as patcher  # noqa: E402

BINUTILS_AVAILABLE = all(shutil.which(tool) is not None for tool in patcher.BINUTILS_TOOLS)


class AssemblyRegressionTests(unittest.TestCase):
    """Verify generated code against the previous hand-authored payload."""

    def test_legacy_fixture_is_exact(self) -> None:
        """Pin the legacy fixture itself by size and SHA-256."""
        legacy = FIXTURE_PATH.read_bytes()
        self.assertEqual(len(legacy), patcher.LEGACY_HIDPI_CODE_SIZE)
        self.assertEqual(hashlib.sha256(legacy).hexdigest(), LEGACY_FIXTURE_SHA256)

    @unittest.skipUnless(BINUTILS_AVAILABLE, "GNU binutils (as/ld/objcopy) not found on PATH")
    def test_each_live_block_matches_legacy_machine_code(self) -> None:
        """Assemble every live routine and require byte-for-byte parity with the old payload."""
        legacy = FIXTURE_PATH.read_bytes()
        for block in patcher.HIDPI_ASSEMBLY_BLOCKS:
            if block.end_offset > len(legacy):
                continue
            with self.subTest(block=block.name):
                address  = patcher.HIDPI_CODE_BASE_VA + block.offset
                actual   = patcher.assemble_x86_64(block.source, address)
                expected = legacy[block.offset:block.end_offset]
                self.assertEqual(actual, expected)


    @unittest.skipUnless(BINUTILS_AVAILABLE, "GNU binutils (as/ld/objcopy) not found on PATH")
    def test_new_layout_blocks_match_independent_reference(self) -> None:
        """Pin the new reservation/gap trampolines against independently assembled bytes."""
        expected_sha256 = {
            "fixed_load_reservation_1": "d17277bb19eb5d987e043e8424d17b61bf16ec805c58ac9489012287fb5ef698",
            "fixed_load_reservation_2": "201e6223bd6009413e533c8687a4fe3f74eaece973127adaf91444eb427842e1",
            "load2_gap": "08b4762366f37340a2f9ae0099c603a0ce18ebc8e4af84ea214806b127679350",
            "processor_gap": "3492f24c782f47c0605f4097098a53c1b227b9d8aa2701b5cd96c77740a0edcd",
        }
        blocks = {block.name: block for block in patcher.HIDPI_ASSEMBLY_BLOCKS}
        for name, expected_hash in expected_sha256.items():
            with self.subTest(block=name):
                block   = blocks[name]
                address = patcher.HIDPI_CODE_BASE_VA + block.offset
                actual  = patcher.assemble_x86_64(block.source, address)
                self.assertEqual(hashlib.sha256(actual).hexdigest(), expected_hash)

    @unittest.skipUnless(BINUTILS_AVAILABLE, "GNU binutils (as/ld/objcopy) not found on PATH")
    def test_bar_height_blocks_match_independent_reference(self) -> None:
        """Pin the two tab-bar-height trampolines and their shared MulDiv helper."""
        expected_sha256 = {
            "bar_metrics": "3993104d02c784a448832b3cd146b58d16e4b30fc997e60f8562a6f560df07c3",
            "upper_bar_height": "1b6b3bbbd4f72bd4ff61d46c5d103f7e4109683760b4f13af89d8a2f9cac6fc2",
            "lower_bar_height": "225cec39741cb5501e3c0de3fbf31321b6750a295045335acff57fde48724d6c",
            "main_system_parameters_info": "2615947debb1cf55874cdd3445ce86933e28d95a1ebaf951e72562900134a0c2",
            "upper_search_icon_square": "8ec8c7cb527c7517520ab5ffda2a6859a5ea7189bcef05bdb65c7cc7943935b4",
            "lower_search_icon_square": "df627f2f34ab569d6fe4c1a7515fa8f6b04e12c308c72e130d894d17ac7496d5",
        }
        blocks = {block.name: block for block in patcher.HIDPI_ASSEMBLY_BLOCKS}
        for name, expected_hash in expected_sha256.items():
            with self.subTest(block=name):
                block   = blocks[name]
                address = patcher.HIDPI_CODE_BASE_VA + block.offset
                actual  = patcher.assemble_x86_64(block.source, address)
                self.assertEqual(hashlib.sha256(actual).hexdigest(), expected_hash)

    @unittest.skipUnless(BINUTILS_AVAILABLE, "GNU binutils (as/ld/objcopy) not found on PATH")
    def test_inplace_replacements_preserve_slice_length(self) -> None:
        """Require each in-place replacement to reassemble to its original slice length."""
        for name, (rva, expected, replacement_source) in patcher.INPLACE_PATCH_SITES.items():
            with self.subTest(site=name):
                replacement = patcher.assemble_x86_64(replacement_source, patcher.EXPECTED_IMAGE_BASE + rva)
                self.assertEqual(len(replacement), len(expected))

    def test_fixed_load_reservations_replace_the_complete_96_dpi_branches(self) -> None:
        """Require each hook to cover the old 65 px reservation and its 160 px visibility test."""
        first_rva, first_bytes   = patcher.PATCH_SITES["fixed_load_reservation_1"]
        second_rva, second_bytes = patcher.PATCH_SITES["fixed_load_reservation_2"]
        self.assertEqual(first_rva, 0x050A72)
        self.assertEqual(second_rva, 0x050AB2)
        self.assertEqual(first_bytes, bytes.fromhex("8d429c83f83c7e0b83c2bf8997c8090000eb0341b601"))
        self.assertEqual(second_bytes, bytes.fromhex("8d429c83f83c7e0b8d4abf898fc8090000eb0341b401"))
        load2_gap_rva, load2_gap_bytes       = patcher.PATCH_SITES["load2_gap"]
        processor_gap_rva, processor_bytes  = patcher.PATCH_SITES["processor_gap"]
        self.assertEqual(load2_gap_rva, 0x050C1E)
        self.assertEqual(processor_gap_rva, 0x050CF3)
        self.assertEqual(load2_gap_bytes, bytes.fromhex("8b87d00a000083e805"))
        self.assertEqual(processor_bytes, bytes.fromhex("412bc083c20589442420"))

    def test_assembly_blocks_are_non_overlapping(self) -> None:
        """Require assembly block ranges to be ordered, bounded, and non-overlapping."""
        previous_end = 0
        for block in patcher.HIDPI_ASSEMBLY_BLOCKS:
            with self.subTest(block=block.name):
                self.assertLess(block.offset, block.end_offset)
                self.assertGreaterEqual(block.offset, previous_end)
                self.assertLessEqual(block.end_offset, patcher.HIDPI_CODE_SIZE)
                previous_end = block.end_offset

    @unittest.skipUnless(BINUTILS_AVAILABLE, "GNU binutils (as/ld/objcopy) not found on PATH")
    def test_generated_data_references_keep_their_legacy_offsets(self) -> None:
        """Require generated strings to stay at the offsets used by RIP-relative code."""
        code = patcher.assemble_hidpi_code()
        user32 = "user32.dll".encode("utf-16le") + b"\0\0"
        self.assertEqual(code[patcher.USER32_DLL_OFFSET:patcher.USER32_DLL_OFFSET + len(user32)], user32)
        get_dpi_name = b"GetDpiForWindow\0"
        self.assertEqual(
            code[patcher.GET_DPI_FOR_WINDOW_NAME_OFFSET:patcher.GET_DPI_FOR_WINDOW_NAME_OFFSET + len(get_dpi_name)],
            get_dpi_name,
        )
        spi_name = b"SystemParametersInfoForDpi\0"
        self.assertEqual(
            code[
                patcher.SYSTEM_PARAMETERS_INFO_FOR_DPI_NAME_OFFSET:
                patcher.SYSTEM_PARAMETERS_INFO_FOR_DPI_NAME_OFFSET + len(spi_name)
            ],
            spi_name,
        )

    @unittest.skipUnless(BINUTILS_AVAILABLE, "GNU binutils (as/ld/objcopy) not found on PATH")
    def test_removed_legacy_dead_trampoline_is_not_emitted(self) -> None:
        """Keep the previously unreachable 0x280 trampoline out of generated code."""
        code = patcher.assemble_hidpi_code()
        self.assertEqual(code[0x0280:0x02E0], b"\xCC" * 0x60)

    @unittest.skipUnless(BINUTILS_AVAILABLE, "GNU binutils (as/ld/objcopy) not found on PATH")
    def test_rel32_jump_without_padding_is_exactly_five_bytes(self) -> None:
        """Exercise the five-byte hook case without asking Keystone to assemble empty source."""
        jump = patcher.make_rel32_jump(0x1400509DD, 0x140280050, 5)
        self.assertEqual(len(jump), 5)
        self.assertEqual(jump, bytes.fromhex("e96ef62200"))

    @unittest.skipUnless(ORIGINAL_EXE.is_file(), "set PROCESS_LASSO_EXE or copy ProcessLasso.exe beside the patcher")
    def test_original_hook_sites_still_match_build_lock(self) -> None:
        """Require every hook-site byte sequence to match the exact original executable."""
        original = ORIGINAL_EXE.read_bytes()
        layout   = patcher.parse_pe(original)
        self.assertEqual(hashlib.sha256(original).hexdigest(), patcher.EXPECTED_SHA256)
        for name, (rva, expected) in patcher.PATCH_SITES.items():
            with self.subTest(site=name):
                offset = patcher.rva_to_file_offset(layout, rva)
                self.assertEqual(original[offset:offset + len(expected)], expected)

    @unittest.skipUnless(ORIGINAL_EXE.is_file(), "set PROCESS_LASSO_EXE or copy ProcessLasso.exe beside the patcher")
    def test_original_inplace_sites_still_match_build_lock(self) -> None:
        """Require every in-place replacement site to match the exact original executable."""
        original = ORIGINAL_EXE.read_bytes()
        layout   = patcher.parse_pe(original)
        for name, (rva, expected, _replacement_source) in patcher.INPLACE_PATCH_SITES.items():
            with self.subTest(site=name):
                offset = patcher.rva_to_file_offset(layout, rva)
                self.assertEqual(original[offset:offset + len(expected)], expected)

    @unittest.skipUnless(BINUTILS_AVAILABLE, "GNU binutils (as/ld/objcopy) not found on PATH")
    @unittest.skipUnless(ORIGINAL_EXE.is_file(), "set PROCESS_LASSO_EXE or copy ProcessLasso.exe beside the patcher")
    def test_rebuilt_executable_is_deterministic(self) -> None:
        """Patch the same original twice and require identical output bytes."""
        first  = PROJECT_ROOT / ".test-output-1.exe"
        second = PROJECT_ROOT / ".test-output-2.exe"
        try:
            patcher.patch_process_lasso(ORIGINAL_EXE, first)
            patcher.patch_process_lasso(ORIGINAL_EXE, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
        finally:
            first.unlink(missing_ok=True)
            second.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
