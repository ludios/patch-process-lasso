#!/usr/bin/env python3
"""Regression tests for the assembly-authored Process Lasso HiDPI patch."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "hidpi_code_legacy.bin"
LEGACY_FIXTURE_SHA256 = "51f35d96033d951af65decef14ece59960ee3f222802d7f55002cc13e9c3aa97"
ORIGINAL_EXE = Path(os.environ.get("PROCESS_LASSO_EXE", PROJECT_ROOT / "ProcessLasso.exe"))
KEYSTONE_AVAILABLE = importlib.util.find_spec("keystone") is not None

sys.path.insert(0, str(PROJECT_ROOT))
import patch_process_lasso_hidpi as patcher  # noqa: E402


class AssemblyRegressionTests(unittest.TestCase):
    """Verify generated code against the previous hand-authored payload."""

    def test_legacy_fixture_is_exact(self) -> None:
        """Pin the legacy fixture itself by size and SHA-256."""
        legacy = FIXTURE_PATH.read_bytes()
        self.assertEqual(len(legacy), patcher.HIDPI_CODE_SIZE)
        self.assertEqual(hashlib.sha256(legacy).hexdigest(), LEGACY_FIXTURE_SHA256)

    @unittest.skipUnless(KEYSTONE_AVAILABLE, "keystone-engine is not installed")
    def test_each_live_block_matches_legacy_machine_code(self) -> None:
        """Assemble every live routine and require byte-for-byte parity with the old payload."""
        legacy = FIXTURE_PATH.read_bytes()
        for block in patcher.HIDPI_ASSEMBLY_BLOCKS:
            with self.subTest(block=block.name):
                address  = patcher.HIDPI_CODE_BASE_VA + block.offset
                actual   = patcher.assemble_x86_64(block.source, address)
                expected = legacy[block.offset:block.end_offset]
                self.assertEqual(actual, expected)

    def test_assembly_blocks_are_non_overlapping(self) -> None:
        """Require assembly block ranges to be ordered, bounded, and non-overlapping."""
        previous_end = 0
        for block in patcher.HIDPI_ASSEMBLY_BLOCKS:
            with self.subTest(block=block.name):
                self.assertLess(block.offset, block.end_offset)
                self.assertGreaterEqual(block.offset, previous_end)
                self.assertLessEqual(block.end_offset, patcher.HIDPI_CODE_SIZE)
                previous_end = block.end_offset

    @unittest.skipUnless(KEYSTONE_AVAILABLE, "keystone-engine is not installed")
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

    @unittest.skipUnless(KEYSTONE_AVAILABLE, "keystone-engine is not installed")
    def test_removed_legacy_dead_trampoline_is_not_emitted(self) -> None:
        """Keep the previously unreachable 0x280 trampoline out of generated code."""
        code = patcher.assemble_hidpi_code()
        self.assertEqual(code[0x0280:0x02E0], b"\xCC" * 0x60)

    @unittest.skipUnless(KEYSTONE_AVAILABLE, "keystone-engine is not installed")
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

    @unittest.skipUnless(KEYSTONE_AVAILABLE, "keystone-engine is not installed")
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
