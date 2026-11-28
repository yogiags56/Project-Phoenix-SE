import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phoenix_a9_evidence import EvidenceError, collect


class A9EvidenceCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def entry(self, name, kind, path, data, provenance=None):
        return {
            "name": name,
            "kind": kind,
            "path": path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "provenance": provenance or {"origin": "synthetic-fixture"},
        }

    def test_collects_all_groups_with_hashes(self):
        sources = [
            ("regs.txt", "cpu_registers", b"MIDR_EL1=0x410fd030\n"),
            ("cpuinfo.txt", "cpuinfo", b"processor : 0\nCPU implementer : 0x41\nCPU part : 0xd03\n"),
            ("dt.txt", "device_tree_summary", b"model=synthetic\ncompatible=synthetic,board\n"),
            ("config.txt", "kernel_config", b"CONFIG_ARM64=y\nCONFIG_SMP=y\n"),
        ]
        entries = []
        for path, kind, data in sources:
            self.write(path, data)
            entries.append(self.entry(path, kind, path, data))
        manifest = {
            "schema_version": 1,
            "tool": "Phoenix A9 Platform Evidence Manifest",
            "sources": entries,
        }
        result = collect(manifest, self.root)
        self.assertEqual(result["status"], "collected")
        self.assertEqual(result["missing_evidence_groups"], [])
        self.assertEqual(len(result["sources"]), 4)
        self.assertEqual(result["evidence"]["cpu_registers"]["MIDR_EL1"], int("410fd030", 16))

    def test_missing_groups_are_incomplete_not_guessed(self):
        data = b"MIDR_EL1=0x410fd030\n"
        self.write("regs.txt", data)
        manifest = {
            "schema_version": 1,
            "tool": "Phoenix A9 Platform Evidence Manifest",
            "sources": [self.entry("registers", "cpu_registers", "regs.txt", data)],
        }
        result = collect(manifest, self.root)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("cpuinfo", result["missing_evidence_groups"])
        self.assertEqual(result["evidence"]["cpuinfo"]["processors"], [])

    def test_hash_mismatch_rejected(self):
        data = b"CONFIG_ARM64=y\n"
        self.write("config.txt", data)
        entry = self.entry("config", "kernel_config", "config.txt", data)
        entry["sha256"] = "0" * 64
        manifest = {
            "schema_version": 1,
            "tool": "Phoenix A9 Platform Evidence Manifest",
            "sources": [entry],
        }
        with self.assertRaises(EvidenceError):
            collect(manifest, self.root)

    def test_path_escape_rejected(self):
        manifest = {
            "schema_version": 1,
            "tool": "Phoenix A9 Platform Evidence Manifest",
            "sources": [{
                "name": "outside",
                "kind": "cpu_registers",
                "path": "../outside.txt",
            }],
        }
        with self.assertRaises(EvidenceError):
            collect(manifest, self.root)

    def test_unrecognized_registers_are_not_imported(self):
        data = b"MIDR_EL1=0x410fd030\nUNKNOWN_REGISTER=0x1234\n"
        self.write("regs.txt", data)
        manifest = {
            "schema_version": 1,
            "tool": "Phoenix A9 Platform Evidence Manifest",
            "sources": [self.entry("registers", "cpu_registers", "regs.txt", data)],
        }
        result = collect(manifest, self.root)
        self.assertNotIn("UNKNOWN_REGISTER", result["evidence"]["cpu_registers"])
        self.assertTrue(any("unrecognized key" in warning for warning in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
