import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phoenix_kernel_compat import KernelAnalysisError, validate_evidence_set_gate


def report(path, tool):
    raw = json.dumps({"tool": tool}, sort_keys=True).encode()
    Path(path).write_bytes(raw)
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "data": {"tool": tool}}


class EvidenceSetGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.inputs = {}
        tools = {
            "macho": "Phoenix Mach-O Analyzer",
            "kc": "Phoenix Kernel Collection Inspector",
            "kext": "Phoenix Kext Dependency Analyzer",
        }
        for role in ("target", "donor"):
            self.inputs[role] = {}
            for name, tool in tools.items():
                path = self.root / role / (name + ".json")
                path.parent.mkdir(parents=True, exist_ok=True)
                self.inputs[role][name] = report(path, tool)

        evidence_sets = {}
        for role in ("target", "donor"):
            evidence_sets[role] = {
                "status": "valid",
                "reports": [
                    {"name": name, "actual_sha256": value["sha256"]}
                    for name, value in self.inputs[role].items()
                ],
            }
        self.validation = {
            "tool": "Phoenix Evidence Set Validator",
            "status": "valid",
            "evidence_sets": evidence_sets,
        }
        self.validation_path = self.root / "validation.json"
        self.write_validation()

    def tearDown(self):
        self.tmp.cleanup()

    def write_validation(self):
        self.validation_path.write_text(json.dumps(self.validation), encoding="utf-8")

    def test_valid_gate_accepts_matching_six_hashes(self):
        digest = validate_evidence_set_gate(self.validation_path, self.inputs["target"], self.inputs["donor"])
        self.assertEqual(len(digest), 64)

    def test_non_valid_evidence_set_is_rejected(self):
        self.validation["evidence_sets"]["donor"]["status"] = "incomplete"
        self.write_validation()
        with self.assertRaises(KernelAnalysisError):
            validate_evidence_set_gate(self.validation_path, self.inputs["target"], self.inputs["donor"])

    def test_report_hash_mismatch_is_rejected(self):
        self.validation["evidence_sets"]["target"]["reports"][0]["actual_sha256"] = "0" * 64
        self.write_validation()
        with self.assertRaises(KernelAnalysisError):
            validate_evidence_set_gate(self.validation_path, self.inputs["target"], self.inputs["donor"])

    def test_missing_report_is_rejected(self):
        self.validation["evidence_sets"]["donor"]["reports"].pop()
        self.write_validation()
        with self.assertRaises(KernelAnalysisError):
            validate_evidence_set_gate(self.validation_path, self.inputs["target"], self.inputs["donor"])


if __name__ == "__main__":
    unittest.main()
