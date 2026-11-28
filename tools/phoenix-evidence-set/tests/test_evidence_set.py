import hashlib
import json
import tempfile
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phoenix_evidence_set import validate_manifest


class EvidenceSetValidatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write_report(self, name, tool, identity):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"tool": tool, "firmware_identity": identity}
        raw = json.dumps(payload, sort_keys=True).encode()
        path.write_bytes(raw)
        return {
            "name": name,
            "path": name,
            "expected_tool": tool,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    def identity(self, product_type, version, build):
        return {
            "product_type": product_type,
            "product_version": version,
            "build_version": build,
            "build_train": "SyntheticTrain",
            "board_identity": "synthetic-board",
        }

    def manifest(self, target_reports, donor_reports, target_identity=None, donor_identity=None):
        return {
            "schema_version": 1,
            "tool": "Phoenix Evidence Set Validator Manifest",
            "evidence_sets": {
                "target": {
                    "role": "target",
                    "identity": target_identity or self.identity("Target1,1", "27.3", "T1"),
                    "reports": target_reports,
                },
                "donor": {
                    "role": "donor",
                    "identity": donor_identity or self.identity("Donor1,1", "27.3", "D1"),
                    "reports": donor_reports,
                },
            },
        }

    def test_valid_independent_target_and_donor_sets(self):
        ti = self.identity("Target1,1", "27.3", "T1")
        di = self.identity("Donor1,1", "27.3", "D1")
        target = [self.write_report("target/macho.json", "Phoenix Mach-O Analyzer", ti)]
        donor = [self.write_report("donor/macho.json", "Phoenix Mach-O Analyzer", di)]
        result = validate_manifest(self.manifest(target, donor, ti, di), self.root)
        self.assertEqual(result["status"], "valid")

    def test_missing_report_identity_is_incomplete(self):
        report = {"tool": "Phoenix Mach-O Analyzer"}
        path = self.root / "target/macho.json"
        path.parent.mkdir(parents=True)
        raw = json.dumps(report).encode()
        path.write_bytes(raw)
        entry = {
            "name": "macho",
            "path": "target/macho.json",
            "expected_tool": "Phoenix Mach-O Analyzer",
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        donor_identity = self.identity("Donor1,1", "27.3", "D1")
        donor = [self.write_report("donor/macho.json", "Phoenix Mach-O Analyzer", donor_identity)]
        result = validate_manifest(self.manifest([entry], donor, self.identity("Target1,1", "27.3", "T1"), donor_identity), self.root)
        self.assertEqual(result["evidence_sets"]["target"]["status"], "incomplete")
        self.assertEqual(result["status"], "incomplete")

    def test_hash_mismatch_is_invalid(self):
        ti = self.identity("Target1,1", "27.3", "T1")
        di = self.identity("Donor1,1", "27.3", "D1")
        target = [self.write_report("target/macho.json", "Phoenix Mach-O Analyzer", ti)]
        donor = [self.write_report("donor/macho.json", "Phoenix Mach-O Analyzer", di)]
        target[0]["sha256"] = "0" * 64
        result = validate_manifest(self.manifest(target, donor, ti, di), self.root)
        self.assertEqual(result["status"], "invalid")

    def test_report_identity_conflict_is_invalid(self):
        ti = self.identity("Target1,1", "27.3", "T1")
        ti_other = self.identity("Target1,1", "27.3", "T2")
        di = self.identity("Donor1,1", "27.3", "D1")
        target = [
            self.write_report("target/macho.json", "Phoenix Mach-O Analyzer", ti),
            self.write_report("target/kc.json", "Phoenix Kernel Collection Inspector", ti_other),
        ]
        donor = [self.write_report("donor/macho.json", "Phoenix Mach-O Analyzer", di)]
        result = validate_manifest(self.manifest(target, donor, ti, di), self.root)
        self.assertEqual(result["evidence_sets"]["target"]["status"], "invalid")

    def test_tool_mismatch_is_invalid(self):
        ti = self.identity("Target1,1", "27.3", "T1")
        di = self.identity("Donor1,1", "27.3", "D1")
        target = [self.write_report("target/macho.json", "Unexpected Tool", ti)]
        donor = [self.write_report("donor/macho.json", "Phoenix Mach-O Analyzer", di)]
        target[0]["expected_tool"] = "Phoenix Mach-O Analyzer"
        result = validate_manifest(self.manifest(target, donor, ti, di), self.root)
        self.assertEqual(result["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
