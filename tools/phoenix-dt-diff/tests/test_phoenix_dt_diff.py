import json
import tempfile
import unittest
from pathlib import Path
from phoenix_dt_diff import CompareError, compare, load_report

def report(nodes):
    return {"tool":"Phoenix FDT Analyzer","schema_version":1,"file_sha256":"fdt-hash",
            "node_index":nodes}

def node(path, properties=None):
    return {"path":path,"properties":properties or {},"child_count":0}

def prop(raw, value=None, cells=None):
    result={"raw_hex":raw,"length":len(raw)//2,"kind":"bytes"}
    if value is not None: result["value"]=value
    if cells is not None:
        result["u32_cells"]=cells
    return result

class DeviceTreeComparatorTests(unittest.TestCase):
    def test_detects_added_removed_and_changed_nodes(self):
        target={"path":"t","sha256":"t","report":report([
            node("/"),node("/soc",{"compatible":prop("61626300","abc")}),
            node("/soc/uart",{"status":prop("6f6b617900","okay")})])}
        donor={"path":"d","sha256":"d","report":report([
            node("/"),node("/soc",{"compatible":prop("61626300","abc"),
                                  "model":prop("6d6f64656c00","model")}),
            node("/soc/gpu")])}
        target["index"]={x["path"]:x for x in target["report"]["node_index"]}
        donor["index"]={x["path"]:x for x in donor["report"]["node_index"]}
        result=compare(target,donor)
        self.assertEqual(result["nodes_added_in_donor"],["/soc/gpu"])
        self.assertEqual(result["nodes_missing_from_donor"],["/soc/uart"])
        self.assertEqual(result["summary"]["critical_property_difference_count"],1)

    def test_compatible_intersection(self):
        a={"path":"a","sha256":"a","report":report([node("/x",{
            "compatible":prop("61006200",["a","b"])})])}
        b={"path":"b","sha256":"b","report":report([node("/x",{
            "compatible":prop("62006300",["b","c"])})])}
        a["index"]={x["path"]:x for x in a["report"]["node_index"]}
        b["index"]={x["path"]:x for x in b["report"]["node_index"]}
        result=compare(a,b)
        self.assertEqual(result["shared_compatible_nodes"][0]["shared_compatible_strings"],["b"])

    def test_detects_phandle_value_changes(self):
        a={"path":"a","sha256":"a","report":report([node("/x",{"phandle":prop("00000001",cells=[1])})])}
        b={"path":"b","sha256":"b","report":report([node("/x",{"phandle":prop("00000002",cells=[2])})])}
        a["index"]={x["path"]:x for x in a["report"]["node_index"]}
        b["index"]={x["path"]:x for x in b["report"]["node_index"]}
        self.assertEqual(len(compare(a,b)["phandle_value_changes"]),1)

    def test_rejects_wrong_report_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,"wrong.json")
            p.write_text(json.dumps({"tool":"other","node_index":[node("/")] }))
            with self.assertRaises(CompareError): load_report(p)

    def test_rejects_duplicate_node_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,"dup.json")
            p.write_text(json.dumps(report([node("/x"),node("/x")])))
            with self.assertRaises(CompareError): load_report(p)

    def test_rejects_empty_node_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,"empty.json")
            p.write_text(json.dumps(report([])))
            with self.assertRaises(CompareError): load_report(p)

if __name__=="__main__":
    unittest.main()
