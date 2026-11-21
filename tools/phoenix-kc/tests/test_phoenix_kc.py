import struct
import unittest
from phoenix_kc import FilesetError, inspect_fileset

def fixture():
    entry_offset=80
    embedded=struct.pack("<8I",0xFEEDFACF,0x0100000C,0,2,0,0,0,0)
    command=bytearray(40)
    struct.pack_into("<IIQQII",command,0,0x80000035,40,0xFFFFFFF007004000,entry_offset,32,0)
    command[32:40]=b"kernel\x00\x00"
    header=struct.pack("<8I",0xFEEDFACF,0x0100000C,0,0xC,1,len(command),0,0)
    return header+bytes(command)+bytes(entry_offset-(32+len(command)))+embedded

class KernelCollectionTests(unittest.TestCase):
    def test_inspect_fileset_entry(self):
        r=inspect_fileset(fixture(),"fixture.kc")
        self.assertEqual(r["container"]["format"],"Mach-O MH_FILESET")
        self.assertEqual(r["summary"]["entry_count"],1)
        self.assertEqual(r["entries"][0]["identifier"],"kernel")
        self.assertTrue(r["entries"][0]["embedded_macho"]["valid"])
    def test_reject_non_fileset(self):
        raw=bytearray(fixture()); struct.pack_into("<I",raw,12,2)
        with self.assertRaises(FilesetError): inspect_fileset(bytes(raw))
    def test_reject_truncated(self):
        with self.assertRaises(FilesetError): inspect_fileset(b"short")
    def test_reject_entry_offset(self):
        raw=bytearray(fixture()); struct.pack_into("<Q",raw,48,0xFFFFFFFF)
        with self.assertRaises(FilesetError): inspect_fileset(bytes(raw))
    def test_reject_bad_command_size(self):
        raw=bytearray(fixture()); struct.pack_into("<I",raw,36,4)
        with self.assertRaises(FilesetError): inspect_fileset(bytes(raw))

if __name__=="__main__": unittest.main()
