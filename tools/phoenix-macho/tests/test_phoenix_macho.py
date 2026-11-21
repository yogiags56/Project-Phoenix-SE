import struct
import unittest
from phoenix_macho import MachOError, parse_binary

def thin_macho():
    endian="<"
    header=struct.pack(endian+"8I",0xFEEDFACF,0x0100000C,0,2,2,32,0,0)
    uuid=bytes(range(16))
    cmd1=struct.pack(endian+"2I",0x1B,24)+uuid
    cmd2=struct.pack(endian+"6I",0x2,24,56,0,56,0)
    return header+cmd1+cmd2

def fat_macho():
    thin=thin_macho()
    offset=28
    header=struct.pack(">2I",0xCAFEBABE,1)
    arch=struct.pack(">5I",0x0100000C,0,offset,len(thin),2)
    return header+arch+thin

class MachOTests(unittest.TestCase):
    def test_parse_thin_arm64(self):
        report=parse_binary(thin_macho(),"kernel")
        self.assertEqual(report["binary_type"],"thin")
        self.assertEqual(report["slices"][0]["architecture"]["name"],"ARM64")
        self.assertEqual(report["slices"][0]["macho"]["uuid"],bytes(range(16)).hex())
        self.assertTrue(report["slices"][0]["macho"]["summary"]["has_symbol_table"])
    def test_parse_universal(self):
        report=parse_binary(fat_macho(),"universal")
        self.assertEqual(report["binary_type"],"universal32")
        self.assertEqual(report["slice_count"],1)
        self.assertEqual(report["slices"][0]["architecture"]["name"],"ARM64")
    def test_reject_truncated(self):
        with self.assertRaises(MachOError):
            parse_binary(b"abc")
    def test_reject_invalid_magic(self):
        with self.assertRaises(MachOError):
            parse_binary(b"NOPE"+bytes(64))
    def test_reject_command_overflow(self):
        raw=bytearray(thin_macho())
        struct.pack_into("<I",raw,20,0x1000)
        with self.assertRaises(MachOError):
            parse_binary(bytes(raw))

if __name__=="__main__":
    unittest.main()
