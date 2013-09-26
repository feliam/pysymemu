# Copyright (c) 2013, Felipe Andres Manzano
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import unittest
from linux import *
from memory import *
from cpu import *

class LinuxTest(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass

    def test_load_elf_static_64(self):
        mem = Memory(64,12)
        cpu = Cpu(mem, "amd64") # "i386" #"amd64"
        linux = Linux([cpu], mem)
        linux.exe("./binaries/elf-static-64")
        self.assertEqual( '\n'.join(["%016x-%016x %s %08x %s"%(start,end,p,offset, filename) for start,end,p,offset, filename in mem.mappings()]), '0000000000400000-00000000004b6000 r x 00000000 ./helpers/loadelf-static-64\n00000000006b5000-00000000006bb000 rw  000b5000 ./helpers/loadelf-static-64\n00000000006bb000-00000000007b2000 rw 000bb000 ./helpers/loadelf-static-64\n00007ffffffde000-00007ffffffff000 rwx 00000000 ')
        self.assertEqual(linux.elf_brk, 0x00000000007b2000)

    def test_load_elf_static_32(self):
        mem = Memory(32,12)
        cpu = Cpu(mem, "i386") # "i386" #"amd64"
        linux = Linux([cpu], mem)
        linux.exe("./binaries/elf-static-32")
        self.assertEqual( '\n'.join(["%016x-%016x %s %08x %s"%(start,end,p,offset, filename) for start,end,p,offset, filename in mem.mappings()]), "0000000008048000-00000000080ec000 r x 00000000 ./helpers/loadelf-static-32\n00000000080ed000-00000000080f0000 rw  000a4000 ./helpers/loadelf-static-32\n00000000080f0000-00000000081e6000 rw 000a7000 ./helpers/loadelf-static-32\n00000000fffdd000-00000000ffffe000 rwx 00000000 ")
        self.assertEqual(linux.elf_brk, 0x081e6000)


    def test_load_elf_dynamic_64(self):
        mem = Memory(64,12)
        cpu = Cpu(mem, "amd64") # "i386" #"amd64"
        linux = Linux([cpu], mem)
        linux.exe("./binaries/elf-dyn-64")
        self.assertEqual( '\n'.join(["%016x-%016x %s %08x %s"%(start,end,p,offset, filename) for start,end,p,offset, filename in mem.mappings()]), '0000555555554000-0000555555555000 r x 00000000 ./helpers/loadelf-dyn-64\n0000555555754000-0000555555756000 rw  00000000 ./helpers/loadelf-dyn-64\n0000555555756000-000055555584a000 rw 00000000 \n00007ffff7ddb000-00007ffff7dfd000 r x 00000000 /lib64/ld-linux-x86-64.so.2\n00007ffff7ffc000-00007ffff7ffe000 rw  00021000 /lib64/ld-linux-x86-64.so.2\n00007ffff7ffe000-00007ffff7fff000 rw 00023000 /lib64/ld-linux-x86-64.so.2\n00007ffffffde000-00007ffffffff000 rwx 00000000 ')
        self.assertEqual(linux.elf_brk, 0x000055555584a000)


    def test_load_elf_dynamic_32(self):
        mem = Memory(32,12)
        cpu = Cpu(mem, "i386") # "i386" #"amd64"
        linux = Linux([cpu], mem)
        linux.exe("./binaries/elf-dyn-32")
        self.assertEqual( '\n'.join(["%016x-%016x %s %08x %s"%(start,end,p,offset, filename) for start,end,p,offset, filename in mem.mappings()]), '0000000056555000-0000000056556000 r x 00000000 ./helpers/loadelf-dyn-32\n0000000056556000-0000000056558000 rw  00000000 ./helpers/loadelf-dyn-32\n0000000056558000-000000005664c000 rw 00000000 \n00000000f7fde000-00000000f7ffc000 r x 00000000 /lib/ld-linux.so.2\n00000000f7ffc000-00000000f7ffe000 rw  0001d000 /lib/ld-linux.so.2\n00000000fffdd000-00000000ffffe000 rwx 00000000 ')
        self.assertEqual(linux.elf_brk, 0x5664c000)

if __name__ == '__main__':
    unittest.main()
