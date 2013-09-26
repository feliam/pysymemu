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

from cStringIO import StringIO
from smtlibv2 import Solver, issymbolic, isconcrete, OR, AND, chr, ord
import unittest
import tempfile, os
import gc, pickle
import fcntl
import resource

from memory import *

class MemoryTest(unittest.TestCase):
    def get_open_fds(self):
        fds = []
        for fd in range(3, resource.RLIMIT_NOFILE):
            try:
                flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            except IOError:
                continue
            fds.append(fd)
        return fds

    def setUp(self):
        self.fds = self.get_open_fds()
    def tearDown(self):
        gc.collect()
        gc.garbage = []
        gc.collect()
        self.assertEqual(self.fds, self.get_open_fds())

    def test_ceil_floor_page_memory_page_12(self):
        mem = Memory(32, 12)
        #Basic check ceil
        self.assertEqual(0x12346000, mem._ceil(0x12345678))
        self.assertEqual(0x12347000, mem._ceil(0x12346000))
        self.assertEqual(0x00000000, mem._ceil(0xffffffff))
        #Basic check floor
        self.assertEqual(0x12345000, mem._floor(0x12345678))
        self.assertEqual(0x12345000, mem._floor(0x12345000))
        self.assertEqual(0xfffff000, mem._floor(0xffffffff))
        #Basic check page
        self.assertEqual(0x12345, mem._page(0x12345678))
        self.assertEqual(0x12345, mem._page(0x12345000))
        self.assertEqual(0xfffff, mem._page(0xffffffff))

    def test_ceil_floor_page_memory_page_13(self):
        mem = SMemory(Solver(), 32, 13)
        self.assertEqual(0x00004000, mem._ceil(0x00002000))
        self.assertEqual(0x00002000, mem._floor(0x00002000))
        self.assertEqual(0x00000001, mem._page(0x00003FFF))

        self.assertEqual(0xABC0E000, mem._ceil(0xABC0D590))
        self.assertEqual(0xABC0C000, mem._floor(0xABC0D590))
        self.assertEqual(0x55E06, mem._page(0xABC0D590))

    def test_search_and_mmap_several_chunks_memory_page_12(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        #Check the search gives basically any value as the mem is free
        self.assertEqual(mem._search(0x1000, 0x20000000), 0x20000000)

        #alloc/map a byte
        first = mem.mmap(None, 0x0001, 'r')
        search = mem._search(0x1000, 0)

        #alloc/map a byte
        second = mem.mmap(0x1000, 0x1000, 'w')
                    
        #alloc/map a byte
        third = mem.mmap(0x2000, 0x1000, 'x')
        
        #Okay 3 maps
        self.assertEqual(len(mem.mappings()), 3)

        self.assertTrue(mem.isValid(first))
        self.assertTrue(mem.isReadable(first))
        self.assertTrue(mem.isConcrete(first))

        self.assertTrue(mem.isValid(second))
        self.assertTrue(mem.isWriteable(second))
        self.assertTrue(mem.isConcrete(second))
        self.assertTrue(mem.isValid(third))
        self.assertTrue(mem.isExecutable(third))
        self.assertTrue(mem.isConcrete(third))

        self.assertFalse(mem.isValid(first-1))
        self.assertTrue(mem.isValid(third-1))
        self.assertTrue(mem.isValid(second+1))
        self.assertFalse(mem.isValid(mem._ceil(third)))

        self.assertEqual(mem._search(0x1000, 0x1000), mem._ceil(third))
        self.assertEqual(mem._search(0x1000, 0x10000000), mem._ceil(first))
        
        #---------alloc in the free spaces now!----------------
        forth = mem.mmap(second, 0x1000, 'x')
        self.assertEqual(forth, mem._ceil(third))
        self.assertTrue(mem.isValid(forth))
        self.assertTrue(mem.isExecutable(forth))
        self.assertTrue(mem.isConcrete(forth))

    def test_search_and_mmap_several_chunks_testing_limits_memory_page_12(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        #Check the search gives basically any value as the mem is free
        self.assertEqual(mem._search(0x1000, 0x20000000), 0x20000000)

        #alloc/map a byte
        first = mem.mmap(0xFFFF000, 0x0001, 'r')
        zero  = mem.mmap(0x0001, 0x0001, 'w')

        #Okay 2 map
        self.assertEqual(len(mem.mappings()), 2)

        self.assertTrue(mem.isValid(first))
        self.assertTrue(mem.isReadable(first))
        self.assertTrue(mem.isConcrete(first))

        self.assertTrue(mem.isValid(zero))
        self.assertRaises(AssertionError, mem.mmap, 0x0000F000, 0, 'r')
        
        self.assertEqual(zero, 0)

    def test_try_to_allocate_greater_than_last_space_memory_page_12(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        #alloc/map a byte
        first = mem.mmap(0xFFFFF000, 0x1001, 'r')

        #Okay 2 map
        self.assertEqual(len(mem.mappings()), 1)

        self.assertTrue(mem.isValid(first))
        self.assertTrue(mem.isReadable(first))
        self.assertTrue(mem.isConcrete(first))

        self.assertFalse(mem.isValid(0xFFFF0001))

    def test_not_enough_memory_page_12(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        #alloc/map a chunk
        first = mem.mmap((0x100000000/2), 0x1000, 'r')

        #Okay 2 map
        self.assertEqual(len(mem.mappings()), 1)

        self.assertTrue(mem.isValid(first))
        self.assertTrue(mem.isReadable(first))
        self.assertTrue(mem.isConcrete(first))

        self.assertRaises(MemoryException, mem.mmap, 0, (0x100000000/2)+1, 'r')

    def testBasicAnonMap(self):
        m = MMapAnon(0x10000000, 0x2000, 'rwx')
        
        #Check the size
        self.assertEqual(len(m), 0x2000)

        #check the outside limits
        self.assertRaises(MemoryException, m.putchar, 0x10000000-1, 'A')
        self.assertRaises(MemoryException, m.putchar, 0x10002000, 'A')
        self.assertRaises(MemoryException, m.getchar, 0x10000000-1)
        self.assertRaises(MemoryException, m.getchar, 0x10002000)


        #check it is initialized with zero
        self.assertEqual(m.getchar(0x10000000), chr(0))
        self.assertEqual(m.getchar(0x10002000-1), chr(0))


        #check all characters go and come back the same...
        #at the first byte of the mapping
        addr = 0x10000000
        for c in xrange(0, 0x100):
            m.putchar(addr, chr(c))
            self.assertEqual(m.getchar(addr), chr(c))

        #at the last byte of the mapping
        addr = 0x10002000-1
        for c in xrange(0, 0x100):
            m.putchar(addr, chr(c))
            self.assertEqual(m.getchar(addr), chr(c))

    def test_basic_put_char_get_char(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)
        
        #alloc/map a litlle mem
        addr = mem.mmap(None, 0x10, 'r')
        for c in xrange(0, 0x10):
            self.assertRaises(MemoryException, mem.putchar, addr+c, 'a')

        addr = mem.mmap(None, 0x10, 'x')
        for c in xrange(0, 0x10):
            self.assertRaises(MemoryException, mem.putchar, addr+c, 'a')

        addr = mem.mmap(None, 0x10, 'w')
        for c in xrange(0, 0x10):
            mem.putchar(addr+c, 'a')
        for c in xrange(0, 0x10):
            self.assertRaises(MemoryException, mem.getchar, addr+c)

        addr = mem.mmap(None, 0x10, 'wx')
        for c in xrange(0, 0x10):
            mem.putchar(addr+c, 'a')
        for c in xrange(0, 0x10):
            self.assertRaises(MemoryException, mem.getchar, addr+c)

        addr = mem.mmap(None, 0x10, 'rw')
        for c in xrange(0, 0x10):
            mem.putchar(addr+c, 'a')
        for c in xrange(0, 0x10):
            self.assertEquals(mem.getchar(addr+c), 'a')

    def testBasicMappingsLimits(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        #Check the search gives basically any value as the mem is free
        self.assertEqual(mem._search(0x1000, 0x20000000), 0x20000000)

        #alloc/map a litlle mem
        size = 0x1000
        addr = mem.mmap(None, size, 'rwx')

        #Okay 1 map
        self.assertEqual(len(mem.mappings()), 1)

        #positive tests
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size-1))

        for i in xrange(addr, addr+size):
            self.assertTrue(mem.isValid(i))

        #negative tests
        self.assertFalse(mem.isValid(0))
        self.assertFalse(mem.isValid(0xffffffff))
        self.assertFalse(mem.isValid(-1))
        self.assertFalse(mem.isValid(0xfffffffffffffffffffffffffff))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+0x1000))

        #check all characters go and come back the same...
        for c in xrange(0, 0x100):
            mem.putchar(addr+0x800, chr(c))
            self.assertEqual(mem.getchar(addr+0x800), chr(c))

    def testBasicMappingsPermissions(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        #Chack the search gives basically any value as the mem is free
        self.assertEqual(mem._search(0x1000, 0x20000000), 0x20000000)

        #alloc/map a litlle mem
        size = 0x1000
        addr = mem.mmap(None, 0x1000, 'r')

        #Okay 1 map
        self.assertEqual(len(mem.mappings()), 1)

        #positive tests
        self.assertTrue(mem.isValid(addr))
        self.assertFalse(mem.isWriteable(addr))
        self.assertFalse(mem.isExecutable(addr))
        self.assertTrue(mem.isReadable(addr))
        self.assertTrue(mem.isConcrete(addr))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isWriteable(addr+size-1))
        self.assertFalse(mem.isExecutable(addr+size-1))
        self.assertTrue(mem.isReadable(addr+size-1))
        self.assertTrue(mem.isConcrete(addr+size-1))


        #ad hoc razonable tests
        self.assertFalse(mem.isValid(0))
        self.assertFalse(mem.isValid(0xffffffff))
        self.assertFalse(mem.isValid(-1))
        self.assertFalse(mem.isValid(0xfffffffffffffffffffffffffff))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isWriteable(addr-1))
        self.assertFalse(mem.isExecutable(addr-1))
        self.assertFalse(mem.isReadable(addr-1))
        self.assertFalse(mem.isConcrete(addr-1))
        self.assertFalse(mem.isValid(addr+size))
        self.assertFalse(mem.isWriteable(addr+size))
        self.assertFalse(mem.isExecutable(addr+size))
        self.assertFalse(mem.isReadable(addr+size))
        self.assertFalse(mem.isConcrete(addr+size))

    def testBasicUnmapping(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x10000
        #alloc/map a little mem
        addr = mem.mmap(None, size, 'rwx')

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size))

        #Okay unmap 
        mem.munmap(addr, size)

        #Okay 0 maps
        self.assertEqual(len(mem.mappings()), 0)

        #limits
        self.assertFalse(mem.isValid(addr))
        self.assertFalse(mem.isValid(addr+size-1))

        #re alloc mem should be at the same address
        addr1 = mem.mmap(addr, size, 'rwx')
        self.assertEqual(addr1, addr)

    def testBasicUnmappingBegginning(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x10000
        #alloc/map a little mem
        addr = mem.mmap(None, size, 'rwx')

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size))

        #Okay unmap 
        mem.munmap(addr, size/2)

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertFalse(mem.isValid(addr))
        self.assertFalse(mem.isValid(addr+size/2-1))
        self.assertTrue(mem.isValid(addr+size/2))
        self.assertTrue(mem.isValid(addr+size-1))

        #re alloc mem should be at the same address
        addr1 = mem.mmap(addr, size/2, 'rwx')
        self.assertEqual(addr1, addr)

    def testBasicUnmappingEnd(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x10000
        #alloc/map a little mem
        addr = mem.mmap(None, size, 'rwx')

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size))

        #Okay unmap 
        mem.munmap(addr+size/2, size)

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size/2-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size/2))
        self.assertFalse(mem.isValid(addr+size-1))

    def testBasicUnmappingMiddle(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x30000
        #alloc/map a little mem
        addr = mem.mmap(None, size, 'rwx')

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size))

        #Okay unmap 
        mem.munmap(addr+size/3, size/3)

        #Okay 2 maps
        self.assertEqual(len(mem.mappings()), 2)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size/3-1))
        self.assertTrue(mem.isValid(addr+2*size/3))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size/3))
        self.assertFalse(mem.isValid(addr+2*size/3-1))
        self.assertFalse(mem.isValid(addr+size))

        addr1 = mem.mmap(None, size/3, 'rwx')
        self.assertEqual(addr1, addr+size/3)

    def testBasicUnmapping2(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        #Check the search gives basically any value as the mem is free
        self.assertEqual(mem._search(0x1000, 0x20000000), 0x20000000)

        size = 0x10000
        #alloc/map a little mem
        addr0 = mem.mmap(None, size, 'rwx')

        #alloc/map another little mem
        addr1 = mem.mmap(addr0+size, size, 'rw')

        #They are consecutive
        self.assertEqual(addr0+size, addr1)

        #and 2 maps
        self.assertEqual(len(mem.mappings()), 2)

        #limits
        self.assertTrue(mem.isValid(addr0))
        self.assertTrue(mem.isValid(addr0+size-1))
        self.assertTrue(mem.isValid(addr1))
        self.assertTrue(mem.isValid(addr1+size-1))
        self.assertFalse(mem.isValid(addr0-1))
        self.assertFalse(mem.isValid(addr1+size))

        #Okay unmap a section touching both mappings
        mem.munmap(addr0+size/2, size)

        #Still 2 maps
        self.assertEqual(len(mem.mappings()), 2)

        #limits
        self.assertTrue(mem.isValid(addr0))
        self.assertTrue(mem.isValid(addr0 + size/2-1))
        self.assertTrue(mem.isValid(addr1 + size/2))
        self.assertTrue(mem.isValid(addr1 + size-1))

        self.assertFalse(mem.isValid(addr0-1))
        self.assertFalse(mem.isValid(addr0+size/2))
        self.assertFalse(mem.isValid(addr1+size/2-1))
        self.assertFalse(mem.isValid(addr1+size))
        self.assertFalse(mem.isValid(addr1))


        for addr in xrange(0x0000000010008000, 0x0000000010018000, 0x10000):
            self.assertFalse(mem.isValid(addr))
        self.assertTrue(mem.isValid(0x0000000010018000))


        #re alloc mem should be at the same address
        addr_re = mem.mmap(addr0+size/2, size-0x1000, 'rwx')
        self.assertEqual(addr_re, addr0+size/2)

        #Now 3 maps
        self.assertEqual(len(mem.mappings()), 3)

    def testBasicUnmappingOverLowerLimit(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x10000
        #alloc/map a little mem
        addr = mem.mmap(0x10000, size, 'rwx')

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size))

        #Okay unmap 
        mem.munmap(addr-size/2, size)

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertTrue(mem.isValid(addr+size/2))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr))
        self.assertFalse(mem.isValid(addr+size/2-1))

    def testBasicUnmappingOverHigherLimit(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x10000
        #alloc/map a little mem
        addr = mem.mmap(0x10000, size, 'rwx')

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size))

        #Okay unmap 
        mem.munmap(addr+size/2, size)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size/2-1))
        self.assertFalse(mem.isValid(addr+size/2))
        self.assertFalse(mem.isValid(addr+size-1))

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

    def testUnmappingAll(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x10000
        #alloc/map a little mem
        addr = mem.mmap(None, size, 'rwx')

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size))

        #Okay unmap 
        mem.munmap(addr, size/2)

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)
        
        #Okay unmap 
        mem.munmap(addr+size/2, size/2)

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 0)

    def testBasicUnmappingOverBothLimits(self):
        mem = SMemory(Solver(), 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x30000
        #alloc/map a little mem
        addr = mem.mmap(0x10000, size, 'rwx')

        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size))

        #Okay unmap 
        mem.munmap(addr+size - size/3, size/2)

        #Okay unmap 
        mem.munmap(addr - (size/2 - size/3), size/2)

        #limits
        
        self.assertTrue(mem.isValid(addr+size - size/3 - 1))
        self.assertFalse(mem.isValid(addr+size - size/3))
        
        self.assertFalse(mem.isValid(addr - (size/2 - size/3) + size/2 - 1))
        self.assertTrue(mem.isValid(addr - (size/2 - size/3) + size/2))
        
        self.assertFalse(mem.isValid(addr))
        self.assertFalse(mem.isValid(addr+size-1))
        #Okay 1 maps
        self.assertEqual(len(mem.mappings()), 1)

    def test_putchar_getchar_mmapFile(self):
        mem = SMemory(Solver(), 32, 12)
        
        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)
        
        rwx_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rwx_file.file.write('a'*0x1001)
        rwx_file.close()
        
        addr_a = mem.mmapFile(0, 0x1000, 'rwx', rwx_file.name)

        self.assertEqual(len(mem.mappings()), 1)
        
        self.assertEqual(mem.getchar(addr_a), 'a')
        self.assertEqual(mem.getchar(addr_a+(0x1000/2)), 'a')
        self.assertEqual(mem.getchar(addr_a+(0x1000-1)), 'a')
        self.assertRaises(MemoryException, mem.getchar, addr_a+(0x1000))
        
        rwx_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rwx_file.file.write('b'*0x1001)
        rwx_file.close()
        
        addr_b = mem.mmapFile(0, 0x1000, 'rw', rwx_file.name)

        self.assertEqual(len(mem.mappings()), 2)
        
        self.assertEqual(mem.getchar(addr_b), 'b')
        self.assertEqual(mem.getchar(addr_b+(0x1000/2)), 'b')
        self.assertEqual(mem.getchar(addr_b+(0x1000-1)), 'b')
        self.assertRaises(MemoryException, mem.getchar, addr_b+(0x1000))
                                             
        rwx_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rwx_file.file.write('c'*0x1001)
        rwx_file.close()

        addr_c = mem.mmapFile(0, 0x1000, 'rx', rwx_file.name)

        self.assertEqual(len(mem.mappings()), 3)
        
        self.assertEqual(mem.getchar(addr_c), 'c')
        self.assertEqual(mem.getchar(addr_c+(0x1000/2)), 'c')
        self.assertEqual(mem.getchar(addr_c+(0x1000-1)), 'c')
        self.assertRaises(MemoryException, mem.getchar, addr_c+(0x1000))
        
        rwx_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rwx_file.file.write('d'*0x1001)
        rwx_file.close()
        
        addr_d = mem.mmapFile(0, 0x1000, 'r', rwx_file.name)

        self.assertEqual(len(mem.mappings()), 4)
        
        self.assertEqual(mem.getchar(addr_d), 'd')
        self.assertEqual(mem.getchar(addr_d+(0x1000/2)), 'd')
        self.assertEqual(mem.getchar(addr_d+(0x1000-1)), 'd')
        self.assertRaises(MemoryException, mem.getchar, addr_d+(0x1000))
        
        rwx_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rwx_file.file.write('e'*0x1001)
        rwx_file.close()
        
        addr_e = mem.mmapFile(0, 0x1000, 'w', rwx_file.name)

        self.assertEqual(len(mem.mappings()), 5)
        
        self.assertRaises(MemoryException, mem.getchar, addr_e)
        self.assertRaises(MemoryException, mem.getchar, addr_e+(0x1000/2))
        self.assertRaises(MemoryException, mem.getchar, addr_e+(0x1000-1))
        self.assertRaises(MemoryException, mem.getchar, addr_e+(0x1000))

    def test_basic_mapping_with_mmapFile(self):
        mem = SMemory(Solver(), 32, 12)
        
        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)
        
        rwx_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rwx_file.file.write('d'*0x1001)
        rwx_file.close()
        addr = mem.mmapFile(0, 0x1000, 'rwx', rwx_file.name)

        #One mapping
        self.assertEqual(len(mem.mappings()), 1)

        for i in xrange(addr, addr+0x1000):
            self.assertTrue(mem.isValid(i))
            self.assertTrue(mem.isReadable(i))
            self.assertTrue(mem.isWriteable(i))

        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isReadable(addr-1))
        self.assertFalse(mem.isWriteable(addr-1))
        self.assertFalse(mem.isValid(addr+0x1000))
        self.assertFalse(mem.isReadable(addr+0x1000))
        self.assertFalse(mem.isWriteable(addr+0x1000))

        self.assertEqual(len(mem.mappings()), 1)
        
        r_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        r_file.file.write('b'*0x1000)
        r_file.close()
        mem.mmapFile(0, 0x1000, 'r', r_file.name)

        #Two mapping
        self.assertEqual(len(mem.mappings()), 2)

        rw_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rw_file.file.write('c'*0x1000)
        rw_file.close()
        mem.mmapFile(None, 0x1000, 'rw', rw_file.name)

        #Three mapping
        self.assertEqual(len(mem.mappings()), 3)
        
        size = 0x30000
        w_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        w_file.file.write('a'*size)
        w_file.close()
        addr = mem.mmapFile(0x20000000, size, 'w', w_file.name)
        
        #Four mapping
        self.assertEqual(len(mem.mappings()), 4)

        #Okay unmap 
        mem.munmap(addr+size/3, size/3)

        #Okay 2 maps
        self.assertEqual(len(mem.mappings()), 5)

        #limits
        self.assertTrue(mem.isValid(addr))
        self.assertTrue(mem.isValid(addr+size/3-1))
        self.assertTrue(mem.isValid(addr+2*size/3))
        self.assertTrue(mem.isValid(addr+size-1))
        self.assertFalse(mem.isValid(addr-1))
        self.assertFalse(mem.isValid(addr+size/3))
        self.assertFalse(mem.isValid(addr+2*size/3-1))
        self.assertFalse(mem.isValid(addr+size))

        #re alloc mem should be at the same address
        addr1 = mem.mmap(addr, size, 'rwx')
        self.assertTrue(addr1, addr)

        #Delete the temporary file
        os.unlink(rwx_file.name)
        os.unlink(r_file.name)
        os.unlink(w_file.name)





    def test_mix_of_concrete_and_symbolic__push_pop_cleaning_store(self):
        #global mainsolver
        my_solver = Solver()
        mem = SMemory(my_solver, 32, 12)
        
        start_mapping_addr = mem.mmap(None, 0x1000, 'rwx')
        
        concrete_addr = start_mapping_addr
        symbolic_addr = start_mapping_addr+1
        
        mem.putchar(concrete_addr, 'C')
        sym = my_solver.mkBitVec(8)
        
        mem.putchar(symbolic_addr, sym)
        my_solver.add(sym.uge(0xfe))
        values = list(my_solver.getallvalues(sym))
        self.assertIn(0xfe, values)
        self.assertIn(0xff, values)
        self.assertNotIn(0x7f, values)
        values = list(my_solver.getallvalues(mem.getchar(symbolic_addr)))
        self.assertIn(0xfe, values)
        self.assertIn(0xff, values)
        self.assertNotIn(0x7f, values)
                    
        my_solver.push()
        my_solver.add(sym==0xfe)
        values = list(my_solver.getallvalues(sym))
        self.assertIn(0xfe, values)
        self.assertNotIn(0xff, values)
        self.assertNotIn(0x7f, values)
        values = list(my_solver.getallvalues(mem.getchar(symbolic_addr)))
        self.assertIn(0xfe, values)
        self.assertNotIn(0xff, values)
        self.assertNotIn(0x7f, values)
        
        my_solver.pop()
        values = list(my_solver.getallvalues(sym))
        self.assertIn(0xfe, values)
        self.assertIn(0xff, values)
        self.assertNotIn(0x7f, values)
        values = list(my_solver.getallvalues(mem.getchar(symbolic_addr)))
        self.assertIn(0xfe, values)
        self.assertIn(0xff, values)
        self.assertNotIn(0x7f, values)

    def test_mix_of_concrete_and_symbolic(self):
        my_solver = Solver()
        mem = SMemory(my_solver, 32, 12)
        
        start_mapping_addr = mem.mmap(None, 0x1000, 'rwx')
        
        concretes = [0, 2, 4, 6]
        symbolics = [1, 3, 5, 7]
        
        for range in concretes:
            mem.putchar(start_mapping_addr+range, 'C')
        
        for range in symbolics:
            mem.putchar(start_mapping_addr+range, my_solver.mkBitVec(8))

        for range in concretes:
            self.assertTrue(isconcrete(mem.getchar(start_mapping_addr+range)))

        for range in concretes:
            self.assertFalse(issymbolic(mem.getchar(start_mapping_addr+range)))
        
        for range in symbolics:
            self.assertTrue(issymbolic(mem.getchar(start_mapping_addr+range)))                

        for range in symbolics:
            self.assertFalse(isconcrete(mem.getchar(start_mapping_addr+range)))
    
        for range in symbolics:
            mem.putchar(start_mapping_addr+range, 'C')
        
        for range in concretes:
            mem.putchar(start_mapping_addr+range, my_solver.mkBitVec(8))

        for range in symbolics:
            self.assertTrue(isconcrete(mem.getchar(start_mapping_addr+range)))

        for range in symbolics:
            self.assertFalse(issymbolic(mem.getchar(start_mapping_addr+range)))
        
        for range in concretes:
            self.assertTrue(issymbolic(mem.getchar(start_mapping_addr+range)))                

        for range in concretes:
            self.assertFalse(isconcrete(mem.getchar(start_mapping_addr+range)))

    def test_one_concrete_one_symbolic(self):
        #global mainsolver
        my_solver = Solver()
        mem = SMemory(my_solver, 32, 12)
        
        addr_for_symbol1 = mem.mmap(None, 0x1000, 'rwx')
        mem.putchar(addr_for_symbol1, 'A')

        symbol1 = my_solver.mkBitVec(8)
        
        my_solver.add(OR(symbol1==ord('B'), symbol1==ord('C')))

        mem.putchar(addr_for_symbol1+1, symbol1)
        
        values = list(my_solver.getallvalues(symbol1))
        self.assertIn(ord('B'), values)
        self.assertIn(ord('C'), values)
        
        symbol2 = my_solver.mkBitVec(32)
        my_solver.add(symbol2>=addr_for_symbol1)
        my_solver.add(symbol2<=addr_for_symbol1+1)

        c = mem.getchar(symbol2)
        self.assertTrue(issymbolic(c))           
        
        values = list(my_solver.getallvalues(c))
        
        self.assertIn(ord('A'), values)
        self.assertIn(ord('B'), values)
        self.assertIn(ord('C'), values)

    def testBasicSymbolic(self):
        my_solver = Solver()
        mem = SMemory(my_solver, 32, 12)

        #alloc/map a little mem
        size = 0x10000
        addr = mem.mmap(None, size, 'rwx')
        #initialize first 10 bytes as [100, 101, 102, .. 109]
        for i in xrange(addr, addr+10):
            mem.putchar(i, chr(100+i-addr))

        #mak a free symbol of 32 bits
        x = my_solver.mkBitVec(32) 
        #constraint it to range into [addr, addr+10)
        my_solver.add(x>=addr)
        my_solver.add(x<addr+10)

        #Well.. x is symbolic
        self.assertTrue(issymbolic(x))
        #It shall be a solution
        self.assertTrue(my_solver.check(), 'sat')
        #if we ask for a possible solution (an x that comply with the constraints)
        sol = my_solver.getvalue(x)
        #it should comply..
        self.assertTrue(sol >= addr and sol<addr+10)

        #min and max value should be addr and addr+9
        m, M = my_solver.minmax(x)
        self.assertEqual(m, addr)
        self.assertEqual(M, addr+9)

        #If we ask for all possible solutions...
        for val in my_solver.getallvalues(x):
            #any solution must comply..
            self.assertTrue(sol >= addr and sol<addr+10)

        #so now lets ask the memory for values pointed by addr
        c = mem.getchar(x)
        for val in my_solver.getallvalues(c):
            self.assertTrue(val>=100 and val<110)

        #constarint the address a litlle more
        my_solver.add(x<=addr)
        #It shall be a solution
        self.assertTrue(my_solver.check(), 'sat')
        #if we ask for a possible solution 
        sol = my_solver.getvalue(x)
        #it must be addr
        self.assertTrue(sol == addr)

        #lets ask the memory for the value under that address
        c = mem.getchar(x)
        sol = my_solver.getvalue(c)
        self.assertTrue(sol==100)

    def testMultiSymbolic(self):
        my_solver = Solver()
        mem = SMemory(my_solver, 32, 12)

        #alloc/map a little mem
        size = 0x10000
        addr = mem.mmap(None, size, 'rwx')
        #initialize first 10 bytes as [100, 101, 102, .. 109]
        for i in xrange(addr, addr+10):
            mem.putchar(i, chr(100+i-addr))

        #Make a char that ranges from 'A' to 'Z'
        v = my_solver.mkBitVec(32) 
        my_solver.add(v>=ord('A'))
        my_solver.add(v<=ord('Z'))

        #assign it to the firt 10 bytes
        mem.putchar(addr+5, chr(v))


        #mak a free symbol of 32 bits
        x = my_solver.mkBitVec(32) 
        #constraint it to range into [addr, addr+10)
        my_solver.add(x>=addr)
        my_solver.add(x<addr+10)

        #so now lets ask the memory for values pointed by addr
        c = mem.getchar(x)
        for val in my_solver.getallvalues(c,1000):
            self.assertTrue(val>=100 and val<110 or val >= ord('A') and val <= ord('Z'))

    def testmprotectFailReading(self):
        my_solver = Solver()
        mem = SMemory(my_solver, 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x10000
        #alloc/map a little mem
        addr = mem.mmap(None, size, 'rwx')
        mem.putchar(addr, 'a')

        self.assertEqual(mem.getchar(addr), 'a')

        mem.mprotect(addr, size, 'w')
        self.assertRaisesRegexp(MemoryException, "No Access Reading <0x%x>"%addr, mem.getchar, addr)

    def testmprotectFailWriting(self):
        my_solver = Solver()
        mem = SMemory(my_solver, 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x10000
        #alloc/map a little mem
        addr = mem.mmap(None, size, 'wx')
        mem.putchar(addr, 'a')

        mem.mprotect(addr, size, 'r')
        self.assertRaisesRegexp(MemoryException, "No Access Writting <0x%x>"%addr, mem.putchar, addr, 'a')

    def testmprotecNoReadthenOkRead(self):
        my_solver = Solver()
        mem = SMemory(my_solver, 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)

        size = 0x10000
        #alloc/map a little mem
        addr = mem.mmap(None, size, 'wx')
        mem.putchar(addr, 'a')

        self.assertRaisesRegexp(MemoryException, "No Access Reading <0x%x>"%addr, mem.getchar, addr)

        mem.mprotect(addr, size, 'r')
        self.assertEqual(mem.getchar(addr), 'a')

    def test_COW(self):
        m = MMapAnon(0x10000000, 0x2000, 'rwx')

        #Check the size
        self.assertEqual(len(m), 0x2000)

        #Set Some chars
        m.putchar(0x10001000, 'A')
        m.putchar(0x10002000-1, 'Z')

        #check it is initialized with zero
        self.assertEqual(m.getchar(0x10001000), 'A')
        self.assertEqual(m.getchar(0x10002000-1), 'Z')

        #Make COW
        cow = MMapCOW(m, 0x1000)

        #Check COW length
        self.assertEqual(len(cow), 0x1000)

        #check it is initialized with zero
        self.assertEqual(m.getchar(0x10001000), 'A')
        self.assertEqual(m.getchar(0x10002000-1), 'Z')

        #Set and check some chars
        cow.putchar(0x10001000, 'a')
        self.assertEqual(cow.getchar(0x10001000), 'a')
        self.assertEqual(cow.getchar(0x10002000-1), 'Z')
        self.assertEqual(m.getchar(0x10001000), 'A')
        self.assertEqual(m.getchar(0x10002000-1), 'Z')


        #Set and check some chars
        cow.putchar(0x10002000-1, 'z')
        self.assertEqual(cow.getchar(0x10001000), 'a')
        self.assertEqual(cow.getchar(0x10002000-1), 'z')
        self.assertEqual(m.getchar(0x10001000), 'A')
        self.assertEqual(m.getchar(0x10002000-1), 'Z')

    def test_pickle_mmap_anon(self):
        m = MMapAnon(0x10000000, 0x3000, 'rwx')
        m.putchar(0x10001000, 'A')
        s = StringIO(pickle.dumps(m))
        m = pickle.load(s)
        self.assertEqual(m.getchar(0x10001000), 'A')


    def test_pickle_mmap_file(self):
        #file mapping
        rwx_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rwx_file.file.write('X'*0x3000)
        rwx_file.close()
        m = MMapFile(0x10000000, 0x3000, 'rwx', rwx_file.name)
        m.putchar(0x10000000, 'Y')
        s = StringIO(pickle.dumps(m))
        m = pickle.load(s)
        self.assertEqual(m.getchar(0x10001000), 'X')
        self.assertEqual(m.getchar(0x10000000), 'Y')

    def test_pickle_mmap_anon_cow(self):
        m = MMapAnon(0x10000000, 0x3000, 'rwx', 'X'*0x1000+'Y'*0x1000+'Z'*0x1000)
        m = MMapCOW(m)
        s = StringIO(pickle.dumps(m))
        m = pickle.load(s)
        self.assertEqual(m.getchar(0x10001000), 'Y')
        self.assertEqual(m.start, 0x10000000)
        self.assertEqual(m.end, 0x10003000)

    def test_pickle_mmap_anon_cow_offset(self):
        m = MMapAnon(0x10000000, 0x3000, 'rwx', 'X'*0x1000+'Y'*0x1000+'Z'*0x1000)
        m = MMapCOW(m, offset=0x1000, size=0x1000)
        s = StringIO(pickle.dumps(m))
        m = pickle.load(s)
        self.assertEqual(m.getchar(0x10001000), 'Y')
        self.assertEqual(m.start, 0x10001000)
        self.assertEqual(m.end, 0x10002000)


    def test_pickle_mmap_file_cow(self):
        #file mapping
        rwx_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rwx_file.file.write('X'*0x1000+'Y'*0x1000+'Z'*0x1000)
        rwx_file.close()
        m = MMapFile(0x10000000, 0x3000, 'rwx', rwx_file.name)
        m = MMapCOW(m)
        s = StringIO(pickle.dumps(m))
        m = pickle.load(s)
        self.assertEqual(m.getchar(0x10001000), 'Y')
        self.assertEqual(m.start, 0x10000000)
        self.assertEqual(m.end, 0x10003000)

    def test_pickle_mmap_file_cow_offset(self):
        #file mapping
        rwx_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rwx_file.file.write('X'*0x1000+'Y'*0x1000+'Z'*0x1000)
        rwx_file.close()
        m = MMapFile(0x10000000, 0x3000, 'rwx', rwx_file.name)
        m = MMapCOW(m, offset=0x1000, size=0x1000)
        s = StringIO(pickle.dumps(m))
        m = pickle.load(s)
        self.assertEqual(m.getchar(0x10001000), 'Y')
        self.assertEqual(m.start, 0x10001000)
        self.assertEqual(m.end, 0x10002000)


    def test_pickle(self):
        my_solver = Solver()
        mem = SMemory(my_solver, 32, 12)

        #start with no maps
        self.assertEqual(len(mem.mappings()), 0)
        #alloc/map a byte
        addr_a = mem.mmap(None, 0x1000, 'r')

        #one map
        self.assertEqual(len(mem.mappings()), 1)

        #file mapping
        rwx_file = tempfile.NamedTemporaryFile('w+b', delete=False)
        rwx_file.file.write('a'*0x3000)
        rwx_file.close()
        addr_f = mem.mmapFile(0, 0x3000, 'rwx', rwx_file.name)
        mem.munmap(addr_f+0x1000, 0x1000)
        #two map2
        self.assertEqual(len(mem.mappings()), 3)

        sym = my_solver.mkBitVec(8)
        mem.putchar(addr_f, sym)

        #save it
        
        s = StringIO(pickle.dumps(mem))

        #load it
        mem1 = pickle.load(s)

        #two maps
        self.assertEqual(len(mem1.mappings()), 3)

        os.unlink(rwx_file.name)

if __name__ == '__main__':
    unittest.main()

