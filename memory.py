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

import mmap
from weakref import WeakValueDictionary
from cStringIO import StringIO
from smtlibv2 import issymbolic, UGE, OR, AND, chr, ord, Solver

import logging
logger = logging.getLogger("MEMORY")

class MemoryException(Exception):
    '''
    Memory exceptions
    '''
    def __init__(self, cause, address=0):
        '''
        Builds a memory exception.
        @param cause: exception message.
        @param address: memory address where the exception occurred.
        '''
        super(MemoryException, self, ).__init__("{} {}".format(cause, address))

class MMap(object):
    """
    A map of memory.
        
    It represents a convex chunk of memory with a start and an end address.
    It may be implemented as an actual file mapping or as a StringIO.
    It may have symbolic overlays.
    Some of it may be symbolic data.       
    
    >>>           ####SS#######S################SSS####
                  ^                                    ^
                start                                 end  

    """
    def __init__(self, start, size, perms, addressbitsize, pagebitsize):
        ''' Builds a map of memory.
            @param start: the first valid address.
            @param size: the size of the map.
            @param perms: the access permissions of the map.
            @param addressbitsize: the size of an address in memory.
            @param pagebitsize: the size of a page in memory.
        '''
        assert addressbitsize in [16, 32, 64], "Not supported address bit size"
        assert pagebitsize in [12, 13], "Not supported page bit size"
        assert type(start) in [int, long] and \
                start & ((1 << pagebitsize)-1) == 0 and \
                start >= 0 and \
                start <= (1 << addressbitsize) - (1 << pagebitsize), "Invalid start address"
        assert type(size) in [int, long] and \
                size & ((1 << pagebitsize)-1) == 0 and \
                size > 0 and \
                start+size <= (1 << addressbitsize), "Invalid end address"

        self.addressbitsize = addressbitsize       #number of bits in an address
        self.pagebitsize = pagebitsize             #number of its in a page boundary 
        self.start = start
        self.end = start + size
        self.perms = perms
        self._data = None                       #This is an absract class


    def _getPerms(self):
        ''' Gets the access permissions of the map.
        '''
        return self._perms

    def _setPerms(self, perms):
        ''' Sets the access permissions of the map. 
            
            @param perms: the new permissions. 
        '''
        assert type(perms) is str and len(perms) <= 3 and perms.strip() in ['', 'r', 'w', 'x', 'rw', 'r x', 'rx', 'rwx', 'wx', ]
        self._perms = perms
    perms = property(_getPerms, _setPerms)

    def __len__(self):
        '''Returns the actual size in bytes of the mapping.
        '''
        return self.end - self.start

    def __str__(self):
        '''Returns the string representation of the map mapping.
        @rtype: str
        '''
        return '0x%016x-0x%016x %s'%(self.start, self.end, self.perms)

    def isExecutable(self):
        """
        Returns true if this mapping contains executable memory.
        @rtype: bool 
        
        @return: 
            - C{True} if this mapping contains executable memory.
            - C{False} if this mapping does not contain executable memory. 
        """
        return 'x' in self.perms
    def isWriteable(self):
        """
        Returns true if this mapping contains writeable memory.
        @rtype: bool 
        
        @return: 
            - C{True} if this mapping contains writeable memory.
            - C{False} if this mapping does not contain writeable memory. 
        """
        return 'w' in self.perms
    def isReadable(self):
        """
        Returns true if this mapping contain readable memory.
        @rtype: bool 
        
        @return: 
            - C{True} if this mapping contains readable memory.
            - C{False} if this mapping does not contain readable memory        
        """
        return 'r' in self.perms

    #read and write potentially symbolic bytes
    def getchar(self, addr):
        """Generic getchar. It returns the character at the specified address. 
        It may return a symbol. This relays in the implementation of self._getchar 
        that depends on which type of mapping this really is; L{MMapFile}, L{MMapAnon}.
            
        @param addr: the address where to obtain the char. 
        @raise MemoryException: if the address is not readable or is not in this mapping.
        @return: the character or symbol at the specified address.
        """

        if addr < self.start or addr >= self.end:
            raise MemoryException("Page Fault reading", addr) 
        if not self.isReadable():
            raise MemoryException("No access reading", addr) 

        return self._getchar(addr)

    def putchar(self, addr, data):
        """ Generic putchar. It sets the character at the specified address. 
            The address and/or the data may be symbolic. This relays in 
            the implementation of self._putchar that depends on which type 
            of mapping this really is; L{MMapFile}, L{MMapAnon}.
            
            @param addr: the address where to set the character.
            @param data: a character to put in the address addr.
            @raise MemoryException: if the address is not writable or is not in this mapping.            
        """
        if addr < self.start or addr >= self.end:
            raise MemoryException("Page Fault writing", addr) 
        if not self.isWriteable():
            raise MemoryException("No access writting", addr) 

        self._putchar(addr, data)

    def select(self, start, size):
        """
            Returns the selected map and a tuple with the remaining maps within this map.
            @rtype: tuple
            @param start: the start address of the selected map.
            @param size: the size of the selected map.
            @return: 
                - If the selected portion is not overlapped with this map:
                    - C{None}, (C{self}, )
                - If the selected portion starts within this map but ends beyond this map:
                    - map<C{start}, C{self.end}>, (map<C{self.start}, C{start-1}>, )
                - If the selected portion fits within this map:
                    - map<C{start}, C{start+size}>, (map<C{self.start}, C{start-1}>, map<C{start+size+1}, C{self.end}>)
                - If just the last part of the selected portion is overlapped with this map:
                    - map<C{self.start}, C{start+size}>, (map<C{start+size+1}, C{self.end}>, ) 
                - If this map is contained in the selected portion:
                    - C{self}, C{tuple()}
        """
        assert type(start) in [int, long] and \
                start & ((1 << self.pagebitsize)-1) == 0 and \
                start > 0
        assert type(size) in [int, long] and \
                size & ((1 << self.pagebitsize)-1) == 0 and \
                size > 0

        end = start+size
        if self.start < start:
            if self.end <= start :
                #not_overlapped
                #print "not_overlapped"
                return None, (self, )
            else:
                if self.end <= end :
                    #print "unmmap the end"
                    remaining, selected = self._split(start)
                    return selected, (remaining, )
                else:
                    #print "unmmap a portion inside"
                    #overlapped_both() Need to return two maps
                    aux, remaining2 = self._split(end)
                    remaining1, selected = aux._split(start)
                    return selected, (remaining1, remaining2)
        else:
            if self.start < end :
                if self.end <= end :
                    #print "unmmap ALL"
                    #overlapped_contained()
                    return self, tuple()
                else :
                    #print "unmmap Begginning"
                    #overlapped_beg()
                    selected, remaining = self._split(end)
                    return selected, (remaining, )
            else :
                #print "not overlapped"
                #not_overlapped_pos()
                return None, (self, )


    def unmap(self, start, size):
        """
        Removes a portion of this map.
        @rtype: tuple
        @param start: the address where the portion to remove begins. 
        @param size: the size of the portion to remove.
        @return: a tuple containing the two maps generated after the portion was removed.
        """
        return self.select(start, size)[1]

    def mprotect(self, address, size, perms):
        '''
        Changes the access permissions of a portion of this map.
        @rtype: list
        @param address: the address where the portion to change the permissions begins.
        @param size: the size of the portion to change the permissions.
        @param perms: the new permissions to assign to the portion of the map.
        @return: 
            - the list of maps with their corresponding permissions: 
                - first two elements of this list are the previous and next maps to the portion where the permissions have changed.
                - last element of this list is the portion map with changed permissions.
        '''
        selected, remains = self.select(address, size)
        selected.perms = perms
        return list(remains) + [selected]

    def __getstate__(self):
        state = {}
        state['addressbitsize'] = self.addressbitsize
        state['pagebitsize'] = self.pagebitsize 
        state['start'] = self.start
        state['end'] = self.end
        state['perms'] = self.perms
        return state

    def __setstate__(self, state):
        """@todo: some asserts"""
        self.addressbitsize = state['addressbitsize']
        self.pagebitsize = state['pagebitsize']
        self.start = state['start']
        self.end = state['end']
        self.perms = state['perms']
        

class MMapFile(MMap):
    '''
    A file map.
    
    A  file is mapped in multiples of the page size.  For a file that is not a multiple of the page size, 
    the remaining memory is zeroed when mapped, and writes to that region are not written out to the file.
    The  effect  of  changing the size of the underlying file of a mapping on the pages that correspond to
    added or removed regions of the file is unspecified.
    '''
    def __init__(self, addr, size, perms, filename, offset=0, addressbitsize=32, pagebitsize=12):
        ''' Builds a map of memory  initialized with the content of filename.
            @param addr: the first valid address of the file map.
            @param size: the size of the file map.
            @param perms: the access permissions of the file map.
            @param filename: the file to map in memory.
            @param offset: the offset into the file where to start the mapping. This offset must be a multiple of pagebitsize.
            @param addressbitsize: the size of an address in memory.
            @param pagebitsize: the size of a page in memory.
        '''
        super(MMapFile, self).__init__(addr, size, perms, addressbitsize, pagebitsize)
        def getSize(fileobject):
            pos = fileobject.tell()
            fileobject.seek(0, 2)
            size = fileobject.tell()
            fileobject.seek(pos, 0) 
            return size
        assert type(offset) in [int, long] and \
                offset & ((1 << pagebitsize)-1) == 0 and \
                offset >= 0

        self.filename = filename
        self.offset = offset

        f = file(filename, "rb")
        self.mapped_size = min(size, getSize(f)-offset)
        self._data = mmap.mmap(f.fileno(), self.mapped_size, 
                                           offset=offset, 
                                           access=mmap.ACCESS_COPY)
        f.close()
        self._data_tail = None

        if self.mapped_size < self.end-self.start:
            self._data_tail = StringIO()
            self._data_tail.write('\x00'*(self.end-self.start-self.mapped_size))

        self.dirty = set()


    def __getstate__(self):
        state = {}
        state['addressbitsize'] = self.addressbitsize
        state['pagebitsize'] = self.pagebitsize
        state['start'] = self.start
        state['end'] = self.end
        state['perms'] = self.perms
        state['filename'] = self.filename
        state['offset'] = self.offset
        state['mapped_size'] = self.mapped_size
        #todo add some hash of the file?
        if self.mapped_size < self.end-self.start:
            state['_data_tail'] = self._data_tail.getvalue().encode('zlib')

        dirty_bytes = []
        for addr in self.dirty:
            dirty_bytes.append((addr, self._getchar(addr)))
        state['dirty_bytes'] = dirty_bytes
        return state

    def __setstate__(self, state):
        """
        @todo: some asserts
        """
        def getSize(fileobject):
            pos = fileobject.tell()
            fileobject.seek(0, 2) 
            size = fileobject.tell()
            fileobject.seek(pos, 0) 
            return size
        self.addressbitsize = state['addressbitsize']
        self.pagebitsize = state['pagebitsize']
        self.start = state['start']
        self.end = state['end']
        self.perms = state['perms']

        self.filename = state['filename']
        self.offset = state['offset']
        self.mapped_size = state['mapped_size']

        f = file(self.filename, "rb")
        self._data = mmap.mmap(f.fileno(), self.mapped_size, 
                                           offset=self.offset, 
                                           access=mmap.ACCESS_COPY)
        f.close()

        self.dirty = set()
        for addr, byte in state['dirty_bytes']:
            self._putchar(addr, byte)
            self.dirty.add(addr)

        self._data_tail = None
        if self.mapped_size < self.end-self.start:
            self._data_tail = StringIO()
            self._data_tail.write(state['_data_tail'].decode('zlib'))



    def _putchar(self, addr, data):
        """
        File mapped based putchar implementation.
        @param addr: the address where to put the data.
        @param data: character to put in this file map.
        """
        if addr < self.start+self.mapped_size:

            self._data.seek(addr-self.start)
            self._data.write(data)
            self.dirty.add(addr)
        else:
            self._data_tail.seek(addr-self.start-self.mapped_size)
            self._data_tail.write(data)

    def _getchar(self, addr):
        """
        File mapped based getchar implementation.
        @rtype: str[1]
        
        @param addr: the address where to obtain the character.
        @return: the character at the specified address. 
        """
        if addr < self.start+self.mapped_size:
            self._data.seek(addr-self.start)
            return self._data.read(1)
        else:
            self._data_tail.seek(addr-self.start-self.mapped_size)
            return self._data_tail.read(1)

    def _split(self, addr):
        """
        Splits the file map in 2 file maps and returns list of these 2 file based maps.
        @rtype: list
        @param addr: the address where to split the file map.
        @return: a list with 2 file based maps.
        """
        assert type(addr) in [int, long] and \
                addr & ((1 << self.pagebitsize)-1) == 0 and \
                addr >= self.start and \
                addr < self.end 

        new_map1 = MMapCOW(self, 0, addr-self.start)
        new_map2 = MMapCOW(self, addr-self.start)
        return [new_map1, new_map2]

class MMapAnon(MMap):
    '''
    A StringIO (or anonymous) map.
    '''
    def __init__(self, start, size, perms, data_init=None, addressbitsize=32, pagebitsize=12):
        ''' Builds a StringIO map.
            @param start: the first valid address of the map.
            @param size: the size of the map.
            @param perms: the access permissions of the map.
            @param data_init: the data to initialize the map.
            @param addressbitsize: the size of an address in memory.
            @param pagebitsize: the size of a page in memory.
        '''
        super(MMapAnon, self).__init__(start, size, perms, addressbitsize, pagebitsize)
        self._data = StringIO()
        self._data.seek(self.end-self.start+1)
        self._data.write("\x00")
        self._data.truncate(self.end-self.start+1)
        if not data_init is None:
            self._data.seek(0)
            self._data.write(data_init)

    def __getstate__(self):
        state = super(MMapAnon, self).__getstate__()
        state['_data'] = self._data.getvalue().encode('zlib')
        return state

    def __setstate__(self, state):
        """@todo: some asserts"""
        super(MMapAnon, self).__setstate__(state)
        self._data = StringIO()
        self._data.write(state['_data'].decode('zlib'))


    def _putchar(self, addr, data):
        """
        StringIO based putchar.  
        @param addr: the address where to put the data.
        @param data: character to put in this map.
        """
        self._data.seek(addr-self.start)
        self._data.write(data)

    def _getchar(self, addr):
        """
        StringIO based getchar.
        @rtype: str[1]
        
        @param addr: the address where to obtain the character.
        @return: the character at the specified address. 
        """
        self._data.seek(addr-self.start)
        return self._data.read(1)

    def _split(self, addr):
        """
        Splits the map in 2 file maps and returns a list of these 2 maps.
        @rtype: list
        
        @param addr: the address where to split the map.
        @return: a list with the 2 generated maps.
        """
        assert type(addr) in [int, long] and \
                addr & ((1 << self.pagebitsize)-1) == 0 and \
                addr >= self.start and \
                addr < self.end 

        new_map1 = MMapCOW(self, 0, addr-self.start)
        new_map2 = MMapCOW(self, addr-self.start)
        return [new_map1, new_map2]


class MMapCOW(MMap):
    '''
    Copy on write based map.
    '''
    def __init__(self, parent, offset=0, size=None):
        ''' A copy on write copy of parent. Writes to the parent after a copy on write are unspecified.
            @param parent: the parent map.
            @param offset: an offset within the parent map from where to create the new map.
            @param size: the size of the new map.
        '''
        if size is None:
            size = parent.end-(parent.start+offset)
        assert parent.start+offset+size <= parent.end
        assert size > 0
        super(MMapCOW, self).__init__(parent.start+offset, size, parent.perms, parent.addressbitsize, parent.pagebitsize)

        self.parent = parent
        self.parent.putchar = False
        self.cow = {}

    def _putchar(self, addr, data):
        """
        CopyOnWrite based putchar implementation.
        @param addr: the address where to put the data.
        @param data: character to put in this map.
        """
        self.cow[addr] = data

    def _getchar(self, addr):
        """
        CopyOnWrite based getchar implementation.
        @rtype: str[1]
        
        @param addr: the address where to obtain the character
        @return: the character at the specified address. 
        """
        if addr in self.cow:
            return self.cow[addr]
        return self.parent._getchar(addr)

    def _split(self, addr):
        """
        Splits the COW based map in 2 maps and returns a list of these 2 maps.
        @rtype: list
        @param addr: the address where to split the map.
        @return: a list with the 2 generated maps.
        """
        assert type(addr) in [int, long] and \
                addr & ((1 << self.pagebitsize)-1) == 0 and \
                addr >= self.start and \
                addr < self.end 

        new_map1 = MMapCOW(self, 0, addr-self.start)
        new_map2 = MMapCOW(self, addr-self.start)

        return [new_map1, new_map2]

    def __getstate__(self):
        state = super(MMapCOW, self).__getstate__()
        state['parent'] = self.parent
        state['cow'] = self.cow
        return state

    def __setstate__(self, state):
        super(MMapCOW, self).__setstate__(state)
        self.parent = state['parent']
        self.parent.putchar = False
        self.cow = state['cow']

class Memory(object):
    """
    The memory manager.
    This class handles all virtual memory mappings and symbolic chunks.
    """
    def __init__(self, addressbitsize=32, pagebitsize=12):
        '''
        Builds a memory chunk.
        @param addressbitsize: size in bits of the address space (default=32).
        @param pagebitsize: size in bits of the page boundary (default=12).
        '''
        assert addressbitsize in [16, 32, 64], "Not supported address bit size"
        assert pagebitsize in [12, 13], "Not supported page bit size"
        self.addressbitsize = addressbitsize
        self.pagebitsize = pagebitsize
        self.maps = set() 
        self.page2map = WeakValueDictionary()   #{page -> ref{MAP}}

    def _ceil(self, address):
        """
        Returns the smallest page boundary value not less than the address.
        @rtype: int
        @param address: the address to calculate its ceil. 
        @return: the ceil of C{address}.
        """
        pagemask = (1 << self.pagebitsize) - 1
        addrmask = (1 << self.addressbitsize) - 1
        return ((address | pagemask) + 1 ) & addrmask

    def _floor(self, address):
        """
        Returns largest page boundary value not greater than the address.
        @rtype: int
        
        @param address: the address to calculate its floor.
        @return: the floor of C{address}.
        """
        pagemask = (1 << self.pagebitsize) - 1
        return address & ~pagemask

    def _page(self, address):
        """
        Calculates the page number of an address.
        @rtype: int

        @param address: the address to calculate its page number.
        @return: the page number address of C{address}.
        """
        return address >> self.pagebitsize

    def _search(self, size, start=0x10000000, counter=0):
        """
        Recursively searches the address space for enough free space to allocate C{size} bytes.
        @rtype: int
        
        @param size: the size in bytes to allocate.
        @param start: an address from where to start the search.
        @param counter: internal parameter to know if all the memory was already scanned. 
        @return: the address of an available space to map C{size} bytes.
        @raise MemoryException: if there is no space available to allocate the desired memory. 


        @todo: Document what happens when you try to allocate something that goes round the address 32/64 bit representation.
        """
        if counter > 1 << self.addressbitsize:
            raise MemoryException("Not enough memory")

        #Alloc starting in second page in case of overflow.
        if  start+ size  > 1 << self.addressbitsize:
            start = 1 << self.pagebitsize

        for p in xrange(self._page(start), self._page(self._ceil(start+size-1))):
            if p in self.page2map:
                return self._search(size, start=self.page2map[p].end, counter= counter+self.page2map[p].end-start)
        assert start+size <= (1 << self.addressbitsize)
        return start

    def mmapFile(self, addr, size, perms, filename, offset=0):
        """
        Creates a new file mapping in the memory address space.
                
        @rtype: int
        
        @param addr: the starting address (took as hint). If C{addr} is C{0} the first big enough
                     chunk of memory will be selected as starting address.
        @param size: the contents of a file mapping are initialized using C{size} bytes starting 
                     at offset C{offset} in the file C{filename}. 
        @param perms: the access permissions to this memory.
        @param filename: the pathname to the file to map.
        @param offset: the contents of a file mapping are initialized using C{size} bytes starting 
                      at offset C{offset} in the file C{filename}.
        @return: the starting address where the file was mapped.   
        @raise error: 
                   - "Address shall be concrete" if C{addr} is not an integer number.  
                   - "Address too big" if C{addr} goes beyond the limit of the memory. 
                   - "Map already used" if the piece of memory starting in C{addr} and with length C{size} isn't free.  
        """
        #If addr is NULL, the system determines where to allocate the region.
        if addr == None:
            addr = 0x10000000

        assert type(addr) in [int, long], "Address shall be concrete"
        assert (addr <= ((1 << self.addressbitsize)-1)), "Address too big"

        #address is rounded down to the nearest multiple of the allocation granularity
        addr = self._floor(addr)

        #size value is rounded up to the next page boundary
        size = self._ceil(size-1)

        #If zero search for a spot
        addr = self._search(size, addr)

        #It should not be allocated
        for i in xrange(self._page(addr), self._page(addr+size)):
            assert not i in self.page2map, "Map already used"

        #Create the anonymous map
        m = MMapFile(addr, size, perms, filename, offset , 
                                        addressbitsize=self.addressbitsize, 
                                        pagebitsize=self.pagebitsize)
        #Okay, ready to alloc
        self.maps.add(m)

        #updating the page to map translation
        for i in range(self._page(m.start), self._page(m.end)):
            self.page2map[i] = m

        return addr

    def mmap(self, addr, size, perms, data_init=None):
        """
        Creates a new mapping in the memory address space.
        
        @rtype: int
        
        @param addr: the starting address (took as hint). If C{addr} is C{0} the first big enough
                     chunk of memory will be selected as starting address.
        @param size: the length of the mapping.
        @param perms: the access permissions to this memory.
        @param data_init: optional data to initialize this memory.
        @return: the starting address where the memory was mapped.  
        @raise error: 
                   - "Address shall be concrete" if C{addr} is not an integer number.  
                   - "Address too big" if C{addr} goes beyond the limit of the memory. 
                   - "Map already used" if the piece of memory starting in C{addr} and with length C{size} isn't free.
        """
        #If addr is NULL, the system determines where to allocate the region.
        if addr == None:
            addr = 0x10000000

        assert type(addr) in [int, long], "Address shall be concrete"
        assert (addr <= ((1 << self.addressbitsize)-1)), "Address too big"


        #address is rounded down to the nearest multiple of the allocation granularity
        addr = self._floor(addr)

        #size value is rounded up to the next page boundary
        size = self._ceil(size-1)

        #If zero search for a spot
        addr = self._search(size, addr)

        #It should not be allocated
        for i in xrange(self._page(addr), self._page(addr+size)):
            assert not i in self.page2map, "Map already used"

        #Create the anonymous map
        m = MMapAnon(start=addr, size=size, perms=perms, data_init=data_init, 
                                                addressbitsize=self.addressbitsize, 
                                                pagebitsize=self.pagebitsize)

        #Okay, ready to alloc
        self.maps.add(m)

        #updating the page to map translation
        for i in range(self._page(m.start), self._page(m.end)):
            self.page2map[i] = m

        logger.debug("New memory map @%x size:%x", addr, size)
        return addr

    def mappings(self):
        """
        Returns a sorted list of all the mappings for this memory.
        
        @rtype: list
        
        @return: a list of mappings.
        """
        result = []
        for m in self.maps:
            if isinstance(m, MMapAnon):
                result.append((m.start, m.end, m.perms, 0, ''))
            elif isinstance(m, MMapFile):
                result.append((m.start, m.end, m.perms, m.offset, m.filename))
            else:
                result.append((m.start, m.end, m.perms, 0, ''))

        return sorted(result)

    def __str__(self):
        return '\n'.join(["%016x-%016x % 4s %08x %s"%(start, end, p, offset, filename) for start, end, p, offset, filename in self.mappings()])

    def munmap(self, start, size):
        """
        Deletes the mappings for the specified address range and causes further references to addresses 
        within the range to generate invalid memory references.
        @param start: the starting address to delete.
        @param size: the length of the unmapping. 
        """
        start = self._floor(start)
        size = self._ceil(size-1)
        #select all mappings that have at least 1 byte unmaped
        affected = set()
        p = self._page(start)
        while p < self._page(self._ceil(start+size)):
            if p in self.page2map:
                m = self.page2map[p]
                affected.add(m)
                p = self._page(m.end)
            else:
                p += 1
        new_maps = []

        for m in affected:
            #remove m pages from the page2maps..
            for p in xrange(self._page(m.start), self._page(m.end)):
                del self.page2map[p]
            #remove m from the maps set
            self.maps.remove(m)

            #unmap the range from m possibly generating 0, 1 or 2 new maps
            new_maps += m.unmap(start, size)

        #reattach the newly generated maps (it may be none)
        for nm in new_maps:
            self.maps.add(nm)
            for p in xrange(self._page(nm.start), self._page(nm.end)):
                self.page2map[p] = nm
        logger.debug("Unmap memory @%x size:%x", start, size)

    def mprotect(self, start, size, perms):
        '''
        Changes the access permissions to the memory mapped in the specified range.
        @param start: start range address. 
        @param size: size of the range.
        @param perms: new permissions for the memory within the range.
        @todo: fix when fail return True./False/Exception?
        @todo: check perms and what happens if the same of existent perms.
        '''
        start = self._floor(start)
        end = self._ceil(start+size-1)
        size = end-start

        #select all mappings that have at least 1 byte mprotected
        affected = set()
        p = self._page(start)
        while p < self._page(end):
            if p in self.page2map.keys():
                m = self.page2map[p]
                #if perms.replace(' ', '') != m.perms.replace(' ', ''):
                affected.add(m)
                p = self._page(m.end)
            else:
                p += 1

        new_maps = []
        for m in affected:
            #remove m pages from the page2maps..
            for p in xrange(self._page(m.start), self._page(m.end-1)):
                del self.page2map[p]
            #remove m from the maps set
            self.maps.remove(m)

            #unmap the range from m posibly generating 0, 1 or 2 new maps
            new_maps += m.mprotect(start, size, perms)

        #reattach the newly generated maps (it may be none)
        for nm in new_maps:
            self.maps.add(nm)
            for p in xrange(self._page(nm.start), self._page(nm.end)):
                self.page2map[p] = nm
        logger.debug("Change perms to memory @%x size:%x newperms: %s", start, size, perms)

    def _getMap(self, address):
        """
        Returns the L{MMap} object containing the address.
        @rtype: L{MMap}
        
        @param address: the address to obtain its mapping. 

        @todo: symbolic address
        """
        return self.page2map[self._page(address)]

    #Permissions
    def getPermissions(self, address):
        """
        Returns the permissions of an address.
        @rtype: str
        
        @param address: the address to obtain its permissions. 

        @todo: symbolic address
        """
        return self._getMap(address).perms

    def isValid(self, address):
        """
        Returns C{True} if C{address} is a valid mapped address.
        @rtype: bool
        
        @param address: the address to know if it is valid or not.
        @return:
                - C{True} if the address is a valid mapped address.
                - C{False} if the address is not a valid mapped address. 

        @todo: symbolic address
        """
        return self._page(address) in self.page2map

    def isExecutable(self, address):
        """
        Returns C{True} if C{address} is executable.
        @rtype: bool
        
        @param address: the address to know if it is executable or not.
        @return:
                - C{True} if the address is executable.
                - C{False} if the address is not executable. 

        @todo: symbolic address
        """
        return self.isValid(address) and self._getMap(address).isExecutable()

    def isWriteable(self, address):
        """
        Returns C{True} if C{address} is writable.
        @rtype: bool
        
        @param address: the address to know if it is writable or not.
        @return:
                - C{True} if the address is writable.
                - C{False} if the address is not writable. 

        @todo: symbolic address
        """
        return self.isValid(address) and self._getMap(address).isWriteable()
    def isReadable(self, address):
        """
        Returns C{True} if C{address} is readable.
        @rtype: bool
        
        @param address: the address to know if it is readable or not.
        @return:
                - C{True} if the address is readable.
                - C{False} if the address is not readable. 

        @todo: symbolic address
        """
        return self.isValid(address) and self._getMap(address).isReadable()

    #write and read potentially symbolic bytes at symbolic indexes
    def putchar(self, addr, data):
        """
        Memory based putchar implementation.
        @param addr: the address where to put the data.
        @param data: character to put in this address of memory.
        @raise MemoryExcetion: if the address is not mapped.
        @todo: if addr is Readable/Executable?
        """
        if not self.isValid(addr): 
            raise MemoryException("Page Fault Writing", addr)

        m = self._getMap(addr)
        m.putchar(addr, data)
        return

    def getchar(self, addr):
        """
        Memory based getchar implementation.
        @rtype: str[1]
        
        @param addr: the address where to obtain the character.
        @return: the character at the specified address.
        @raise MemoryExcetion: if the address is not mapped.
        @todo: if addr is Readable/Executable?
        """
        if not self.isValid(addr):
            raise MemoryException("Page Fault Reading", addr)

        #Concrete case get the corresponding Map
        m = self._getMap(addr)
        return m.getchar(addr)

    #marshaling/pickle
    def __getstate__(self):
        state = {}
        state['addressbitsize'] = self.addressbitsize 
        state['pagebitsize'] = self.pagebitsize 
        state['maps'] = self.maps 
        return state

    def __setstate__(self, state):
        self.addressbitsize = state['addressbitsize']
        self.pagebitsize = state['pagebitsize'] 
        self.maps = state['maps'] 
        self.page2map = WeakValueDictionary()
        for m in self.maps:
            for i in range(self._page(m.start), self._page(m.end)):
                self.page2map[i] = m

class SMemory(Memory):
    ''' 
    The symbolic memory manager.
    This class handles all virtual memory mappings and symbolic chunks.
    @todo: improve comments
    ''' 

    def __init__(self, solver, addressbitsize=32, pagebitsize=12):
        ''' Builds a map of memory.
            @param solver: 
            @param addressbitsize: the size in bits of the address space (default=32).
            @param pagebitsize: the size in bits of a page boundary memory (default=12).
        '''
        super(SMemory, self).__init__(addressbitsize, pagebitsize)
        self.solver = solver
        self.addr2symbol = set()
        self.symbol = self.solver.mkArray(self.addressbitsize, name="MEM" )
        logger.info("Initializing Symbolic Memory")

    def isSymbolic(self, address):
        """
        Returns C{True} if value pointed by C{address} is a symbol.
        @rtype: bool
        @param address: the address to know if points to a symbol.
        @return:
            - C{True} if C{address} point to a symbol.
            - C{False} if C{address} does not point to a symbol.

        @todo: symbolic address
        """
        return self.isValid(address) and address in self.addr2symbol

    def isConcrete(self, address):
        """
        Returns C{true} if value pointed by C{address} is concrete.
        @rtype: bool
        
        @param address: the address to know if points to a concrete value.
        @return:
            - C{True} if C{address} point to a concrete value.
            - C{False} if C{address} does not point to a concrete value.
        
        @todo: symbolic address
        """
        return self.isValid(address) and not address in self.addr2symbol

    #write and read potentially symbolic bytes at symbolic indexes
    def putchar(self, addr, data):
        """
        Concrete/Symbolic putchar implementation
        
        @param addr: the address to put a concrete or symbolic content
        @param data: the content to put in C{addr}
        
        @todo: if addr is Readable/Executable? Double checked when accesing parent class!
        @todo: Instead of concretizing all possible values in range raise exception
               and make executor for arr on each mapped page

        """
        if issymbolic(addr):
            logger.debug("Write to symbolic address %s", addr)
            addr_min, addr_max = self.solver.minmax(addr)
            logger.debug("Range: %x <-> %x Data: %s", addr_min, addr_max, data)
            #Mark and intialize symbolic range
            for i in xrange(addr_min, addr_max+1):
                if not self.isWriteable(i):
                    raise MemoryException("No Access Writting", i)
            for i in xrange(addr_min, addr_max+1):
                if not i in self.addr2symbol:
                    self.symbol[i] = self.getchar(i)
                    self.addr2symbol.add(i)
            
            self.symbol[addr] = chr(data)
        else:
            #concrete addr case
            if not self.isWriteable(addr):
                raise MemoryException("No Access Writting", addr)
            if issymbolic(data):
                self.symbol[addr] = chr(data)
                self.addr2symbol.add(addr)
            else:
                #both concrete
                self.addr2symbol.discard(addr)
                super(SMemory, self).putchar(addr, data)

    def getchar(self, addr):
        """
        Concrete/Symbolic getchar implementation
        @rtype: str[1] or BitVec[8]
        
        @param addr: the address to obtain its content
        @return: a character or a symbol stored in C{addr}
        
        @todo:  if addr is Readable/Executable? Double checked when accesing parebnt class!!!
        """
        if issymbolic(addr):
            logger.debug("Read from symbolic address %s", str(addr).replace("\n",""))
            addr_min, addr_max = self.solver.minmax(addr)
            self.solver.add(addr.uge(addr_min))
            self.solver.add(addr.ule(addr_max))
            logger.debug("Range: %x <-> %x", addr_min, addr_max)
            if addr_max-addr_min > 0x10000000:
                raise MemoryException("Dangling symbolic pointer[0x%08x-0x%08x]"%(addr_min, addr_max), addr)
            #Symbolic address case
            for i in xrange(addr_min, addr_max+1):
                if not self.isReadable(i):
                    raise MemoryException("No Access Reading", i)
                if not i in self.addr2symbol:
                    self.symbol[i] = self.getchar(i)
                    self.addr2symbol.add(i)
            return chr(self.solver.simplify(self.symbol[addr]))

        if not self.isReadable(addr):
            raise MemoryException("No Access Reading", addr)

        #if the pointed value is a symbol...
        if self.isSymbolic(addr):
            return chr(self.solver.simplify(self.symbol[addr]))

        return super(SMemory, self).getchar(addr)


    def __getstate__(self):
        state = super(SMemory, self).__getstate__()
        state['issymbol'] = self.addr2symbol
        state['symbol'] = self.symbol
        state['solver'] = self.solver
        return state

    def __setstate__(self, state):
        super(SMemory, self).__setstate__(state)
        self.page2map = WeakValueDictionary()
        for m in self.maps:
            for i in range(self._page(m.start), self._page(m.end)):
                self.page2map[i] = m
        self.addr2symbol = state['issymbol']
        self.symbol = state['symbol']
        self.solver = state['solver']


