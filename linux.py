import weakref
import sys, os, struct
from smtlibv2 import chr, ord
from elftools.elf.elffile import ELFFile
from contextlib import closing

import logging
logger = logging.getLogger("LINUX")

class SyscallNotImplemented(Exception):
    ''' Exception raised when you try to call a not implemented
        system call. Go to linux.py and add it!
    '''
    pass

class File(object):
    def __init__(self, *args, **kwargs):
        self.file = file(*args,**kwargs)
    def stat(self):
        return os.fstat(self.fileno())
    def ioctl(self, request, argp):
        #argp ignored..
        import fcntl
        return fcntl.fcntl(self, request)
    @property
    def name(self):
        return self.file.name
    @property
    def mode(self):
        return self.file.mode
    def tell(self, *args):
        return self.file.tell(*args)
    def seek(self, *args):
        return self.file.seek(*args)
    def write(self, *args):
        return self.file.write(*args)
    def read(self, *args):
        return self.file.read(*args)
    def close(self, *args):
        return self.file.close(*args)
    def fileno(self, *args):
        return self.file.fileno(*args)

    def __getstate__(self):
        state = {}
        state['name'] = self.name
        state['mode'] = self.mode
        state['pos'] = self.tell()
        return state

    def __setstate__(self, state):
        name = state['name']
        mode = state['mode']
        pos = state['pos']
        self.file = file(name,mode)
        self.seek(pos)

class Linux(object):
    '''
    A simple Linux Operating System Model.
    This class emulates the most common Linux system calls
    '''
    def __init__(self, cpus, mem):
        '''
        Builds a Linux OS model
        @param cpus: CPU for this model.
        @param mem: memory for this model.
        @todo: generalize for more CPUs.
        @todo: fix deps?
        '''
        self.files = [] 
        self.cpu = cpus[0]
        self.mem = mem
        self.cpu.setOS(self)
        self.base = 0
        self.elf_bss = 0
        self.end_code = 0
        self.end_data = 0
        self.elf_brk = 0

    def __getstate__(self):
        state = {}
        state['files'] = self.files
        state['cpu'] = self.cpu
        state['mem'] = self.mem
        state['base'] = self.base
        state['elf_bss'] = self.elf_bss
        state['end_code'] = self.end_code
        state['end_data'] = self.end_data
        state['elf_brk'] = self.elf_brk
        return state

    def __setstate__(self, state):
        """
        @todo: some asserts
        @todo: fix deps? (last line)
        """
        self.files = state['files']
        self.cpu = state['cpu']
        self.mem = state['mem']
        self.base = state['base']
        self.elf_bss = state['elf_bss']
        self.end_code = state['end_code']
        self.end_data = state['end_data']
        self.elf_brk = state['elf_brk']
        self.cpu.setOS(self)

    def _read_string(self, cpu, buf):
        """
        Reads a null terminated concrete buffer form memory
        @todo: FIX. move to cpu or memory 
        """
        filename = ""
        for i in xrange(0,1024):
            c = chr(cpu.load(buf+i,8))
            if c == '\x00':
                break
            filename += c
        return filename

    def exe(self, filename, argv=[], envp=[], stdin='stdin', stdout='stdout', stderr='stderr'):
        '''
        Loads and an ELF program in memory and prepares the initial CPU state. 
        Creates the stack and loads the environment variables and the arguments in it.
        @param filename: pathname of the file to be executed.
        @param argv: list of parameters for the program to execute.
        @param envp: list of environment variables for the program to execute.
        @raise error:
            - 'Not matching cpu': if the program is compiled for a different architecture
            - 'Not matching memory': if the program is compiled for a different address size
        @todo: define va_randomize and read_implies_exec personality 
        '''
        #Set standar file descriptors
        self.files = [ File(stdin,'rb'), File(stdout,'wb'), File(stderr,'wb')]

        #load elf See binfmt_elf.c
        #read the ELF object file
        elf = ELFFile(file(filename)) 
        arch = {'x86':'i386','x64':'amd64'}[elf.get_machine_arch()]
        addressbitsize = {'x86':32, 'x64':64}[elf.get_machine_arch()]
        logger.info("Loading %s as a %s elf"%(filename,arch))
        logger.info("\tArguments: %s"%repr(argv))
        logger.debug("\tEnvironmen:")
        for e in envp:
            logger.debug("\t\t%s"%repr(e))

        assert self.cpu.machine == arch, "Not matching cpu"
        assert self.mem.addressbitsize == addressbitsize, "Not matching memory"
        assert elf.header.e_type in ['ET_DYN', 'ET_EXEC']
        cpu = self.cpu

        #Get interpreter elf
        interpreter = None
        for elf_segment in elf.iter_segments():
            if elf_segment.header.p_type != 'PT_INTERP':
                continue
            interpreter = ELFFile(file(elf_segment.data()[:-1]))
            break
        if not interpreter is None:
            assert interpreter.get_machine_arch() == elf.get_machine_arch()
            assert interpreter.header.e_type in ['ET_DYN', 'ET_EXEC']

        #Stack Executability
        executable_stack = False
        for elf_segment in elf.iter_segments():
            if elf_segment.header.p_type != 'PT_GNU_STACK':
                continue
            if elf_segment.header.p_flags & 0x01:
                executable_stack = True
            else:
                executable_stack = False
            break
       
        base = 0
        elf_bss = 0
        end_code = 0
        end_data = 0
        elf_brk = 0
        load_addr = 0

        base = 0
        for elf_segment in elf.iter_segments():
            if elf_segment.header.p_type != 'PT_LOAD':
                continue

            align = 0x1000 #elf_segment.header.p_align

            ELF_PAGEOFFSET = elf_segment.header.p_vaddr & (align-1)

            flags = elf_segment.header.p_flags
            memsz = elf_segment.header.p_memsz + ELF_PAGEOFFSET
            offset = elf_segment.header.p_offset - ELF_PAGEOFFSET
            filesz = elf_segment.header.p_filesz + ELF_PAGEOFFSET
            vaddr = elf_segment.header.p_vaddr - ELF_PAGEOFFSET
            memsz = self.mem._ceil(memsz+1) # (memsz + align ) & ~(align-1) 
            if base == 0 and elf.header.e_type == 'ET_DYN':
                assert vaddr == 0
                if addressbitsize == 32:
                    base = 0x56555000
                else:
                    base = 0x555555554000

            #PF_X   0x1 Execute
            #PF_W   0x2 Write
            #PF_R   0x4 Read
            #base = cpu.mem.mmap(base+vaddr,memsz,flags&0x4,flags&0x2,flags&0x1,data) - vaddr
            perms = ['   ', '  x', ' w ', ' wx', 'r  ', 'r x', 'rw ', 'rwx'][flags&7]
            hint = base+vaddr
            if hint == 0:
                hint = None
            base = self.mem.mmapFile(hint,memsz,perms,elf_segment.stream.name,offset) - vaddr
            logger.debug("Loading elf offset: %08x addr:%08x %08x %s" %(offset, base+vaddr, base+vaddr+memsz, perms))

            if load_addr == 0 :
                load_addr = base + vaddr

            k = base + vaddr + filesz;
            if k > elf_bss :
                elf_bss = k;
            if (flags & 4) and end_code < k: #PF_X
                end_code = k
            if end_data < k:
                end_data = k
            k = base + vaddr + memsz
            if k > elf_brk:
                elf_brk = k

        elf_entry = elf.header.e_entry
        if elf.header.e_type == 'ET_DYN':
            elf_entry += load_addr
        entry = elf_entry
        real_elf_brk = elf_brk

        # We need to explicitly zero any fractional pages
        # after the data section (i.e. bss).  This would
        # contain the junk from the file that should not
        # be in memory
        #TODO:
        #cpu.write(elf_bss, '\x00'*((elf_bss | (align-1))-elf_bss))

        logger.debug("Zeroing main elf fractional pages. From %x to %x.", elf_bss, elf_brk)
        logger.debug("Main elf bss:%x"%elf_bss)
        logger.debug("Main elf brk %x:"%elf_brk)

        self.mem.mprotect(self.mem._floor(elf_bss), elf_brk-elf_bss, 'rw')
        for i in xrange(elf_bss, elf_brk):
            try:
                self.mem.putchar(i, '\x00')
            except Exception, e:
                logger.debug("Exception zeroing main elf fractional pages: %s"%str(e))
        #TODO: FIX mprotect as it was before zeroing?

        reserved = self.mem.mmap(base+vaddr+memsz,0x1000000,'   ')
        interpreter_base = 0
        if not interpreter is None:
            base = 0
            elf_bss = 0
            end_code = 0
            end_data = 0
            elf_brk = 0
            entry = interpreter.header.e_entry
            for elf_segment in interpreter.iter_segments():
                if elf_segment.header.p_type != 'PT_LOAD':
                    continue
                align = 0x1000#elf_segment.header.p_align
                vaddr = elf_segment.header.p_vaddr
                filesz = elf_segment.header.p_filesz 
                flags = elf_segment.header.p_flags
                offset = elf_segment.header.p_offset
                memsz = elf_segment.header.p_memsz

                ELF_PAGEOFFSET = (vaddr & (align-1))
                memsz = memsz + ELF_PAGEOFFSET
                offset = offset - ELF_PAGEOFFSET
                filesz = filesz + ELF_PAGEOFFSET
                vaddr = vaddr - ELF_PAGEOFFSET
                memsz = self.mem._ceil(memsz+1)

                if base == 0 and elf.header.e_type == 'ET_DYN':
                    assert vaddr == 0
                    if addressbitsize == 32:
                        base = 0xf7fde000
                    else:
                        base = 0x7ffff7ddb000

                if base == 0:
                    assert vaddr == 0
                perms = ['   ', '  x', ' w ', ' wx', 'r  ', 'r x', 'rw ', 'rwx'][flags&7]
                hint = base+vaddr
                if hint == 0:
                    hint = None
                base = self.mem.mmapFile(hint ,memsz,perms,elf_segment.stream.name,offset) - vaddr

                logger.debug("Loading interpreter offset: %08x addr:%08x %08x %s%s%s" %(offset, base+vaddr, base+vaddr+memsz, (flags&1 and 'r' or ' '), (flags&2 and 'w' or ' '), (flags&4 and 'x' or ' ')))

                k = base + vaddr+ filesz;
                if k > elf_bss :
                    elf_bss = k;
                if (flags & 4) and end_code < k: #PF_X
                    end_code = k
                if end_data < k:
                    end_data = k
                k = base + vaddr+ memsz
                if k > elf_brk:
                    elf_brk = k

            if interpreter.header.e_type == 'ET_DYN':
                entry += base
            interpreter_base = base

            logger.debug("Zeroing interpreter elf fractional pages. From %x to %x.", elf_bss, elf_brk)
            logger.debug("Interpreter bss:%x"%elf_bss)
            logger.debug("Interpreter brk %x:"%elf_brk)

            self.mem.mprotect(self.mem._floor(elf_bss), elf_brk-elf_bss, 'rw')
            for i in xrange(elf_bss, elf_brk):
                try:
                    self.mem.putchar(i, '\x00')
                except Exception, e:
                    logger.debug("Exception zeroing Interpreter fractional pages: %s"%str(e))
            #TODO FIX mprotect as it was before zeroing?

        #free reserved brk space
        self.mem.munmap(reserved,0x1000000)

        #load vdso #TODO or #IGNORE
        bsz = addressbitsize/8

        if addressbitsize == 32:
            stack_base = 0xbffdf000
        else:
            stack_base = 0x7ffffffde000
        stack = self.mem.mmap(stack_base,0x21000,'rwx')+0x21000-1
        logger.info("Setting argv, envp and auxv.")
        #http://www.phrack.org/issues.html?issue=58&id=5#article
        # position            content                     size (bytes) + comment
        # ----------------------------------------------------------------------
        # stack pointer ->  [ argc = number of args ]     4
        #                 [ argv[0] (pointer) ]         4   (program name)
        #                 [ argv[1] (pointer) ]         4
        #                 [ argv[..] (pointer) ]        4 * x
        #                 [ argv[n - 1] (pointer) ]     4
        #                 [ argv[n] (pointer) ]         4   (= NULL)
        #
        #                 [ envp[0] (pointer) ]         4
        #                 [ envp[1] (pointer) ]         4
        #                 [ envp[..] (pointer) ]        4
        #                 [ envp[term] (pointer) ]      4   (= NULL)
        #
        #                 [ auxv[0] (Elf32_auxv_t) ]    8
        #                 [ auxv[1] (Elf32_auxv_t) ]    8
        #                 [ auxv[..] (Elf32_auxv_t) ]   8
        #                 [ auxv[term] (Elf32_auxv_t) ] 8   (= AT_NULL vector)
        #
        #                 [ padding ]                   0 - 16
        #
        #                 [ argument ASCIIZ strings ]   >= 0
        #                 [ environment ASCIIZ str. ]   >= 0
        #
        # (0xbffffffc)      [ end marker ]                4   (= NULL)
        #
        # (0xc0000000)      < top of stack >              0   (virtual)
        # ----------------------------------------------------------------------
        argvlst=[]
        envplst=[]
        #end envp marker empty string
        stack-=1
        cpu.write(stack,'\x00')
        envplst.append(stack)

        for e in envp:                   
            stack-=(len(e)+1)
            envplst.append(stack)
            cpu.write(stack,e)
            cpu.write(stack+len(e),'\x00')

        for a in argv:                
            stack-=(len(a)+1)
            argvlst.append(stack)
            cpu.write(stack,a)
            cpu.write(stack+len(a),'\x00')

        stack = ((stack - bsz) /bsz )*bsz      # [ padding ]

        stack-=bsz
        cpu.store(stack,0,addressbitsize)
        stack-=bsz
        cpu.store(stack,0,addressbitsize)

        #The "secure execution" mode of secure_getenv() is controlled by the
        #AT_SECURE flag contained in the auxiliary vector passed from the
        #kernel to user space.
        for i in reversed([ 3, load_addr+elf.header.e_phoff, 
                            4, 0x0000000000000038, #64bits 0x38 | #32bits 0x20
                            5, 0x0000000000000007, #64bits 0x07 | #32bits 0x0a
                            6, 4096, 
                            7, interpreter_base, 
                            8, 0, 
                            9, elf_entry, 
                            11, 1000, 
                            12, 1000, 
                            13, 1000, 
                            14, 1000, 
                            17, 100, 
                            23, 0,
                            0, 0]):
            stack-=bsz
            cpu.store(stack,i,addressbitsize)

        stack-=bsz                            # NULL ENVP
        cpu.store(stack,0,addressbitsize)

        for e in reversed(envplst):              # ENVP n
            stack-=bsz
            cpu.store(stack,e,addressbitsize)

        stack-=bsz
        cpu.store(stack,0,addressbitsize)     # NULL ARGV

        for a in reversed(argvlst):              # Argv n
            stack-=bsz
            cpu.store(stack,a,addressbitsize)

        stack-=bsz
        cpu.store(stack,len(argvlst),addressbitsize) #ARGC

        logger.info("Setting initial cpu state")
        #set initial CPU state
        cpu.setRegister('RAX',            0x0)
        cpu.setRegister('RCX',            0x0)
        cpu.setRegister('RDX',            0x0)
        cpu.setRegister('RBX',            0x0)
        cpu.setRegister('RSP',            stack)
        cpu.setRegister('RBP',            0x0)
        cpu.setRegister('RSI',            0x0)
        cpu.setRegister('RDI',            0x0)
        cpu.setRegister('RIP',            entry)
        cpu.setRegister('RFLAGS',         0x202)
        cpu.setRegister('CS',             0x23)
        cpu.setRegister('SS',             0x2b)
        cpu.setRegister('DS',             0x2b)
        cpu.setRegister('ES',             0x2b)
        cpu.setRegister('FS',             0x0)
        cpu.setRegister('GS',             0x0)


        logger.info("Entry point: %016x", entry)
        logger.info("Stack start: %016x", stack)
        logger.info("Brk: %016x", real_elf_brk)
        logger.info("Mappings:")
        for m in str(self.mem).split('\n'):
            logger.info("  %s", m)
        self.base = base
        self.elf_bss = elf_bss
        self.end_code = end_code
        self.end_data = end_data
        self.elf_brk = real_elf_brk

        #Clean heap?
        #for i in xrange(self.end_data, self.elf_brk-1):
        #    cpu.write(i, '\x00')

        #dump initial mappings
        #for m in self.mem.mappings():
        #    start =m[0]
        #    end = m[1]
        #    f = file('map%016x_%016x.img'%(start,end),'w+')
        #    for i in xrange(start,end):
        #        f.write(self.mem.getchar(i))

    def sys_uname(self, cpu, old_utsname):
        '''
        Writes system information in the variable C{old_utsname}.
        @rtype: int
        @param cpu: current CPU.
        @param old_utsname: the buffer to write the system info.
        @return: C{0} on success  
        '''
        uname = "Linux" + '\x00'*(65-5)
        uname += "localhost" + '\x00'*(65-9)
        uname += "3.9.2-gentoo" + '\x00'*(65-12)
        uname += "#2 SMP Fri May 17 21:08:46 ART 2013"+ '\x00'*(65-35)
        uname += "x86_64"+ '\x00'*(65-6)
        uname += "(none)"+ '\x00'*(65-6)
        cpu.write(old_utsname, uname)
        return 0

    def sys_brk(self, cpu, brk):
        '''
        Changes data segment size (moves the C{elf_brk} to the new address)
        @rtype: int
        @param cpu: current CPU.
        @param brk: the new address for C{elf_brk}.
        @return: the value of the new C{elf_brk}.
        @raise error: 
                    - "Error in brk!" if there is any error allocating the memory
        '''
        if brk != 0:
            size = brk-self.elf_brk
            perms = cpu.mem.getPermissions(self.elf_brk-1)
            addr = cpu.mem.mmap(self.elf_brk, size, perms)
            assert cpu.mem._ceil(self.elf_brk-1) == addr, "Error in brk!"
            self.elf_brk += size
        return self.elf_brk 

    def sys_arch_prctl(self, cpu, code, addr):
        '''
        Sets architecture-specific thread state
        @rtype: int
        
        @param cpu: current CPU.
        @param code: must be C{ARCH_SET_FS}.
        @param addr: the base address of the FS segment.
        @return: C{0} on success
        @raise error:
            - if C{code} is different to C{ARCH_SET_FS}
        '''
        ARCH_SET_GS = 0x1001
        ARCH_SET_FS = 0x1002
        ARCH_GET_FS = 0x1003
        ARCH_GET_GS = 0x1004
        assert code == ARCH_SET_FS
        cpu.FS = 0
        cpu.segments['FS'][0] = addr
        return 0


    def sys_open(self, cpu, buf, flags, mode):
        '''
        Given a pathname for a file, it returns a file descriptor
        @rtype: int
        @param cpu: current CPU.   
        @param buf: buffer with the pathname of the file to open.
        @param flags: file access bits.
        @param mode: file permissions mode.
        @return: a file description of the opened file.
        @todo: flags and mode not used
        '''
        filename = self._read_string(cpu, buf)

        f = File(filename)

        if None in self.files:
            fd = self.files.index(None)
            self.files[fd]=f
        else:
            self.files.append(f)
            fd = len(self.files)-1
        return fd

    def sys_read(self, cpu, fd, buf, count):
        '''
        Reads from a file descriptor
        @rtype: int
        @param cpu: current CPU.
        @param fd: the file descriptor to read.
        @param buf: address of the buffer to put the read bytes.
        @param count: maximum number of bytes to read.
        @return: the amount of bytes read.
        @todo: Out number of bytes actually read | EAGAIN | EBADF | EFAULT | EINTR | EINVAL | EIO | EISDIR
        '''
        data = self.files[fd].read(count)
        cpu.write(buf, data)
        return len(data)

    def sys_close(self, cpu, fd):
        '''
        Closes a file descriptor
        @rtype: int
        @param cpu: current CPU.
        @param fd: the file descriptor to close.
        @return: C{0} on success.  
        '''
        self.files[fd]=None
        return 0

    def sys_fstat(self, cpu, fd, buf):
        '''
        Determines information about a file based on its file descriptor.
        @rtype: int
        @param cpu: current CPU.
        @param fd: the file descriptor of the file that is being inquired.
        @param buf: a buffer where data about the file will be stored. 
        @return: C{0} on success.   
        '''
        '''
           dev_t     st_dev;     /* ID of device containing file */
           ino_t     st_ino;     /* inode number */
           mode_t    st_mode;    /* protection */
           nlink_t   st_nlink;   /* number of hard links */
           uid_t     st_uid;     /* user ID of owner */
           gid_t     st_gid;     /* group ID of owner */
           dev_t     st_rdev;    /* device ID (if special file) */
           off_t     st_size;    /* total size, in bytes */
           blksize_t st_blksize; /* blocksize for file system I/O */
           blkcnt_t  st_blocks;  /* number of 512B blocks allocated */
           time_t    st_atime;   /* time of last access */
           time_t    st_mtime;   /* time of last modification */
           time_t    st_ctime;   /* time of last status change */
        '''
        stat = self.files[fd].stat()
        bufstat = ''
        bufstat += struct.pack('<L', stat.st_dev)
        bufstat += struct.pack('<L', 0)
        bufstat += struct.pack('<L', 0)
        bufstat += struct.pack('<L', stat.st_ino)
        bufstat += struct.pack('<L', stat.st_mode)
        bufstat += struct.pack('<L', stat.st_nlink)
        bufstat += struct.pack('<L', 0)
        bufstat += struct.pack('<L', 0)
        bufstat += struct.pack('<L', 0)
        bufstat += struct.pack('<L', 0)
        bufstat += struct.pack('<L', 0)
        bufstat += struct.pack('<L', stat.st_size)
        bufstat += struct.pack('<L', 0)
        bufstat += struct.pack('<L', stat.st_blksize)
        bufstat += struct.pack('<L', stat.st_blocks)
        bufstat += struct.pack('<L', 0)

        bufstat += struct.pack('d', stat.st_atime)
        bufstat += struct.pack('d', stat.st_ctime)
        bufstat += struct.pack('d', stat.st_mtime)
        cpu.write(buf, bufstat)
        return 0

    def sys_fstat64(self, cpu, fd, buf):
        '''
        Determines information about a file based on its file descriptor (for Linux 64 bits).
        @rtype: int
        @param cpu: current CPU.
        @param fd: the file descriptor of the file that is being inquired.
        @param buf: a buffer where data about the file will be stored. 
        @return: C{0} on success.
        @todo: Fix device number.   
        '''
        ''' unsigned long	st_dev;		/* Device.  */
            unsigned long	st_ino;		/* File serial number.  */
            unsigned int	st_mode;	/* File mode.  */
            unsigned int	st_nlink;	/* Link count.  */
            unsigned int	st_uid;		/* User ID of the file's owner.  */
            unsigned int	st_gid;		/* Group ID of the file's group. */
            unsigned long	st_rdev;	/* Device number, if device.  */
            unsigned long	__pad1;
            long		st_size;	/* Size of file, in bytes.  */
            int		st_blksize;	/* Optimal block size for I/O.  */
            int		__pad2;
            long		st_blocks;	/* Number 512-byte blocks allocated. */

            long		st_atime;	/* Time of last access.  */
            unsigned long	st_atime_nsec;

            long		st_mtime;	/* Time of last modification.  */
            unsigned long	st_mtime_nsec;
            long		st_ctime;	/* Time of last status change.  */
            unsigned long	st_ctime_nsec;
            unsigned int	__unused4;
            unsigned int	__unused5;'''

        stat = self.files[fd].stat()
        bufstat = ''
        bufstat += struct.pack('<Q', stat.st_dev)
        bufstat += struct.pack('<Q', stat.st_ino)
        bufstat += struct.pack('<L', stat.st_mode)
        bufstat += struct.pack('<L', stat.st_nlink)
        bufstat += struct.pack('<L', stat.st_uid)
        bufstat += struct.pack('<L', stat.st_gid)

        bufstat += struct.pack('<Q', 0)
        bufstat += struct.pack('<Q', 0) #pad

        bufstat += struct.pack('<Q', stat.st_size)
        bufstat += struct.pack('<L', 1000 )
        bufstat += struct.pack('<L', 0) #pad

        bufstat += struct.pack('<Q', stat.st_size/512)

        bufstat += struct.pack('d', stat.st_atime)
        bufstat += struct.pack('<Q', 0)
        bufstat += struct.pack('d', stat.st_mtime)
        bufstat += struct.pack('<Q', 0)
        bufstat += struct.pack('d', stat.st_ctime)
        bufstat += struct.pack('<Q', 0)
        bufstat += struct.pack('<L', 0) #pad
        bufstat += struct.pack('<L', 0) #pad

        cpu.write(buf, bufstat)
        return 0

    def sys_stat64(self, cpu, path, buf):
        '''
        Determines information about a file based on its filename (for Linux 64 bits).
        @rtype: int
        @param cpu: current CPU.
        @param path: the pathname of the file that is being inquired.
        @param buf: a buffer where data about the file will be stored. 
        @return: C{0} on success.   
        '''
        fd = self.sys_open(cpu, path, 0, 'r')
        ret = self.sys_fstat64(cpu, fd, buf)
        self.sys_close(cpu, fd)
        return ret

    def sys_mmap2(self, cpu, address, size, prot, flags, fd, offset):
        ''' 
        Creates a new mapping in the virtual address space of the calling process.
        @rtype: int
        @param cpu: current CPU.
        @param address: the starting address for the new mapping. This address is used as hint unless the
                        flag contains C{MAP_FIXED}.
        @param size: the length of the mapping.
        @param prot: the desired memory protection of the mapping.
        @param flags: determines whether updates to the mapping are visible to other 
                      processes mapping the same region, and whether updates are carried 
                      through to the underlying file. 
        @param fd: the contents of a file mapping are initialized using C{size} bytes starting at 
                   offset C{offset} in the file referred to by the file descriptor C{fd}.
        @param offset: the contents of a file mapping are initialized using C{size} bytes starting at 
                       offset C{offset}*0x1000 in the file referred to by the file descriptor C{fd}.
        @return: 
            - C{-1} In case you use C{MAP_FIXED} in the flags and the mapping can not be place at the desired address.
            - the address of the new mapping.
        '''
        return self.sys_mmap(cpu, address, size, prot, flags, fd, offset*0x1000)

    def sys_mmap(self, cpu, address, size, prot, flags, fd, offset):
        ''' 
        Creates a new mapping in the virtual address space of the calling process. 
        @rtype: int
        
        @param cpu: current CPU.
        @param address: the starting address for the new mapping. This address is used as hint unless the
                        flag contains C{MAP_FIXED}.
        @param size: the length of the mapping.
        @param prot: the desired memory protection of the mapping.
        @param flags: determines whether updates to the mapping are visible to other 
                      processes mapping the same region, and whether updates are carried 
                      through to the underlying file. 
        @param fd: the contents of a file mapping are initialized using C{size} bytes starting at 
                   offset C{offset} in the file referred to by the file descriptor C{fd}.
        @param offset: the contents of a file mapping are initialized using C{size} bytes starting at 
                       offset C{offset} in the file referred to by the file descriptor C{fd}.
        @return: 
                - C{-1} in case you use C{MAP_FIXED} in the flags and the mapping can not be place at the desired address.
                - the address of the new mapping (that must be the same as address in case you included C{MAP_FIXED} in flags).
        @todo: handle exception.
        '''
        if address == 0:
            address = None
        if flags & 0x10 !=0 :
            cpu.mem.munmap(address,size)

        perms = ['   ', 'r  ',' w ','rw ','  x','r x', ' wx','rwx'][prot&7]
        if fd == 0xffffffff or fd == 0xffffffffffffffff:
            result = cpu.mem.mmap(address, size, perms)
        else:
            result = cpu.mem.mmapFile(address, size, perms, self.files[fd].name, offset)

        if (flags & 0x10 !=0) and result != address:
            cpu.mem.munmap(result, size)
            result = -1

        return result

    def sys_write(self, cpu, fd, buf, size):
        '''
        Writes to a file descriptor 
        @rtype: int
        
        @param cpu: current CPU.
        @param fd: the file descriptor of the file to write.
        @param buf: the buffer where the bytes to write are taken. 
        @param size: it writes up to C{size} bytes from the buffer C{buf} 
                     to the file referred to by the file descriptor C{fd}.      
        @return: the amount of bytes written.
        @todo: Out eax number of bytes actually sent | EAGAIN | EBADF | EFAULT | EINTR | EINVAL | EIO | ENOSPC | EPIPE
        '''
        for i in xrange(0, size):
            value = chr(cpu.load(buf+i,8))
            if not isinstance(value, str):
                logger.warning("Writing symbolic values to file %s", self.files[fd].name)
                value = str(value)
            self.files[fd].write(value)
        return size 

    def sys_exit_group(self, cpu, error_code):
        '''
        Exits all threads in a process
        @param cpu: current CPU.
        @param error_code: not used.
        @raise Exception: 'Finished'
        '''
        raise Exception('Finished')

    def sys_access(self, cpu, buf, mode):
        '''
        Checks real user's permissions for a file 
        @rtype: int
        
        @param cpu: current CPU.
        @param buf: a buffer containing the pathname to the file to check its permissions.
        @param mode: the access permissions to check.
        @return: 
            -  C{0} if the calling process can access the file in the desired mode.
            - C{-1} if the calling process can not access the file in the desired mode.
        '''
        filename = ""
        for i in xrange(0,255):
            c = chr(cpu.load(buf+i,8))
            if c == '\x00':
                break
            filename += c

            #if path.isfile(PATH) and access(PATH, MODE):
            #    print "File exists and is readable"
            #else:
            #    print "Either file is missing or is not readable"
        if os.access(filename, mode):
            return 0
        else:
            return -1

    def sys_mprotect(self, cpu, start, size, prot):
        '''
        Sets protection on a region of memory. Changes protection for the calling process's 
        memory page(s) containing any part of the address range in the interval [C{start}, C{start}+C{size}-1].  
        @rtype: int
        
        @param cpu: current CPU.
        @param start: the starting address to change the permissions.
        @param size: the size of the portion of memory to change the permissions.
        @param prot: the new acces premission for the memory.
        @return: C{0} on success.
        '''
        perms = ['   ', 'r  ',' w ','rw ','  x','r x', ' wx','rwx'][prot&7]
        cpu.mem.mprotect(start, size, perms)
        return 0

    def sys_munmap(self, cpu, addr, size):
        '''
        Unmaps a file from memory. It deletes the mappings for the specified address range
        @rtype: int
        
        @param cpu: current CPU.
        @param addr: the starting address to unmap.
        @param size: the size of the portion to unmap.
        @return: C{0} on success.  
        '''
        cpu.mem.munmap(addr, size)
        return 0

    def sys_getuid(self, cpu):
        '''
        Gets user identity.
        @rtype: int
        
        @param cpu: current CPU.
        @return: this call returns C{1000} for all the users.  
        '''
        return 1000
    def sys_getgid(self, cpu):
        '''
        Gets group identity.
        @rtype: int
        
        @param cpu: current CPU.
        @return: this call returns C{1000} for all the groups.  
        '''
        return 1000
    def sys_geteuid(self, cpu):
        '''
        Gets user identity.
        @rtype: int
        
        @param cpu: current CPU.
        @return: This call returns C{1000} for all the users.  
        '''
        return 1000
    def sys_getegid(self, cpu):
        '''
        Gets group identity.
        @rtype: int
        
        @param cpu: current CPU.
        @return: this call returns C{1000} for all the groups.  
        '''
        return 1000

    def sys_writev(self, cpu, fd, iov, count):
        '''
        Works just like C{sys_write} except that multiple buffers are written out (for Linux 64 bits).
        @rtype: int
        
        @param cpu: current CPU.
        @param fd: the file descriptor of the file to write.
        @param iov: the buffer where the the bytes to write are taken. 
        @param count: amount of C{iov} buffers to write into the file.
        @return: the amount of bytes written in total.
        '''
        total = 0
        for i in xrange(0, count):
            buf = cpu.load(iov+i*16,64)
            size = cpu.load(iov+i*16+8,64)

            data = ""
            for i in xrange(0,size):
                data += chr(cpu.load(buf+i,8))

            self.files[fd].write(data)
            total+=size
        return total

    def sys_writev32(self, cpu, fd, iov, count):
        '''
        Works just like C{sys_write} except that multiple buffers are written out. (32 bit version)
        @rtype: int
        
        @param cpu: current CPU.
        @param fd: the file descriptor of the file to write.
        @param iov: the buffer where the the bytes to write are taken. 
        @param count: amount of C{iov} buffers to write into the file.
        @return: the amount of bytes written in total.
        '''
        total = 0
        for i in xrange(0, count):
            buf = cpu.load(iov+i*8,32)
            size = cpu.load(iov+i*8+4,32)

            #data = ""
            for i in xrange(0,size):
                #data += chr()
                self.files[fd].write(chr(cpu.load(buf+i,8)))
            total+=size
        return total

    def sys_set_thread_area32(self, cpu, user_info):
        '''
        Sets a thread local storage (TLS) area. Sets the base address of the GS segment.
        @rtype: int
        
        @param cpu: current CPU.
        @param user_info: the TLS array entry set corresponds to the value of C{u_info->entry_number}.
        @return: C{0} on success.   
        '''
        n = cpu.load(user_info,32)
        pointer = cpu.load(user_info+4,32)
        m = cpu.load(user_info+8,32)
        flags = cpu.load(user_info+12,32)
        assert n == 0xffffffff
        assert flags == 0x51  #TODO: fix
        cpu.GS=0x63
        cpu.segments['GS'][0x63] = pointer
        cpu.store(user_info, (0x63-3)/8, 32)
        return 0

    def sys_getpriority(self, cpu, which, who):
        '''
        System call ignored. 
        @rtype: int
        
        @return: C{0}
        '''
        logger.debug("Ignoring sys_get_priority")
        return 0

    def sys_setpriority(self, cpu, which, who, prio):
        '''
        System call ignored.
        @rtype: int
        
        @return: C{0}
        '''
        logger.debug("Ignoring sys_set_priority")
        return 0

    def sys_acct(self, cpu, path):
        '''
        System call not implemented.
        @rtype: int
        
        @return: C{-1}
        '''
        logger.debug("BSD account not implemented!")
        return -1

    def sys_ioctl(self, cpu, fd, request, argp):
        return self.files[fd].ioctl(request, argp)


    def syscall(self, cpu):
        ''' 
        64 bit dispatcher.
        @param cpu: current CPU. 
        '''
        syscalls = { 0x000000000000003f: self.sys_uname, 
                 0x000000000000000c: self.sys_brk, 
                 0x000000000000009e: self.sys_arch_prctl,
                 0x0000000000000002: self.sys_open,
                 0x0000000000000000: self.sys_read,
                 0x0000000000000003: self.sys_close,
                 0x0000000000000005: self.sys_fstat64,
                 0x0000000000000009: self.sys_mmap,
                 0x0000000000000001: self.sys_write,
                 0x00000000000000e7: self.sys_exit_group,
                 0x0000000000000015: self.sys_access,
                 0x000000000000000a: self.sys_mprotect,
                 0x000000000000000b: self.sys_munmap,
                 0x0000000000000014: self.sys_writev,
                 0x0000000000000004: self.sys_stat64,
                 0x0000000000000059: self.sys_acct,
                }
        if cpu.RAX not in syscalls.keys():
            raise SyscallNotImplemented("64 bit system call %s Not Implemented" % cpu.RAX)
        func = syscalls[cpu.RAX]
        logger.debug("SYSCALL64: %s", func.func_name)

        nargs = func.func_code.co_argcount
        if nargs == 3:
            cpu.RAX = func(cpu, cpu.RDI)
        elif nargs == 4:
            cpu.RAX = func(cpu, cpu.RDI, cpu.RSI)
        elif nargs == 5:
            cpu.RAX = func(cpu, cpu.RDI, cpu.RSI, cpu.RDX)
        elif nargs == 6:
            cpu.RAX = func(cpu, cpu.RDI, cpu.RSI, cpu.RDX, cpu.R10)
        elif nargs == 7:
            cpu.RAX = func(cpu, cpu.RDI, cpu.RSI, cpu.RDX, cpu.R10, cpu.R8)
        elif nargs == 8:
            cpu.RAX = func(cpu, cpu.RDI, cpu.RSI, cpu.RDX, cpu.R10, cpu.R8, cpu.R9)
        else:
            print nargs
            raise NotImplemented()

    def int80(self, cpu):
        ''' 
        32 bit dispatcher.
        @param cpu: current CPU.
        '''
        syscalls = { 0x00000001: self.sys_exit_group, 
                     0x00000003: self.sys_read, 
                     0x00000004: self.sys_write,
                     0x00000005: self.sys_open,
                     0x00000006: self.sys_close,
                     0x00000021: self.sys_access, 
                     0x0000002d: self.sys_brk,
                     0x00000036: self.sys_ioctl,
                     0x00000059: self.sys_acct,
                     0x0000005b: self.sys_munmap,
                     0x0000007a: self.sys_uname, 
                     0x0000007d: self.sys_mprotect,
                     0x0000008c: self.sys_setpriority,
                     0x0000008d: self.sys_getpriority,
                     0x00000092: self.sys_writev32,
                     0x000000c0: self.sys_mmap2, 
                     0x000000c5: self.sys_fstat, 
                     0x000000c7: self.sys_getuid,
                     0x000000c8: self.sys_getgid,
                     0x000000c9: self.sys_geteuid,
                     0x000000ca: self.sys_getegid,
                     0x000000f3: self.sys_set_thread_area32,
                     0x000000fc: self.sys_exit_group, 
                    }
        if cpu.EAX not in syscalls.keys():
            raise SyscallNotImplemented("32 bit system call %s Not Implemented" % cpu.RAX)
        func = syscalls[cpu.EAX]
        logger.debug("SYSCALL32: %s", func.func_name)

        nargs = func.func_code.co_argcount
        if nargs == 3:
            cpu.EAX = func(cpu, cpu.EBX)
        elif nargs == 4:
            cpu.EAX = func(cpu, cpu.EBX, cpu.ECX)
        elif nargs == 5:
            cpu.EAX = func(cpu, cpu.EBX, cpu.ECX, cpu.EDX)
        elif nargs == 6:
            cpu.EAX = func(cpu, cpu.EBX, cpu.ECX, cpu.EDX, cpu.ESI)
        elif nargs == 7:
            cpu.EAX = func(cpu, cpu.EBX, cpu.ECX, cpu.EDX, cpu.ESI, cpu.EDI)
        elif nargs == 8:
            cpu.EAX = func(cpu, cpu.EBX, cpu.ECX, cpu.EDX, cpu.ESI, cpu.EDI, cpu.EBP)
        else:
            raise NotImplemented()

    def execute(self):
        """
        Execute one cpu instruction in the current thread (only one suported).
        @rtype: bool
        @return: C{True}
        
        @todo: This is where we could implement a simple schedule.
        """
        self.cpu.execute()
        return True


class SymbolicFile(object):
    '''
    Represents a symbolic file
    '''
    def __init__(self, solver, path="sfile", mode='rw', max_size=100, wildcard='+'):
        '''
        Builds a symbolic file
        @param solver: the solver
        @param path: the pathname of the symbolic file
        @param mode: the access permissions of the symbolic file
        @param max_size: Maximun amount of bytes of the symbolic file   
        '''
        assert 'r' in mode
        if isinstance(path, str):
            path = File(path, mode)
        assert isinstance(path, File)

        #self._solver = weakref.ref(solver)
        WILDCARD = '+'

        symbols_cnt = 0
        data = path.read()
        size = len(data)
        self.array = solver.mkArray(name=path.name, is_input=True, max_size=size)
        for i in range(size):
            if data[i] != WILDCARD:
                self.array[i] = data[i]
            else:
                symbols_cnt+=1
        if symbols_cnt > max_size:
            logger.warning("Found more free symbolic vlues than allowed (%d > %d)",symbols_cnt, max_size)

        self.pos = 0
        self.max_size=min(len(data), max_size)

    def __getstate__(self):
        state = {}
        state['array'] = self.array
        state['pos'] = self.pos
        state['max_size'] = self.max_size
        return state

    def __setstate__(self, state):
        self.pos = state['pos']
        self.max_size = state['max_size']
        self.array = state['array']

    @property
    def solver(self):
        return self._solver()
    @property
    def name(self):
        return self.array.name

    def ioctl(self, request, argp):
        #logger.debug("IOCTL on symbolic files not implemented! (req:%x)", request)
        return 0

    def stat(self):
        from collections import namedtuple
        stat_result = namedtuple('stat_result', ['st_mode','st_ino','st_dev','st_nlink','st_uid','st_gid','st_size','st_atime','st_mtime','st_ctime', 'st_blksize','st_blocks','st_rdev'])
        return stat_result(8592,11,9,1,1000,5,0,1378673920,1378673920,1378653796,0x400,0x8808,0)

    def fileno(self):
        '''
        Not implemented
        '''
        pass
        #return self.f.fileno()

    def tell(self):
        '''
        Returns the read/write file offset
        @rtype: int
        @return: the read/write file offset.
        '''
        return self.pos

    def read(self, count):
        '''
        Reads up to C{count} bytes from the file.
        @rtype: list
        @return: the list of symbolic bytes read  
        '''
        if self.pos > self.max_size :
            return []
        else:
            size = min(count,self.max_size-self.pos)
            ret = [self.array[i] for i in xrange(self.pos,self.pos+size)]
            self.pos+=size
            return ret

    def write(self, data):
        '''
        Writes the symbolic bytes in C{data} onto the file. 
        '''
        for c in data:
            size = min(len(data),self.max_size-self.pos)
            for i in xrange(self.pos,self.pos+size):
                self.array[i] = data[i-self.pos]


class SLinux(Linux):
    '''
    A symbolic extension of a Linux Operating System Model.
    '''
    
    def __init__(self, solver, cpus, mem, symbolic_files=['stdin']):
        '''
        Builds a symbolic extension of a Linux OS
        @param solver: a solver.
        @param cpus: CPU for this model.
        @param mem: memory for this model.
        '''
        super(SLinux, self).__init__(cpus, mem)
        self._solver = weakref.ref(solver)
        self.symbolic_files = symbolic_files

    @property
    def solver(self):
        return self._solver()

    #marshaling/pickle
    def __getstate__(self):
        state = super(SLinux, self).__getstate__()
        state['solver'] = self.solver
        state['symbolic_files'] = self.symbolic_files
        return state

    def __setstate__(self, state):
        self._solver = weakref.ref(state['solver'])
        self.symbolic_files = state['symbolic_files']
        super(SLinux, self).__setstate__(state)

    def exe(self, filename, argv=[], envp=[], stdin='stdin', stdout='stdout', stderr='stderr'):
        super(SLinux,self).exe(filename, argv, envp, stdin='stdin', stdout='stdout', stderr='stderr')
        if stdin in self.symbolic_files:
            #Replace stdin with symbolic file
            self.files[0] = SymbolicFile(self.solver, self.files[0],'rb')


    def sys_open(self, cpu, buf, flags, mode):
        # buf: address of zero-terminated pathname
        # flags/access: file access bits
        # perms: file permission mode
        filename = self._read_string(cpu, buf)

        f = File(filename) #todo modes, flags
        if filename in self.symbolic_files:
            f = SymbolicFile(self.solver, f, mode)

        if None in self.files:
            fd = self.files.index(None)
            self.files[fd]=f
        else:
            self.files.append(f)
            fd = len(self.files)-1
        return fd

    def sys_exit_group(self, cpu, error_code):
        return super(SLinux, self).sys_exit_group(cpu, error_code)

