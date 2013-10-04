import copy
import sys
import sys
import time
import subprocess
from distorm3 import Decompose, Decode16Bits, Decode32Bits, Decode64Bits, Mnemonics, Registers

count = 0
 
class Gdb(subprocess.Popen):
    def __init__(self, prg, prompt='(gdb) '):
        """Construct interactive Popen."""
        self.prompt = prompt
        subprocess.Popen.__init__(self, ['gdb', prg], stdin=subprocess.PIPE, stdout=subprocess.PIPE , stderr=subprocess.STDOUT)

    def correspond(self, text):
        """Communicate with the child process without closing stdin."""
        self.stdin.write(text)
        self.stdin.flush()
        str_buffer = ''
        while not str_buffer.endswith(self.prompt):
            str_buffer += self.stdout.read(1)
        return str_buffer

    def getR(self, reg):
        reg = "$"+reg
        if "XMM" in reg:
            reg = reg+".uint128"
            val = self.correspond('p %s\n'%reg.lower()).split("=")[-1].split("\n")[0]
            if "0x" in val:
                return int(val.split("0x")[-1],16)
            else:
                return int(val)
        if "FLAG" in reg:
            reg = "(unsigned) "+reg
        if reg in ['$R%dB'%i for i in range(16)] :
            reg = reg[:-1] + "&0xff"
        if reg in ['$R%dW'%i for i in range(16)] :
            reg = reg[:-1] + "&0xffff"
        val = self.correspond('p /x %s\n'%reg.lower()).split("0x")[-1]
        return long(val.split("\n")[0],16)

    def setR(reg, value):
        self.correspond('set $%s = %s\n'%(reg.lower(), int(value)))
    def setByte(self, m, value):
        self.correspond('set *(char*)(%s) = %s\n'%(m,value))

    def stepi(self):
        #print self.correspond("x/i $pc\n")
        self.correspond("stepi\n")
    def getM(self, m):
        try:
            return long(self.correspond('x/xg %s\n'%m).split("\t")[-1].split("0x")[-1].split("\n")[0],16)
        except Exception,e:
            print 'x/xg %s\n'%m
            print self.correspond('x/xg %s\n'%m)
            raise e
            return 0
    def getPid(self):
        return int(self.correspond('info proc\n').split("\n")[0].split(" ")[-1])
    def getStack(self):
        maps = file("/proc/%s/maps"%self.correspond('info proc\n').split("\n")[0].split(" ")[-1]).read().split("\n")
        i,o = [ int(x,16) for x in maps[-3].split(" ")[0].split('-')]
        print self.correspond('dump mem lala 0x%x 0x%x\n'%(i,o))
    def getByte(self, m):
        arch = self.get_arch()
        mask = {'i386': 0xffffffff, 'amd64': 0xffffffffffffffff}[arch]
        return int(self.correspond("x/1bx %d\n"%(m&mask)).split("\t")[-1].split("\n")[0][2:],16)
    def get_entry(self):
        a=self.correspond('info target\n')
        return int(a[a.find("Entry point:"):].split('\n')[0].split(' ')[-1][2:],16)

    _arch = None
    def get_arch(self):
        if self._arch is not None:
            return self._arch
        infotarget = self.correspond('info target\n')
        if 'elf32-i386' in infotarget:
            self._arch = 'i386'
            return 'i386'
        elif 'elf64-x86-64' in infotarget:
            self._arch = 'amd64'
            return 'amd64'
        else:
            print infotarget
            raise NotImplemented


gdb = Gdb(sys.argv[1])
arch = gdb.correspond('')

#guess arch
arch = gdb.get_arch()

#gues architecture from file
entry = gdb.get_entry()
gdb.correspond("b *0\n")
gdb.correspond("run arg1 arg2 arg3 < /dev/urandom > /dev/null\n")
gdb.correspond("d 1\n")

# Simulate no vdso (As when analized with symbemu)
found = 0
for i in range(75,120):
    if gdb.getM('$sp+sizeof(void*)*%d'%i) ==0x19 and gdb.getM('$sp+%d'%(i+2))==0x1f:
        found = i
if found !=0:
    gdb.setByte('$sp+sizeof(void*)*%d'%found,1)
    gdb.setByte('$sp+sizeof(void*)*%d'%(found+2),1)

vdso = gdb.getM('$sp+sizeof(void*)*%d'%(found+1))
for i in range(75,120):
    val = gdb.getM('$sp+sizeof(void*)*%d'%i)
    if val > vdso-0x10000 and val <= vdso+0x10000:
        if (gdb.getM('$sp+sizeof(void*)*%d'%(i-1))) != 1:
            gdb.setByte('$sp+sizeof(void*)*%d'%(i-1),1)

STACK_INSTRUCTIONS = ['BOUND', 'CALL', 'CALLF', 'ENTER', 'INT', 'INT1', 'INTO', 'IRET', 'IRETD', 'LEAVE', 'POP', 'POPA', 'POPAD', 'POPF', 'POPFD', 'PUSH', 'PUSHA', 'PUSHAD', 'PUSHF', 'PUSHFD', 'RETF', 'RETN', 'RET']
while True:
    try:
        stepped = False
        pc = gdb.getR({'i386': 'EIP', 'amd64': 'RIP'}[arch]) 
        text = ''.join([chr(gdb.getByte(pc+i)) for i in range(16)])
        #print text.encode('hex')
        instruction = Decompose(pc, text, {'i386':Decode32Bits, 'amd64':Decode64Bits}[arch])[0]
        #print instruction
        print "#INSTRUCTION:",hex(pc), instruction

        if instruction.mnemonic in ['CPUID', 'RDTSC', 'NOP', 'SYSCALL', 'INT', 'SYSENTER'] or \
           instruction.segment != 255 and not instruction.isSegmentDefault:
            print "#Skiping:, ", instruction.mnemonic
            print "SKP:", gdb.stepi()
            continue

        # gather PRE info
        test = {'mnemonic': instruction.mnemonic, 'disassembly': str(instruction), 'text':text[:instruction.size], 'arch':arch}
        registers = {}
        memory = {}
        #default registers...
        registers[{'i386': 'EIP', 'amd64': 'RIP'}[arch]] = gdb.getR({'i386': 'EIP', 'amd64': 'RIP'}[arch])
        registers[{'i386': 'ESP', 'amd64': 'RSP'}[arch]] = gdb.getR({'i386': 'ESP', 'amd64': 'RSP'}[arch])
        registers[{'i386': 'EBP', 'amd64': 'RBP'}[arch]] = gdb.getR({'i386': 'EBP', 'amd64': 'RBP'}[arch])
        registers[{'i386': 'ECX', 'amd64': 'RCX'}[arch]] = gdb.getR({'i386': 'ECX', 'amd64': 'RCX'}[arch])
        registers[{'i386': 'ESI', 'amd64': 'RSI'}[arch]] = gdb.getR({'i386': 'ESI', 'amd64': 'RSI'}[arch])
        registers[{'i386': 'EDI', 'amd64': 'RDI'}[arch]] = gdb.getR({'i386': 'EDI', 'amd64': 'RDI'}[arch])
        registers[{'i386': 'EDX', 'amd64': 'RDX'}[arch]] = gdb.getR({'i386': 'EDX', 'amd64': 'RDX'}[arch])
        registers[{'i386': 'EAX', 'amd64': 'RAX'}[arch]] = gdb.getR({'i386': 'EAX', 'amd64': 'RAX'}[arch])

        registers[{'i386':'EFLAGS', 'amd64': 'RFLAGS'}[arch]] = gdb.getR('EFLAGS')

        #save operands
        for o in instruction.operands:
            if o.type == 'Immediate':
                #ignore, already encoded in instruction
                continue
            elif o.type == 'Register':
                registers[o.name] = gdb.getR(o.name)
            elif o.type == 'AbsoluteMemory':
                #save register involved and memory values
                address = 0
                address += o.disp
                if not o.base is None:
                    name = Registers[o.base]
                    registers[name] = gdb.getR(name)
                    address += registers[name]
                if not o.index is None and o.scale > 0:
                    name = Registers[o.index]
                    registers[name] = gdb.getR(name)
                    address += o.scale*registers[name]
                for i in range(address, address+o.size):
                    memory[i] = chr(gdb.getByte(i))

        if instruction.mnemonic in STACK_INSTRUCTIONS:
            #save a bunch of stack
            pointer =  gdb.getR({'i386': 'ESP', 'amd64': 'RSP'}[arch])
            for i in range(-{'i386': 5, 'amd64': 9}[arch], {'i386': 5, 'amd64': 9}[arch]):
                memory[pointer+i] = chr(gdb.getByte(pointer+i))

        if instruction.mnemonic in ['LEAVE', 'ENTER']:
            pointer =  gdb.getR({'i386': 'EBP', 'amd64': 'RBP'}[arch])
            for i in range(-{'i386': 5, 'amd64': 9}[arch], {'i386': 5, 'amd64': 9}[arch]):
                memory[pointer+i] = chr(gdb.getByte(pointer+i))

        #save the encoded instruction
        for i in range(instruction.size):
            memory[pc+i] = text[i]


        test['pre'] = {}
        test['pre']['memory'] = memory
        test['pre']['registers'] = registers

        # STEP !
        gdb.stepi()
        stepped = True

        # gather POS info
        registers = {}
        memory = dict(memory)
        #default registers...
        registers[{'i386': 'EIP', 'amd64': 'RIP'}[arch]] = gdb.getR({'i386': 'EIP', 'amd64': 'RIP'}[arch])
        registers[{'i386': 'ESP', 'amd64': 'RSP'}[arch]] = gdb.getR({'i386': 'ESP', 'amd64': 'RSP'}[arch])
        registers[{'i386': 'EBP', 'amd64': 'RBP'}[arch]] = gdb.getR({'i386': 'EBP', 'amd64': 'RBP'}[arch])
        registers[{'i386': 'ECX', 'amd64': 'RCX'}[arch]] = gdb.getR({'i386': 'ECX', 'amd64': 'RCX'}[arch])
        registers[{'i386': 'ESI', 'amd64': 'RSI'}[arch]] = gdb.getR({'i386': 'ESI', 'amd64': 'RSI'}[arch])
        registers[{'i386': 'EDI', 'amd64': 'RDI'}[arch]] = gdb.getR({'i386': 'EDI', 'amd64': 'RDI'}[arch])
        registers[{'i386': 'EDX', 'amd64': 'RDX'}[arch]] = gdb.getR({'i386': 'EDX', 'amd64': 'RDX'}[arch])
        registers[{'i386': 'EAX', 'amd64': 'RAX'}[arch]] = gdb.getR({'i386': 'EAX', 'amd64': 'RAX'}[arch])
        registers[{'i386': 'EFLAGS', 'amd64': 'RFLAGS'}[arch]] = gdb.getR('EFLAGS')

        #save operands
        for o in instruction.operands:
            if o.type == 'Immediate':
                #ignore, already encoded in instruction
                continue
            elif o.type == 'Register':
                registers[o.name] = gdb.getR(o.name)

        #update memory
        for i in memory.keys():
            memory[i] = chr(gdb.getByte(i))

        if instruction.mnemonic in STACK_INSTRUCTIONS:
            #save a bunch of stack
            pointer =  gdb.getR({'i386': 'ESP', 'amd64': 'RSP'}[arch])
            for i in range(-{'i386': 5, 'amd64': 9}[arch], {'i386': 5, 'amd64': 9}[arch]):
                memory[pointer+i] = chr(gdb.getByte(pointer+i))
        if instruction.mnemonic in ['LEAVE', 'ENTER']:
            pointer =  gdb.getR({'i386': 'EBP', 'amd64': 'RBP'}[arch])
            for i in range(-{'i386': 5, 'amd64': 9}[arch], {'i386': 5, 'amd64': 9}[arch]):
                memory[pointer+i] = chr(gdb.getByte(pointer+i))

        test['pos'] = {}
        test['pos']['memory'] = memory
        test['pos']['registers'] = registers

        print test 

        count += 1
        #check if exit
        if instruction.mnemonic in ['SYSCALL', 'INT', 'SYSENTER']:
            if "The program has no registers now." in gdb.correspond("info registers \n"):
                print "done" 
                break

    except Exception,e:
        if "The program has no registers now." in gdb.correspond("info registers\n"):
            break
        print "#", e, instruction
        if not stepped:
            gdb.stepi()

print "# Processed %d instructions." % count


