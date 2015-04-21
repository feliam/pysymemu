import copy
import traceback
import sys
import sys
import time
import subprocess
from capstone import *
from capstone.x86 import *
CapRegisters = ['(INVALID)', 'AH', 'AL', 'AX', 'BH', 'BL', 'BP', 'BPL', 'BX', 'CH', 'CL', 'CS', 'CX', 'DH', 'DI', 'DIL', 'DL', 'DS', 'DX', 'EAX', 'EBP', 'EBX', 'ECX', 'EDI', 'EDX', 'RFLAGS', 'EIP', 'EIZ', 'ES', 'ESI', 'ESP', 'FPSW', 'FS', 'GS', 'IP', 'RAX', 'RBP', 'RBX', 'RCX', 'RDI', 'RDX', 'RIP', 'RIZ', 'RSI', 'RSP', 'SI', 'SIL', 'SP', 'SPL', 'SS', 'CR0', 'CR1', 'CR2', 'CR3', 'CR4', 'CR5', 'CR6', 'CR7', 'CR8', 'CR9', 'CR10', 'CR11', 'CR12', 'CR13', 'CR14', 'CR15', 'DR0', 'DR1', 'DR2', 'DR3', 'DR4', 'DR5', 'DR6', 'DR7', 'FP0', 'FP1', 'FP2', 'FP3', 'FP4', 'FP5', 'FP6', 'FP7', 'K0', 'K1', 'K2', 'K3', 'K4', 'K5', 'K6', 'K7', 'MM0', 'MM1', 'MM2', 'MM3', 'MM4', 'MM5', 'MM6', 'MM7', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'ST0', 'ST1', 'ST2', 'ST3', 'ST4', 'ST5', 'ST6', 'ST7', 'XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7', 'XMM8', 'XMM9', 'XMM10', 'XMM11', 'XMM12', 'XMM13', 'XMM14', 'XMM15', 'XMM16', 'XMM17', 'XMM18', 'XMM19', 'XMM20', 'XMM21', 'XMM22', 'XMM23', 'XMM24', 'XMM25', 'XMM26', 'XMM27', 'XMM28', 'XMM29', 'XMM30', 'XMM31', 'YMM0', 'YMM1', 'YMM2', 'YMM3', 'YMM4', 'YMM5', 'YMM6', 'YMM7', 'YMM8', 'YMM9', 'YMM10', 'YMM11', 'YMM12', 'YMM13', 'YMM14', 'YMM15', 'YMM16', 'YMM17', 'YMM18', 'YMM19', 'YMM20', 'YMM21', 'YMM22', 'YMM23', 'YMM24', 'YMM25', 'YMM26', 'YMM27', 'YMM28', 'YMM29', 'YMM30', 'YMM31', 'ZMM0', 'ZMM1', 'ZMM2', 'ZMM3', 'ZMM4', 'ZMM5', 'ZMM6', 'ZMM7', 'ZMM8', 'ZMM9', 'ZMM10', 'ZMM11', 'ZMM12', 'ZMM13', 'ZMM14', 'ZMM15', 'ZMM16', 'ZMM17', 'ZMM18', 'ZMM19', 'ZMM20', 'ZMM21', 'ZMM22', 'ZMM23', 'ZMM24', 'ZMM25', 'ZMM26', 'ZMM27', 'ZMM28', 'ZMM29', 'ZMM30', 'ZMM31', 'R8B', 'R9B', 'R10B', 'R11B', 'R12B', 'R13B', 'R14B', 'R15B', 'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D', 'R8W', 'R9W', 'R10W', 'R11W', 'R12W', 'R13W', 'R14W', 'R15W']

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
        #instruction = Decompose(pc, text, {'i386':Decode32Bits, 'amd64':Decode64Bits}[arch])[0]

        cap_arch = {'i386': CS_ARCH_X86, 'amd64': CS_ARCH_X86}[arch] 
        cap_mode = {'i386': CS_MODE_32, 'amd64': CS_MODE_64}[arch] 
        md = Cs(cap_arch, cap_mode)
        md.detail = True
        md.syntax = 0

        instruction = None
        for i in md.disasm(text, pc):
            instruction = i
            break

        #print instruction
        disassembly = "0x%x:\t%s\t%s" %(instruction.address, instruction.mnemonic, instruction.op_str)
        print "#INSTRUCTION:", disassembly

        if instruction.insn_name().upper() in ['CPUID', 'RDTSC', 'NOP', 'SYSCALL', 'INT', 'SYSENTER']:
            print "#Skiping:, ", instruction.insn_name().upper()
            print "SKP:", gdb.stepi()
            continue

        # gather PRE info
        test = {'mnemonic': instruction.insn_name().upper(), 'disassembly': disassembly, 'text':text[:instruction.size], 'arch':arch}
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
            if o.type == X86_OP_IMM:
                #ignore, already encoded in instruction
                continue
            elif o.type == X86_OP_REG:
                REGNAME = instruction.reg_name(o.reg).upper()
                registers[REGNAME] = gdb.getR(REGNAME)
            elif o.type == X86_OP_MEM:
                #save register involved and memory values
                address = 0
                address += o.mem.disp
                if o.mem.base != 0:
                    base = instruction.reg_name(o.mem.base).upper()
                    registers[base] = gdb.getR(base)
                    address += registers[base]
                if o.mem.index != 0:
                    name = instruction.reg_name(o.mem.index).upper()
                    registers[name] = gdb.getR(name)
                    address += o.mem.scale*registers[name]

                for i in range(address, address+o.size):
                    memory[i] = chr(gdb.getByte(i))

        if instruction.insn_name().upper() in STACK_INSTRUCTIONS:
            #save a bunch of stack
            pointer =  gdb.getR({'i386': 'ESP', 'amd64': 'RSP'}[arch])
            for i in range(-{'i386': 5, 'amd64': 9}[arch], {'i386': 5, 'amd64': 9}[arch]):
                memory[pointer+i] = chr(gdb.getByte(pointer+i))

        if instruction.insn_name().upper() in ['LEAVE', 'ENTER']:
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
            if o.type == X86_OP_REG:
                name = instruction.reg_name(o.reg).upper()
                registers[name] = gdb.getR(name)
            elif o.type == X86_OP_IMM:
                continue

        #update memory
        for i in memory.keys():
            memory[i] = chr(gdb.getByte(i))

        if instruction.insn_name().upper() in STACK_INSTRUCTIONS:
            #save a bunch of stack
            pointer =  gdb.getR({'i386': 'ESP', 'amd64': 'RSP'}[arch])
            for i in range(-{'i386': 5, 'amd64': 9}[arch], {'i386': 5, 'amd64': 9}[arch]):
                memory[pointer+i] = chr(gdb.getByte(pointer+i))
        if instruction.insn_name().upper() in ['LEAVE', 'ENTER']:
            pointer =  gdb.getR({'i386': 'EBP', 'amd64': 'RBP'}[arch])
            for i in range(-{'i386': 5, 'amd64': 9}[arch], {'i386': 5, 'amd64': 9}[arch]):
                memory[pointer+i] = chr(gdb.getByte(pointer+i))

        test['pos'] = {}
        test['pos']['memory'] = memory
        test['pos']['registers'] = registers

        print test 

        count += 1
        #check if exit
        if instruction.insn_name().upper() in ['SYSCALL', 'INT', 'SYSENTER']:
            if "The program has no registers now." in gdb.correspond("info registers \n"):
                print "done" 
                break

    except Exception,e:
        if "The program has no registers now." in gdb.correspond("info registers\n"):
            break
        print '-'*60
        traceback.print_exc(file=sys.stdout)
        print '-'*60
        import pdb
        pdb.set_trace()
        print "#", e
        print "instruction", dir(instruction)
        if not stepped:
            gdb.stepi()

print "# Processed %d instructions." % count


