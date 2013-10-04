import sys, random
tests = []
tests_str = file(sys.argv[1], 'r').read().split('\n')
for t_str in tests_str:
    try:
        tests.append(eval(t_str))
    except:
        pass

random.shuffle(tests)

op_count = {}
test_dic = {}
for test in tests:
    try:
        cnt = op_count.get(test['mnemonic'],0)
        if cnt > 100:
            continue
        op_count[test['mnemonic']] = cnt+1
        test_dic["%s_%d"%(test['mnemonic'],op_count[test['mnemonic']])] = test
    except Exception,e:
        pass



print """
from smtlibv2 import Solver
from cpu import Cpu

import unittest

sizes = {'RAX': 64, 'EAX': 32, 'AX': 16, 'AL': 8, 'AH': 8, 'RCX': 64, 'ECX': 32, 'CX': 16, 'CL': 8, 'CH': 8, 'RDX': 64, 'EDX': 32, 'DX': 16, 'DL': 8, 'DH': 8, 'RBX': 64, 'EBX': 32, 'BX': 16, 'BL': 8, 'BH': 8, 'RSP': 64, 'ESP': 32, 'SP': 16, 'SPL': 8, 'RBP': 64, 'EBP': 32, 'BP': 16, 'BPL': 8, 'RSI': 64, 'ESI': 32, 'SI': 16, 'SIL': 8, 'RDI': 64, 'EDI': 32, 'DI': 16, 'DIL': 8, 'R8': 64, 'R8D': 32, 'R8W': 16, 'R8B': 8, 'R9': 64, 'R9D': 32, 'R9W': 16, 'R9B': 8, 'R10': 64, 'R10D': 32, 'R10W': 16, 'R10B': 8, 'R11': 64, 'R11D': 32, 'R11W': 16, 'R11B': 8, 'R12': 64, 'R12D': 32, 'R12W': 16, 'R12B': 8, 'R13': 64, 'R13D': 32, 'R13W': 16, 'R13B': 8, 'R14': 64, 'R14D': 32, 'R14W': 16, 'R14B': 8, 'R15': 64, 'R15D': 32, 'R15W': 16, 'R15B': 8, 'ES': 16, 'CS': 16, 'SS': 16, 'DS': 16, 'FS': 16, 'GS': 16, 'RIP': 64, 'EIP':32, 'IP': 16, 'RFLAGS': 64, 'EFLAGS': 32, 'FLAGS': 16, 'XMM0': 128, 'XMM1': 128, 'XMM2': 128, 'XMM3': 128, 'XMM4': 128, 'XMM5': 128, 'XMM6': 128, 'XMM7': 128, 'XMM8': 128, 'XMM9': 128, 'XMM10': 128, 'XMM11': 128, 'XMM12': 128, 'XMM13': 128, 'XMM14': 128, 'XMM15': 128, 'YMM0': 256, 'YMM1': 256, 'YMM2': 256, 'YMM3': 256, 'YMM4': 256, 'YMM5': 256, 'YMM6': 256, 'YMM7': 256, 'YMM8': 256, 'YMM9': 256, 'YMM10': 256, 'YMM11': 256, 'YMM12': 256, 'YMM13': 256, 'YMM14': 256, 'YMM15': 256}

class SymCPUTest(unittest.TestCase):
    class ROOperand(object):
        ''' Mocking class for operand ronly '''
        def __init__(self, size, value):
            self.size = size
            self.value = value
        def read(self):
            return self.value & ((1<<self.size)-1)

    class RWOperand(ROOperand):
        ''' Mocking class for operand rw '''
        def write(self, value):
            self.value = value & ((1<<self.size)-1)
            return self.value

    class SMem(object):
        ''' Mocking class for memory '''
        def __init__(self, array, init):
            self.code = {}
            self.mem = array
            for addr, val in init.items():
                self.mem[addr] = val
        def setcode(self, addr, c):
            assert isinstance(addr,(int,long))
            assert isinstance(c,str) and len(c) == 1
            self.code[addr] = c

        def getchar(self, addr):
            if isinstance(addr, (int,long)) and addr in self.code.keys():
                return self.code[addr]
            if isinstance(addr, (int,long)) and addr == max(self.code.keys())+1:
                raise Exception("no more code!")
            return self.mem[addr]
        def putchar(self, addr, char):
            self.mem[addr]=char

"""


flags_maks={
    'CF': 0x00001,
    'PF': 0x00004,
    'AF': 0x00010,
    'ZF': 0x00040,
    'SF': 0x00080,
    'DF': 0x00400,
    'OF': 0x00800,
    'IF': 0x10000,
}
for test_name in sorted(test_dic.keys()):
    mask = 0
    try:
        for fl in flags[test_dic[test_name]['mnemonic']]['defined']:
            mask |= flags_maks[fl]
    except:
        mask = 0x00001|0x00004|0x00010|0x00040|0x00080|0x00400|0x00800|0x10000
    print """
    def test_%s(self):
        ''' %s '''
        test = %s

        solver = Solver()

        mem = SymCPUTest.SMem(solver.mkArray({'i386': 32, 'amd64': 64}[test['arch']]), test['pre']['memory'])
        cpu = Cpu(mem, test['arch'])
        for reg_name in test['pre']['registers']:
            if reg_name in ['RIP','EIP','IP']:
                cpu.setRegister(reg_name, test['pre']['registers'][reg_name])
                try:
                    for i in range(16):
                        addr = test['pre']['registers'][reg_name]+i
                        mem.setcode(addr, test['pre']['memory'][addr])
                except Exception,e:
                    pass
            else:
                var = solver.mkBitVec(sizes[reg_name],reg_name)
                solver.add(var == test['pre']['registers'][reg_name])
                cpu.setRegister(reg_name, var)

        cpu.execute()

        for addr in test['pos']['memory'].keys():
            solver.add(mem.getchar(addr) == test['pos']['memory'][addr])

        for reg_name in test['pos']['registers']:
            if 'FLAG' in reg_name:
                solver.add(cpu.getRegister(reg_name)&0x%x == test['pos']['registers'][reg_name]&0x%x)
            else:
                solver.add(cpu.getRegister(reg_name) == test['pos']['registers'][reg_name])
        self.assertEqual(solver.check(), 'sat')
"""%(test_name,test_dic[test_name]['disassembly'],repr(test_dic[test_name]),mask,mask)
print """
if __name__ == '__main__':
    unittest.main()
"""

