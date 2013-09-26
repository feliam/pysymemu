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
        if cnt > 100: #No more than 10000 instructions of each kind
            continue
        op_count[test['mnemonic']] = cnt+1
        test_dic["%s_%d"%(test['mnemonic'],op_count[test['mnemonic']])] = test
    except Exception,e:
        print "EX", e, test
        pass



print """
from cpu import Cpu

import unittest

class CPUTest(unittest.TestCase):
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

    class Mem(object):
        ''' Mocking class for memory '''
        def __init__(self, mem):
            self.mem = dict(mem)
        def getchar(self, addr):
            #print "getchar",hex(addr), "%02x"%ord(self.mem[addr])
            return self.mem[addr]
        def putchar(self, addr, char):
            #print "putchar",hex(addr), "%02x"%ord(char)
            self.mem[addr]=char
"""

from flags import flags
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
    def test%s(self):
        ''' Instruction %s '''
        test = %s
        mem = CPUTest.Mem(test['pre']['memory'])
        cpu = Cpu(mem, test['arch'])
        for reg_name in test['pre']['registers']:
            cpu.setRegister(reg_name, test['pre']['registers'][reg_name])

        cpu.execute()

        for addr in mem.mem:
            self.assertEqual(mem.getchar(addr), test['pos']['memory'][addr], "Memory at address %%016x doesn't match %%s vs %%s"%%(addr, repr(mem.getchar(addr)), repr(test['pos']['memory'][addr])))
        for reg_name in test['pos']['registers']:
            if 'FLAG' in reg_name:
                self.assertEqual(cpu.getRegister(reg_name)&0x%x, test['pos']['registers'][reg_name]&0x%x, "%%s doesn't match %%x vs %%x"%%(reg_name,cpu.getRegister(reg_name), test['pos']['registers'][reg_name]))
            else:
                self.assertEqual(cpu.getRegister(reg_name), test['pos']['registers'][reg_name], "%%s doesn't match %%x vs %%x"%%(reg_name,cpu.getRegister(reg_name), test['pos']['registers'][reg_name]))
"""%(test_name,test_dic[test_name]['disassembly'],repr(test_dic[test_name]),mask,mask)
print """
if __name__ == '__main__':
    unittest.main()
"""
