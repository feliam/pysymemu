import unittest
from cpu import *

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


class CPUTest(unittest.TestCase):
    def setUp(self):
        class Memory:  #todo Mock
            def getchar(self, addr):
                raise NotImplemented()
            def putchar(self, addr, value):
                raise NotImplemented()
        mem = Memory()
        self.cpu = Cpu(mem, 'i386') #TODO reset cpu in between tests...
                    #TODO mock getchar/putchar in case the instructon access memory directly
    def tearDown(self):
        self.cpu = None
    def testInitialRegState(self):
        cpu = self.cpu
        #'CR0', 'CR1', 'CR2', 'CR3', 'CR4', 'CR5', 'CR6', 'CR7', 'CR8',
        # 'DR0', 'DR1', 'DR2', 'DR3', 'DR4', 'DR5', 'DR6', 'DR7',
        #'MM0', 'MM1', 'MM2', 'MM3', 'MM4', 'MM5', 'MM6', 'MM7',
        #  'ST0', 'ST1', 'ST2', 'ST3', 'ST4', 'ST5', 'ST6', 'ST7'

        for reg_name in ['AH', 'AL', 'AX', 'BH', 'BL', 'BP', 'BPL', 'BX', 'CH', 'CL',  'CS', 'CX', 'DH', 'DI', 'DIL', 'DL', 'DS', 'DX', 'EAX', 'EBP', 'EBX', 'ECX', 'EDI', 'EDX', 'EFLAGS', 'EIP', 'ES', 'ESI', 'ESP', 'FLAGS', 'FS', 'GS',  'R10', 'R10B', 'R10D', 'R10W', 'R11', 'R11B', 'R11D', 'R11W', 'R12', 'R12B', 'R12D', 'R12W', 'R13', 'R13B', 'R13D', 'R13W', 'R14', 'R14B', 'R14D', 'R14W', 'R15', 'R15B', 'R15D', 'R15W', 'R8', 'R8B', 'R8D', 'R8W', 'R9', 'R9B', 'R9D', 'R9W', 'RAX', 'RBP', 'RBX', 'RCX', 'RDI', 'RDX', 'RFLAGS', 'RIP', 'RSI', 'RSP', 'SI', 'SIL', 'SP', 'SPL', 'SS', 'XMM0', 'XMM1', 'XMM10', 'XMM11', 'XMM12', 'XMM13', 'XMM14', 'XMM15', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7', 'XMM8', 'XMM9', 'YMM0', 'YMM1', 'YMM10', 'YMM11', 'YMM12', 'YMM13', 'YMM14', 'YMM15', 'YMM2', 'YMM3', 'YMM4', 'YMM5', 'YMM6', 'YMM7', 'YMM8', 'YMM9']:
            self.assertEqual(cpu.getRegister(reg_name),0)

    def testRegisterCacheAccess(self):
        cpu = self.cpu
        cpu.ESI = 0x12345678
        self.assertEqual(cpu.ESI, 0x12345678)
        cpu.SI = 0xAAAA
        self.assertEqual(cpu.SI, 0xAAAA)

        
        cpu.RAX = 0x12345678aabbccdd
        self.assertEqual(cpu.ESI, 0x1234AAAA)
        cpu.SI = 0xAAAA
        self.assertEqual(cpu.SI, 0xAAAA)




    def testFlagAccess(self):
        '''_flags
        'CF': 0x0001,
        'PF': 0x0004,
        'AF': 0x0010,
        'ZF': 0x0040,
        'SF': 0x0080,
        'DF': 0x0400,
        'OF': 0x0800,'''

        cpu = self.cpu
        cpu.RFLAGS = 0
        self.assertFalse(cpu.CF)
        self.assertFalse(cpu.PF)
        self.assertFalse(cpu.AF)
        self.assertFalse(cpu.ZF)
        self.assertFalse(cpu.SF)
        self.assertFalse(cpu.DF)
        self.assertFalse(cpu.OF)

        #flag to register CF
        cpu.CF = True
        self.assertTrue( cpu.RFLAGS&cpu._flags['CF'] !=0)
        cpu.CF = False
        self.assertTrue( cpu.RFLAGS&cpu._flags['CF'] ==0)

        #register to flag CF
        cpu.RFLAGS |= cpu._flags['CF']
        self.assertTrue(cpu.CF)
        cpu.RFLAGS &= ~cpu._flags['CF']
        self.assertFalse(cpu.CF)

        #flag to register PF
        cpu.PF = True
        self.assertTrue( cpu.RFLAGS&cpu._flags['PF'] !=0)
        cpu.PF = False
        self.assertTrue( cpu.RFLAGS&cpu._flags['PF'] ==0)

        #register to flag PF
        cpu.RFLAGS |= cpu._flags['PF']
        self.assertTrue(cpu.PF)
        cpu.RFLAGS &= ~cpu._flags['PF']
        self.assertFalse(cpu.PF)

        #flag to register AF
        cpu.AF = True
        self.assertTrue( cpu.RFLAGS&cpu._flags['AF'] !=0)
        cpu.AF = False
        self.assertTrue( cpu.RFLAGS&cpu._flags['AF'] ==0)

        #register to flag AF
        cpu.RFLAGS |= cpu._flags['AF']
        self.assertTrue(cpu.AF)
        cpu.RFLAGS &= ~cpu._flags['AF']
        self.assertFalse(cpu.AF)

        #flag to register ZF
        cpu.ZF = True
        self.assertTrue( cpu.RFLAGS&cpu._flags['ZF'] !=0)
        cpu.ZF = False
        self.assertTrue( cpu.RFLAGS&cpu._flags['ZF'] ==0)

        #register to flag ZF
        cpu.RFLAGS |= cpu._flags['ZF']
        self.assertTrue(cpu.ZF)
        cpu.RFLAGS &= ~cpu._flags['ZF']
        self.assertFalse(cpu.ZF)

        #flag to register SF
        cpu.SF = True
        self.assertTrue( cpu.RFLAGS&cpu._flags['SF'] !=0)
        cpu.SF = False
        self.assertTrue( cpu.RFLAGS&cpu._flags['SF'] ==0)

        #register to flag SF
        cpu.RFLAGS |= cpu._flags['SF']
        self.assertTrue(cpu.SF)
        cpu.RFLAGS &= ~cpu._flags['SF']
        self.assertFalse(cpu.SF)

        #flag to register DF
        cpu.DF = True
        self.assertTrue( cpu.RFLAGS&cpu._flags['DF'] !=0)
        cpu.DF = False
        self.assertTrue( cpu.RFLAGS&cpu._flags['DF'] ==0)

        #register to flag DF
        cpu.RFLAGS |= cpu._flags['DF']
        self.assertTrue(cpu.DF)
        cpu.RFLAGS &= ~cpu._flags['DF']
        self.assertFalse(cpu.DF)

        #flag to register OF
        cpu.OF = True
        self.assertTrue( cpu.RFLAGS&cpu._flags['OF'] !=0)
        cpu.OF = False
        self.assertTrue( cpu.RFLAGS&cpu._flags['OF'] ==0)

        #register to flag
        cpu.RFLAGS |= cpu._flags['OF']
        self.assertTrue(cpu.OF)
        cpu.RFLAGS &= ~cpu._flags['OF']
        self.assertFalse(cpu.OF)


    def testRegisterAccess(self):
        cpu = self.cpu

        #initially zero
        self.assertEqual(cpu.EAX, 0)

        cpu.EAX += 1
        self.assertEqual(cpu.EAX, 1)
        cpu.EAX = 0x8000000
        self.assertEqual(cpu.EAX, 0x8000000)
        cpu.EAX = 0xff000000
        self.assertEqual(cpu.EAX, 0xff000000)
        cpu.EAX = 0x00ff0000
        self.assertEqual(cpu.EAX, 0x00ff0000)
        cpu.EAX = 0x0000ff00
        self.assertEqual(cpu.EAX, 0x0000ff00)
        cpu.EAX = 0xff
        self.assertEqual(cpu.EAX, 0xff)

        #overflow shall be discarded
        cpu.EAX = 0x100000000
        self.assertEqual(cpu.EAX, 0x00000000)

        #partial register access
        cpu.EAX = 0x11223344
        self.assertEqual(cpu.EAX, 0x11223344)
        self.assertEqual(cpu.AX, 0x3344)
        self.assertEqual(cpu.AH, 0x33)
        self.assertEqual(cpu.AL, 0x44)

        #partial register mod
        cpu.AL=0xDD
        self.assertEqual(cpu.EAX, 0x112233DD)
        self.assertEqual(cpu.AX, 0x33DD)
        self.assertEqual(cpu.AH, 0x33)
        self.assertEqual(cpu.AL, 0xDD)

        cpu.AH=0xCC
        self.assertEqual(cpu.EAX, 0x1122CCDD)
        self.assertEqual(cpu.AX, 0xCCDD)
        self.assertEqual(cpu.AH, 0xCC)
        self.assertEqual(cpu.AL, 0xDD)

        #partial register mod is truncated
        cpu.AL=0x1234DD
        self.assertEqual(cpu.EAX, 0x1122CCDD)
        self.assertEqual(cpu.AX, 0xCCDD)
        self.assertEqual(cpu.AH, 0xCC)
        self.assertEqual(cpu.AL, 0xDD)

        cpu.EDX = 0x8048c50
        self.assertEqual(cpu.EDX, 0x8048c50)


if __name__ == '__main__':
    unittest.main()


