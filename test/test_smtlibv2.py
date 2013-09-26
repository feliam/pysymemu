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

from smtlibv2 import *
import unittest
import fcntl
import resource
import gc
import sys
#logging.basicConfig(filename = "test.log",
#                format = "%(asctime)s: %(name)s:%(levelname)s: %(message)s",
#                level = logging.DEBUG)

class ExpressionTest(unittest.TestCase):
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
        self.assertEqual(self.fds, self.get_open_fds())

    def checkLeak(self, s):
        import gc, pickle
        s_str = pickle.dumps(s)
        del s
        s1 = pickle.loads(s_str)
        s2 = pickle.loads(s_str)
        del s1
        del s2
        gc.collect()
        self.assertEqual(gc.garbage, [])

    '''
    def testBasicAST(self):
        a = Symbol(1)
        b = Symbol(2)
        c = Symbol('+', a, b)
        self.assertTrue(a.isleaf)
        self.assertTrue(b.isleaf)
        self.assertFalse(c.isleaf)
        self.assertEqual(c.children, (a,b))
    '''

    def testSolver(self):
        s = Solver()
        a = s.mkBitVec(32)
        b = s.mkBitVec(32)
        s.add(a+b>100)
        self.assertEqual(s.check(), 'sat')
        self.checkLeak(s)

    def testBool(self):
        s = Solver()
        bf = Bool('false')
        bt = Bool('true')
        s.add( bf & bt )
        self.assertEqual(s.check(), 'unsat')
        self.checkLeak(s)

    def testBasicArray(self):
        s = Solver()
        #make array of 32->8 bits
        array = s.mkArray(32)
        #make free 32bit bitvector 
        key = s.mkBitVec(32)

        #assert that the array is 'A' at key position
        s.add(array[key] == 'A')
        #lets restrict key to be greater than 1000
        s.add(key.ugt(1000))

        s.push()
        #1001 position of array can be 'A'
        s.add(array[1001] == 'A')
        self.assertEqual(s.check(), 'sat')
        s.pop()

        s.push()
        #1001 position of array can also be 'B'
        s.add(array[1001] == 'B')
        self.assertEqual(s.check(), 'sat')
        s.pop()

        s.push()
        #but if it is 'B' ...
        s.add(array[1001] == 'B')
        #then key can not be 1001
        s.add(key == 1001)
        self.assertEqual(s.check(), 'unsat')
        s.pop()

        s.push()
        #If 1001 position is 'B' ...
        s.add(array[1001] == 'B')
        #then key can be 1000 for ex..
        s.add(key == 1002)
        self.assertEqual(s.check(), 'sat')
        s.pop()
        #self.checkLeak(s)


    def testBasicArrayStore(self):
        s = Solver()
        #make array of 32->8 bits
        array = s.mkArray(32)
        #make free 32bit bitvector 
        key = s.mkBitVec(32)

        #assert that the array is 'A' at key position
        array[key] = 'A'
        #lets restrict key to be greater than 1000
        s.add(key.ugt(1000))
        s.push()
        #1001 position of array can be 'A'
        s.add(array[1001] == 'A')
        self.assertEqual(s.check(), 'sat')
        s.pop()

        s.push()
        #1001 position of array can also be 'B'
        s.add(array[1001] == 'B')
        self.assertEqual(s.check(), 'sat')
        s.pop()

        s.push()
        #but if it is 'B' ...
        s.add(array[1001] == 'B')
        #then key can not be 1001
        s.add(key == 1001)
        self.assertEqual(s.check(), 'unsat')
        s.pop()

        s.push()
        #If 1001 position is 'B' ...
        s.add(array[1001] == 'B')
        #then key can be 1000 for ex..
        s.add(key != 1002)
        self.assertEqual(s.check(), 'sat')
        s.pop()
        self.checkLeak(s)


    def testBasicPickle(self):
        import pickle
        s = Solver()
        #make array of 32->8 bits
        array = s.mkArray(32)
        #make free 32bit bitvector 
        key = s.mkBitVec(32)

        #assert that the array is 'A' at key position
        array[key] = 'A'
        #lets restrict key to be greater than 1000
        s.add(key.ugt(1000))
        s = pickle.loads(pickle.dumps(s))
        self.assertEqual(s.check(), 'sat')
        self.checkLeak(s)

    def testBitvector_add(self):
        s = Solver()
        a = s.mkBitVec(32)
        b = s.mkBitVec(32)
        c = s.mkBitVec(32)
        s.add(c==a+b)
        s.add(a == 1)
        s.add(b == 10)
        self.assertEqual(s.check(), 'sat')
        self.assertEqual(s.getvalue(c), 11)
        self.checkLeak(s)

    def testBitvector_add1(self):
        s = Solver()
        a = s.mkBitVec(32)
        b = s.mkBitVec(32)
        c = s.mkBitVec(32)
        s.add(c==a+10)
        s.add(a == 1)
        self.assertEqual(s.check(), 'sat')
        self.assertEqual(s.getvalue(c), 11)
        self.checkLeak(s)

    def testBitvector_add2(self):
        s = Solver()
        a = s.mkBitVec(32)
        b = s.mkBitVec(32)
        c = s.mkBitVec(32)
        s.add(11==a+10)
        self.assertEqual(s.check(), 'sat')
        self.assertEqual(s.getvalue(a), 1)
        self.checkLeak(s)

if __name__ == '__main__':
    unittest.main()

