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

import sys
import time
import os
import tempfile
import copy
import pickle
import random
import logging
import traceback
import argparse

from cpu import Cpu, SymbolicLoopException, SymbolicPCException
from memory import SMemory, MemoryException
from linux import SLinux, SymbolicFile, File, ProcessExit
from smtlib import issymbolic, Symbol, Solver, BitVec, Array, Bool, chr


class State(object):

    @property
    def solver(self):
        return self.os.solver
    @property
    def cpu(self):
        return self.os.cpu

    def execute(self):
        self.trace.append(self.os.cpu.PC)
        return self.os.execute()

    def makeSymbolic(self, data, name = '', WILDCARD='+'):
        if WILDCARD in data:
            size = len(data)
            symb = self.solver.mkArray(name=name, is_input=True, max_size=size)
            for j in xrange(size):
                if data[j] != WILDCARD:
                    symb[j] = data[j]
            return [chr(symb[i]) for i in range(size)]
        else:
            return data

    def __init__(self, program, arguments, environment={}, symbolic=[]):
        # guess architecture from file
        from elftools.elf.elffile import ELFFile
        arch = {'x86':'i386','x64':'amd64'}[ELFFile(file(args.program)).get_machine_arch()]
        bits = {'i386':32, 'amd64':64}[arch]
        self.trace = []
        logger.info("Loading %s ELF program %s", arch, program)
        logger.info("Arguments: %s", arguments)
        logger.info("Environment: %s", environment)

        solver = Solver()
        mem = SMemory(solver, bits, 12)
        cpu0 = Cpu(mem, arch)
        os = SLinux(solver, [cpu0], mem)

        self.os=os


        environment = [ '%s=%s' % (key, val) for (key,val) in environment.items() ]
        arguments = [program] + [ self.makeSymbolic(arguments[i], 'ARGV%02d'%i) for i in xrange(0, len(arguments)) ]
        environment = [ self.makeSymbolic(environment[i], 'ENV%02d'%i) for i in xrange(0, len(environment)) ]

        #pass arguments to exe
        os.exe(program, arguments, environment)

        #FIXME: Find a way to set symbolic files from command line
        # open standard files stdin, stdout, stderr
        assert os._open(SymbolicFile(solver, 'stdin','rb')) == 0
        assert os._open(File('stdout','wb')) == 1
        assert os._open(File('stderr','wb')) == 2

        self.trace = []

    def branch(self):
        return copy.deepcopy(self)
        #return pickle.loads(pickle.dumps(state,  2))

    @property
    def name(self):
        return 'state_%016x_%d.pkl'%(self.cpu.PC, self.cpu.icount)

class Executor(object):
    def __init__(self, workspace=None, **options):
        #Make working directory
        self.workspace = tempfile.mkdtemp(prefix=workspace, dir='./')
        self.states = []
        self.test_number = 0

    def _getFilename(self, filename):
        return os.path.join(self.workspace, filename)

    def delState(self, state):
        if state in self.states:
            self.states.remove(state)

    def putState(self, state, policy='RANDOM'):
        name = state.name
        print "\tSaving state %s"%name
        with file(self._getFilename(name),'w+') as f:
            pickle.dump(state, f, 2)

        #TODO pickle dump on file
        self.states.append(state.name)

    def getState(self, policy='RANDOM'):
        #TODO pickle load from file
        if not self.states:
            return None
        nnstates = {}
        for nn in self.states:
            nnstates.setdefault(nn.split("_")[1], set()).add(nn)
        nncounts = [ (x, len(nnstates[x])) for x in nnstates.keys()]
        #print '\n'.join(map(str, nncounts))
        nncount_min = min(nncounts, key=lambda(a,b): b)
        l = [x for x in self.states if nncount_min[0] in x]
        random.shuffle(l)
        st = l.pop()
        self.states.remove(st)
        print "\t Loading state ",  st
        with file(self._getFilename(st),'rb') as f:
            st = pickle.load(f)
        return st

    def generate_testcase(self, linux):
        self.test_number+= 1
        solver = linux.solver
        assert solver.check() == 'sat'
        for symbol,size in solver.input_symbols:
            if isinstance(symbol, Array):
                buf = ''
                for i in range(size):
                    buf += chr(solver.getvalue(symbol[i]))
                print "%s: "%symbol.name, repr(buf)
            else:
                print symbol, type(symbol)
                raise NotImplemented
            file(self._getFilename('test_%d.txt'%self.test_number),'a').write("%s: %s\n"%(symbol.name, repr(buf)))








def parse_arguments():
    ################################################################################
    # parse arguments
    parser = argparse.ArgumentParser(description='Symbolically analize a program')
    parser.add_argument('--workspace', type=str, nargs=1, default='pse_',
                       help='A folder name fpor temporaries and results. (default pse_?????)')
    parser.add_argument('--log', type=str, nargs=1, default=['/dev/stdout'],
                       help='The log filename')
    parser.add_argument('--verbose', action="store_true", help='Enable debug mode.')
    parser.add_argument('--sym', type=str, action='append', default=[],
                       help='Consider a filename as symbolic')
    parser.add_argument('--stdin', type=str, nargs=1, default='stdin',
                       help='A filename to pass as standar stdin (default: stdin)')
    parser.add_argument('--stdout', type=str, nargs=1, default='stdout',
                       help='A filename to pass as standar stdout (default: stdout)')
    parser.add_argument('--stderr', type=str, nargs=1, default='stderr',
                       help='A filename to pass as standar stderr (default: stderr)')
    parser.add_argument('--env', type=str,  action='append', default =[],
                       help='A environment variable to pass to the program (ex. VAR=VALUE)')
    parser.add_argument('program', type=str, metavar='PROGRAM',
                       help='Program to analize' )
    parser.add_argument('argv', type=str, nargs='...', metavar='...',
                       help='Program arguments. Need a -- separator. Ex: -- -y 2453' )
    raw_args = sys.argv[1:]
    prg_args = []

    if '--' in raw_args:
        prg_args = raw_args[raw_args.index('--')+1:]
        raw_args = raw_args[:raw_args.index('--')]

    args = parser.parse_args(raw_args)
    args.argv += prg_args

    return args



if __name__ == '__main__':
    args = parse_arguments()
    ################################################################################
    # logging
    logging.basicConfig(filename = args.log[0],
                        format = "%(asctime)s: %(name)s:%(levelname)s: %(message)s",
                        level = {False:logging.INFO, True:logging.DEBUG}[args.verbose])

    verbosity = {False:logging.INFO, True:logging.DEBUG}[args.verbose]
    logging.getLogger("EXECUTOR").setLevel(verbosity)
    logging.getLogger("CPU").setLevel(verbosity)
    logging.getLogger("SOLVER").setLevel(verbosity)
    logging.getLogger("MEM").setLevel(verbosity)

    logger = logging.getLogger("EXECUTOR")

    print "[+] Running", args.program
    print "\twith arguments:", args.argv
    print "\twith environment:", args.env

    env = os.environ
    env.update([ e.split('=') for e in args.env])

    state = State(args.program, args.argv, env )

    time_start = time.clock()
    count = 0
    test_case_no = 0

    executor = Executor(workspace=args.workspace)
    executor.putState(state)

    current_state = None
    print "Starting..."
    try:
        while len(executor.states) != 0:
            #select a suitable state to analize
            if current_state is None:
                current_state = executor.getState()

            try:
                #execute until exception or finnish
                while current_state.execute():
                   count += 1
            except SymbolicLoopException, e:
                counter = current_state.cpu.getRegister(e.reg_name)
                cmin, cmax = current_state.solver.minmax(counter)

                vals = list(set([cmin, cmax, (cmax-cmin)/2]))

                #Shuffle the possibilities, 
                random.shuffle(vals)
                #we will keep one state for the current analisys and save 
                #all the rest to files
                for new_counter in vals[1:]:
                    new_state = current_state.branch()
                    #add the constraint
                    new_state.solver.add(counter == new_counter)
                    #and set the PC of the new state to the concrete pc-dest
                    new_state.cpu.setRegister(e.reg_name, new_counter )
                    #add the state to the list of pending states
                    executor.putState(new_state)

                #keep analizing one of the states already loaded up
                new_counter = vals[0]

                current_state.solver.add(counter == new_counter)
                new_state.cpu.setRegister(e.reg_name, new_counter)


            except SymbolicPCException, e:
                #if PC gets "tainted" with symbols do stuff
                assert issymbolic(current_state.cpu.PC)
                #get all possible PC destinations (raise if more tahn 100 options)
                vals = list(current_state.solver.getallvalues(current_state.cpu.PC, maxcnt = 100))
                print "Symbolic PC found, possible detinations are: ", ["%x"%x for x in vals]

                #Shuffle the possibilities, 
                random.shuffle(vals)
                #we will keep one state for the current analisys and save 
                #all the rest to files
                current_pc = current_state.cpu.PC
                for new_pc in vals[1:]:
                    new_state = current_state.branch()
                    #add the constraint
                    new_state.solver.add(new_state.cpu.PC == new_pc)
                    #and set the PC of the new state to the concrete pc-dest
                    new_state.cpu.PC = new_pc
                    #add the state to the list of pending states
                    executor.putState(new_state)

                #keep analizing one of the states already loaded up
                new_pc = vals[0]

                current_state.solver.add(current_pc == new_pc)
                current_state.cpu.PC = new_pc

                #Try to do some symplifications to shrink symbolic footprint
                try :
                    bvals = []
                    current_state.solver.push()
                    current_state.solver.add(current_state.cpu.IF == True)
                    if current_state.solver.check()=='sat':
                        bvals.append(True)
                    current_state.solver.pop()
                    current_state.solver.push()
                    current_state.solver.add(current_state.cpu.IF == False)
                    if current_state.solver.check()=='sat':
                        bvals.append(False)
                    current_state.solver.pop()
                    if len(bvals) == 1:
                        current_state.cpu.IF = bvals[0]
                except Exception,e:
                    print "EEXXXXX",e,current_state.cpu.IF
                    pass
                current_state.cpu.IF = current_state.solver.simplify(current_state.cpu.IF)
                current_state.cpu.RAX = current_state.solver.simplify(current_state.cpu.RAX)
                current_state.cpu.RCX = current_state.solver.simplify(current_state.cpu.RCX)
                current_state.cpu.RSI = current_state.solver.simplify(current_state.cpu.RSI)
                current_state.cpu.RDI = current_state.solver.simplify(current_state.cpu.RDI)
                #save a checkpoint of the current state
                #pickle.dump(linux,file(folder+os.sep+name,'w+'),2)


                new_pc=None
                vals = None

            except ProcessExit, e:
                test_case_no+=1
                print "Program Finnished correctly"
                executor.generate_testcase(current_state)
                current_state = None

            except Exception,e:
                test_case_no+=1
                if e.message == "Max number of different solutions hit":
                    print "Max number of target PCs hit. Checking for wild PC."
                    solver = current_state.solver
                    solver.push()
                    try:
                        #Quick heuristics to determine wild pc
                        solver.push()
                        solver.add(current_state.cpu.PC == 0x41414141)
                        if solver.check() == 'sat':
                            print "PC seems controled!"
                        solver.pop()
                        m,M = solver.minmax(linux.cpu.PC)
                        print "Program counter range: %016x - %016x" %(m,M)
                        executor.generate_testcase(linux)
                    finally:
                        solver.pop()
                else:
                    print Exception, e
                    executor.generate_testcase(current_state)
                    print '-'*60
                    traceback.print_exc(file=sys.stdout)
                    print '-'*60
                    import pdb
                    pdb.set_trace()
                current_state = None

    except Exception,e:
        print "Exception in user code:", e
        print '-'*60
        traceback.print_exc(file=sys.stdout)
        print '-'*60
        import pdb
        pdb.set_trace()

    print "Results dumped in ", executor.workspace
    print count, count/(time.clock()-time_start)

