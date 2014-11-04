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

from cpu import Cpu
from memory import SMemory, MemoryException
from linux import SLinux
from smtlibv2 import issymbolic, Symbol, Solver, BitVec, Array, Bool, chr

# logging
logging.basicConfig( filename = "system.log",
#                     filename = "/dev/stdout",
                    format = "%(asctime)s: %(name)s:%(levelname)s: %(message)s",
#                    level = logging.INFO)
                    level = logging.DEBUG)
logger = logging.getLogger("SYSTEM")

# parse arguments
parser = argparse.ArgumentParser(description='Symbolically analize a program')


parser.add_argument('--worspace', type=str, nargs=1, default='pse_',
                   help='A folder name fpor temporaries and results. (default pse_?????)')

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
print "[+] Running", args.program
print "\twith arguments:", args.argv
print "\twith environment:", args.env

# guess architecture from file
from elftools.elf.elffile import ELFFile
arch = {'x86':'i386','x64':'amd64'}[ELFFile(file(args.program)).get_machine_arch()]
bits = {'i386':32, 'amd64':64}[arch]
print "[+] Detected arch:", arch

#Make working directory
folder = tempfile.mkdtemp(prefix=args.worspace, dir='./')

# Make initial state
solver = Solver()
mem = SMemory(solver, bits,12)
linux = SLinux(solver, [Cpu(mem, arch)], mem, symbolic_files=args.sym)

print "Symbolic files: ", args.sym
del solver
del mem

WILDCARD = '+'
input_symbols = []
argv = [ args.program ] # argv[0] not symbolic #fix?
for i in range(len(args.argv)):
    if WILDCARD in args.argv[i]:
        print "Argument %d has symbols"%i
        name = "ARG%d"%i
        size = len(args.argv[i])
        sarg = linux.solver.mkArray(name=name, is_input=True, max_size=size)
        for j in range(size):
            if args.argv[i][j] != WILDCARD:
                sarg[j] = args.argv[i][j]
        input_symbols.append((name, size))
        argv.append([sarg[j] for j in range(size)])
    else:
        argv.append(args.argv[i])


env = [ '%s=%s' % (key, val) for (key,val) in os.environ.items() ]
for i in range(len(args.env)):
    if WILDCARD in args.env[i]:
        print "Environment variable %d has symbols"%i
        name = "ENV%d"%i
        size = len(args.env[i])
        senv = linux.solver.mkArray(name=name, is_input=True, max_size=size)
        for j in range(size):
            if args.env[i][j] != WILDCARD:
                senv[j] = args.env[i][j]
        input_symbols.append((name, size))
        env.append([chr(senv[j]) for j in range(size)])

#pass stdin, stdout, stderr as kw arguments to exe
linux.exe(args.program, argv, env, stdin=args.stdin, stdout=args.stdout, stderr=args.stderr)
del env
del argv

with file(folder+os.sep+'dump_init.pkl','w+') as f:
    pickle.dump(linux,f ,2)

time_start = time.clock()
count = 0
test_case_no = 0
states = ['dump_init.pkl']

def get_state():
    nnstates = {}
    for nn in states:
        nnstates.setdefault(nn.split("_")[1], set()).add(nn)
    nncounts = [ (x, len(nnstates[x])) for x in nnstates.keys()]
    #print '\n'.join(map(str, nncounts))
    nncount_min = min(nncounts, key=lambda(a,b): b)
    l = [x for x in states if nncount_min[0] in x]
    random.shuffle(l)
    st = l.pop()
    states.remove(st)
    return st

def generate_testcase(linux):
    global test_case_no
    test_case_no += 1
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
        file(folder+os.sep+'test_%d.txt'%test_case_no,'a').write("%s: %s\n"%(symbol.name, repr(buf)))
print "Starting..."
try:
    while len(states) !=0:
        #select a suitable state to analize
        current_state = get_state()
        try:
            #load the state
            linux = pickle.load(file(folder+os.sep+current_state,'r'))
            #execute until exception or finnish
            while linux.execute():
                linux.cpu.PC = linux.solver.simplify(linux.cpu.PC)

                #if PC gets "tainted" with symbols do stuff
                if issymbolic(linux.cpu.PC):
                    #get all possible PC destinations (raise if more tahn 100 options)
                    vals = list(linux.solver.getallvalues(linux.cpu.PC, maxcnt = 100))
                    print "Symbolic PC found, possible detinations are: ", ["%x"%x for x in vals]
                    #import pdb
                    #pdb.set_trace()
                    

                    #Shuffle the possibilities, 
                    random.shuffle(vals)
                    #we will keep one state for the current analisys and save 
                    #all the rest to files
                    current_pc = linux.cpu.PC
                    for new_pc in vals[1:]:
                        name = 'dump_%016x_%d.pkl'%(new_pc, linux.cpu.icount)
                        print "\tSaving state %s PC: 0x%x"%(name, new_pc)
                        linux.solver.push()
                        #add the constraint
                        linux.solver.add(current_pc == new_pc)
                        #and set the PC to the concretye destination
                        linux.cpu.PC = new_pc
                        with file(folder+os.sep+name,'w+') as f:
                            pickle.dump(linux, f, 2)
                        linux.solver.pop()
                        #add the state to the list of pending states
                        states.append(name)

                    #keep analizing one of the states already loaded up
                    new_pc = vals[0]

                    name = 'dump_%016x_%d.pkl'%(new_pc, linux.cpu.icount)
                    linux.solver.add(current_pc == new_pc)
                    linux.cpu.PC = new_pc

                    #Try to do some symplifications to shrink symbolic footprint
                    try :
                        bvals = []
                        linux.solver.push()
                        linux.solver.add(linux.cpu.IF == True)
                        if linux.solver.check()=='sat':
                            bvals.append(True)
                        linux.solver.pop()
                        linux.solver.push()
                        linux.solver.add(linux.cpu.IF == False)
                        if linux.solver.check()=='sat':
                            bvals.append(False)
                        linux.solver.pop()
                        if len(bvals) == 1:
                            linux.cpu.IF = bvals[0]
                    except Exception,e:
                        print "EEXXXXX",e,linux.cpu.IF
                        pass
                    linux.cpu.IF = linux.solver.simplify(linux.cpu.IF)
                    linux.cpu.RAX = linux.solver.simplify(linux.cpu.RAX)
                    linux.cpu.RCX = linux.solver.simplify(linux.cpu.RCX)
                    linux.cpu.RSI = linux.solver.simplify(linux.cpu.RSI)
                    linux.cpu.RDI = linux.solver.simplify(linux.cpu.RDI)
                    #save a checkpoint of the current state
                    pickle.dump(linux,file(folder+os.sep+name,'w+'),2)



                    '''
                    if len(vals)>1:
                        name = 'dump_%016x_%d.pkl'%(new_pc, linux.cpu.icount)
                        print "Continuing through pc: 0x%x"%new_pc
                        print "\tsmt size %d"%len(str(linux.solver))
                        print "Generating failsafe dump ... ", name
                        print current_pc == new_pc
                        cons = linux.solver.simplify(current_pc == new_pc)
                        if str(cons).startswith('(= '):
                            print "TRYING REPLACING EQ", cons
                            #for ex. (= (select arg #x00000000) #x2d)
                            left = ' '.join(str(cons)[3:-1].split(' ')[:-1])
                            right = str(cons)[3:-1].split(' ')[-1]
                            if right.startswith("#x"):
                                right = int(right[2:],16)
                                for addr, (val,size) in linux.cpu.mem_cache.items():
                                    if str(val) == left:
                                        print "MOD!!", addr, right, val, size
                                        linux.cpu.mem_cache[addr] = (right,size)

                        linux.solver.add(current_pc == new_pc)
                        linux.cpu.IF = linux.solver.simplify(linux.cpu.IF)
                        pickle.dump(linux,file(name,'w+'),2)

                    else:
                        try :
                            bvals = []
                            linux.solver.push()
                            linux.solver.add(linux.cpu.IF == True)
                            if linux.solver.check()=='sat':
                                bvals.append(True)
                            linux.solver.pop()
                            linux.solver.push()
                            linux.solver.add(linux.cpu.IF == False)
                            if linux.solver.check()=='sat':
                                bvals.append(False)
                            linux.solver.pop()
                            if len(bvals) == 1:
                                linux.cpu.IF = bvals[0]
                        except Exception,e:
                            print "EEXXXXX",e,linux.cpu.IF
                            pass
                        linux.cpu.IF = linux.solver.simplify(linux.cpu.IF)
                        linux.cpu.RCX = linux.solver.simplify(linux.cpu.RCX)
                    '''
                    new_pc=None
                    vals = None

#                print "="*80
#                print "INSTRUCTION: %016x %s"% (linux.cpu.PC, linux.cpu.instruction)
#                print linux.cpu.dumpregs()
                count += 1
        except Exception,e:
            test_case_no+=1
            if e.message == 'Finished':
                print "Program Finnished correctly"
                generate_testcase(linux)
            elif e.message == "Max number of different solutions hit":
                print "Max number of target PCs hit. Checking for wild PC."
                solver = linux.solver
                solver.push()
                try:
                    #Quick heuristics to determine wild pc
                    solver.push()
                    solver.add(linux.cpu.PC == 0x41414141)
                    if solver.check() == 'sat':
                        print "PC seems controled!"
                    solver.pop()
                    m,M = solver.minmax(linux.cpu.PC)
                    print "Program counter range: %016x - %016x" %(m,M)
                    generate_testcase(linux)
                finally:
                    solver.pop()
            else:
                print Exception, e
                generate_testcase(linux)
                print '-'*60
                traceback.print_exc(file=sys.stdout)
                print '-'*60
                import pdb
                pdb.set_trace()

except Exception,e:
    print "Exception in user code:", e
    print '-'*60
    traceback.print_exc(file=sys.stdout)
    print '-'*60
    import pdb
    pdb.set_trace()

print "Results dumped in ", folder
print count, count/(time.clock()-time_start)
