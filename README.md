PySymEmu
========

A symbolic execution tool, capable of automatically generating interesting inputs for x86/x64 binary programs.

Ekoparty slides: https://github.com/feliam/pysymemu/blob/master/doc/pysymemu.pdf?raw=true

API documentation: http://feliam.github.io/pysymemu/

Features:
---------
* Implements most x86/amd64 instructions
* Loads ELF32 and ELF64 files
* Enables to recreate specific machine states by API
* Instruction semantics *easy* to read and extend
* Instruction set can operate in concrete or symbolic values
* Memory modeled so it can be concrete or symbolic (and is COW-enabled)
* Handles operations on symbolic pointers and indexes 
* Emulation and symbolic states serialiable, meaning that the analisys can be paused/resumed or paralellized(dispy.sourceforge.net)
* POSIX system calls modeled (Linux32 and Linux64)
* Automatic generation of instruction testcases
* API and instruction documentation
* Automatic generation of intruction unittests
* Multiple SMT solvers supported through pysmtlib (Z3, YICES, CVC4)

Dependencies:
-------------
* Capstone-engine decoder/disassembler. http://www.capstone-engine.org
* z3, an smt solver. http://z3.codeplex.com/ (1)
* pyelftool, an ELF parsing library. https://github.com/eliben/pyelftools

Quick install of deps?
```
  
  echo Installing Capstone engine
  sudo pip install capstone
  
  echo Installing pyelftools
  sudo pip install pyelftools
  
  #Install z3 SMT solver 
  echo Go to http://z3.codeplex.com/SourceControl/latest# click Download to download z3 source code
  echo Make a folder. Unzip z3 inside that folder. dos2unix on configure. Then configure;make
```

Directory structure
-------------------
```
 doc/                    Slides and papers
 examples/               Asorted set of small C examples to emulate
 tutorial/               Very simple test cases
 test/                   Unittests
 setup.py                Setuputils/pipy related (not used yet)
 linux.py                The Linux operating system micro model
 memory.py               The symbolic memory model
 smtlibv2.py             Smtlib v2 solver API 
 system.py               A quick command line tool
```

Tests
-----
You may use the discover command.

``` $ python -m unittest discover test```

Note that cpu.py testcases are generated semi-automatically using tools at test/auto

API Documentation
-----------------
You may generate a fair amount of API doc using epydoc. epydoc.sourceforge.net/‎
The following command will generate an html/ folder with the api documentation:

``` $ epydoc  cpu.py memory.py linux.py smtlibv2.py system.py ```

Running it
----------
THIS IS APLHA SOFT. 
But you may play directly on binary ELF files until you hit an unimplemented instruction or systemcall(2).
The commandline gives you a somehow confusing help. :)
```
 $ python system.py --help
 usage: system.py [-h] [--worspace WORSPACE] [--sym SYM] [--stdin STDIN]
                 [--stdout STDOUT] [--stderr STDERR] [--env ENV]
                 PROGRAM ...

 Symbolically analize a program

 positional arguments:
   PROGRAM              Program to analize
   ...                  Program arguments. Need a -- separator. Ex: -- -y 2453
 
 optional arguments:
   -h, --help           show this help message and exit
   --worspace WORSPACE  A folder name fpor temporaries and results. (default pse_?????)
   --sym SYM            Consider a filename as symbolic
   --stdin STDIN        A filename to pass as standar stdin (default: stdin)
   --stdout STDOUT      A filename to pass as standar stdout (default: stdout)
   --stderr STDERR      A filename to pass as standar stderr (default: stderr)
   --env ENV            A environment variable to pass to the program (ex. VAR=VALUE)
```

Basicaly you pass a binary file for pysymemu to emulate. Let's try the toy examples:

```
 $ cd examples
 $ cat toy002-libc.c
```

```C
int main()
{
    unsigned int cmd;
    
    if (read(0, &cmd, sizeof(cmd)) != sizeof(cmd))
    {
        printf("Error reading stdin!");
        exit(-1);
    }
    
    if (cmd > 0x41)
    {
        printf("Message: It is greater than 0x41\n");
    }
    else 
    {
        printf("Message: It is smaller or equal than 0x41\n");
    }

return 0;
}
```


```
 $ make
 gcc -fno-builtin -static -nostdlib -m32  -fomit-frame-pointer  toy001-nostdlib.c  -o toy001-nostdlib
 gcc toy002-libc.c -static -o toy002-libc
 $ cd -
```

Now run it under the emulator like this. First create 3 dummy files to replace the virtual/emulated stdin, stdout and stderr

```
 $ touch stderr
 $ touch stdout
 $ echo ++++++++++ > stdin
```

We'll be considering that the stdin is filled by symbolic data ( marked with '+' (yes, I know)). Also we need to tell 
pysymemu which part of the environment should be considered symbolic and which concret. We mark the 'stdin' file as 
symbolic (its '+' will be free 8bit variables) with --sym 'stdin', like this:

``` $ python system.py --sym stdin examples/toy002-libc```

The quick and dirty command line tool will generate somthing like this..
```
 $ python system.py  --sym stdin examples/toy002-libc
 [+] Running examples/toy002-libc
 	with arguments: []
 	with environment: []
 [+] Detected arch: amd64
 starting
 Symbolic PC found, possible detinations are:  ['4005ab', '40059d']
 	Saving state dump_00000000004005ab_8452.pkl PC: 0x4005ab
 Program Finnished correctly
 stdin:  '\xc1\x00\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\n'
 Program Finnished correctly
 stdin:  ' \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n'
 Results dumped in  ./pse_xYhZwA
 10392 3038.59649123
```

And an insanelly verbose system.log file.
Also a folder with all intermediate states and results ...

```
$ ls ./pse_xYhZwA
dump_000000000040059d_8452.pkl  dump_00000000004005ab_8452.pkl  dump_init.pkl  test_2.txt  test_4.txt
```

```
 $ tail -n 12341 ./pse_xYhZwA/test*
 ==> ./pse_xYhZwA/test_2.txt <==
 stdin: '\xc1\x00\x80\x80\x80\x80\x80\x80'
 
 ==> ./pse_xYhZwA/test_4.txt <==
 stdin: '\x20\x00\x00\x00\x00\x00\x00\x00'
```

1. With a few mods it may accept any smtlibv2 solver that can handle (get-value) command.
2. In such case you should go to cpu.py or linux.py and add the necesarry code!
