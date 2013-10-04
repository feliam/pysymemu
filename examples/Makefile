all: toy001-nostdlib  toy002-libc  toy003-sindex  toy004-strcmp  toy005-arguments

clean:
		rm -rf toy001-nostdlib toy002-libc

toy001-nostdlib:
		gcc -fno-builtin -static -nostdlib -m32  -fomit-frame-pointer  toy001-nostdlib.c  -o toy001-nostdlib

toy002-libc:
		gcc toy002-libc.c -static -o toy002-libc

toy003-sindex:
		gcc toy003-sindex.c -o toy003-sindex

toy004-strcmp:
		gcc toy004-strcmp.c -o toy004-strcmp

toy005-arguments:
		gcc toy005-arguments.c  -o toy005-arguments


