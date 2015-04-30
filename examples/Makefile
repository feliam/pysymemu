CC=gcc
CFLAGS=-m32 -O0

all:toy001-nostdlib  toy002-libc  toy003-sindex  toy004-strcmp  toy005-arguments

clean:
		rm -rf toy001-nostdlib  toy002-libc  toy003-sindex  toy004-strcmp  toy005-arguments

toy001-nostdlib:
		$(CC) -m32 -fno-builtin -static -nostdlib  -fomit-frame-pointer  toy001-nostdlib.c  -o toy001-nostdlib

toy002-libc:
		$(CC) $(CFLAGS) toy002-libc.c -static -o toy002-libc

toy003-sindex:
		$(CC) $(CFLAGS) toy003-sindex.c -o toy003-sindex

toy004-strcmp:
		$(CC) $(CFLAGS) toy004-strcmp.c -o toy004-strcmp

toy005-arguments:
		$(CC) $(CFLAGS) toy005-arguments.c  -o toy005-arguments


