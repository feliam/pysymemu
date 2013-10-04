/*
    Minimal toy example with input output
    Compile with :
    $ gcc toy005-arguments.c  -o toy005-arguments
    Analize it with:
    python system.py -sym stdin example/toy005-arguments
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char* argv[], char* envp[]){
    int i;
    
    printf("Got %d arguments.\n", argc);
    if(argc > 1)
        if (!strcmp(argv[1], "--dostuff"))
            printf ("Do stuf!\n");
        
    
return 0;
}


