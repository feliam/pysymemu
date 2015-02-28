/* Minimal toy example with input from argv
 *
 * The "special" character '+' marks symbolic bytes on the argyuments to the program.
 *
 * Compile with :
 *   $ gcc toy005-arguments.c  -o toy005-arguments
 *
 * Analize it with:
 *   $ python system.py example/toy005-arguments ++++++++++
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


