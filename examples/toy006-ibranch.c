/* Minimal toy example with input output
 *
 * The symbolic input is taken from command line argumets passed to the interpreted program
 * Will use the argv input to select a pointer from a lit and call it.
 *
 * Compile with :
 *   $ gcc toy006-ibranch.c  -o toy005-ibranch
 *
 * Analize it with:
 *   $ python system.py example/toy005-arguments +
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void f(){
    printf("Function f\n");
}
void g(){
    printf("Function g\n");
}


int main(int argc, char* argv[], char* envp[]){
    int i;
    void (*funcs[2])( );

    funcs[0] = f;
    funcs[1] = g;


    funcs[argv[1][0] == 'A']();


return 0;
}


