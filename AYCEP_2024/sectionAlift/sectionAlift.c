#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

// gcc sectionAlift.c -fno-stack-protector -no-pie -o sectionAlift -static

int main(void) {
    char command[200];
    
    // Setup -- ignore this
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    memset(command, 0x0, sizeof(command)); 
    
    printf("Maverick Inc. Section A Lift Control\n"); 
    printf("Enter command >> "); 
    
    fgets(command, 0x200, stdin); 
    
    printf("Command has been sent to the server.\n");
    
    return 0; 
}
