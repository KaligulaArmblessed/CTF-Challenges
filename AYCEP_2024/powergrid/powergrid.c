#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

// gcc powergrid.c -o powergrid -fno-stack-protector

int get_command(void) {
    char command[400];
    
    printf("Enter command >> "); 
    fgets(command, 0x400, stdin); 
    printf("Command successfully received.\n");
    return 0;
}

int get_powergrid_ref(unsigned id) {
    void * function = (void *)get_command;
    uint64_t power_grid_ids[5] = {0x63, 0x61, 0x74, 0x73, 0x21}; 
    if (id > 5) {
        printf("Invalid ID\n"); 
        return -1;
    }
    printf("Reference number: 0x%llx\n", power_grid_ids[id]); 
    return 0; 
} 

// Ignore
void callme() {
  asm volatile ("pop %%rdi\n\t"
      "ret"
      :
      :
      : "rdi");
}

int main(void) {
    unsigned int id = 0;  
    
    // Setup -- ignore this
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    printf("Maverick Inc. Security System Power Control\n"); 
    
    // Get power grid id
    printf("Enter grid id >> "); 
    if ((scanf("%d", &id)) != 1) {
        printf("Reference retrieval failed.\n"); 
        return -1; 
    } else {
        get_powergrid_ref(id); 
    }
    
    // Ignore
    int c;
    while ((c = getchar()) != '\n' && c != EOF) { }
    
    // Process command
    get_command(); 
    
    return 0; 
}
