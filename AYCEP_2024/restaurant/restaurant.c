#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 

// gcc restaurant.c -fno-stack-protector -o restaurant

int menu(char * food) {
    FILE * fd = 0;
    char line[0x50] = {0};
    if (strncmp("honhonbaguette", food, 14) == 0) {
        fd = fopen("./flag.txt", "r"); 
        fgets(line, sizeof(line), fd); 
        printf("Oh no! Here's a flag instead of lunch: \n"); 
        printf("%s\n", line); 
        fclose(fd); 
        return 0; 
    }
    printf("Just a standard lunch for you!\n"); 
    return 0; 
}

int main(void) {
    char lunch[0x10] = {0}; 
    char buf[0x20] = {0};
    char choice[150] = {0}; 
    
    // Setup -- ignore this
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    strncpy(lunch, "escargot", 8); // I really like escargots!
    
    printf("Welcome to the ROP LLC. Cyber Cafe\n"); 
    printf("What would you like for lunch? >> "); 
    fgets(choice, sizeof(choice), stdin); 
    strcpy(buf, choice); 
    
    menu(lunch); 
    return 0; 
}
