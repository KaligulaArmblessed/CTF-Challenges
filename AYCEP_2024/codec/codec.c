#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/time.h> 
#include <time.h>
#include <stdint.h> 
#include <stddef.h>

void rand_str(char *dest, size_t length) {
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}

void rot13(char str[]) {
   int case_type, idx, len;

   for (idx = 0, len = strlen(str); idx < len; idx++) {
      // Only process alphabetic characters.
      if (str[idx] < 'A' || (str[idx] > 'Z' && str[idx] < 'a') || str[idx] > 'z')
         continue;
      // Determine if the char is upper or lower case.
      if (str[idx] >= 'a')
         case_type = 'a';
      else
         case_type = 'A';
      // Rotate the char's value, ensuring it doesn't accidentally "fall off" the end.
      str[idx] = (str[idx] + 13) % (case_type + 26);
      if (str[idx] < 26)
         str[idx] += case_type;
   }
}

int main(void) {
    char buf[0x200]; 
    char rand[0x30]; 
    uint64_t diff = 0;  
    struct timeval stop, start; 
    
    srand((unsigned int)(time(NULL)));
    
    memset(buf, 0x0, sizeof(buf)); 
    memset(rand, 0x0, sizeof(rand));
    
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    printf("Welcome to the ROP LLC. covert communications channel\n"); 
    printf("Messages passing through this channel have to be sent and received very quickly.\n"); 
    printf("Are you ready? >> "); 
    fgets(buf, 0x200-1, stdin);
    if (strncmp("Yes", buf, 3) != 0) {
        printf("Fail!\n");
        return -1; 
    }
    
    memset(buf, 0x0, sizeof(buf)); 
    printf("Trial 1: Repeat this random string to me\n"); 
    rand_str(rand, 0x20); 
    printf("%s\n", rand); 
    printf(">> "); 
    gettimeofday(&start, NULL);
    fgets(buf, 0x200-1, stdin); 
    gettimeofday(&stop, NULL);
    diff = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;  
    if (diff > 800000) {
        printf("Too slow!\n"); 
        return -1; 
    }
    if (strncmp(rand, buf, 0x20) != 0) {
        printf("Fail!\n"); 
        return -1; 
    }
    printf("Trial 1 passed.\n"); 
    
    
    memset(buf, 0x0, sizeof(buf)); 
    memset(rand, 0x0, sizeof(rand)); 
    printf("Trial 2: Turn this string to uppercase\n"); 
    rand_str(rand, 0x20); 
    printf("%s\n", rand); 
    printf(">> "); 
    gettimeofday(&start, NULL);
    fgets(buf, 0x200-1, stdin); 
    gettimeofday(&stop, NULL);
    diff = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;  
    if (diff > 800000) {
        printf("Too slow!\n"); 
        return -1; 
    }
    int i = 0; 
    for (i = 0; rand[i]!='\0'; i++) {
        if(rand[i] >= 'a' && rand[i] <= 'z') {
            rand[i] = rand[i] - 32;
        }
    }
    if (strncmp(rand, buf, 0x20) != 0) {
        printf("Fail!\n"); 
        return -1; 
    }
    printf("Trial 2 passed.\n"); 
    
    memset(buf, 0x0, sizeof(buf)); 
    memset(rand, 0x0, sizeof(rand)); 
    printf("Trial 3: Encode this string with rot13\n"); 
    rand_str(rand, 0x20); 
    printf("%s\n", rand); 
    printf(">> "); 
    gettimeofday(&start, NULL);
    fgets(buf, 0x200-1, stdin); 
    gettimeofday(&stop, NULL);
    diff = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;  
    if (diff > 800000) {
        printf("Too slow!\n"); 
        return -1; 
    }
    rot13(rand);
    if (strncmp(rand, buf, 0x20) != 0) {
        printf("Fail!\n"); 
        return -1; 
    }
    printf("Trial 3 passed.\n"); 
    
    char lol[] = "If ya wanna win, ya gotta want it!";
    memset(buf, 0x0, sizeof(buf)); 
    printf("Final trial: What attitude should you have as a ROP LLC. operative?\n"); 
    printf(">> "); 
    gettimeofday(&start, NULL);
    fgets(buf, 0x200-1, stdin); 
    gettimeofday(&stop, NULL);
    diff = (stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec;  
    if (diff > 800000) {
        printf("Too slow!\n"); 
        return -1; 
    }
    if (strncmp(lol, buf, strlen(lol) != 0)) {
        printf("Fail!\n"); 
        return -1;
    } else {
        FILE * fd = 0; 
        char line[0x50] = {0}; 
        fd = fopen("./flag.txt", "r"); 
        fgets(line, sizeof(line), fd); 
        printf("Congratulations! Here's your flag: \n"); 
        printf("%s\n", line); 
        fclose(fd);
        return 0; 
    }
    
    return 0; 
}
