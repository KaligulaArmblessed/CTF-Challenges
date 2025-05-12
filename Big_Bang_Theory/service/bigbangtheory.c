#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/delay.h>

#define IOC_MAGIC '\xca'

#define ROSES_ARE_RED_WIRES_ARE_TOO  _IOWR(IOC_MAGIC, 0, struct req) // DO_CREATE
#define BOOMERS_BEWARE               _IOWR(IOC_MAGIC, 1, struct req) // DO_READ
#define SNIP_HAPPENS                 _IOWR(IOC_MAGIC, 2, struct req) // DO_DELETE 
#define JAMES_BOMB                   _IOWR(IOC_MAGIC, 3, struct req) // DO_SECRET
#define THIS_IS_FINE                 _IOWR(IOC_MAGIC, 4, struct req) // DO_CHANGESIZE
#define BOMB_VOYAGE                  _IOWR(IOC_MAGIC, 5, struct req) // DO_WRITE

struct mutex mod_mutex;

struct req {
    uint64_t idx;
    uint64_t size; 
    uint64_t addr;
    uint64_t signature; 
};

struct cutting_edge_technology {
    uint64_t signature; 
    uint64_t size;
    uint64_t secret; 
    char owner[0x28]; 
}; // kmalloc-64 

// Tech stuff
#define TECH_MAX 0x400
void * tech_array[TECH_MAX] = {0};
unsigned int tech_count = 0;

// Secret stuff
#define SECRET_MAX 10 
#define SECRET_SIZE 32 
unsigned int secret_idx = 0; 
char secret0[SECRET_SIZE]; 
char secret1[SECRET_SIZE]; 
char secret2[SECRET_SIZE];
char secret3[SECRET_SIZE];
char secret4[SECRET_SIZE];
char secret5[SECRET_SIZE];
char secret6[SECRET_SIZE];
char secret7[SECRET_SIZE];
char secret8[SECRET_SIZE];
char secret9[SECRET_SIZE];
char secret10[SECRET_SIZE];
char * secret_array[SECRET_MAX+1] = {secret0, secret1, secret2, secret3, secret4, secret5, secret6, secret7, secret8, secret9, secret10};

static int initialize_secret(void) {
    char str0[] = "####5TANDing here I realize\x00"; 
    char str1[] = "####The elements\x00"; 
    char str2[] = "####can be my guide\x00"; 
    char str3[] = "####My atomic weight\x00";
    char str4[] = "####Is twice my number\x00";
    char str5[] = "####Bonded with 6 hydrogens\x00"; 
    char str6[] = "####We form a hexagon\x00"; 
    char str7[] = "####My number is\x00";
    char str8[] = "####the secret key\x00";
    char str9[] = "####To stopping this bomb\x00";
    char str10[] = "####From combusting you see\x00"; 
    
    memset(secret0, 0x23, sizeof(secret0)); 
    memset(secret1, 0x23, sizeof(secret1)); 
    memset(secret2, 0x23, sizeof(secret2)); 
    memset(secret3, 0x23, sizeof(secret3)); 
    memset(secret4, 0x23, sizeof(secret4)); 
    memset(secret5, 0x23, sizeof(secret5)); 
    memset(secret6, 0x23, sizeof(secret6)); 
    memset(secret7, 0x23, sizeof(secret7)); 
    memset(secret8, 0x23, sizeof(secret8)); 
    memset(secret9, 0x23, sizeof(secret9)); 
    memset(secret10, 0x23, sizeof(secret10)); 
    
    strncpy(secret0, str0, strlen(str0)); 
    strncpy(secret1, str1, strlen(str1)); 
    strncpy(secret2, str2, strlen(str2));
    strncpy(secret3, str3, strlen(str3));
    strncpy(secret4, str4, strlen(str4));
    strncpy(secret5, str5, strlen(str5));
    strncpy(secret6, str6, strlen(str6));
    strncpy(secret7, str7, strlen(str7));
    strncpy(secret8, str8, strlen(str8));
    strncpy(secret9, str9, strlen(str9));
    strncpy(secret10, str10, strlen(str10));
    
    return 0; 
}

// Module stuff
static int open_module(struct inode *inode, struct file *filp);
static long ioctl_module(struct file *filp, unsigned int cmd, unsigned long arg);

static struct file_operations fops = {
	open : open_module,
	unlocked_ioctl : ioctl_module
};

static struct miscdevice bigbangtheory = {
    .minor      = 53,
    .name       = "bigbangtheory",
    .fops       = &fops,
    .mode	    = 0666,
};

static int open_module(struct inode *inode, struct file *filp) {
	return 0;
}

static long ioctl_module(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct req user_data; 
    struct cutting_edge_technology * tech = NULL; 
    uint64_t tech_size = 0; 
    void * secret = 0; 
    char buf[1024] = {0}; 
    int ret = 0;
    
    memset(&user_data, 0, sizeof(user_data));
    memset(buf, 0, sizeof(buf));
    
    mutex_lock(&mod_mutex); 
    
    switch(cmd) {
        case ROSES_ARE_RED_WIRES_ARE_TOO: { // DO_CREATE 
        
            // Make sure that tech_count is less than 0x400 which is TECH_MAX
            if (tech_count >= TECH_MAX) {
                pr_info("Max number of objects reached\n"); 
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            
            // Copy stuff from userspace
            if (copy_from_user(&user_data, (struct req __user *)arg, sizeof(user_data)) != 0) {
                mutex_unlock(&mod_mutex); 
		        return -1;
            } 
         
            // Max owner size is supposed to be 0x28
            if (copy_from_user((void *)(&tech_size), (void __user *) user_data.size, 0x8) != 0) {
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            if (tech_size > 0x28) {
                pr_info("Size too big 0x%llx\n", tech_size);
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            
            // Create the tech object
            tech = kzalloc(sizeof(struct cutting_edge_technology), GFP_KERNEL); 
            
            // Set size
            tech->size = tech_size; 
            
            // Copy the owner name into the tech object 
            ret = copy_from_user(buf, (void __user *) user_data.addr, tech_size);
            memcpy(&tech->owner, buf, tech_size-1); 
            
            // Create the secret object 
            secret = kzalloc(SECRET_SIZE, GFP_KERNEL); // kmalloc-32
            memset(secret, 0x23, SECRET_SIZE); // Set all characters to #
            tech->secret = (uint64_t)secret; 
            
            // Set signature
            tech->signature = 0x454d455355464544; 
            
            // Add the tech object into tech_array, set idx, then increment tech_count
            tech_array[tech_count] = tech; 
            tech_count = tech_count + 1; 
            
            // Unlock mutex and exit
            mutex_unlock(&mod_mutex); 
            return 0; 
            break;
        }
        case BOOMERS_BEWARE: { // DO_READ 
        
            // Copy from user
            if (copy_from_user(&user_data, (struct req __user *)arg, sizeof(user_data)) != 0) {
                mutex_unlock(&mod_mutex); 
		        return -1;
            } 
            
            if (user_data.idx >= tech_count) {
                pr_info("Invalid index\n"); 
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            
            // Access tech object
            tech = tech_array[user_data.idx]; 
            if (tech == 0x0) {
                pr_info("Trying to reference deleted object\n"); 
                mutex_unlock(&mod_mutex); 
                return -1; 
            }
            
            // Read owner and send back to user
            ret = copy_to_user((void __user *)user_data.addr, &tech->owner, 0x28);
            
            // Read signature and send back to user
            ret = copy_to_user((void __user *)user_data.signature, &tech->signature, 0x8);
            
            // Unlock mutex and exit
            mutex_unlock(&mod_mutex); 
            return 0; 
            break;
        }
        case SNIP_HAPPENS: { // DO_DELETE 
        
            // Copy from user
            if (copy_from_user(&user_data, (struct req __user *)arg, sizeof(user_data)) != 0) {
                mutex_unlock(&mod_mutex); 
		        return -1;
            } 
            
            if (user_data.idx >= tech_count) {
                pr_info("Invalid index\n"); 
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            
            // Access tech object
            tech = tech_array[user_data.idx]; 
            if (tech == 0x0) {
                pr_info("Trying to reference deleted object\n"); 
                mutex_unlock(&mod_mutex); 
                return -1; 
            }
            
            // Free secret
            kfree((void *)tech->secret); 
            tech->secret = 0x0; 
            
            // Free tech object
            kfree((void *)tech); 
            tech_array[user_data.idx] = 0x0; 
            
            // Unlock mutex and return
            mutex_unlock(&mod_mutex); 
            return 0; 
            break;
        }
        case JAMES_BOMB: { // DO_SECRET
            // Copy from user
            if (copy_from_user(&user_data, (struct req __user *)arg, sizeof(user_data)) != 0) {
                mutex_unlock(&mod_mutex); 
		        return -1;
            } 
            
            if (user_data.idx >= tech_count) {
                pr_info("Invalid index\n"); 
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            
            // Access tech object
            tech = tech_array[user_data.idx]; 
            if (tech == 0x0) {
                pr_info("Trying to reference deleted object\n"); 
                mutex_unlock(&mod_mutex); 
                return -1; 
            }
            
            // Initialize secret buffer
            memset((void *)tech->secret, 0x23, SECRET_SIZE); 
            
            // Write secret to buffer
            memcpy((void *)tech->secret, secret_array[secret_idx], SECRET_SIZE); 
            if (secret_idx == SECRET_MAX) {
                secret_idx = 0x0; 
            } else {
                secret_idx = secret_idx + 1;
            }
            
            // Unlock mutex and exit
            mutex_unlock(&mod_mutex); 
            return 0; 
            break;
        }
        case THIS_IS_FINE: { // DO_CHANGESIZE
            // Copy from user
            if (copy_from_user(&user_data, (struct req __user *)arg, sizeof(user_data)) != 0) {
                mutex_unlock(&mod_mutex); 
		        return -1;
            } 
            
            if (user_data.idx >= tech_count) {
                pr_info("Invalid index\n"); 
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            
            // Access tech object
            tech = tech_array[user_data.idx]; 
            if (tech == 0x0) {
                pr_info("Trying to reference deleted object\n"); 
                mutex_unlock(&mod_mutex); 
                return -1; 
            }
            
            // Max owner size is supposed to be 0x28
            if (copy_from_user((void *)(&tech_size), (void __user *) user_data.size, 0x8) != 0) {
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            if (tech_size > 0x28) {
                pr_info("Size too big 0x%llx\n", tech_size);
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            msleep(10); 
            
            // DOUBLE FETCH
            if (copy_from_user((void *)(&tech->size), (void __user *) user_data.size, 0x8) != 0) {
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            
            // Return size to user
            ret = copy_to_user((void __user *)user_data.addr, (void *)(&tech->size), 0x8);
            
            // Unlock mutex and exit
            mutex_unlock(&mod_mutex); 
            return 0; 
            break;
        }
        case BOMB_VOYAGE: { // DO_WRITE
            // Copy from user
            if (copy_from_user(&user_data, (struct req __user *)arg, sizeof(user_data)) != 0) {
                mutex_unlock(&mod_mutex); 
		        return -1;
            } 
            
            if (user_data.idx >= tech_count) {
                pr_info("Invalid index\n"); 
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            
            // Access tech object
            tech = tech_array[user_data.idx]; 
            if (tech == 0x0) {
                pr_info("Trying to reference deleted object\n"); 
                mutex_unlock(&mod_mutex); 
                return -1; 
            }
            
            // Overwrite owner
            if (copy_from_user((void *)(&tech->owner), (void __user *) user_data.addr, tech->size) != 0) {
                mutex_unlock(&mod_mutex); 
                return -1;
            }
            
            // Unlock mutex and return
            mutex_unlock(&mod_mutex); 
            return 0; 
            break;
        }
        default: 
            mutex_unlock(&mod_mutex); 
            return -1;
            break;
    }
    return 0;
}

static int bigbangtheory_init(void) {
    mutex_init(&mod_mutex);
    initialize_secret(); 
	return misc_register(&bigbangtheory);
}

static void bigbangtheory_exit(void) {
	 misc_deregister(&bigbangtheory);
}

module_init(bigbangtheory_init);
module_exit(bigbangtheory_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Wire we here? Just to suffer?");
MODULE_AUTHOR("Kaligula Armblessed");
