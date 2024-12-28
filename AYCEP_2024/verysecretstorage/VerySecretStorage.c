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

#define IOC_MAGIC '\xca'

#define DO_CREATE  _IOWR(IOC_MAGIC, 0, struct req)
#define DO_READ    _IOWR(IOC_MAGIC, 1, struct req) 
#define DO_WRITE   _IOWR(IOC_MAGIC, 2, struct req) 
#define DO_RESIZE  _IOWR(IOC_MAGIC, 3, struct req)
#define DO_DELETE  _IOWR(IOC_MAGIC, 4, struct req) 

struct mutex storage_mutex;

struct req {
    uint64_t idx;
    uint64_t name_addr;
    uint64_t note_size;
    uint64_t note_addr;
};

struct box {
    char name[0x50];
    uint64_t note_size; 
    uint64_t note_addr;
}; 

void * box_array[0x30] = {0};
unsigned int box_count = 0;

static int open_module(struct inode *inode, struct file *filp);
static long ioctl_module(struct file *filp, unsigned int cmd, unsigned long arg);

static struct file_operations fops = {
	open : open_module,
	unlocked_ioctl : ioctl_module
};

static struct miscdevice secretstorage = {
    .minor      = 53,
    .name       = "secretstorage",
    .fops       = &fops,
    .mode	    = 0666,
};

static int open_module(struct inode *inode, struct file *filp) {
	return 0;
}

static long ioctl_module(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct req user_data; 
    struct box * box = NULL; 
    void * note = 0; 
    char buf[1024] = {0}; 
    int ret = 0;
    
    memset(&user_data, 0, sizeof(user_data));
    memset(buf, 0, sizeof(buf));
    
    if (copy_from_user(&user_data, (struct req __user *)arg, sizeof(user_data)) != 0) {
		return -1;
    } 
    pr_info("Copy from user done\n"); 
    if (user_data.note_size > 0x1000) {
        pr_info("Note size too big\n");
        return -1;
    }
    
    mutex_lock(&storage_mutex); 
    
    switch(cmd) {
        case DO_CREATE: { 
            if (box_count >= 0x30) {
                mutex_unlock(&storage_mutex); 
                pr_info("Too many boxes!\n"); 
                return -1; 
                break;
            }
            box = kmalloc(sizeof(struct box), GFP_KERNEL);
            ret = copy_from_user(buf, (void __user *) user_data.name_addr, 0x50-1);
            memcpy(&box->name, buf, 0x50-1); 
            memset(buf, 0, sizeof(buf));
            if (user_data.note_size != 0) {
                note = kmalloc(user_data.note_size, GFP_KERNEL);
                box->note_addr = (uint64_t) note; 
                box->note_size = user_data.note_size;
                
                // Copy information to the note
                ret = copy_from_user(buf, (void __user *) user_data.note_addr, box->note_size);
                memcpy((void *) note, buf, box->note_size-1);
                memset(buf, 0, sizeof(buf));
            }
            box_array[box_count] = box; 
            box_count = box_count + 1; 
            mutex_unlock(&storage_mutex); 
            return 0; 
            break;
        }
        case DO_READ: {
            if (user_data.idx > (box_count - 1)) {
                mutex_unlock(&storage_mutex); 
                pr_info("Invalid idx\n"); 
                return -1; 
                break;
            }
            box = box_array[user_data.idx]; 
            memcpy(buf, &box->name, 0x50-1); 
            ret = copy_to_user((void __user *)user_data.name_addr, buf, 0x50-1);
            if (box->note_addr != 0 && box->note_addr != 0x10) {
                memset(buf, 0x0, sizeof(buf)); 
                memcpy(buf, (void *)box->note_addr, box->note_size-1); 
                ret = copy_to_user((void __user *)user_data.note_addr, buf, box->note_size); 
            }
            mutex_unlock(&storage_mutex); 
            return 0; 
            break;
        }
        case DO_WRITE: {
            if (user_data.idx > (box_count - 1)) {
                mutex_unlock(&storage_mutex); 
                pr_info("Invalid idx\n"); 
                return -1; 
                break;
            }
            box = box_array[user_data.idx]; 
            ret = copy_from_user(&box->name, (void __user *) user_data.name_addr, 0x50-1);
            if (box->note_size != 0 && box->note_addr != 0 && box->note_addr != 0x10) {
                ret = copy_from_user((void *)box->note_addr, (void __user *) user_data.note_addr, box->note_size);
            }
            mutex_unlock(&storage_mutex); 
            return 0; 
            break;
        }
        case DO_RESIZE: {
            if (user_data.idx > (box_count - 1)) {
                mutex_unlock(&storage_mutex); 
                pr_info("Invalid idx\n"); 
                return -1; 
                break;
            }
            box = box_array[user_data.idx]; 
            ret = copy_from_user(&box->name, (void __user *) user_data.name_addr, 0x50-1);
            if (user_data.note_size != 0) {
                kfree((void *)box->note_addr);
                note = kmalloc(user_data.note_size, GFP_KERNEL); 
                box->note_addr = (uint64_t)note; 
                box->note_size = user_data.note_size; 
                ret = copy_from_user(note, (void __user *) user_data.note_addr, user_data.note_size);
            }
            mutex_unlock(&storage_mutex); 
            return 0; 
            break;
        }
        case DO_DELETE: {
            if (user_data.idx > (box_count - 1)) {
                mutex_unlock(&storage_mutex); 
                pr_info("Invalid idx\n"); 
                return -1; 
                break;
            }
            box = box_array[user_data.idx]; 
            if (box->note_addr != 0 && box->note_addr != 0x10) {
                kfree((void *)box->note_addr); 
                box->note_addr = 0; 
            }
            kfree(box); 
            mutex_unlock(&storage_mutex); 
            return 0; 
            break;
        }
        default: 
            mutex_unlock(&storage_mutex); 
            return -1;
            break;
    }
    return 0;
}

static int secretstorage_init(void) {
    mutex_init(&storage_mutex);
	return misc_register(&secretstorage);
}

static void secretstorage_exit(void) {
	 misc_deregister(&secretstorage);
}

module_init(secretstorage_init);
module_exit(secretstorage_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ROP LLC's Very Secret Storage!!! Warning: Highly secure. Contains top secret information!!!");
MODULE_AUTHOR("Kaligula Armblessed, CEO of ROP LLC."); // <-- Totally not evil at all!

// IMPORTANT INTEL FROM OUR ALLIES AT MAVERICK INC. 
// We have managed to get our hands on this leaked source code file for ROP LLC.'s secret storage kernel module. Can you use your skills from your time at ROP LLC.'s VR training to find the vulnerability and root their storage server?

