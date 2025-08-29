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
#define CREATE_SECRET_MESSAGE  _IOWR(IOC_MAGIC, 0, struct req)
#define WRITE_SECRET_MESSAGE   _IOWR(IOC_MAGIC, 1, struct req)

struct mutex mod_mutex;

struct req {
    uint64_t size;
    uint64_t message;
};

struct secret_message {
    uint64_t size; 
    uint64_t message;
};

int secret_message_created = 0;
int secret_message_written = 0;  
struct secret_message * secret_msg = 0;

static int open_module(struct inode *inode, struct file *filp);
static long ioctl_module(struct file *filp, unsigned int cmd, unsigned long arg);

static struct file_operations fops = {
	open : open_module,
	unlocked_ioctl : ioctl_module
};

static struct miscdevice jacks_filedump = {
    .minor      = 53,
    .name       = "jacks_filedump",
    .fops       = &fops,
    .mode	    = 0666,
};

static int open_module(struct inode *inode, struct file *filp) {
	return 0;
}

static long ioctl_module(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct req user_data; 
    int ret = 0;
    uint64_t size = 0; 
    char buf[0x400]; 
    uint16_t * message_buf = 0; 
    
    memset(&user_data, 0, sizeof(user_data));
    memset(buf, 0x0, sizeof(buf)); 
    mutex_lock(&mod_mutex); 
    
    if (copy_from_user(&user_data, (struct req __user *)arg, sizeof(user_data)) != 0) {
        mutex_unlock(&mod_mutex);
		return -1;
    } 
    pr_info("Copy from user done\n"); 
    
    if (user_data.size > 0x400 || user_data.size == 0x0) {
        pr_info("Invalid size\n"); 
        mutex_unlock(&mod_mutex); 
        return -1; 
    }
    
    switch(cmd) {
        case CREATE_SECRET_MESSAGE: {
            size = user_data.size; 
            if (secret_message_created == 1) {
                pr_info("Secret message has already been created!\n"); 
                mutex_unlock(&mod_mutex);
                return -1; 
                break;
               }
            secret_msg = kzalloc(sizeof(struct secret_message), GFP_KERNEL_ACCOUNT);
            message_buf = kzalloc(size * 2, GFP_KERNEL_ACCOUNT); 
            secret_msg->size = size; 
            secret_msg->message = (uint64_t)message_buf; 
            pr_info("Secret message created!\n"); 
            secret_message_created = 1;
            mutex_unlock(&mod_mutex); 
            return 0; 
            break;
        }
        case WRITE_SECRET_MESSAGE: {
            if (secret_message_written == 1) {
                pr_info("Secret message has already been written!\n"); 
                mutex_unlock(&mod_mutex); 
                return -1; 
                break;
            }
            if (secret_message_created == 0 || secret_msg == 0) {
                pr_info("Secret message does not exist!\n"); 
                mutex_unlock(&mod_mutex); 
                return -1; 
                break; 
            }
            size = secret_msg->size; 
            ret = copy_from_user(buf, (void __user *) user_data.message, size);
            for (int i = 0; i < size; i++) {
                ((uint16_t*)secret_msg->message)[i] = buf[i];
            }
            ((uint16_t*)secret_msg->message)[size] = 0x0; 
            pr_info("Secret message written!\n");
            secret_message_written = 1; 
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

static int filedump_init(void) {
    mutex_init(&mod_mutex);
	return misc_register(&jacks_filedump);
}

static void filedump_exit(void) {
	 misc_deregister(&jacks_filedump);
}

module_init(filedump_init);
module_exit(filedump_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Muahahahahaha!!! ROP LLC. is definitely not evil!!!");
MODULE_AUTHOR("Kaligula Armblessed");
