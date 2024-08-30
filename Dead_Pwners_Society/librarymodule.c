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
#define DO_DELETE  _IOWR(IOC_MAGIC, 1, struct req) 
#define DO_BORROW  _IOWR(IOC_MAGIC, 2, struct req) 
#define DO_READ    _IOWR(IOC_MAGIC, 3, struct req)
#define DO_NOTE    _IOWR(IOC_MAGIC, 4, struct req)
#define DO_RETURN  _IOWR(IOC_MAGIC, 5, struct req)

struct mutex book_mutex;
struct mutex loan_mutex; 

struct list_head book_head;
struct list_head loan_head;
uint64_t book_count = 0;

struct req {
    uint64_t idx;
    uint64_t name_addr;
    uint64_t note_size;
    uint64_t note_addr;
    uint64_t info_addr;
};

struct reference {
    uint8_t val;
};

static int reference_init(struct reference *ref) {
    ref->val = 1; 
    return 0; 
}

static int reference_get(struct reference *ref) {
    ref->val = ref->val + 1; 
    return 0;
}

static int reference_put(struct reference *ref) {
    ref->val = ref->val - 1; 
    return 0;
}

struct book {
    char name[0x40];
    uint64_t idx;
    struct list_head book_list; 
    struct list_head loan_list;
    uint64_t note_size; 
    uint64_t note_addr; 
    struct reference ref;
    char info[0x79];
}; 

static int open_module(struct inode *inode, struct file *filp);
static long ioctl_module(struct file *filp, unsigned int cmd, unsigned long arg);

static struct file_operations fops = {
	open : open_module,
	unlocked_ioctl : ioctl_module
};

static struct miscdevice librarymodule = {
    .minor      = 53,
    .name       = "librarymodule",
    .fops       = &fops,
    .mode	    = 0666,
};

static int open_module(struct inode *inode, struct file *filp) {
	return 0;
}

static long ioctl_module(struct file *filp, unsigned int cmd, unsigned long arg) {
    struct req user_data; 
    struct book * book = NULL; 
    struct book * entry = 0;
    struct book * loan_entry = 0;
    struct list_head * ptr = 0;
    struct list_head * loan_ptr = 0;
    void * note;
    char buf[1024] = {0}; 
    int ret = 0;
    int found = 0;
    
    memset(&user_data, 0, sizeof(user_data));
    memset(buf, 0, sizeof(buf));
    
    if (copy_from_user(&user_data, (struct req __user *)arg, sizeof(user_data)) != 0) {
		return -1;
    } 
    pr_info("Copy from user done\n"); 
    
    if (user_data.note_size > 32) {
        pr_info("Note size too big\n");
        return -1;
    }
    
    switch(cmd) {
        case DO_CREATE: { 
            mutex_lock(&book_mutex);
            book = kzalloc(sizeof(struct book), GFP_KERNEL); 
            book->idx = book_count; 
            book_count = book_count + 1;
            ret = copy_from_user(buf, (void __user *) user_data.name_addr, 0x40-1);
            memcpy(&book->name, buf, 0x40-1); 
            memset(buf, 0, sizeof(buf));
            ret = copy_from_user(buf, (void __user *) user_data.info_addr, 0x79-1);
            memcpy(&book->info, buf, 0x79-1);
            memset(buf, 0, sizeof(buf));
            book->note_size = user_data.note_size; 
            note = kzalloc(book->note_size, GFP_KERNEL); 
            if ((note != 0) && ((uint64_t) note != 0x10)) { 
                ret = copy_from_user(buf, (void __user *) user_data.note_addr, book->note_size-1);
                memcpy((void *) note, buf, book->note_size-1); 
                book->note_addr = (uint64_t) note;
            }
            reference_init(&book->ref); 
            list_add_tail(&book->book_list, &book_head);
            pr_info("Created book at index %lld\n", book->idx); 
            mutex_unlock(&book_mutex);
            return 0; 
            break;
        }
        case DO_DELETE: {
            mutex_lock(&book_mutex);
            list_for_each(ptr, &book_head) {
                entry = list_entry(ptr, struct book, book_list);
                if (entry->idx == user_data.idx) {
                    if (entry->ref.val != 1) {
                        mutex_unlock(&book_mutex);
                        return -1;
                        break;
                    }
                    reference_put(&entry->ref); 
                    list_del(&entry->book_list); 
                    if (entry->note_addr != 0) { 
                        kfree((void *) entry->note_addr);
                        entry->note_addr = 0; 
                    }
                    kfree(entry);
                    pr_info("Deleted book at index %lld\n", user_data.idx);
                    mutex_unlock(&book_mutex);
                    return 0;
                }
            }
            mutex_unlock(&book_mutex);
            return -1;
            break;
        }
        case DO_BORROW: {
            mutex_lock(&book_mutex);
            mutex_lock(&loan_mutex);
            
            list_for_each(ptr, &book_head) {
                entry = list_entry(ptr, struct book, book_list);
                if (entry->idx == user_data.idx) {
                    if ((entry->ref.val == 0) || (entry->ref.val > 10)) {
                        mutex_unlock(&book_mutex);
                        mutex_unlock(&loan_mutex);
                        return -1;
                        break;
                    }
                    list_for_each(loan_ptr, &loan_head) {
                        loan_entry = list_entry(loan_ptr, struct book, loan_list);
                        if (loan_entry->idx == entry->idx) {
                            found = 1; 
                            break;
                        }
                    }
                    if (found == 0) {
                        list_add_tail(&entry->loan_list, &loan_head);
                    }
                    reference_get(&entry->ref);
                    mutex_unlock(&book_mutex);
                    mutex_unlock(&loan_mutex);
                    return 0; 
                }
            }
            mutex_unlock(&book_mutex);
            mutex_unlock(&loan_mutex);
            return -1;
            break;
        }
        case DO_READ: {
            list_for_each(loan_ptr, &loan_head) {
                loan_entry = list_entry(loan_ptr, struct book, loan_list);
                if (loan_entry->idx == user_data.idx) {
                    pr_info("Read book at index %lld\n", user_data.idx);
                    reference_get(&loan_entry->ref); 
                    memcpy(buf, (void *) loan_entry->note_addr, loan_entry->note_size-1);
                    ret = copy_to_user((void __user *)user_data.note_addr, buf, loan_entry->note_size-1);
                    memset(buf, 0, sizeof(buf)); 
                    memcpy(buf, &loan_entry->name, 0x40-1);
                    ret = copy_to_user((void __user *)user_data.name_addr, buf, 0x40-1);
                    memset(buf, 0, sizeof(buf)); 
                    memcpy(buf, &loan_entry->info, 0x79-1);
                    ret = copy_to_user((void __user *)user_data.info_addr, buf, 0x79-1);
                    reference_put(&loan_entry->ref); 
                    return 0;
                }
            }
            return -1;
            break;
        }
        case DO_NOTE: {
            mutex_lock(&book_mutex);
            mutex_lock(&loan_mutex);
            list_for_each(loan_ptr, &loan_head) {
                loan_entry = list_entry(loan_ptr, struct book, loan_list);
                if (loan_entry->idx == user_data.idx) {
                    pr_info("Changing note for book at index %lld\n", user_data.idx);
                    reference_get(&loan_entry->ref); 
                    if (loan_entry->note_addr != 0) { 
                        kfree((void *) loan_entry->note_addr);
                        loan_entry->note_addr = 0; 
                    }
                    loan_entry->note_size = user_data.note_size; 
                    note = kzalloc(loan_entry->note_size, GFP_KERNEL); 
                    if ((note != 0) && ((uint64_t) note != 0x10)) { 
                        ret = copy_from_user(buf, (void __user *) user_data.note_addr, loan_entry->note_size-1);
                        memcpy((void *) note, buf, loan_entry->note_size-1); 
                        loan_entry->note_addr = (uint64_t) note;
                    }
                    reference_put(&loan_entry->ref); 
                    mutex_unlock(&book_mutex);
                    mutex_unlock(&loan_mutex); 
                    return 0;
                }
            }
            mutex_unlock(&book_mutex);
            mutex_unlock(&loan_mutex);
            return -1;
            break;
        }
        case DO_RETURN: { 
            mutex_lock(&book_mutex);
            mutex_lock(&loan_mutex);
            list_for_each(loan_ptr, &loan_head) {
                loan_entry = list_entry(loan_ptr, struct book, loan_list);
                if (loan_entry->idx == user_data.idx) {
                    if (loan_entry->ref.val < 2) {
                        mutex_unlock(&book_mutex);
                        mutex_unlock(&loan_mutex);
                        return -1; 
                        break;
                    }
                    reference_put(&loan_entry->ref); 
                    if (loan_entry->ref.val == 1) {
                        list_del(&loan_entry->loan_list); 
                    }
                    mutex_unlock(&book_mutex);
                    mutex_unlock(&loan_mutex);
                    return 0; 
                    break;
                }
            }
            mutex_unlock(&book_mutex);
            mutex_unlock(&loan_mutex);
            return -1; 
            break;
        }
        default: 
            return -1;
            break;
    }
    
    return 0;
}

static int librarymodule_init(void) {
    INIT_LIST_HEAD(&book_head);
    INIT_LIST_HEAD(&loan_head);
    mutex_init(&book_mutex);
    mutex_init(&loan_mutex);
	return misc_register(&librarymodule);
}

static void librarymodule_exit(void) {
	 misc_deregister(&librarymodule);
}

module_init(librarymodule_init);
module_exit(librarymodule_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Dead Pwners Society V1.0");