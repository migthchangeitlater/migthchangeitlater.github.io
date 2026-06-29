#include <linux/miscdevice.h>
#include <linux/percpu.h>

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    asm volatile (
        ".intel_syntax noprefix\n"
        "cli\n"                     // no funny business while in kernelspace
        ".att_syntax prefix\n"
        :
        :
        :
    );
    // use your stand 
    this_cpu_write(cpu_current_top_of_stack, arg);
    // now its Dio's turn
    return 0;
}
static int dev_open(struct inode *inode, struct file *file) {
	file->private_data = NULL;
	return 0;
}

static int dev_release(struct inode *inode, struct file *file) {
	return 0;
}

static struct file_operations chall_fops = {
	.open = dev_open,
	.release = dev_release,
    .unlocked_ioctl = dev_ioctl
};

struct miscdevice chall_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "jojo",
    .fops = &chall_fops,
};

static int __init init_dev(void) {
    if (misc_register(&chall_dev) < 0) {
        printk(KERN_INFO "[CHALL] [ERR] Failed to register device\n");
		return -1;
	}

	return 0;
}

static void __exit exit_dev(void) {
	misc_deregister(&chall_dev);
}

module_init(init_dev);
module_exit(exit_dev);

MODULE_AUTHOR("mightchangeitlater");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Academy CTF 2026 <3");
