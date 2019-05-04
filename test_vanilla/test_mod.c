#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/types.h>

#include <asm/uaccess.h>

#define DEVICE_NAME "jiquekosatax"

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

static int Major;
static int Device_open = 0;

static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release	
};

int init_module_jique(void){
	Major = register_chrdev(0, DEVICE_NAME, &fops);
	if (Major<0){
		printk(KERN_ALERT "Register Jiquekosatax failed with %d\n",Major);
		return Major;
	}
	printk(KERN_INFO "Jiquekosatax installed.\n");
	return 0;
}

void cleanup_module_jique(void){
	unregister_chrdev(Major, DEVICE_NAME);
}

// file operations
static int device_open(struct inode* inode,struct file* fp){
	if(Device_open)
		return -EBUSY;
	Device_open++;
	try_module_get(THIS_MODULE);

	return 0;
}

static int device_release(struct inode* inode, struct file * fp){
	Device_open--;
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t device_read(struct file* fp, char * buf, size_t rlength, loff_t *offset){
	struct device dev;
	long tmp=0;
	unsigned long tmp0,tmp1;
	long* p;
	p = 42;
	printk(KERN_INFO "Jique start0\n");
	tmp0 = (unsigned long)(void*)(&(dev.dma_mem));
	tmp1 = (unsigned long)(void*)(&dev);
	tmp = tmp0-tmp1;
	*p = tmp;
	printk(KERN_INFO "Jique start1\n");
	tmp0 = (unsigned long)(void*)(&(dev.of_node));
	tmp1 = (unsigned long)(void*)(&dev);
	tmp = tmp0-tmp1;
	printk(KERN_INFO "finished computing, %lu, %lu\n",tmp0,tmp1);
	printk(KERN_INFO "%ld\n", tmp);
	return 0;
	
}

static ssize_t device_write(struct file *fp, const char *buf, size_t length, loff_t *offset){
	printk(KERN_INFO "Not supported.\n");
	return -EINVAL;
}

module_init(init_module_jique);
module_exit(cleanup_module_jique);
