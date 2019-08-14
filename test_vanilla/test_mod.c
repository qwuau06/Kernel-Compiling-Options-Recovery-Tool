#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>

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

struct test_struct {
	u32	t32;
	u64	t64;
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
	struct device tst;
	unsigned long tmp0,tmp1;//,tmp2,tmp3,tmp4,tmp5,tmp6,tmp7;
	long* p, * q, *r, *s, *t, *x, *y, *z;
	p = (long*)0x42;
	q = (long*)0x24;
	r = (long*)0x72;
	s = (long*)0x89;
	t = (long*)0x97;
	x = (long*)0xa0;
	y = (long*)0xb0;
	z = (long*)0xc0;
//	tmp0 = (unsigned long)((void*)&tst.power.suspend_timer-(void*)&tst);
//	*p = tmp0;
//	tmp1 = (unsigned long)((void*)&tst.power.timer_expires-(void*)&tst);
//	*q = tmp1;
	tmp0 = (unsigned long)((void*)&tst.power.constraints-(void*)&tst);
	*p = tmp0;
	tmp1 = (unsigned long)((void*)&tst.pm_domain-(void*)&tst);
	*q = tmp1;
//	tmp4 = (unsigned long)((void*)&tst.dma_parms-(void*)&tst);
//	*t = tmp4;
//	tmp5 = (unsigned long)((void*)&tst.dma_parms-(void*)&tst);
//	*x = tmp5;
//	tmp6 = (unsigned long)((void*)&tst.dma_parms-(void*)&tst);
//	*y = tmp6;
//	tmp7 = (unsigned long)((void*)&tst.dma_parms-(void*)&tst);
//	*z = tmp7;
	return 0;
	
}

static ssize_t device_write(struct file *fp, const char *buf, size_t length, loff_t *offset){
	printk(KERN_INFO "Not supported.\n");
	return -EINVAL;
}

module_init(init_module_jique);
module_exit(cleanup_module_jique);
