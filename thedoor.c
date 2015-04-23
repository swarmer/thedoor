#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>


static dev_t dev_id;
static struct class *dev_class;
static struct cdev device;


static int thedoor_open(struct inode *inod, struct file *fl)
{
    return 0;
}

static int thedoor_close(struct inode *inod, struct file *fl)
{
    return 0;
}

static ssize_t thedoor_read(struct file *fl, char __user *buf, size_t len, loff_t *off)
{
    return 0;
}

static ssize_t thedoor_write(
    struct file *fl, const char __user *buf, size_t len, loff_t *off)
{
    return 0;
}

static struct file_operations thedoor_fops = {
    .owner = THIS_MODULE,
    .open = thedoor_open,
    .release = thedoor_close,
    .read = thedoor_read,
    .write = thedoor_write
};


static int __init thedoor_init(void)
{
    printk("Thedoor loading");

    if (alloc_chrdev_region(&dev_id, 0, 1, "thedoor") < 0)
        goto error;

    if ((dev_class = class_create(THIS_MODULE, "thedoor")) == NULL)
        goto error_class;

    if (device_create(dev_class, NULL, dev_id, NULL, "door") == NULL)
        goto error_device;

    cdev_init(&device, &thedoor_fops);
    if (cdev_add(&device, dev_id, 1) == -1)
        goto error_cdev;

    return 0;

error_cdev:
    device_destroy(dev_class, dev_id);
error_device:
    class_destroy(dev_class);
error_class:
    unregister_chrdev_region(dev_id, 1);
error:
    return -1;
}


static void __exit thedoor_exit(void)
{
    printk("Thedoor unloading");

    cdev_del(&device);
    device_destroy(dev_class, dev_id);
    class_destroy(dev_class);
    unregister_chrdev_region(dev_id, 1);
}


module_init(thedoor_init);
module_exit(thedoor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("swarmer <anton@swarmer.me>");
MODULE_DESCRIPTION("A bad backdoor");
