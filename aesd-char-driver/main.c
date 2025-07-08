/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Dominik H"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    struct aesd_dev *dev;
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    struct aesd_dev *dev = filp->private_data;

    if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;

    struct aesd_buffer_entry *entry;
    size_t entry_offset_byte_rtn;
    
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(dev->buff, *f_pos, &entry_offset_byte_rtn);
	if (!entry) {
        retval = 0;  // No data to read
        goto out;
    }
    
    ssize_t bytes_to_copy = entry->size - entry_offset_byte_rtn;
    if (bytes_to_copy > count) bytes_to_copy = count;

	if (copy_to_user(buf, entry->buffptr + entry_offset_byte_rtn, bytes_to_copy)) {
		retval = -EFAULT;
		goto out;
	}
	*f_pos += bytes_to_copy;
	retval = bytes_to_copy;

  out:
	mutex_unlock(&dev->lock);
	return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */

    struct aesd_dev *dev = filp->private_data;

    if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;

    char *kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf) {
        retval = -ENOMEM;
        goto out;
    }
    if (copy_from_user(kbuf, buf, count)) {
		retval = -EFAULT;
        kfree(kbuf);
		goto out;
	}

    char *new_buf = krealloc(dev->partial_buff, dev->partial_size + count, GFP_KERNEL);
    if (!new_buf) {
        kfree(kbuf);
        goto out;
    }

    memcpy(new_buf + dev->partial_size, kbuf, count);
    dev->partial_buff = new_buf;
    dev->partial_size += count;
    dev->partial_buff[dev->partial_size] = buf;
    kfree(kbuf);

    if (!memchr(dev->partial_buff, '\n', dev->partial_size)) {
        retval = count;
        goto out;
    }

    struct aesd_buffer_entry entry;
    entry.buffptr = dev->partial_buff;
    entry.size = dev->partial_size;

    if (dev->buff->full) {
        kfree(dev->buff->entry[dev->buff->in_offs].buffptr);
    }
    
    aesd_circular_buffer_add_entry(dev->buff, &entry);
	*f_pos += count;
	retval = count;

    dev->partial_buff = NULL;
    dev->partial_size = 0;

  out:
	mutex_unlock(&dev->lock);
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    
    aesd_device.buff = kmalloc(sizeof(struct aesd_circular_buffer), GFP_KERNEL);
    if (!aesd_device.buff)
        return -ENOMEM;
    aesd_circular_buffer_init(aesd_device.buff);

    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    for (int i = 0; i <AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
        kfree(aesd_device.buff->entry[i].buffptr);
    }
    kfree(aesd_device.buff);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
