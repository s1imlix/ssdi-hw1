#ifndef __ROOTKIT_HW2_H
#define __ROOTKIT_HW2_H

#include <linux/string.h>

#define MASQ_LEN 0x10
#define TASK_FILTER_LEN 0x10

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

struct masq_proc {
  char new_name[MASQ_LEN];
  char orig_name[MASQ_LEN];
};

struct masq_proc_req {
  size_t len;
  struct masq_proc *list;
};

struct list_head {
  struct list_head *next, *prev;
};

struct filter_info {
  int syscall_nr;
  char comm[TASK_FILTER_LEN]; // process name

  // function pointer
  unsigned long orig_handler_addr;
  struct list_head list;
};

#define MAGIC 'k'
#define IOCTL_MOD_HIDE _IO(MAGIC, 0)
#define IOCTL_MOD_MASQ _IOR(MAGIC, 1, struct masq_proc_req)
#define IOCTL_ADD_FILTER _IOR(MAGIC, 2, struct filter_info)
#define IOCTL_REMOVE_FILTER _IOR(MAGIC, 3, struct filter_info)

#endif /* __ROOTKIT_HW2_H */
