#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

const char *filename = "./test.txt";

int main() {
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  // try to read two bytes
  char buf[2];
  int n = read(fd, buf, 2);
  if (n < 0) {
    perror("child read() failed despite not having filter");
  } else {
    printf("child read() succeeded with %d bytes\n", n);
  }
}
