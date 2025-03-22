#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>


const char *filename = "./test.txt";
const char *test_dir_name = "/home/hello2";


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


  if (mkdir(test_dir_name, 0777) == 0) {
    printf("mkdir() succeeded for child, removing newly created dir %s\n", test_dir_name);
    rmdir(test_dir_name);
  } else {
    printf("mkdir() failed successfully for child with filter");
  }


}
