#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int main(int argc, char *argv[])
{
	int		fd = open(argv[1], O_RDWR | O_CREAT | O_EXCL, 0666);
	size_t		len = atoi(argv[2]);
	char const	*mode = argv[3];
	unsigned char	*mem;
	size_t		i;

	assert(fd >= 0);

	if (ftruncate(fd, len) < 0)
		abort();

	if (len == 0)
		return 0;

	mem = mmap(NULL, len, PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED)
		abort();

	if (strcmp(mode, "zero") == 0) {
		;			/* noop */
	} else if (strcmp(mode, "ff") == 0) {
		memset(mem, 0xff, len);
	} else if (strcmp(mode, "seq") == 0) {
		for (i = 0; i < len; ++i)
			mem[i] = i;
	} else if (strcmp(mode, "rnd") == 0) {
		srand(len);
		for (i = 0; i < len; ++i)
			mem[i] = rand();
	}
}
