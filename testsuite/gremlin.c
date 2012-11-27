#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int main(int argc, char *argv[])
{
	int		fd = open(argv[1], O_RDWR, 0666);
	off_t		len = lseek(fd, 0, SEEK_END);
	unsigned char	*mem;

	assert(fd >= 0);
	assert(len > 0);

	mem = mmap(NULL, len, PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED)
		abort();

	mem[len-1]++;
}
