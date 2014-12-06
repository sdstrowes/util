#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "itob.h"

static char* itob(uintmax_t in, int len, char* out)
{
	char* ptr;
	for (ptr = out + len - 1; ptr != out; ptr--) {
		*ptr = (in & 0x00000001) ? '1' : '0';
		in = in >> 1;
	}
	*ptr = (in & 1) ? '1' : '0';
	return ptr;
}

char* uint8tob(uint8_t in, char* out)   { return itob(in, 8, out);  }
char* int8tob(int8_t in, char* out)     { return itob(in, 8, out);  }

char* uint16tob(uint16_t in, char* out) { return itob(in, 16, out); }
char* int16tob(int16_t in, char* out)   { return itob(in, 16, out); }

char* uint32tob(uint32_t in, char* out) { return itob(in, 32, out); }
char* int32tob(int32_t in, char* out)   { return itob(in, 32, out); }

char* uint64tob(uint64_t in, char* out) { return itob(in, 64, out); }
char* int64tob(int64_t in, char* out)   { return itob(in, 64, out); }

int main()
{
	uint32_t test32;
	uint64_t test64;
	char buffer[MAXINT_SIZE];

	test32=1024;
	memset(buffer, '\0', MAXINT_SIZE);
	printf("%s\n", 	uint32tob(test32, buffer));

	test64=6000000000ULL;
	memset(buffer, '\0', MAXINT_SIZE);
	printf("%s\n", uint64tob(test64, buffer));

	return 1;
}
