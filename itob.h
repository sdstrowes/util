#include <stdint.h>
#include <limits.h>

#define MAXINT_SIZE CHAR_BIT*sizeof(uintmax_t)+1

char* uint8tob(uint8_t, char*);
char* int8tob(int8_t, char*);

char* uint16tob(uint16_t, char*);
char* int16tob(int16_t, char*);

char* uint32tob(uint32_t, char*);
char* int32tob(int32_t, char*);

char* uint64tob(uint64_t, char*);
char* int64tob(int64_t, char*);
