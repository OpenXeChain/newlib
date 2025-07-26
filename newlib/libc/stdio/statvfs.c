#include <sys/statvfs.h>

// XBOX: TODO IMPLEMENT THOSE FOR C++ filesystem to work
int statvfs (const char *__path, struct statvfs *__buf) {
    return -1;
}

int fstatvfs (int __fd, struct statvfs *__buf) {
    return -1;
}