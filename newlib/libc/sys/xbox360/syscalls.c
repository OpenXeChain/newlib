#include <sys/stat.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/times.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PAGE_NOACCESS          0x01     
#define PAGE_READONLY          0x02     
#define PAGE_READWRITE         0x04     
#define PAGE_WRITECOPY         0x08     
#define PAGE_EXECUTE           0x10     
#define PAGE_EXECUTE_READ      0x20     
#define PAGE_EXECUTE_READWRITE 0x40     
#define PAGE_EXECUTE_WRITECOPY 0x80     
#define PAGE_GUARD            0x100     
#define PAGE_NOCACHE          0x200     
#define PAGE_WRITECOMBINE     0x400     
#define PAGE_USER_READONLY   0x1000     
#define PAGE_USER_READWRITE  0x2000     
#define MEM_COMMIT           0x1000     
#define MEM_RESERVE          0x2000     
#define MEM_DECOMMIT         0x4000     
#define MEM_RELEASE          0x8000     
#define MEM_FREE            0x10000     
#define MEM_PRIVATE         0x20000     
#define MEM_RESET           0x80000     
#define MEM_TOP_DOWN       0x100000     
#define MEM_NOZERO         0x800000     
#define MEM_LARGE_PAGES  0x20000000     
#define MEM_HEAP         0x40000000     
#define MEM_16MB_PAGES   0x80000000   
void* NtAllocateVirtualMemory(void** lpAddress,  size_t* dwSize, unsigned int flAllocationType, unsigned int flProtect, unsigned int dwMemoryRegionType);
void* NtFreeVirtualMemory(void** BaseAddress,  size_t* RegionSize, unsigned int FreeType);
void DbgPrint(const char* msg, ...);
void _exit(int status) {
    DbgPrint("LIBC: exit %d\r\n", status);
}
int close(int file) {
    DbgPrint("LIBC: close %d\r\n", file);
    return 0x60;
}
char **environ; /* pointer to array of char * strings that define the current environment variables */
int execve(char *name, char **argv, char **env) {
    DbgPrint("LIBC: execve\r\n");
    return  0x69;
}
int fork() {
    DbgPrint("LIBC: fork\r\n");
    return -1;
}
int fstat(int file, struct stat *st) {
    DbgPrint("LIBC: fstat %d\r\n", file);
    return -1;
}
int getpid() {
    return -1;
}
int isatty(int file) {
    DbgPrint("LIBC: isatty %d\r\n", file);
    return 0;
}
int kill(int pid, int sig) {
    return -1;
}
int link(char *old, char *new) {
    return -1;
}
int lseek(int file, int ptr, int dir) {
    DbgPrint("LIBC: lseek %d\r\n", file);
    return -1;
}
int open(const char *name, int flags, ...) {
    DbgPrint("LIBC: open %s\r\n", name);
    return -1;
}
int read(int file, char *ptr, int len) {
    DbgPrint("LIBC: read %d\r\n", file);
    return -1;
}

int stat(const char *file, struct stat *st) {
    DbgPrint("LIBC: stat %s\r\n", file);
    return -1;
}
clock_t times(struct tms *buf) {
     DbgPrint("LIBC: time\r\n");
    return -1;
}
int unlink(char *name) {
    return -1;
}
int wait(int *status) {
    return -1;
}
int write(int file, char *ptr, int len) {
     DbgPrint("LIBC: write %d\r\n", file);
    return -1;
}
int gettimeofday(struct timeval *p, void *z) {
    return -1;
}




struct header {
        size_t size;
        size_t real_size;
        unsigned is_free;
        struct header* next;
};

typedef struct header header_t;

static header_t *head = NULL, *tail = NULL;

static header_t *get_free_block(size_t size) {
    header_t *curr = head;
    while (curr) {
        if (curr->is_free && curr->size >= size) return curr;
        curr = curr->next;
    }
    return NULL;
}

//TODO: this is not threadsafe and also doesnt use pages efficiently
void *malloc(size_t size) {
    DbgPrint("LIBC: malloc: %d\r\n", size);
    size_t total_size;
    void *block = 0;
    header_t *header;

    if (!size) return NULL;

    header = get_free_block(size);
    if (header) {
        header->is_free = 0;
        return (void*)(header + 1);
    }

    total_size = sizeof(header_t) + size;

    NtAllocateVirtualMemory(&block, &total_size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES | MEM_HEAP, PAGE_READWRITE, 0);

    if (block == NULL || block == (void*)-1) {
        return NULL;
    }

    header = (header_t*)block;
    header->size = size;
    header->is_free = 0;
    header->real_size = total_size;
    header->next = NULL;
    if (!head) head = header;
    if (tail) tail->next = header;
    tail = header;

    return (void*)(header + 1);
}


void *_malloc_r (struct _reent *r, size_t n)
{
  return malloc (n);
}

void free(void *block) {
    DbgPrint("LIBC: free\r\n");
    header_t *header;

    if (!block) return;

    header = (header_t*)block - 1;

    if ((char*)block + header->size == (char*)tail + sizeof(header_t)) {
        NtFreeVirtualMemory(&header, &header->real_size, MEM_RELEASE);
    } else {
        header->is_free = 1;
    }
}

void _free_r (struct _reent *r, void *p)
{
  free (p);
}


void *calloc(size_t num, size_t nsize) {
    DbgPrint("LIBC: calloc: %d:%d\r\n", num, nsize);
    size_t size;
    void *block;

    if (!num || !nsize) return NULL;

    size = num * nsize;
    if (nsize != size / num) return NULL;

    block = malloc(size);
    if (!block) return NULL;

    memset(block, 0, size);
    return block;
}

void *
_calloc_r (struct _reent *ptr, size_t size, size_t len)
{
  return calloc (size, len);
}


void *realloc(void *block, size_t size) {
    DbgPrint("LIBC: realloc: %d\r\n", size);
    header_t *header;
    void *ret;

    if (!block) return malloc(size);

    header = (header_t*)block - 1;
    if (header->size >= size) return block;

    ret = malloc(size);
    if (ret) {
        memcpy(ret, block, header->size);
        free(block);
    }
    return ret;
}

void *_realloc_r (struct _reent *r, void *p, size_t n) _NOTHROW
{
  return realloc (p, n);
}
