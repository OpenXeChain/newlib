#include <sys/stat.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/times.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_WRITECOPY 0x08
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD 0x100
#define PAGE_NOCACHE 0x200
#define PAGE_WRITECOMBINE 0x400
#define PAGE_USER_READONLY 0x1000
#define PAGE_USER_READWRITE 0x2000
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_DECOMMIT 0x4000
#define MEM_RELEASE 0x8000
#define MEM_FREE 0x10000
#define MEM_PRIVATE 0x20000
#define MEM_RESET 0x80000
#define MEM_TOP_DOWN 0x100000
#define MEM_NOZERO 0x800000
#define MEM_LARGE_PAGES 0x20000000
#define MEM_HEAP 0x40000000
#define MEM_16MB_PAGES 0x80000000
#define EPOCH_BIAS 116444736000000000i64
typedef long NTSTATUS;
typedef unsigned long ACCESS_MASK;
typedef struct _STRING
{
    unsigned short Length;
    unsigned short MaximumLength;
    char *Buffer;
} STRING, *PSTRING;
typedef PSTRING POBJECT_STRING;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        void *Pointer;
    } st;
    unsigned long *Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES
{
    void* RootDirectory;
    POBJECT_STRING ObjectName;
    unsigned long Attributes;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef union _LARGE_INTEGER
{
    struct
    {
        long HighPart;
        unsigned int LowPart;
    };
    struct
    {
        long HighPart;
        unsigned int LowPart;
    } u;
    long long QuadPart;
} LARGE_INTEGER;

typedef LARGE_INTEGER *PLARGE_INTEGER;


NTSTATUS NtAllocateVirtualMemory(void **lpAddress, size_t *dwSize, unsigned int flAllocationType, unsigned int flProtect, unsigned int dwMemoryRegionType);
NTSTATUS NtFreeVirtualMemory(void **BaseAddress, size_t *RegionSize, unsigned int FreeType);
NTSTATUS NtCreateFile(unsigned int *FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, unsigned int FileAttributes, unsigned int ShareAccess, unsigned int CreateDisposition, unsigned int CreateOptions);
void RtlInitAnsiString(PSTRING DestinationString, char *SourceString);

void DbgPrint(const char *msg, ...);

__attribute__((naked)) void RtlDebugPrintHelper(char *buffer, unsigned int len)
{
    __asm__("twui 0, 0x14\n\t"
            "blr\n\t");
}

void _exit(int status)
{
    DbgPrint("LIBC: exit %d\r\n", status);
}
int close(int file)
{
    DbgPrint("LIBC: close %d\r\n", file);
    return 0x60;
}
char **environ; /* pointer to array of char * strings that define the current environment variables */
int execve(char *name, char **argv, char **env)
{
    DbgPrint("LIBC: execve\r\n");
    return -1;
}
int fork()
{
    DbgPrint("LIBC: fork\r\n");
    return -1;
}
int fstat(int file, struct stat *st)
{
    DbgPrint("LIBC: fstat %d\r\n", file);
    return -1;
}
int getpid()
{
    return -1;
}

int isatty(int file)
{
    return 0;
}

int kill(int pid, int sig)
{
    return -1;
}
int link(char *old, char *new)
{
    return -1;
}
int lseek(int file, int ptr, int dir)
{
    DbgPrint("LIBC: lseek %d\r\n", file);
    return -1;
}

#define GENERIC_READ (0x80000000L)
#define GENERIC_WRITE (0x40000000L)
#define GENERIC_EXECUTE (0x20000000L)
#define GENERIC_ALL (0x10000000L)
#define FTEXT 0x80

#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define FILE_SHARE_DELETE 0x00000004
#define CREATE_NEW 1
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define OPEN_ALWAYS 4
#define TRUNCATE_EXISTING 5

#define FILE_ATTRIBUTE_READONLY 0x00000001
#define FILE_ATTRIBUTE_HIDDEN 0x00000002
#define FILE_ATTRIBUTE_SYSTEM 0x00000004
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010
#define FILE_ATTRIBUTE_ARCHIVE 0x00000020
#define FILE_ATTRIBUTE_DEVICE 0x00000040
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#define FILE_ATTRIBUTE_TEMPORARY 0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE 0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT 0x00000400
#define FILE_ATTRIBUTE_COMPRESSED 0x00000800
#define FILE_ATTRIBUTE_OFFLINE 0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED 0x00004000
#define FILE_ATTRIBUTE_INTEGRITY_STREAM 0x00008000
#define FILE_ATTRIBUTE_VIRTUAL 0x00010000
#define FILE_ATTRIBUTE_NO_SCRUB_DATA 0x00020000
#define FILE_ATTRIBUTE_EA 0x00040000
#define FILE_ATTRIBUTE_PINNED 0x00080000
#define FILE_ATTRIBUTE_UNPINNED 0x00100000
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000
#define DELETE (0x00010000L)
#define FILE_FLAG_RANDOM_ACCESS 0x10000000
#define FILE_FLAG_SEQUENTIAL_SCAN 0x08000000

#define _FBINARY 0x10000
#define O_BINARY _FBINARY

int open(const char *name, int flags, ...)
{
    DbgPrint("LIBC: open %s\r\n", name);
    va_list ap;
    va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);
    unsigned int fileFlags = 0;
    unsigned int fileAccess = 0;
    unsigned int fileCreate = 0;
    unsigned int fileShare = FILE_SHARE_READ | FILE_SHARE_WRITE;
    unsigned int fileAttributes = FILE_ATTRIBUTE_NORMAL;

    if ((flags & O_BINARY) == 0)
        fileFlags |= FTEXT;

    switch (flags & (O_RDONLY | O_WRONLY | O_RDWR))
    {

    case O_RDONLY:
        fileAccess = GENERIC_READ;
        break;
    case O_WRONLY:
    {
        fileAccess = GENERIC_WRITE;
    }
    break;
    case O_RDWR:
        fileAccess = GENERIC_READ | GENERIC_WRITE;
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    switch (flags & (O_CREAT | O_EXCL | O_TRUNC))
    {
    case 0:
    case O_EXCL:
        fileCreate = OPEN_EXISTING;
        break;

    case O_CREAT:
        fileCreate = OPEN_ALWAYS;
        break;

    case O_CREAT | O_EXCL:
    case O_CREAT | O_TRUNC | O_EXCL:
        fileCreate = CREATE_NEW;
        break;

    case O_TRUNC:
    case O_TRUNC | O_EXCL:
        fileCreate = TRUNCATE_EXISTING;
        break;

    case O_CREAT | O_TRUNC:
        fileCreate = CREATE_ALWAYS;
        break;

    default:
        errno = EINVAL;
        return -1;
    }

    // COnvert to NtCreateFile
    switch (fileCreate)
    {
    case 1u:
        fileCreate = 2;
        break;
    case 2u:
        fileCreate = 5;
        break;
    case 3u:
        fileCreate = 1;
        break;
    case 4u:
        fileCreate = 3;
        break;
    default:
        if (fileCreate != 5 || (fileCreate = 4, (fileAccess & 0x40000000) == 0))
        {
            errno = EINVAL;
            return -1;
        }
        break;
    }

    STRING path;
    RtlInitAnsiString(&path, name);

    IO_STATUS_BLOCK ioblock;

    OBJECT_ATTRIBUTES o;
    o.RootDirectory = (void *)-3;
    o.Attributes = 64;
    o.ObjectName = &path;

    if ((fileAttributes & 0x4000000) != 0)
        fileAccess |= 0x10000u;

    unsigned int file = 0;
    NTSTATUS result = NtCreateFile(&file, fileAccess | 0x100080, &o, &ioblock, 0, fileAttributes & 0x7FA7, fileShare, fileCreate, fileAttributes);
    DbgPrint("NTCreateFile status: %d:%x\r\n", result, result);
    return file;
}
int read(int file, char *ptr, int len)
{
    DbgPrint("LIBC: read %d\r\n", file);
    return -1;
}

int stat(const char *file, struct stat *st)
{
    DbgPrint("LIBC: stat %s\r\n", file);
    return -1;
}

clock_t times(struct tms *buf)
{
    DbgPrint("LIBC: time\r\n");
    return -1;
}
int unlink(char *name)
{
    return -1;
}
int wait(int *status)
{
    return -1;
}
int write(int file, char *ptr, int len)
{
    DbgPrint("LIBC: write %d\r\n", file);
    if (file == 1 || file == 2)
    { // stdout or stderr
        RtlDebugPrintHelper(ptr, len);
        return len;
    }

    return -1;
}
int gettimeofday(struct timeval *p, void *z)
{
    return -1;
}

struct header
{
    size_t size;
    size_t real_size;
    unsigned is_free;
    struct header *next;
};

typedef struct header header_t;

static header_t *head = NULL, *tail = NULL;

static header_t *get_free_block(size_t size)
{
    header_t *curr = head;
    while (curr)
    {
        if (curr->is_free && curr->size >= size)
            return curr;
        curr = curr->next;
    }
    return NULL;
}

// TODO: this is not threadsafe and also doesnt use pages efficiently
void *malloc(size_t size)
{
    DbgPrint("LIBC: malloc: %d\r\n", size);
    size_t total_size;
    void *block = 0;
    header_t *header;

    if (!size)
        return NULL;

    header = get_free_block(size);
    if (header)
    {
        header->is_free = 0;
        return (void *)(header + 1);
    }

    total_size = sizeof(header_t) + size;

    NtAllocateVirtualMemory(&block, &total_size, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES | MEM_HEAP, PAGE_READWRITE, 0);

    if (block == NULL || block == (void *)-1)
    {
        return NULL;
    }

    header = (header_t *)block;
    header->size = size;
    header->is_free = 0;
    header->real_size = total_size;
    header->next = NULL;
    if (!head)
        head = header;
    if (tail)
        tail->next = header;
    tail = header;

    return (void *)(header + 1);
}

void *_malloc_r(struct _reent *r, size_t n)
{
    return malloc(n);
}

void free(void *block)
{
    DbgPrint("LIBC: free\r\n");
    header_t *header;

    if (!block)
        return;

    header = (header_t *)block - 1;

    if ((char *)block + header->size == (char *)tail + sizeof(header_t))
    {
        NtFreeVirtualMemory(&header, &header->real_size, MEM_RELEASE);
    }
    else
    {
        header->is_free = 1;
    }
}

void _free_r(struct _reent *r, void *p)
{
    free(p);
}

void *calloc(size_t num, size_t nsize)
{
    DbgPrint("LIBC: calloc: %d:%d\r\n", num, nsize);
    size_t size;
    void *block;

    if (!num || !nsize)
        return NULL;

    size = num * nsize;
    if (nsize != size / num)
        return NULL;

    block = malloc(size);
    if (!block)
        return NULL;

    memset(block, 0, size);
    return block;
}

void *
_calloc_r(struct _reent *ptr, size_t size, size_t len)
{
    return calloc(size, len);
}

void *realloc(void *block, size_t size)
{
    DbgPrint("LIBC: realloc: %d\r\n", size);
    header_t *header;
    void *ret;

    if (!block)
        return malloc(size);

    header = (header_t *)block - 1;
    if (header->size >= size)
        return block;

    ret = malloc(size);
    if (ret)
    {
        memcpy(ret, block, header->size);
        free(block);
    }
    return ret;
}

void *_realloc_r(struct _reent *r, void *p, size_t n) _NOTHROW
{
    return realloc(p, n);
}
