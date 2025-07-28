#include <sys/stat.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/times.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <xecore/xboxkrnl.h>
#include <xecore/xam.h>

#define EPOCH_BIAS 116444736000000000ULL

#define FTEXT 0x80

#define _FBINARY 0x10000
#define O_BINARY _FBINARY

typedef uint32_t ACCESS_MASK;

// TODO: xbox 360
/*NTSYSAPI
EXPORTNUM(13)
DWORD
NTAPI
ExCreateThread(
    IN		PHANDLE pHandle,
    IN		DWORD dwStackSize,
    IN		LPDWORD lpThreadId,
    IN		PVOID apiThreadStartup,
    IN		LPTHREAD_START_ROUTINE lpStartAddress,
    IN		LPVOID lpParameter,
    IN		DWORD dwCreationFlagsMod
);*/

__attribute__((naked)) void RtlDebugPrintHelper(char *buffer, uint32_t len)
{
    __asm__("twui 0, 0x14\n\t"
            "blr\n\t");
}

bool GetFileInformationByHandle(HANDLE hFile, BY_HANDLE_FILE_INFORMATION *lpFileInformation)
{
    IO_STATUS_BLOCK io;
    FILE_FS_VOLUME_INFORMATION volumeInfo;
    FILE_INTERNAL_INFORMATION fileInternalInfo;
    FILE_NETWORK_OPEN_INFORMATION networkOpenInfo;
    lpFileInformation->nNumberOfLinks = 0;
    NTSTATUS status = NtQueryVolumeInformationFile(hFile, &io, &volumeInfo, sizeof(FILE_FS_VOLUME_INFORMATION), FileFsVolumeInformation);
    if (status < 0)
        return false;

    lpFileInformation->dwVolumeSerialNumber = volumeInfo.VolumeSerialNumber;

    status = NtQueryInformationFile(hFile, &io, &fileInternalInfo, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation);
    if (status < 0)
        return false;

    // File index
    lpFileInformation->nFileIndexHigh =
        (fileInternalInfo.IndexNumber & 0xFFFFFFFF00000000) >> 32;

    lpFileInformation->nFileIndexLow =
        fileInternalInfo.IndexNumber & 0x00000000FFFFFFFF;

    status = NtQueryInformationFile(hFile, &io, &networkOpenInfo, sizeof(FILE_NETWORK_OPEN_INFORMATION), FileNetworkOpenInformation);
    if (status < 0)
        return false;

    lpFileInformation->dwFileAttributes = networkOpenInfo.FileAttributes;

    // Creation time
    lpFileInformation->ftCreationTime.dwHighDateTime =
        (networkOpenInfo.CreationTime & 0xFFFFFFFF00000000) >> 32;

    lpFileInformation->ftCreationTime.dwLowDateTime =
        networkOpenInfo.CreationTime & 0x00000000FFFFFFFF;

    // Last access time
    lpFileInformation->ftLastAccessTime.dwHighDateTime =
        (networkOpenInfo.LastAccessTime & 0xFFFFFFFF00000000) >> 32;

    lpFileInformation->ftLastAccessTime.dwLowDateTime =
        networkOpenInfo.LastAccessTime & 0x00000000FFFFFFFF;

    // Last write time
    lpFileInformation->ftLastWriteTime.dwHighDateTime =
        (networkOpenInfo.LastWriteTime & 0xFFFFFFFF00000000) >> 32;

    lpFileInformation->ftLastWriteTime.dwLowDateTime =
        networkOpenInfo.LastWriteTime & 0x00000000FFFFFFFF;

    // File size
    lpFileInformation->nFileSizeHigh =
        (networkOpenInfo.AllocationSize & 0xFFFFFFFF00000000) >> 32;

    lpFileInformation->nFileSizeLow =
        networkOpenInfo.AllocationSize & 0x00000000FFFFFFFF;

    return true;
}

#define MAX_FDS 1024
HANDLE handle_table[MAX_FDS];
int next_fd = 3;
RTL_CRITICAL_SECTION handle_table_lock;

void init_handle_table()
{
    RtlInitializeCriticalSection(&handle_table_lock);
    for (int i = 0; i < MAX_FDS; ++i)
        handle_table[i] = 0;
    next_fd = 3;
}

int handle_to_fd(HANDLE h)
{
    RtlEnterCriticalSection(&handle_table_lock);
    for (int i = next_fd; i < MAX_FDS; ++i)
    {
        if (handle_table[i] == 0)
        {
            handle_table[i] = h;
            next_fd = i + 1;
            RtlLeaveCriticalSection(&handle_table_lock);
            return i;
        }
    }
    RtlLeaveCriticalSection(&handle_table_lock);
    return -1;
}

HANDLE fd_to_handle(int fd)
{
    if (fd < 3 || fd >= MAX_FDS)
        return (HANDLE)-1;
    RtlEnterCriticalSection(&handle_table_lock);
    HANDLE h = handle_table[fd];
    RtlLeaveCriticalSection(&handle_table_lock);
    return h ? h : (HANDLE)-1;
}

void close_fd(int fd)
{
    if (fd < 3 || fd >= MAX_FDS)
        return;
    RtlEnterCriticalSection(&handle_table_lock);
    if (handle_table[fd])
    {
        handle_table[fd] = 0;
        if (fd < next_fd)
            next_fd = fd;
    }
    RtlLeaveCriticalSection(&handle_table_lock);
}

void _exit(int status)
{
    // XamLoaderTerminateTitle seems more correct, but that always puts us back to
    // stock dashboard, instead of any custom dashboard which may be set.
    // Use XamLoaderLaunchTitle instead for better homebrew compatibility.
    XamLoaderLaunchTitle(NULL, 0);
}

int close(int file)
{
    bool result = CloseHandle(fd_to_handle(file));
    close_fd(file);

    return result ? 0 : -1;
}

char **environ;
int execve(char *name, char **argv, char **env)
{
    return -1;
}
int fork()
{
    // Not a thing on 360
    return -1;
}

//Todo: implement time conversion for create, access, write times
int fstat(int file, struct stat *st)
{
    BY_HANDLE_FILE_INFORMATION fileInformation;
    HANDLE fileHandle = fd_to_handle(file);
    bool success = GetFileInformationByHandle(fileHandle, &fileInformation);
    if (!success)
        return -1;

    st->st_ino = st->st_uid = st->st_gid = st->st_mode = 0;
    st->st_nlink = 1;

    if (fileInformation.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
        st->st_mode |= (_S_IREAD + (_S_IREAD >> 3) + (_S_IREAD >> 6));
    else
        st->st_mode |= ((_S_IREAD | _S_IWRITE) + ((_S_IREAD | _S_IWRITE) >> 3) + ((_S_IREAD | _S_IWRITE) >> 6));
#ifdef _USE_INT64
    st->st_size = ((__int64)(fileInformation.nFileSizeHigh)) * (0x100000000i64) +
                  (__int64)(fileInformation.nFileSizeLow);
#else
    st->st_size = fileInformation.nFileSizeLow;
#endif
    st->st_rdev = st->st_dev = 0;
    return 0;
}
int getpid()
{
    // Not a thing on 360
    return -1;
}

int isatty(int file)
{
    // Not a thing on 360
    return 0;
}

int kill(int pid, int sig)
{
    // Not a thing on 360
    return -1;
}
int link(char *old, char *new)
{
    // Not a thing on 360, there are no symlinks
    return -1;
}
int lseek(int file, int ptr, int dir)
{
    HANDLE fileHandle = fd_to_handle(file);
    if (fileHandle == -1)
    {
        errno = EBADF;
        return -1;
    }

    return SetFilePointer(fileHandle, ptr, NULL, dir);
}

int open(const char *name, int flags, ...)
{
    va_list ap;
    va_start(ap, flags);
    int mode = va_arg(ap, int);
    va_end(ap);
    uint32_t fileFlags = 0;
    uint32_t fileAccess = 0;
    uint32_t fileCreate = 0;
    uint32_t fileShare = FILE_SHARE_READ | FILE_SHARE_WRITE;
    uint32_t fileAttributes = FILE_ATTRIBUTE_NORMAL;

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

    HANDLE file = CreateFileA(name,
                              fileAccess,
                              fileShare,
                              NULL,
                              fileCreate,
                              fileAttributes,
                              NULL);

    return handle_to_fd(file);
}

int read(int file, char *ptr, int len)
{
    HANDLE fileHandle = fd_to_handle(file);

    uint32_t bytesRead = 0;
    bool success = ReadFile(fileHandle, ptr, len, &bytesRead, 0);

    if (success)
        return bytesRead;
    return -1;
}

int stat(const char *file, struct stat *st)
{
    int fd;

    fd = open(file, O_RDONLY);
    if (fd < 0)
    {
        return -1;
    }

    if (fstat(fd, st) < 0)
    {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

clock_t times(struct tms *buf)
{
    DbgPrint("LIBC: times\r\n");
    return -1;
}

int unlink(char *name)
{
    bool success = DeleteFileA(name);
    return success ? 0 : -1;
}

int wait(int *status)
{
    // Not a thing on 360
    return -1;
}

int write(int file, char *ptr, int len)
{
    if (file == 1 || file == 2)
    { // stdout or stderr
        RtlDebugPrintHelper(ptr, len);
        return len;
    }

    HANDLE fileHandle = fd_to_handle(file);
    uint32_t bytesWritten = 0;
    bool success = WriteFile(fileHandle, ptr, len, &bytesWritten, 0);

    if (success)
        return bytesWritten;

    return -1;
}

int gettimeofday(struct timeval *p, void *z)
{
    int64_t f;
    KeQuerySystemTime(&f);

    p->tv_sec = (f - EPOCH_BIAS) / 10000000;
    p->tv_usec = p->tv_usec * 1000000;
    return 0;
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
    header_t *header;

    if (!block)
        return;

    header = (header_t *)block - 1;

    if ((char *)block + header->size == (char *)tail + sizeof(header_t))
    {
        NtFreeVirtualMemory(&header, &header->real_size, MEM_RELEASE, 0);
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

void *_calloc_r(struct _reent *ptr, size_t size, size_t len)
{
    return calloc(size, len);
}

void *realloc(void *block, size_t size)
{
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

void crtinit()
{
    init_handle_table();
}
