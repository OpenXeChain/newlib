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
#include <stdbool.h>

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
#define EPOCH_BIAS 116444736000000000ULL

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

typedef struct _RTL_CRITICAL_SECTION
{

    union
    {
        unsigned long *RawEvent[4];
    } Synchronization;
    long LockCount;
    long RecursionCount;
    unsigned long OwningThread;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

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
    unsigned long Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILETIME
{
    unsigned int dwHighDateTime;
    unsigned int dwLowDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

typedef struct _OBJECT_ATTRIBUTES
{
    void *RootDirectory;
    POBJECT_STRING ObjectName;
    unsigned long Attributes;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef union _LARGE_INTEGER
{
    struct
    {
        unsigned int HighPart;
        unsigned int LowPart;
    };
    long long QuadPart;
} LARGE_INTEGER;
typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 0x1,
    FileFullDirectoryInformation = 0x2,
    FileBothDirectoryInformation = 0x3,
    FileBasicInformation = 0x4, // FILE_BASIC_INFORMATION below
    FileStandardInformation = 0x5,
    FileInternalInformation = 0x6,
    FileEaInformation = 0x7,
    FileAccessInformation = 0x8,
    FileNameInformation = 0x9,
    FileRenameInformation = 0xa,
    FileLinkInformation = 0xb,
    FileNamesInformation = 0xc,
    FileDispositionInformation = 0xd, // use sdk FILE_DISPOSITION_INFO
    FilePositionInformation = 0xe,    // FILE_POSITION_INFORMATION below
    FileFullEaInformation = 0xf,
    FileModeInformation = 0x10,
    FileAlignmentInformation = 0x11,
    FileAllInformation = 0x12,
    FileAllocationInformation = 0x13, // use sdk FILE_ALLOCATION_INFO
    FileEndOfFileInformation = 0x14,  // use sdk FILE_END_OF_FILE_INFO
    FileAlternateNameInformation = 0x15,
    FileStreamInformation = 0x16,
    FileMountPartitionInformation = 0x17,
    FileMountPartitionsInformation = 0x18,
    FilePipeRemoteInformation = 0x19,
    FileSectorInformation = 0x1a,
    FileXctdCompressionInformation = 0x1b,
    FileCompressionInformation = 0x1c,
    FileObjectIdInformation = 0x1d,
    FileCompletionInformation = 0x1e,
    FileMoveClusterInformation = 0x1f,
    FileIoPriorityInformation = 0x20,
    FileReparsePointInformation = 0x21,
    FileNetworkOpenInformation = 0x22,
    FileAttributeTagInformation = 0x23,
    FileTrackingInformation = 0x24,
    FileMaximumInformation = 0x25
} FILE_INFORMATION_CLASS;

typedef enum _FSINFOCLASS 
{
    FileFsVolumeInformation = 0x1,
    FileFsLabelInformation = 0x2,
    FileFsSizeInformation = 0x3,
    FileFsDeviceInformation = 0x4,
    FileFsAttributeInformation = 0x5,
    FileFsControlInformation = 0x6,
    FileFsFullSizeInformation = 0x7,
    FileFsObjectIdInformation = 0x8,
    FileFsMaximumInformation = 0x9,
} FSINFOCLASS;

typedef void (*PIO_APC_ROUTINE)(void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, unsigned long Reserved);

//xboxkrnl
NTSTATUS NtAllocateVirtualMemory(void **lpAddress, size_t *dwSize, unsigned int flAllocationType, unsigned int flProtect, unsigned int dwMemoryRegionType);
NTSTATUS NtFreeVirtualMemory(void **BaseAddress, size_t *RegionSize, unsigned int FreeType);
NTSTATUS NtCreateFile(unsigned int *FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, unsigned int FileAttributes, unsigned int ShareAccess, unsigned int CreateDisposition, unsigned int CreateOptions);
NTSTATUS NtReadFile(unsigned int FileHandle, unsigned int Event, PIO_APC_ROUTINE ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, void *Buffer, unsigned int Length, PLARGE_INTEGER ByteOffset);
NTSTATUS NtWriteFile(unsigned int FileHandle, unsigned int Event, PIO_APC_ROUTINE ApcRoutine, void *ApcContext, PIO_STATUS_BLOCK IoStatusBlock, void *Buffer, unsigned int Length, PLARGE_INTEGER ByteOffset);
NTSTATUS NtClose(unsigned int Handle);
NTSTATUS NtOpenFile(unsigned int *FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, unsigned int ShareAccess, unsigned int OpenOptions);
NTSTATUS NtSetInformationFile(unsigned int FileHandle, PIO_STATUS_BLOCK IoStatusBlock, void *FileInformation, unsigned int Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS NtQueryInformationFile(unsigned int FileHandle, PIO_STATUS_BLOCK IoStatusBlock, void *FileInformation, unsigned int Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS NtQueryVolumeInformationFile(unsigned int FileHandle, PIO_STATUS_BLOCK IoStatusBlock, void *FileSystemInformation, unsigned int Length, FSINFOCLASS FileSystemInformationClass);
NTSTATUS NtWaitForSingleObjectEx(unsigned int Handle, unsigned int WaitMode, bool Alertable, PLARGE_INTEGER Timeout);

void RtlEnterCriticalSection(PRTL_CRITICAL_SECTION CriticalSection);
void RtlLeaveCriticalSection(PRTL_CRITICAL_SECTION CriticalSection);
unsigned int RtlTryEnterCriticalSection(PRTL_CRITICAL_SECTION CriticalSection);
void RtlInitializeCriticalSection(PRTL_CRITICAL_SECTION CriticalSection);
void RtlInitializeCriticalSectionAndSpinCount(PRTL_CRITICAL_SECTION CriticalSection, unsigned int SpinCount);

// Equal to GetSystemTimeAsFile
NTSTATUS KeQuerySystemTime(PFILETIME CurrentTime);

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

void RtlInitAnsiString(PSTRING DestinationString, char *SourceString);

void DbgPrint(const char *msg, ...);


//Xam
unsigned int SetFilePointer(unsigned int hFile, long lDistanceToMove, long* lpDistanceToMoveHigh, unsigned int dwMoveMethod);

__attribute__((naked)) void RtlDebugPrintHelper(char *buffer, unsigned int len)
{
    __asm__("twui 0, 0x14\n\t"
            "blr\n\t");
}

#define MAX_FDS 1024
unsigned int handle_table[MAX_FDS];
int next_fd = 3;
RTL_CRITICAL_SECTION handle_table_lock;

void init_handle_table()
{
    RtlInitializeCriticalSection(&handle_table_lock);
    for (int i = 0; i < MAX_FDS; ++i)
        handle_table[i] = 0;
    next_fd = 3;
}

int handle_to_fd(unsigned int h)
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

unsigned int fd_to_handle(int fd)
{
    if (fd < 3 || fd >= MAX_FDS)
        return -1;
    RtlEnterCriticalSection(&handle_table_lock);
    unsigned int h = handle_table[fd];
    RtlLeaveCriticalSection(&handle_table_lock);
    return h ? h : -1;
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
    DbgPrint("LIBC: exit %d\r\n", status);
}

int close(int file)
{
    DbgPrint("LIBC: Close %d:%d\n", file, fd_to_handle(file));
    NTSTATUS status = NtClose(fd_to_handle(file));
    close_fd(file);
    if (status >= 0)
        return 0;

    errno = EBADF;
    DbgPrint("LIBC: Close failed!: %d:%x\r\n", status);
    return -1;
}

char **environ;
int execve(char *name, char **argv, char **env)
{
    DbgPrint("LIBC: execve\r\n");
    return -1;
}
int fork()
{
    // Not a thing on 360
    return -1;
}
int fstat(int file, struct stat *st)
{
    DbgPrint("LIBC: fstat %d\r\n", file);
    return -1;
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
    DbgPrint("LIBC: lseek %d\r\n", file);
    unsigned int fileHandle = fd_to_handle(file);
    if(fileHandle == -1) {
        errno = EBADF;
        return -1;
    }

    return SetFilePointer(fileHandle, ptr, NULL, dir);
}

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
    DbgPrint("NTCreateFile status: %d:%x. Handle: %d\r\n", result, result, file);

    return handle_to_fd(file);
}

int read(int file, char *ptr, int len)
{
    DbgPrint("LIBC: read %d\r\n", file);
    unsigned int fileHandle = fd_to_handle(file);
    IO_STATUS_BLOCK block;
    NTSTATUS status = NtReadFile(fileHandle, 0, 0, 0, &block, ptr, len, 0);
    if (status == 259)
    { // Operation pending
        status = NtWaitForSingleObjectEx(fileHandle, 1u, false, 0);
        if (status < 0)
        {
            errno = EINVAL;
            return -1;
        }
    }

    if (status >= 0)
        return (int)block.Information;
    return -1;
}

int stat(const char *file, struct stat *st)
{
    DbgPrint("LIBC: stat %s\r\n", file);
    return -1;
}

clock_t times(struct tms *buf)
{
    DbgPrint("LIBC: times\r\n");
    return -1;
}

int unlink(char *name)
{
    STRING filePath;
    RtlInitAnsiString(&filePath, name);
    OBJECT_ATTRIBUTES obj;
    obj.RootDirectory = (void *)-3;
    obj.Attributes = 64;
    obj.ObjectName = &filePath;
    IO_STATUS_BLOCK io;
    unsigned int handle = 0;
    char fileInformation[4];
    fileInformation[0] = 1;
    NTSTATUS status = NtOpenFile(&handle, 0x10000u, &obj, &io, 7u, 0x4040u);
    if (status >= 0)
    {
        io.Information = 1;
        status = NtSetInformationFile(handle, &io, fileInformation, 1u, FileDispositionInformation);
        NtClose(handle);
        if (status >= 0)
            return 0;
    }
    return -1;
}

int wait(int *status)
{
    // Not a thing on 360
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

    unsigned int fileHandle = fd_to_handle(file);
    IO_STATUS_BLOCK block;
    NTSTATUS status = NtWriteFile(fileHandle, 0, 0, 0, &block, ptr, len, 0);
    if (status == 259)
    { // Operation pending
        status = NtWaitForSingleObjectEx(fileHandle, 1u, false, 0);
        if (status < 0)
        {
            errno = EINVAL;
            return -1;
        }
    }

    if (status >= 0)
        return (int)block.Information;

    return -1;
}

int gettimeofday(struct timeval *p, void *z)
{
    LARGE_INTEGER f;
    NTSTATUS status = KeQuerySystemTime(&f);
    if (status < 0)
        return -1;

    p->tv_sec = (f.QuadPart - EPOCH_BIAS) / 10000000;
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

void crtinit()
{
    init_handle_table();
}