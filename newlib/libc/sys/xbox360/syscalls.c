#include <sys/stat.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/times.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void _exit(int status) {

}
int close(int file) {
    return 0x60;
}
char **environ; /* pointer to array of char * strings that define the current environment variables */
int execve(char *name, char **argv, char **env) {
    return  0x69;
}
int fork() {
    return -1;
}
int fstat(int file, struct stat *st) {
    return -1;
}
int getpid() {
    return -1;
}
int isatty(int file) {
    return 0;
}
int kill(int pid, int sig) {
    return -1;
}
int link(char *old, char *new) {
    return -1;
}
int lseek(int file, int ptr, int dir) {
    return -1;
}
int open(const char *name, int flags, ...) {
    return -1;
}
int read(int file, char *ptr, int len) {
    return -1;
}
/*caddr_t sbrk(int incr) {
    return 0;
}*/

int stat(const char *file, struct stat *st) {
    return -1;
}
clock_t times(struct tms *buf) {
    return -1;
}
int unlink(char *name) {
    return -1;
}
int wait(int *status) {
    return -1;
}
int write(int file, char *ptr, int len) {
    return -1;
}
int gettimeofday(struct timeval *p, void *z) {
    return -1;
}


void free (void *ptr)
{
 // if (ptr)
  //  sys_free ((long long *)ptr - 1);
  *(int*)ptr = 0x88;
}


void *malloc (size_t size)
{
  return (void*)0xdeadbeef;
}

void *_malloc_r (struct _reent *r, size_t n)
{
  return malloc (n);
}

void _free_r (struct _reent *r, void *p)
{
  free (p);
}


void *
calloc (size_t size, size_t len)
{
  void *p = malloc (size * len);
  if (!p)
    return p;
  return memset (p, 0, size * len);
}

void *
_calloc_r (struct _reent *ptr, size_t size, size_t len)
{
  return calloc (size, len);
}


void *
realloc (void *old_ptr, size_t new_size)
{
  void *new_ptr = malloc (new_size);

  if (old_ptr && new_ptr)
    {
      size_t old_size = *(size_t *)((long long *)old_ptr - 1);
      size_t copy_size = old_size > new_size ? new_size : old_size;
      memcpy (new_ptr, old_ptr, copy_size);
      free (old_ptr);
    }

  return new_ptr;
}

void *_realloc_r (struct _reent *r, void *p, size_t n) _NOTHROW
{
  return realloc (p, n);
}
