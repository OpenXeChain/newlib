#include <stdlib.h>

extern void crtinit(); // newlib xbox 360 specific crt init
extern void __attribute__((weak)) main();
extern int __attribute__((weak)) DllMain(unsigned int Handle,
                                         unsigned int Reason,
                                         unsigned int Reserved);

typedef void (*func_ptr)(void);
extern func_ptr __CTOR_LIST__[]; // Compiler generated list of static cxx constructors
extern func_ptr __DTOR_LIST__[]; // Compiler generated list of static cxx deconstructors (to be implemented)

void __do_global_dtors(void) {
  static func_ptr *p = __DTOR_LIST__ + 1;

  while (*p) {
    (*(p))();
    p++;
  }
}

void __do_global_ctors(void) {
  unsigned int nptrs = (unsigned int)(ptrdiff_t)__CTOR_LIST__[0];
  unsigned int i;

  if (nptrs == (unsigned int)-1) {
    for (nptrs = 0; __CTOR_LIST__[nptrs + 1] != 0; nptrs++)
      ;
  }

  for (i = nptrs; i >= 1; i--) {
    __CTOR_LIST__[i]();
  }
}

static int initialized = 0;

void _start(unsigned int Handle, unsigned int Reason, unsigned int Reserved) {
  if (!initialized) {
    crtinit();
    __do_global_ctors();
    initialized = 1;
  }

  // If main == NULL, the main function does not exist.
  // Assume we're a DLL instead.
  if (!main) {
      DllMain(Handle, Reason, Reserved);
  } else {
      main();
      exit(0);
  }
}
