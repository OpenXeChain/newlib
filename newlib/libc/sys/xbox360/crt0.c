extern void crtinit();
extern int DllMain(unsigned int Handle, unsigned int Reason, unsigned int Reserved);
void _start(unsigned int Handle, unsigned int Reason, unsigned int Reserved){
    crtinit();
    DllMain(Handle, Reason, Reserved);
}
