extern void crtinit();
extern void main();
extern void exit();
void _start(unsigned int Handle, unsigned int Reason, unsigned int Reserved)
{
    crtinit();
    main();
    exit();
}
