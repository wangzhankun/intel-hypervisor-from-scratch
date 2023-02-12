#include <iostream>
#include <string>
#include <immintrin.h>
#include <cpuid.h>
#include <fcntl.h>
#include <unistd.h>

using namespace std;

bool is_vmx_supported()
{
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    return (ecx & 0x00000020);
}

int main(int argc, char **argv)
{
    if(is_vmx_supported())
        cout << "VMX supported" << endl;
    else
        cout << "VMX not supported" << endl;

    int fd = open("/dev/hypervisor", O_RDWR);

    close(fd);
    return 0;
}
