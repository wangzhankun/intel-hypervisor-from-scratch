#include <iostream>
#include <string>
#include <immintrin.h>
#include <cpuid.h>
#include <fcntl.h>
#include <unistd.h>

using namespace std;

void printAppearance()
{
    printf("\n"

           "    _   _                             _                  _____                      ____                 _       _     \n"
           "   | | | |_   _ _ __   ___ _ ____   _(_)___  ___  _ __  |  ___| __ ___  _ __ ___   / ___|  ___ _ __ __ _| |_ ___| |__  \n"
           "   | |_| | | | | '_ \\ / _ \\ '__\\ \\ / / / __|/ _ \\| '__| | |_ | '__/ _ \\| '_ ` _ \\  \\___ \\ / __| '__/ _` | __/ __| '_ \\ \n"
           "   |  _  | |_| | |_) |  __/ |   \\ V /| \\__ \\ (_) | |    |  _|| | | (_) | | | | | |  ___) | (__| | | (_| | || (__| | | |\n"
           "   |_| |_|\\__, | .__/ \\___|_|    \\_/ |_|___/\\___/|_|    |_|  |_|  \\___/|_| |_| |_| |____/ \\___|_|  \\__,_|\\__\\___|_| |_|\n"
           "          |___/|_|                                                                                                     \n"

           "\n\n");
    unsigned int eax = 0x80000008, ebx, ecx, edx;
    __cpuid(0x80000008, eax, ebx, ecx, edx);
    printf("physical address width that the cpu can support is %d bits\n", eax & 0xff);
    sleep(1);
}

int main(int argc, char **argv)
{
    printAppearance();

    int fd = open("/dev/myhypervisor", O_RDWR);
    if (fd < 0)
    {
        cout << "Failed to open /dev/hypervisor" << endl;
        return -1;
    }

    // cout << "Press any key to stop the hypervisor" << endl;

    // char c;
    // cin >> c;

    close(fd);
    return 0;
}
