#include <iostream>
#include <string>
#include <immintrin.h>
#include <cpuid.h>
#include <fcntl.h>
#include <unistd.h>
#include "../../lib/header.h"
#include <sys/mman.h>
#include <memory.h>
using namespace std;

const u64 GUEST_PHYS_MEMORY_BASE = 0;
const u64 GUEST_PHYS_MEMORY_SIZE = 1 << 23; // 8MB
const u64 GUEST_PT1 = 0x1000;
const u64 GUEST_PT2 = 0x2000;
const u64 GUEST_PT3 = 0x3000;
const u64 GUEST_ENTRY = 0x8000;
const u64 GUEST_STACK_TOP = 0x1000 * 256;

const u64 GUEST_DATA_REGION = GUEST_STACK_TOP + 0x1000;

struct PAGE_TABLE
{
    u64 entry[512];
};

void setupGuestPageTable(void *hva)
{
    // vol3 Table 4-15. Format of a PML4 Entry (PML4E) that References a Page-Directory-Pointer Table (Contd.)
    struct PAGE_TABLE *pt1 = (struct PAGE_TABLE *)(hva + GUEST_PT1);
    pt1->entry[0] = GUEST_PT2;
    pt1->entry[0] |= (1ULL) | (1ULL << 1);

    // VOL3 Table 4-17. Format of a Page-Directory-Pointer-Table Entry (PDPTE) that References a Page Directory
    struct PAGE_TABLE *pt2 = (struct PAGE_TABLE *)(hva + GUEST_PT2);
    pt2->entry[0] = GUEST_PT3;
    pt2->entry[0] |= (1ULL) | (1ULL << 1);

    struct PAGE_TABLE *pt3 = (struct PAGE_TABLE *)(hva + GUEST_PT3);
    for (int i = 0; i < 512; i++)
    {
        // each huge page is 2MB
        pt3->entry[i] = (GUEST_PHYS_MEMORY_BASE + i) << 21;
        pt3->entry[i] |= (1ULL) | (1ULL << 1) | (1ULL << 7);
    }
}

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

    // https://shell-storm.org/online/Online-Assembler-and-Disassembler
    unsigned char code[] = {
        // xor ebx, ebx
        // mov [0x9000], ebx
        // mov  eax, [0x9000]
        // cpuid
        // hlt
        0x31, 0xdb, 0x89, 0x1d, 0xf8, 0x8f, 0x00, 0x00, 0xa1, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xa2, 0xf4};

    ioctl(fd, HV_CREATE_VM, 0);

    void *hva = mmap(0, GUEST_PHYS_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    memset(hva, 0, GUEST_PHYS_MEMORY_SIZE);
    memcpy(hva + GUEST_ENTRY, code, sizeof(code));

    setupGuestPageTable(hva);

    struct HV_USERSPACE_MEM_REGION region = {
        .guest_phys_addr = 0,
        .userspace_addr = (uint64_t)hva,
        .size = GUEST_PHYS_MEMORY_SIZE,
        .flags = 0,
    };

    ioctl(fd, HV_MEM_INIT, &region);

    struct HV_VCPU vcpu;
    ioctl(fd, HV_GET_VCPU, &vcpu);

    vcpu.crs.cr3.All = GUEST_PT1;
    // vcpu.crs.cr0 = 0x60000010;
    // vcpu.crs.cr4 = 0x20;
    vcpu.regs.rip = GUEST_ENTRY;
    vcpu.regs.rsp = GUEST_STACK_TOP;

    ioctl(fd, HV_SET_VCPU, &vcpu);
    ioctl(fd, HV_RUN, NULL);

    close(fd);
    return 0;
}
