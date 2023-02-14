#ifndef __REG_H__
#define __REG_H__

#include <linux/types.h>
#include "./types.h"

#define IA32_FEATURE_CONTROL_MSR 0x3a
#define IA32_VMX_BASIC_MSR 0x480

typedef union _IA32_FEATURE_CONTROL_MSR_BITs
{
    uint64_t All;
    struct
    {
        uint64_t Lock : 1;               // [0]
        uint64_t EnableSMX : 1;          // [1]
        uint64_t EnableVmxon : 1;        // [2]
        uint64_t Reserved2 : 5;          // [3-7]
        uint64_t EnableLocalSENTER : 7;  // [8-14]
        uint64_t EnableGlobalSENTER : 1; // [15]
        uint64_t Reserved3a : 16;        //
        uint64_t Reserved3b : 32;        // [16-63]
    } Fields;
} IA32_FEATURE_CONTROL_MSR_BITs, *PIA32_FEATURE_CONTROL_MSR_BITs;

typedef union
{
    uint64_t All;
    struct 
    {
        uint64_t RevisionId : 31;
        uint64_t Reserved : 1;
        uint64_t RegionSize : 13;
        uint64_t RegionClear : 1;
        uint64_t Reserved2 : 16;
    } Fields;
} IA32_VMX_BASIC_MSR_BITs;


#define __FORCE_ORDER "m"(*(unsigned int *)0x1000UL)

static inline unsigned long _read_cr4(void)
{
    unsigned long val;
    asm volatile("mov %%cr4,%0\n\t"
                 : "=r"(val)
                 : __FORCE_ORDER);
    return val;
}
#define read_cr4() _read_cr4()

static inline void _write_cr4(unsigned long val)
{
    asm volatile("mov %0,%%cr4"
                 :
                 : "r"(val)
                 : "memory");
}
#define write_cr4(x) _write_cr4(x)


#endif // __REG_H__