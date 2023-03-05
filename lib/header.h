#ifndef __LIB_HEADER__H__
#define __LIB_HEADER__H__

// 如何使用IOCTL https://blog.csdn.net/qq_19923217/article/details/82698787
// 这个是通用文件，内核和用户态都可以使用


// if  kernel mode
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
typedef uint64_t u64;
#endif

typedef union
{
	u64 All;
	struct
	{
		u64 PE : 1; // protected mode enable
		u64 MP : 1; // monitor coprocessor
		u64 EM : 1; // emulation
		u64 TS : 1; // task switched
		u64 ET : 1; // extension type
		u64 NE : 1; // numeric error
		u64 Reserved1 : 10;
		u64 WP : 1; // write protect
		u64 Reserved2 : 1;
		u64 AM : 1; // alignment mask
		u64 Reserved3 : 10;
		u64 NW : 1; // not write through
		u64 CD : 1; // cache disable
		u64 PG : 1; // paging
		u64 Reserved4 : 32;
	} Fields;
} CR0_BITS;

typedef union
{
	u64 All;
	struct
	{
		union
		{
			struct
			{
				u64 Reserved1 : 3;
				u64 PWT : 1; // page-level write-through
				u64 PCD : 1; // page-level cache disable
				u64 Reserved2 : 7;
			} CR4_PCIDE_0;
			struct
			{
				u64 PCID : 12;
			} CR4_PCIDE_1;
		};
		u64 PML4_PhysicallAddr : 42; // physical address extension
	} Fields;
} CR3_BITS;

typedef union
{
	u64 All;
	struct
	{
		u64 VME : 1;		//0 virtual 8086 mode extensions
		u64 PVI : 1;		//1 protected-mode virtual interrupts
		u64 TSD : 1;		//2 time stamp disable
		u64 DE : 1;			//3 debugging extensions
		u64 PSE : 1;		//4 page size extensions
		u64 PAE : 1;		//5 physical address extension
		u64 MCE : 1;		//6 machine check enable
		u64 PGE : 1;		//7 page global enable
		u64 PCE : 1;		//8 performance monitoring counter enable
		u64 OSFXSR : 1;		//9 os support for fxsave and fxrstor instructions
		u64 OSXMMEXCPT : 1; //10 os support for unmasked SIMD floating-point exceptions
		u64 UMIP : 1;//11 user-mode instruction prevention (SGDT, SIDT, SLDT, SMSW, STR are disabled in user mode)
		u64 Reserved1 : 1;//12
		u64 VMXE : 1; //13 vmx enable
		u64 SMXE : 1; //14 smx enable
		u64 Reserved2 : 1;//15
		u64 FSGSBASE : 1; //16 support for rd/wr fs/gs base instructions
		u64 PCIDE : 1;	  //17 process-context identifiers enable
		u64 OSXSAVE : 1;  //18 os support for xsave and xrestore instructions
		u64 Reserved3 : 1;//19
		u64 SMEP : 1; //20 supervisor mode execution prevention enable
		u64 SMAP : 1; //21 supervisor mode access prevention enable
		u64 PKE : 1;  //22 protection key enable for user-mode-pages
		u64 CET : 1;  //23 control-flow enforcement technology enable
		u64 PKS : 1;  //24 protection key enable for supervisor-mode-pages
		u64 Reserved4 : 39;

	} Fields;
} CR4_BITS;


struct HV_REGS{
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
};

struct HV_CRS{
    CR0_BITS cr0;
    uint64_t cr2;
    CR3_BITS cr3;
    CR4_BITS cr4;
    uint64_t cr8;
};  


struct HV_SREGS{
    uint16_t cs;
    uint16_t ds;
    uint16_t es;
    uint16_t fs;
    uint16_t gs;
    uint16_t ss;

    uint64_t tr;
    uint64_t ldt;
    
    uint64_t gdt_base;
    uint16_t gdt_limit;
    uint16_t gdt_ars;
    
    uint64_t idt_base;
    uint16_t idt_limit;
    uint16_t idt_ars;
};


struct HV_VCPU{
    struct HV_REGS regs;
    struct HV_CRS crs;
    struct HV_SREGS sregs;
};

struct HV_USERSPACE_MEM_REGION{
    uint64_t guest_phys_addr;//客户机物理地址
    uint64_t userspace_addr;// 用户空间地址
    uint64_t size;//大小
    uint64_t flags;//access right
};

#define IOCTL_MAGIC 'hv'

#define HV_CREATE_VM _IO(IOCTL_MAGIC, 0)

#define HV_MEM_INIT _IOW(IOCTL_MAGIC, 1, struct HV_USERSPACE_MEM_REGION)

#define HV_GET_VCPU _IOR(IOCTL_MAGIC, 2, struct HV_VCPU)
#define HV_SET_VCPU _IOW(IOCTL_MAGIC, 3, struct HV_VCPU)


#define HV_RUN _IO(IOCTL_MAGIC, 4)

#define HV_HLT _IO(IOCTL_MAGIC, 5)







#endif // __LIB_HEADER__H__