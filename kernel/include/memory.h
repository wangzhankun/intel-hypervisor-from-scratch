#ifndef __MEMORY_H__
#define __MEMORY_H__

#include "./types.h"

typedef struct _VIRTUAL_MACHINE_STATE
{
    phys_addr_t VmxonRegion; // VMXON region
    phys_addr_t VmcsRegion;  // VMCS region
} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

// extern VIRTUAL_MACHINE_STATE* g_guest_state;

extern bool initVMX(void);
extern void exitVMX(void);

#endif // __MEMORY_H__