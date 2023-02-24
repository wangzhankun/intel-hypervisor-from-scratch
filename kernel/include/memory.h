#ifndef __MEMORY_H__
#define __MEMORY_H__

#include "./types.h"
#include "./vmx.h"


void freeMsrBitmap(VIRTUAL_MACHINE_STATE *guest_state);

void freeVMCSRegion(VIRTUAL_MACHINE_STATE *guest_state);

void freeVMXRegion(VIRTUAL_MACHINE_STATE *guest_state);

BOOL allocateVMCSRegion(VIRTUAL_MACHINE_STATE *guest_state);

BOOL allocateVMXRegion(VIRTUAL_MACHINE_STATE *guest_state);

bool allocateMsrBitmap(VIRTUAL_MACHINE_STATE *guest_state);
#endif // __MEMORY_H__