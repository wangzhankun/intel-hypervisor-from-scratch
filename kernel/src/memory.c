#include "../include/global.h"
#include "../include/vmx.h"

BOOL allocateVMXRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    guest_state->VmxonRegion = 0;

    void *AlignedVirtualBuffer = get_zeroed_page(GFP_KERNEL);
    if (AlignedVirtualBuffer == 0)
    {
        LOG_ERR("allocate vmxon region failed");
        return false;
    }

    guest_state->VmxonRegion = __pa((void *)AlignedVirtualBuffer);

    return true;
}

BOOL allocateVMCSRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    guest_state->VmcsRegion = 0;

    void *AlignedVirtualBuffer = get_zeroed_page(GFP_KERNEL);
    if (AlignedVirtualBuffer == 0)
    {
        LOG_ERR("allocate vmcs region failed");
        return false;
    }


    guest_state->VmcsRegion = __pa(AlignedVirtualBuffer);
    return true;
}

void freeVMXRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (guest_state->VmxonRegion != 0)
    {
        free_pages(__va(guest_state->VmxonRegion), 0);
        guest_state->VmxonRegion = 0;
    }
}

void freeVMCSRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (guest_state->VmcsRegion != 0)
    {
        free_pages(__va(guest_state->VmcsRegion), 0);
        guest_state->VmcsRegion = 0;
    }
}

