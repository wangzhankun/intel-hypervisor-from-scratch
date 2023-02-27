#include "../include/global.h"
#include "../include/vmx.h"

BOOL allocateVMXRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    guest_state->VmxonRegionPhyAddr = 0;

    void *AlignedVirtualBuffer = get_zeroed_page(GFP_KERNEL);
    if (AlignedVirtualBuffer == 0)
    {
        LOG_ERR("allocate vmxon region failed");
        return false;
    }

    guest_state->VmxonRegionPhyAddr = __pa((void *)AlignedVirtualBuffer);

    return true;
}

BOOL allocateVMCSRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    guest_state->VmcsRegionPhyAddr = 0;

    void *AlignedVirtualBuffer = get_zeroed_page(GFP_KERNEL);
    if (AlignedVirtualBuffer == 0)
    {
        LOG_ERR("allocate vmcs region failed");
        return false;
    }

    guest_state->VmcsRegionPhyAddr = __pa(AlignedVirtualBuffer);
    return true;
}

bool allocateMsrBitmap(VIRTUAL_MACHINE_STATE *guest_state)
{
    // If the “use MSR bitmaps” VM-execution control is 1, bits 11:0 of the MSR-bitmap address must be 0. The
    // address should not set any bits beyond the processor’s physical-address width.
    void *AlignedVirtualBuffer = get_zeroed_page(GFP_KERNEL);
    if (AlignedVirtualBuffer == 0)
    {
        LOG_ERR("allocate msr bitmap failed");
        return false;
    }

    guest_state->MsrBitmap = (uint64_t)AlignedVirtualBuffer;
    guest_state->MsrBitmapPhysical = __pa(AlignedVirtualBuffer);

    return true;
}

void freeVMXRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (guest_state->VmxonRegionPhyAddr != 0)
    {
        free_pages(__va(guest_state->VmxonRegionPhyAddr), 0);
        guest_state->VmxonRegionPhyAddr = 0;
    }
}

void freeVMCSRegion(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (guest_state->VmcsRegionPhyAddr != 0)
    {
        free_pages(__va(guest_state->VmcsRegionPhyAddr), 0);
        guest_state->VmcsRegionPhyAddr = 0;
    }
}

void freeMsrBitmap(VIRTUAL_MACHINE_STATE *guest_state)
{
    if (guest_state->MsrBitmap != 0)
    {
        free_pages((void *)guest_state->MsrBitmap, 0);
        guest_state->MsrBitmap = 0;
    }
}
