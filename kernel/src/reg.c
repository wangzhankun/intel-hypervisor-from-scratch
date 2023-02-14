#include "../include/global.h"
#include "../include/reg.h"

bool enableVMX(void)
{
    IA32_FEATURE_CONTROL_MSR_BITs feature_control_msr;

    // Read the feature control MSR
    rdmsrl(IA32_FEATURE_CONTROL_MSR, feature_control_msr.All);
    if (feature_control_msr.Fields.Lock)
    {
        if (feature_control_msr.Fields.EnableVmxon == 0)
        {
            LOG_ERR("VMX is locked and disabled by BIOS");
            return false;
        }
        else
        {
            LOG_INFO("VMX is locked and enabled by BIOS");
            return true;
        }
    }
    else
    {
        // enable VMX
        feature_control_msr.Fields.EnableVmxon = 1;
        feature_control_msr.Fields.Lock = 1;
        wrmsrl(IA32_FEATURE_CONTROL_MSR, feature_control_msr.All);
    }

    return true;
}

bool is_vmx_supported(void)
{
    unsigned int vmx_eax, vmx_ebx, vmx_ecx, vmx_edx;
    native_cpuid(&vmx_eax, &vmx_ebx, &vmx_ecx, &vmx_edx);
    return (vmx_ecx & (1 << 5)) != 0;
}




