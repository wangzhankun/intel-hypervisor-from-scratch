#include "../include/reg.h"
#include "../include/global.h"

BOOL enableVMX(void)
{
    IA32_FEATURE_CONTROL_MSR_BITs feature_control_msr;

    // Read the feature control MSR
    feature_control_msr.All = hyper_rdmsr(IA32_FEATURE_CONTROL_MSR);
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
        hyper_wrmsr(IA32_FEATURE_CONTROL_MSR, feature_control_msr.All);
    }

    return true;
}

BOOL is_vmx_supported(void)
{
    return this_cpu_has(X86_FEATURE_VMX);
}




