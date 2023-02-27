define addsym
    add-symbol-file  /home/wang/Documents/vmm/hypervisor-from-scatch/build/linux/x86_64/debug/myhypervisor.ko $arg0
    b kernel/src/VmExitHandler.c:397
    b kernel/src/vmx.c:356
    b initEPT2
    b handleVmcall
    b handleEPTViolation
    b eptVmxRootModePageHook
    b eptSplitLargePage
    b VmexitHandler
end
directory /home/wang/Documents/vmm/linux-5.15
directory /home/wang/Documents/vmm/hypervisor-from-scatch/build/linux/x86_64/debug
directory /home/wang/Documents/vmm/hypervisor-from-scatch
set serial baud 115200
target remote /tmp/serial4