-- add_requires("linux-headers", {system = true, configs = {driver_modules = true}})
-- add_packages("linux-headers")

target("myhypervisor")
    set_values("linux.driver.debug", true)
    add_cflags("-g -O0")
    add_rules("platform.linux.driver")
    set_values("linux.driver.linux-headers", "/lib/modules/5.15.0/build")
    add_files("src/*.c", "src/*.S")


    on_install("linux|x86_64", function (package)
        import("core.project.depend")
        local targetfile = package:targetfile() -- build/linux/x86_64/release/testdriver.ko

        -- 检测驱动是否已经安装，如果已经安装，先卸载
        local basename = package:basename()
        local modules = os.iorun("sudo lsmod")
        local installed = modules:match(basename)
        if installed then
            os.vrunv("sudo rmmod " .. basename)
        end
    

        os.vrunv("sudo insmod " .. targetfile)
        os.vrunv("sudo chmod 666 /dev/" .. basename)
    end)

    on_uninstall("linux|x86_64", function(package)
        import("core.project.depend")
        local targetfile = package:targetfile() -- build/linux/x86_64/release/testdriver.ko
        os.vrunv("sudo rmmod " .. targetfile)
    end)

target_end()
