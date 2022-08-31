/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2022 Authors of KubeArmor */

#ifndef __VMLINUX_MACRO_H__
#define __VMLINUX_MACRO_H__

/* --------------------------------------------------------------
 * ## Missing macro/enum in vmlinux BTF (/sys/kernel/btf/vmlinux)
 * --------------------------------------------------------------
 * ### DWARF
 * ---------
 * 1) Macros in C will not part of DWARF section in an ELF file.
 * 2) When it comes to struct & enum of a C program, the decision to
 *    include them in the DWARF section of ELF file depends on whether
 *    the compiler thinks they will be useful during debugging.
 *    For example, due to compiler optimization or because of to the way
 *    the code is written, certain lines of code, struct and enums will
 *    become unreachable when the ELF file is executed and debugged. The
 *    compiler deems them as unnecessary debug_info and (by default) do
 *    not add such struct and enum in the DWARF section of the ELF file
 *    (unless `-fno-eliminate-unused-debug-types` flag is used).
 *
 * ### vmlinux BTF
 * ---------------
 * 1) `/sys/kernel/btf/vmlinux` file is usually generated from the DWARF
 *    section of the kernel image (vmlinux). So whatever apply to DWARF
 *    in general applies to vmlinux BTF as well.
 * 2) Macros in the kernel source will not part of vmlinux BTF [Ref 1]
 * 3) Kernel struct & enum may or may not be present in the vmlinux BTF
 *    unless the `BTF_TYPE_EMIT*` macros are explicity used on those
 *    struct and enum in the kernel source [Ref 2 and 3].
 * 
 * ### Reference
 * -------------
 * 1) https://lore.kernel.org/all/CAO658oV9AAcMMbVhjkoq5PtpvbVf41Cd_TBLCORTcf3trtwHfw@mail.gmail.com/T/
 * 2) https://lore.kernel.org/bpf/20210317174132.589276-1-yhs@fb.com/
 * 3) https://elixir.bootlin.com/linux/v5.19.4/source/include/linux/btf.h#L12
 *
 * -------------------------------------------------------------- */

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#endif

#define LINUX_VERSION_CODE KERNEL_VERSION(LINUX_VERSION_MAJOR,      \
                                          LINUX_VERSION_PATCHLEVEL, \
                                          LINUX_VERSION_SUBLEVEL)

/*
 * In some kernels (example - Debian 11 w/ kernel 5.10.0-17-amd64),
 * the BTF information for the below enum value is not present
 * in /sys/kernel/btf/vmlinux.
 */
#define PROC_PID_INIT_INO   0xEFFFFFFCU

/*
 * The following values are define as macro in the kernel until v5.6.19.
 * From 5.7, they are defined as enum values. 
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define BPF_ANY             0
#define BPF_F_CURRENT_CPU   0xffffffffULL
#endif

#endif
