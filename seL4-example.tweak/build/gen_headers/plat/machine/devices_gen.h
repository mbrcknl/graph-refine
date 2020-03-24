/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */
/*
 * This file is autogenerated by kernel/tools/hardware_gen.py.
 */

#ifndef __PLAT_DEVICES_GEN_H
#define __PLAT_DEVICES_GEN_H
#include <linker.h>

#ifndef KDEV_BASE
#include <mode/hardware.h>
#endif

#define physBase 0x80000000

/* INTERRUPTS */
/* KERNEL DEVICES */

#ifndef __ASSEMBLER__
static const kernel_frame_t BOOT_RODATA *kernel_devices = NULL;

/* PHYSICAL MEMORY */
static const p_region_t BOOT_RODATA avail_p_regs[] = {
    { 0x80200000, 0x17ff00000 }, /* /memory@80000000 */
};

#endif /* !__ASSEMBLER__ */

#endif /* __PLAT_DEVICES_GEN_H */