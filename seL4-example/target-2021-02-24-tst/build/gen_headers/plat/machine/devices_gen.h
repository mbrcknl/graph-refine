/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
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
#define PLIC_PPTR (KDEV_BASE + 0x0)

#ifndef __ASSEMBLER__
static const kernel_frame_t BOOT_RODATA kernel_devices[] = {
    /* /soc/interrupt-controller@c000000 */
    {
        0xc000000,
        PLIC_PPTR,
        false, /* userAvailable */
    },
    {
        0xc200000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x200000,
        false, /* userAvailable */
    },
    {
        0xc400000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x400000,
        false, /* userAvailable */
    },
    {
        0xc600000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x600000,
        false, /* userAvailable */
    },
    {
        0xc800000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x800000,
        false, /* userAvailable */
    },
    {
        0xca00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0xa00000,
        false, /* userAvailable */
    },
    {
        0xcc00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0xc00000,
        false, /* userAvailable */
    },
    {
        0xce00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0xe00000,
        false, /* userAvailable */
    },
    {
        0xd000000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x1000000,
        false, /* userAvailable */
    },
    {
        0xd200000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x1200000,
        false, /* userAvailable */
    },
    {
        0xd400000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x1400000,
        false, /* userAvailable */
    },
    {
        0xd600000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x1600000,
        false, /* userAvailable */
    },
    {
        0xd800000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x1800000,
        false, /* userAvailable */
    },
    {
        0xda00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x1a00000,
        false, /* userAvailable */
    },
    {
        0xdc00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x1c00000,
        false, /* userAvailable */
    },
    {
        0xde00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x1e00000,
        false, /* userAvailable */
    },
    {
        0xe000000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x2000000,
        false, /* userAvailable */
    },
    {
        0xe200000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x2200000,
        false, /* userAvailable */
    },
    {
        0xe400000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x2400000,
        false, /* userAvailable */
    },
    {
        0xe600000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x2600000,
        false, /* userAvailable */
    },
    {
        0xe800000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x2800000,
        false, /* userAvailable */
    },
    {
        0xea00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x2a00000,
        false, /* userAvailable */
    },
    {
        0xec00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x2c00000,
        false, /* userAvailable */
    },
    {
        0xee00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x2e00000,
        false, /* userAvailable */
    },
    {
        0xf000000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x3000000,
        false, /* userAvailable */
    },
    {
        0xf200000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x3200000,
        false, /* userAvailable */
    },
    {
        0xf400000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x3400000,
        false, /* userAvailable */
    },
    {
        0xf600000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x3600000,
        false, /* userAvailable */
    },
    {
        0xf800000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x3800000,
        false, /* userAvailable */
    },
    {
        0xfa00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x3a00000,
        false, /* userAvailable */
    },
    {
        0xfc00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x3c00000,
        false, /* userAvailable */
    },
    {
        0xfe00000,
        /* contains PLIC_PPTR */
        KDEV_BASE + 0x3e00000,
        false, /* userAvailable */
    },
};

/* PHYSICAL MEMORY */
static const p_region_t BOOT_RODATA avail_p_regs[] = {
    { 0x80200000, 0x280000000 }, /* /memory@80000000 */
};

#endif /* !__ASSEMBLER__ */

#endif /* __PLAT_DEVICES_GEN_H */