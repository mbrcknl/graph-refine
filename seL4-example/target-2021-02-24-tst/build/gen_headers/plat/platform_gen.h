/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef __RISCV_PLAT_H
#define __RISCV_PLAT_H

#include <config.h>
#define TIMER_CLOCK_HZ 1000000llu
#include <machine/interrupt.h>

/*
 * seL4 assigns all IRQs global interrupt numbers that are used in interrupt
 * invocations. On RISC-V we have 3 different types of interrupts: core timer,
 * core software generated, and global external IRQs delivered through the PLIC.
 * Only global external interrupts are available from user level and so it is
 * nice to be able to match PLIC IRQ numbers to seL4 IRQ numbers. The PLIC uses
 * IRQ 0 to refer to no IRQ pending and so we can also use 0 for irqInvalid in
 * the global IRQ number space and not have any aliasing issues. We then place
 * the kernel timer interrupts after the last PLIC interrupt and intend on
 * placing software generated interrupts after this in the future. As the kernel
 * timer and SGI interrupts are never seen outside of the kernel, it doesn't
 * matter what number they get assigned to as we can refer to them by their enum
 * field name.
 */
enum IRQConstants {
    PLIC_IRQ_OFFSET = 0,
    PLIC_MAX_IRQ = PLIC_IRQ_OFFSET + (53),
#ifdef ENABLE_SMP_SUPPORT
    INTERRUPT_IPI_0,
    INTERRUPT_IPI_1,
#endif
    INTERRUPT_CORE_TIMER,
    maxIRQ = INTERRUPT_CORE_TIMER,
} platform_interrupt_t;

enum irqNumbers {
    irqInvalid = 0
};

#define KERNEL_TIMER_IRQ INTERRUPT_CORE_TIMER
#define IRQ_CNODE_SLOT_BITS (6)

#include <drivers/irq/riscv_plic0.h>

#endif /* !__RISCV_PLAT_H */
