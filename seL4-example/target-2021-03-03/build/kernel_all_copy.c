#line 1 "/home/koc034/Documents/newver/seL4/src/api/faults.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <types.h>
#include <api/faults.h>
#include <api/syscall.h>
#include <kernel/thread.h>
#include <arch/kernel/thread.h>
#include <machine/debug.h>
#ifdef CONFIG_KERNEL_MCS
#include <mode/api/ipc_buffer.h>
#include <object/schedcontext.h>
#endif

/* consistency with libsel4 */
compile_assert(InvalidRoot, lookup_fault_invalid_root + 1 == seL4_InvalidRoot)
compile_assert(MissingCapability, lookup_fault_missing_capability + 1 == seL4_MissingCapability)
compile_assert(DepthMismatch, lookup_fault_depth_mismatch + 1 == seL4_DepthMismatch)
compile_assert(GuardMismatch, lookup_fault_guard_mismatch + 1 == seL4_GuardMismatch)
compile_assert(seL4_UnknownSyscall_Syscall, (word_t) n_syscallMessage == seL4_UnknownSyscall_Syscall)
compile_assert(seL4_UserException_Number, (word_t) n_exceptionMessage == seL4_UserException_Number)
compile_assert(seL4_UserException_Code, (word_t) n_exceptionMessage + 1 == seL4_UserException_Code)

static inline unsigned int
setMRs_lookup_failure(tcb_t *receiver, word_t *receiveIPCBuffer,
                      lookup_fault_t luf, unsigned int offset)
{
    word_t lufType = lookup_fault_get_lufType(luf);
    word_t i;

    i = setMR(receiver, receiveIPCBuffer, offset, lufType + 1);

    /* check constants match libsel4 */
    if (offset == seL4_CapFault_LookupFailureType) {
        assert(offset + 1 == seL4_CapFault_BitsLeft);
        assert(offset + 2 == seL4_CapFault_DepthMismatch_BitsFound);
        assert(offset + 2 == seL4_CapFault_GuardMismatch_GuardFound);
        assert(offset + 3 == seL4_CapFault_GuardMismatch_BitsFound);
    } else {
        assert(offset == 1);
    }

    switch (lufType) {
    case lookup_fault_invalid_root:
        return i;

    case lookup_fault_missing_capability:
        return setMR(receiver, receiveIPCBuffer, offset + 1,
                     lookup_fault_missing_capability_get_bitsLeft(luf));

    case lookup_fault_depth_mismatch:
        setMR(receiver, receiveIPCBuffer, offset + 1,
              lookup_fault_depth_mismatch_get_bitsLeft(luf));
        return setMR(receiver, receiveIPCBuffer, offset + 2,
                     lookup_fault_depth_mismatch_get_bitsFound(luf));

    case lookup_fault_guard_mismatch:
        setMR(receiver, receiveIPCBuffer, offset + 1,
              lookup_fault_guard_mismatch_get_bitsLeft(luf));
        setMR(receiver, receiveIPCBuffer, offset + 2,
              lookup_fault_guard_mismatch_get_guardFound(luf));
        return setMR(receiver, receiveIPCBuffer, offset + 3,
                     lookup_fault_guard_mismatch_get_bitsFound(luf));

    default:
        fail("Invalid lookup failure");
    }
}

static inline void copyMRsFaultReply(tcb_t *sender, tcb_t *receiver, MessageID_t id, word_t length)
{
    word_t i;
    bool_t archInfo;

    archInfo = Arch_getSanitiseRegisterInfo(receiver);

    for (i = 0; i < MIN(length, n_msgRegisters); i++) {
        register_t r = fault_messages[id][i];
        word_t v = getRegister(sender, msgRegisters[i]);
        setRegister(receiver, r, sanitiseRegister(r, v, archInfo));
    }

    if (i < length) {
        word_t *sendBuf = lookupIPCBuffer(false, sender);
        if (sendBuf) {
            for (; i < length; i++) {
                register_t r = fault_messages[id][i];
                word_t v = sendBuf[i + 1];
                setRegister(receiver, r, sanitiseRegister(r, v, archInfo));
            }
        }
    }
}

static inline void copyMRsFault(tcb_t *sender, tcb_t *receiver, MessageID_t id,
                                word_t length, word_t *receiveIPCBuffer)
{
    word_t i;
    for (i = 0; i < MIN(length, n_msgRegisters); i++) {
        setRegister(receiver, msgRegisters[i], getRegister(sender, fault_messages[id][i]));
    }

    if (receiveIPCBuffer) {
        for (; i < length; i++) {
            receiveIPCBuffer[i + 1] = getRegister(sender, fault_messages[id][i]);
        }
    }
}

bool_t handleFaultReply(tcb_t *receiver, tcb_t *sender)
{
    /* These lookups are moved inward from doReplyTransfer */
    seL4_MessageInfo_t tag = messageInfoFromWord(getRegister(sender, msgInfoRegister));
    word_t label = seL4_MessageInfo_get_label(tag);
    word_t length = seL4_MessageInfo_get_length(tag);
    seL4_Fault_t fault = receiver->tcbFault;

    switch (seL4_Fault_get_seL4_FaultType(fault)) {
    case seL4_Fault_CapFault:
        return true;

    case seL4_Fault_UnknownSyscall:
        copyMRsFaultReply(sender, receiver, MessageID_Syscall, MIN(length, n_syscallMessage));
        return (label == 0);

    case seL4_Fault_UserException:
        copyMRsFaultReply(sender, receiver, MessageID_Exception, MIN(length, n_exceptionMessage));
        return (label == 0);

#ifdef CONFIG_KERNEL_MCS
    case seL4_Fault_Timeout:
        copyMRsFaultReply(sender, receiver, MessageID_TimeoutReply, MIN(length, n_timeoutMessage));
        return (label == 0);
#endif
#ifdef CONFIG_HARDWARE_DEBUG_API
    case seL4_Fault_DebugException: {
        word_t n_instrs;

        if (seL4_Fault_DebugException_get_exceptionReason(fault) != seL4_SingleStep) {
            /* Only single-step replies are required to set message registers.
             */
            return (label == 0);
        }

        if (length < DEBUG_REPLY_N_EXPECTED_REGISTERS) {
            /* A single-step reply doesn't mean much if it isn't composed of the bp
             * number and number of instructions to skip. But even if both aren't
             * set, we can still allow the thread to continue because replying
             * should uniformly resume thread execution, based on the general seL4
             * API model.
             *
             * If it was single-step, but no reply registers were set, just
             * default to skipping 1 and continuing.
             *
             * On x86, bp_num actually doesn't matter for single-stepping
             * because single-stepping doesn't use a hardware register -- it
             * uses EFLAGS.TF.
             */
            n_instrs = 1;
        } else {
            /* If the reply had all expected registers set, proceed as normal */
            n_instrs = getRegister(sender, msgRegisters[0]);
        }

        syscall_error_t res;

        res = Arch_decodeConfigureSingleStepping(receiver, 0, n_instrs, true);
        if (res.type != seL4_NoError) {
            return false;
        };

        configureSingleStepping(receiver, 0, n_instrs, true);

        /* Replying will always resume the thread: the only variant behaviour
         * is whether or not the thread will be resumed with stepping still
         * enabled.
         */
        return (label == 0);
    }
#endif

    default:
        return Arch_handleFaultReply(receiver, sender, seL4_Fault_get_seL4_FaultType(fault));
    }
}

word_t setMRs_fault(tcb_t *sender, tcb_t *receiver, word_t *receiveIPCBuffer)
{
    switch (seL4_Fault_get_seL4_FaultType(sender->tcbFault)) {
    case seL4_Fault_CapFault:
        setMR(receiver, receiveIPCBuffer, seL4_CapFault_IP, getRestartPC(sender));
        setMR(receiver, receiveIPCBuffer, seL4_CapFault_Addr,
              seL4_Fault_CapFault_get_address(sender->tcbFault));
        setMR(receiver, receiveIPCBuffer, seL4_CapFault_InRecvPhase,
              seL4_Fault_CapFault_get_inReceivePhase(sender->tcbFault));
        return setMRs_lookup_failure(receiver, receiveIPCBuffer,
                                     sender->tcbLookupFailure, seL4_CapFault_LookupFailureType);

    case seL4_Fault_UnknownSyscall: {
        copyMRsFault(sender, receiver, MessageID_Syscall, n_syscallMessage,
                     receiveIPCBuffer);

        return setMR(receiver, receiveIPCBuffer, n_syscallMessage,
                     seL4_Fault_UnknownSyscall_get_syscallNumber(sender->tcbFault));
    }

    case seL4_Fault_UserException: {
        copyMRsFault(sender, receiver, MessageID_Exception,
                     n_exceptionMessage, receiveIPCBuffer);
        setMR(receiver, receiveIPCBuffer, n_exceptionMessage,
              seL4_Fault_UserException_get_number(sender->tcbFault));
        return setMR(receiver, receiveIPCBuffer, n_exceptionMessage + 1u,
                     seL4_Fault_UserException_get_code(sender->tcbFault));
    }

#ifdef CONFIG_KERNEL_MCS
    case seL4_Fault_Timeout: {
        word_t len = setMR(receiver, receiveIPCBuffer, seL4_Timeout_Data,
                           seL4_Fault_Timeout_get_badge(sender->tcbFault));
        if (sender->tcbSchedContext) {
            time_t consumed = schedContext_updateConsumed(sender->tcbSchedContext);
            return mode_setTimeArg(len, consumed,
                                   receiveIPCBuffer, receiver);
        } else {
            return len;
        }
    }
#endif
#ifdef CONFIG_HARDWARE_DEBUG_API
    case seL4_Fault_DebugException: {
        word_t reason = seL4_Fault_DebugException_get_exceptionReason(sender->tcbFault);

        setMR(receiver, receiveIPCBuffer,
              seL4_DebugException_FaultIP, getRestartPC(sender));
        unsigned int ret = setMR(receiver, receiveIPCBuffer,
                                 seL4_DebugException_ExceptionReason, reason);

        if (reason != seL4_SingleStep && reason != seL4_SoftwareBreakRequest) {
            ret = setMR(receiver, receiveIPCBuffer,
                        seL4_DebugException_TriggerAddress,
                        seL4_Fault_DebugException_get_breakpointAddress(sender->tcbFault));

            /* Breakpoint messages also set a "breakpoint number" register. */
            ret = setMR(receiver, receiveIPCBuffer,
                        seL4_DebugException_BreakpointNumber,
                        seL4_Fault_DebugException_get_breakpointNumber(sender->tcbFault));
        }
        return ret;
    }
#endif /* CONFIG_HARDWARE_DEBUG_API */

    default:
        return Arch_setMRs_fault(sender, receiver, receiveIPCBuffer,
                                 seL4_Fault_get_seL4_FaultType(sender->tcbFault));
    }
}
#line 1 "/home/koc034/Documents/newver/seL4/src/api/syscall.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <types.h>
#include <benchmark/benchmark.h>
#include <arch/benchmark.h>
#include <benchmark/benchmark_track.h>
#include <benchmark/benchmark_utilisation.h>
#include <api/syscall.h>
#include <api/failures.h>
#include <api/faults.h>
#include <kernel/cspace.h>
#include <kernel/faulthandler.h>
#include <kernel/thread.h>
#include <kernel/vspace.h>
#include <machine/io.h>
#include <plat/machine/hardware.h>
#include <object/interrupt.h>
#include <model/statedata.h>
#include <string.h>
#include <kernel/traps.h>
#include <arch/machine.h>

#ifdef CONFIG_DEBUG_BUILD
#include <arch/machine/capdl.h>
#endif

/* The haskell function 'handleEvent' is split into 'handleXXX' variants
 * for each event causing a kernel entry */

exception_t handleInterruptEntry(void)
{
    irq_t irq;

    irq = getActiveIRQ();
#ifdef CONFIG_KERNEL_MCS
    if (SMP_TERNARY(clh_is_self_in_queue(), 1)) {
        updateTimestamp();
        checkBudget();
    }
#endif

    if (IRQT_TO_IRQ(irq) != IRQT_TO_IRQ(irqInvalid)) {
        handleInterrupt(irq);
        Arch_finaliseInterrupt();
    } else {
#ifdef CONFIG_IRQ_REPORTING
        userError("Spurious interrupt!");
#endif
        handleSpuriousIRQ();
    }

#ifdef CONFIG_KERNEL_MCS
    if (SMP_TERNARY(clh_is_self_in_queue(), 1)) {
#endif
        schedule();
        activateThread();
#ifdef CONFIG_KERNEL_MCS
    }
#endif

    return EXCEPTION_NONE;
}

exception_t handleUnknownSyscall(word_t w)
{
#ifdef CONFIG_PRINTING
    if (w == SysDebugPutChar) {
        kernel_putchar(getRegister(NODE_STATE(ksCurThread), capRegister));
        return EXCEPTION_NONE;
    }
    if (w == SysDebugDumpScheduler) {
#ifdef CONFIG_DEBUG_BUILD
        debug_dumpScheduler();
#endif
        return EXCEPTION_NONE;
    }
#endif
#ifdef CONFIG_DEBUG_BUILD
    if (w == SysDebugHalt) {
        tcb_t *UNUSED tptr = NODE_STATE(ksCurThread);
        printf("Debug halt syscall from user thread %p \"%s\"\n", tptr, TCB_PTR_DEBUG_PTR(tptr)->tcbName);
        halt();
    }
    if (w == SysDebugSnapshot) {
#if defined CONFIG_ARCH_ARM || defined CONFIG_ARCH_X86_64 || defined CONFIG_ARCH_RISCV32
        tcb_t *UNUSED tptr = NODE_STATE(ksCurThread);
        printf("Debug snapshot syscall from user thread %p \"%s\"\n", tptr, TCB_PTR_DEBUG_PTR(tptr)->tcbName);
        capDL();
#else
        printf("Debug snapshot syscall not supported for the current arch\n");
#endif
        return EXCEPTION_NONE;
    }
    if (w == SysDebugCapIdentify) {
        word_t cptr = getRegister(NODE_STATE(ksCurThread), capRegister);
        lookupCapAndSlot_ret_t lu_ret = lookupCapAndSlot(NODE_STATE(ksCurThread), cptr);
        word_t cap_type = cap_get_capType(lu_ret.cap);
        setRegister(NODE_STATE(ksCurThread), capRegister, cap_type);
        return EXCEPTION_NONE;
    }

    if (w == SysDebugNameThread) {
        /* This is a syscall meant to aid debugging, so if anything goes wrong
         * then assume the system is completely misconfigured and halt */
        const char *name;
        word_t len;
        word_t cptr = getRegister(NODE_STATE(ksCurThread), capRegister);
        lookupCapAndSlot_ret_t lu_ret = lookupCapAndSlot(NODE_STATE(ksCurThread), cptr);
        /* ensure we got a TCB cap */
        word_t cap_type = cap_get_capType(lu_ret.cap);
        if (cap_type != cap_thread_cap) {
            userError("SysDebugNameThread: cap is not a TCB, halting");
            halt();
        }
        /* Add 1 to the IPC buffer to skip the message info word */
        name = (const char *)(lookupIPCBuffer(true, NODE_STATE(ksCurThread)) + 1);
        if (!name) {
            userError("SysDebugNameThread: Failed to lookup IPC buffer, halting");
            halt();
        }
        /* ensure the name isn't too long */
        len = strnlen(name, seL4_MsgMaxLength * sizeof(word_t));
        if (len == seL4_MsgMaxLength * sizeof(word_t)) {
            userError("SysDebugNameThread: Name too long, halting");
            halt();
        }
        setThreadName(TCB_PTR(cap_thread_cap_get_capTCBPtr(lu_ret.cap)), name);
        return EXCEPTION_NONE;
    }
#if defined ENABLE_SMP_SUPPORT && defined CONFIG_ARCH_ARM
    if (w == SysDebugSendIPI) {
        seL4_Word target = getRegister(NODE_STATE(ksCurThread), capRegister);
        seL4_Word irq = getRegister(NODE_STATE(ksCurThread), msgInfoRegister);

        if (target > CONFIG_MAX_NUM_NODES) {
            userError("SysDebugSendIPI: Invalid target, halting");
            halt();
        }
        if (irq > 15) {
            userError("SysDebugSendIPI: Invalid IRQ, not a SGI, halting");
            halt();
        }

        ipi_send_target(CORE_IRQ_TO_IRQT(0, irq), BIT(target));
        return EXCEPTION_NONE;
    }
#endif /* ENABLE_SMP_SUPPORT && CONFIG_ARCH_ARM */
#endif /* CONFIG_DEBUG_BUILD */

#ifdef CONFIG_DANGEROUS_CODE_INJECTION
    if (w == SysDebugRun) {
        ((void (*)(void *))getRegister(NODE_STATE(ksCurThread), capRegister))((void *)getRegister(NODE_STATE(ksCurThread),
                                                                                                  msgInfoRegister));
        return EXCEPTION_NONE;
    }
#endif

#ifdef CONFIG_KERNEL_X86_DANGEROUS_MSR
    if (w == SysX86DangerousWRMSR) {
        uint64_t val;
        uint32_t reg = getRegister(NODE_STATE(ksCurThread), capRegister);
        if (CONFIG_WORD_SIZE == 32) {
            val = (uint64_t)getSyscallArg(0, NULL) | ((uint64_t)getSyscallArg(1, NULL) << 32);
        } else {
            val = getSyscallArg(0, NULL);
        }
        x86_wrmsr(reg, val);
        return EXCEPTION_NONE;
    } else if (w == SysX86DangerousRDMSR) {
        uint64_t val;
        uint32_t reg = getRegister(NODE_STATE(ksCurThread), capRegister);
        val = x86_rdmsr(reg);
        int num = 1;
        if (CONFIG_WORD_SIZE == 32) {
            setMR(NODE_STATE(ksCurThread), NULL, 0, val & 0xffffffff);
            setMR(NODE_STATE(ksCurThread), NULL, 1, val >> 32);
            num++;
        } else {
            setMR(NODE_STATE(ksCurThread), NULL, 0, val);
        }
        setRegister(NODE_STATE(ksCurThread), msgInfoRegister, wordFromMessageInfo(seL4_MessageInfo_new(0, 0, 0, num)));
        return EXCEPTION_NONE;
    }
#endif

#ifdef CONFIG_ENABLE_BENCHMARKS
    if (w == SysBenchmarkFlushCaches) {
#ifdef CONFIG_ARCH_ARM
        tcb_t *thread = NODE_STATE(ksCurThread);
        if (getRegister(thread, capRegister)) {
            arch_clean_invalidate_L1_caches(getRegister(thread, msgInfoRegister));
        } else {
            arch_clean_invalidate_caches();
        }
#else
        arch_clean_invalidate_caches();
#endif
        return EXCEPTION_NONE;
    } else if (w == SysBenchmarkResetLog) {
#ifdef CONFIG_KERNEL_LOG_BUFFER
        if (ksUserLogBuffer == 0) {
            userError("A user-level buffer has to be set before resetting benchmark.\
                    Use seL4_BenchmarkSetLogBuffer\n");
            setRegister(NODE_STATE(ksCurThread), capRegister, seL4_IllegalOperation);
            return EXCEPTION_SYSCALL_ERROR;
        }

        ksLogIndex = 0;
#endif /* CONFIG_KERNEL_LOG_BUFFER */
#ifdef CONFIG_BENCHMARK_TRACK_UTILISATION
        NODE_STATE(benchmark_log_utilisation_enabled) = true;
        benchmark_track_reset_utilisation(NODE_STATE(ksIdleThread));
        NODE_STATE(ksCurThread)->benchmark.schedule_start_time = ksEnter;
        NODE_STATE(ksCurThread)->benchmark.number_schedules++;

        NODE_STATE(benchmark_start_time) = ksEnter;
        NODE_STATE(benchmark_kernel_time) = 0;
        NODE_STATE(benchmark_kernel_number_entries) = 0;
        NODE_STATE(benchmark_kernel_number_schedules) = 1;
        benchmark_arch_utilisation_reset();
#endif /* CONFIG_BENCHMARK_TRACK_UTILISATION */
        setRegister(NODE_STATE(ksCurThread), capRegister, seL4_NoError);
        return EXCEPTION_NONE;
    } else if (w == SysBenchmarkFinalizeLog) {
#ifdef CONFIG_KERNEL_LOG_BUFFER
        ksLogIndexFinalized = ksLogIndex;
        setRegister(NODE_STATE(ksCurThread), capRegister, ksLogIndexFinalized);
#endif /* CONFIG_KERNEL_LOG_BUFFER */
#ifdef CONFIG_BENCHMARK_TRACK_UTILISATION
        benchmark_utilisation_finalise();
#endif /* CONFIG_BENCHMARK_TRACK_UTILISATION */
        return EXCEPTION_NONE;
    } else if (w == SysBenchmarkSetLogBuffer) {
#ifdef CONFIG_KERNEL_LOG_BUFFER
        word_t cptr_userFrame = getRegister(NODE_STATE(ksCurThread), capRegister);

        if (benchmark_arch_map_logBuffer(cptr_userFrame) != EXCEPTION_NONE) {
            setRegister(NODE_STATE(ksCurThread), capRegister, seL4_IllegalOperation);
            return EXCEPTION_SYSCALL_ERROR;
        }

        setRegister(NODE_STATE(ksCurThread), capRegister, seL4_NoError);
        return EXCEPTION_NONE;
#endif /* CONFIG_KERNEL_LOG_BUFFER */
    }

#ifdef CONFIG_BENCHMARK_TRACK_UTILISATION
    else if (w == SysBenchmarkGetThreadUtilisation) {
        benchmark_track_utilisation_dump();
        return EXCEPTION_NONE;
    } else if (w == SysBenchmarkResetThreadUtilisation) {
        word_t tcb_cptr = getRegister(NODE_STATE(ksCurThread), capRegister);
        lookupCap_ret_t lu_ret;
        word_t cap_type;

        lu_ret = lookupCap(NODE_STATE(ksCurThread), tcb_cptr);
        /* ensure we got a TCB cap */
        cap_type = cap_get_capType(lu_ret.cap);
        if (cap_type != cap_thread_cap) {
            userError("SysBenchmarkResetThreadUtilisation: cap is not a TCB, halting");
            return EXCEPTION_NONE;
        }

        tcb_t *tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(lu_ret.cap));

        benchmark_track_reset_utilisation(tcb);
        return EXCEPTION_NONE;
    }
#ifdef CONFIG_DEBUG_BUILD
    else if (w == SysBenchmarkDumpAllThreadsUtilisation) {
        printf("{\n");
        printf("  \"BENCHMARK_TOTAL_UTILISATION\":%lu,\n",
               (word_t)(NODE_STATE(benchmark_end_time) - NODE_STATE(benchmark_start_time)));
        printf("  \"BENCHMARK_TOTAL_KERNEL_UTILISATION\":%lu,\n", (word_t) NODE_STATE(benchmark_kernel_time));
        printf("  \"BENCHMARK_TOTAL_NUMBER_KERNEL_ENTRIES\":%lu,\n", (word_t) NODE_STATE(benchmark_kernel_number_entries));
        printf("  \"BENCHMARK_TOTAL_NUMBER_SCHEDULES\":%lu,\n", (word_t) NODE_STATE(benchmark_kernel_number_schedules));
        printf("  \"BENCHMARK_TCB_\": [\n");
        for (tcb_t *curr = NODE_STATE(ksDebugTCBs); curr != NULL; curr = TCB_PTR_DEBUG_PTR(curr)->tcbDebugNext) {
            printf("    {\n");
            printf("      \"NAME\":\"%s\",\n", TCB_PTR_DEBUG_PTR(curr)->tcbName);
            printf("      \"UTILISATION\":%lu,\n", (word_t) curr->benchmark.utilisation);
            printf("      \"NUMBER_SCHEDULES\":%lu,\n", (word_t) curr->benchmark.number_schedules);
            printf("      \"KERNEL_UTILISATION\":%lu,\n", (word_t) curr->benchmark.kernel_utilisation);
            printf("      \"NUMBER_KERNEL_ENTRIES\":%lu\n", (word_t) curr->benchmark.number_kernel_entries);
            printf("    }");
            if (TCB_PTR_DEBUG_PTR(curr)->tcbDebugNext != NULL) {
                printf(",\n");
            } else {
                printf("\n");
            }
        }
        printf("  ]\n}\n");
        return EXCEPTION_NONE;
    } else if (w == SysBenchmarkResetAllThreadsUtilisation) {
        for (tcb_t *curr = NODE_STATE(ksDebugTCBs); curr != NULL; curr = TCB_PTR_DEBUG_PTR(curr)->tcbDebugNext) {
            benchmark_track_reset_utilisation(curr);
        }
        return EXCEPTION_NONE;
    }
#endif /* CONFIG_DEBUG_BUILD */
#endif /* CONFIG_BENCHMARK_TRACK_UTILISATION */

    else if (w == SysBenchmarkNullSyscall) {
        return EXCEPTION_NONE;
    }
#endif /* CONFIG_ENABLE_BENCHMARKS */

    MCS_DO_IF_BUDGET({
#ifdef CONFIG_SET_TLS_BASE_SELF
        if (w == SysSetTLSBase)
        {
            word_t tls_base = getRegister(NODE_STATE(ksCurThread), capRegister);
            /*
             * This updates the real register as opposed to the thread state
             * value. For many architectures, the TLS variables only get
             * updated on a thread switch.
             */
            return Arch_setTLSRegister(tls_base);
        }
#endif
        current_fault = seL4_Fault_UnknownSyscall_new(w);
        handleFault(NODE_STATE(ksCurThread));
    })

    schedule();
    activateThread();

    return EXCEPTION_NONE;
}

exception_t handleUserLevelFault(word_t w_a, word_t w_b)
{
    MCS_DO_IF_BUDGET({
        current_fault = seL4_Fault_UserException_new(w_a, w_b);
        handleFault(NODE_STATE(ksCurThread));
    })
    schedule();
    activateThread();

    return EXCEPTION_NONE;
}

exception_t handleVMFaultEvent(vm_fault_type_t vm_faultType)
{
    MCS_DO_IF_BUDGET({

        exception_t status = handleVMFault(NODE_STATE(ksCurThread), vm_faultType);
        if (status != EXCEPTION_NONE)
        {
            handleFault(NODE_STATE(ksCurThread));
        }
    })

    schedule();
    activateThread();

    return EXCEPTION_NONE;
}

#ifdef CONFIG_KERNEL_MCS
static exception_t handleInvocation(bool_t isCall, bool_t isBlocking, bool_t canDonate, bool_t firstPhase, cptr_t cptr)
#else
static exception_t handleInvocation(bool_t isCall, bool_t isBlocking)
#endif
{
    seL4_MessageInfo_t info;
    lookupCapAndSlot_ret_t lu_ret;
    word_t *buffer;
    exception_t status;
    word_t length;
    tcb_t *thread;

    thread = NODE_STATE(ksCurThread);

    info = messageInfoFromWord(getRegister(thread, msgInfoRegister));
#ifndef CONFIG_KERNEL_MCS
    cptr_t cptr = getRegister(thread, capRegister);
#endif

    /* faulting section */
    lu_ret = lookupCapAndSlot(thread, cptr);

    if (unlikely(lu_ret.status != EXCEPTION_NONE)) {
        userError("Invocation of invalid cap #%lu.", cptr);
        current_fault = seL4_Fault_CapFault_new(cptr, false);

        if (isBlocking) {
            handleFault(thread);
        }

        return EXCEPTION_NONE;
    }

    buffer = lookupIPCBuffer(false, thread);

    status = lookupExtraCaps(thread, buffer, info);

    if (unlikely(status != EXCEPTION_NONE)) {
        userError("Lookup of extra caps failed.");
        if (isBlocking) {
            handleFault(thread);
        }
        return EXCEPTION_NONE;
    }

    /* Syscall error/Preemptible section */
    length = seL4_MessageInfo_get_length(info);
    if (unlikely(length > n_msgRegisters && !buffer)) {
        length = n_msgRegisters;
    }
#ifdef CONFIG_KERNEL_MCS
    status = decodeInvocation(seL4_MessageInfo_get_label(info), length,
                              cptr, lu_ret.slot, lu_ret.cap,
                              isBlocking, isCall,
                              canDonate, firstPhase, buffer);
#else
    status = decodeInvocation(seL4_MessageInfo_get_label(info), length,
                              cptr, lu_ret.slot, lu_ret.cap,
                              isBlocking, isCall, buffer);
#endif

    if (unlikely(status == EXCEPTION_PREEMPTED)) {
        return status;
    }

    if (unlikely(status == EXCEPTION_SYSCALL_ERROR)) {
        if (isCall) {
            replyFromKernel_error(thread);
        }
        return EXCEPTION_NONE;
    }

    if (unlikely(
            thread_state_get_tsType(thread->tcbState) == ThreadState_Restart)) {
        if (isCall) {
            replyFromKernel_success_empty(thread);
        }
        setThreadState(thread, ThreadState_Running);
    }

    return EXCEPTION_NONE;
}

#ifdef CONFIG_KERNEL_MCS
static inline lookupCap_ret_t lookupReply(void)
{
    word_t replyCPtr = getRegister(NODE_STATE(ksCurThread), replyRegister);
    lookupCap_ret_t lu_ret = lookupCap(NODE_STATE(ksCurThread), replyCPtr);
    if (unlikely(lu_ret.status != EXCEPTION_NONE)) {
        userError("Reply cap lookup failed");
        current_fault = seL4_Fault_CapFault_new(replyCPtr, true);
        handleFault(NODE_STATE(ksCurThread));
        return lu_ret;
    }

    if (unlikely(cap_get_capType(lu_ret.cap) != cap_reply_cap)) {
        userError("Cap in reply slot is not a reply");
        current_fault = seL4_Fault_CapFault_new(replyCPtr, true);
        handleFault(NODE_STATE(ksCurThread));
        lu_ret.status = EXCEPTION_FAULT;
        return lu_ret;
    }

    return lu_ret;
}
#else
static void handleReply(void)
{
    cte_t *callerSlot;
    cap_t callerCap;

    callerSlot = TCB_PTR_CTE_PTR(NODE_STATE(ksCurThread), tcbCaller);
    callerCap = callerSlot->cap;

    switch (cap_get_capType(callerCap)) {
    case cap_reply_cap: {
        tcb_t *caller;

        if (cap_reply_cap_get_capReplyMaster(callerCap)) {
            break;
        }
        caller = TCB_PTR(cap_reply_cap_get_capTCBPtr(callerCap));
        /* Haskell error:
         * "handleReply: caller must not be the current thread" */
        assert(caller != NODE_STATE(ksCurThread));
        doReplyTransfer(NODE_STATE(ksCurThread), caller, callerSlot,
                        cap_reply_cap_get_capReplyCanGrant(callerCap));
        return;
    }

    case cap_null_cap:
        userError("Attempted reply operation when no reply cap present.");
        return;

    default:
        break;
    }

    fail("handleReply: invalid caller cap");
}
#endif

#ifdef CONFIG_KERNEL_MCS
static void handleRecv(bool_t isBlocking, bool_t canReply)
#else
static void handleRecv(bool_t isBlocking)
#endif
{
    word_t epCPtr;
    lookupCap_ret_t lu_ret;

    epCPtr = getRegister(NODE_STATE(ksCurThread), capRegister);

    lu_ret = lookupCap(NODE_STATE(ksCurThread), epCPtr);

    if (unlikely(lu_ret.status != EXCEPTION_NONE)) {
        /* current_lookup_fault has been set by lookupCap */
        current_fault = seL4_Fault_CapFault_new(epCPtr, true);
        handleFault(NODE_STATE(ksCurThread));
        return;
    }

    switch (cap_get_capType(lu_ret.cap)) {
    case cap_endpoint_cap:
        if (unlikely(!cap_endpoint_cap_get_capCanReceive(lu_ret.cap))) {
            current_lookup_fault = lookup_fault_missing_capability_new(0);
            current_fault = seL4_Fault_CapFault_new(epCPtr, true);
            handleFault(NODE_STATE(ksCurThread));
            break;
        }

#ifdef CONFIG_KERNEL_MCS
        cap_t ep_cap = lu_ret.cap;
        cap_t reply_cap = cap_null_cap_new();
        if (canReply) {
            lu_ret = lookupReply();
            if (lu_ret.status != EXCEPTION_NONE) {
                return;
            } else {
                reply_cap = lu_ret.cap;
            }
        }
        receiveIPC(NODE_STATE(ksCurThread), ep_cap, isBlocking, reply_cap);
#else
        deleteCallerCap(NODE_STATE(ksCurThread));
        receiveIPC(NODE_STATE(ksCurThread), lu_ret.cap, isBlocking);
#endif
        break;

    case cap_notification_cap: {
        notification_t *ntfnPtr;
        tcb_t *boundTCB;
        ntfnPtr = NTFN_PTR(cap_notification_cap_get_capNtfnPtr(lu_ret.cap));
        boundTCB = (tcb_t *)notification_ptr_get_ntfnBoundTCB(ntfnPtr);
        if (unlikely(!cap_notification_cap_get_capNtfnCanReceive(lu_ret.cap)
                     || (boundTCB && boundTCB != NODE_STATE(ksCurThread)))) {
            current_lookup_fault = lookup_fault_missing_capability_new(0);
            current_fault = seL4_Fault_CapFault_new(epCPtr, true);
            handleFault(NODE_STATE(ksCurThread));
            break;
        }

        receiveSignal(NODE_STATE(ksCurThread), lu_ret.cap, isBlocking);
        break;
    }
    default:
        current_lookup_fault = lookup_fault_missing_capability_new(0);
        current_fault = seL4_Fault_CapFault_new(epCPtr, true);
        handleFault(NODE_STATE(ksCurThread));
        break;
    }
}

#ifdef CONFIG_KERNEL_MCS
static inline void mcsIRQ(irq_t irq)
{
    if (IRQT_TO_IRQ(irq) == KERNEL_TIMER_IRQ) {
        /* if this is a timer irq we must update the time as we need to reprogram the timer, and we
         * can't lose the time that has just been used by the kernel. */
        updateTimestamp();
    }

    /* at this point we could be handling a timer interrupt which actually ends the current
     * threads timeslice. However, preemption is possible on revoke, which could have deleted
     * the current thread and/or the current scheduling context, rendering them invalid. */
    if (isSchedulable(NODE_STATE(ksCurThread))) {
        /* if the thread is schedulable, the tcb and scheduling context are still valid */
        checkBudget();
    } else if (NODE_STATE(ksCurSC)->scRefillMax) {
        /* otherwise, if the thread is not schedulable, the SC could be valid - charge it if so */
        chargeBudget(NODE_STATE(ksConsumed), false, CURRENT_CPU_INDEX(), true);
    }

}
#else
#define handleRecv(isBlocking, canReply) handleRecv(isBlocking)
#define mcsIRQ(irq)
#define handleInvocation(isCall, isBlocking, canDonate, firstPhase, cptr) handleInvocation(isCall, isBlocking)
#endif

static void handleYield(void)
{
#ifdef CONFIG_KERNEL_MCS
    /* Yield the current remaining budget */
    ticks_t consumed = NODE_STATE(ksCurSC)->scConsumed + NODE_STATE(ksConsumed);
    chargeBudget(refill_head(NODE_STATE(ksCurSC))->rAmount, false, CURRENT_CPU_INDEX(), true);
    /* Manually updated the scConsumed so that the full timeslice isn't added, just what was consumed */
    NODE_STATE(ksCurSC)->scConsumed = consumed;
#else
    tcbSchedDequeue(NODE_STATE(ksCurThread));
    SCHED_APPEND_CURRENT_TCB;
    rescheduleRequired();
#endif
}

exception_t handleSyscall(syscall_t syscall)
{
    exception_t ret;
    irq_t irq;
    MCS_DO_IF_BUDGET({
        switch (syscall)
        {
        case SysSend:
            ret = handleInvocation(false, true, false, false, getRegister(NODE_STATE(ksCurThread), capRegister));
            if (unlikely(ret != EXCEPTION_NONE)) {
                irq = getActiveIRQ();
                if (IRQT_TO_IRQ(irq) != IRQT_TO_IRQ(irqInvalid)) {
                    mcsIRQ(irq);
                    handleInterrupt(irq);
                    Arch_finaliseInterrupt();
                }
            }

            break;

        case SysNBSend:
            ret = handleInvocation(false, false, false, false, getRegister(NODE_STATE(ksCurThread), capRegister));
            if (unlikely(ret != EXCEPTION_NONE)) {
                irq = getActiveIRQ();
                if (IRQT_TO_IRQ(irq) != IRQT_TO_IRQ(irqInvalid)) {
                    mcsIRQ(irq);
                    handleInterrupt(irq);
                    Arch_finaliseInterrupt();
                }
            }
            break;

        case SysCall:
            ret = handleInvocation(true, true, true, false, getRegister(NODE_STATE(ksCurThread), capRegister));
            if (unlikely(ret != EXCEPTION_NONE)) {
                irq = getActiveIRQ();
                if (IRQT_TO_IRQ(irq) != IRQT_TO_IRQ(irqInvalid)) {
                    mcsIRQ(irq);
                    handleInterrupt(irq);
                    Arch_finaliseInterrupt();
                }
            }
            break;

        case SysRecv:
            handleRecv(true, true);
            break;
#ifndef CONFIG_KERNEL_MCS
        case SysReply:
            handleReply();
            break;

        case SysReplyRecv:
            handleReply();
            handleRecv(true, true);
            break;

#else /* CONFIG_KERNEL_MCS */
        case SysWait:
            handleRecv(true, false);
            break;

        case SysNBWait:
            handleRecv(false, false);
            break;
        case SysReplyRecv: {
            cptr_t reply = getRegister(NODE_STATE(ksCurThread), replyRegister);
            ret = handleInvocation(false, false, true, true, reply);
            /* reply cannot error and is not preemptible */
            assert(ret == EXCEPTION_NONE);
            handleRecv(true, true);
            break;
        }

        case SysNBSendRecv: {
            cptr_t dest = getNBSendRecvDest();
            ret = handleInvocation(false, false, true, true, dest);
            if (unlikely(ret != EXCEPTION_NONE)) {
                irq = getActiveIRQ();
                if (IRQT_TO_IRQ(irq) != IRQT_TO_IRQ(irqInvalid)) {
                    mcsIRQ(irq);
                    handleInterrupt(irq);
                    Arch_finaliseInterrupt();
                }
                break;
            }
            handleRecv(true, true);
            break;
        }

        case SysNBSendWait:
            ret = handleInvocation(false, false, true, true, getRegister(NODE_STATE(ksCurThread), replyRegister));
            if (unlikely(ret != EXCEPTION_NONE)) {
                irq = getActiveIRQ();
                if (IRQT_TO_IRQ(irq) != IRQT_TO_IRQ(irqInvalid)) {
                    mcsIRQ(irq);
                    handleInterrupt(irq);
                    Arch_finaliseInterrupt();
                }
                break;
            }
            handleRecv(true, false);
            break;
#endif
        case SysNBRecv:
            handleRecv(false, true);
            break;

        case SysYield:
            handleYield();
            break;

        default:
            fail("Invalid syscall");
        }

    })

    schedule();
    activateThread();

    return EXCEPTION_NONE;
}
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/api/benchmark.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef CONFIG_ENABLE_BENCHMARK

#endif /* CONFIG_ENABLE_BENCHMARK */


#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/api/faults.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <object.h>
#include <kernel/vspace.h>
#include <api/faults.h>
#include <api/syscall.h>

#include <types.h>
#include <machine/io.h>
#include <api/faults.h>
#include <api/syscall.h>
#include <util.h>

bool_t Arch_handleFaultReply(tcb_t *receiver, tcb_t *sender, word_t faultType)
{
    switch (faultType) {
    case seL4_Fault_VMFault:
        return true;

    default:
        fail("Invalid fault");
    }
}

word_t Arch_setMRs_fault(tcb_t *sender, tcb_t *receiver, word_t *receiveIPCBuffer, word_t faultType)
{
    switch (faultType) {
    case seL4_Fault_VMFault: {
        setMR(receiver, receiveIPCBuffer, seL4_VMFault_IP, getRestartPC(sender));
        setMR(receiver, receiveIPCBuffer, seL4_VMFault_Addr,
              seL4_Fault_VMFault_get_address(sender->tcbFault));
        setMR(receiver, receiveIPCBuffer, seL4_VMFault_PrefetchFault,
              seL4_Fault_VMFault_get_instructionFault(sender->tcbFault));
        return setMR(receiver, receiveIPCBuffer, seL4_VMFault_FSR,
                     seL4_Fault_VMFault_get_FSR(sender->tcbFault));
    }
    default:
        fail("Invalid fault");
    }
}
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/c_traps.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <model/statedata.h>
#include <arch/fastpath/fastpath.h>
#include <arch/kernel/traps.h>
#include <machine/debug.h>
#include <api/syscall.h>
#include <util.h>
#include <arch/machine/hardware.h>
#include <machine/fpu.h>

#include <benchmark/benchmark_track.h>
#include <benchmark/benchmark_utilisation.h>

/** DONT_TRANSLATE */
void VISIBLE NORETURN restore_user_context(void)
{
    word_t cur_thread_reg = (word_t) NODE_STATE(ksCurThread)->tcbArch.tcbContext.registers;
    c_exit_hook();
    NODE_UNLOCK_IF_HELD;

#ifdef ENABLE_SMP_SUPPORT
    word_t sp;
    asm volatile("csrr %0, sscratch" : "=r"(sp));
    sp -= sizeof(word_t);
    *((word_t *)sp) = cur_thread_reg;
#endif


#ifdef CONFIG_HAVE_FPU
    lazyFPURestore(NODE_STATE(ksCurThread));
    set_tcb_fs_state(NODE_STATE(ksCurThread), isFpuEnable());
#endif

    asm volatile(
        "mv t0, %[cur_thread]       \n"
        LOAD_S " ra, (0*%[REGSIZE])(t0)  \n"
        LOAD_S "  sp, (1*%[REGSIZE])(t0)  \n"
        LOAD_S "  gp, (2*%[REGSIZE])(t0)  \n"
        /* skip tp */
        /* skip x5/t0 */
        /* no-op store conditional to clear monitor state */
        /* this may succeed in implementations with very large reservations, but the saved ra is dead */
        "sc.w zero, zero, (t0)\n"
        LOAD_S "  t2, (6*%[REGSIZE])(t0)  \n"
        LOAD_S "  s0, (7*%[REGSIZE])(t0)  \n"
        LOAD_S "  s1, (8*%[REGSIZE])(t0)  \n"
        LOAD_S "  a0, (9*%[REGSIZE])(t0) \n"
        LOAD_S "  a1, (10*%[REGSIZE])(t0) \n"
        LOAD_S "  a2, (11*%[REGSIZE])(t0) \n"
        LOAD_S "  a3, (12*%[REGSIZE])(t0) \n"
        LOAD_S "  a4, (13*%[REGSIZE])(t0) \n"
        LOAD_S "  a5, (14*%[REGSIZE])(t0) \n"
        LOAD_S "  a6, (15*%[REGSIZE])(t0) \n"
        LOAD_S "  a7, (16*%[REGSIZE])(t0) \n"
        LOAD_S "  s2, (17*%[REGSIZE])(t0) \n"
        LOAD_S "  s3, (18*%[REGSIZE])(t0) \n"
        LOAD_S "  s4, (19*%[REGSIZE])(t0) \n"
        LOAD_S "  s5, (20*%[REGSIZE])(t0) \n"
        LOAD_S "  s6, (21*%[REGSIZE])(t0) \n"
        LOAD_S "  s7, (22*%[REGSIZE])(t0) \n"
        LOAD_S "  s8, (23*%[REGSIZE])(t0) \n"
        LOAD_S "  s9, (24*%[REGSIZE])(t0) \n"
        LOAD_S "  s10, (25*%[REGSIZE])(t0)\n"
        LOAD_S "  s11, (26*%[REGSIZE])(t0)\n"
        LOAD_S "  t3, (27*%[REGSIZE])(t0) \n"
        LOAD_S "  t4, (28*%[REGSIZE])(t0) \n"
        LOAD_S "  t5, (29*%[REGSIZE])(t0) \n"
        LOAD_S "  t6, (30*%[REGSIZE])(t0) \n"
        /* Get next restored tp */
        LOAD_S "  t1, (3*%[REGSIZE])(t0)  \n"
        /* get restored tp */
        "add tp, t1, x0  \n"
        /* get sepc */
        LOAD_S "  t1, (34*%[REGSIZE])(t0)\n"
        "csrw sepc, t1  \n"
#ifndef ENABLE_SMP_SUPPORT
        /* Write back sscratch with cur_thread_reg to get it back on the next trap entry */
        "csrw sscratch, t0         \n"
#endif
        LOAD_S "  t1, (32*%[REGSIZE])(t0) \n"
        "csrw sstatus, t1\n"

        LOAD_S "  t1, (5*%[REGSIZE])(t0) \n"
        LOAD_S "  t0, (4*%[REGSIZE])(t0) \n"
        "sret"
        : /* no output */
        : [REGSIZE] "i"(sizeof(word_t)),
        [cur_thread] "r"(cur_thread_reg)
        : "memory"
    );

    UNREACHABLE();
}

void VISIBLE NORETURN c_handle_interrupt(void)
{
    NODE_LOCK_IRQ_IF(getActiveIRQ() != irq_remote_call_ipi);

    c_entry_hook();

    handleInterruptEntry();

    restore_user_context();
    UNREACHABLE();
}

void VISIBLE NORETURN c_handle_exception(void)
{
    NODE_LOCK_SYS;

    c_entry_hook();

    word_t scause = read_scause();
    switch (scause) {
    case RISCVInstructionAccessFault:
    case RISCVLoadAccessFault:
    case RISCVStoreAccessFault:
    case RISCVLoadPageFault:
    case RISCVStorePageFault:
    case RISCVInstructionPageFault:
        handleVMFaultEvent(scause);
        break;
    default:
#ifdef CONFIG_HAVE_FPU
        if (!isFpuEnable()) {
            /* we assume the illegal instruction is caused by FPU first */
            handleFPUFault();
            setNextPC(NODE_STATE(ksCurThread), getRestartPC(NODE_STATE(ksCurThread)));
            break;
        }
#endif
        handleUserLevelFault(scause, 0);
        break;
    }

    restore_user_context();
    UNREACHABLE();
}

void NORETURN slowpath(syscall_t syscall)
{
    /* check for undefined syscall */
    if (unlikely(syscall < SYSCALL_MIN || syscall > SYSCALL_MAX)) {
        handleUnknownSyscall(syscall);
    } else {
        handleSyscall(syscall);
    }

    restore_user_context();
    UNREACHABLE();
}

void VISIBLE NORETURN c_handle_syscall(word_t cptr, word_t msgInfo, word_t unused1, word_t unused2, word_t unused3,
                                       word_t unused4, word_t reply, syscall_t syscall)
{
    NODE_LOCK_SYS;

    c_entry_hook();

#ifdef CONFIG_FASTPATH
    if (syscall == (syscall_t)SysCall) {
        fastpath_call(cptr, msgInfo);
        UNREACHABLE();
    } else if (syscall == (syscall_t)SysReplyRecv) {
#ifdef CONFIG_KERNEL_MCS
        fastpath_reply_recv(cptr, msgInfo, reply);
#else
        fastpath_reply_recv(cptr, msgInfo);
#endif
        UNREACHABLE();
    }
#endif /* CONFIG_FASTPATH */
    slowpath(syscall);
    UNREACHABLE();
}
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/idle.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <arch/sbi.h>

void idle_thread(void)
{
    while (1) {
        asm volatile("wfi");
    }
}

/** DONT_TRANSLATE */
void VISIBLE NO_INLINE halt(void)
{
#ifdef CONFIG_PRINTING
    printf("halting...");
#endif

    sbi_shutdown();

    UNREACHABLE();
}
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/boot.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <kernel/boot.h>
#include <machine/io.h>
#include <model/statedata.h>
#include <object/interrupt.h>
#include <arch/machine.h>
#include <arch/kernel/boot.h>
#include <arch/kernel/vspace.h>
#include <arch/benchmark.h>
#include <linker.h>
#include <plat/machine/hardware.h>
#include <machine.h>

/* pointer to the end of boot code/data in kernel image */
/* need a fake array to get the pointer from the linker script */
extern char ki_boot_end[1];
/* pointer to end of kernel image */
extern char ki_end[1];

#ifdef ENABLE_SMP_SUPPORT
BOOT_DATA static volatile word_t node_boot_lock = 0;
#endif

/* kernel image + [extra bootinfo] + user image */
#define MAX_RESERVED 3
BOOT_DATA static region_t res_reg[MAX_RESERVED];

BOOT_CODE static bool_t create_untypeds(cap_t root_cnode_cap, region_t boot_mem_reuse_reg)
{
    seL4_SlotPos   slot_pos_before;
    seL4_SlotPos   slot_pos_after;

    slot_pos_before = ndks_boot.slot_pos_cur;
    create_device_untypeds(root_cnode_cap, slot_pos_before);
    bool_t res = create_kernel_untypeds(root_cnode_cap, boot_mem_reuse_reg, slot_pos_before);

    slot_pos_after = ndks_boot.slot_pos_cur;
    ndks_boot.bi_frame->untyped = (seL4_SlotRegion) {
        slot_pos_before, slot_pos_after
    };
    return res;

}

BOOT_CODE cap_t create_mapped_it_frame_cap(cap_t pd_cap, pptr_t pptr, vptr_t vptr, asid_t asid, bool_t
                                           use_large, bool_t executable)
{
    cap_t cap;
    vm_page_size_t frame_size;

    if (use_large) {
        frame_size = RISCV_Mega_Page;
    } else {
        frame_size = RISCV_4K_Page;
    }

    cap = cap_frame_cap_new(
              asid,                            /* capFMappedASID       */
              pptr,                            /* capFBasePtr          */
              frame_size,                      /* capFSize             */
              wordFromVMRights(VMReadWrite),   /* capFVMRights         */
              0,                               /* capFIsDevice         */
              vptr                             /* capFMappedAddress    */
          );

    map_it_frame_cap(pd_cap, cap);
    return cap;
}

BOOT_CODE static void arch_init_freemem(region_t ui_reg, v_region_t ui_v_reg,
                                        region_t dtb_reg, word_t extra_bi_size_bits)
{
    // This looks a bit awkward as our symbols are a reference in the kernel image window, but
    // we want to do all allocations in terms of the main kernel window, so we do some translation
    res_reg[0].start = (pptr_t)paddr_to_pptr(kpptr_to_paddr((void *)KERNEL_ELF_BASE));
    res_reg[0].end = (pptr_t)paddr_to_pptr(kpptr_to_paddr((void *)ki_end));

    int index = 1;
    if (dtb_reg.start) {
        /* optionally reserve the dtb region, as it could be empty */
        res_reg[index].start = dtb_reg.start;
        res_reg[index].end = dtb_reg.end;
        index += 1;
    }

    res_reg[index].start = ui_reg.start;
    res_reg[index].end = ui_reg.end;
    index += 1;

    init_freemem(get_num_avail_p_regs(), get_avail_p_regs(), index, res_reg, ui_v_reg,
                 extra_bi_size_bits);
}

BOOT_CODE static void init_irqs(cap_t root_cnode_cap)
{
    irq_t i;

    for (i = 0; i <= maxIRQ; i++) {
        if (i != irqInvalid) {
            /* IRQ 0 is irqInvalid */
            setIRQState(IRQInactive, i);
        }
    }
    setIRQState(IRQTimer, KERNEL_TIMER_IRQ);
#ifdef ENABLE_SMP_SUPPORT
    setIRQState(IRQIPI, irq_remote_call_ipi);
    setIRQState(IRQIPI, irq_reschedule_ipi);
#endif
    /* provide the IRQ control cap */
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapIRQControl), cap_irq_control_cap_new());
}

/* ASM symbol for the CPU initialisation trap. */
extern char trap_entry[1];

/* This and only this function initialises the CPU. It does NOT initialise any kernel state. */

#ifdef CONFIG_HAVE_FPU
BOOT_CODE static void init_fpu(void)
{
    set_fs_clean();
    write_fcsr(0);
    disableFpu();
}
#endif

BOOT_CODE static void init_cpu(void)
{

    activate_kernel_vspace();
    /* Write trap entry address to stvec */
    write_stvec((word_t)trap_entry);
    initLocalIRQController();
#ifndef CONFIG_KERNEL_MCS
    initTimer();
#endif

    /* disable FPU access */
    set_fs_off();

#ifdef CONFIG_HAVE_FPU
    init_fpu();
#endif
}

/* This and only this function initialises the platform. It does NOT initialise any kernel state. */

BOOT_CODE static void init_plat(void)
{
    initIRQController();
}


#ifdef ENABLE_SMP_SUPPORT
BOOT_CODE static bool_t try_init_kernel_secondary_core(word_t hart_id, word_t core_id)
{
    while (!node_boot_lock);

    fence_r_rw();

    init_cpu();
    NODE_LOCK_SYS;

    ksNumCPUs++;
    init_core_state(SchedulerAction_ResumeCurrentThread);
    ifence_local();
    return true;
}

BOOT_CODE static void release_secondary_cores(void)
{
    node_boot_lock = 1;
    fence_w_r();

    while (ksNumCPUs != CONFIG_MAX_NUM_NODES) {
        __atomic_signal_fence(__ATOMIC_ACQ_REL);
    }
}

#endif
/* Main kernel initialisation function. */

static BOOT_CODE bool_t try_init_kernel(
    paddr_t ui_p_reg_start,
    paddr_t ui_p_reg_end,
    uint32_t pv_offset,
    vptr_t  v_entry,
    paddr_t dtb_addr_start,
    paddr_t dtb_addr_end
)
{
    cap_t root_cnode_cap;
    cap_t it_pd_cap;
    cap_t it_ap_cap;
    cap_t ipcbuf_cap;
    p_region_t boot_mem_reuse_p_reg = ((p_region_t) {
        kpptr_to_paddr((void *)KERNEL_ELF_BASE), kpptr_to_paddr(ki_boot_end)
    });
    region_t boot_mem_reuse_reg = paddr_to_pptr_reg(boot_mem_reuse_p_reg);
    region_t ui_reg = paddr_to_pptr_reg((p_region_t) {
        ui_p_reg_start, ui_p_reg_end
    });
    region_t dtb_reg;
    word_t extra_bi_size;
    pptr_t extra_bi_offset = 0;
    vptr_t extra_bi_frame_vptr;
    vptr_t bi_frame_vptr;
    vptr_t ipcbuf_vptr;
    create_frames_of_region_ret_t create_frames_ret;
    create_frames_of_region_ret_t extra_bi_ret;

    /* convert from physical addresses to userland vptrs */
    v_region_t ui_v_reg;
    v_region_t it_v_reg;
    ui_v_reg.start = (word_t)(ui_p_reg_start - pv_offset);
    ui_v_reg.end   = (word_t)(ui_p_reg_end   - pv_offset);

    ipcbuf_vptr = ui_v_reg.end;
    bi_frame_vptr = ipcbuf_vptr + BIT(PAGE_BITS);
    extra_bi_frame_vptr = bi_frame_vptr + BIT(PAGE_BITS);

    /* If no DTB was provided, skip allocating extra bootinfo */
    p_region_t dtb_p_reg = {
        dtb_addr_start, ROUND_UP(dtb_addr_end, PAGE_BITS)
    };
    if (dtb_addr_start == 0) {
        extra_bi_size = 0;
        dtb_reg = (region_t) {
            0, 0
        };
    } else {
        /* convert physical address to addressable pointer */
        dtb_reg = paddr_to_pptr_reg(dtb_p_reg);
        extra_bi_size = sizeof(seL4_BootInfoHeader) + (dtb_reg.end - dtb_reg.start);
    }
    word_t extra_bi_size_bits = calculate_extra_bi_size_bits(extra_bi_size);

    /* The region of the initial thread is the user image + ipcbuf + boot info + extra */
    it_v_reg.start = ui_v_reg.start;
    it_v_reg.end = extra_bi_frame_vptr + BIT(extra_bi_size_bits);

    map_kernel_window();

    /* initialise the CPU */
    init_cpu();

    /* initialize the platform */
    init_plat();

    /* make the free memory available to alloc_region() */
    arch_init_freemem(ui_reg, it_v_reg, dtb_reg, extra_bi_size_bits);

    /* create the root cnode */
    root_cnode_cap = create_root_cnode();
    if (cap_get_capType(root_cnode_cap) == cap_null_cap) {
        return false;
    }

    /* create the cap for managing thread domains */
    create_domain_cap(root_cnode_cap);

    /* initialise the IRQ states and provide the IRQ control cap */
    init_irqs(root_cnode_cap);

    /* create the bootinfo frame */
    populate_bi_frame(0, CONFIG_MAX_NUM_NODES, ipcbuf_vptr, extra_bi_size);

    /* put DTB in the bootinfo block, if present. */
    seL4_BootInfoHeader header;
    if (dtb_reg.start) {
        header.id = SEL4_BOOTINFO_HEADER_FDT;
        header.len = extra_bi_size;
        *(seL4_BootInfoHeader *)(rootserver.extra_bi + extra_bi_offset) = header;
        extra_bi_offset += sizeof(header);
        memcpy((void *)(rootserver.extra_bi + extra_bi_offset), (void *)dtb_reg.start,
               dtb_reg.end - dtb_reg.start);
        extra_bi_offset += (dtb_reg.end - dtb_reg.start);
    }

    if (extra_bi_size > extra_bi_offset) {
        /* provide a chunk for any leftover padding in the extended boot info */
        header.id = SEL4_BOOTINFO_HEADER_PADDING;
        header.len = (extra_bi_size - extra_bi_offset);
        *(seL4_BootInfoHeader *)(rootserver.extra_bi + extra_bi_offset) = header;
    }

    /* Construct an initial address space with enough virtual addresses
     * to cover the user image + ipc buffer and bootinfo frames */
    it_pd_cap = create_it_address_space(root_cnode_cap, it_v_reg);
    if (cap_get_capType(it_pd_cap) == cap_null_cap) {
        return false;
    }

    /* Create and map bootinfo frame cap */
    create_bi_frame_cap(
        root_cnode_cap,
        it_pd_cap,
        bi_frame_vptr
    );

    /* create and map extra bootinfo region */
    if (extra_bi_size > 0) {
        region_t extra_bi_region = {
            .start = rootserver.extra_bi,
            .end = rootserver.extra_bi + extra_bi_size
        };
        extra_bi_ret =
            create_frames_of_region(
                root_cnode_cap,
                it_pd_cap,
                extra_bi_region,
                true,
                pptr_to_paddr((void *)extra_bi_region.start) - extra_bi_frame_vptr
            );
        if (!extra_bi_ret.success) {
            return false;
        }
        ndks_boot.bi_frame->extraBIPages = extra_bi_ret.region;
    }

#ifdef CONFIG_KERNEL_MCS
    init_sched_control(root_cnode_cap, CONFIG_MAX_NUM_NODES);
#endif

    /* create the initial thread's IPC buffer */
    ipcbuf_cap = create_ipcbuf_frame_cap(root_cnode_cap, it_pd_cap, ipcbuf_vptr);
    if (cap_get_capType(ipcbuf_cap) == cap_null_cap) {
        return false;
    }

    /* create all userland image frames */
    create_frames_ret =
        create_frames_of_region(
            root_cnode_cap,
            it_pd_cap,
            ui_reg,
            true,
            pv_offset
        );
    if (!create_frames_ret.success) {
        return false;
    }
    ndks_boot.bi_frame->userImageFrames = create_frames_ret.region;

    /* create the initial thread's ASID pool */
    it_ap_cap = create_it_asid_pool(root_cnode_cap);
    if (cap_get_capType(it_ap_cap) == cap_null_cap) {
        return false;
    }
    write_it_asid_pool(it_ap_cap, it_pd_cap);

#ifdef CONFIG_KERNEL_MCS
    NODE_STATE(ksCurTime) = getCurrentTime();
#endif

    /* create the idle thread */
    if (!create_idle_thread()) {
        return false;
    }


    /* create the initial thread */
    tcb_t *initial = create_initial_thread(
                         root_cnode_cap,
                         it_pd_cap,
                         v_entry,
                         bi_frame_vptr,
                         ipcbuf_vptr,
                         ipcbuf_cap
                     );

    if (initial == NULL) {
        return false;
    }

    init_core_state(initial);

    /* convert the remaining free memory into UT objects and provide the caps */
    if (!create_untypeds(
            root_cnode_cap,
            boot_mem_reuse_reg)) {
        return false;
    }

    /* no shared-frame caps (RISCV has no multikernel support) */
    ndks_boot.bi_frame->sharedFrames = S_REG_EMPTY;

    /* finalise the bootinfo frame */
    bi_finalise();

    ksNumCPUs = 1;

    SMP_COND_STATEMENT(clh_lock_init());
    SMP_COND_STATEMENT(release_secondary_cores());

    printf("Booting all finished, dropped to user space\n");
    return true;
}

BOOT_CODE VISIBLE void init_kernel(
    paddr_t ui_p_reg_start,
    paddr_t ui_p_reg_end,
    sword_t pv_offset,
    vptr_t  v_entry,
    paddr_t dtb_addr_p,
    uint32_t dtb_size
#ifdef ENABLE_SMP_SUPPORT
    ,
    word_t hart_id,
    word_t core_id
#endif
)
{
    bool_t result;
    paddr_t dtb_end_p = 0;

    if (dtb_addr_p) {
        dtb_end_p = dtb_addr_p + dtb_size;
    }

#ifdef ENABLE_SMP_SUPPORT
    add_hart_to_core_map(hart_id, core_id);
    if (core_id == 0) {
        result = try_init_kernel(ui_p_reg_start,
                                 ui_p_reg_end,
                                 pv_offset,
                                 v_entry,
                                 dtb_addr_p,
                                 dtb_end_p);
    } else {
        result = try_init_kernel_secondary_core(hart_id, core_id);
    }
#else
    result = try_init_kernel(ui_p_reg_start,
                             ui_p_reg_end,
                             pv_offset,
                             v_entry,
                             dtb_addr_p,
                             dtb_end_p);
#endif
    if (!result) {
        fail("Kernel init failed for some reason :(");
    }

#ifdef CONFIG_KERNEL_MCS
    NODE_STATE(ksCurTime) = getCurrentTime();
    NODE_STATE(ksConsumed) = 0;
#endif

    schedule();
    activateThread();
}
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/thread.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <object.h>
#include <machine.h>
#include <arch/model/statedata.h>
#include <arch/kernel/vspace.h>
#include <arch/kernel/thread.h>
#include <linker.h>

extern char kernel_stack_alloc[CONFIG_MAX_NUM_NODES][BIT(CONFIG_KERNEL_STACK_BITS)];

void Arch_switchToThread(tcb_t *tcb)
{
    setVMRoot(tcb);
}

BOOT_CODE void Arch_configureIdleThread(tcb_t *tcb)
{
    setRegister(tcb, NextIP, (word_t)idleThreadStart);

    /* Enable interrupts and keep working in supervisor mode */
    setRegister(tcb, SSTATUS, (word_t) SSTATUS_SPP | SSTATUS_SPIE);
#ifdef ENABLE_SMP_SUPPORT
    for (int i = 0; i < CONFIG_MAX_NUM_NODES; i++) {
        if (NODE_STATE_ON_CORE(ksIdleThread, i) == tcb) {
            setRegister(tcb, SP, (word_t)kernel_stack_alloc + (i + 1) * BIT(CONFIG_KERNEL_STACK_BITS));
            break;
        }
    }
#else
    setRegister(tcb, SP, (word_t)kernel_stack_alloc + BIT(CONFIG_KERNEL_STACK_BITS));
#endif
}

void Arch_switchToIdleThread(void)
{
    tcb_t *tcb = NODE_STATE(ksIdleThread);

    /* Force the idle thread to run on kernel page table */
    setVMRoot(tcb);
}

void Arch_activateIdleThread(tcb_t *tcb)
{
    /* Don't need to do anything */
}

void Arch_postModifyRegisters(tcb_t *tptr)
{
    /* Nothing to do */
}
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/vspace.c"
/*
 * Copyright 2020, DornerWorks
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <benchmark/benchmark.h>
#include <api/failures.h>
#include <api/syscall.h>
#include <kernel/boot.h>
#include <kernel/cspace.h>
#include <kernel/thread.h>
#include <object/tcb.h>
#include <machine/io.h>
#include <model/preemption.h>
#include <model/statedata.h>
#include <object/cnode.h>
#include <object/untyped.h>
#include <arch/api/invocation.h>
#include <arch/kernel/vspace.h>
#include <linker.h>
#include <arch/machine.h>
#include <plat/machine/hardware.h>
#include <kernel/stack.h>
#include <util.h>

struct resolve_ret {
    paddr_t frameBase;
    vm_page_size_t frameSize;
    bool_t valid;
};
typedef struct resolve_ret resolve_ret_t;

static exception_t performPageGetAddress(void *vbase_ptr);

static word_t CONST RISCVGetWriteFromVMRights(vm_rights_t vm_rights)
{
    /* Write-only frame cap rights not currently supported. */
    return vm_rights == VMReadWrite;
}

static inline word_t CONST RISCVGetReadFromVMRights(vm_rights_t vm_rights)
{
    /* Write-only frame cap rights not currently supported.
     * Kernel-only conveys no user rights. */
    return vm_rights != VMKernelOnly;
}

static inline bool_t isPTEPageTable(pte_t *pte)
{
    return pte_ptr_get_valid(pte) &&
           !(pte_ptr_get_read(pte) || pte_ptr_get_write(pte) || pte_ptr_get_execute(pte));
}

/** Helper function meant only to be used for mapping the kernel
 * window.
 *
 * Maps all pages with full RWX and supervisor perms by default.
 */
static pte_t pte_next(word_t phys_addr, bool_t is_leaf)
{
    word_t ppn = (word_t)(phys_addr >> 12);

    uint8_t read = is_leaf ? 1 : 0;
    uint8_t write = read;
    uint8_t exec = read;

    return pte_new(ppn,
                   0,     /* sw */
                   1,     /* dirty */
                   1,     /* accessed */
                   1,     /* global */
                   0,     /* user */
                   exec,  /* execute */
                   write, /* write */
                   read,  /* read */
                   1      /* valid */
                  );
}

/* ==================== BOOT CODE STARTS HERE ==================== */

BOOT_CODE void map_kernel_frame(paddr_t paddr, pptr_t vaddr, vm_rights_t vm_rights)
{
#if __riscv_xlen == 32
    paddr = ROUND_DOWN(paddr, RISCV_GET_LVL_PGSIZE_BITS(0));
    assert((paddr % RISCV_GET_LVL_PGSIZE(0)) == 0);
    kernel_root_pageTable[RISCV_GET_PT_INDEX(vaddr, 0)] = pte_next(paddr, true);
#else
    if (vaddr >= KDEV_BASE) {
        /* Map devices in 2nd-level page table */
        paddr = ROUND_DOWN(paddr, RISCV_GET_LVL_PGSIZE_BITS(1));
        assert((paddr % RISCV_GET_LVL_PGSIZE(1)) == 0);
        kernel_image_level2_dev_pt[RISCV_GET_PT_INDEX(vaddr, 1)] = pte_next(paddr, true);
    } else {
        paddr = ROUND_DOWN(paddr, RISCV_GET_LVL_PGSIZE_BITS(0));
        assert((paddr % RISCV_GET_LVL_PGSIZE(0)) == 0);
        kernel_root_pageTable[RISCV_GET_PT_INDEX(vaddr, 0)] = pte_next(paddr, true);
    }
#endif
}

BOOT_CODE VISIBLE void map_kernel_window(void)
{
    /* mapping of KERNEL_ELF_BASE (virtual address) to kernel's
     * KERNEL_ELF_PHYS_BASE  */
    assert(CONFIG_PT_LEVELS > 1 && CONFIG_PT_LEVELS <= 4);

    /* kernel window starts at PPTR_BASE */
    word_t pptr = PPTR_BASE;

    /* first we map in memory from PADDR_BASE */
    word_t paddr = PADDR_BASE;
    while (pptr < PPTR_TOP) {
        assert(IS_ALIGNED(pptr, RISCV_GET_LVL_PGSIZE_BITS(0)));
        assert(IS_ALIGNED(paddr, RISCV_GET_LVL_PGSIZE_BITS(0)));

        kernel_root_pageTable[RISCV_GET_PT_INDEX(pptr, 0)] = pte_next(paddr, true);

        pptr += RISCV_GET_LVL_PGSIZE(0);
        paddr += RISCV_GET_LVL_PGSIZE(0);
    }
    /* now we should be mapping the 1GiB kernel base */
    assert(pptr == PPTR_TOP);
    pptr = ROUND_DOWN(KERNEL_ELF_BASE, RISCV_GET_LVL_PGSIZE_BITS(0));
    paddr = ROUND_DOWN(KERNEL_ELF_PADDR_BASE, RISCV_GET_LVL_PGSIZE_BITS(0));

#if __riscv_xlen == 32
    kernel_root_pageTable[RISCV_GET_PT_INDEX(pptr, 0)] = pte_next(paddr, true);
    pptr += RISCV_GET_LVL_PGSIZE(0);
    paddr += RISCV_GET_LVL_PGSIZE(0);
#ifdef CONFIG_KERNEL_LOG_BUFFER
    kernel_root_pageTable[RISCV_GET_PT_INDEX(KS_LOG_PPTR, 0)] =
        pte_next(kpptr_to_paddr(kernel_image_level2_log_buffer_pt), false);
#endif
#else
    word_t index = 0;
    /* The kernel image are mapped twice, locating the two indexes in the
     * root page table, pointing them to the same second level page table.
     */
    kernel_root_pageTable[RISCV_GET_PT_INDEX(KERNEL_ELF_PADDR_BASE + PPTR_BASE_OFFSET, 0)] =
        pte_next(kpptr_to_paddr(kernel_image_level2_pt), false);
    kernel_root_pageTable[RISCV_GET_PT_INDEX(pptr, 0)] =
        pte_next(kpptr_to_paddr(kernel_image_level2_pt), false);
    while (pptr < PPTR_TOP + RISCV_GET_LVL_PGSIZE(0)) {
        kernel_image_level2_pt[index] = pte_next(paddr, true);
        index++;
        pptr += RISCV_GET_LVL_PGSIZE(1);
        paddr += RISCV_GET_LVL_PGSIZE(1);
    }

    /* Map kernel device page table */
    kernel_root_pageTable[RISCV_GET_PT_INDEX(KDEV_BASE, 0)] =
        pte_next(kpptr_to_paddr(kernel_image_level2_dev_pt), false);
#endif

    /* There should be 1GiB free where we put device mapping */
    assert(pptr == UINTPTR_MAX - RISCV_GET_LVL_PGSIZE(0) + 1);
    map_kernel_devices();
}

BOOT_CODE void map_it_pt_cap(cap_t vspace_cap, cap_t pt_cap)
{
    lookupPTSlot_ret_t pt_ret;
    pte_t *targetSlot;
    vptr_t vptr = cap_page_table_cap_get_capPTMappedAddress(pt_cap);
    pte_t *lvl1pt = PTE_PTR(pptr_of_cap(vspace_cap));

    /* pt to be mapped */
    pte_t *pt   = PTE_PTR(pptr_of_cap(pt_cap));

    /* Get PT slot to install the address in */
    pt_ret = lookupPTSlot(lvl1pt, vptr);

    targetSlot = pt_ret.ptSlot;

    *targetSlot = pte_new(
                      (addrFromPPtr(pt) >> seL4_PageBits),
                      0, /* sw */
                      1, /* dirty */
                      1, /* accessed */
                      0,  /* global */
                      0,  /* user */
                      0,  /* execute */
                      0,  /* write */
                      0,  /* read */
                      1 /* valid */
                  );
    sfence();
}

BOOT_CODE void map_it_frame_cap(cap_t vspace_cap, cap_t frame_cap)
{
    pte_t *lvl1pt   = PTE_PTR(pptr_of_cap(vspace_cap));
    pte_t *frame_pptr   = PTE_PTR(pptr_of_cap(frame_cap));
    vptr_t frame_vptr = cap_frame_cap_get_capFMappedAddress(frame_cap);

    /* We deal with a frame as 4KiB */
    lookupPTSlot_ret_t lu_ret = lookupPTSlot(lvl1pt, frame_vptr);
    assert(lu_ret.ptBitsLeft == seL4_PageBits);

    pte_t *targetSlot = lu_ret.ptSlot;

    *targetSlot = pte_new(
                      (pptr_to_paddr(frame_pptr) >> seL4_PageBits),
                      0, /* sw */
                      1, /* dirty */
                      1, /* accessed */
                      0,  /* global */
                      1,  /* user */
                      1,  /* execute */
                      1,  /* write */
                      1,  /* read */
                      1   /* valid */
                  );
    sfence();
}

BOOT_CODE cap_t create_unmapped_it_frame_cap(pptr_t pptr, bool_t use_large)
{
    cap_t cap = cap_frame_cap_new(
                    asidInvalid,                     /* capFMappedASID       */
                    pptr,                            /* capFBasePtr          */
                    0,                               /* capFSize             */
                    0,                               /* capFVMRights         */
                    0,
                    0                                /* capFMappedAddress    */
                );

    return cap;
}

/* Create a page table for the initial thread */
static BOOT_CODE cap_t create_it_pt_cap(cap_t vspace_cap, pptr_t pptr, vptr_t vptr, asid_t asid)
{
    cap_t cap;
    cap = cap_page_table_cap_new(
              asid,   /* capPTMappedASID      */
              pptr,   /* capPTBasePtr         */
              1,      /* capPTIsMapped        */
              vptr    /* capPTMappedAddress   */
          );

    map_it_pt_cap(vspace_cap, cap);
    return cap;
}

BOOT_CODE word_t arch_get_n_paging(v_region_t it_v_reg)
{
    word_t n = 0;
    for (int i = 0; i < CONFIG_PT_LEVELS - 1; i++) {
        n += get_n_paging(it_v_reg, RISCV_GET_LVL_PGSIZE_BITS(i));
    }
    return n;
}

/* Create an address space for the initial thread.
 * This includes page directory and page tables */
BOOT_CODE cap_t create_it_address_space(cap_t root_cnode_cap, v_region_t it_v_reg)
{
    cap_t      lvl1pt_cap;
    vptr_t     pt_vptr;

    copyGlobalMappings(PTE_PTR(rootserver.vspace));

    lvl1pt_cap =
        cap_page_table_cap_new(
            IT_ASID,               /* capPTMappedASID    */
            (word_t) rootserver.vspace,  /* capPTBasePtr       */
            1,                     /* capPTIsMapped      */
            (word_t) rootserver.vspace   /* capPTMappedAddress */
        );

    seL4_SlotPos slot_pos_before = ndks_boot.slot_pos_cur;
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadVSpace), lvl1pt_cap);

    /* create all n level PT caps necessary to cover userland image in 4KiB pages */
    for (int i = 0; i < CONFIG_PT_LEVELS - 1; i++) {

        for (pt_vptr = ROUND_DOWN(it_v_reg.start, RISCV_GET_LVL_PGSIZE_BITS(i));
             pt_vptr < it_v_reg.end;
             pt_vptr += RISCV_GET_LVL_PGSIZE(i)) {
            if (!provide_cap(root_cnode_cap,
                             create_it_pt_cap(lvl1pt_cap, it_alloc_paging(), pt_vptr, IT_ASID))
               ) {
                return cap_null_cap_new();
            }
        }

    }

    seL4_SlotPos slot_pos_after = ndks_boot.slot_pos_cur;
    ndks_boot.bi_frame->userImagePaging = (seL4_SlotRegion) {
        slot_pos_before, slot_pos_after
    };

    return lvl1pt_cap;
}

BOOT_CODE void activate_kernel_vspace(void)
{
    setVSpaceRoot(kpptr_to_paddr(&kernel_root_pageTable), 0);
}

BOOT_CODE void write_it_asid_pool(cap_t it_ap_cap, cap_t it_lvl1pt_cap)
{
    asid_pool_t *ap = ASID_POOL_PTR(pptr_of_cap(it_ap_cap));
    ap->array[IT_ASID] = PTE_PTR(pptr_of_cap(it_lvl1pt_cap));
    riscvKSASIDTable[IT_ASID >> asidLowBits] = ap;
}

/* ==================== BOOT CODE FINISHES HERE ==================== */

static findVSpaceForASID_ret_t findVSpaceForASID(asid_t asid)
{
    findVSpaceForASID_ret_t ret;
    asid_pool_t        *poolPtr;
    pte_t     *vspace_root;

    poolPtr = riscvKSASIDTable[asid >> asidLowBits];
    if (!poolPtr) {
        current_lookup_fault = lookup_fault_invalid_root_new();

        ret.vspace_root = NULL;
        ret.status = EXCEPTION_LOOKUP_FAULT;
        return ret;
    }

    vspace_root = poolPtr->array[asid & MASK(asidLowBits)];
    if (!vspace_root) {
        current_lookup_fault = lookup_fault_invalid_root_new();

        ret.vspace_root = NULL;
        ret.status = EXCEPTION_LOOKUP_FAULT;
        return ret;
    }

    ret.vspace_root = vspace_root;
    ret.status = EXCEPTION_NONE;
    return ret;
}

void copyGlobalMappings(pte_t *newLvl1pt)
{
    unsigned long i;
    pte_t *global_kernel_vspace = kernel_root_pageTable;

    for (i = RISCV_GET_PT_INDEX(PPTR_BASE, 0); i < BIT(PT_INDEX_BITS); i++) {
        newLvl1pt[i] = global_kernel_vspace[i];
    }
}

word_t *PURE lookupIPCBuffer(bool_t isReceiver, tcb_t *thread)
{
    word_t w_bufferPtr;
    cap_t bufferCap;
    vm_rights_t vm_rights;

    w_bufferPtr = thread->tcbIPCBuffer;
    bufferCap = TCB_PTR_CTE_PTR(thread, tcbBuffer)->cap;

    if (unlikely(cap_get_capType(bufferCap) != cap_frame_cap)) {
        return NULL;
    }
    if (unlikely(cap_frame_cap_get_capFIsDevice(bufferCap))) {
        return NULL;
    }

    vm_rights = cap_frame_cap_get_capFVMRights(bufferCap);
    if (likely(vm_rights == VMReadWrite ||
               (!isReceiver && vm_rights == VMReadOnly))) {
        word_t basePtr, pageBits;

        basePtr = cap_frame_cap_get_capFBasePtr(bufferCap);
        pageBits = pageBitsForSize(cap_frame_cap_get_capFSize(bufferCap));
        return (word_t *)(basePtr + (w_bufferPtr & MASK(pageBits)));
    } else {
        return NULL;
    }
}

static inline pte_t *getPPtrFromHWPTE(pte_t *pte)
{
    return PTE_PTR(ptrFromPAddr(pte_ptr_get_ppn(pte) << seL4_PageTableBits));
}

lookupPTSlot_ret_t lookupPTSlot(pte_t *lvl1pt, vptr_t vptr)
{
    lookupPTSlot_ret_t ret;

    word_t level = CONFIG_PT_LEVELS - 1;
    pte_t *pt = lvl1pt;

    /* this is how many bits we potentially have left to decode. Initially we have the
     * full address space to decode, and every time we walk this will be reduced. The
     * final value of this after the walk is the size of the frame that can be inserted,
     * or already exists, in ret.ptSlot. The following formulation is an invariant of
     * the loop: */
    ret.ptBitsLeft = PT_INDEX_BITS * level + seL4_PageBits;
    ret.ptSlot = pt + ((vptr >> ret.ptBitsLeft) & MASK(PT_INDEX_BITS));

    while (isPTEPageTable(ret.ptSlot) && likely(0 < level)) {
        level--;
        ret.ptBitsLeft -= PT_INDEX_BITS;
        pt = getPPtrFromHWPTE(ret.ptSlot);
        ret.ptSlot = pt + ((vptr >> ret.ptBitsLeft) & MASK(PT_INDEX_BITS));
    }

    return ret;
}

exception_t handleVMFault(tcb_t *thread, vm_fault_type_t vm_faultType)
{
    uint64_t addr;

    addr = read_stval();

    switch (vm_faultType) {
    case RISCVLoadPageFault:
    case RISCVLoadAccessFault:
        current_fault = seL4_Fault_VMFault_new(addr, RISCVLoadAccessFault, false);
        return EXCEPTION_FAULT;
    case RISCVStorePageFault:
    case RISCVStoreAccessFault:
        current_fault = seL4_Fault_VMFault_new(addr, RISCVStoreAccessFault, false);
        return EXCEPTION_FAULT;
    case RISCVInstructionPageFault:
    case RISCVInstructionAccessFault:
        current_fault = seL4_Fault_VMFault_new(addr, RISCVInstructionAccessFault, true);
        return EXCEPTION_FAULT;

    default:
        fail("Invalid VM fault type");
    }
}

void deleteASIDPool(asid_t asid_base, asid_pool_t *pool)
{
    /* Haskell error: "ASID pool's base must be aligned" */
    assert(IS_ALIGNED(asid_base, asidLowBits));

    if (riscvKSASIDTable[asid_base >> asidLowBits] == pool) {
        riscvKSASIDTable[asid_base >> asidLowBits] = NULL;
        setVMRoot(NODE_STATE(ksCurThread));
    }
}

static exception_t performASIDControlInvocation(void *frame, cte_t *slot, cte_t *parent, asid_t asid_base)
{
    /** AUXUPD: "(True, typ_region_bytes (ptr_val \<acute>frame) 12)" */
    /** GHOSTUPD: "(True, gs_clear_region (ptr_val \<acute>frame) 12)" */
    cap_untyped_cap_ptr_set_capFreeIndex(&(parent->cap),
                                         MAX_FREE_INDEX(cap_untyped_cap_get_capBlockSize(parent->cap)));

    memzero(frame, BIT(pageBitsForSize(RISCV_4K_Page)));
    /** AUXUPD: "(True, ptr_retyps 1 (Ptr (ptr_val \<acute>frame) :: asid_pool_C ptr))" */

    cteInsert(
        cap_asid_pool_cap_new(
            asid_base,          /* capASIDBase  */
            WORD_REF(frame)     /* capASIDPool  */
        ),
        parent,
        slot
    );
    /* Haskell error: "ASID pool's base must be aligned" */
    assert((asid_base & MASK(asidLowBits)) == 0);
    riscvKSASIDTable[asid_base >> asidLowBits] = (asid_pool_t *)frame;

    return EXCEPTION_NONE;
}

static exception_t performASIDPoolInvocation(asid_t asid, asid_pool_t *poolPtr, cte_t *vspaceCapSlot)
{
    cap_t cap = vspaceCapSlot->cap;
    pte_t *regionBase = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(cap));
    cap = cap_page_table_cap_set_capPTMappedASID(cap, asid);
    cap = cap_page_table_cap_set_capPTMappedAddress(cap, 0);
    cap = cap_page_table_cap_set_capPTIsMapped(cap, 1);
    vspaceCapSlot->cap = cap;

    copyGlobalMappings(regionBase);

    poolPtr->array[asid & MASK(asidLowBits)] = regionBase;

    return EXCEPTION_NONE;
}

void deleteASID(asid_t asid, pte_t *vspace)
{
    asid_pool_t *poolPtr;

    poolPtr = riscvKSASIDTable[asid >> asidLowBits];
    if (poolPtr != NULL && poolPtr->array[asid & MASK(asidLowBits)] == vspace) {
        hwASIDFlush(asid);
        poolPtr->array[asid & MASK(asidLowBits)] = NULL;
        setVMRoot(NODE_STATE(ksCurThread));
    }
}

void unmapPageTable(asid_t asid, vptr_t vptr, pte_t *target_pt)
{
    findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
    if (unlikely(find_ret.status != EXCEPTION_NONE)) {
        /* nothing to do */
        return;
    }
    /* We won't ever unmap a top level page table */
    assert(find_ret.vspace_root != target_pt);
    pte_t *ptSlot = NULL;
    pte_t *pt = find_ret.vspace_root;

    for (word_t i = 0; i < CONFIG_PT_LEVELS - 1 && pt != target_pt; i++) {
        ptSlot = pt + RISCV_GET_PT_INDEX(vptr, i);
        if (unlikely(!isPTEPageTable(ptSlot))) {
            /* couldn't find it */
            return;
        }
        pt = getPPtrFromHWPTE(ptSlot);
    }

    if (pt != target_pt) {
        /* didn't find it */
        return;
    }
    /* If we found a pt then ptSlot won't be null */
    assert(ptSlot != NULL);
    *ptSlot = pte_new(
                  0,  /* phy_address */
                  0,  /* sw */
                  0,  /* dirty */
                  0,  /* accessed */
                  0,  /* global */
                  0,  /* user */
                  0,  /* execute */
                  0,  /* write */
                  0,  /* read */
                  0  /* valid */
              );
    sfence();
}

static pte_t pte_pte_invalid_new(void)
{
    return (pte_t) {
        0
    };
}

void unmapPage(vm_page_size_t page_size, asid_t asid, vptr_t vptr, pptr_t pptr)
{
    findVSpaceForASID_ret_t find_ret;
    lookupPTSlot_ret_t  lu_ret;

    find_ret = findVSpaceForASID(asid);
    if (find_ret.status != EXCEPTION_NONE) {
        return;
    }

    lu_ret = lookupPTSlot(find_ret.vspace_root, vptr);
    if (unlikely(lu_ret.ptBitsLeft != pageBitsForSize(page_size))) {
        return;
    }
    if (!pte_ptr_get_valid(lu_ret.ptSlot) || isPTEPageTable(lu_ret.ptSlot)
        || (pte_ptr_get_ppn(lu_ret.ptSlot) << seL4_PageBits) != pptr_to_paddr((void *)pptr)) {
        return;
    }

    lu_ret.ptSlot[0] = pte_pte_invalid_new();
    sfence();
}

void setVMRoot(tcb_t *tcb)
{
    cap_t threadRoot;
    asid_t asid;
    pte_t *lvl1pt;
    findVSpaceForASID_ret_t  find_ret;

    threadRoot = TCB_PTR_CTE_PTR(tcb, tcbVTable)->cap;

    if (cap_get_capType(threadRoot) != cap_page_table_cap) {
        setVSpaceRoot(kpptr_to_paddr(&kernel_root_pageTable), 0);
        return;
    }

    lvl1pt = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(threadRoot));

    asid = cap_page_table_cap_get_capPTMappedASID(threadRoot);
    find_ret = findVSpaceForASID(asid);
    if (unlikely(find_ret.status != EXCEPTION_NONE || find_ret.vspace_root != lvl1pt)) {
        setVSpaceRoot(kpptr_to_paddr(&kernel_root_pageTable), 0);
        return;
    }

    setVSpaceRoot(addrFromPPtr(lvl1pt), asid);
}

bool_t CONST isValidVTableRoot(cap_t cap)
{
    return (cap_get_capType(cap) == cap_page_table_cap &&
            cap_page_table_cap_get_capPTIsMapped(cap));
}

exception_t checkValidIPCBuffer(vptr_t vptr, cap_t cap)
{
    if (unlikely(cap_get_capType(cap) != cap_frame_cap)) {
        userError("Requested IPC Buffer is not a frame cap.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (unlikely(cap_frame_cap_get_capFIsDevice(cap))) {
        userError("Specifying a device frame as an IPC buffer is not permitted.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (unlikely(!IS_ALIGNED(vptr, seL4_IPCBufferSizeBits))) {
        userError("Requested IPC Buffer location 0x%x is not aligned.",
                  (int)vptr);
        current_syscall_error.type = seL4_AlignmentError;
        return EXCEPTION_SYSCALL_ERROR;
    }

    return EXCEPTION_NONE;
}

vm_rights_t CONST maskVMRights(vm_rights_t vm_rights, seL4_CapRights_t cap_rights_mask)
{
    if (vm_rights == VMReadOnly && seL4_CapRights_get_capAllowRead(cap_rights_mask)) {
        return VMReadOnly;
    }
    if (vm_rights == VMReadWrite && seL4_CapRights_get_capAllowRead(cap_rights_mask)) {
        if (!seL4_CapRights_get_capAllowWrite(cap_rights_mask)) {
            return VMReadOnly;
        } else {
            return VMReadWrite;
        }
    }
    return VMKernelOnly;
}

/* The rest of the file implements the RISCV object invocations */

static pte_t CONST makeUserPTE(paddr_t paddr, bool_t executable, vm_rights_t vm_rights)
{
    word_t write = RISCVGetWriteFromVMRights(vm_rights);
    word_t read = RISCVGetReadFromVMRights(vm_rights);
    if (unlikely(!read && !write && !executable)) {
        return pte_pte_invalid_new();
    } else {
        return pte_new(
                   paddr >> seL4_PageBits,
                   0, /* sw */
                   1, /* dirty */
                   1, /* accessed */
                   0, /* global */
                   1, /* user */
                   executable, /* execute */
                   RISCVGetWriteFromVMRights(vm_rights), /* write */
                   RISCVGetReadFromVMRights(vm_rights), /* read */
                   1 /* valid */
               );
    }
}

static inline bool_t CONST checkVPAlignment(vm_page_size_t sz, word_t w)
{
    return (w & MASK(pageBitsForSize(sz))) == 0;
}

static exception_t decodeRISCVPageTableInvocation(word_t label, word_t length,
                                                  cte_t *cte, cap_t cap, word_t *buffer)
{
    if (label == RISCVPageTableUnmap) {
        if (unlikely(!isFinalCapability(cte))) {
            userError("RISCVPageTableUnmap: cannot unmap if more than once cap exists");
            current_syscall_error.type = seL4_RevokeFirst;
            return EXCEPTION_SYSCALL_ERROR;
        }
        /* Ensure that if the page table is mapped, it is not a top level table */
        if (likely(cap_page_table_cap_get_capPTIsMapped(cap))) {
            asid_t asid = cap_page_table_cap_get_capPTMappedASID(cap);
            findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
            pte_t *pte = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(cap));
            if (unlikely(find_ret.status == EXCEPTION_NONE &&
                         find_ret.vspace_root == pte)) {
                userError("RISCVPageTableUnmap: cannot call unmap on top level PageTable");
                current_syscall_error.type = seL4_RevokeFirst;
                return EXCEPTION_SYSCALL_ERROR;
            }
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performPageTableInvocationUnmap(cap, cte);
    }

    if (unlikely((label != RISCVPageTableMap))) {
        userError("RISCVPageTable: Illegal Operation");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (unlikely(length < 2 || current_extra_caps.excaprefs[0] == NULL)) {
        userError("RISCVPageTable: truncated message");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }
    if (unlikely(cap_page_table_cap_get_capPTIsMapped(cap))) {
        userError("RISCVPageTable: PageTable is already mapped.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 0;
        return EXCEPTION_SYSCALL_ERROR;
    }

    word_t vaddr = getSyscallArg(0, buffer);
    cap_t lvl1ptCap = current_extra_caps.excaprefs[0]->cap;

    if (unlikely(cap_get_capType(lvl1ptCap) != cap_page_table_cap ||
                 cap_page_table_cap_get_capPTIsMapped(lvl1ptCap) == asidInvalid)) {
        userError("RISCVPageTableMap: Invalid top-level PageTable.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;

        return EXCEPTION_SYSCALL_ERROR;
    }

    pte_t *lvl1pt = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(lvl1ptCap));
    asid_t asid = cap_page_table_cap_get_capPTMappedASID(lvl1ptCap);

    if (unlikely(vaddr >= USER_TOP)) {
        userError("RISCVPageTableMap: Virtual address cannot be in kernel window.");
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 0;

        return EXCEPTION_SYSCALL_ERROR;
    }

    findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
    if (unlikely(find_ret.status != EXCEPTION_NONE)) {
        userError("RISCVPageTableMap: ASID lookup failed");
        current_syscall_error.type = seL4_FailedLookup;
        current_syscall_error.failedLookupWasSource = false;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (unlikely(find_ret.vspace_root != lvl1pt)) {
        userError("RISCVPageTableMap: ASID lookup failed");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    lookupPTSlot_ret_t lu_ret = lookupPTSlot(lvl1pt, vaddr);

    /* if there is already something mapped (valid is set) or we have traversed far enough
     * that a page table is not valid to map then tell the user that they ahve to delete
     * something before they can put a PT here */
    if (lu_ret.ptBitsLeft == seL4_PageBits || pte_ptr_get_valid(lu_ret.ptSlot)) {
        userError("RISCVPageTableMap: All objects mapped at this address");
        current_syscall_error.type = seL4_DeleteFirst;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Get the slot to install the PT in */
    pte_t *ptSlot = lu_ret.ptSlot;

    paddr_t paddr = addrFromPPtr(
                        PTE_PTR(cap_page_table_cap_get_capPTBasePtr(cap)));
    pte_t pte = pte_new((paddr >> seL4_PageBits),
                        0, /* sw */
                        1, /* dirty */
                        1, /* accessed */
                        0,  /* global */
                        0,  /* user */
                        0,  /* execute */
                        0,  /* write */
                        0,  /* read */
                        1 /* valid */
                       );

    cap = cap_page_table_cap_set_capPTIsMapped(cap, 1);
    cap = cap_page_table_cap_set_capPTMappedASID(cap, asid);
    cap = cap_page_table_cap_set_capPTMappedAddress(cap, (vaddr & ~MASK(lu_ret.ptBitsLeft)));

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return performPageTableInvocationMap(cap, cte, pte, ptSlot);
}

static exception_t decodeRISCVFrameInvocation(word_t label, word_t length,
                                              cte_t *cte, cap_t cap, word_t *buffer)
{
    switch (label) {
    case RISCVPageMap: {
        if (unlikely(length < 3 || current_extra_caps.excaprefs[0] == NULL)) {
            userError("RISCVPageMap: Truncated message.");
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }

        word_t vaddr = getSyscallArg(0, buffer);
        word_t w_rightsMask = getSyscallArg(1, buffer);
        vm_attributes_t attr = vmAttributesFromWord(getSyscallArg(2, buffer));
        cap_t lvl1ptCap = current_extra_caps.excaprefs[0]->cap;

        vm_page_size_t frameSize = cap_frame_cap_get_capFSize(cap);
        vm_rights_t capVMRights = cap_frame_cap_get_capFVMRights(cap);

        if (unlikely(cap_get_capType(lvl1ptCap) != cap_page_table_cap ||
                     !cap_page_table_cap_get_capPTIsMapped(lvl1ptCap))) {
            userError("RISCVPageMap: Bad PageTable cap.");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return EXCEPTION_SYSCALL_ERROR;
        }

        pte_t *lvl1pt = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(lvl1ptCap));
        asid_t asid = cap_page_table_cap_get_capPTMappedASID(lvl1ptCap);

        findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
        if (unlikely(find_ret.status != EXCEPTION_NONE)) {
            userError("RISCVPageMap: No PageTable for ASID");
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = false;
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (unlikely(find_ret.vspace_root != lvl1pt)) {
            userError("RISCVPageMap: ASID lookup failed");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return EXCEPTION_SYSCALL_ERROR;
        }

        /* check the vaddr is valid */
        word_t vtop = vaddr + BIT(pageBitsForSize(frameSize)) - 1;
        if (unlikely(vtop >= USER_TOP)) {
            current_syscall_error.type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
        if (unlikely(!checkVPAlignment(frameSize, vaddr))) {
            current_syscall_error.type = seL4_AlignmentError;
            return EXCEPTION_SYSCALL_ERROR;
        }

        /* Check if this page is already mapped */
        lookupPTSlot_ret_t lu_ret = lookupPTSlot(lvl1pt, vaddr);
        if (unlikely(lu_ret.ptBitsLeft != pageBitsForSize(frameSize))) {
            current_lookup_fault = lookup_fault_missing_capability_new(lu_ret.ptBitsLeft);
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = false;
            return EXCEPTION_SYSCALL_ERROR;
        }

        asid_t frame_asid = cap_frame_cap_get_capFMappedASID(cap);
        if (unlikely(frame_asid != asidInvalid)) {
            /* this frame is already mapped */
            if (frame_asid != asid) {
                userError("RISCVPageMap: Attempting to remap a frame that does not belong to the passed address space");
                current_syscall_error.type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 1;
                return EXCEPTION_SYSCALL_ERROR;
            }
            word_t mapped_vaddr = cap_frame_cap_get_capFMappedAddress(cap);
            if (unlikely(mapped_vaddr != vaddr)) {
                userError("RISCVPageMap: attempting to map frame into multiple addresses");
                current_syscall_error.type = seL4_InvalidArgument;
                current_syscall_error.invalidArgumentNumber = 0;
                return EXCEPTION_SYSCALL_ERROR;
            }
            /* this check is redundant, as lookupPTSlot does not stop on a page
             * table PTE */
            if (unlikely(isPTEPageTable(lu_ret.ptSlot))) {
                userError("RISCVPageMap: no mapping to remap.");
                current_syscall_error.type = seL4_DeleteFirst;
                return EXCEPTION_SYSCALL_ERROR;
            }
        } else {
            /* check this vaddr isn't already mapped */
            if (unlikely(pte_ptr_get_valid(lu_ret.ptSlot))) {
                userError("Virtual address already mapped");
                current_syscall_error.type = seL4_DeleteFirst;
                return EXCEPTION_SYSCALL_ERROR;
            }
        }

        vm_rights_t vmRights = maskVMRights(capVMRights, rightsFromWord(w_rightsMask));
        paddr_t frame_paddr = addrFromPPtr((void *) cap_frame_cap_get_capFBasePtr(cap));
        cap = cap_frame_cap_set_capFMappedASID(cap, asid);
        cap = cap_frame_cap_set_capFMappedAddress(cap,  vaddr);

        bool_t executable = !vm_attributes_get_riscvExecuteNever(attr);
        pte_t pte = makeUserPTE(frame_paddr, executable, vmRights);
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performPageInvocationMapPTE(cap, cte, pte, lu_ret.ptSlot);
    }

    case RISCVPageUnmap: {
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performPageInvocationUnmap(cap, cte);
    }

    case RISCVPageGetAddress: {

        /* Check that there are enough message registers */
        assert(n_msgRegisters >= 1);

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performPageGetAddress((void *)cap_frame_cap_get_capFBasePtr(cap));
    }

    default:
        userError("RISCVPage: Illegal operation.");
        current_syscall_error.type = seL4_IllegalOperation;

        return EXCEPTION_SYSCALL_ERROR;
    }

}

exception_t decodeRISCVMMUInvocation(word_t label, word_t length, cptr_t cptr,
                                     cte_t *cte, cap_t cap, word_t *buffer)
{
    switch (cap_get_capType(cap)) {

    case cap_page_table_cap:
        return decodeRISCVPageTableInvocation(label, length, cte, cap, buffer);

    case cap_frame_cap:
        return decodeRISCVFrameInvocation(label, length, cte, cap, buffer);

    case cap_asid_control_cap: {
        word_t     i;
        asid_t           asid_base;
        word_t           index;
        word_t           depth;
        cap_t            untyped;
        cap_t            root;
        cte_t           *parentSlot;
        cte_t           *destSlot;
        lookupSlot_ret_t lu_ret;
        void            *frame;
        exception_t      status;

        if (label != RISCVASIDControlMakePool) {
            current_syscall_error.type = seL4_IllegalOperation;

            return EXCEPTION_SYSCALL_ERROR;
        }

        if (length < 2 || current_extra_caps.excaprefs[0] == NULL
            || current_extra_caps.excaprefs[1] == NULL) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }

        index = getSyscallArg(0, buffer);
        depth = getSyscallArg(1, buffer);
        parentSlot = current_extra_caps.excaprefs[0];
        untyped = parentSlot->cap;
        root = current_extra_caps.excaprefs[1]->cap;

        /* Find first free pool */
        for (i = 0; i < nASIDPools && riscvKSASIDTable[i]; i++);

        if (i == nASIDPools) {
            /* no unallocated pool is found */
            current_syscall_error.type = seL4_DeleteFirst;

            return EXCEPTION_SYSCALL_ERROR;
        }

        asid_base = i << asidLowBits;

        if (cap_get_capType(untyped) != cap_untyped_cap ||
            cap_untyped_cap_get_capBlockSize(untyped) != seL4_ASIDPoolBits ||
            cap_untyped_cap_get_capIsDevice(untyped)) {
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;

            return EXCEPTION_SYSCALL_ERROR;
        }

        status = ensureNoChildren(parentSlot);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        frame = WORD_PTR(cap_untyped_cap_get_capPtr(untyped));

        lu_ret = lookupTargetSlot(root, index, depth);
        if (lu_ret.status != EXCEPTION_NONE) {
            return lu_ret.status;
        }
        destSlot = lu_ret.slot;

        status = ensureEmptySlot(destSlot);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performASIDControlInvocation(frame, destSlot, parentSlot, asid_base);
    }

    case cap_asid_pool_cap: {
        cap_t        vspaceCap;
        cte_t       *vspaceCapSlot;
        asid_pool_t *pool;
        word_t i;
        asid_t       asid;

        if (label != RISCVASIDPoolAssign) {
            current_syscall_error.type = seL4_IllegalOperation;

            return EXCEPTION_SYSCALL_ERROR;
        }
        if (current_extra_caps.excaprefs[0] == NULL) {
            current_syscall_error.type = seL4_TruncatedMessage;

            return EXCEPTION_SYSCALL_ERROR;
        }

        vspaceCapSlot = current_extra_caps.excaprefs[0];
        vspaceCap = vspaceCapSlot->cap;

        if (unlikely(
                cap_get_capType(vspaceCap) != cap_page_table_cap ||
                cap_page_table_cap_get_capPTIsMapped(vspaceCap))) {
            userError("RISCVASIDPool: Invalid vspace root.");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;

            return EXCEPTION_SYSCALL_ERROR;
        }

        pool = riscvKSASIDTable[cap_asid_pool_cap_get_capASIDBase(cap) >> asidLowBits];
        if (!pool) {
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = false;
            current_lookup_fault = lookup_fault_invalid_root_new();
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (pool != ASID_POOL_PTR(cap_asid_pool_cap_get_capASIDPool(cap))) {
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        /* Find first free ASID */
        asid = cap_asid_pool_cap_get_capASIDBase(cap);
        for (i = 0; i < BIT(asidLowBits) && (asid + i == 0 || pool->array[i]); i++);

        if (i == BIT(asidLowBits)) {
            current_syscall_error.type = seL4_DeleteFirst;

            return EXCEPTION_SYSCALL_ERROR;
        }

        asid += i;

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performASIDPoolInvocation(asid, pool, vspaceCapSlot);
    }
    default:
        fail("Invalid arch cap type");
    }
}

exception_t performPageTableInvocationMap(cap_t cap, cte_t *ctSlot,
                                          pte_t pte, pte_t *ptSlot)
{
    ctSlot->cap = cap;
    *ptSlot = pte;
    sfence();

    return EXCEPTION_NONE;
}

exception_t performPageTableInvocationUnmap(cap_t cap, cte_t *ctSlot)
{
    if (cap_page_table_cap_get_capPTIsMapped(cap)) {
        pte_t *pt = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(cap));
        unmapPageTable(
            cap_page_table_cap_get_capPTMappedASID(cap),
            cap_page_table_cap_get_capPTMappedAddress(cap),
            pt
        );
        clearMemory((void *)pt, seL4_PageTableBits);
    }
    cap_page_table_cap_ptr_set_capPTIsMapped(&(ctSlot->cap), 0);

    return EXCEPTION_NONE;
}

static exception_t performPageGetAddress(void *vbase_ptr)
{
    paddr_t capFBasePtr;

    /* Get the physical address of this frame. */
    capFBasePtr = addrFromPPtr(vbase_ptr);

    /* return it in the first message register */
    setRegister(NODE_STATE(ksCurThread), msgRegisters[0], capFBasePtr);
    setRegister(NODE_STATE(ksCurThread), msgInfoRegister,
                wordFromMessageInfo(seL4_MessageInfo_new(0, 0, 0, 1)));

    return EXCEPTION_NONE;
}

static exception_t updatePTE(pte_t pte, pte_t *base)
{
    *base = pte;
    sfence();
    return EXCEPTION_NONE;
}

exception_t performPageInvocationMapPTE(cap_t cap, cte_t *ctSlot,
                                        pte_t pte, pte_t *base)
{
    ctSlot->cap = cap;
    return updatePTE(pte, base);
}

exception_t performPageInvocationUnmap(cap_t cap, cte_t *ctSlot)
{
    if (cap_frame_cap_get_capFMappedASID(cap) != asidInvalid) {
        unmapPage(cap_frame_cap_get_capFSize(cap),
                  cap_frame_cap_get_capFMappedASID(cap),
                  cap_frame_cap_get_capFMappedAddress(cap),
                  cap_frame_cap_get_capFBasePtr(cap)
                 );
    }

    cap_t slotCap = ctSlot->cap;
    slotCap = cap_frame_cap_set_capFMappedAddress(slotCap, 0);
    slotCap = cap_frame_cap_set_capFMappedASID(slotCap, asidInvalid);
    ctSlot->cap = slotCap;

    return EXCEPTION_NONE;
}

#ifdef CONFIG_PRINTING
void Arch_userStackTrace(tcb_t *tptr)
{
    cap_t threadRoot = TCB_PTR_CTE_PTR(tptr, tcbVTable)->cap;
    if (!isValidVTableRoot(threadRoot)) {
        printf("Invalid vspace\n");
        return;
    }

    word_t sp = getRegister(tptr, SP);
    if (!IS_ALIGNED(sp, seL4_WordSizeBits)) {
        printf("SP %p not aligned", (void *) sp);
        return;
    }

    pte_t *vspace_root = PTE_PTR(pptr_of_cap(threadRoot));
    for (int i = 0; i < CONFIG_USER_STACK_TRACE_LENGTH; i++) {
        word_t address = sp + (i * sizeof(word_t));
        lookupPTSlot_ret_t ret = lookupPTSlot(vspace_root, address);
        if (pte_ptr_get_valid(ret.ptSlot) && !isPTEPageTable(ret.ptSlot)) {
            pptr_t pptr = (pptr_t)(getPPtrFromHWPTE(ret.ptSlot));
            word_t *value = (word_t *)((word_t)pptr + (address & MASK(ret.ptBitsLeft)));
            printf("0x%lx: 0x%lx\n", (long) address, (long) *value);
        } else {
            printf("0x%lx: INVALID\n", (long) address);
        }
    }
}
#endif

#ifdef CONFIG_KERNEL_LOG_BUFFER
exception_t benchmark_arch_map_logBuffer(word_t frame_cptr)
{
    lookupCapAndSlot_ret_t lu_ret;
    vm_page_size_t frameSize;
    pptr_t  frame_pptr;

    /* faulting section */
    lu_ret = lookupCapAndSlot(NODE_STATE(ksCurThread), frame_cptr);

    if (unlikely(lu_ret.status != EXCEPTION_NONE)) {
        userError("Invalid cap #%lu.", frame_cptr);
        current_fault = seL4_Fault_CapFault_new(frame_cptr, false);

        return EXCEPTION_SYSCALL_ERROR;
    }

    if (cap_get_capType(lu_ret.cap) != cap_frame_cap) {
        userError("Invalid cap. Log buffer should be of a frame cap");
        current_fault = seL4_Fault_CapFault_new(frame_cptr, false);

        return EXCEPTION_SYSCALL_ERROR;
    }

    frameSize = cap_frame_cap_get_capFSize(lu_ret.cap);

    if (frameSize != RISCV_Mega_Page) {
        userError("Invalid frame size. The kernel expects large page log buffer");
        current_fault = seL4_Fault_CapFault_new(frame_cptr, false);

        return EXCEPTION_SYSCALL_ERROR;
    }

    frame_pptr = cap_frame_cap_get_capFBasePtr(lu_ret.cap);

    ksUserLogBuffer = pptr_to_paddr((void *) frame_pptr);

#if __riscv_xlen == 32
    paddr_t physical_address = ksUserLogBuffer;
    for (word_t i = 0; i < BIT(PT_INDEX_BITS); i += 1) {
        kernel_image_level2_log_buffer_pt[i] = pte_next(physical_address, true);
        physical_address += BIT(PAGE_BITS);
    }
    assert(physical_address - ksUserLogBuffer == BIT(seL4_LargePageBits));
#else
    kernel_image_level2_dev_pt[RISCV_GET_PT_INDEX(KS_LOG_PPTR, 1)] = pte_next(ksUserLogBuffer, true);
#endif

    sfence();

    return EXCEPTION_NONE;
}
#endif /* CONFIG_KERNEL_LOG_BUFFER */
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/machine/fpu.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef CONFIG_HAVE_FPU
#include <arch/machine/fpu.h>

bool_t isFPUEnabledCached[CONFIG_MAX_NUM_NODES];
#endif
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/machine/hardware.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <types.h>
#include <machine/registerset.h>
#include <machine/timer.h>
#include <arch/machine.h>
#include <arch/smp/ipi.h>


#define SIPI_IP   1
#define SIPI_IE   1
#define STIMER_IP 5
#define STIMER_IE 5
#define STIMER_CAUSE 5
#define SEXTERNAL_IP 9
#define SEXTERNAL_IE 9
#define SEXTERNAL_CAUSE 9

#ifndef CONFIG_KERNEL_MCS
#define RESET_CYCLES ((TIMER_CLOCK_HZ / MS_IN_S) * CONFIG_TIMER_TICK_MS)
#endif /* !CONFIG_KERNEL_MCS */

#define IS_IRQ_VALID(X) (((X)) <= maxIRQ && (X)!= irqInvalid)

word_t PURE getRestartPC(tcb_t *thread)
{
    return getRegister(thread, FaultIP);
}

void setNextPC(tcb_t *thread, word_t v)
{
    setRegister(thread, NextIP, v);
}

BOOT_CODE int get_num_avail_p_regs(void)
{
    return sizeof(avail_p_regs) / sizeof(p_region_t);
}

BOOT_CODE p_region_t *get_avail_p_regs(void)
{
    return (p_region_t *) avail_p_regs;
}

BOOT_CODE void map_kernel_devices(void)
{
    if (kernel_devices == NULL) {
        return;
    }

    for (int i = 0; i < (sizeof(kernel_devices) / sizeof(kernel_frame_t)); i++) {
        map_kernel_frame(kernel_devices[i].paddr, kernel_devices[i].pptr,
                         VMKernelOnly);
        if (!kernel_devices[i].userAvailable) {
            p_region_t reg = {
                .start = kernel_devices[i].paddr,
                .end = kernel_devices[i].paddr + (1 << seL4_LargePageBits),
            };
            reserve_region(reg);
        }
    }
}

/*
 * The following assumes familiarity with RISC-V interrupt delivery and the PLIC.
 * See the RISC-V privileged specifivation v1.10 and the comment in
 * include/plat/spike/plat/machine.h for more information.
 * RISC-V IRQ handling on seL4 works as follows:
 *
 * On other architectures the kernel masks interrupts between delivering them to
 * userlevel and receiving the acknowledgement invocation. This strategy doesn't
 * work on RISC-V as an IRQ is implicitly masked when it is claimed, until the
 * claim is acknowledged. If we mask and unmask the interrupt at the PLIC while
 * a claim is in progress we sometimes experience IRQ sources not being masked
 * and unmasked as expected. Because of this, we don't mask and unmask IRQs that
 * are for user level, and also call plic_complete_claim for seL4_IRQHandler_Ack.
 */

/**
 * Gets the new active irq from the PLIC or STIP.
 *
 * getNewActiveIRQ is only called by getActiveIRQ and checks for a pending IRQ.
 * We read sip and if the SEIP bit is set we claim an
 * IRQ from the PLIC. If STIP is set then it is a kernel timer interrupt.
 * Otherwise we return IRQ invalid. It is possible to reveive irqInvalid from
 * the PLIC if another HART context has claimed the IRQ before us. This function
 * is not idempotent as plic_get_claim is called which accepts an IRQ message
 * from the PLIC and will claim different IRQs if called subsequent times.
 *
 * @return     The new active irq.
 */
static irq_t getNewActiveIRQ(void)
{

    uint64_t sip = read_sip();
    /* Interrupt priority (high to low ): external -> software -> timer */
    if (sip & BIT(SEXTERNAL_IP)) {
        return plic_get_claim();
#ifdef ENABLE_SMP_SUPPORT
    } else if (sip & BIT(SIPI_IP)) {
        sbi_clear_ipi();
        return ipi_get_irq();
#endif
    } else if (sip & BIT(STIMER_IP)) {
        return INTERRUPT_CORE_TIMER;
    }

    return irqInvalid;
}

static uint32_t active_irq[CONFIG_MAX_NUM_NODES] = { irqInvalid };


/**
 * Gets the active irq. Returns the same irq if called again before ackInterrupt.
 *
 * getActiveIRQ is used to return a currently pending IRQ. This function can be
 * called multiple times and needs to return the same IRQ until ackInterrupt is
 * called. getActiveIRQ returns irqInvalid if no interrupt is pending. It is
 * assumed that if isIRQPending is true, then getActiveIRQ will not return
 * irqInvalid. getActiveIRQ will call getNewActiveIRQ and cache its result until
 * ackInterrupt is called.
 *
 * @return     The active irq.
 */
static inline irq_t getActiveIRQ(void)
{

    uint32_t irq;
    if (!IS_IRQ_VALID(active_irq[CURRENT_CPU_INDEX()])) {
        active_irq[CURRENT_CPU_INDEX()] = getNewActiveIRQ();
    }

    if (IS_IRQ_VALID(active_irq[CURRENT_CPU_INDEX()])) {
        irq = active_irq[CURRENT_CPU_INDEX()];
    } else {
        irq = irqInvalid;
    }

    return irq;
}

#ifdef HAVE_SET_TRIGGER
/**
 * Sets the irq trigger.
 *
 * setIRQTrigger can change the trigger between edge and level at the PLIC for
 * external interrupts. It is implementation specific as whether the PLIC has
 * support for this operation.
 *
 * @param[in]  irq             The irq
 * @param[in]  edge_triggered  edge triggered otherwise level triggered
 */
void setIRQTrigger(irq_t irq, bool_t edge_triggered)
{
    plic_irq_set_trigger(irq, edge_triggered);
}
#endif

/* isIRQPending is used to determine whether to preempt long running
 * operations at various preemption points throughout the kernel. If this
 * returns true, it means that if the Kernel were to return to user mode, it
 * would then immediately take an interrupt. We check the SIP register for if
 * either a timer interrupt (STIP) or an external interrupt (SEIP) is pending.
 * We don't check software generated interrupts. These are used to perform cross
 * core signalling which isn't currently supported.
 * TODO: Add SSIP check when SMP support is added.
 */
static inline bool_t isIRQPending(void)
{
    word_t sip = read_sip();
    return (sip & (BIT(STIMER_IP) | BIT(SEXTERNAL_IP)));
}

/**
 * Disable or enable IRQs.
 *
 * maskInterrupt disables and enables IRQs. When an IRQ is disabled, it should
 * not raise an interrupt on the Kernel's HART context. This either masks the
 * core timer on the sie register or masks an external IRQ at the plic.
 *
 * @param[in]  disable  The disable
 * @param[in]  irq      The irq
 */
static inline void maskInterrupt(bool_t disable, irq_t irq)
{
    assert(IS_IRQ_VALID(irq));
    if (irq == INTERRUPT_CORE_TIMER) {
        if (disable) {
            clear_sie_mask(BIT(STIMER_IE));
        } else {
            set_sie_mask(BIT(STIMER_IE));
        }
#ifdef ENABLE_SMP_SUPPORT
    } else if (irq == irq_reschedule_ipi || irq == irq_remote_call_ipi) {
        return;
#endif
    } else {
        plic_mask_irq(disable, irq);
    }
}

/**
 * Kernel has dealt with the pending interrupt getActiveIRQ can return next IRQ.
 *
 * ackInterrupt is used by the kernel to indicate it has processed the interrupt
 * delivery and getActiveIRQ is now able to return a different IRQ number. Note
 * that this is called after a notification has been signalled to user level,
 * but before user level has handled the cause.
 *
 * @param[in]  irq   The irq
 */
static inline void ackInterrupt(irq_t irq)
{
    assert(IS_IRQ_VALID(irq));
    active_irq[CURRENT_CPU_INDEX()] = irqInvalid;

    if (irq == INTERRUPT_CORE_TIMER) {
        /* Reprogramming the timer has cleared the interrupt. */
        return;
    }
#ifdef ENABLE_SMP_SUPPORT
    if (irq == irq_reschedule_ipi || irq == irq_remote_call_ipi) {
        ipi_clear_irq(irq);
    }
#endif
}

#ifndef CONFIG_KERNEL_MCS
void resetTimer(void)
{
    uint64_t target;
    // repeatedly try and set the timer in a loop as otherwise there is a race and we
    // may set a timeout in the past, resulting in it never getting triggered
    do {
        target = riscv_read_time() + RESET_CYCLES;
        sbi_set_timer(target);
    } while (riscv_read_time() > target);
}

/**
   DONT_TRANSLATE
 */
BOOT_CODE void initTimer(void)
{
    sbi_set_timer(riscv_read_time() + RESET_CYCLES);
}
#endif /* !CONFIG_KERNEL_MCS */

void plat_cleanL2Range(paddr_t start, paddr_t end)
{
}
void plat_invalidateL2Range(paddr_t start, paddr_t end)
{
}

void plat_cleanInvalidateL2Range(paddr_t start, paddr_t end)
{
}

BOOT_CODE void initL2Cache(void)
{
}

BOOT_CODE void initLocalIRQController(void)
{
    printf("Init local IRQ\n");

#ifdef CONFIG_PLAT_HIFIVE
    /* Init per-hart PLIC */
    plic_init_hart();
#endif

    word_t sie = 0;
    sie |= BIT(SEXTERNAL_IE);
    sie |= BIT(STIMER_IE);

#ifdef ENABLE_SMP_SUPPORT
    /* enable the software-generated interrupts */
    sie |= BIT(SIPI_IE);
#endif

    set_sie_mask(sie);
}

BOOT_CODE void initIRQController(void)
{
    printf("Initialing PLIC...\n");

    plic_init_controller();
}

static inline void handleSpuriousIRQ(void)
{
    /* Do nothing */
    printf("Superior IRQ!! SIP %lx\n", read_sip());
}
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/machine/io.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <machine/io.h>
#include <arch/sbi.h>

#if defined(CONFIG_PRINTING) || defined(CONFIG_DEBUG_BUILD)
void putDebugChar(unsigned char c)
{
    sbi_console_putchar(c);
}
#endif
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/machine/registerset.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <arch/machine/registerset.h>

const register_t msgRegisters[] = {
    a2, a3, a4, a5
};
compile_assert(
    consistent_message_registers,
    sizeof(msgRegisters) / sizeof(msgRegisters[0]) == n_msgRegisters
);

const register_t frameRegisters[] = {
    FaultIP, ra, sp, gp,
    s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11,
};
compile_assert(
    consistent_frame_registers,
    sizeof(frameRegisters) / sizeof(frameRegisters[0]) == n_frameRegisters
);

const register_t gpRegisters[] = {
    a0, a1, a2, a3, a4, a5, a6, a7,
    t0, t1, t2, t3, t4, t5, t6,
    tp,
};
compile_assert(
    consistent_gp_registers,
    sizeof(gpRegisters) / sizeof(gpRegisters[0]) == n_gpRegisters
);

#ifdef CONFIG_KERNEL_MCS
word_t getNBSendRecvDest(void)
{
    return getRegister(NODE_STATE(ksCurThread), nbsendRecvDest);
}
#endif
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/model/statedata.c"
/*
 * Copyright 2020, DornerWorks
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <util.h>
#include <api/types.h>
#include <arch/types.h>
#include <arch/model/statedata.h>
#include <arch/object/structures.h>
#include <linker.h>
#include <plat/machine/hardware.h>

/* The top level asid mapping table */
asid_pool_t *riscvKSASIDTable[BIT(asidHighBits)];

/* Kernel Page Tables */
pte_t kernel_root_pageTable[BIT(PT_INDEX_BITS)] ALIGN_BSS(BIT(seL4_PageTableBits));

#if __riscv_xlen != 32
pte_t kernel_image_level2_pt[BIT(PT_INDEX_BITS)] ALIGN_BSS(BIT(seL4_PageTableBits));
pte_t kernel_image_level2_dev_pt[BIT(PT_INDEX_BITS)] ALIGN_BSS(BIT(seL4_PageTableBits));
#elif defined(CONFIG_KERNEL_LOG_BUFFER)
pte_t kernel_image_level2_log_buffer_pt[BIT(PT_INDEX_BITS)] ALIGN_BSS(BIT(seL4_PageTableBits));
#endif

SMP_STATE_DEFINE(core_map_t, coreMap);
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/object/interrupt.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <api/failures.h>

#include <arch/object/interrupt.h>

exception_t Arch_checkIRQ(word_t irq)
{
    if (irq > maxIRQ || irq == irqInvalid) {
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 1;
        current_syscall_error.rangeErrorMax = maxIRQ;
        userError("Rejecting request for IRQ %u. IRQ is out of range [1..maxIRQ].", (int)irq);
        return EXCEPTION_SYSCALL_ERROR;
    }
    return EXCEPTION_NONE;
}

static exception_t Arch_invokeIRQControl(irq_t irq, cte_t *handlerSlot, cte_t *controlSlot, bool_t trigger)
{
#ifdef HAVE_SET_TRIGGER
    setIRQTrigger(irq, trigger);
#endif
    return invokeIRQControl(irq, handlerSlot, controlSlot);
}

exception_t Arch_decodeIRQControlInvocation(word_t invLabel, word_t length,
                                            cte_t *srcSlot, word_t *buffer)
{
    if (invLabel == RISCVIRQIssueIRQHandlerTrigger) {
        if (length < 4 || current_extra_caps.excaprefs[0] == NULL) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (!config_set(HAVE_SET_TRIGGER)) {
            userError("This platform does not support setting the IRQ trigger");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }

        word_t irq_w = getSyscallArg(0, buffer);
        irq_t irq = (irq_t) irq_w;
        bool_t trigger = !!getSyscallArg(1, buffer);
        word_t index = getSyscallArg(2, buffer);
        word_t depth = getSyscallArg(3, buffer);

        cap_t cnodeCap = current_extra_caps.excaprefs[0]->cap;

        exception_t status = Arch_checkIRQ(irq_w);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        if (isIRQActive(irq)) {
            current_syscall_error.type = seL4_RevokeFirst;
            userError("Rejecting request for IRQ %u. Already active.", (int)irq);
            return EXCEPTION_SYSCALL_ERROR;
        }

        lookupSlot_ret_t lu_ret = lookupTargetSlot(cnodeCap, index, depth);
        if (lu_ret.status != EXCEPTION_NONE) {
            userError("Target slot for new IRQ Handler cap invalid: cap %lu, IRQ %u.",
                      getExtraCPtr(buffer, 0), (int)irq);
            return lu_ret.status;
        }

        cte_t *destSlot = lu_ret.slot;

        status = ensureEmptySlot(destSlot);
        if (status != EXCEPTION_NONE) {
            userError("Target slot for new IRQ Handler cap not empty: cap %lu, IRQ %u.",
                      getExtraCPtr(buffer, 0), (int)irq);
            return status;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return Arch_invokeIRQControl(irq, destSlot, srcSlot, trigger);
    } else {
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }
}
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/object/objecttype.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <api/failures.h>
#include <kernel/vspace.h>
#include <object/structures.h>
#include <arch/machine.h>
#include <arch/model/statedata.h>
#include <arch/object/objecttype.h>

deriveCap_ret_t Arch_deriveCap(cte_t *slot, cap_t cap)
{
    deriveCap_ret_t ret;

    switch (cap_get_capType(cap)) {

    case cap_page_table_cap:
        if (cap_page_table_cap_get_capPTIsMapped(cap)) {
            ret.cap = cap;
            ret.status = EXCEPTION_NONE;
        } else {
            userError("Deriving an unmapped PT cap");
            current_syscall_error.type = seL4_IllegalOperation;
            ret.cap = cap_null_cap_new();
            ret.status = EXCEPTION_SYSCALL_ERROR;
        }
        return ret;

    case cap_frame_cap:
        cap = cap_frame_cap_set_capFMappedAddress(cap, 0);
        ret.cap = cap_frame_cap_set_capFMappedASID(cap, asidInvalid);
        ret.status = EXCEPTION_NONE;
        return ret;

    case cap_asid_control_cap:
    case cap_asid_pool_cap:
        ret.cap = cap;
        ret.status = EXCEPTION_NONE;
        return ret;

    default:
        /* This assert has no equivalent in haskell,
         * as the options are restricted by type */
        fail("Invalid arch cap type");
    }
}

cap_t CONST Arch_updateCapData(bool_t preserve, word_t data, cap_t cap)
{
    return cap;
}

cap_t CONST Arch_maskCapRights(seL4_CapRights_t cap_rights_mask, cap_t cap)
{
    if (cap_get_capType(cap) == cap_frame_cap) {
        vm_rights_t vm_rights;

        vm_rights = vmRightsFromWord(cap_frame_cap_get_capFVMRights(cap));
        vm_rights = maskVMRights(vm_rights, cap_rights_mask);
        return cap_frame_cap_set_capFVMRights(cap, wordFromVMRights(vm_rights));
    } else {
        return cap;
    }
}

finaliseCap_ret_t Arch_finaliseCap(cap_t cap, bool_t final)
{
    finaliseCap_ret_t fc_ret;

    switch (cap_get_capType(cap)) {
    case cap_frame_cap:

        if (cap_frame_cap_get_capFMappedASID(cap)) {
            unmapPage(cap_frame_cap_get_capFSize(cap),
                      cap_frame_cap_get_capFMappedASID(cap),
                      cap_frame_cap_get_capFMappedAddress(cap),
                      cap_frame_cap_get_capFBasePtr(cap));
        }
        break;
    case cap_page_table_cap:
        if (final && cap_page_table_cap_get_capPTIsMapped(cap)) {
            /*
             * This PageTable is either mapped as a vspace_root or otherwise exists
             * as an entry in another PageTable. We check if it is a vspace_root and
             * if it is delete the entry from the ASID pool otherwise we treat it as
             * a mapped PageTable and unmap it from whatever page table it is mapped
             * into.
             */
            asid_t asid = cap_page_table_cap_get_capPTMappedASID(cap);
            findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
            pte_t *pte = PTE_PTR(cap_page_table_cap_get_capPTBasePtr(cap));
            if (find_ret.status == EXCEPTION_NONE && find_ret.vspace_root == pte) {
                deleteASID(asid, pte);
            } else {
                unmapPageTable(asid, cap_page_table_cap_get_capPTMappedAddress(cap), pte);
            }
        }
        break;
    case cap_asid_pool_cap:
        if (final) {
            deleteASIDPool(
                cap_asid_pool_cap_get_capASIDBase(cap),
                ASID_POOL_PTR(cap_asid_pool_cap_get_capASIDPool(cap))
            );
        }
        break;
    case cap_asid_control_cap:
        break;
    }
    fc_ret.remainder = cap_null_cap_new();
    fc_ret.cleanupInfo = cap_null_cap_new();
    return fc_ret;
}

bool_t CONST Arch_sameRegionAs(cap_t cap_a, cap_t cap_b)
{
    switch (cap_get_capType(cap_a)) {
    case cap_frame_cap:
        if (cap_get_capType(cap_b) == cap_frame_cap) {
            word_t botA, botB, topA, topB;
            botA = cap_frame_cap_get_capFBasePtr(cap_a);
            botB = cap_frame_cap_get_capFBasePtr(cap_b);
            topA = botA + MASK(pageBitsForSize(cap_frame_cap_get_capFSize(cap_a)));
            topB = botB + MASK(pageBitsForSize(cap_frame_cap_get_capFSize(cap_b))) ;
            return ((botA <= botB) && (topA >= topB) && (botB <= topB));
        }
        break;

    case cap_page_table_cap:
        if (cap_get_capType(cap_b) == cap_page_table_cap) {
            return cap_page_table_cap_get_capPTBasePtr(cap_a) ==
                   cap_page_table_cap_get_capPTBasePtr(cap_b);
        }
        break;
    case cap_asid_control_cap:
        if (cap_get_capType(cap_b) == cap_asid_control_cap) {
            return true;
        }
        break;

    case cap_asid_pool_cap:
        if (cap_get_capType(cap_b) == cap_asid_pool_cap) {
            return cap_asid_pool_cap_get_capASIDPool(cap_a) ==
                   cap_asid_pool_cap_get_capASIDPool(cap_b);
        }
        break;
    }

    return false;
}


bool_t CONST Arch_sameObjectAs(cap_t cap_a, cap_t cap_b)
{
    if ((cap_get_capType(cap_a) == cap_frame_cap) &&
        (cap_get_capType(cap_b) == cap_frame_cap)) {
        return ((cap_frame_cap_get_capFBasePtr(cap_a) ==
                 cap_frame_cap_get_capFBasePtr(cap_b)) &&
                (cap_frame_cap_get_capFSize(cap_a) ==
                 cap_frame_cap_get_capFSize(cap_b)) &&
                ((cap_frame_cap_get_capFIsDevice(cap_a) == 0) ==
                 (cap_frame_cap_get_capFIsDevice(cap_b) == 0)));
    }
    return Arch_sameRegionAs(cap_a, cap_b);
}

word_t Arch_getObjectSize(word_t t)
{
    switch (t) {
    case seL4_RISCV_4K_Page:
    case seL4_RISCV_PageTableObject:
        return seL4_PageBits;
    case seL4_RISCV_Mega_Page:
        return seL4_LargePageBits;
#if CONFIG_PT_LEVELS > 2
    case seL4_RISCV_Giga_Page:
        return seL4_HugePageBits;
#endif
#if CONFIG_PT_LEVELS > 3
    case seL4_RISCV_Tera_Page:
        return seL4_TeraPageBits;
#endif
    default:
        fail("Invalid object type");
        return 0;
    }
}

cap_t Arch_createObject(object_t t, void *regionBase, word_t userSize, bool_t
                        deviceMemory)
{
    switch (t) {
    case seL4_RISCV_4K_Page:
        if (deviceMemory) {
            /** AUXUPD: "(True, ptr_retyps 1
                     (Ptr (ptr_val \<acute>regionBase) :: user_data_device_C ptr))" */
            /** GHOSTUPD: "(True, gs_new_frames vmpage_size.RISCVSmallPage
                                                    (ptr_val \<acute>regionBase)
                                                    (unat RISCVPageBits))" */
        } else {
            /** AUXUPD: "(True, ptr_retyps 1
                     (Ptr (ptr_val \<acute>regionBase) :: user_data_C ptr))" */
            /** GHOSTUPD: "(True, gs_new_frames vmpage_size.RISCVSmallPage
                                                    (ptr_val \<acute>regionBase)
                                                    (unat RISCVPageBits))" */
        }
        return cap_frame_cap_new(
                   asidInvalid,                    /* capFMappedASID       */
                   (word_t) regionBase,            /* capFBasePtr          */
                   RISCV_4K_Page,                  /* capFSize             */
                   wordFromVMRights(VMReadWrite),  /* capFVMRights         */
                   deviceMemory,                   /* capFIsDevice         */
                   0                               /* capFMappedAddress    */
               );

    case seL4_RISCV_Mega_Page: {
        if (deviceMemory) {
            /** AUXUPD: "(True, ptr_retyps (2^9)
                     (Ptr (ptr_val \<acute>regionBase) :: user_data_device_C ptr))" */
            /** GHOSTUPD: "(True, gs_new_frames vmpage_size.RISCVLargePage
                                                    (ptr_val \<acute>regionBase)
                                                    (unat RISCVMegaPageBits))" */
        } else {
            /** AUXUPD: "(True, ptr_retyps (2^9)
                     (Ptr (ptr_val \<acute>regionBase) :: user_data_C ptr))" */
            /** GHOSTUPD: "(True, gs_new_frames vmpage_size.RISCVLargePage
                                                    (ptr_val \<acute>regionBase)
                                                    (unat RISCVMegaPageBits))" */
        }
        return cap_frame_cap_new(
                   asidInvalid,                    /* capFMappedASID       */
                   (word_t) regionBase,            /* capFBasePtr          */
                   RISCV_Mega_Page,                  /* capFSize             */
                   wordFromVMRights(VMReadWrite),  /* capFVMRights         */
                   deviceMemory,                   /* capFIsDevice         */
                   0                               /* capFMappedAddress    */
               );
    }

#if CONFIG_PT_LEVELS > 2
    case seL4_RISCV_Giga_Page: {
        if (deviceMemory) {
            /** AUXUPD: "(True, ptr_retyps (2^18)
                     (Ptr (ptr_val \<acute>regionBase) :: user_data_device_C ptr))" */
            /** GHOSTUPD: "(True, gs_new_frames vmpage_size.RISCVHugePage
                                                    (ptr_val \<acute>regionBase)
                                                    (unat RISCVGigaPageBits))" */
        } else {
            /** AUXUPD: "(True, ptr_retyps (2^18)
                     (Ptr (ptr_val \<acute>regionBase) :: user_data_C ptr))" */
            /** GHOSTUPD: "(True, gs_new_frames vmpage_size.RISCVHugePage
                                                    (ptr_val \<acute>regionBase)
                                                    (unat RISCVGigaPageBits))" */
        }
        return cap_frame_cap_new(
                   asidInvalid,                    /* capFMappedASID       */
                   (word_t) regionBase,            /* capFBasePtr          */
                   RISCV_Giga_Page,                  /* capFSize             */
                   wordFromVMRights(VMReadWrite),  /* capFVMRights         */
                   deviceMemory,                   /* capFIsDevice         */
                   0                               /* capFMappedAddress    */
               );
    }
#endif

    case seL4_RISCV_PageTableObject:
        /** AUXUPD: "(True, ptr_retyps 1
              (Ptr (ptr_val \<acute>regionBase) :: (pte_C[512]) ptr))" */
        return cap_page_table_cap_new(
                   asidInvalid,            /* capPTMappedASID    */
                   (word_t)regionBase,     /* capPTBasePtr       */
                   0,                      /* capPTIsMapped      */
                   0                       /* capPTMappedAddress */
               );

    default:
        /*
         * This is a conflation of the haskell error: "Arch.createNewCaps
         * got an API type" and the case where an invalid object type is
         * passed (which is impossible in haskell).
         */
        fail("Arch_createObject got an API type or invalid object type");
    }
}

exception_t Arch_decodeInvocation(
    word_t label,
    word_t length,
    cptr_t cptr,
    cte_t *slot,
    cap_t cap,
    bool_t call,
    word_t *buffer
)
{
    return decodeRISCVMMUInvocation(label, length, cptr, slot, cap, buffer);
}

void Arch_prepareThreadDelete(tcb_t *thread)
{
#ifdef CONFIG_HAVE_FPU
    fpuThreadDelete(thread);
#endif
}

bool_t Arch_isFrameType(word_t type)
{
    switch (type) {
#if CONFIG_PT_LEVELS == 4
    case seL4_RISCV_Tera_Page:
#endif
#if CONFIG_PT_LEVELS > 2
    case seL4_RISCV_Giga_Page:
#endif
    case seL4_RISCV_Mega_Page:
    case seL4_RISCV_4K_Page:
        return true;
    default:
        return false;
    }
}
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/object/tcb.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <api/failures.h>
#include <machine/registerset.h>
#include <object/structures.h>
#include <arch/machine.h>
#include <object/tcb.h>

word_t CONST Arch_decodeTransfer(word_t flags)
{
    return 0;
}

exception_t CONST Arch_performTransfer(word_t arch, tcb_t *tcb_src, tcb_t *tcb_dest)
{
    return EXCEPTION_NONE;
}

#ifdef ENABLE_SMP_SUPPORT
void Arch_migrateTCB(tcb_t *thread)
{
#ifdef CONFIG_HAVE_FPU
    if (nativeThreadUsingFPU(thread)) {
        switchFpuOwner(NULL, thread->tcbAffinity);
    }
#endif
}
#endif
#line 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/smp/ipi.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <mode/smp/ipi.h>
#include <smp/lock.h>
#include <util.h>

#ifdef ENABLE_SMP_SUPPORT

/* the remote call being requested */
static volatile IpiRemoteCall_t  remoteCall;
static volatile irq_t            ipiIrq[CONFIG_MAX_NUM_NODES];

static inline void init_ipi_args(IpiRemoteCall_t func,
                                 word_t data1, word_t data2, word_t data3,
                                 word_t mask)
{
    remoteCall = func;
    ipi_args[0] = data1;
    ipi_args[1] = data2;
    ipi_args[2] = data3;

    /* get number of cores involved in this IPI */
    totalCoreBarrier = popcountl(mask);
}

static void handleRemoteCall(IpiRemoteCall_t call, word_t arg0,
                             word_t arg1, word_t arg2, bool_t irqPath)
{
    /* we gets spurious irq_remote_call_ipi calls, e.g. when handling IPI
     * in lock while hardware IPI is pending. Guard against spurious IPIs! */
    if (clh_is_ipi_pending(getCurrentCPUIndex())) {
        switch ((IpiRemoteCall_t)call) {
        case IpiRemoteCall_Stall:
            ipiStallCoreCallback(irqPath);
            break;

#ifdef CONFIG_HAVE_FPU
        case IpiRemoteCall_switchFpuOwner:
            switchLocalFpuOwner((user_fpu_state_t *)arg0);
            break;
#endif /* CONFIG_HAVE_FPU */

        default:
            fail("Invalid remote call");
            break;
        }

        big_kernel_lock.node_owners[getCurrentCPUIndex()].ipi = 0;
        ipiIrq[getCurrentCPUIndex()] = irqInvalid;
        ipi_wait(totalCoreBarrier);
    }
}

void ipi_send_mask(irq_t ipi, word_t mask, bool_t isBlocking)
{

    generic_ipi_send_mask(ipi, mask, isBlocking);
}

irq_t ipi_get_irq(void)
{
    assert(!(ipiIrq[getCurrentCPUIndex()] == irqInvalid && big_kernel_lock.node_owners[getCurrentCPUIndex()].ipi == 1));
    return ipiIrq[getCurrentCPUIndex()];
}

void ipi_clear_irq(irq_t irq)
{
    ipiIrq[getCurrentCPUIndex()] = irqInvalid;
    return;
}

/* this function is called with a single hart id. */
void ipi_send_target(irq_t irq, word_t hart_id)
{
    unsigned long hart_mask;
    word_t core_id = hartIDToCoreID(hart_id);
    assert(core_id < CONFIG_MAX_NUM_NODES);
    hart_mask = BIT(hart_id);

    assert((ipiIrq[core_id] == irqInvalid) || (ipiIrq[core_id] == irq_reschedule_ipi) ||
           (ipiIrq[core_id] == irq_remote_call_ipi && big_kernel_lock.node_owners[core_id].ipi == 0));

    ipiIrq[core_id] = irq;
    asm volatile("fence rw,rw");
    sbi_send_ipi(&hart_mask);
}

#endif
#line 1 "/home/koc034/Documents/newver/seL4/src/assert.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <machine/io.h>

#ifdef CONFIG_DEBUG_BUILD

void _fail(
    const char  *s,
    const char  *file,
    unsigned int line,
    const char  *function)
{
    printf(
        "seL4 called fail at %s:%u in function %s, saying \"%s\"\n",
        file,
        line,
        function,
        s
    );
    halt();
}

void _assert_fail(
    const char  *assertion,
    const char  *file,
    unsigned int line,
    const char  *function)
{
    printf("seL4 failed assertion '%s' at %s:%u in function %s\n",
           assertion,
           file,
           line,
           function
          );
    halt();
}

#endif
#line 1 "/home/koc034/Documents/newver/seL4/src/benchmark/benchmark_track.c"
/*
 * Copyright 2016, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <benchmark/benchmark_track.h>
#include <model/statedata.h>

#ifdef CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES

timestamp_t ksEnter;
seL4_Word ksLogIndex;
seL4_Word ksLogIndexFinalized;

void benchmark_track_exit(void)
{
    timestamp_t duration = 0;
    timestamp_t ksExit = timestamp();
    benchmark_track_kernel_entry_t *ksLog = (benchmark_track_kernel_entry_t *) KS_LOG_PPTR;

    if (likely(ksUserLogBuffer != 0)) {
        /* If Log buffer is filled, do nothing */
        if (likely(ksLogIndex < MAX_LOG_SIZE)) {
            duration = ksExit - ksEnter;
            ksLog[ksLogIndex].entry = ksKernelEntry;
            ksLog[ksLogIndex].start_time = ksEnter;
            ksLog[ksLogIndex].duration = duration;
            ksLogIndex++;
        }
    }
}
#endif /* CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES */
#line 1 "/home/koc034/Documents/newver/seL4/src/benchmark/benchmark_utilisation.c"
/*
 * Copyright 2016, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <benchmark/benchmark_utilisation.h>

#ifdef CONFIG_BENCHMARK_TRACK_UTILISATION

timestamp_t ksEnter;

void benchmark_track_utilisation_dump(void)
{
    uint64_t *buffer = ((uint64_t *) & (((seL4_IPCBuffer *)lookupIPCBuffer(true, NODE_STATE(ksCurThread)))->msg[0]));
    tcb_t *tcb = NULL;
    word_t tcb_cptr = getRegister(NODE_STATE(ksCurThread), capRegister);
    lookupCap_ret_t lu_ret;
    word_t cap_type;

    lu_ret = lookupCap(NODE_STATE(ksCurThread), tcb_cptr);
    /* ensure we got a TCB cap */
    cap_type = cap_get_capType(lu_ret.cap);
    if (cap_type != cap_thread_cap) {
        userError("SysBenchmarkFinalizeLog: cap is not a TCB, halting");
        return;
    }

    tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(lu_ret.cap));

    /* Selected TCB counters */
    buffer[BENCHMARK_TCB_UTILISATION] = tcb->benchmark.utilisation; /* Requested thread utilisation */
    buffer[BENCHMARK_TCB_NUMBER_SCHEDULES] = tcb->benchmark.number_schedules; /* Number of times scheduled */
    buffer[BENCHMARK_TCB_KERNEL_UTILISATION] = tcb->benchmark.kernel_utilisation; /* Utilisation spent in kernel */
    buffer[BENCHMARK_TCB_NUMBER_KERNEL_ENTRIES] = tcb->benchmark.number_kernel_entries; /* Number of kernel entries */

    /* Idle counters */
    buffer[BENCHMARK_IDLE_LOCALCPU_UTILISATION] = NODE_STATE(
                                                      ksIdleThread)->benchmark.utilisation; /* Idle thread utilisation of current CPU */
#ifdef ENABLE_SMP_SUPPORT
    buffer[BENCHMARK_IDLE_TCBCPU_UTILISATION] = NODE_STATE_ON_CORE(ksIdleThread,
                                                                   tcb->tcbAffinity)->benchmark.utilisation; /* Idle thread utilisation of CPU the TCB is running on */
#else
    buffer[BENCHMARK_IDLE_TCBCPU_UTILISATION] = buffer[BENCHMARK_IDLE_LOCALCPU_UTILISATION];
#endif

    buffer[BENCHMARK_IDLE_NUMBER_SCHEDULES] = NODE_STATE(
                                                  ksIdleThread)->benchmark.number_schedules; /* Number of times scheduled */
    buffer[BENCHMARK_IDLE_KERNEL_UTILISATION] = NODE_STATE(
                                                    ksIdleThread)->benchmark.kernel_utilisation; /* Utilisation spent in kernel */
    buffer[BENCHMARK_IDLE_NUMBER_KERNEL_ENTRIES] = NODE_STATE(
                                                       ksIdleThread)->benchmark.number_kernel_entries; /* Number of kernel entries */


    /* Total counters */
#ifdef CONFIG_ARM_ENABLE_PMU_OVERFLOW_INTERRUPT
    buffer[BENCHMARK_TOTAL_UTILISATION] =
        (NODE_STATE(ccnt_num_overflows) * 0xFFFFFFFFU) + NODE_STATE(benchmark_end_time) - NODE_STATE(benchmark_start_time);
#else
    buffer[BENCHMARK_TOTAL_UTILISATION] = NODE_STATE(benchmark_end_time) - NODE_STATE(
                                              benchmark_start_time); /* Overall time */
#endif /* CONFIG_ARM_ENABLE_PMU_OVERFLOW_INTERRUPT */
    buffer[BENCHMARK_TOTAL_NUMBER_SCHEDULES] = NODE_STATE(benchmark_kernel_number_schedules);
    buffer[BENCHMARK_TOTAL_KERNEL_UTILISATION] = NODE_STATE(benchmark_kernel_time);
    buffer[BENCHMARK_TOTAL_NUMBER_KERNEL_ENTRIES] = NODE_STATE(benchmark_kernel_number_entries);

}

void benchmark_track_reset_utilisation(tcb_t *tcb)
{
    tcb->benchmark.utilisation = 0;
    tcb->benchmark.number_schedules = 0;
    tcb->benchmark.number_kernel_entries = 0;
    tcb->benchmark.kernel_utilisation = 0;
    tcb->benchmark.schedule_start_time = 0;
}
#endif /* CONFIG_BENCHMARK_TRACK_UTILISATION */
#line 1 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <fastpath/fastpath.h>
#ifdef CONFIG_KERNEL_MCS
#include <object/reply.h>
#endif

#ifdef CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES
#include <benchmark/benchmark_track.h>
#endif
#include <benchmark/benchmark_utilisation.h>

#ifdef CONFIG_ARCH_ARM
static inline
#ifndef CONFIG_ARCH_ARM_V6
FORCE_INLINE
#endif
#endif
void NORETURN fastpath_call(word_t cptr, word_t msgInfo)
{
    seL4_MessageInfo_t info;
    cap_t ep_cap;
    endpoint_t *ep_ptr;
    word_t length;
    tcb_t *dest;
    word_t badge;
    cap_t newVTable;
    vspace_root_t *cap_pd;
    pde_t stored_hw_asid;
    word_t fault_type;
    dom_t dom;

    /* Get message info, length, and fault type. */
    info = messageInfoFromWord_raw(msgInfo);
    length = seL4_MessageInfo_get_length(info);
    fault_type = seL4_Fault_get_seL4_FaultType(NODE_STATE(ksCurThread)->tcbFault);

    /* Check there's no extra caps, the length is ok and there's no
     * saved fault. */
    if (unlikely(fastpath_mi_check(msgInfo) ||
                 fault_type != seL4_Fault_NullFault)) {
        slowpath(SysCall);
    }

    /* Lookup the cap */
    ep_cap = lookup_fp(TCB_PTR_CTE_PTR(NODE_STATE(ksCurThread), tcbCTable)->cap, cptr);

    /* Check it's an endpoint */
    if (unlikely(!cap_capType_equals(ep_cap, cap_endpoint_cap) ||
                 !cap_endpoint_cap_get_capCanSend(ep_cap))) {
        slowpath(SysCall);
    }

    /* Get the endpoint address */
    ep_ptr = EP_PTR(cap_endpoint_cap_get_capEPPtr(ep_cap));

    /* Get the destination thread, which is only going to be valid
     * if the endpoint is valid. */
    dest = TCB_PTR(endpoint_ptr_get_epQueue_head(ep_ptr));

    /* Check that there's a thread waiting to receive */
    if (unlikely(endpoint_ptr_get_state(ep_ptr) != EPState_Recv)) {
        slowpath(SysCall);
    }

    /* ensure we are not single stepping the destination in ia32 */
#if defined(CONFIG_HARDWARE_DEBUG_API) && defined(CONFIG_ARCH_IA32)
    if (unlikely(dest->tcbArch.tcbContext.breakpointState.single_step_enabled)) {
        slowpath(SysCall);
    }
#endif

    /* Get destination thread.*/
    newVTable = TCB_PTR_CTE_PTR(dest, tcbVTable)->cap;

    /* Get vspace root. */
    cap_pd = cap_vtable_cap_get_vspace_root_fp(newVTable);

    /* Ensure that the destination has a valid VTable. */
    if (unlikely(! isValidVTableRoot_fp(newVTable))) {
        slowpath(SysCall);
    }

#ifdef CONFIG_ARCH_AARCH32
    /* Get HW ASID */
    stored_hw_asid = cap_pd[PD_ASID_SLOT];
#endif

#ifdef CONFIG_ARCH_X86_64
    /* borrow the stored_hw_asid for PCID */
    stored_hw_asid.words[0] = cap_pml4_cap_get_capPML4MappedASID_fp(newVTable);
#endif

#ifdef CONFIG_ARCH_IA32
    /* stored_hw_asid is unused on ia32 fastpath, but gets passed into a function below. */
    stored_hw_asid.words[0] = 0;
#endif
#ifdef CONFIG_ARCH_AARCH64
    stored_hw_asid.words[0] = cap_vtable_root_get_mappedASID(newVTable);
#endif

#ifdef CONFIG_ARCH_RISCV
    /* Get HW ASID */
    stored_hw_asid.words[0] = cap_page_table_cap_get_capPTMappedASID(newVTable);
#endif

    /* let gcc optimise this out for 1 domain */
    dom = maxDom ? ksCurDomain : 0;
    /* ensure only the idle thread or lower prio threads are present in the scheduler */
    if (unlikely(dest->tcbPriority < NODE_STATE(ksCurThread->tcbPriority) &&
                 !isHighestPrio(dom, dest->tcbPriority))) {
        slowpath(SysCall);
    }

    /* Ensure that the endpoint has has grant or grant-reply rights so that we can
     * create the reply cap */
    if (unlikely(!cap_endpoint_cap_get_capCanGrant(ep_cap) &&
                 !cap_endpoint_cap_get_capCanGrantReply(ep_cap))) {
        slowpath(SysCall);
    }

#ifdef CONFIG_ARCH_AARCH32
    if (unlikely(!pde_pde_invalid_get_stored_asid_valid(stored_hw_asid))) {
        slowpath(SysCall);
    }
#endif

    /* Ensure the original caller is in the current domain and can be scheduled directly. */
    if (unlikely(dest->tcbDomain != ksCurDomain && maxDom)) {
        slowpath(SysCall);
    }

#ifdef CONFIG_KERNEL_MCS
    if (unlikely(dest->tcbSchedContext != NULL)) {
        slowpath(SysCall);
    }

    reply_t *reply = thread_state_get_replyObject_np(dest->tcbState);
    if (unlikely(reply == NULL)) {
        slowpath(SysCall);
    }
#endif

#ifdef ENABLE_SMP_SUPPORT
    /* Ensure both threads have the same affinity */
    if (unlikely(NODE_STATE(ksCurThread)->tcbAffinity != dest->tcbAffinity)) {
        slowpath(SysCall);
    }
#endif /* ENABLE_SMP_SUPPORT */

    /*
     * --- POINT OF NO RETURN ---
     *
     * At this stage, we have committed to performing the IPC.
     */

#ifdef CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES
    ksKernelEntry.is_fastpath = true;
#endif

    /* Dequeue the destination. */
    endpoint_ptr_set_epQueue_head_np(ep_ptr, TCB_REF(dest->tcbEPNext));
    if (unlikely(dest->tcbEPNext)) {
        dest->tcbEPNext->tcbEPPrev = NULL;
    } else {
        endpoint_ptr_mset_epQueue_tail_state(ep_ptr, 0, EPState_Idle);
    }

    badge = cap_endpoint_cap_get_capEPBadge(ep_cap);

    /* Unlink dest <-> reply, link src (cur thread) <-> reply */
    thread_state_ptr_set_tsType_np(&NODE_STATE(ksCurThread)->tcbState,
                                   ThreadState_BlockedOnReply);
#ifdef CONFIG_KERNEL_MCS
    thread_state_ptr_set_replyObject_np(&dest->tcbState, 0);
    thread_state_ptr_set_replyObject_np(&NODE_STATE(ksCurThread)->tcbState, REPLY_REF(reply));
    reply->replyTCB = NODE_STATE(ksCurThread);

    sched_context_t *sc = NODE_STATE(ksCurThread)->tcbSchedContext;
    sc->scTcb = dest;
    dest->tcbSchedContext = sc;
    NODE_STATE(ksCurThread)->tcbSchedContext = NULL;

    reply_t *old_caller = sc->scReply;
    reply->replyPrev = call_stack_new(REPLY_REF(sc->scReply), false);
    if (unlikely(old_caller)) {
        old_caller->replyNext = call_stack_new(REPLY_REF(reply), false);
    }
    reply->replyNext = call_stack_new(SC_REF(sc), true);
    sc->scReply = reply;
#else
    /* Get sender reply slot */
    cte_t *replySlot = TCB_PTR_CTE_PTR(NODE_STATE(ksCurThread), tcbReply);

    /* Get dest caller slot */
    cte_t *callerSlot = TCB_PTR_CTE_PTR(dest, tcbCaller);

    /* Insert reply cap */
    word_t replyCanGrant = thread_state_ptr_get_blockingIPCCanGrant(&dest->tcbState);;
    cap_reply_cap_ptr_new_np(&callerSlot->cap, replyCanGrant, 0,
                             TCB_REF(NODE_STATE(ksCurThread)));
    mdb_node_ptr_set_mdbPrev_np(&callerSlot->cteMDBNode, CTE_REF(replySlot));
    mdb_node_ptr_mset_mdbNext_mdbRevocable_mdbFirstBadged(
        &replySlot->cteMDBNode, CTE_REF(callerSlot), 1, 1);
#endif

    fastpath_copy_mrs(length, NODE_STATE(ksCurThread), dest);

    /* Dest thread is set Running, but not queued. */
    thread_state_ptr_set_tsType_np(&dest->tcbState,
                                   ThreadState_Running);
    switchToThread_fp(dest, cap_pd, stored_hw_asid);

    msgInfo = wordFromMessageInfo(seL4_MessageInfo_set_capsUnwrapped(info, 0));

    fastpath_restore(badge, msgInfo, NODE_STATE(ksCurThread));
}

#ifdef CONFIG_ARCH_ARM
static inline
#ifndef CONFIG_ARCH_ARM_V6
FORCE_INLINE
#endif
#endif
#ifdef CONFIG_KERNEL_MCS
void NORETURN fastpath_reply_recv(word_t cptr, word_t msgInfo, word_t reply)
#else
void NORETURN fastpath_reply_recv(word_t cptr, word_t msgInfo)
#endif
{
    seL4_MessageInfo_t info;
    cap_t ep_cap;
    endpoint_t *ep_ptr;
    word_t length;
    tcb_t *caller;
    word_t badge;
    tcb_t *endpointTail;
    word_t fault_type;

    cap_t newVTable;
    vspace_root_t *cap_pd;
    pde_t stored_hw_asid;
    dom_t dom;

    /* Get message info and length */
    info = messageInfoFromWord_raw(msgInfo);
    length = seL4_MessageInfo_get_length(info);
    fault_type = seL4_Fault_get_seL4_FaultType(NODE_STATE(ksCurThread)->tcbFault);

    /* Check there's no extra caps, the length is ok and there's no
     * saved fault. */
    if (unlikely(fastpath_mi_check(msgInfo) ||
                 fault_type != seL4_Fault_NullFault)) {
        slowpath(SysReplyRecv);
    }

    /* Lookup the cap */
    ep_cap = lookup_fp(TCB_PTR_CTE_PTR(NODE_STATE(ksCurThread), tcbCTable)->cap,
                       cptr);

    /* Check it's an endpoint */
    if (unlikely(!cap_capType_equals(ep_cap, cap_endpoint_cap) ||
                 !cap_endpoint_cap_get_capCanReceive(ep_cap))) {
        slowpath(SysReplyRecv);
    }

#ifdef CONFIG_KERNEL_MCS
    /* lookup the reply object */
    cap_t reply_cap = lookup_fp(TCB_PTR_CTE_PTR(NODE_STATE(ksCurThread), tcbCTable)->cap, reply);

    /* check it's a reply object */
    if (unlikely(!cap_capType_equals(reply_cap, cap_reply_cap))) {
        slowpath(SysReplyRecv);
    }
#endif

    /* Check there is nothing waiting on the notification */
    if (unlikely(NODE_STATE(ksCurThread)->tcbBoundNotification &&
                 notification_ptr_get_state(NODE_STATE(ksCurThread)->tcbBoundNotification) == NtfnState_Active)) {
        slowpath(SysReplyRecv);
    }

    /* Get the endpoint address */
    ep_ptr = EP_PTR(cap_endpoint_cap_get_capEPPtr(ep_cap));

    /* Check that there's not a thread waiting to send */
    if (unlikely(endpoint_ptr_get_state(ep_ptr) == EPState_Send)) {
        slowpath(SysReplyRecv);
    }

#ifdef CONFIG_KERNEL_MCS
    /* Get the reply address */
    reply_t *reply_ptr = REPLY_PTR(cap_reply_cap_get_capReplyPtr(reply_cap));
    /* check that its valid and at the head of the call chain
       and that the current thread's SC is going to be donated. */
    if (unlikely(reply_ptr->replyTCB == NULL ||
                 call_stack_get_isHead(reply_ptr->replyNext) == 0 ||
                 SC_PTR(call_stack_get_callStackPtr(reply_ptr->replyNext)) != NODE_STATE(ksCurThread)->tcbSchedContext)) {
        slowpath(SysReplyRecv);
    }

    /* Determine who the caller is. */
    caller = reply_ptr->replyTCB;
#else
    /* Only reply if the reply cap is valid. */
    cte_t *callerSlot = TCB_PTR_CTE_PTR(NODE_STATE(ksCurThread), tcbCaller);
    cap_t callerCap = callerSlot->cap;
    if (unlikely(!fastpath_reply_cap_check(callerCap))) {
        slowpath(SysReplyRecv);
    }

    /* Determine who the caller is. */
    caller = TCB_PTR(cap_reply_cap_get_capTCBPtr(callerCap));
#endif

    /* ensure we are not single stepping the caller in ia32 */
#if defined(CONFIG_HARDWARE_DEBUG_API) && defined(CONFIG_ARCH_IA32)
    if (unlikely(caller->tcbArch.tcbContext.breakpointState.single_step_enabled)) {
        slowpath(SysReplyRecv);
    }
#endif

    /* Check that the caller has not faulted, in which case a fault
       reply is generated instead. */
    fault_type = seL4_Fault_get_seL4_FaultType(caller->tcbFault);
    if (unlikely(fault_type != seL4_Fault_NullFault)) {
        slowpath(SysReplyRecv);
    }

    /* Get destination thread.*/
    newVTable = TCB_PTR_CTE_PTR(caller, tcbVTable)->cap;

    /* Get vspace root. */
    cap_pd = cap_vtable_cap_get_vspace_root_fp(newVTable);

    /* Ensure that the destination has a valid MMU. */
    if (unlikely(! isValidVTableRoot_fp(newVTable))) {
        slowpath(SysReplyRecv);
    }

#ifdef CONFIG_ARCH_AARCH32
    /* Get HWASID. */
    stored_hw_asid = cap_pd[PD_ASID_SLOT];
#endif

#ifdef CONFIG_ARCH_X86_64
    stored_hw_asid.words[0] = cap_pml4_cap_get_capPML4MappedASID(newVTable);
#endif
#ifdef CONFIG_ARCH_IA32
    /* stored_hw_asid is unused on ia32 fastpath, but gets passed into a function below. */
    stored_hw_asid.words[0] = 0;
#endif
#ifdef CONFIG_ARCH_AARCH64
    stored_hw_asid.words[0] = cap_vtable_root_get_mappedASID(newVTable);
#endif

#ifdef CONFIG_ARCH_RISCV
    stored_hw_asid.words[0] = cap_page_table_cap_get_capPTMappedASID(newVTable);
#endif

    /* Ensure the original caller can be scheduled directly. */
    dom = maxDom ? ksCurDomain : 0;
    if (unlikely(!isHighestPrio(dom, caller->tcbPriority))) {
        slowpath(SysReplyRecv);
    }

#ifdef CONFIG_ARCH_AARCH32
    /* Ensure the HWASID is valid. */
    if (unlikely(!pde_pde_invalid_get_stored_asid_valid(stored_hw_asid))) {
        slowpath(SysReplyRecv);
    }
#endif

    /* Ensure the original caller is in the current domain and can be scheduled directly. */
    if (unlikely(caller->tcbDomain != ksCurDomain && maxDom)) {
        slowpath(SysReplyRecv);
    }

#ifdef CONFIG_KERNEL_MCS
    if (unlikely(caller->tcbSchedContext != NULL)) {
        slowpath(SysReplyRecv);
    }
#endif

#ifdef ENABLE_SMP_SUPPORT
    /* Ensure both threads have the same affinity */
    if (unlikely(NODE_STATE(ksCurThread)->tcbAffinity != caller->tcbAffinity)) {
        slowpath(SysReplyRecv);
    }
#endif /* ENABLE_SMP_SUPPORT */

#ifdef CONFIG_KERNEL_MCS
    /* not possible to set reply object and not be blocked */
    assert(thread_state_get_replyObject(NODE_STATE(ksCurThread)->tcbState) == 0);
#endif

    /*
     * --- POINT OF NO RETURN ---
     *
     * At this stage, we have committed to performing the IPC.
     */

#ifdef CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES
    ksKernelEntry.is_fastpath = true;
#endif

    /* Set thread state to BlockedOnReceive */
    thread_state_ptr_mset_blockingObject_tsType(
        &NODE_STATE(ksCurThread)->tcbState, (word_t)ep_ptr, ThreadState_BlockedOnReceive);
#ifdef CONFIG_KERNEL_MCS
    /* unlink reply object from caller */
    thread_state_ptr_set_replyObject_np(&caller->tcbState, 0);
    /* set the reply object */
    thread_state_ptr_set_replyObject_np(&NODE_STATE(ksCurThread)->tcbState, REPLY_REF(reply_ptr));
    reply_ptr->replyTCB = NODE_STATE(ksCurThread);
#else
    thread_state_ptr_set_blockingIPCCanGrant(&NODE_STATE(ksCurThread)->tcbState,
                                             cap_endpoint_cap_get_capCanGrant(ep_cap));;
#endif

    /* Place the thread in the endpoint queue */
    endpointTail = endpoint_ptr_get_epQueue_tail_fp(ep_ptr);
    if (likely(!endpointTail)) {
        NODE_STATE(ksCurThread)->tcbEPPrev = NULL;
        NODE_STATE(ksCurThread)->tcbEPNext = NULL;

        /* Set head/tail of queue and endpoint state. */
        endpoint_ptr_set_epQueue_head_np(ep_ptr, TCB_REF(NODE_STATE(ksCurThread)));
        endpoint_ptr_mset_epQueue_tail_state(ep_ptr, TCB_REF(NODE_STATE(ksCurThread)),
                                             EPState_Recv);
    } else {
#ifdef CONFIG_KERNEL_MCS
        /* Update queue. */
        tcb_queue_t queue = tcbEPAppend(NODE_STATE(ksCurThread), ep_ptr_get_queue(ep_ptr));
        endpoint_ptr_set_epQueue_head_np(ep_ptr, TCB_REF(queue.head));
        endpoint_ptr_mset_epQueue_tail_state(ep_ptr, TCB_REF(queue.end), EPState_Recv);
#else
        /* Append current thread onto the queue. */
        endpointTail->tcbEPNext = NODE_STATE(ksCurThread);
        NODE_STATE(ksCurThread)->tcbEPPrev = endpointTail;
        NODE_STATE(ksCurThread)->tcbEPNext = NULL;

        /* Update tail of queue. */
        endpoint_ptr_mset_epQueue_tail_state(ep_ptr, TCB_REF(NODE_STATE(ksCurThread)),
                                             EPState_Recv);
#endif
    }

#ifdef CONFIG_KERNEL_MCS
    /* update call stack */
    word_t prev_ptr = call_stack_get_callStackPtr(reply_ptr->replyPrev);
    sched_context_t *sc = NODE_STATE(ksCurThread)->tcbSchedContext;
    NODE_STATE(ksCurThread)->tcbSchedContext = NULL;
    caller->tcbSchedContext = sc;
    sc->scTcb = caller;

    sc->scReply = REPLY_PTR(prev_ptr);
    if (unlikely(REPLY_PTR(prev_ptr) != NULL)) {
        sc->scReply->replyNext = reply_ptr->replyNext;
    }

    /* TODO neccessary? */
    reply_ptr->replyPrev.words[0] = 0;
    reply_ptr->replyNext.words[0] = 0;
#else
    /* Delete the reply cap. */
    mdb_node_ptr_mset_mdbNext_mdbRevocable_mdbFirstBadged(
        &CTE_PTR(mdb_node_get_mdbPrev(callerSlot->cteMDBNode))->cteMDBNode,
        0, 1, 1);
    callerSlot->cap = cap_null_cap_new();
    callerSlot->cteMDBNode = nullMDBNode;
#endif

    /* I know there's no fault, so straight to the transfer. */

    /* Replies don't have a badge. */
    badge = 0;

    fastpath_copy_mrs(length, NODE_STATE(ksCurThread), caller);

    /* Dest thread is set Running, but not queued. */
    thread_state_ptr_set_tsType_np(&caller->tcbState,
                                   ThreadState_Running);
    switchToThread_fp(caller, cap_pd, stored_hw_asid);

    msgInfo = wordFromMessageInfo(seL4_MessageInfo_set_capsUnwrapped(info, 0));

    fastpath_restore(badge, msgInfo, NODE_STATE(ksCurThread));
}
#line 1 "/home/koc034/Documents/newver/seL4/src/inlines.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <api/failures.h>

lookup_fault_t current_lookup_fault;
seL4_Fault_t current_fault;
syscall_error_t current_syscall_error;
#ifdef CONFIG_KERNEL_INVOCATION_REPORT_ERROR_IPC
debug_syscall_error_t current_debug_error;
#endif

#line 1 "/home/koc034/Documents/newver/seL4/src/kernel/boot.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <kernel/boot.h>
#include <kernel/thread.h>
#include <machine/io.h>
#include <machine/registerset.h>
#include <model/statedata.h>
#include <arch/machine.h>
#include <arch/kernel/boot.h>
#include <arch/kernel/vspace.h>
#include <linker.h>
#include <hardware.h>
#include <util.h>

/* (node-local) state accessed only during bootstrapping */
ndks_boot_t ndks_boot BOOT_BSS;

rootserver_mem_t rootserver BOOT_BSS;
static region_t rootserver_mem BOOT_BSS;

BOOT_CODE static void merge_regions(void)
{
    /* Walk through reserved regions and see if any can be merged */
    for (word_t i = 1; i < ndks_boot.resv_count;) {
        if (ndks_boot.reserved[i - 1].end == ndks_boot.reserved[i].start) {
            /* extend earlier region */
            ndks_boot.reserved[i - 1].end = ndks_boot.reserved[i].end;
            /* move everything else down */
            for (word_t j = i + 1; j < ndks_boot.resv_count; j++) {
                ndks_boot.reserved[j - 1] = ndks_boot.reserved[j];
            }

            ndks_boot.resv_count--;
            /* don't increment i in case there are multiple adjacent regions */
        } else {
            i++;
        }
    }
}

BOOT_CODE bool_t reserve_region(p_region_t reg)
{
    word_t i;
    assert(reg.start <= reg.end);
    if (reg.start == reg.end) {
        return true;
    }

    /* keep the regions in order */
    for (i = 0; i < ndks_boot.resv_count; i++) {
        /* Try and merge the region to an existing one, if possible */
        if (ndks_boot.reserved[i].start == reg.end) {
            ndks_boot.reserved[i].start = reg.start;
            merge_regions();
            return true;
        }
        if (ndks_boot.reserved[i].end == reg.start) {
            ndks_boot.reserved[i].end = reg.end;
            merge_regions();
            return true;
        }
        /* Otherwise figure out where it should go. */
        if (ndks_boot.reserved[i].start > reg.end) {
            /* move regions down, making sure there's enough room */
            if (ndks_boot.resv_count + 1 >= MAX_NUM_RESV_REG) {
                printf("Can't mark region 0x%lx-0x%lx as reserved, try increasing MAX_NUM_RESV_REG (currently %d)\n",
                       reg.start, reg.end, (int)MAX_NUM_RESV_REG);
                return false;
            }
            for (word_t j = ndks_boot.resv_count; j > i; j--) {
                ndks_boot.reserved[j] = ndks_boot.reserved[j - 1];
            }
            /* insert the new region */
            ndks_boot.reserved[i] = reg;
            ndks_boot.resv_count++;
            return true;
        }
    }

    if (i + 1 == MAX_NUM_RESV_REG) {
        printf("Can't mark region 0x%lx-0x%lx as reserved, try increasing MAX_NUM_RESV_REG (currently %d)\n",
               reg.start, reg.end, (int)MAX_NUM_RESV_REG);
        return false;
    }

    ndks_boot.reserved[i] = reg;
    ndks_boot.resv_count++;

    return true;
}

BOOT_CODE bool_t insert_region(region_t reg)
{
    word_t i;

    assert(reg.start <= reg.end);
    if (is_reg_empty(reg)) {
        return true;
    }
    for (i = 0; i < MAX_NUM_FREEMEM_REG; i++) {
        if (is_reg_empty(ndks_boot.freemem[i])) {
            reserve_region(pptr_to_paddr_reg(reg));
            ndks_boot.freemem[i] = reg;
            return true;
        }
    }
#ifdef CONFIG_ARCH_ARM
    /* boot.h should have calculated MAX_NUM_FREEMEM_REG correctly.
     * If we've run out, then something is wrong.
     * Note that the capDL allocation toolchain does not know about
     * MAX_NUM_FREEMEM_REG, so throwing away regions may prevent
     * capDL applications from being loaded! */
    printf("Can't fit memory region 0x%lx-0x%lx, try increasing MAX_NUM_FREEMEM_REG (currently %d)\n",
           reg.start, reg.end, (int)MAX_NUM_FREEMEM_REG);
    assert(!"Ran out of freemem slots");
#else
    printf("Dropping memory region 0x%lx-0x%lx, try increasing MAX_NUM_FREEMEM_REG (currently %d)\n",
           reg.start, reg.end, (int)MAX_NUM_FREEMEM_REG);
#endif
    return false;
}

BOOT_CODE static pptr_t alloc_rootserver_obj(word_t size_bits, word_t n)
{
    pptr_t allocated = rootserver_mem.start;
    /* allocated memory must be aligned */
    assert(allocated % BIT(size_bits) == 0);
    rootserver_mem.start += (n * BIT(size_bits));
    /* we must not have run out of memory */
    assert(rootserver_mem.start <= rootserver_mem.end);
    memzero((void *) allocated, n * BIT(size_bits));
    return allocated;
}

BOOT_CODE static word_t rootserver_max_size_bits(word_t extra_bi_size_bits)
{
    word_t cnode_size_bits = CONFIG_ROOT_CNODE_SIZE_BITS + seL4_SlotBits;
    word_t max = MAX(cnode_size_bits, seL4_VSpaceBits);
    return MAX(max, extra_bi_size_bits);
}

BOOT_CODE static word_t calculate_rootserver_size(v_region_t v_reg, word_t extra_bi_size_bits)
{
    /* work out how much memory we need for root server objects */
    word_t size = BIT(CONFIG_ROOT_CNODE_SIZE_BITS + seL4_SlotBits);
    size += BIT(seL4_TCBBits); // root thread tcb
    size += 2 * BIT(seL4_PageBits); // boot info + ipc buf
    size += BIT(seL4_ASIDPoolBits);
    size += extra_bi_size_bits > 0 ? BIT(extra_bi_size_bits) : 0;
    size += BIT(seL4_VSpaceBits); // root vspace
#ifdef CONFIG_KERNEL_MCS
    size += BIT(seL4_MinSchedContextBits); // root sched context
#endif
    /* for all archs, seL4_PageTable Bits is the size of all non top-level paging structures */
    return size + arch_get_n_paging(v_reg) * BIT(seL4_PageTableBits);
}

BOOT_CODE static void maybe_alloc_extra_bi(word_t cmp_size_bits, word_t extra_bi_size_bits)
{
    if (extra_bi_size_bits >= cmp_size_bits && rootserver.extra_bi == 0) {
        rootserver.extra_bi = alloc_rootserver_obj(extra_bi_size_bits, 1);
    }
}

BOOT_CODE void create_rootserver_objects(pptr_t start, v_region_t v_reg, word_t extra_bi_size_bits)
{
    /* the largest object the PD, the root cnode, or the extra boot info */
    word_t cnode_size_bits = CONFIG_ROOT_CNODE_SIZE_BITS + seL4_SlotBits;
    word_t max = rootserver_max_size_bits(extra_bi_size_bits);

    word_t size = calculate_rootserver_size(v_reg, extra_bi_size_bits);
    rootserver_mem.start = start;
    rootserver_mem.end = start + size;

    maybe_alloc_extra_bi(max, extra_bi_size_bits);

    /* the root cnode is at least 4k, so it could be larger or smaller than a pd. */
#if (CONFIG_ROOT_CNODE_SIZE_BITS + seL4_SlotBits) > seL4_VSpaceBits
    rootserver.cnode = alloc_rootserver_obj(cnode_size_bits, 1);
    maybe_alloc_extra_bi(seL4_VSpaceBits, extra_bi_size_bits);
    rootserver.vspace = alloc_rootserver_obj(seL4_VSpaceBits, 1);
#else
    rootserver.vspace = alloc_rootserver_obj(seL4_VSpaceBits, 1);
    maybe_alloc_extra_bi(cnode_size_bits, extra_bi_size_bits);
    rootserver.cnode = alloc_rootserver_obj(cnode_size_bits, 1);
#endif

    /* at this point we are up to creating 4k objects - which is the min size of
     * extra_bi so this is the last chance to allocate it */
    maybe_alloc_extra_bi(seL4_PageBits, extra_bi_size_bits);
    rootserver.asid_pool = alloc_rootserver_obj(seL4_ASIDPoolBits, 1);
    rootserver.ipc_buf = alloc_rootserver_obj(seL4_PageBits, 1);
    rootserver.boot_info = alloc_rootserver_obj(seL4_PageBits, 1);

    /* TCBs on aarch32 can be larger than page tables in certain configs */
#if seL4_TCBBits >= seL4_PageTableBits
    rootserver.tcb = alloc_rootserver_obj(seL4_TCBBits, 1);
#endif

    /* paging structures are 4k on every arch except aarch32 (1k) */
    word_t n = arch_get_n_paging(v_reg);
    rootserver.paging.start = alloc_rootserver_obj(seL4_PageTableBits, n);
    rootserver.paging.end = rootserver.paging.start + n * BIT(seL4_PageTableBits);

    /* for most archs, TCBs are smaller than page tables */
#if seL4_TCBBits < seL4_PageTableBits
    rootserver.tcb = alloc_rootserver_obj(seL4_TCBBits, 1);
#endif

#ifdef CONFIG_KERNEL_MCS
    rootserver.sc = alloc_rootserver_obj(seL4_MinSchedContextBits, 1);
#endif
    /* we should have allocated all our memory */
    assert(rootserver_mem.start == rootserver_mem.end);
}

BOOT_CODE void write_slot(slot_ptr_t slot_ptr, cap_t cap)
{
    slot_ptr->cap = cap;

    slot_ptr->cteMDBNode = nullMDBNode;
    mdb_node_ptr_set_mdbRevocable(&slot_ptr->cteMDBNode, true);
    mdb_node_ptr_set_mdbFirstBadged(&slot_ptr->cteMDBNode, true);
}

/* Our root CNode needs to be able to fit all the initial caps and not
 * cover all of memory.
 */
compile_assert(root_cnode_size_valid,
               CONFIG_ROOT_CNODE_SIZE_BITS < 32 - seL4_SlotBits &&
               BIT(CONFIG_ROOT_CNODE_SIZE_BITS) >= seL4_NumInitialCaps &&
               BIT(CONFIG_ROOT_CNODE_SIZE_BITS) >= (seL4_PageBits - seL4_SlotBits))

BOOT_CODE cap_t
create_root_cnode(void)
{
    /* write the number of root CNode slots to global state */
    ndks_boot.slot_pos_max = BIT(CONFIG_ROOT_CNODE_SIZE_BITS);

    cap_t cap =
        cap_cnode_cap_new(
            CONFIG_ROOT_CNODE_SIZE_BITS,      /* radix      */
            wordBits - CONFIG_ROOT_CNODE_SIZE_BITS, /* guard size */
            0,                                /* guard      */
            rootserver.cnode              /* pptr       */
        );

    /* write the root CNode cap into the root CNode */
    write_slot(SLOT_PTR(rootserver.cnode, seL4_CapInitThreadCNode), cap);

    return cap;
}

/* Check domain scheduler assumptions. */
compile_assert(num_domains_valid,
               CONFIG_NUM_DOMAINS >= 1 && CONFIG_NUM_DOMAINS <= 256)
compile_assert(num_priorities_valid,
               CONFIG_NUM_PRIORITIES >= 1 && CONFIG_NUM_PRIORITIES <= 256)

BOOT_CODE void
create_domain_cap(cap_t root_cnode_cap)
{
    /* Check domain scheduler assumptions. */
    assert(ksDomScheduleLength > 0);
    for (word_t i = 0; i < ksDomScheduleLength; i++) {
        assert(ksDomSchedule[i].domain < CONFIG_NUM_DOMAINS);
        assert(ksDomSchedule[i].length > 0);
    }

    cap_t cap = cap_domain_cap_new();
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapDomain), cap);
}


BOOT_CODE cap_t create_ipcbuf_frame_cap(cap_t root_cnode_cap, cap_t pd_cap, vptr_t vptr)
{
    clearMemory((void *)rootserver.ipc_buf, PAGE_BITS);

    /* create a cap of it and write it into the root CNode */
    cap_t cap = create_mapped_it_frame_cap(pd_cap, rootserver.ipc_buf, vptr, IT_ASID, false, false);
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadIPCBuffer), cap);

    return cap;
}

BOOT_CODE void create_bi_frame_cap(cap_t root_cnode_cap, cap_t pd_cap, vptr_t vptr)
{
    /* create a cap of it and write it into the root CNode */
    cap_t cap = create_mapped_it_frame_cap(pd_cap, rootserver.boot_info, vptr, IT_ASID, false, false);
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapBootInfoFrame), cap);
}

BOOT_CODE word_t calculate_extra_bi_size_bits(word_t extra_size)
{
    if (extra_size == 0) {
        return 0;
    }

    word_t clzl_ret = clzl(ROUND_UP(extra_size, seL4_PageBits));
    word_t msb = seL4_WordBits - 1 - clzl_ret;
    /* If region is bigger than a page, make sure we overallocate rather than underallocate */
    if (extra_size > BIT(msb)) {
        msb++;
    }
    return msb;
}

BOOT_CODE void populate_bi_frame(node_id_t node_id, word_t num_nodes, vptr_t ipcbuf_vptr,
                                 word_t extra_bi_size)
{
    clearMemory((void *) rootserver.boot_info, BI_FRAME_SIZE_BITS);
    if (extra_bi_size) {
        clearMemory((void *) rootserver.extra_bi, calculate_extra_bi_size_bits(extra_bi_size));
    }

    /* initialise bootinfo-related global state */
    ndks_boot.bi_frame = BI_PTR(rootserver.boot_info);
    ndks_boot.slot_pos_cur = seL4_NumInitialCaps;
    BI_PTR(rootserver.boot_info)->nodeID = node_id;
    BI_PTR(rootserver.boot_info)->numNodes = num_nodes;
    BI_PTR(rootserver.boot_info)->numIOPTLevels = 0;
    BI_PTR(rootserver.boot_info)->ipcBuffer = (seL4_IPCBuffer *) ipcbuf_vptr;
    BI_PTR(rootserver.boot_info)->initThreadCNodeSizeBits = CONFIG_ROOT_CNODE_SIZE_BITS;
    BI_PTR(rootserver.boot_info)->initThreadDomain = ksDomSchedule[ksDomScheduleIdx].domain;
    BI_PTR(rootserver.boot_info)->extraLen = extra_bi_size;
}

BOOT_CODE bool_t provide_cap(cap_t root_cnode_cap, cap_t cap)
{
    if (ndks_boot.slot_pos_cur >= ndks_boot.slot_pos_max) {
        printf("Kernel init failed: ran out of cap slots\n");
        return false;
    }
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), ndks_boot.slot_pos_cur), cap);
    ndks_boot.slot_pos_cur++;
    return true;
}

BOOT_CODE create_frames_of_region_ret_t create_frames_of_region(
    cap_t    root_cnode_cap,
    cap_t    pd_cap,
    region_t reg,
    bool_t   do_map,
    sword_t  pv_offset
)
{
    pptr_t     f;
    cap_t      frame_cap;
    seL4_SlotPos slot_pos_before;
    seL4_SlotPos slot_pos_after;

    slot_pos_before = ndks_boot.slot_pos_cur;

    for (f = reg.start; f < reg.end; f += BIT(PAGE_BITS)) {
        if (do_map) {
            frame_cap = create_mapped_it_frame_cap(pd_cap, f, pptr_to_paddr((void *)(f - pv_offset)), IT_ASID, false, true);
        } else {
            frame_cap = create_unmapped_it_frame_cap(f, false);
        }
        if (!provide_cap(root_cnode_cap, frame_cap))
            return (create_frames_of_region_ret_t) {
            S_REG_EMPTY, false
        };
    }

    slot_pos_after = ndks_boot.slot_pos_cur;

    return (create_frames_of_region_ret_t) {
        (seL4_SlotRegion) { slot_pos_before, slot_pos_after }, true
    };
}

BOOT_CODE cap_t create_it_asid_pool(cap_t root_cnode_cap)
{
    cap_t ap_cap = cap_asid_pool_cap_new(IT_ASID >> asidLowBits, rootserver.asid_pool);
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadASIDPool), ap_cap);

    /* create ASID control cap */
    write_slot(
        SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapASIDControl),
        cap_asid_control_cap_new()
    );

    return ap_cap;
}

#ifdef CONFIG_KERNEL_MCS
BOOT_CODE static bool_t configure_sched_context(tcb_t *tcb, sched_context_t *sc_pptr, ticks_t timeslice, word_t core)
{
    tcb->tcbSchedContext = sc_pptr;
    REFILL_NEW(tcb->tcbSchedContext, MIN_REFILLS, timeslice, 0, core);

    tcb->tcbSchedContext->scTcb = tcb;
    return true;
}

BOOT_CODE bool_t init_sched_control(cap_t root_cnode_cap, word_t num_nodes)
{
    bool_t ret = true;
    seL4_SlotPos slot_pos_before = ndks_boot.slot_pos_cur;
    /* create a sched control cap for each core */
    for (int i = 0; i < num_nodes && ret; i++) {
        ret = provide_cap(root_cnode_cap, cap_sched_control_cap_new(i));
    }

    if (!ret) {
        return false;
    }

    /* update boot info with slot region for sched control caps */
    ndks_boot.bi_frame->schedcontrol = (seL4_SlotRegion) {
        .start = slot_pos_before,
        .end = ndks_boot.slot_pos_cur
    };

    return true;
}
#endif

BOOT_CODE bool_t create_idle_thread(void)
{
    pptr_t pptr;

#ifdef ENABLE_SMP_SUPPORT
    for (int i = 0; i < CONFIG_MAX_NUM_NODES; i++) {
#endif /* ENABLE_SMP_SUPPORT */
        pptr = (pptr_t) &ksIdleThreadTCB[SMP_TERNARY(i, 0)];
        NODE_STATE_ON_CORE(ksIdleThread, i) = TCB_PTR(pptr + TCB_OFFSET);
        configureIdleThread(NODE_STATE_ON_CORE(ksIdleThread, i));
#ifdef CONFIG_DEBUG_BUILD
        setThreadName(NODE_STATE_ON_CORE(ksIdleThread, i), "idle_thread");
#endif
        SMP_COND_STATEMENT(NODE_STATE_ON_CORE(ksIdleThread, i)->tcbAffinity = i);
#ifdef CONFIG_KERNEL_MCS
        bool_t result = configure_sched_context(NODE_STATE_ON_CORE(ksIdleThread, i), SC_PTR(&ksIdleThreadSC[SMP_TERNARY(i, 0)]),
                                                usToTicks(CONFIG_BOOT_THREAD_TIME_SLICE * US_IN_MS), SMP_TERNARY(i, 0));
        SMP_COND_STATEMENT(NODE_STATE_ON_CORE(ksIdleThread, i)->tcbSchedContext->scCore = i;)
        if (!result) {
            printf("Kernel init failed: Unable to allocate sc for idle thread\n");
            return false;
        }
#endif
#ifdef ENABLE_SMP_SUPPORT
    }
#endif /* ENABLE_SMP_SUPPORT */
    return true;
}

BOOT_CODE tcb_t *create_initial_thread(cap_t root_cnode_cap, cap_t it_pd_cap, vptr_t ui_v_entry, vptr_t bi_frame_vptr,
                                       vptr_t ipcbuf_vptr, cap_t ipcbuf_cap)
{
    tcb_t *tcb = TCB_PTR(rootserver.tcb + TCB_OFFSET);
#ifndef CONFIG_KERNEL_MCS
    tcb->tcbTimeSlice = CONFIG_TIME_SLICE;
#endif

    Arch_initContext(&tcb->tcbArch.tcbContext);

    /* derive a copy of the IPC buffer cap for inserting */
    deriveCap_ret_t dc_ret = deriveCap(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadIPCBuffer), ipcbuf_cap);
    if (dc_ret.status != EXCEPTION_NONE) {
        printf("Failed to derive copy of IPC Buffer\n");
        return NULL;
    }

    /* initialise TCB (corresponds directly to abstract specification) */
    cteInsert(
        root_cnode_cap,
        SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadCNode),
        SLOT_PTR(rootserver.tcb, tcbCTable)
    );
    cteInsert(
        it_pd_cap,
        SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadVSpace),
        SLOT_PTR(rootserver.tcb, tcbVTable)
    );
    cteInsert(
        dc_ret.cap,
        SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadIPCBuffer),
        SLOT_PTR(rootserver.tcb, tcbBuffer)
    );
    tcb->tcbIPCBuffer = ipcbuf_vptr;

    setRegister(tcb, capRegister, bi_frame_vptr);
    setNextPC(tcb, ui_v_entry);

    /* initialise TCB */
#ifdef CONFIG_KERNEL_MCS
    if (!configure_sched_context(tcb, SC_PTR(rootserver.sc), usToTicks(CONFIG_BOOT_THREAD_TIME_SLICE * US_IN_MS), 0)) {
        return NULL;
    }
#endif

    tcb->tcbPriority = seL4_MaxPrio;
    tcb->tcbMCP = seL4_MaxPrio;
    tcb->tcbDomain = ksDomSchedule[ksDomScheduleIdx].domain;
#ifndef CONFIG_KERNEL_MCS
    setupReplyMaster(tcb);
#endif
    setThreadState(tcb, ThreadState_Running);

    ksCurDomain = ksDomSchedule[ksDomScheduleIdx].domain;
#ifdef CONFIG_KERNEL_MCS
    ksDomainTime = usToTicks(ksDomSchedule[ksDomScheduleIdx].length * US_IN_MS);
#else
    ksDomainTime = ksDomSchedule[ksDomScheduleIdx].length;
#endif
    assert(ksCurDomain < CONFIG_NUM_DOMAINS && ksDomainTime > 0);

#ifndef CONFIG_KERNEL_MCS
    SMP_COND_STATEMENT(tcb->tcbAffinity = 0);
#endif

    /* create initial thread's TCB cap */
    cap_t cap = cap_thread_cap_new(TCB_REF(tcb));
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadTCB), cap);

#ifdef CONFIG_KERNEL_MCS
    cap = cap_sched_context_cap_new(SC_REF(tcb->tcbSchedContext), seL4_MinSchedContextBits);
    write_slot(SLOT_PTR(pptr_of_cap(root_cnode_cap), seL4_CapInitThreadSC), cap);
#endif
#ifdef CONFIG_DEBUG_BUILD
    setThreadName(tcb, "rootserver");
#endif

    return tcb;
}

BOOT_CODE void init_core_state(tcb_t *scheduler_action)
{
#ifdef CONFIG_HAVE_FPU
    NODE_STATE(ksActiveFPUState) = NULL;
#endif
#ifdef CONFIG_DEBUG_BUILD
    /* add initial threads to the debug queue */
    NODE_STATE(ksDebugTCBs) = NULL;
    if (scheduler_action != SchedulerAction_ResumeCurrentThread &&
        scheduler_action != SchedulerAction_ChooseNewThread) {
        tcbDebugAppend(scheduler_action);
    }
    tcbDebugAppend(NODE_STATE(ksIdleThread));
#endif
    NODE_STATE(ksSchedulerAction) = scheduler_action;
    NODE_STATE(ksCurThread) = NODE_STATE(ksIdleThread);
#ifdef CONFIG_KERNEL_MCS
    NODE_STATE(ksCurSC) = NODE_STATE(ksCurThread->tcbSchedContext);
    NODE_STATE(ksConsumed) = 0;
    NODE_STATE(ksReprogram) = true;
    NODE_STATE(ksReleaseHead) = NULL;
    NODE_STATE(ksCurTime) = getCurrentTime();
#endif
}

BOOT_CODE static bool_t provide_untyped_cap(
    cap_t      root_cnode_cap,
    bool_t     device_memory,
    pptr_t     pptr,
    word_t     size_bits,
    seL4_SlotPos first_untyped_slot
)
{
    bool_t ret;
    cap_t ut_cap;
    word_t i = ndks_boot.slot_pos_cur - first_untyped_slot;
    if (i < CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS) {
        ndks_boot.bi_frame->untypedList[i] = (seL4_UntypedDesc) {
            pptr_to_paddr((void *)pptr), size_bits, device_memory, {0}
        };
        ut_cap = cap_untyped_cap_new(MAX_FREE_INDEX(size_bits),
                                     device_memory, size_bits, pptr);
        ret = provide_cap(root_cnode_cap, ut_cap);
    } else {
        printf("Kernel init: Too many untyped regions for boot info\n");
        ret = true;
    }
    return ret;
}

BOOT_CODE bool_t create_untypeds_for_region(
    cap_t      root_cnode_cap,
    bool_t     device_memory,
    region_t   reg,
    seL4_SlotPos first_untyped_slot
)
{
    word_t align_bits;
    word_t size_bits;

    while (!is_reg_empty(reg)) {
        /* Determine the maximum size of the region */
        size_bits = seL4_WordBits - 1 - clzl(reg.end - reg.start);

        /* Determine the alignment of the region */
        if (reg.start != 0) {
            align_bits = ctzl(reg.start);
        } else {
            align_bits = size_bits;
        }
        /* Reduce size bits to align if needed */
        if (align_bits < size_bits) {
            size_bits = align_bits;
        }
        if (size_bits > seL4_MaxUntypedBits) {
            size_bits = seL4_MaxUntypedBits;
        }

        if (size_bits >= seL4_MinUntypedBits) {
            if (!provide_untyped_cap(root_cnode_cap, device_memory, reg.start, size_bits, first_untyped_slot)) {
                return false;
            }
        }
        reg.start += BIT(size_bits);
    }
    return true;
}

BOOT_CODE bool_t create_device_untypeds(cap_t root_cnode_cap, seL4_SlotPos slot_pos_before)
{
    paddr_t start = 0;
    for (word_t i = 0; i < ndks_boot.resv_count; i++) {
        if (start < ndks_boot.reserved[i].start) {
            region_t reg = paddr_to_pptr_reg((p_region_t) {
                start, ndks_boot.reserved[i].start
            });
            if (!create_untypeds_for_region(root_cnode_cap, true, reg, slot_pos_before)) {
                return false;
            }
        }

        start = ndks_boot.reserved[i].end;
    }

    if (start < CONFIG_PADDR_USER_DEVICE_TOP) {
        region_t reg = paddr_to_pptr_reg((p_region_t) {
            start, CONFIG_PADDR_USER_DEVICE_TOP
        });
        /*
         * The auto-generated bitfield code will get upset if the
         * end pptr is larger than the maximum pointer size for this architecture.
         */
        if (reg.end > PPTR_TOP) {
            reg.end = PPTR_TOP;
        }
        if (!create_untypeds_for_region(root_cnode_cap, true, reg, slot_pos_before)) {
            return false;
        }
    }
    return true;
}

BOOT_CODE bool_t create_kernel_untypeds(cap_t root_cnode_cap, region_t boot_mem_reuse_reg,
                                        seL4_SlotPos first_untyped_slot)
{
    word_t     i;
    region_t   reg;

    /* if boot_mem_reuse_reg is not empty, we can create UT objs from boot code/data frames */
    if (!create_untypeds_for_region(root_cnode_cap, false, boot_mem_reuse_reg, first_untyped_slot)) {
        return false;
    }

    /* convert remaining freemem into UT objects and provide the caps */
    for (i = 0; i < MAX_NUM_FREEMEM_REG; i++) {
        reg = ndks_boot.freemem[i];
        ndks_boot.freemem[i] = REG_EMPTY;
        if (!create_untypeds_for_region(root_cnode_cap, false, reg, first_untyped_slot)) {
            return false;
        }
    }

    return true;
}

BOOT_CODE void bi_finalise(void)
{
    seL4_SlotPos slot_pos_start = ndks_boot.slot_pos_cur;
    seL4_SlotPos slot_pos_end = ndks_boot.slot_pos_max;
    ndks_boot.bi_frame->empty = (seL4_SlotRegion) {
        slot_pos_start, slot_pos_end
    };
}

static inline pptr_t ceiling_kernel_window(pptr_t p)
{
    /* Adjust address if it exceeds the kernel window
     * Note that we compare physical address in case of overflow.
     */
    if (pptr_to_paddr((void *)p) > PADDR_TOP) {
        p = PPTR_TOP;
    }
    return p;
}

/* we can't delcare arrays on the stack, so this is space for
 * the below function to use. */
static BOOT_DATA region_t avail_reg[MAX_NUM_FREEMEM_REG];
/**
 * Dynamically initialise the available memory on the platform.
 * A region represents an area of memory.
 */
BOOT_CODE void init_freemem(word_t n_available, const p_region_t *available,
                            word_t n_reserved, region_t *reserved,
                            v_region_t it_v_reg, word_t extra_bi_size_bits)
{
    /* Force ordering and exclusivity of reserved regions */
    for (word_t i = 0; n_reserved > 0 && i < n_reserved - 1; i++) {
        assert(reserved[i].start <= reserved[i].end);
        assert(reserved[i].end <= reserved[i + 1].start);
    }

    /* Force ordering and exclusivity of available regions */
    assert(n_available > 0);
    for (word_t i = 0; i < n_available - 1; i++) {
        assert(available[i].start < available[i].end);
        assert(available[i].end <= available[i + 1].start);
    }

    for (word_t i = 0; i < MAX_NUM_FREEMEM_REG; i++) {
        ndks_boot.freemem[i] = REG_EMPTY;
    }

    /* convert the available regions to pptrs */
    for (word_t i = 0; i < n_available; i++) {
        avail_reg[i] = paddr_to_pptr_reg(available[i]);
        avail_reg[i].end = ceiling_kernel_window(avail_reg[i].end);
        avail_reg[i].start = ceiling_kernel_window(avail_reg[i].start);
    }

    word_t a = 0;
    word_t r = 0;
    /* Now iterate through the available regions, removing any reserved regions. */
    while (a < n_available && r < n_reserved) {
        if (reserved[r].start == reserved[r].end) {
            /* reserved region is empty - skip it */
            r++;
        } else if (avail_reg[a].start >= avail_reg[a].end) {
            /* skip the entire region - it's empty now after trimming */
            a++;
        } else if (reserved[r].end <= avail_reg[a].start) {
            /* the reserved region is below the available region - skip it*/
            reserve_region(pptr_to_paddr_reg(reserved[r]));
            r++;
        } else if (reserved[r].start >= avail_reg[a].end) {
            /* the reserved region is above the available region - take the whole thing */
            insert_region(avail_reg[a]);
            a++;
        } else {
            /* the reserved region overlaps with the available region */
            if (reserved[r].start <= avail_reg[a].start) {
                /* the region overlaps with the start of the available region.
                 * trim start of the available region */
                avail_reg[a].start = MIN(avail_reg[a].end, reserved[r].end);
                reserve_region(pptr_to_paddr_reg(reserved[r]));
                r++;
            } else {
                assert(reserved[r].start < avail_reg[a].end);
                /* take the first chunk of the available region and move
                 * the start to the end of the reserved region */
                region_t m = avail_reg[a];
                m.end = reserved[r].start;
                insert_region(m);
                if (avail_reg[a].end > reserved[r].end) {
                    avail_reg[a].start = reserved[r].end;
                    reserve_region(pptr_to_paddr_reg(reserved[r]));
                    r++;
                } else {
                    a++;
                }
            }
        }
    }

    for (; r < n_reserved; r++) {
        if (reserved[r].start < reserved[r].end) {
            reserve_region(pptr_to_paddr_reg(reserved[r]));
        }
    }

    /* no more reserved regions - add the rest */
    for (; a < n_available; a++) {
        if (avail_reg[a].start < avail_reg[a].end) {
            insert_region(avail_reg[a]);
        }
    }

    /* now try to fit the root server objects into a region */
    word_t i = MAX_NUM_FREEMEM_REG - 1;
    if (!is_reg_empty(ndks_boot.freemem[i])) {
        printf("Insufficient MAX_NUM_FREEMEM_REG");
        halt();
    }
    /* skip any empty regions */
    for (; is_reg_empty(ndks_boot.freemem[i]) && i >= 0; i--);

    /* try to grab the last available p region to create the root server objects
     * from. If possible, retain any left over memory as an extra p region */
    word_t size = calculate_rootserver_size(it_v_reg, extra_bi_size_bits);
    word_t max = rootserver_max_size_bits(extra_bi_size_bits);
    for (; i >= 0; i--) {
        word_t next = i + 1;
        pptr_t start = ROUND_DOWN(ndks_boot.freemem[i].end - size, max);
        if (start >= ndks_boot.freemem[i].start) {
            create_rootserver_objects(start, it_v_reg, extra_bi_size_bits);
            if (i < MAX_NUM_FREEMEM_REG) {
                ndks_boot.freemem[next].end = ndks_boot.freemem[i].end;
                ndks_boot.freemem[next].start = start + size;
            }
            ndks_boot.freemem[i].end = start;
            break;
        } else if (i < MAX_NUM_FREEMEM_REG) {
            ndks_boot.freemem[next] = ndks_boot.freemem[i];
        }
    }
}
#line 1 "/home/koc034/Documents/newver/seL4/src/kernel/cspace.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <object.h>
#include <api/failures.h>
#include <kernel/thread.h>
#include <kernel/cspace.h>
#include <model/statedata.h>
#include <arch/machine.h>

lookupCap_ret_t lookupCap(tcb_t *thread, cptr_t cPtr)
{
    lookupSlot_raw_ret_t lu_ret;
    lookupCap_ret_t ret;

    lu_ret = lookupSlot(thread, cPtr);
    if (unlikely(lu_ret.status != EXCEPTION_NONE)) {
        ret.status = lu_ret.status;
        ret.cap = cap_null_cap_new();
        return ret;
    }

    ret.status = EXCEPTION_NONE;
    ret.cap = lu_ret.slot->cap;
    return ret;
}

lookupCapAndSlot_ret_t lookupCapAndSlot(tcb_t *thread, cptr_t cPtr)
{
    lookupSlot_raw_ret_t lu_ret;
    lookupCapAndSlot_ret_t ret;

    lu_ret = lookupSlot(thread, cPtr);
    if (unlikely(lu_ret.status != EXCEPTION_NONE)) {
        ret.status = lu_ret.status;
        ret.slot = NULL;
        ret.cap = cap_null_cap_new();
        return ret;
    }

    ret.status = EXCEPTION_NONE;
    ret.slot = lu_ret.slot;
    ret.cap = lu_ret.slot->cap;
    return ret;
}

lookupSlot_raw_ret_t lookupSlot(tcb_t *thread, cptr_t capptr)
{
    cap_t threadRoot;
    resolveAddressBits_ret_t res_ret;
    lookupSlot_raw_ret_t ret;

    threadRoot = TCB_PTR_CTE_PTR(thread, tcbCTable)->cap;
    res_ret = resolveAddressBits(threadRoot, capptr, wordBits);

    ret.status = res_ret.status;
    ret.slot = res_ret.slot;
    return ret;
}

lookupSlot_ret_t lookupSlotForCNodeOp(bool_t isSource, cap_t root, cptr_t capptr,
                                      word_t depth)
{
    resolveAddressBits_ret_t res_ret;
    lookupSlot_ret_t ret;

    ret.slot = NULL;

    if (unlikely(cap_get_capType(root) != cap_cnode_cap)) {
        current_syscall_error.type = seL4_FailedLookup;
        current_syscall_error.failedLookupWasSource = isSource;
        current_lookup_fault = lookup_fault_invalid_root_new();
        ret.status = EXCEPTION_SYSCALL_ERROR;
        return ret;
    }

    if (unlikely(depth < 1 || depth > wordBits)) {
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 1;
        current_syscall_error.rangeErrorMax = wordBits;
        ret.status = EXCEPTION_SYSCALL_ERROR;
        return ret;
    }
    res_ret = resolveAddressBits(root, capptr, depth);
    if (unlikely(res_ret.status != EXCEPTION_NONE)) {
        current_syscall_error.type = seL4_FailedLookup;
        current_syscall_error.failedLookupWasSource = isSource;
        /* current_lookup_fault will have been set by resolveAddressBits */
        ret.status = EXCEPTION_SYSCALL_ERROR;
        return ret;
    }

    if (unlikely(res_ret.bitsRemaining != 0)) {
        current_syscall_error.type = seL4_FailedLookup;
        current_syscall_error.failedLookupWasSource = isSource;
        current_lookup_fault =
            lookup_fault_depth_mismatch_new(0, res_ret.bitsRemaining);
        ret.status = EXCEPTION_SYSCALL_ERROR;
        return ret;
    }

    ret.slot = res_ret.slot;
    ret.status = EXCEPTION_NONE;
    return ret;
}

lookupSlot_ret_t lookupSourceSlot(cap_t root, cptr_t capptr, word_t depth)
{
    return lookupSlotForCNodeOp(true, root, capptr, depth);
}

lookupSlot_ret_t lookupTargetSlot(cap_t root, cptr_t capptr, word_t depth)
{
    return lookupSlotForCNodeOp(false, root, capptr, depth);
}

lookupSlot_ret_t lookupPivotSlot(cap_t root, cptr_t capptr, word_t depth)
{
    return lookupSlotForCNodeOp(true, root, capptr, depth);
}

resolveAddressBits_ret_t resolveAddressBits(cap_t nodeCap, cptr_t capptr, word_t n_bits)
{
    resolveAddressBits_ret_t ret;
    word_t radixBits, guardBits, levelBits, guard;
    word_t capGuard, offset;
    cte_t *slot;

    ret.bitsRemaining = n_bits;
    ret.slot = NULL;

    if (unlikely(cap_get_capType(nodeCap) != cap_cnode_cap)) {
        current_lookup_fault = lookup_fault_invalid_root_new();
        ret.status = EXCEPTION_LOOKUP_FAULT;
        return ret;
    }

    while (1) {
        radixBits = cap_cnode_cap_get_capCNodeRadix(nodeCap);
        guardBits = cap_cnode_cap_get_capCNodeGuardSize(nodeCap);
        levelBits = radixBits + guardBits;

        /* Haskell error: "All CNodes must resolve bits" */
        assert(levelBits != 0);

        capGuard = cap_cnode_cap_get_capCNodeGuard(nodeCap);

        /* sjw --- the MASK(5) here is to avoid the case where n_bits = 32
           and guardBits = 0, as it violates the C spec to >> by more
           than 31 */

        guard = (capptr >> ((n_bits - guardBits) & MASK(wordRadix))) & MASK(guardBits);
        if (unlikely(guardBits > n_bits || guard != capGuard)) {
            current_lookup_fault =
                lookup_fault_guard_mismatch_new(capGuard, n_bits, guardBits);
            ret.status = EXCEPTION_LOOKUP_FAULT;
            return ret;
        }

        if (unlikely(levelBits > n_bits)) {
            current_lookup_fault =
                lookup_fault_depth_mismatch_new(levelBits, n_bits);
            ret.status = EXCEPTION_LOOKUP_FAULT;
            return ret;
        }

        offset = (capptr >> (n_bits - levelBits)) & MASK(radixBits);
        slot = CTE_PTR(cap_cnode_cap_get_capCNodePtr(nodeCap)) + offset;

        if (likely(n_bits <= levelBits)) {
            ret.status = EXCEPTION_NONE;
            ret.slot = slot;
            ret.bitsRemaining = 0;
            return ret;
        }

        /** GHOSTUPD: "(\<acute>levelBits > 0, id)" */

        n_bits -= levelBits;
        nodeCap = slot->cap;

        if (unlikely(cap_get_capType(nodeCap) != cap_cnode_cap)) {
            ret.status = EXCEPTION_NONE;
            ret.slot = slot;
            ret.bitsRemaining = n_bits;
            return ret;
        }
    }

    ret.status = EXCEPTION_NONE;
    return ret;
}
#line 1 "/home/koc034/Documents/newver/seL4/src/kernel/faulthandler.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <api/failures.h>
#include <kernel/cspace.h>
#include <kernel/faulthandler.h>
#include <kernel/thread.h>
#include <machine/io.h>
#include <arch/machine.h>

#ifdef CONFIG_KERNEL_MCS
void handleFault(tcb_t *tptr)
{
    bool_t hasFaultHandler = sendFaultIPC(tptr, TCB_PTR_CTE_PTR(tptr, tcbFaultHandler)->cap,
                                          tptr->tcbSchedContext != NULL);
    if (!hasFaultHandler) {
        handleNoFaultHandler(tptr);
    }
}

void handleTimeout(tcb_t *tptr)
{
    assert(validTimeoutHandler(tptr));
    sendFaultIPC(tptr, TCB_PTR_CTE_PTR(tptr, tcbTimeoutHandler)->cap, false);
}

bool_t sendFaultIPC(tcb_t *tptr, cap_t handlerCap, bool_t can_donate)
{
    if (cap_get_capType(handlerCap) == cap_endpoint_cap) {
        assert(cap_endpoint_cap_get_capCanSend(handlerCap));
        assert(cap_endpoint_cap_get_capCanGrant(handlerCap) ||
               cap_endpoint_cap_get_capCanGrantReply(handlerCap));

        tptr->tcbFault = current_fault;
        sendIPC(true, false,
                cap_endpoint_cap_get_capEPBadge(handlerCap),
                cap_endpoint_cap_get_capCanGrant(handlerCap),
                cap_endpoint_cap_get_capCanGrantReply(handlerCap),
                can_donate, tptr,
                EP_PTR(cap_endpoint_cap_get_capEPPtr(handlerCap)));

        return true;
    } else {
        assert(cap_get_capType(handlerCap) == cap_null_cap);
        return false;
    }
}
#else

void handleFault(tcb_t *tptr)
{
    exception_t status;
    seL4_Fault_t fault = current_fault;

    status = sendFaultIPC(tptr);
    if (status != EXCEPTION_NONE) {
        handleDoubleFault(tptr, fault);
    }
}

exception_t sendFaultIPC(tcb_t *tptr)
{
    cptr_t handlerCPtr;
    cap_t  handlerCap;
    lookupCap_ret_t lu_ret;
    lookup_fault_t original_lookup_fault;

    original_lookup_fault = current_lookup_fault;

    handlerCPtr = tptr->tcbFaultHandler;
    lu_ret = lookupCap(tptr, handlerCPtr);
    if (lu_ret.status != EXCEPTION_NONE) {
        current_fault = seL4_Fault_CapFault_new(handlerCPtr, false);
        return EXCEPTION_FAULT;
    }
    handlerCap = lu_ret.cap;

    if (cap_get_capType(handlerCap) == cap_endpoint_cap &&
        cap_endpoint_cap_get_capCanSend(handlerCap) &&
        (cap_endpoint_cap_get_capCanGrant(handlerCap) ||
         cap_endpoint_cap_get_capCanGrantReply(handlerCap))) {
        tptr->tcbFault = current_fault;
        if (seL4_Fault_get_seL4_FaultType(current_fault) == seL4_Fault_CapFault) {
            tptr->tcbLookupFailure = original_lookup_fault;
        }
        sendIPC(true, true,
                cap_endpoint_cap_get_capEPBadge(handlerCap),
                cap_endpoint_cap_get_capCanGrant(handlerCap), true, tptr,
                EP_PTR(cap_endpoint_cap_get_capEPPtr(handlerCap)));

        return EXCEPTION_NONE;
    } else {
        current_fault = seL4_Fault_CapFault_new(handlerCPtr, false);
        current_lookup_fault = lookup_fault_missing_capability_new(0);

        return EXCEPTION_FAULT;
    }
}
#endif

#ifdef CONFIG_PRINTING
static void print_fault(seL4_Fault_t f)
{
    switch (seL4_Fault_get_seL4_FaultType(f)) {
    case seL4_Fault_NullFault:
        printf("null fault");
        break;
    case seL4_Fault_CapFault:
        printf("cap fault in %s phase at address %p",
               seL4_Fault_CapFault_get_inReceivePhase(f) ? "receive" : "send",
               (void *)seL4_Fault_CapFault_get_address(f));
        break;
    case seL4_Fault_VMFault:
        printf("vm fault on %s at address %p with status %p",
               seL4_Fault_VMFault_get_instructionFault(f) ? "code" : "data",
               (void *)seL4_Fault_VMFault_get_address(f),
               (void *)seL4_Fault_VMFault_get_FSR(f));
        break;
    case seL4_Fault_UnknownSyscall:
        printf("unknown syscall %p",
               (void *)seL4_Fault_UnknownSyscall_get_syscallNumber(f));
        break;
    case seL4_Fault_UserException:
        printf("user exception %p code %p",
               (void *)seL4_Fault_UserException_get_number(f),
               (void *)seL4_Fault_UserException_get_code(f));
        break;
#ifdef CONFIG_KERNEL_MCS
    case seL4_Fault_Timeout:
        printf("Timeout fault for 0x%x\n", (unsigned int) seL4_Fault_Timeout_get_badge(f));
        break;
#endif
    default:
        printf("unknown fault");
        break;
    }
}
#endif

#ifdef CONFIG_KERNEL_MCS
void handleNoFaultHandler(tcb_t *tptr)
#else
/* The second fault, ex2, is stored in the global current_fault */
void handleDoubleFault(tcb_t *tptr, seL4_Fault_t ex1)
#endif
{
#ifdef CONFIG_PRINTING
#ifdef CONFIG_KERNEL_MCS
    printf("Found thread has no fault handler while trying to handle:\n");
    print_fault(current_fault);
#else
    seL4_Fault_t ex2 = current_fault;
    printf("Caught ");
    print_fault(ex2);
    printf("\nwhile trying to handle:\n");
    print_fault(ex1);
#endif
#ifdef CONFIG_DEBUG_BUILD
    printf("\nin thread %p \"%s\" ", tptr, TCB_PTR_DEBUG_PTR(tptr)->tcbName);
#endif /* CONFIG_DEBUG_BUILD */

    printf("at address %p\n", (void *)getRestartPC(tptr));
    printf("With stack:\n");
    Arch_userStackTrace(tptr);
#endif

    setThreadState(tptr, ThreadState_Inactive);
}
#line 1 "/home/koc034/Documents/newver/seL4/src/kernel/sporadic.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <api/failures.h>
#include <object/structures.h>

/* functions to manage the circular buffer of
 * sporadic budget replenishments (refills for short).
 *
 * The circular buffer always has at least one item in it.
 *
 * Items are appended at the tail (the back) and
 * removed from the head (the front). Below is
 * an example of a queue with 4 items (h = head, t = tail, x = item, [] = slot)
 * and max size 8.
 *
 * [][h][x][x][t][][][]
 *
 * and another example of a queue with 5 items
 *
 * [x][t][][][][h][x][x]
 *
 * The queue has a minimum size of 1, so it is possible that h == t.
 *
 * The queue is implemented as head + tail rather than head + size as
 * we cannot use the mod operator on all architectures without accessing
 * the fpu or implementing divide.
 */

/* return the index of the next item in the refill queue */
static inline word_t refill_next(sched_context_t *sc, word_t index)
{
    return (index == sc->scRefillMax - 1u) ? (0) : index + 1u;
}

#ifdef CONFIG_PRINTING
/* for debugging */
UNUSED static inline void print_index(sched_context_t *sc, word_t index)
{

    printf("index %lu, Amount: %llx, time %llx\n", index, refill_index(sc, index)->rAmount,
           refill_index(sc, index)->rTime);
}

UNUSED static inline void refill_print(sched_context_t *sc)
{
    printf("Head %lu tail %lu\n", sc->scRefillHead, sc->scRefillTail);
    word_t current = sc->scRefillHead;
    /* always print the head */
    print_index(sc, current);

    while (current != sc->scRefillTail) {
        current = refill_next(sc, current);
        print_index(sc, current);
    }

}
#endif /* CONFIG_PRINTING */
#ifdef CONFIG_DEBUG_BUILD
/* check a refill queue is ordered correctly */
static UNUSED bool_t refill_ordered(sched_context_t *sc)
{
    word_t current = sc->scRefillHead;
    word_t next = refill_next(sc, sc->scRefillHead);

    while (current != sc->scRefillTail) {
        if (!(refill_index(sc, current)->rTime <= refill_index(sc, next)->rTime)) {
            refill_print(sc);
            return false;
        }
        current = next;
        next = refill_next(sc, current);
    }

    return true;
}

#define REFILL_SANITY_START(sc) ticks_t _sum = refill_sum(sc); assert(refill_ordered(sc));
#define REFILL_SANITY_CHECK(sc, budget) \
    do { \
        assert(refill_sum(sc) == budget); assert(refill_ordered(sc)); \
    } while (0)

#define REFILL_SANITY_END(sc) \
    do {\
        REFILL_SANITY_CHECK(sc, _sum);\
    } while (0)
#else
#define REFILL_SANITY_START(sc)
#define REFILL_SANITY_CHECK(sc, budget)
#define REFILL_SANITY_END(sc)
#endif /* CONFIG_DEBUG_BUILD */

/* compute the sum of a refill queue */
static UNUSED ticks_t refill_sum(sched_context_t *sc)
{
    ticks_t sum = refill_head(sc)->rAmount;
    word_t current = sc->scRefillHead;

    while (current != sc->scRefillTail) {
        current = refill_next(sc, current);
        sum += refill_index(sc, current)->rAmount;
    }

    return sum;
}

/* pop head of refill queue */
static inline refill_t refill_pop_head(sched_context_t *sc)
{
    /* queues cannot be smaller than 1 */
    assert(!refill_single(sc));

    UNUSED word_t prev_size = refill_size(sc);
    refill_t refill = *refill_head(sc);
    sc->scRefillHead = refill_next(sc, sc->scRefillHead);

    /* sanity */
    assert(prev_size == (refill_size(sc) + 1));
    assert(sc->scRefillHead < sc->scRefillMax);
    return refill;
}

/* add item to tail of refill queue */
static inline void refill_add_tail(sched_context_t *sc, refill_t refill)
{
    /* cannot add beyond queue size */
    assert(refill_size(sc) < sc->scRefillMax);

    word_t new_tail = refill_next(sc, sc->scRefillTail);
    sc->scRefillTail = new_tail;
    *refill_tail(sc) = refill;

    /* sanity */
    assert(new_tail < sc->scRefillMax);
}

static inline void maybe_add_empty_tail(sched_context_t *sc)
{
    if (isRoundRobin(sc)) {
        /* add an empty refill - we track the used up time here */
        refill_t empty_tail = { .rTime = NODE_STATE(ksCurTime)};
        refill_add_tail(sc, empty_tail);
        assert(refill_size(sc) == MIN_REFILLS);
    }
}

#ifdef ENABLE_SMP_SUPPORT
void refill_new(sched_context_t *sc, word_t max_refills, ticks_t budget, ticks_t period, word_t core)
#else
void refill_new(sched_context_t *sc, word_t max_refills, ticks_t budget, ticks_t period)
#endif
{
    sc->scPeriod = period;
    sc->scRefillHead = 0;
    sc->scRefillTail = 0;
    sc->scRefillMax = max_refills;
    assert(budget > MIN_BUDGET);
    /* full budget available */
    refill_head(sc)->rAmount = budget;
    /* budget can be used from now */
    refill_head(sc)->rTime = NODE_STATE_ON_CORE(ksCurTime, core);
    maybe_add_empty_tail(sc);
    REFILL_SANITY_CHECK(sc, budget);
}

void refill_update_foo1(sched_context_t *sc);
void refill_update_foo1(sched_context_t *sc) {
    *refill_index(sc, 0) = *refill_head(sc);
}

void refill_update_foo2(sched_context_t *sc, ticks_t new_budget);
void refill_update_foo2(sched_context_t *sc, ticks_t new_budget) {
    refill_head(sc)->rAmount = new_budget;
}

void refill_update_foo3(sched_context_t *sc);
void refill_update_foo3(sched_context_t *sc) {
    maybe_add_empty_tail(sc);
}

void refill_update_foo4(sched_context_t *sc, ticks_t new_period, ticks_t new_budget);
void refill_update_foo4(sched_context_t *sc, ticks_t new_period, ticks_t new_budget) {
    refill_t new = { .rAmount = (new_budget - refill_head(sc)->rAmount),
                     .rTime = refill_head(sc)->rTime + new_period
                   };
    refill_add_tail(sc, new);
}

void refill_update(sched_context_t *sc, ticks_t new_period, ticks_t new_budget, word_t new_max_refills)
{

    /* refill must be initialised in order to be updated - otherwise refill_new should be used */
    assert(sc->scRefillMax > 0);

    /* this is called on an active thread. We want to preserve the sliding window constraint -
     * so over new_period, new_budget should not be exceeded even temporarily */

    /* move the head refill to the start of the list - it's ok as we're going to truncate the
     * list to size 1 - and this way we can't be in an invalid list position once new_max_refills
     * is updated */
    refill_t * the_zero = refill_index(sc, 0);
    refill_t * the_head = refill_head(sc);
    *the_zero = *the_head;
    sc->scRefillHead = 0;
    /* truncate refill list to size 1 */
    sc->scRefillTail = sc->scRefillHead;
    /* update max refills */
    sc->scRefillMax = new_max_refills;
    /* update period */
    sc->scPeriod = new_period;

    if (refill_ready(sc)) {
        refill_head(sc)->rTime = NODE_STATE_ON_CORE(ksCurTime, sc->scCore);
    }

    if (refill_head(sc)->rAmount >= new_budget) {
        /* if the heads budget exceeds the new budget just trim it */
        refill_head(sc)->rAmount = new_budget;
        maybe_add_empty_tail(sc);
    } else {
        /* otherwise schedule the rest for the next period */
        refill_t new = { .rAmount = (new_budget - refill_head(sc)->rAmount),
                         .rTime = refill_head(sc)->rTime + new_period
                       };
        refill_add_tail(sc, new);
    }

    REFILL_SANITY_CHECK(sc, new_budget);
}

static NO_INLINE void schedule_used(sched_context_t *sc, refill_t new)
{
    /* schedule the used amount */
    if (new.rAmount < MIN_BUDGET && !refill_single(sc)) {
        /* used amount is to small - merge with last and delay */
        refill_tail(sc)->rAmount += new.rAmount;
        refill_tail(sc)->rTime = MAX(new.rTime, refill_tail(sc)->rTime);
    } else if (new.rTime <= refill_tail(sc)->rTime) {
        refill_tail(sc)->rAmount += new.rAmount;
    } else {
        refill_add_tail(sc, new);
    }
}

static NO_INLINE void ensure_sufficient_head(sched_context_t *sc)
{
    /* ensure the refill head is sufficient, such that when we wake in awaken,
     * there is enough budget to run */
    while (refill_head(sc)->rAmount < MIN_BUDGET || refill_full(sc)) {
        refill_t refill = refill_pop_head(sc);
        refill_head(sc)->rAmount += refill.rAmount;
        /* this loop is guaranteed to terminate as the sum of
         * rAmount in a refill must be >= MIN_BUDGET */
    }
}

uint64_t refill_budget_check_loop(sched_context_t *sc, uint64_t usageA) {
   uint64_t usage = usageA;
    while (refill_head(sc)->rAmount <= usage) {
        /* exhaust and schedule replenishment */
        usage -= refill_head(sc)->rAmount;
        if (refill_single(sc)) {
            /* update in place */
            refill_head(sc)->rTime += sc->scPeriod;
        } else {
            refill_t old_head = refill_pop_head(sc);
            old_head.rTime = old_head.rTime + sc->scPeriod;
            schedule_used(sc, old_head);
        }
    }
    return usage;
}

void refill_budget_check(ticks_t usage)
{
    sched_context_t *sc = NODE_STATE(ksCurSC);
    /* this function should only be called when the sc is out of budget */
    ticks_t capacity = refill_capacity(NODE_STATE(ksCurSC), usage);
    assert(capacity < MIN_BUDGET || refill_full(sc));
    assert(sc->scPeriod > 0);
    REFILL_SANITY_START(sc);

    if (capacity == 0) {
        usage = refill_budget_check_loop(sc, usage);

        /* budget overrun */
        if (usage > 0) {
            /* budget reduced when calculating capacity */
            /* due to overrun delay next replenishment */
            refill_head(sc)->rTime += usage;
            /* merge front two replenishments if times overlap */
            if (!refill_single(sc) &&
                refill_head(sc)->rTime + refill_head(sc)->rAmount >=
                refill_index(sc, refill_next(sc, sc->scRefillHead))->rTime) {

                refill_t refill = refill_pop_head(sc);
                refill_head(sc)->rAmount += refill.rAmount;
                refill_head(sc)->rTime = refill.rTime;
            }
        }
    }

    capacity = refill_capacity(sc, usage);
    if (capacity > 0 && refill_ready(sc)) {
        refill_split_check(usage);
    }

    ensure_sufficient_head(sc);

    REFILL_SANITY_END(sc);
}

void refill_split_check(ticks_t usage)
{
    sched_context_t *sc = NODE_STATE(ksCurSC);
    /* invalid to call this on a NULL sc */
    assert(sc != NULL);
    /* something is seriously wrong if this is called and no
     * time has been used */
    assert(usage > 0);
    assert(usage <= refill_head(sc)->rAmount);
    assert(sc->scPeriod > 0);

    REFILL_SANITY_START(sc);

    /* first deal with the remaining budget of the current replenishment */
    ticks_t remnant = refill_head(sc)->rAmount - usage;

    /* set up a new replenishment structure */
    refill_t new = (refill_t) {
        .rAmount = usage, .rTime = refill_head(sc)->rTime + sc->scPeriod
    };

    if (refill_size(sc) == sc->scRefillMax || remnant < MIN_BUDGET) {
        /* merge remnant with next replenishment - either it's too small
         * or we're out of space */
        if (refill_single(sc)) {
            /* update inplace */
            new.rAmount += remnant;
            *refill_head(sc) = new;
        } else {
            refill_pop_head(sc);
            refill_head(sc)->rAmount += remnant;
            schedule_used(sc, new);
            ensure_sufficient_head(sc);
        }
        assert(refill_ordered(sc));
    } else {
        /* leave remnant as reduced replenishment */
        assert(remnant >= MIN_BUDGET);
        /* split the head refill  */
        refill_head(sc)->rAmount = remnant;
        schedule_used(sc, new);
    }

    REFILL_SANITY_END(sc);
}


static bool_t refill_unblock_check_mergable(sched_context_t *sc)
{
    ticks_t amount = refill_head(sc)->rAmount;
    ticks_t tail = NODE_STATE_ON_CORE(ksCurTime, sc->scCore) + amount;
    bool_t enough_time = refill_index(sc, refill_next(sc, sc->scRefillHead))->rTime <= tail;
    return !refill_single(sc) && enough_time;
}

void refill_unblock_check(sched_context_t *sc)
{

    if (isRoundRobin(sc)) {
        /* nothing to do */
        return;
    }

    /* advance earliest activation time to now */
    REFILL_SANITY_START(sc);
    if (refill_ready(sc)) {
        refill_head(sc)->rTime = NODE_STATE_ON_CORE(ksCurTime, sc->scCore);
        NODE_STATE(ksReprogram) = true;

        /* merge available replenishments */
        while (refill_unblock_check_mergable(sc)) {
            ticks_t amount = refill_head(sc)->rAmount;
            refill_pop_head(sc);
            refill_head(sc)->rAmount += amount;
            refill_head(sc)->rTime = NODE_STATE_ON_CORE(ksCurTime, sc->scCore);
        }

        assert(refill_sufficient(sc, 0));
    }
    REFILL_SANITY_END(sc);
}
#line 1 "/home/koc034/Documents/newver/seL4/src/kernel/stack.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <kernel/stack.h>

VISIBLE ALIGN(KERNEL_STACK_ALIGNMENT)
char kernel_stack_alloc[CONFIG_MAX_NUM_NODES][BIT(CONFIG_KERNEL_STACK_BITS)];
#line 1 "/home/koc034/Documents/newver/seL4/src/kernel/thread.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <object.h>
#include <util.h>
#include <api/faults.h>
#include <api/types.h>
#include <kernel/cspace.h>
#include <kernel/thread.h>
#include <kernel/vspace.h>
#ifdef CONFIG_KERNEL_MCS
#include <object/schedcontext.h>
#endif
#include <model/statedata.h>
#include <arch/machine.h>
#include <arch/kernel/thread.h>
#include <machine/registerset.h>
#include <linker.h>

static seL4_MessageInfo_t
transferCaps(seL4_MessageInfo_t info,
             endpoint_t *endpoint, tcb_t *receiver,
             word_t *receiveBuffer);

BOOT_CODE void configureIdleThread(tcb_t *tcb)
{
    Arch_configureIdleThread(tcb);
    setThreadState(tcb, ThreadState_IdleThreadState);
}

void activateThread(void)
{
#ifdef CONFIG_KERNEL_MCS
    if (unlikely(NODE_STATE(ksCurThread)->tcbYieldTo)) {
        schedContext_completeYieldTo(NODE_STATE(ksCurThread));
        assert(thread_state_get_tsType(NODE_STATE(ksCurThread)->tcbState) == ThreadState_Running);
    }
#endif

    switch (thread_state_get_tsType(NODE_STATE(ksCurThread)->tcbState)) {
    case ThreadState_Running:
#ifdef CONFIG_VTX
    case ThreadState_RunningVM:
#endif
        break;

    case ThreadState_Restart: {
        word_t pc;

        pc = getRestartPC(NODE_STATE(ksCurThread));
        setNextPC(NODE_STATE(ksCurThread), pc);
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Running);
        break;
    }

    case ThreadState_IdleThreadState:
        Arch_activateIdleThread(NODE_STATE(ksCurThread));
        break;

    default:
        fail("Current thread is blocked");
    }
}

void suspend(tcb_t *target)
{
    cancelIPC(target);
    if (thread_state_get_tsType(target->tcbState) == ThreadState_Running) {
        /* whilst in the running state it is possible that restart pc of a thread is
         * incorrect. As we do not know what state this thread will transition to
         * after we make it inactive we update its restart pc so that the thread next
         * runs at the correct address whether it is restarted or moved directly to
         * running */
        updateRestartPC(target);
    }
    setThreadState(target, ThreadState_Inactive);
    tcbSchedDequeue(target);
#ifdef CONFIG_KERNEL_MCS
    tcbReleaseRemove(target);
    schedContext_cancelYieldTo(target);
#endif
}

void restart(tcb_t *target)
{
    if (isStopped(target)) {
        cancelIPC(target);
#ifdef CONFIG_KERNEL_MCS
        setThreadState(target, ThreadState_Restart);
        schedContext_resume(target->tcbSchedContext);
        if (isSchedulable(target)) {
            possibleSwitchTo(target);
        }
#else
        setupReplyMaster(target);
        setThreadState(target, ThreadState_Restart);
        SCHED_ENQUEUE(target);
        possibleSwitchTo(target);
#endif
    }
}

void doIPCTransfer(tcb_t *sender, endpoint_t *endpoint, word_t badge,
                   bool_t grant, tcb_t *receiver)
{
    void *receiveBuffer, *sendBuffer;

    receiveBuffer = lookupIPCBuffer(true, receiver);

    if (likely(seL4_Fault_get_seL4_FaultType(sender->tcbFault) == seL4_Fault_NullFault)) {
        sendBuffer = lookupIPCBuffer(false, sender);
        doNormalTransfer(sender, sendBuffer, endpoint, badge, grant,
                         receiver, receiveBuffer);
    } else {
        doFaultTransfer(badge, sender, receiver, receiveBuffer);
    }
}

#ifdef CONFIG_KERNEL_MCS
void doReplyTransfer(tcb_t *sender, reply_t *reply, bool_t grant)
#else
void doReplyTransfer(tcb_t *sender, tcb_t *receiver, cte_t *slot, bool_t grant)
#endif
{
#ifdef CONFIG_KERNEL_MCS
    if (reply->replyTCB == NULL ||
        thread_state_get_tsType(reply->replyTCB->tcbState) != ThreadState_BlockedOnReply) {
        /* nothing to do */
        return;
    }

    tcb_t *receiver = reply->replyTCB;
    reply_remove(reply, receiver);
    assert(thread_state_get_replyObject(receiver->tcbState) == REPLY_REF(0));
    assert(reply->replyTCB == NULL);
#else
    assert(thread_state_get_tsType(receiver->tcbState) ==
           ThreadState_BlockedOnReply);
#endif

    word_t fault_type = seL4_Fault_get_seL4_FaultType(receiver->tcbFault);
    if (likely(fault_type == seL4_Fault_NullFault)) {
        doIPCTransfer(sender, NULL, 0, grant, receiver);
#ifdef CONFIG_KERNEL_MCS
        setThreadState(receiver, ThreadState_Running);
#else
        /** GHOSTUPD: "(True, gs_set_assn cteDeleteOne_'proc (ucast cap_reply_cap))" */
        cteDeleteOne(slot);
        setThreadState(receiver, ThreadState_Running);
        possibleSwitchTo(receiver);
#endif
    } else {
#ifndef CONFIG_KERNEL_MCS
        /** GHOSTUPD: "(True, gs_set_assn cteDeleteOne_'proc (ucast cap_reply_cap))" */
        cteDeleteOne(slot);
#endif
        bool_t restart = handleFaultReply(receiver, sender);
        receiver->tcbFault = seL4_Fault_NullFault_new();
        if (restart) {
            setThreadState(receiver, ThreadState_Restart);
#ifndef CONFIG_KERNEL_MCS
            possibleSwitchTo(receiver);
#endif
        } else {
            setThreadState(receiver, ThreadState_Inactive);
        }
    }

#ifdef CONFIG_KERNEL_MCS
    if (receiver->tcbSchedContext && isRunnable(receiver)) {
        if ((refill_ready(receiver->tcbSchedContext) && refill_sufficient(receiver->tcbSchedContext, 0))) {
            possibleSwitchTo(receiver);
        } else {
            if (validTimeoutHandler(receiver) && fault_type != seL4_Fault_Timeout) {
                current_fault = seL4_Fault_Timeout_new(receiver->tcbSchedContext->scBadge);
                handleTimeout(receiver);
            } else {
                postpone(receiver->tcbSchedContext);
            }
        }
    }
#endif
}

void doNormalTransfer(tcb_t *sender, word_t *sendBuffer, endpoint_t *endpoint,
                      word_t badge, bool_t canGrant, tcb_t *receiver,
                      word_t *receiveBuffer)
{
    word_t msgTransferred;
    seL4_MessageInfo_t tag;
    exception_t status;

    tag = messageInfoFromWord(getRegister(sender, msgInfoRegister));

    if (canGrant) {
        status = lookupExtraCaps(sender, sendBuffer, tag);
        if (unlikely(status != EXCEPTION_NONE)) {
            current_extra_caps.excaprefs[0] = NULL;
        }
    } else {
        current_extra_caps.excaprefs[0] = NULL;
    }

    msgTransferred = copyMRs(sender, sendBuffer, receiver, receiveBuffer,
                             seL4_MessageInfo_get_length(tag));

    tag = transferCaps(tag, endpoint, receiver, receiveBuffer);

    tag = seL4_MessageInfo_set_length(tag, msgTransferred);
    setRegister(receiver, msgInfoRegister, wordFromMessageInfo(tag));
    setRegister(receiver, badgeRegister, badge);
}

void doFaultTransfer(word_t badge, tcb_t *sender, tcb_t *receiver,
                     word_t *receiverIPCBuffer)
{
    word_t sent;
    seL4_MessageInfo_t msgInfo;

    sent = setMRs_fault(sender, receiver, receiverIPCBuffer);
    msgInfo = seL4_MessageInfo_new(
                  seL4_Fault_get_seL4_FaultType(sender->tcbFault), 0, 0, sent);
    setRegister(receiver, msgInfoRegister, wordFromMessageInfo(msgInfo));
    setRegister(receiver, badgeRegister, badge);
}

/* Like getReceiveSlots, this is specialised for single-cap transfer. */
static seL4_MessageInfo_t transferCaps(seL4_MessageInfo_t info,
                                       endpoint_t *endpoint, tcb_t *receiver,
                                       word_t *receiveBuffer)
{
    word_t i;
    cte_t *destSlot;

    info = seL4_MessageInfo_set_extraCaps(info, 0);
    info = seL4_MessageInfo_set_capsUnwrapped(info, 0);

    if (likely(!current_extra_caps.excaprefs[0] || !receiveBuffer)) {
        return info;
    }

    destSlot = getReceiveSlots(receiver, receiveBuffer);

    for (i = 0; i < seL4_MsgMaxExtraCaps && current_extra_caps.excaprefs[i] != NULL; i++) {
        cte_t *slot = current_extra_caps.excaprefs[i];
        cap_t cap = slot->cap;

        if (cap_get_capType(cap) == cap_endpoint_cap &&
            EP_PTR(cap_endpoint_cap_get_capEPPtr(cap)) == endpoint) {
            /* If this is a cap to the endpoint on which the message was sent,
             * only transfer the badge, not the cap. */
            setExtraBadge(receiveBuffer,
                          cap_endpoint_cap_get_capEPBadge(cap), i);

            info = seL4_MessageInfo_set_capsUnwrapped(info,
                                                      seL4_MessageInfo_get_capsUnwrapped(info) | (1 << i));

        } else {
            deriveCap_ret_t dc_ret;

            if (!destSlot) {
                break;
            }

            dc_ret = deriveCap(slot, cap);

            if (dc_ret.status != EXCEPTION_NONE) {
                break;
            }
            if (cap_get_capType(dc_ret.cap) == cap_null_cap) {
                break;
            }

            cteInsert(dc_ret.cap, slot, destSlot);

            destSlot = NULL;
        }
    }

    return seL4_MessageInfo_set_extraCaps(info, i);
}

void doNBRecvFailedTransfer(tcb_t *thread)
{
    /* Set the badge register to 0 to indicate there was no message */
    setRegister(thread, badgeRegister, 0);
}

static void nextDomain(void)
{
    ksDomScheduleIdx++;
    if (ksDomScheduleIdx >= ksDomScheduleLength) {
        ksDomScheduleIdx = 0;
    }
#ifdef CONFIG_KERNEL_MCS
    NODE_STATE(ksReprogram) = true;
#endif
    ksWorkUnitsCompleted = 0;
    ksCurDomain = ksDomSchedule[ksDomScheduleIdx].domain;
#ifdef CONFIG_KERNEL_MCS
    ksDomainTime = usToTicks(ksDomSchedule[ksDomScheduleIdx].length * US_IN_MS);
#else
    ksDomainTime = ksDomSchedule[ksDomScheduleIdx].length;
#endif
}

#ifdef CONFIG_KERNEL_MCS
static void switchSchedContext(void)
{
    if (unlikely(NODE_STATE(ksCurSC) != NODE_STATE(ksCurThread)->tcbSchedContext) && NODE_STATE(ksCurSC)->scRefillMax) {
        NODE_STATE(ksReprogram) = true;
        refill_unblock_check(NODE_STATE(ksCurThread->tcbSchedContext));

        assert(refill_ready(NODE_STATE(ksCurThread->tcbSchedContext)));
        assert(refill_sufficient(NODE_STATE(ksCurThread->tcbSchedContext), 0));
    }

    if (NODE_STATE(ksReprogram)) {
        /* if we are reprogamming, we have acted on the new kernel time and cannot
         * rollback -> charge the current thread */
        commitTime();
    }

    NODE_STATE(ksCurSC) = NODE_STATE(ksCurThread)->tcbSchedContext;
}
#endif

static void scheduleChooseNewThread(void)
{
    if (ksDomainTime == 0) {
        nextDomain();
    }
    chooseThread();
}

void schedule(void)
{
#ifdef CONFIG_KERNEL_MCS
    awaken();
#endif

    if (NODE_STATE(ksSchedulerAction) != SchedulerAction_ResumeCurrentThread) {
        bool_t was_runnable;
        if (isSchedulable(NODE_STATE(ksCurThread))) {
            was_runnable = true;
            SCHED_ENQUEUE_CURRENT_TCB;
        } else {
            was_runnable = false;
        }

        if (NODE_STATE(ksSchedulerAction) == SchedulerAction_ChooseNewThread) {
            scheduleChooseNewThread();
        } else {
            tcb_t *candidate = NODE_STATE(ksSchedulerAction);
            assert(isSchedulable(candidate));
            /* Avoid checking bitmap when ksCurThread is higher prio, to
             * match fast path.
             * Don't look at ksCurThread prio when it's idle, to respect
             * information flow in non-fastpath cases. */
            bool_t fastfail =
                NODE_STATE(ksCurThread) == NODE_STATE(ksIdleThread)
                || (candidate->tcbPriority < NODE_STATE(ksCurThread)->tcbPriority);
            if (fastfail &&
                !isHighestPrio(ksCurDomain, candidate->tcbPriority)) {
                SCHED_ENQUEUE(candidate);
                /* we can't, need to reschedule */
                NODE_STATE(ksSchedulerAction) = SchedulerAction_ChooseNewThread;
                scheduleChooseNewThread();
            } else if (was_runnable && candidate->tcbPriority == NODE_STATE(ksCurThread)->tcbPriority) {
                /* We append the candidate at the end of the scheduling queue, that way the
                 * current thread, that was enqueued at the start of the scheduling queue
                 * will get picked during chooseNewThread */
                SCHED_APPEND(candidate);
                NODE_STATE(ksSchedulerAction) = SchedulerAction_ChooseNewThread;
                scheduleChooseNewThread();
            } else {
                assert(candidate != NODE_STATE(ksCurThread));
                switchToThread(candidate);
            }
        }
    }
    NODE_STATE(ksSchedulerAction) = SchedulerAction_ResumeCurrentThread;
#ifdef ENABLE_SMP_SUPPORT
    doMaskReschedule(ARCH_NODE_STATE(ipiReschedulePending));
    ARCH_NODE_STATE(ipiReschedulePending) = 0;
#endif /* ENABLE_SMP_SUPPORT */

#ifdef CONFIG_KERNEL_MCS
    switchSchedContext();

    if (NODE_STATE(ksReprogram)) {
        setNextInterrupt();
        NODE_STATE(ksReprogram) = false;
    }
#endif
}

void chooseThread(void)
{
    word_t prio;
    word_t dom;
    tcb_t *thread;

    if (CONFIG_NUM_DOMAINS > 1) {
        dom = ksCurDomain;
    } else {
        dom = 0;
    }

    if (likely(NODE_STATE(ksReadyQueuesL1Bitmap[dom]))) {
        prio = getHighestPrio(dom);
        thread = NODE_STATE(ksReadyQueues)[ready_queues_index(dom, prio)].head;
        assert(thread);
        assert(isSchedulable(thread));
#ifdef CONFIG_KERNEL_MCS
        assert(refill_sufficient(thread->tcbSchedContext, 0));
        assert(refill_ready(thread->tcbSchedContext));
#endif
        switchToThread(thread);
    } else {
        switchToIdleThread();
    }
}

void switchToThread(tcb_t *thread)
{
#ifdef CONFIG_KERNEL_MCS
    assert(thread->tcbSchedContext != NULL);
    assert(!thread_state_get_tcbInReleaseQueue(thread->tcbState));
    assert(refill_sufficient(thread->tcbSchedContext, 0));
    assert(refill_ready(thread->tcbSchedContext));
#endif

#ifdef CONFIG_BENCHMARK_TRACK_UTILISATION
    benchmark_utilisation_switch(NODE_STATE(ksCurThread), thread);
#endif
    Arch_switchToThread(thread);
    tcbSchedDequeue(thread);
    NODE_STATE(ksCurThread) = thread;
}

void switchToIdleThread(void)
{
#ifdef CONFIG_BENCHMARK_TRACK_UTILISATION
    benchmark_utilisation_switch(NODE_STATE(ksCurThread), NODE_STATE(ksIdleThread));
#endif
    Arch_switchToIdleThread();
    NODE_STATE(ksCurThread) = NODE_STATE(ksIdleThread);
}

void setDomain(tcb_t *tptr, dom_t dom)
{
    tcbSchedDequeue(tptr);
    tptr->tcbDomain = dom;
    if (isSchedulable(tptr)) {
        SCHED_ENQUEUE(tptr);
    }
    if (tptr == NODE_STATE(ksCurThread)) {
        rescheduleRequired();
    }
}

void setMCPriority(tcb_t *tptr, prio_t mcp)
{
    tptr->tcbMCP = mcp;
}
#ifdef CONFIG_KERNEL_MCS
void setPriority(tcb_t *tptr, prio_t prio)
{
    switch (thread_state_get_tsType(tptr->tcbState)) {
    case ThreadState_Running:
    case ThreadState_Restart:
        if (thread_state_get_tcbQueued(tptr->tcbState) || tptr == NODE_STATE(ksCurThread)) {
            tcbSchedDequeue(tptr);
            tptr->tcbPriority = prio;
            SCHED_ENQUEUE(tptr);
            rescheduleRequired();
        } else {
            tptr->tcbPriority = prio;
        }
        break;
    case ThreadState_BlockedOnReceive:
    case ThreadState_BlockedOnSend:
        tptr->tcbPriority = prio;
        reorderEP(EP_PTR(thread_state_get_blockingObject(tptr->tcbState)), tptr);
        break;
    case ThreadState_BlockedOnNotification:
        tptr->tcbPriority = prio;
        reorderNTFN(NTFN_PTR(thread_state_get_blockingObject(tptr->tcbState)), tptr);
        break;
    default:
        tptr->tcbPriority = prio;
        break;
    }
}
#else
void setPriority(tcb_t *tptr, prio_t prio)
{
    tcbSchedDequeue(tptr);
    tptr->tcbPriority = prio;
    if (isRunnable(tptr)) {
        if (tptr == NODE_STATE(ksCurThread)) {
            rescheduleRequired();
        } else {
            possibleSwitchTo(tptr);
        }
    }
}
#endif

/* Note that this thread will possibly continue at the end of this kernel
 * entry. Do not queue it yet, since a queue+unqueue operation is wasteful
 * if it will be picked. Instead, it waits in the 'ksSchedulerAction' site
 * on which the scheduler will take action. */
void possibleSwitchTo(tcb_t *target)
{
#ifdef CONFIG_KERNEL_MCS
    if (target->tcbSchedContext != NULL && !thread_state_get_tcbInReleaseQueue(target->tcbState)) {
#endif
        if (ksCurDomain != target->tcbDomain
            SMP_COND_STATEMENT( || target->tcbAffinity != getCurrentCPUIndex())) {
            SCHED_ENQUEUE(target);
        } else if (NODE_STATE(ksSchedulerAction) != SchedulerAction_ResumeCurrentThread) {
            /* Too many threads want special treatment, use regular queues. */
            rescheduleRequired();
            SCHED_ENQUEUE(target);
        } else {
            NODE_STATE(ksSchedulerAction) = target;
        }
#ifdef CONFIG_KERNEL_MCS
    }
#endif

}

void setThreadState(tcb_t *tptr, _thread_state_t ts)
{
    thread_state_ptr_set_tsType(&tptr->tcbState, ts);
    scheduleTCB(tptr);
}

void scheduleTCB(tcb_t *tptr)
{
    if (tptr == NODE_STATE(ksCurThread) &&
        NODE_STATE(ksSchedulerAction) == SchedulerAction_ResumeCurrentThread &&
        !isSchedulable(tptr)) {
        rescheduleRequired();
    }
}

#ifdef CONFIG_KERNEL_MCS
void postpone(sched_context_t *sc)
{
    tcbSchedDequeue(sc->scTcb);
    tcbReleaseEnqueue(sc->scTcb);
    NODE_STATE_ON_CORE(ksReprogram, sc->scCore) = true;
}

void setNextInterrupt(void)
{
    time_t next_interrupt = NODE_STATE(ksCurTime) +
                            refill_head(NODE_STATE(ksCurThread)->tcbSchedContext)->rAmount;

    if (CONFIG_NUM_DOMAINS > 1) {
        next_interrupt = MIN(next_interrupt, NODE_STATE(ksCurTime) + ksDomainTime);
    }

    if (NODE_STATE(ksReleaseHead) != NULL) {
        next_interrupt = MIN(refill_head(NODE_STATE(ksReleaseHead)->tcbSchedContext)->rTime, next_interrupt);
    }

    setDeadline(next_interrupt - getTimerPrecision());
}

void chargeBudget(ticks_t consumed, bool_t canTimeoutFault, word_t core, bool_t isCurCPU)
{

    if (isRoundRobin(NODE_STATE_ON_CORE(ksCurSC, core))) {
        assert(refill_size(NODE_STATE_ON_CORE(ksCurSC, core)) == MIN_REFILLS);
        refill_head(NODE_STATE_ON_CORE(ksCurSC, core))->rAmount += refill_tail(NODE_STATE_ON_CORE(ksCurSC, core))->rAmount;
        refill_tail(NODE_STATE_ON_CORE(ksCurSC, core))->rAmount = 0;
    } else {
        refill_budget_check(consumed);
    }

    assert(refill_head(NODE_STATE_ON_CORE(ksCurSC, core))->rAmount >= MIN_BUDGET);
    NODE_STATE_ON_CORE(ksCurSC, core)->scConsumed += consumed;
    NODE_STATE_ON_CORE(ksConsumed, core) = 0;
    if (isCurCPU && likely(isSchedulable(NODE_STATE_ON_CORE(ksCurThread, core)))) {
        assert(NODE_STATE(ksCurThread)->tcbSchedContext == NODE_STATE(ksCurSC));
        endTimeslice(canTimeoutFault);
        rescheduleRequired();
        NODE_STATE(ksReprogram) = true;
    }
}

void endTimeslice(bool_t can_timeout_fault)
{
    if (can_timeout_fault && !isRoundRobin(NODE_STATE(ksCurSC)) && validTimeoutHandler(NODE_STATE(ksCurThread))) {
        current_fault = seL4_Fault_Timeout_new(NODE_STATE(ksCurSC)->scBadge);
        handleTimeout(NODE_STATE(ksCurThread));
    } else if (refill_ready(NODE_STATE(ksCurSC)) && refill_sufficient(NODE_STATE(ksCurSC), 0)) {
        /* apply round robin */
        assert(refill_sufficient(NODE_STATE(ksCurSC), 0));
        assert(!thread_state_get_tcbQueued(NODE_STATE(ksCurThread)->tcbState));
        SCHED_APPEND_CURRENT_TCB;
    } else {
        /* postpone until ready */
        postpone(NODE_STATE(ksCurSC));
    }
}
#else

void timerTick(void)
{
    if (likely(thread_state_get_tsType(NODE_STATE(ksCurThread)->tcbState) ==
               ThreadState_Running)
#ifdef CONFIG_VTX
        || thread_state_get_tsType(NODE_STATE(ksCurThread)->tcbState) ==
        ThreadState_RunningVM
#endif
       ) {
        if (NODE_STATE(ksCurThread)->tcbTimeSlice > 1) {
            NODE_STATE(ksCurThread)->tcbTimeSlice--;
        } else {
            NODE_STATE(ksCurThread)->tcbTimeSlice = CONFIG_TIME_SLICE;
            SCHED_APPEND_CURRENT_TCB;
            rescheduleRequired();
        }
    }

    if (CONFIG_NUM_DOMAINS > 1) {
        ksDomainTime--;
        if (ksDomainTime == 0) {
            rescheduleRequired();
        }
    }
}
#endif

void rescheduleRequired(void)
{
    if (NODE_STATE(ksSchedulerAction) != SchedulerAction_ResumeCurrentThread
        && NODE_STATE(ksSchedulerAction) != SchedulerAction_ChooseNewThread
#ifdef CONFIG_KERNEL_MCS
        && isSchedulable(NODE_STATE(ksSchedulerAction))
#endif
       ) {
#ifdef CONFIG_KERNEL_MCS
        assert(refill_sufficient(NODE_STATE(ksSchedulerAction)->tcbSchedContext, 0));
        assert(refill_ready(NODE_STATE(ksSchedulerAction)->tcbSchedContext));
#endif
        SCHED_ENQUEUE(NODE_STATE(ksSchedulerAction));
    }
    NODE_STATE(ksSchedulerAction) = SchedulerAction_ChooseNewThread;
}

#ifdef CONFIG_KERNEL_MCS
void awaken(void)
{
    while (unlikely(NODE_STATE(ksReleaseHead) != NULL && refill_ready(NODE_STATE(ksReleaseHead)->tcbSchedContext))) {
        tcb_t *awakened = tcbReleaseDequeue();
        /* the currently running thread cannot have just woken up */
        assert(awakened != NODE_STATE(ksCurThread));
        /* round robin threads should not be in the release queue */
        assert(!isRoundRobin(awakened->tcbSchedContext));
        /* threads should wake up on the correct core */
        SMP_COND_STATEMENT(assert(awakened->tcbAffinity == getCurrentCPUIndex()));
        /* threads HEAD refill should always be > MIN_BUDGET */
        assert(refill_sufficient(awakened->tcbSchedContext, 0));
        possibleSwitchTo(awakened);
        /* changed head of release queue -> need to reprogram */
        NODE_STATE(ksReprogram) = true;
    }
}
#endif
#line 1 "/home/koc034/Documents/newver/seL4/src/machine/fpu.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <machine/fpu.h>
#include <api/failures.h>
#include <model/statedata.h>
#include <arch/object/structures.h>

#ifdef CONFIG_HAVE_FPU
/* Switch the owner of the FPU to the given thread on local core. */
void switchLocalFpuOwner(user_fpu_state_t *new_owner)
{
    enableFpu();
    if (NODE_STATE(ksActiveFPUState)) {
        saveFpuState(NODE_STATE(ksActiveFPUState));
    }
    if (new_owner) {
        NODE_STATE(ksFPURestoresSinceSwitch) = 0;
        loadFpuState(new_owner);
    } else {
        disableFpu();
    }
    NODE_STATE(ksActiveFPUState) = new_owner;
}

void switchFpuOwner(user_fpu_state_t *new_owner, word_t cpu)
{
#ifdef ENABLE_SMP_SUPPORT
    if (cpu != getCurrentCPUIndex()) {
        doRemoteswitchFpuOwner(new_owner, cpu);
    } else
#endif /* ENABLE_SMP_SUPPORT */
    {
        switchLocalFpuOwner(new_owner);
    }
}

/* Handle an FPU fault.
 *
 * This CPU exception is thrown when userspace attempts to use the FPU while
 * it is disabled. We need to save the current state of the FPU, and hand
 * it over. */
exception_t handleFPUFault(void)
{
    /* If we have already given the FPU to the user, we should not reach here.
     * This should only be able to occur on CPUs without an FPU at all, which
     * we presumably are happy to assume will not be running seL4. */
    assert(!nativeThreadUsingFPU(NODE_STATE(ksCurThread)));

    /* Otherwise, lazily switch over the FPU. */
    switchLocalFpuOwner(&NODE_STATE(ksCurThread)->tcbArch.tcbContext.fpuState);

    return EXCEPTION_NONE;
}

/* Prepare for the deletion of the given thread. */
void fpuThreadDelete(tcb_t *thread)
{
    /* If the thread being deleted currently owns the FPU, switch away from it
     * so that 'ksActiveFPUState' doesn't point to invalid memory. */
    if (nativeThreadUsingFPU(thread)) {
        switchFpuOwner(NULL, SMP_TERNARY(thread->tcbAffinity, 0));
    }
}
#endif /* CONFIG_HAVE_FPU */
#line 1 "/home/koc034/Documents/newver/seL4/src/machine/io.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Portions derived from musl:
 *
 * Copyright © 2005-2020 Rich Felker, et al.
 *
 * SPDX-License-Identifier: MIT
 */

#include <config.h>
#include <machine/io.h>

#ifdef CONFIG_PRINTING

#include <stdarg.h>
#include <stdint.h>

/*
 * a handle defining how to output a character
 */
typedef void (*out_fn)(char character, char *buf, word_t idx);

/*
 * structure to allow a generic vprintf
 * a out_fn handle and a buf to work on
 */
typedef struct {
    out_fn putchar;
    char *buf;
    word_t idx;
    word_t maxlen;
} out_wrap_t;

/*
 * putchar would then just call the handle with its buf
 * and current idx and then increment idx
 */
static void putchar_wrap(out_wrap_t *out, char c)
{
    if (out->maxlen < 0 || out->idx < out->maxlen) {
        out->putchar(c, out->buf, out->idx);
        out->idx++;
    }
}


void putchar(char c)
{
    if (c == '\n') {
        putDebugChar('\r');
    }
    putDebugChar(c);
}

static inline bool_t isdigit(char c)
{
    return c >= '0' &&
           c <= '9';
}

/* Convenient bit representation for modifier flags, which all fall
 * within 31 codepoints of the space character. */

#define MASK_TYPE(a) (1U<<( a -' '))

#define ALT_FORM     (1U<<('#'-' '))
#define ZERO_PAD     (1U<<('0'-' '))
#define LEFT_ADJ     (1U<<('-'-' '))
#define PAD_POS      (1U<<(' '-' '))
#define MARK_POS     (1U<<('+'-' '))
#define GROUPED      (1U<<('\''-' '))

#define FLAGMASK (ALT_FORM|ZERO_PAD|LEFT_ADJ|PAD_POS|MARK_POS|GROUPED)

#define INTMAX_MAX INT32_MAX
#define INT_MAX  0x7fffffff

#define ULONG_MAX ((unsigned long)(-1))

/* State machine to accept length modifiers + conversion specifiers.
 * Result is 0 on failure, or an argument type to pop on success. */

enum {
    BARE, LPRE, LLPRE, HPRE, HHPRE, BIGLPRE,
    ZTPRE, JPRE,
    STOP,
    PTR, INT, UINT, ULLONG,
    LONG, ULONG,
    SHORT, USHORT, CHAR, UCHAR,
    WORDT, LLONG,
#define IMAX LLONG
#define UMAX ULLONG
#define PDIFF LONG
#define UIPTR ULONG
    NOARG,
    MAXSTATE
};

#define S(x) [(x)-'A']

static const unsigned char states[]['z' - 'A' + 1] = {
    { /* 0: bare types */
        S('d') = INT, S('i') = INT,
        S('o') = UINT, S('u') = UINT, S('x') = UINT, S('X') = UINT,
        S('c') = CHAR,
        S('s') = PTR, S('p') = UIPTR, S('n') = PTR,
        S('l') = LPRE, S('h') = HPRE,
        S('z') = ZTPRE, S('j') = JPRE, S('t') = ZTPRE,
    }, { /* 1: l-prefixed */
        S('d') = LONG, S('i') = LONG,
        S('o') = ULONG, S('u') = ULONG, S('x') = ULONG, S('X') = ULONG,
        S('n') = PTR,
        S('l') = LLPRE,
    }, { /* 2: ll-prefixed */
        S('d') = LLONG, S('i') = LLONG,
        S('o') = ULLONG, S('u') = ULLONG,
        S('x') = ULLONG, S('X') = ULLONG,
        S('n') = PTR,
    }, { /* 3: h-prefixed */
        S('d') = SHORT, S('i') = SHORT,
        S('o') = USHORT, S('u') = USHORT,
        S('x') = USHORT, S('X') = USHORT,
        S('n') = PTR,
        S('h') = HHPRE,
    }, { /* 4: hh-prefixed */
        S('d') = CHAR, S('i') = CHAR,
        S('o') = UCHAR, S('u') = UCHAR,
        S('x') = UCHAR, S('X') = UCHAR,
        S('n') = PTR,
    }, { /* 5: L-prefixed not supported */
    }, { /* 6: z- or t-prefixed (assumed to be same size) */
        S('d') = PDIFF, S('i') = PDIFF,
        S('o') = WORDT, S('u') = WORDT,
        S('x') = WORDT, S('X') = WORDT,
        S('n') = PTR,
    }, { /* 7: j-prefixed */
        S('d') = IMAX, S('i') = IMAX,
        S('o') = UMAX, S('u') = UMAX,
        S('x') = UMAX, S('X') = UMAX,
        S('n') = PTR,
    }
};

#define OOB(x) ((unsigned)(x)-'A' > 'z'-'A')
#define DIGIT(c) (c - '0')

union arg {
    word_t i;
    long double f;
    void *p;
};

static void pop_arg(union arg *arg, int type, va_list *ap)
{
    switch (type) {
    case PTR:
        arg->p = va_arg(*ap, void *);
        break;
    case INT:
        arg->i = va_arg(*ap, int);
        break;
    case UINT:
        arg->i = va_arg(*ap, unsigned int);
        break;
    case LONG:
        arg->i = va_arg(*ap, long);
        break;
    case ULONG:
        arg->i = va_arg(*ap, unsigned long);
        break;
    case LLONG:
        arg->i = va_arg(*ap, long long);
        break;
    case ULLONG:
        arg->i = va_arg(*ap, unsigned long long);
        break;
    case SHORT:
        arg->i = (short)va_arg(*ap, int);
        break;
    case USHORT:
        arg->i = (unsigned short)va_arg(*ap, int);
        break;
    case CHAR:
        arg->i = (signed char)va_arg(*ap, int);
        break;
    case UCHAR:
        arg->i = (unsigned char)va_arg(*ap, int);
        break;
    case WORDT:
        arg->i = va_arg(*ap, word_t);
    }
}

static void out(out_wrap_t *f, const char *s, word_t l)
{
    for (word_t i = 0; i < l; i++) {
        putchar_wrap(f, s[i]);
    }
}

static void pad(out_wrap_t *f, char c, int w, int l, int fl)
{
    char pad[256];
    if (fl & (LEFT_ADJ | ZERO_PAD) || l >= w) {
        return;
    }
    l = w - l;
    memset(pad, c, l > sizeof pad ? sizeof pad : l);
    for (; l >= sizeof pad; l -= sizeof pad) {
        out(f, pad, sizeof pad);
    }
    out(f, pad, l);
}

static const char xdigits[16] = {
    "0123456789ABCDEF"
};

static char *fmt_x(word_t x, char *s, int lower)
{
    for (; x; x >>= 4) {
        *--s = xdigits[(x & 15)] | lower;
    }
    return s;
}

static char *fmt_o(word_t x, char *s)
{
    for (; x; x >>= 3) {
        *--s = '0' + (x & 7);
    }
    return s;
}

static char *fmt_u(word_t x, char *s)
{
    unsigned long y;
    for (; x > ULONG_MAX; x /= 10) {
        *--s = '0' + x % 10;
    }
    for (y = x;           y; y /= 10) {
        *--s = '0' + y % 10;
    }
    return s;
}

// Maximum buffer size taken to ensure correct adaptation
// However, it could be reduced/removed if we could measure
// the buf length under all code paths
#define LDBL_MANT_DIG 113

#define NL_ARGMAX 9

static int getint(char **s)
{
    int i;
    for (i = 0; isdigit(**s); (*s)++) {
        if (i > INT_MAX / 10U || DIGIT(**s) > INT_MAX - 10 * i) {
            i = -1;
        } else {
            i = 10 * i + DIGIT(**s);
        }
    }
    return i;
}

static int printf_core(out_wrap_t *f, const char *fmt, va_list *ap, union arg *nl_arg, int *nl_type)
{
    char *a, *z, *s = (char *)fmt;
    unsigned l10n = 0, fl;
    int w, p, xp;
    union arg arg;
    int argpos;
    unsigned st, ps;
    int cnt = 0, l = 0;
    word_t i;
    char buf[sizeof(word_t) * 3 + 3 + LDBL_MANT_DIG / 4];
    const char *prefix;
    int t, pl;

    for (;;) {
        /* This error is only specified for snprintf, but since it's
         * unspecified for other forms, do the same. Stop immediately
         * on overflow; otherwise %n could produce wrong results. */
        if (l > INT_MAX - cnt) {
            goto overflow;
        }

        /* Update output count, end loop when fmt is exhausted */
        cnt += l;
        if (!*s) {
            break;
        }

        /* Handle literal text and %% format specifiers */
        for (a = s; *s && *s != '%'; s++);
        for (z = s; s[0] == '%' && s[1] == '%'; z++, s += 2);
        if (z - a > INT_MAX - cnt) {
            goto overflow;
        }
        l = z - a;
        if (f) {
            out(f, a, l);
        }
        if (l) {
            continue;
        }

        if (isdigit(s[1]) && s[2] == '$') {
            l10n = 1;
            argpos = DIGIT(s[1]);
            s += 3;
        } else {
            argpos = -1;
            s++;
        }

        /* Read modifier flags */
        for (fl = 0; (unsigned)*s - ' ' < 32 && (FLAGMASK & MASK_TYPE(*s)); s++) {
            fl |= MASK_TYPE(*s);
        }

        /* Read field width */
        if (*s == '*') {
            if (isdigit(s[1]) && s[2] == '$') {
                l10n = 1;
                nl_type[DIGIT(s[1])] = INT;
                w = nl_arg[DIGIT(s[1])].i;
                s += 3;
            } else if (!l10n) {
                w = f ? va_arg(*ap, int) : 0;
                s++;
            } else {
                goto inval;
            }
            if (w < 0) {
                fl |= LEFT_ADJ;
                w = -w;
            }
        } else if ((w = getint(&s)) < 0) {
            goto overflow;
        }

        /* Read precision */
        if (*s == '.' && s[1] == '*') {
            if (isdigit(s[2]) && s[3] == '$') {
                nl_type[DIGIT(s[2])] = INT;
                p = nl_arg[DIGIT(s[2])].i;
                s += 4;
            } else if (!l10n) {
                p = f ? va_arg(*ap, int) : 0;
                s += 2;
            } else {
                goto inval;
            }
            xp = (p >= 0);
        } else if (*s == '.') {
            s++;
            p = getint(&s);
            xp = 1;
        } else {
            p = -1;
            xp = 0;
        }

        /* Format specifier state machine */
        st = 0;
        do {
            if (OOB(*s)) {
                goto inval;
            }
            ps = st;
            st = states[st]S(*s++);
        } while (st - 1 < STOP);
        if (!st) {
            goto inval;
        }

        /* Check validity of argument type (nl/normal) */
        if (st == NOARG) {
            if (argpos >= 0) {
                goto inval;
            }
        } else {
            if (argpos >= 0) {
                nl_type[argpos] = st;
                arg = nl_arg[argpos];
            } else if (f) {
                pop_arg(&arg, st, ap);
            } else {
                return 0;
            }
        }

        if (!f) {
            continue;
        }

        z = buf + sizeof(buf);
        prefix = "-+   0X0x";
        pl = 0;
        t = s[-1];

        /* - and 0 flags are mutually exclusive */
        if (fl & LEFT_ADJ) {
            fl &= ~ZERO_PAD;
        }

        if (t == 'n') {
            if (!arg.p) {
                continue;
            }
            switch (ps) {
            case BARE:
                *(int *)arg.p = cnt;
                break;
            case LPRE:
                *(long *)arg.p = cnt;
                break;
            case LLPRE:
                *(long long *)arg.p = cnt;
                break;
            case HPRE:
                *(unsigned short *)arg.p = cnt;
                break;
            case HHPRE:
                *(unsigned char *)arg.p = cnt;
                break;
            case ZTPRE:
                *(word_t *)arg.p = cnt;
                break;
            case JPRE:
                *(word_t *)arg.p = cnt;
                break;
            }
            continue;
        } else if (t == 'c') {
            p = 1;
            a = z - p;
            *a = arg.i;
            fl &= ~ZERO_PAD;
        } else if (t == 's') {
            a = arg.p ? arg.p : "(null)";
            z = a + strnlen(a, p < 0 ? INT_MAX : p);
            if (p < 0 && *z) {
                goto overflow;
            }
            p = z - a;
            fl &= ~ZERO_PAD;
        } else {
            switch (t) {
            case 'p':
                p = MAX(p, 2 * sizeof(void *));
                t = 'x';
                fl |= ALT_FORM;
            case 'x':
            case 'X':
                a = fmt_x(arg.i, z, t & 32);
                if (arg.i && (fl & ALT_FORM)) {
                    prefix += (t >> 4);
                    pl = 2;
                }
                break;
            case 'o':
                a = fmt_o(arg.i, z);
                if ((fl & ALT_FORM) && p < (z - a + 1)) {
                    p = z - a + 1;
                }
                break;
            case 'd':
            case 'i':
                pl = 1;
                if (arg.i > INTMAX_MAX) {
                    arg.i = -arg.i;
                } else if (fl & MARK_POS) {
                    prefix++;
                } else if (fl & PAD_POS) {
                    prefix += 2;
                } else {
                    pl = 0;
                }
            case 'u':
                a = fmt_u(arg.i, z);
                break;
            }
            if (xp && p < 0) {
                goto overflow;
            }
            if (xp) {
                fl &= ~ZERO_PAD;
            }
            if (!arg.i && !p) {
                a = z;
            } else {
                p = MAX(p, z - a + !arg.i);
            }
        }

        if (p < z - a) {
            p = z - a;
        }
        if (p > INT_MAX - pl) {
            goto overflow;
        }
        if (w < pl + p) {
            w = pl + p;
        }
        if (w > INT_MAX - cnt) {
            goto overflow;
        }

        pad(f, ' ', w, pl + p, fl);
        out(f, prefix, pl);
        pad(f, '0', w, pl + p, fl ^ ZERO_PAD);
        pad(f, '0', p, z - a, 0);
        out(f, a, z - a);
        pad(f, ' ', w, pl + p, fl ^ LEFT_ADJ);

        l = w;
    }

    if (f) {
        return cnt;
    }
    if (!l10n) {
        return 0;
    }

    for (i = 1; i <= NL_ARGMAX && nl_type[i]; i++) {
        pop_arg(nl_arg + i, nl_type[i], ap);
    }
    for (; i <= NL_ARGMAX && !nl_type[i]; i++);
    if (i <= NL_ARGMAX) {
        goto inval;
    }
    return 1;

// goto for potential debug error support
inval:
overflow:
    return -1;
}

// sprintf fills its buf with the given character
static void buf_out_fn(char c, char *buf, word_t idx)
{
    buf[idx] = c;
}

// printf only needs to call kernel_putchar
static void kernel_out_fn(char c, char *buf, word_t idx)
{
    kernel_putchar(c);
}

word_t puts(const char *s)
{
    for (; *s; s++) {
        kernel_putchar(*s);
    }
    kernel_putchar('\n');
    return 0;
}

static int vprintf(out_wrap_t *out, const char *fmt, va_list ap)
{
    va_list ap2;
    int nl_type[NL_ARGMAX + 1] = {0};
    union arg nl_arg[NL_ARGMAX + 1];
    int ret;

    // validate format string
    va_copy(ap2, ap);
    if (printf_core(0, fmt, &ap2, nl_arg, nl_type) < 0) {
        va_end(ap2);
        return -1;
    }

    ret = printf_core(out, fmt, &ap2, nl_arg, nl_type);
    va_end(ap2);
    return ret;
}

word_t kprintf(const char *format, ...)
{
    va_list args;
    word_t ret;

    out_wrap_t out = { kernel_out_fn, NULL, 0, -1 };

    va_start(args, format);
    ret = vprintf(&out, format, args);
    va_end(args);
    return ret;
}

word_t ksnprintf(char *str, word_t size, const char *format, ...)
{
    va_list args;
    word_t i;

    out_wrap_t out = { buf_out_fn, str, 0, size };

    va_start(args, format);
    i = vprintf(&out, format, args);
    va_end(args);

    // make sure there is space for a 0 byte
    if (i >= size) {
        i = size - 1;
    }
    str[i] = 0;

    return i;
}

#endif /* CONFIG_PRINTING */
#line 1 "/home/koc034/Documents/newver/seL4/src/machine/registerset.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <machine/registerset.h>

const register_t fault_messages[][MAX_MSG_SIZE] = {
    [MessageID_Syscall] = SYSCALL_MESSAGE,
    [MessageID_Exception] = EXCEPTION_MESSAGE,
#ifdef CONFIG_KERNEL_MCS
    [MessageID_TimeoutReply] = TIMEOUT_REPLY_MESSAGE,
#endif
};
#line 1 "/home/koc034/Documents/newver/seL4/src/model/preemption.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <api/failures.h>
#include <model/preemption.h>
#include <model/statedata.h>
#include <plat/machine/hardware.h>
#include <config.h>

/*
 * Possibly preempt the current thread to allow an interrupt to be handled.
 */
exception_t preemptionPoint(void)
{
    /* Record that we have performed some work. */
    ksWorkUnitsCompleted++;

    /*
     * If we have performed a non-trivial amount of work since last time we
     * checked for preemption, and there is an interrupt pending, handle the
     * interrupt.
     *
     * We avoid checking for pending IRQs every call, as our callers tend to
     * call us in a tight loop and checking for pending IRQs can be quite slow.
     */
    if (ksWorkUnitsCompleted >= CONFIG_MAX_NUM_WORK_UNITS_PER_PREEMPTION) {
        ksWorkUnitsCompleted = 0;
        if (isIRQPending()) {
            return EXCEPTION_PREEMPTED;
#ifdef CONFIG_KERNEL_MCS
        } else {
            updateTimestamp();
            if (!checkBudget()) {
                return EXCEPTION_PREEMPTED;
            }
#endif
        }
    }

    return EXCEPTION_NONE;
}

#line 1 "/home/koc034/Documents/newver/seL4/src/model/smp.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <model/smp.h>
#include <object/tcb.h>

#ifdef ENABLE_SMP_SUPPORT

void migrateTCB(tcb_t *tcb, word_t new_core)
{
#ifdef CONFIG_DEBUG_BUILD
    tcbDebugRemove(tcb);
#endif
    Arch_migrateTCB(tcb);
    tcb->tcbAffinity = new_core;
#ifdef CONFIG_DEBUG_BUILD
    tcbDebugAppend(tcb);
#endif
}

#endif /* ENABLE_SMP_SUPPORT */
#line 1 "/home/koc034/Documents/newver/seL4/src/model/statedata.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <api/debug.h>
#include <types.h>
#include <plat/machine.h>
#include <model/statedata.h>
#include <model/smp.h>
#include <object/structures.h>
#include <object/tcb.h>
#include <benchmark/benchmark_track.h>

/* Collective cpu states, including both pre core architecture dependant and independent data */
SMP_STATE_DEFINE(smpStatedata_t, ksSMP[CONFIG_MAX_NUM_NODES] ALIGN(L1_CACHE_LINE_SIZE));

/* Global count of how many cpus there are */
word_t ksNumCPUs;

/* Pointer to the head of the scheduler queue for each priority */
UP_STATE_DEFINE(tcb_queue_t, ksReadyQueues[NUM_READY_QUEUES]);
UP_STATE_DEFINE(word_t, ksReadyQueuesL1Bitmap[CONFIG_NUM_DOMAINS]);
UP_STATE_DEFINE(word_t, ksReadyQueuesL2Bitmap[CONFIG_NUM_DOMAINS][L2_BITMAP_SIZE]);
compile_assert(ksReadyQueuesL1BitmapBigEnough, (L2_BITMAP_SIZE - 1) <= wordBits)
#ifdef CONFIG_KERNEL_MCS
/* Head of the queue of threads waiting for their budget to be replenished */
UP_STATE_DEFINE(tcb_t *, ksReleaseHead);
#endif

/* Current thread TCB pointer */
UP_STATE_DEFINE(tcb_t *, ksCurThread);

/* Idle thread TCB pointer */
UP_STATE_DEFINE(tcb_t *, ksIdleThread);

/* Values of 0 and ~0 encode ResumeCurrentThread and ChooseNewThread
 * respectively; other values encode SwitchToThread and must be valid
 * tcb pointers */
UP_STATE_DEFINE(tcb_t *, ksSchedulerAction);

#ifdef CONFIG_HAVE_FPU
/* Currently active FPU state, or NULL if there is no active FPU state */
UP_STATE_DEFINE(user_fpu_state_t *, ksActiveFPUState);

UP_STATE_DEFINE(word_t, ksFPURestoresSinceSwitch);
#endif /* CONFIG_HAVE_FPU */
#ifdef CONFIG_KERNEL_MCS
/* the amount of time passed since the kernel time was last updated */
UP_STATE_DEFINE(ticks_t, ksConsumed);
/* whether we need to reprogram the timer before exiting the kernel */
UP_STATE_DEFINE(bool_t, ksReprogram);
/* the current kernel time (recorded on kernel entry) */
UP_STATE_DEFINE(ticks_t, ksCurTime);
/* current scheduling context pointer */
UP_STATE_DEFINE(sched_context_t *, ksCurSC);
#endif

#ifdef CONFIG_DEBUG_BUILD
UP_STATE_DEFINE(tcb_t *, ksDebugTCBs);
#endif /* CONFIG_DEBUG_BUILD */
#ifdef CONFIG_BENCHMARK_TRACK_UTILISATION
UP_STATE_DEFINE(bool_t, benchmark_log_utilisation_enabled);
UP_STATE_DEFINE(timestamp_t, benchmark_start_time);
UP_STATE_DEFINE(timestamp_t, benchmark_end_time);
UP_STATE_DEFINE(timestamp_t, benchmark_kernel_time);
UP_STATE_DEFINE(timestamp_t, benchmark_kernel_number_entries);
UP_STATE_DEFINE(timestamp_t, benchmark_kernel_number_schedules);
#endif /* CONFIG_BENCHMARK_TRACK_UTILISATION */

/* Units of work we have completed since the last time we checked for
 * pending interrupts */
word_t ksWorkUnitsCompleted;

irq_state_t intStateIRQTable[INT_STATE_ARRAY_SIZE];
/* CNode containing interrupt handler endpoints - like all seL4 objects, this CNode needs to be
 * of a size that is a power of 2 and aligned to its size. */
cte_t intStateIRQNode[BIT(IRQ_CNODE_SLOT_BITS)] ALIGN(BIT(IRQ_CNODE_SLOT_BITS + seL4_SlotBits));
compile_assert(irqCNodeSize, sizeof(intStateIRQNode) >= ((INT_STATE_ARRAY_SIZE) *sizeof(cte_t)));

/* Currently active domain */
dom_t ksCurDomain;

/* Domain timeslice remaining */
#ifdef CONFIG_KERNEL_MCS
ticks_t ksDomainTime;
#else
word_t ksDomainTime;
#endif

/* An index into ksDomSchedule for active domain and length. */
word_t ksDomScheduleIdx;

/* Only used by lockTLBEntry */
word_t tlbLockCount = 0;

/* Idle thread. */
SECTION("._idle_thread") char ksIdleThreadTCB[CONFIG_MAX_NUM_NODES][BIT(seL4_TCBBits)] ALIGN(BIT(TCB_SIZE_BITS));

#ifdef CONFIG_KERNEL_MCS
/* Idle thread Schedcontexts */
char ksIdleThreadSC[CONFIG_MAX_NUM_NODES][BIT(seL4_MinSchedContextBits)] ALIGN(BIT(seL4_MinSchedContextBits));
#endif

#if (defined CONFIG_DEBUG_BUILD || defined CONFIG_BENCHMARK_TRACK_KERNEL_ENTRIES)
kernel_entry_t ksKernelEntry;
#endif /* DEBUG */

#ifdef CONFIG_KERNEL_LOG_BUFFER
paddr_t ksUserLogBuffer;
#endif /* CONFIG_KERNEL_LOG_BUFFER */
#line 1 "/home/koc034/Documents/newver/seL4/src/object/cnode.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <types.h>
#include <api/failures.h>
#include <api/invocation.h>
#include <api/syscall.h>
#include <api/types.h>
#include <machine/io.h>
#include <object/structures.h>
#include <object/objecttype.h>
#include <object/cnode.h>
#include <object/interrupt.h>
#include <object/untyped.h>
#include <kernel/cspace.h>
#include <kernel/thread.h>
#include <model/preemption.h>
#include <model/statedata.h>
#include <util.h>

struct finaliseSlot_ret {
    exception_t status;
    bool_t success;
    cap_t cleanupInfo;
};
typedef struct finaliseSlot_ret finaliseSlot_ret_t;

static finaliseSlot_ret_t finaliseSlot(cte_t *slot, bool_t exposed);
static void emptySlot(cte_t *slot, cap_t cleanupInfo);
static exception_t reduceZombie(cte_t *slot, bool_t exposed);

#ifdef CONFIG_KERNEL_MCS
#define CNODE_LAST_INVOCATION CNodeRotate
#else
#define CNODE_LAST_INVOCATION CNodeSaveCaller
#endif

exception_t decodeCNodeInvocation(word_t invLabel, word_t length, cap_t cap,
                                  word_t *buffer)
{
    lookupSlot_ret_t lu_ret;
    cte_t *destSlot;
    word_t index, w_bits;
    exception_t status;

    /* Haskell error: "decodeCNodeInvocation: invalid cap" */
    assert(cap_get_capType(cap) == cap_cnode_cap);

    if (invLabel < CNodeRevoke || invLabel > CNODE_LAST_INVOCATION) {
        userError("CNodeCap: Illegal Operation attempted.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (length < 2) {
        userError("CNode operation: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }
    index = getSyscallArg(0, buffer);
    w_bits = getSyscallArg(1, buffer);

    lu_ret = lookupTargetSlot(cap, index, w_bits);
    if (lu_ret.status != EXCEPTION_NONE) {
        userError("CNode operation: Target slot invalid.");
        return lu_ret.status;
    }
    destSlot = lu_ret.slot;

    if (invLabel >= CNodeCopy && invLabel <= CNodeMutate) {
        cte_t *srcSlot;
        word_t srcIndex, srcDepth, capData;
        bool_t isMove;
        seL4_CapRights_t cap_rights;
        cap_t srcRoot, newCap;
        deriveCap_ret_t dc_ret;
        cap_t srcCap;

        if (length < 4 || current_extra_caps.excaprefs[0] == NULL) {
            userError("CNode Copy/Mint/Move/Mutate: Truncated message.");
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }
        srcIndex = getSyscallArg(2, buffer);
        srcDepth = getSyscallArg(3, buffer);

        srcRoot = current_extra_caps.excaprefs[0]->cap;

        status = ensureEmptySlot(destSlot);
        if (status != EXCEPTION_NONE) {
            userError("CNode Copy/Mint/Move/Mutate: Destination not empty.");
            return status;
        }

        lu_ret = lookupSourceSlot(srcRoot, srcIndex, srcDepth);
        if (lu_ret.status != EXCEPTION_NONE) {
            userError("CNode Copy/Mint/Move/Mutate: Invalid source slot.");
            return lu_ret.status;
        }
        srcSlot = lu_ret.slot;

        if (cap_get_capType(srcSlot->cap) == cap_null_cap) {
            userError("CNode Copy/Mint/Move/Mutate: Source slot invalid or empty.");
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 1;
            current_lookup_fault =
                lookup_fault_missing_capability_new(srcDepth);
            return EXCEPTION_SYSCALL_ERROR;
        }

        switch (invLabel) {
        case CNodeCopy:

            if (length < 5) {
                userError("Truncated message for CNode Copy operation.");
                current_syscall_error.type = seL4_TruncatedMessage;
                return EXCEPTION_SYSCALL_ERROR;
            }

            cap_rights = rightsFromWord(getSyscallArg(4, buffer));
            srcCap = maskCapRights(cap_rights, srcSlot->cap);
            dc_ret = deriveCap(srcSlot, srcCap);
            if (dc_ret.status != EXCEPTION_NONE) {
                userError("Error deriving cap for CNode Copy operation.");
                return dc_ret.status;
            }
            newCap = dc_ret.cap;
            isMove = false;

            break;

        case CNodeMint:
            if (length < 6) {
                userError("CNode Mint: Truncated message.");
                current_syscall_error.type = seL4_TruncatedMessage;
                return EXCEPTION_SYSCALL_ERROR;
            }

            cap_rights = rightsFromWord(getSyscallArg(4, buffer));
            capData = getSyscallArg(5, buffer);
            srcCap = maskCapRights(cap_rights, srcSlot->cap);
            dc_ret = deriveCap(srcSlot,
                               updateCapData(false, capData, srcCap));
            if (dc_ret.status != EXCEPTION_NONE) {
                userError("Error deriving cap for CNode Mint operation.");
                return dc_ret.status;
            }
            newCap = dc_ret.cap;
            isMove = false;

            break;

        case CNodeMove:
            newCap = srcSlot->cap;
            isMove = true;

            break;

        case CNodeMutate:
            if (length < 5) {
                userError("CNode Mutate: Truncated message.");
                current_syscall_error.type = seL4_TruncatedMessage;
                return EXCEPTION_SYSCALL_ERROR;
            }

            capData = getSyscallArg(4, buffer);
            newCap = updateCapData(true, capData, srcSlot->cap);
            isMove = true;

            break;

        default:
            assert(0);
            return EXCEPTION_NONE;
        }

        if (cap_get_capType(newCap) == cap_null_cap) {
            userError("CNode Copy/Mint/Move/Mutate: Mutated cap would be invalid.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        if (isMove) {
            return invokeCNodeMove(newCap, srcSlot, destSlot);
        } else {
            return invokeCNodeInsert(newCap, srcSlot, destSlot);
        }
    }

    if (invLabel == CNodeRevoke) {
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return invokeCNodeRevoke(destSlot);
    }

    if (invLabel == CNodeDelete) {
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return invokeCNodeDelete(destSlot);
    }

#ifndef CONFIG_KERNEL_MCS
    if (invLabel == CNodeSaveCaller) {
        status = ensureEmptySlot(destSlot);
        if (status != EXCEPTION_NONE) {
            userError("CNode SaveCaller: Destination slot not empty.");
            return status;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return invokeCNodeSaveCaller(destSlot);
    }
#endif

    if (invLabel == CNodeCancelBadgedSends) {
        cap_t destCap;

        destCap = destSlot->cap;

        if (!hasCancelSendRights(destCap)) {
            userError("CNode CancelBadgedSends: Target cap invalid.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return invokeCNodeCancelBadgedSends(destCap);
    }

    if (invLabel == CNodeRotate) {
        word_t pivotNewData, pivotIndex, pivotDepth;
        word_t srcNewData, srcIndex, srcDepth;
        cte_t *pivotSlot, *srcSlot;
        cap_t pivotRoot, srcRoot, newSrcCap, newPivotCap;

        if (length < 8 || current_extra_caps.excaprefs[0] == NULL
            || current_extra_caps.excaprefs[1] == NULL) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }
        pivotNewData = getSyscallArg(2, buffer);
        pivotIndex   = getSyscallArg(3, buffer);
        pivotDepth   = getSyscallArg(4, buffer);
        srcNewData   = getSyscallArg(5, buffer);
        srcIndex     = getSyscallArg(6, buffer);
        srcDepth     = getSyscallArg(7, buffer);

        pivotRoot = current_extra_caps.excaprefs[0]->cap;
        srcRoot   = current_extra_caps.excaprefs[1]->cap;

        lu_ret = lookupSourceSlot(srcRoot, srcIndex, srcDepth);
        if (lu_ret.status != EXCEPTION_NONE) {
            return lu_ret.status;
        }
        srcSlot = lu_ret.slot;

        lu_ret = lookupPivotSlot(pivotRoot, pivotIndex, pivotDepth);
        if (lu_ret.status != EXCEPTION_NONE) {
            return lu_ret.status;
        }
        pivotSlot = lu_ret.slot;

        if (pivotSlot == srcSlot || pivotSlot == destSlot) {
            userError("CNode Rotate: Pivot slot the same as source or dest slot.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (srcSlot != destSlot) {
            status = ensureEmptySlot(destSlot);
            if (status != EXCEPTION_NONE) {
                return status;
            }
        }

        if (cap_get_capType(srcSlot->cap) == cap_null_cap) {
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 1;
            current_lookup_fault = lookup_fault_missing_capability_new(srcDepth);
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (cap_get_capType(pivotSlot->cap) == cap_null_cap) {
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 0;
            current_lookup_fault = lookup_fault_missing_capability_new(pivotDepth);
            return EXCEPTION_SYSCALL_ERROR;
        }

        newSrcCap = updateCapData(true, srcNewData, srcSlot->cap);
        newPivotCap = updateCapData(true, pivotNewData, pivotSlot->cap);

        if (cap_get_capType(newSrcCap) == cap_null_cap) {
            userError("CNode Rotate: Source cap invalid.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (cap_get_capType(newPivotCap) == cap_null_cap) {
            userError("CNode Rotate: Pivot cap invalid.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return invokeCNodeRotate(newSrcCap, newPivotCap,
                                 srcSlot, pivotSlot, destSlot);
    }

    return EXCEPTION_NONE;
}

exception_t invokeCNodeRevoke(cte_t *destSlot)
{
    return cteRevoke(destSlot);
}

exception_t invokeCNodeDelete(cte_t *destSlot)
{
    return cteDelete(destSlot, true);
}

exception_t invokeCNodeCancelBadgedSends(cap_t cap)
{
    word_t badge = cap_endpoint_cap_get_capEPBadge(cap);
    if (badge) {
        endpoint_t *ep = (endpoint_t *)
                         cap_endpoint_cap_get_capEPPtr(cap);
        cancelBadgedSends(ep, badge);
    }
    return EXCEPTION_NONE;
}

exception_t invokeCNodeInsert(cap_t cap, cte_t *srcSlot, cte_t *destSlot)
{
    cteInsert(cap, srcSlot, destSlot);

    return EXCEPTION_NONE;
}

exception_t invokeCNodeMove(cap_t cap, cte_t *srcSlot, cte_t *destSlot)
{
    cteMove(cap, srcSlot, destSlot);

    return EXCEPTION_NONE;
}

exception_t invokeCNodeRotate(cap_t cap1, cap_t cap2, cte_t *slot1,
                              cte_t *slot2, cte_t *slot3)
{
    if (slot1 == slot3) {
        cteSwap(cap1, slot1, cap2, slot2);
    } else {
        cteMove(cap2, slot2, slot3);
        cteMove(cap1, slot1, slot2);
    }

    return EXCEPTION_NONE;
}

#ifndef CONFIG_KERNEL_MCS
exception_t invokeCNodeSaveCaller(cte_t *destSlot)
{
    cap_t cap;
    cte_t *srcSlot;

    srcSlot = TCB_PTR_CTE_PTR(NODE_STATE(ksCurThread), tcbCaller);
    cap = srcSlot->cap;

    switch (cap_get_capType(cap)) {
    case cap_null_cap:
        userError("CNode SaveCaller: Reply cap not present.");
        break;

    case cap_reply_cap:
        if (!cap_reply_cap_get_capReplyMaster(cap)) {
            cteMove(cap, srcSlot, destSlot);
        }
        break;

    default:
        fail("caller capability must be null or reply");
        break;
    }

    return EXCEPTION_NONE;
}
#endif

/*
 * If creating a child UntypedCap, don't allow new objects to be created in the
 * parent.
 */
static void setUntypedCapAsFull(cap_t srcCap, cap_t newCap, cte_t *srcSlot)
{
    if ((cap_get_capType(srcCap) == cap_untyped_cap)
        && (cap_get_capType(newCap) == cap_untyped_cap)) {
        if ((cap_untyped_cap_get_capPtr(srcCap)
             == cap_untyped_cap_get_capPtr(newCap))
            && (cap_untyped_cap_get_capBlockSize(newCap)
                == cap_untyped_cap_get_capBlockSize(srcCap))) {
            cap_untyped_cap_ptr_set_capFreeIndex(&(srcSlot->cap),
                                                 MAX_FREE_INDEX(cap_untyped_cap_get_capBlockSize(srcCap)));
        }
    }
}

void cteInsert(cap_t newCap, cte_t *srcSlot, cte_t *destSlot)
{
    mdb_node_t srcMDB, newMDB;
    cap_t srcCap;
    bool_t newCapIsRevocable;

    srcMDB = srcSlot->cteMDBNode;
    srcCap = srcSlot->cap;

    newCapIsRevocable = isCapRevocable(newCap, srcCap);

    newMDB = mdb_node_set_mdbPrev(srcMDB, CTE_REF(srcSlot));
    newMDB = mdb_node_set_mdbRevocable(newMDB, newCapIsRevocable);
    newMDB = mdb_node_set_mdbFirstBadged(newMDB, newCapIsRevocable);

    /* Haskell error: "cteInsert to non-empty destination" */
    assert(cap_get_capType(destSlot->cap) == cap_null_cap);
    /* Haskell error: "cteInsert: mdb entry must be empty" */
    assert((cte_t *)mdb_node_get_mdbNext(destSlot->cteMDBNode) == NULL &&
           (cte_t *)mdb_node_get_mdbPrev(destSlot->cteMDBNode) == NULL);

    /* Prevent parent untyped cap from being used again if creating a child
     * untyped from it. */
    setUntypedCapAsFull(srcCap, newCap, srcSlot);

    destSlot->cap = newCap;
    destSlot->cteMDBNode = newMDB;
    mdb_node_ptr_set_mdbNext(&srcSlot->cteMDBNode, CTE_REF(destSlot));
    if (mdb_node_get_mdbNext(newMDB)) {
        mdb_node_ptr_set_mdbPrev(
            &CTE_PTR(mdb_node_get_mdbNext(newMDB))->cteMDBNode,
            CTE_REF(destSlot));
    }
}

void cteMove(cap_t newCap, cte_t *srcSlot, cte_t *destSlot)
{
    mdb_node_t mdb;
    word_t prev_ptr, next_ptr;

    /* Haskell error: "cteMove to non-empty destination" */
    assert(cap_get_capType(destSlot->cap) == cap_null_cap);
    /* Haskell error: "cteMove: mdb entry must be empty" */
    assert((cte_t *)mdb_node_get_mdbNext(destSlot->cteMDBNode) == NULL &&
           (cte_t *)mdb_node_get_mdbPrev(destSlot->cteMDBNode) == NULL);

    mdb = srcSlot->cteMDBNode;
    destSlot->cap = newCap;
    srcSlot->cap = cap_null_cap_new();
    destSlot->cteMDBNode = mdb;
    srcSlot->cteMDBNode = nullMDBNode;

    prev_ptr = mdb_node_get_mdbPrev(mdb);
    if (prev_ptr)
        mdb_node_ptr_set_mdbNext(
            &CTE_PTR(prev_ptr)->cteMDBNode,
            CTE_REF(destSlot));

    next_ptr = mdb_node_get_mdbNext(mdb);
    if (next_ptr)
        mdb_node_ptr_set_mdbPrev(
            &CTE_PTR(next_ptr)->cteMDBNode,
            CTE_REF(destSlot));
}

void capSwapForDelete(cte_t *slot1, cte_t *slot2)
{
    cap_t cap1, cap2;

    if (slot1 == slot2) {
        return;
    }

    cap1 = slot1->cap;
    cap2 = slot2->cap;

    cteSwap(cap1, slot1, cap2, slot2);
}

void cteSwap(cap_t cap1, cte_t *slot1, cap_t cap2, cte_t *slot2)
{
    mdb_node_t mdb1, mdb2;
    word_t next_ptr, prev_ptr;

    slot1->cap = cap2;
    slot2->cap = cap1;

    mdb1 = slot1->cteMDBNode;

    prev_ptr = mdb_node_get_mdbPrev(mdb1);
    if (prev_ptr)
        mdb_node_ptr_set_mdbNext(
            &CTE_PTR(prev_ptr)->cteMDBNode,
            CTE_REF(slot2));

    next_ptr = mdb_node_get_mdbNext(mdb1);
    if (next_ptr)
        mdb_node_ptr_set_mdbPrev(
            &CTE_PTR(next_ptr)->cteMDBNode,
            CTE_REF(slot2));

    mdb2 = slot2->cteMDBNode;
    slot1->cteMDBNode = mdb2;
    slot2->cteMDBNode = mdb1;

    prev_ptr = mdb_node_get_mdbPrev(mdb2);
    if (prev_ptr)
        mdb_node_ptr_set_mdbNext(
            &CTE_PTR(prev_ptr)->cteMDBNode,
            CTE_REF(slot1));

    next_ptr = mdb_node_get_mdbNext(mdb2);
    if (next_ptr)
        mdb_node_ptr_set_mdbPrev(
            &CTE_PTR(next_ptr)->cteMDBNode,
            CTE_REF(slot1));
}

exception_t cteRevoke(cte_t *slot)
{
    cte_t *nextPtr;
    exception_t status;

    /* there is no need to check for a NullCap as NullCaps are
       always accompanied by null mdb pointers */
    for (nextPtr = CTE_PTR(mdb_node_get_mdbNext(slot->cteMDBNode));
         nextPtr && isMDBParentOf(slot, nextPtr);
         nextPtr = CTE_PTR(mdb_node_get_mdbNext(slot->cteMDBNode))) {
        status = cteDelete(nextPtr, true);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        status = preemptionPoint();
        if (status != EXCEPTION_NONE) {
            return status;
        }
    }

    return EXCEPTION_NONE;
}

exception_t cteDelete(cte_t *slot, bool_t exposed)
{
    finaliseSlot_ret_t fs_ret;

    fs_ret = finaliseSlot(slot, exposed);
    if (fs_ret.status != EXCEPTION_NONE) {
        return fs_ret.status;
    }

    if (exposed || fs_ret.success) {
        emptySlot(slot, fs_ret.cleanupInfo);
    }
    return EXCEPTION_NONE;
}

static void emptySlot(cte_t *slot, cap_t cleanupInfo)
{
    if (cap_get_capType(slot->cap) != cap_null_cap) {
        mdb_node_t mdbNode;
        cte_t *prev, *next;

        mdbNode = slot->cteMDBNode;
        prev = CTE_PTR(mdb_node_get_mdbPrev(mdbNode));
        next = CTE_PTR(mdb_node_get_mdbNext(mdbNode));

        if (prev) {
            mdb_node_ptr_set_mdbNext(&prev->cteMDBNode, CTE_REF(next));
        }
        if (next) {
            mdb_node_ptr_set_mdbPrev(&next->cteMDBNode, CTE_REF(prev));
        }
        if (next)
            mdb_node_ptr_set_mdbFirstBadged(&next->cteMDBNode,
                                            mdb_node_get_mdbFirstBadged(next->cteMDBNode) ||
                                            mdb_node_get_mdbFirstBadged(mdbNode));
        slot->cap = cap_null_cap_new();
        slot->cteMDBNode = nullMDBNode;

        postCapDeletion(cleanupInfo);
    }
}

static inline bool_t CONST capRemovable(cap_t cap, cte_t *slot)
{
    switch (cap_get_capType(cap)) {
    case cap_null_cap:
        return true;
    case cap_zombie_cap: {
        word_t n = cap_zombie_cap_get_capZombieNumber(cap);
        cte_t *z_slot = (cte_t *)cap_zombie_cap_get_capZombiePtr(cap);
        return (n == 0 || (n == 1 && slot == z_slot));
    }
    default:
        fail("finaliseCap should only return Zombie or NullCap");
    }
}

static inline bool_t CONST capCyclicZombie(cap_t cap, cte_t *slot)
{
    return cap_get_capType(cap) == cap_zombie_cap &&
           CTE_PTR(cap_zombie_cap_get_capZombiePtr(cap)) == slot;
}

static finaliseSlot_ret_t finaliseSlot(cte_t *slot, bool_t immediate)
{
    bool_t final;
    finaliseCap_ret_t fc_ret;
    exception_t status;
    finaliseSlot_ret_t ret;

    while (cap_get_capType(slot->cap) != cap_null_cap) {
        final = isFinalCapability(slot);
        fc_ret = finaliseCap(slot->cap, final, false);

        if (capRemovable(fc_ret.remainder, slot)) {
            ret.status = EXCEPTION_NONE;
            ret.success = true;
            ret.cleanupInfo = fc_ret.cleanupInfo;
            return ret;
        }

        slot->cap = fc_ret.remainder;

        if (!immediate && capCyclicZombie(fc_ret.remainder, slot)) {
            ret.status = EXCEPTION_NONE;
            ret.success = false;
            ret.cleanupInfo = fc_ret.cleanupInfo;
            return ret;
        }

        status = reduceZombie(slot, immediate);
        if (status != EXCEPTION_NONE) {
            ret.status = status;
            ret.success = false;
            ret.cleanupInfo = cap_null_cap_new();
            return ret;
        }

        status = preemptionPoint();
        if (status != EXCEPTION_NONE) {
            ret.status = status;
            ret.success = false;
            ret.cleanupInfo = cap_null_cap_new();
            return ret;
        }
    }
    ret.status = EXCEPTION_NONE;
    ret.success = true;
    ret.cleanupInfo = cap_null_cap_new();
    return ret;
}

static exception_t reduceZombie(cte_t *slot, bool_t immediate)
{
    cte_t *ptr;
    word_t n, type;
    exception_t status;

    assert(cap_get_capType(slot->cap) == cap_zombie_cap);
    ptr = (cte_t *)cap_zombie_cap_get_capZombiePtr(slot->cap);
    n = cap_zombie_cap_get_capZombieNumber(slot->cap);
    type = cap_zombie_cap_get_capZombieType(slot->cap);

    /* Haskell error: "reduceZombie: expected unremovable zombie" */
    assert(n > 0);

    if (immediate) {
        cte_t *endSlot = &ptr[n - 1];

        status = cteDelete(endSlot, false);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        switch (cap_get_capType(slot->cap)) {
        case cap_null_cap:
            break;

        case cap_zombie_cap: {
            cte_t *ptr2 =
                (cte_t *)cap_zombie_cap_get_capZombiePtr(slot->cap);

            if (ptr == ptr2 &&
                cap_zombie_cap_get_capZombieNumber(slot->cap) == n &&
                cap_zombie_cap_get_capZombieType(slot->cap) == type) {
                assert(cap_get_capType(endSlot->cap) == cap_null_cap);
                slot->cap =
                    cap_zombie_cap_set_capZombieNumber(slot->cap, n - 1);
            } else {
                /* Haskell error:
                 * "Expected new Zombie to be self-referential."
                 */
                assert(ptr2 == slot && ptr != slot);
            }
            break;
        }

        default:
            fail("Expected recursion to result in Zombie.");
        }
    } else {
        /* Haskell error: "Cyclic zombie passed to unexposed reduceZombie" */
        assert(ptr != slot);

        if (cap_get_capType(ptr->cap) == cap_zombie_cap) {
            /* Haskell error: "Moving self-referential Zombie aside." */
            assert(ptr != CTE_PTR(cap_zombie_cap_get_capZombiePtr(ptr->cap)));
        }

        capSwapForDelete(ptr, slot);
    }
    return EXCEPTION_NONE;
}

void cteDeleteOne(cte_t *slot)
{
    word_t cap_type = cap_get_capType(slot->cap);
    if (cap_type != cap_null_cap) {
        bool_t final;
        finaliseCap_ret_t fc_ret UNUSED;

        /** GHOSTUPD: "(gs_get_assn cteDeleteOne_'proc \<acute>ghost'state = (-1)
            \<or> gs_get_assn cteDeleteOne_'proc \<acute>ghost'state = \<acute>cap_type, id)" */

        final = isFinalCapability(slot);
        fc_ret = finaliseCap(slot->cap, final, true);
        /* Haskell error: "cteDeleteOne: cap should be removable" */
        assert(capRemovable(fc_ret.remainder, slot) &&
               cap_get_capType(fc_ret.cleanupInfo) == cap_null_cap);
        emptySlot(slot, cap_null_cap_new());
    }
}

void insertNewCap(cte_t *parent, cte_t *slot, cap_t cap)
{
    cte_t *next;

    next = CTE_PTR(mdb_node_get_mdbNext(parent->cteMDBNode));
    slot->cap = cap;
    slot->cteMDBNode = mdb_node_new(CTE_REF(next), true, true, CTE_REF(parent));
    if (next) {
        mdb_node_ptr_set_mdbPrev(&next->cteMDBNode, CTE_REF(slot));
    }
    mdb_node_ptr_set_mdbNext(&parent->cteMDBNode, CTE_REF(slot));
}

#ifndef CONFIG_KERNEL_MCS
void setupReplyMaster(tcb_t *thread)
{
    cte_t *slot;

    slot = TCB_PTR_CTE_PTR(thread, tcbReply);
    if (cap_get_capType(slot->cap) == cap_null_cap) {
        /* Haskell asserts that no reply caps exist for this thread here. This
         * cannot be translated. */
        slot->cap = cap_reply_cap_new(true, true, TCB_REF(thread));
        slot->cteMDBNode = nullMDBNode;
        mdb_node_ptr_set_mdbRevocable(&slot->cteMDBNode, true);
        mdb_node_ptr_set_mdbFirstBadged(&slot->cteMDBNode, true);
    }
}
#endif

bool_t PURE isMDBParentOf(cte_t *cte_a, cte_t *cte_b)
{
    if (!mdb_node_get_mdbRevocable(cte_a->cteMDBNode)) {
        return false;
    }
    if (!sameRegionAs(cte_a->cap, cte_b->cap)) {
        return false;
    }
    switch (cap_get_capType(cte_a->cap)) {
    case cap_endpoint_cap: {
        word_t badge;

        badge = cap_endpoint_cap_get_capEPBadge(cte_a->cap);
        if (badge == 0) {
            return true;
        }
        return (badge == cap_endpoint_cap_get_capEPBadge(cte_b->cap)) &&
               !mdb_node_get_mdbFirstBadged(cte_b->cteMDBNode);
        break;
    }

    case cap_notification_cap: {
        word_t badge;

        badge = cap_notification_cap_get_capNtfnBadge(cte_a->cap);
        if (badge == 0) {
            return true;
        }
        return
            (badge == cap_notification_cap_get_capNtfnBadge(cte_b->cap)) &&
            !mdb_node_get_mdbFirstBadged(cte_b->cteMDBNode);
        break;
    }

    default:
        return true;
        break;
    }
}

exception_t ensureNoChildren(cte_t *slot)
{
    if (mdb_node_get_mdbNext(slot->cteMDBNode) != 0) {
        cte_t *next;

        next = CTE_PTR(mdb_node_get_mdbNext(slot->cteMDBNode));
        if (isMDBParentOf(slot, next)) {
            current_syscall_error.type = seL4_RevokeFirst;
            return EXCEPTION_SYSCALL_ERROR;
        }
    }

    return EXCEPTION_NONE;
}

exception_t ensureEmptySlot(cte_t *slot)
{
    if (cap_get_capType(slot->cap) != cap_null_cap) {
        current_syscall_error.type = seL4_DeleteFirst;
        return EXCEPTION_SYSCALL_ERROR;
    }

    return EXCEPTION_NONE;
}

bool_t PURE isFinalCapability(cte_t *cte)
{
    mdb_node_t mdb;
    bool_t prevIsSameObject;

    mdb = cte->cteMDBNode;

    if (mdb_node_get_mdbPrev(mdb) == 0) {
        prevIsSameObject = false;
    } else {
        cte_t *prev;

        prev = CTE_PTR(mdb_node_get_mdbPrev(mdb));
        prevIsSameObject = sameObjectAs(prev->cap, cte->cap);
    }

    if (prevIsSameObject) {
        return false;
    } else {
        if (mdb_node_get_mdbNext(mdb) == 0) {
            return true;
        } else {
            cte_t *next;

            next = CTE_PTR(mdb_node_get_mdbNext(mdb));
            return !sameObjectAs(cte->cap, next->cap);
        }
    }
}

bool_t PURE slotCapLongRunningDelete(cte_t *slot)
{
    if (cap_get_capType(slot->cap) == cap_null_cap) {
        return false;
    } else if (! isFinalCapability(slot)) {
        return false;
    }
    switch (cap_get_capType(slot->cap)) {
    case cap_thread_cap:
    case cap_zombie_cap:
    case cap_cnode_cap:
        return true;
    default:
        return false;
    }
}

/* This implementation is specialised to the (current) limit
 * of one cap receive slot. */
cte_t *getReceiveSlots(tcb_t *thread, word_t *buffer)
{
    cap_transfer_t ct;
    cptr_t cptr;
    lookupCap_ret_t luc_ret;
    lookupSlot_ret_t lus_ret;
    cte_t *slot;
    cap_t cnode;

    if (!buffer) {
        return NULL;
    }

    ct = loadCapTransfer(buffer);
    cptr = ct.ctReceiveRoot;

    luc_ret = lookupCap(thread, cptr);
    if (luc_ret.status != EXCEPTION_NONE) {
        return NULL;
    }
    cnode = luc_ret.cap;

    lus_ret = lookupTargetSlot(cnode, ct.ctReceiveIndex, ct.ctReceiveDepth);
    if (lus_ret.status != EXCEPTION_NONE) {
        return NULL;
    }
    slot = lus_ret.slot;

    if (cap_get_capType(slot->cap) != cap_null_cap) {
        return NULL;
    }

    return slot;
}

cap_transfer_t PURE loadCapTransfer(word_t *buffer)
{
    const int offset = seL4_MsgMaxLength + seL4_MsgMaxExtraCaps + 2;
    return capTransferFromWords(buffer + offset);
}
#line 1 "/home/koc034/Documents/newver/seL4/src/object/endpoint.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <types.h>
#include <string.h>
#include <sel4/constants.h>
#include <kernel/thread.h>
#include <kernel/vspace.h>
#include <machine/registerset.h>
#include <model/statedata.h>
#include <object/notification.h>
#include <object/cnode.h>
#include <object/endpoint.h>
#include <object/tcb.h>

static inline void ep_ptr_set_queue(endpoint_t *epptr, tcb_queue_t queue)
{
    endpoint_ptr_set_epQueue_head(epptr, (word_t)queue.head);
    endpoint_ptr_set_epQueue_tail(epptr, (word_t)queue.end);
}

#ifdef CONFIG_KERNEL_MCS
void sendIPC(bool_t blocking, bool_t do_call, word_t badge,
             bool_t canGrant, bool_t canGrantReply, bool_t canDonate, tcb_t *thread, endpoint_t *epptr)
#else
void sendIPC(bool_t blocking, bool_t do_call, word_t badge,
             bool_t canGrant, bool_t canGrantReply, tcb_t *thread, endpoint_t *epptr)
#endif
{
    switch (endpoint_ptr_get_state(epptr)) {
    case EPState_Idle:
    case EPState_Send:
        if (blocking) {
            tcb_queue_t queue;

            /* Set thread state to BlockedOnSend */
            thread_state_ptr_set_tsType(&thread->tcbState,
                                        ThreadState_BlockedOnSend);
            thread_state_ptr_set_blockingObject(
                &thread->tcbState, EP_REF(epptr));
            thread_state_ptr_set_blockingIPCBadge(
                &thread->tcbState, badge);
            thread_state_ptr_set_blockingIPCCanGrant(
                &thread->tcbState, canGrant);
            thread_state_ptr_set_blockingIPCCanGrantReply(
                &thread->tcbState, canGrantReply);
            thread_state_ptr_set_blockingIPCIsCall(
                &thread->tcbState, do_call);

            scheduleTCB(thread);

            /* Place calling thread in endpoint queue */
            queue = ep_ptr_get_queue(epptr);
            queue = tcbEPAppend(thread, queue);
            endpoint_ptr_set_state(epptr, EPState_Send);
            ep_ptr_set_queue(epptr, queue);
        }
        break;

    case EPState_Recv: {
        tcb_queue_t queue;
        tcb_t *dest;

        /* Get the head of the endpoint queue. */
        queue = ep_ptr_get_queue(epptr);
        dest = queue.head;

        /* Haskell error "Receive endpoint queue must not be empty" */
        assert(dest);

        /* Dequeue the first TCB */
        queue = tcbEPDequeue(dest, queue);
        ep_ptr_set_queue(epptr, queue);

        if (!queue.head) {
            endpoint_ptr_set_state(epptr, EPState_Idle);
        }

        /* Do the transfer */
        doIPCTransfer(thread, epptr, badge, canGrant, dest);

#ifdef CONFIG_KERNEL_MCS
        reply_t *reply = REPLY_PTR(thread_state_get_replyObject(dest->tcbState));
        if (reply) {
            reply_unlink(reply, dest);
        }

        if (do_call ||
            seL4_Fault_ptr_get_seL4_FaultType(&thread->tcbFault) != seL4_Fault_NullFault) {
            if (reply != NULL && (canGrant || canGrantReply)) {
                reply_push(thread, dest, reply, canDonate);
            } else {
                setThreadState(thread, ThreadState_Inactive);
            }
        } else if (canDonate && dest->tcbSchedContext == NULL) {
            schedContext_donate(thread->tcbSchedContext, dest);
        }

        /* blocked threads should have enough budget to get out of the kernel */
        assert(dest->tcbSchedContext == NULL || refill_sufficient(dest->tcbSchedContext, 0));
        assert(dest->tcbSchedContext == NULL || refill_ready(dest->tcbSchedContext));
        setThreadState(dest, ThreadState_Running);
        possibleSwitchTo(dest);
#else
        bool_t replyCanGrant = thread_state_ptr_get_blockingIPCCanGrant(&dest->tcbState);;

        setThreadState(dest, ThreadState_Running);
        possibleSwitchTo(dest);

        if (do_call) {
            if (canGrant || canGrantReply) {
                setupCallerCap(thread, dest, replyCanGrant);
            } else {
                setThreadState(thread, ThreadState_Inactive);
            }
        }
#endif
        break;
    }
    }
}

#ifdef CONFIG_KERNEL_MCS
void receiveIPC(tcb_t *thread, cap_t cap, bool_t isBlocking, cap_t replyCap)
#else
void receiveIPC(tcb_t *thread, cap_t cap, bool_t isBlocking)
#endif
{
    endpoint_t *epptr;
    notification_t *ntfnPtr;

    /* Haskell error "receiveIPC: invalid cap" */
    assert(cap_get_capType(cap) == cap_endpoint_cap);

    epptr = EP_PTR(cap_endpoint_cap_get_capEPPtr(cap));

#ifdef CONFIG_KERNEL_MCS
    reply_t *replyPtr = NULL;
    if (cap_get_capType(replyCap) == cap_reply_cap) {
        replyPtr = REPLY_PTR(cap_reply_cap_get_capReplyPtr(replyCap));
        if (unlikely(replyPtr->replyTCB != NULL && replyPtr->replyTCB != thread)) {
            userError("Reply object already has unexecuted reply!");
            cancelIPC(replyPtr->replyTCB);
        }
    }
#endif

    /* Check for anything waiting in the notification */
    ntfnPtr = thread->tcbBoundNotification;
    if (ntfnPtr && notification_ptr_get_state(ntfnPtr) == NtfnState_Active) {
        completeSignal(ntfnPtr, thread);
    } else {
#ifdef CONFIG_KERNEL_MCS
        /* If this is a blocking recv and we didn't have a pending notification,
         * then if we are running on an SC from a bound notification, then we
         * need to return it so that we can passively wait on the EP for potentially
         * SC donations from client threads.
         */
        if (ntfnPtr && isBlocking) {
            maybeReturnSchedContext(ntfnPtr, thread);
        }
#endif
        switch (endpoint_ptr_get_state(epptr)) {
        case EPState_Idle:
        case EPState_Recv: {
            tcb_queue_t queue;

            if (isBlocking) {
                /* Set thread state to BlockedOnReceive */
                thread_state_ptr_set_tsType(&thread->tcbState,
                                            ThreadState_BlockedOnReceive);
                thread_state_ptr_set_blockingObject(
                    &thread->tcbState, EP_REF(epptr));
#ifdef CONFIG_KERNEL_MCS
                thread_state_ptr_set_replyObject(&thread->tcbState, REPLY_REF(replyPtr));
                if (replyPtr) {
                    replyPtr->replyTCB = thread;
                }
#else
                thread_state_ptr_set_blockingIPCCanGrant(
                    &thread->tcbState, cap_endpoint_cap_get_capCanGrant(cap));
#endif
                scheduleTCB(thread);

                /* Place calling thread in endpoint queue */
                queue = ep_ptr_get_queue(epptr);
                queue = tcbEPAppend(thread, queue);
                endpoint_ptr_set_state(epptr, EPState_Recv);
                ep_ptr_set_queue(epptr, queue);
            } else {
                doNBRecvFailedTransfer(thread);
            }
            break;
        }

        case EPState_Send: {
            tcb_queue_t queue;
            tcb_t *sender;
            word_t badge;
            bool_t canGrant;
            bool_t canGrantReply;
            bool_t do_call;

            /* Get the head of the endpoint queue. */
            queue = ep_ptr_get_queue(epptr);
            sender = queue.head;

            /* Haskell error "Send endpoint queue must not be empty" */
            assert(sender);

            /* Dequeue the first TCB */
            queue = tcbEPDequeue(sender, queue);
            ep_ptr_set_queue(epptr, queue);

            if (!queue.head) {
                endpoint_ptr_set_state(epptr, EPState_Idle);
            }

            /* Get sender IPC details */
            badge = thread_state_ptr_get_blockingIPCBadge(&sender->tcbState);
            canGrant =
                thread_state_ptr_get_blockingIPCCanGrant(&sender->tcbState);
            canGrantReply =
                thread_state_ptr_get_blockingIPCCanGrantReply(&sender->tcbState);

            /* Do the transfer */
            doIPCTransfer(sender, epptr, badge,
                          canGrant, thread);

            do_call = thread_state_ptr_get_blockingIPCIsCall(&sender->tcbState);

#ifdef CONFIG_KERNEL_MCS
            if (do_call ||
                seL4_Fault_get_seL4_FaultType(sender->tcbFault) != seL4_Fault_NullFault) {
                if ((canGrant || canGrantReply) && replyPtr != NULL) {
                    bool_t canDonate = sender->tcbSchedContext != NULL
                                       && seL4_Fault_get_seL4_FaultType(sender->tcbFault) != seL4_Fault_Timeout;
                    reply_push(sender, thread, replyPtr, canDonate);
                } else {
                    setThreadState(sender, ThreadState_Inactive);
                }
            } else {
                setThreadState(sender, ThreadState_Running);
                possibleSwitchTo(sender);
                assert(sender->tcbSchedContext == NULL || refill_sufficient(sender->tcbSchedContext, 0));
            }
#else
            if (do_call) {
                if (canGrant || canGrantReply) {
                    setupCallerCap(sender, thread, cap_endpoint_cap_get_capCanGrant(cap));
                } else {
                    setThreadState(sender, ThreadState_Inactive);
                }
            } else {
                setThreadState(sender, ThreadState_Running);
                possibleSwitchTo(sender);
            }
#endif
            break;
        }
        }
    }
}

void replyFromKernel_error(tcb_t *thread)
{
    word_t len;
    word_t *ipcBuffer;

    ipcBuffer = lookupIPCBuffer(true, thread);
    setRegister(thread, badgeRegister, 0);
    len = setMRs_syscall_error(thread, ipcBuffer);

#ifdef CONFIG_KERNEL_INVOCATION_REPORT_ERROR_IPC
    char *debugBuffer = (char *)(ipcBuffer + DEBUG_MESSAGE_START + 1);
    word_t add = strlcpy(debugBuffer, (char *)current_debug_error.errorMessage,
                         DEBUG_MESSAGE_MAXLEN * sizeof(word_t));

    len += (add / sizeof(word_t)) + 1;
#endif

    setRegister(thread, msgInfoRegister, wordFromMessageInfo(
                    seL4_MessageInfo_new(current_syscall_error.type, 0, 0, len)));
}

void replyFromKernel_success_empty(tcb_t *thread)
{
    setRegister(thread, badgeRegister, 0);
    setRegister(thread, msgInfoRegister, wordFromMessageInfo(
                    seL4_MessageInfo_new(0, 0, 0, 0)));
}

void cancelIPC(tcb_t *tptr)
{
    thread_state_t *state = &tptr->tcbState;

#ifdef CONFIG_KERNEL_MCS
    /* cancel ipc cancels all faults */
    seL4_Fault_NullFault_ptr_new(&tptr->tcbFault);
#endif

    switch (thread_state_ptr_get_tsType(state)) {
    case ThreadState_BlockedOnSend:
    case ThreadState_BlockedOnReceive: {
        /* blockedIPCCancel state */
        endpoint_t *epptr;
        tcb_queue_t queue;

        epptr = EP_PTR(thread_state_ptr_get_blockingObject(state));

        /* Haskell error "blockedIPCCancel: endpoint must not be idle" */
        assert(endpoint_ptr_get_state(epptr) != EPState_Idle);

        /* Dequeue TCB */
        queue = ep_ptr_get_queue(epptr);
        queue = tcbEPDequeue(tptr, queue);
        ep_ptr_set_queue(epptr, queue);

        if (!queue.head) {
            endpoint_ptr_set_state(epptr, EPState_Idle);
        }

#ifdef CONFIG_KERNEL_MCS
        reply_t *reply = REPLY_PTR(thread_state_get_replyObject(tptr->tcbState));
        if (reply != NULL) {
            reply_unlink(reply, tptr);
        }
#endif
        setThreadState(tptr, ThreadState_Inactive);
        break;
    }

    case ThreadState_BlockedOnNotification:
        cancelSignal(tptr,
                     NTFN_PTR(thread_state_ptr_get_blockingObject(state)));
        break;

    case ThreadState_BlockedOnReply: {
#ifdef CONFIG_KERNEL_MCS
        reply_remove_tcb(tptr);
#else
        cte_t *slot, *callerCap;

        tptr->tcbFault = seL4_Fault_NullFault_new();

        /* Get the reply cap slot */
        slot = TCB_PTR_CTE_PTR(tptr, tcbReply);

        callerCap = CTE_PTR(mdb_node_get_mdbNext(slot->cteMDBNode));
        if (callerCap) {
            /** GHOSTUPD: "(True,
                gs_set_assn cteDeleteOne_'proc (ucast cap_reply_cap))" */
            cteDeleteOne(callerCap);
        }
#endif

        break;
    }
    }
}

void cancelAllIPC(endpoint_t *epptr)
{
    switch (endpoint_ptr_get_state(epptr)) {
    case EPState_Idle:
        break;

    default: {
        tcb_t *thread = TCB_PTR(endpoint_ptr_get_epQueue_head(epptr));

        /* Make endpoint idle */
        endpoint_ptr_set_state(epptr, EPState_Idle);
        endpoint_ptr_set_epQueue_head(epptr, 0);
        endpoint_ptr_set_epQueue_tail(epptr, 0);

        /* Set all blocked threads to restart */
        for (; thread; thread = thread->tcbEPNext) {
#ifdef CONFIG_KERNEL_MCS
            reply_t *reply = REPLY_PTR(thread_state_get_replyObject(thread->tcbState));
            if (reply != NULL) {
                reply_unlink(reply, thread);
            }
            if (seL4_Fault_get_seL4_FaultType(thread->tcbFault) == seL4_Fault_NullFault) {
                setThreadState(thread, ThreadState_Restart);
                possibleSwitchTo(thread);
            } else {
                setThreadState(thread, ThreadState_Inactive);
            }
#else
            setThreadState(thread, ThreadState_Restart);
            SCHED_ENQUEUE(thread);
#endif
        }

        rescheduleRequired();
        break;
    }
    }
}

void cancelBadgedSends(endpoint_t *epptr, word_t badge)
{
    switch (endpoint_ptr_get_state(epptr)) {
    case EPState_Idle:
    case EPState_Recv:
        break;

    case EPState_Send: {
        tcb_t *thread, *next;
        tcb_queue_t queue = ep_ptr_get_queue(epptr);

        /* this is a de-optimisation for verification
         * reasons. it allows the contents of the endpoint
         * queue to be ignored during the for loop. */
        endpoint_ptr_set_state(epptr, EPState_Idle);
        endpoint_ptr_set_epQueue_head(epptr, 0);
        endpoint_ptr_set_epQueue_tail(epptr, 0);

        for (thread = queue.head; thread; thread = next) {
            word_t b = thread_state_ptr_get_blockingIPCBadge(
                           &thread->tcbState);
            next = thread->tcbEPNext;
#ifdef CONFIG_KERNEL_MCS
            /* senders do not have reply objects in their state, and we are only cancelling sends */
            assert(REPLY_PTR(thread_state_get_replyObject(thread->tcbState)) == NULL);
            if (b == badge) {
                if (seL4_Fault_get_seL4_FaultType(thread->tcbFault) ==
                    seL4_Fault_NullFault) {
                    setThreadState(thread, ThreadState_Restart);
                    possibleSwitchTo(thread);
                } else {
                    setThreadState(thread, ThreadState_Inactive);
                }
                queue = tcbEPDequeue(thread, queue);
            }
#else
            if (b == badge) {
                setThreadState(thread, ThreadState_Restart);
                SCHED_ENQUEUE(thread);
                queue = tcbEPDequeue(thread, queue);
            }
#endif
        }
        ep_ptr_set_queue(epptr, queue);

        if (queue.head) {
            endpoint_ptr_set_state(epptr, EPState_Send);
        }

        rescheduleRequired();

        break;
    }

    default:
        fail("invalid EP state");
    }
}

#ifdef CONFIG_KERNEL_MCS
void reorderEP(endpoint_t *epptr, tcb_t *thread)
{
    tcb_queue_t queue = ep_ptr_get_queue(epptr);
    queue = tcbEPDequeue(thread, queue);
    queue = tcbEPAppend(thread, queue);
    ep_ptr_set_queue(epptr, queue);
}
#endif
#line 1 "/home/koc034/Documents/newver/seL4/src/object/interrupt.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <types.h>
#include <api/failures.h>
#include <api/invocation.h>
#include <api/syscall.h>
#include <machine/io.h>
#include <object/structures.h>
#include <object/interrupt.h>
#include <object/cnode.h>
#include <object/notification.h>
#include <kernel/cspace.h>
#include <kernel/thread.h>
#include <model/statedata.h>
#include <machine/timer.h>
#include <smp/ipi.h>

exception_t decodeIRQControlInvocation(word_t invLabel, word_t length,
                                       cte_t *srcSlot, word_t *buffer)
{
    if (invLabel == IRQIssueIRQHandler) {
        word_t index, depth, irq_w;
        irq_t irq;
        cte_t *destSlot;
        cap_t cnodeCap;
        lookupSlot_ret_t lu_ret;
        exception_t status;

        if (length < 3 || current_extra_caps.excaprefs[0] == NULL) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }
        irq_w = getSyscallArg(0, buffer);
        irq = CORE_IRQ_TO_IRQT(0, irq_w);
        index = getSyscallArg(1, buffer);
        depth = getSyscallArg(2, buffer);

        cnodeCap = current_extra_caps.excaprefs[0]->cap;

        status = Arch_checkIRQ(irq_w);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        if (isIRQActive(irq)) {
            current_syscall_error.type = seL4_RevokeFirst;
            userError("Rejecting request for IRQ %u. Already active.", (int)IRQT_TO_IRQ(irq));
            return EXCEPTION_SYSCALL_ERROR;
        }

        lu_ret = lookupTargetSlot(cnodeCap, index, depth);
        if (lu_ret.status != EXCEPTION_NONE) {
            userError("Target slot for new IRQ Handler cap invalid: cap %lu, IRQ %u.",
                      getExtraCPtr(buffer, 0), (int)IRQT_TO_IRQ(irq));
            return lu_ret.status;
        }
        destSlot = lu_ret.slot;

        status = ensureEmptySlot(destSlot);
        if (status != EXCEPTION_NONE) {
            userError("Target slot for new IRQ Handler cap not empty: cap %lu, IRQ %u.",
                      getExtraCPtr(buffer, 0), (int)IRQT_TO_IRQ(irq));
            return status;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return invokeIRQControl(irq, destSlot, srcSlot);
    } else {
        return Arch_decodeIRQControlInvocation(invLabel, length, srcSlot, buffer);
    }
}

exception_t invokeIRQControl(irq_t irq, cte_t *handlerSlot, cte_t *controlSlot)
{
    setIRQState(IRQSignal, irq);
    cteInsert(cap_irq_handler_cap_new(IRQT_TO_IDX(irq)), controlSlot, handlerSlot);

    return EXCEPTION_NONE;
}

exception_t decodeIRQHandlerInvocation(word_t invLabel, irq_t irq)
{
    switch (invLabel) {
    case IRQAckIRQ:
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        invokeIRQHandler_AckIRQ(irq);
        return EXCEPTION_NONE;

    case IRQSetIRQHandler: {
        cap_t ntfnCap;
        cte_t *slot;

        if (current_extra_caps.excaprefs[0] == NULL) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }
        ntfnCap = current_extra_caps.excaprefs[0]->cap;
        slot = current_extra_caps.excaprefs[0];

        if (cap_get_capType(ntfnCap) != cap_notification_cap ||
            !cap_notification_cap_get_capNtfnCanSend(ntfnCap)) {
            if (cap_get_capType(ntfnCap) != cap_notification_cap) {
                userError("IRQSetHandler: provided cap is not an notification capability.");
            } else {
                userError("IRQSetHandler: caller does not have send rights on the endpoint.");
            }
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        invokeIRQHandler_SetIRQHandler(irq, ntfnCap, slot);
        return EXCEPTION_NONE;
    }

    case IRQClearIRQHandler:
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        invokeIRQHandler_ClearIRQHandler(irq);
        return EXCEPTION_NONE;

    default:
        userError("IRQHandler: Illegal operation.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }
}

void invokeIRQHandler_AckIRQ(irq_t irq)
{
#ifdef CONFIG_ARCH_RISCV
    plic_complete_claim(irq);
#else
#if defined ENABLE_SMP_SUPPORT && defined CONFIG_ARCH_ARM
    if (IRQ_IS_PPI(irq) && IRQT_TO_CORE(irq) != getCurrentCPUIndex()) {
        doRemoteMaskPrivateInterrupt(IRQT_TO_CORE(irq), false, IRQT_TO_IDX(irq));
        return;
    }
#endif
    maskInterrupt(false, irq);
#endif
}

void invokeIRQHandler_SetIRQHandler(irq_t irq, cap_t cap, cte_t *slot)
{
    cte_t *irqSlot;

    irqSlot = intStateIRQNode + IRQT_TO_IDX(irq);
    /** GHOSTUPD: "(True, gs_set_assn cteDeleteOne_'proc (-1))" */
    cteDeleteOne(irqSlot);
    cteInsert(cap, slot, irqSlot);
}

void invokeIRQHandler_ClearIRQHandler(irq_t irq)
{
    cte_t *irqSlot;

    irqSlot = intStateIRQNode + IRQT_TO_IDX(irq);
    /** GHOSTUPD: "(True, gs_set_assn cteDeleteOne_'proc (-1))" */
    cteDeleteOne(irqSlot);
}

void deletingIRQHandler(irq_t irq)
{
    cte_t *slot;

    slot = intStateIRQNode + IRQT_TO_IDX(irq);
    /** GHOSTUPD: "(True, gs_set_assn cteDeleteOne_'proc (ucast cap_notification_cap))" */
    cteDeleteOne(slot);
}

void deletedIRQHandler(irq_t irq)
{
    setIRQState(IRQInactive, irq);
}

void handleInterrupt(irq_t irq)
{
    if (unlikely(IRQT_TO_IRQ(irq) > maxIRQ)) {
        /* mask, ack and pretend it didn't happen. We assume that because
         * the interrupt controller for the platform returned this IRQ that
         * it is safe to use in mask and ack operations, even though it is
         * above the claimed maxIRQ. i.e. we're assuming maxIRQ is wrong */
        printf("Received IRQ %d, which is above the platforms maxIRQ of %d\n", (int)IRQT_TO_IRQ(irq), (int)maxIRQ);
        maskInterrupt(true, irq);
        ackInterrupt(irq);
        return;
    }
    switch (intStateIRQTable[IRQT_TO_IDX(irq)]) {
    case IRQSignal: {
        cap_t cap;

        cap = intStateIRQNode[IRQT_TO_IDX(irq)].cap;

        if (cap_get_capType(cap) == cap_notification_cap &&
            cap_notification_cap_get_capNtfnCanSend(cap)) {
            sendSignal(NTFN_PTR(cap_notification_cap_get_capNtfnPtr(cap)),
                       cap_notification_cap_get_capNtfnBadge(cap));
        } else {
#ifdef CONFIG_IRQ_REPORTING
            printf("Undelivered IRQ: %d\n", (int)IRQT_TO_IRQ(irq));
#endif
        }
#ifndef CONFIG_ARCH_RISCV
        maskInterrupt(true, irq);
#endif
        break;
    }

    case IRQTimer:
#ifdef CONFIG_KERNEL_MCS
        ackDeadlineIRQ();
        NODE_STATE(ksReprogram) = true;
#else
        timerTick();
        resetTimer();
#endif
        break;

#ifdef ENABLE_SMP_SUPPORT
    case IRQIPI:
        handleIPI(irq, true);
        break;
#endif /* ENABLE_SMP_SUPPORT */

    case IRQReserved:
        handleReservedIRQ(irq);
        break;

    case IRQInactive:
        /*
         * This case shouldn't happen anyway unless the hardware or
         * platform code is broken. Hopefully masking it again should make
         * the interrupt go away.
         */
        maskInterrupt(true, irq);
#ifdef CONFIG_IRQ_REPORTING
        printf("Received disabled IRQ: %d\n", (int)IRQT_TO_IRQ(irq));
#endif
        break;

    default:
        /* No corresponding haskell error */
        fail("Invalid IRQ state");
    }

    ackInterrupt(irq);
}

bool_t isIRQActive(irq_t irq)
{
    return intStateIRQTable[IRQT_TO_IDX(irq)] != IRQInactive;
}

void setIRQState(irq_state_t irqState, irq_t irq)
{
    intStateIRQTable[IRQT_TO_IDX(irq)] = irqState;
#if defined ENABLE_SMP_SUPPORT && defined CONFIG_ARCH_ARM
    if (IRQ_IS_PPI(irq) && IRQT_TO_CORE(irq) != getCurrentCPUIndex()) {
        doRemoteMaskPrivateInterrupt(IRQT_TO_CORE(irq), irqState == IRQInactive, IRQT_TO_IDX(irq));
        return;
    }
#endif
    maskInterrupt(irqState == IRQInactive, irq);
}
#line 1 "/home/koc034/Documents/newver/seL4/src/object/notification.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>

#include <types.h>
#include <kernel/thread.h>
#include <object/structures.h>
#include <object/tcb.h>
#include <object/endpoint.h>
#include <model/statedata.h>
#include <machine/io.h>

#include <object/notification.h>

static inline tcb_queue_t PURE ntfn_ptr_get_queue(notification_t *ntfnPtr)
{
    tcb_queue_t ntfn_queue;

    ntfn_queue.head = (tcb_t *)notification_ptr_get_ntfnQueue_head(ntfnPtr);
    ntfn_queue.end = (tcb_t *)notification_ptr_get_ntfnQueue_tail(ntfnPtr);

    return ntfn_queue;
}

static inline void ntfn_ptr_set_queue(notification_t *ntfnPtr, tcb_queue_t ntfn_queue)
{
    notification_ptr_set_ntfnQueue_head(ntfnPtr, (word_t)ntfn_queue.head);
    notification_ptr_set_ntfnQueue_tail(ntfnPtr, (word_t)ntfn_queue.end);
}

static inline void ntfn_set_active(notification_t *ntfnPtr, word_t badge)
{
    notification_ptr_set_state(ntfnPtr, NtfnState_Active);
    notification_ptr_set_ntfnMsgIdentifier(ntfnPtr, badge);
}

#ifdef CONFIG_KERNEL_MCS
static inline void maybeDonateSchedContext(tcb_t *tcb, notification_t *ntfnPtr)
{
    if (tcb->tcbSchedContext == NULL) {
        sched_context_t *sc = SC_PTR(notification_ptr_get_ntfnSchedContext(ntfnPtr));
        if (sc != NULL && sc->scTcb == NULL) {
            schedContext_donate(sc, tcb);
            if (sc != NODE_STATE(ksCurSC)) {
                /* refill_unblock_check should not be called on the
                 * current SC as it is already running. The current SC
                 * may have been bound to a notificaiton object if the
                 * current thread was deleted in a long-running deletion
                 * that became preempted. */
                refill_unblock_check(sc);
            }
            schedContext_resume(sc);
        }
    }
}

#endif

#ifdef CONFIG_KERNEL_MCS
#define MCS_DO_IF_SC(tcb, ntfnPtr, _block) \
    maybeDonateSchedContext(tcb, ntfnPtr); \
    if (isSchedulable(tcb)) { \
        _block \
    }
#else
#define MCS_DO_IF_SC(tcb, ntfnPtr, _block) \
    { \
        _block \
    }
#endif

void sendSignal(notification_t *ntfnPtr, word_t badge)
{
    switch (notification_ptr_get_state(ntfnPtr)) {
    case NtfnState_Idle: {
        tcb_t *tcb = (tcb_t *)notification_ptr_get_ntfnBoundTCB(ntfnPtr);
        /* Check if we are bound and that thread is waiting for a message */
        if (tcb) {
            if (thread_state_ptr_get_tsType(&tcb->tcbState) == ThreadState_BlockedOnReceive) {
                /* Send and start thread running */
                cancelIPC(tcb);
                setThreadState(tcb, ThreadState_Running);
                setRegister(tcb, badgeRegister, badge);
                MCS_DO_IF_SC(tcb, ntfnPtr, {
                    possibleSwitchTo(tcb);
                })
#ifdef CONFIG_VTX
            } else if (thread_state_ptr_get_tsType(&tcb->tcbState) == ThreadState_RunningVM) {
#ifdef ENABLE_SMP_SUPPORT
                if (tcb->tcbAffinity != getCurrentCPUIndex()) {
                    ntfn_set_active(ntfnPtr, badge);
                    doRemoteVMCheckBoundNotification(tcb->tcbAffinity, tcb);
                } else
#endif /* ENABLE_SMP_SUPPORT */
                {
                    setThreadState(tcb, ThreadState_Running);
                    setRegister(tcb, badgeRegister, badge);
                    Arch_leaveVMAsyncTransfer(tcb);
                    MCS_DO_IF_SC(tcb, ntfnPtr, {
                        possibleSwitchTo(tcb);
                    })
                }
#endif /* CONFIG_VTX */
            } else {
                /* In particular, this path is taken when a thread
                 * is waiting on a reply cap since BlockedOnReply
                 * would also trigger this path. I.e, a thread
                 * with a bound notification will not be awakened
                 * by signals on that bound notification if it is
                 * in the middle of an seL4_Call.
                 */
                ntfn_set_active(ntfnPtr, badge);
            }
        } else {
            ntfn_set_active(ntfnPtr, badge);
        }
        break;
    }
    case NtfnState_Waiting: {
        tcb_queue_t ntfn_queue;
        tcb_t *dest;

        ntfn_queue = ntfn_ptr_get_queue(ntfnPtr);
        dest = ntfn_queue.head;

        /* Haskell error "WaitingNtfn Notification must have non-empty queue" */
        assert(dest);

        /* Dequeue TCB */
        ntfn_queue = tcbEPDequeue(dest, ntfn_queue);
        ntfn_ptr_set_queue(ntfnPtr, ntfn_queue);

        /* set the thread state to idle if the queue is empty */
        if (!ntfn_queue.head) {
            notification_ptr_set_state(ntfnPtr, NtfnState_Idle);
        }

        setThreadState(dest, ThreadState_Running);
        setRegister(dest, badgeRegister, badge);
        MCS_DO_IF_SC(dest, ntfnPtr, {
            possibleSwitchTo(dest);
        })
        break;
    }

    case NtfnState_Active: {
        word_t badge2;

        badge2 = notification_ptr_get_ntfnMsgIdentifier(ntfnPtr);
        badge2 |= badge;

        notification_ptr_set_ntfnMsgIdentifier(ntfnPtr, badge2);
        break;
    }
    }
}

void receiveSignal(tcb_t *thread, cap_t cap, bool_t isBlocking)
{
    notification_t *ntfnPtr;

    ntfnPtr = NTFN_PTR(cap_notification_cap_get_capNtfnPtr(cap));

    switch (notification_ptr_get_state(ntfnPtr)) {
    case NtfnState_Idle:
    case NtfnState_Waiting: {
        tcb_queue_t ntfn_queue;

        if (isBlocking) {
            /* Block thread on notification object */
            thread_state_ptr_set_tsType(&thread->tcbState,
                                        ThreadState_BlockedOnNotification);
            thread_state_ptr_set_blockingObject(&thread->tcbState,
                                                NTFN_REF(ntfnPtr));
#ifdef CONFIG_KERNEL_MCS
            maybeReturnSchedContext(ntfnPtr, thread);
#endif
            scheduleTCB(thread);

            /* Enqueue TCB */
            ntfn_queue = ntfn_ptr_get_queue(ntfnPtr);
            ntfn_queue = tcbEPAppend(thread, ntfn_queue);

            notification_ptr_set_state(ntfnPtr, NtfnState_Waiting);
            ntfn_ptr_set_queue(ntfnPtr, ntfn_queue);
        } else {
            doNBRecvFailedTransfer(thread);
        }

        break;
    }

    case NtfnState_Active:
        setRegister(
            thread, badgeRegister,
            notification_ptr_get_ntfnMsgIdentifier(ntfnPtr));
        notification_ptr_set_state(ntfnPtr, NtfnState_Idle);
#ifdef CONFIG_KERNEL_MCS
        maybeDonateSchedContext(thread, ntfnPtr);
#endif
        break;
    }
}

void cancelAllSignals(notification_t *ntfnPtr)
{
    if (notification_ptr_get_state(ntfnPtr) == NtfnState_Waiting) {
        tcb_t *thread = TCB_PTR(notification_ptr_get_ntfnQueue_head(ntfnPtr));

        notification_ptr_set_state(ntfnPtr, NtfnState_Idle);
        notification_ptr_set_ntfnQueue_head(ntfnPtr, 0);
        notification_ptr_set_ntfnQueue_tail(ntfnPtr, 0);

        /* Set all waiting threads to Restart */
        for (; thread; thread = thread->tcbEPNext) {
            setThreadState(thread, ThreadState_Restart);
#ifdef CONFIG_KERNEL_MCS
            possibleSwitchTo(thread);
#else
            SCHED_ENQUEUE(thread);
#endif
        }
        rescheduleRequired();
    }
}

void cancelSignal(tcb_t *threadPtr, notification_t *ntfnPtr)
{
    tcb_queue_t ntfn_queue;

    /* Haskell error "cancelSignal: notification object must be in a waiting" state */
    assert(notification_ptr_get_state(ntfnPtr) == NtfnState_Waiting);

    /* Dequeue TCB */
    ntfn_queue = ntfn_ptr_get_queue(ntfnPtr);
    ntfn_queue = tcbEPDequeue(threadPtr, ntfn_queue);
    ntfn_ptr_set_queue(ntfnPtr, ntfn_queue);

    /* Make notification object idle */
    if (!ntfn_queue.head) {
        notification_ptr_set_state(ntfnPtr, NtfnState_Idle);
    }

    /* Make thread inactive */
    setThreadState(threadPtr, ThreadState_Inactive);
}

void completeSignal(notification_t *ntfnPtr, tcb_t *tcb)
{
    word_t badge;

    if (likely(tcb && notification_ptr_get_state(ntfnPtr) == NtfnState_Active)) {
        badge = notification_ptr_get_ntfnMsgIdentifier(ntfnPtr);
        setRegister(tcb, badgeRegister, badge);
        notification_ptr_set_state(ntfnPtr, NtfnState_Idle);
#ifdef CONFIG_KERNEL_MCS
        maybeDonateSchedContext(tcb, ntfnPtr);
#endif
    } else {
        fail("tried to complete signal with inactive notification object");
    }
}

static inline void doUnbindNotification(notification_t *ntfnPtr, tcb_t *tcbptr)
{
    notification_ptr_set_ntfnBoundTCB(ntfnPtr, (word_t) 0);
    tcbptr->tcbBoundNotification = NULL;
}

void unbindMaybeNotification(notification_t *ntfnPtr)
{
    tcb_t *boundTCB;
    boundTCB = (tcb_t *)notification_ptr_get_ntfnBoundTCB(ntfnPtr);

    if (boundTCB) {
        doUnbindNotification(ntfnPtr, boundTCB);
    }
}

void unbindNotification(tcb_t *tcb)
{
    notification_t *ntfnPtr;
    ntfnPtr = tcb->tcbBoundNotification;

    if (ntfnPtr) {
        doUnbindNotification(ntfnPtr, tcb);
    }
}

void bindNotification(tcb_t *tcb, notification_t *ntfnPtr)
{
    notification_ptr_set_ntfnBoundTCB(ntfnPtr, (word_t)tcb);
    tcb->tcbBoundNotification = ntfnPtr;
}

#ifdef CONFIG_KERNEL_MCS
void reorderNTFN(notification_t *ntfnPtr, tcb_t *thread)
{
    tcb_queue_t queue = ntfn_ptr_get_queue(ntfnPtr);
    queue = tcbEPDequeue(thread, queue);
    queue = tcbEPAppend(thread, queue);
    ntfn_ptr_set_queue(ntfnPtr, queue);
}
#endif
#line 1 "/home/koc034/Documents/newver/seL4/src/object/objecttype.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <config.h>
#include <types.h>
#include <api/failures.h>
#include <api/syscall.h>
#include <arch/object/objecttype.h>
#include <machine/io.h>
#include <object/objecttype.h>
#include <object/structures.h>
#include <object/notification.h>
#include <object/endpoint.h>
#include <object/cnode.h>
#include <object/interrupt.h>
#ifdef CONFIG_KERNEL_MCS
#include <object/schedcontext.h>
#include <object/schedcontrol.h>
#endif
#include <object/tcb.h>
#include <object/untyped.h>
#include <model/statedata.h>
#include <kernel/thread.h>
#include <kernel/vspace.h>
#include <machine.h>
#include <util.h>
#include <string.h>

word_t getObjectSize(word_t t, word_t userObjSize)
{
    if (t >= seL4_NonArchObjectTypeCount) {
        return Arch_getObjectSize(t);
    } else {
        switch (t) {
        case seL4_TCBObject:
            return seL4_TCBBits;
        case seL4_EndpointObject:
            return seL4_EndpointBits;
        case seL4_NotificationObject:
            return seL4_NotificationBits;
        case seL4_CapTableObject:
            return seL4_SlotBits + userObjSize;
        case seL4_UntypedObject:
            return userObjSize;
#ifdef CONFIG_KERNEL_MCS
        case seL4_SchedContextObject:
            return userObjSize;
        case seL4_ReplyObject:
            return seL4_ReplyBits;
#endif
        default:
            fail("Invalid object type");
            return 0;
        }
    }
}

deriveCap_ret_t deriveCap(cte_t *slot, cap_t cap)
{
    deriveCap_ret_t ret;

    if (isArchCap(cap)) {
        return Arch_deriveCap(slot, cap);
    }

    switch (cap_get_capType(cap)) {
    case cap_zombie_cap:
        ret.status = EXCEPTION_NONE;
        ret.cap = cap_null_cap_new();
        break;

    case cap_irq_control_cap:
        ret.status = EXCEPTION_NONE;
        ret.cap = cap_null_cap_new();
        break;

    case cap_untyped_cap:
        ret.status = ensureNoChildren(slot);
        if (ret.status != EXCEPTION_NONE) {
            ret.cap = cap_null_cap_new();
        } else {
            ret.cap = cap;
        }
        break;

#ifndef CONFIG_KERNEL_MCS
    case cap_reply_cap:
        ret.status = EXCEPTION_NONE;
        ret.cap = cap_null_cap_new();
        break;
#endif
    default:
        ret.status = EXCEPTION_NONE;
        ret.cap = cap;
    }

    return ret;
}

finaliseCap_ret_t finaliseCap(cap_t cap, bool_t final, bool_t exposed)
{
    finaliseCap_ret_t fc_ret;

    if (isArchCap(cap)) {
        return Arch_finaliseCap(cap, final);
    }

    switch (cap_get_capType(cap)) {
    case cap_endpoint_cap:
        if (final) {
            cancelAllIPC(EP_PTR(cap_endpoint_cap_get_capEPPtr(cap)));
        }

        fc_ret.remainder = cap_null_cap_new();
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;

    case cap_notification_cap:
        if (final) {
            notification_t *ntfn = NTFN_PTR(cap_notification_cap_get_capNtfnPtr(cap));
#ifdef CONFIG_KERNEL_MCS
            schedContext_unbindNtfn(SC_PTR(notification_ptr_get_ntfnSchedContext(ntfn)));
#endif
            unbindMaybeNotification(ntfn);
            cancelAllSignals(ntfn);
        }
        fc_ret.remainder = cap_null_cap_new();
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;

    case cap_reply_cap:
#ifdef CONFIG_KERNEL_MCS
        if (final) {
            reply_t *reply = REPLY_PTR(cap_reply_cap_get_capReplyPtr(cap));
            if (reply && reply->replyTCB) {
                switch (thread_state_get_tsType(reply->replyTCB->tcbState)) {
                case ThreadState_BlockedOnReply:
                    reply_remove(reply, reply->replyTCB);
                    break;
                case ThreadState_BlockedOnReceive:
                    reply_unlink(reply, reply->replyTCB);
                    break;
                default:
                    fail("Invalid tcb state");
                }
            }
        }
        fc_ret.remainder = cap_null_cap_new();
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;
#endif
    case cap_null_cap:
    case cap_domain_cap:
        fc_ret.remainder = cap_null_cap_new();
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;
    }

    if (exposed) {
        fail("finaliseCap: failed to finalise immediately.");
    }

    switch (cap_get_capType(cap)) {
    case cap_cnode_cap: {
        if (final) {
            fc_ret.remainder =
                Zombie_new(
                    1ul << cap_cnode_cap_get_capCNodeRadix(cap),
                    cap_cnode_cap_get_capCNodeRadix(cap),
                    cap_cnode_cap_get_capCNodePtr(cap)
                );
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        break;
    }

    case cap_thread_cap: {
        if (final) {
            tcb_t *tcb;
            cte_t *cte_ptr;

            tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));
            SMP_COND_STATEMENT(remoteTCBStall(tcb);)
            cte_ptr = TCB_PTR_CTE_PTR(tcb, tcbCTable);
            unbindNotification(tcb);
#ifdef CONFIG_KERNEL_MCS
            if (tcb->tcbSchedContext) {
                schedContext_completeYieldTo(tcb->tcbSchedContext->scYieldFrom);
                schedContext_unbindTCB(tcb->tcbSchedContext, tcb);
            }
#endif
            suspend(tcb);
#ifdef CONFIG_DEBUG_BUILD
            tcbDebugRemove(tcb);
#endif
            Arch_prepareThreadDelete(tcb);
            fc_ret.remainder =
                Zombie_new(
                    tcbArchCNodeEntries,
                    ZombieType_ZombieTCB,
                    CTE_REF(cte_ptr)
                );
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        break;
    }

#ifdef CONFIG_KERNEL_MCS
    case cap_sched_context_cap:
        if (final) {
            sched_context_t *sc = SC_PTR(cap_sched_context_cap_get_capSCPtr(cap));
            schedContext_unbindAllTCBs(sc);
            schedContext_unbindNtfn(sc);
            if (sc->scReply) {
                assert(call_stack_get_isHead(sc->scReply->replyNext));
                sc->scReply->replyNext = call_stack_new(0, false);
                sc->scReply = NULL;
            }
            if (sc->scYieldFrom) {
                schedContext_completeYieldTo(sc->scYieldFrom);
            }
            /* mark the sc as no longer valid */
            sc->scRefillMax = 0;
            fc_ret.remainder = cap_null_cap_new();
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        break;
#endif

    case cap_zombie_cap:
        fc_ret.remainder = cap;
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;

    case cap_irq_handler_cap:
        if (final) {
            irq_t irq = IDX_TO_IRQT(cap_irq_handler_cap_get_capIRQ(cap));

            deletingIRQHandler(irq);

            fc_ret.remainder = cap_null_cap_new();
            fc_ret.cleanupInfo = cap;
            return fc_ret;
        }
        break;
    }

    fc_ret.remainder = cap_null_cap_new();
    fc_ret.cleanupInfo = cap_null_cap_new();
    return fc_ret;
}

bool_t CONST hasCancelSendRights(cap_t cap)
{
    switch (cap_get_capType(cap)) {
    case cap_endpoint_cap:
        return cap_endpoint_cap_get_capCanSend(cap) &&
               cap_endpoint_cap_get_capCanReceive(cap) &&
               cap_endpoint_cap_get_capCanGrantReply(cap) &&
               cap_endpoint_cap_get_capCanGrant(cap);

    default:
        return false;
    }
}

bool_t CONST sameRegionAs(cap_t cap_a, cap_t cap_b)
{
    switch (cap_get_capType(cap_a)) {
    case cap_untyped_cap:
        if (cap_get_capIsPhysical(cap_b)) {
            word_t aBase, bBase, aTop, bTop;

            aBase = (word_t)WORD_PTR(cap_untyped_cap_get_capPtr(cap_a));
            bBase = (word_t)cap_get_capPtr(cap_b);

            aTop = aBase + MASK(cap_untyped_cap_get_capBlockSize(cap_a));
            bTop = bBase + MASK(cap_get_capSizeBits(cap_b));

            return (aBase <= bBase) && (bTop <= aTop) && (bBase <= bTop);
        }
        break;

    case cap_endpoint_cap:
        if (cap_get_capType(cap_b) == cap_endpoint_cap) {
            return cap_endpoint_cap_get_capEPPtr(cap_a) ==
                   cap_endpoint_cap_get_capEPPtr(cap_b);
        }
        break;

    case cap_notification_cap:
        if (cap_get_capType(cap_b) == cap_notification_cap) {
            return cap_notification_cap_get_capNtfnPtr(cap_a) ==
                   cap_notification_cap_get_capNtfnPtr(cap_b);
        }
        break;

    case cap_cnode_cap:
        if (cap_get_capType(cap_b) == cap_cnode_cap) {
            return (cap_cnode_cap_get_capCNodePtr(cap_a) ==
                    cap_cnode_cap_get_capCNodePtr(cap_b)) &&
                   (cap_cnode_cap_get_capCNodeRadix(cap_a) ==
                    cap_cnode_cap_get_capCNodeRadix(cap_b));
        }
        break;

    case cap_thread_cap:
        if (cap_get_capType(cap_b) == cap_thread_cap) {
            return cap_thread_cap_get_capTCBPtr(cap_a) ==
                   cap_thread_cap_get_capTCBPtr(cap_b);
        }
        break;

    case cap_reply_cap:
        if (cap_get_capType(cap_b) == cap_reply_cap) {
#ifdef CONFIG_KERNEL_MCS
            return cap_reply_cap_get_capReplyPtr(cap_a) ==
                   cap_reply_cap_get_capReplyPtr(cap_b);
#else
            return cap_reply_cap_get_capTCBPtr(cap_a) ==
                   cap_reply_cap_get_capTCBPtr(cap_b);
#endif
        }
        break;

    case cap_domain_cap:
        if (cap_get_capType(cap_b) == cap_domain_cap) {
            return true;
        }
        break;

    case cap_irq_control_cap:
        if (cap_get_capType(cap_b) == cap_irq_control_cap ||
            cap_get_capType(cap_b) == cap_irq_handler_cap) {
            return true;
        }
        break;

    case cap_irq_handler_cap:
        if (cap_get_capType(cap_b) == cap_irq_handler_cap) {
            return (word_t)cap_irq_handler_cap_get_capIRQ(cap_a) ==
                   (word_t)cap_irq_handler_cap_get_capIRQ(cap_b);
        }
        break;

#ifdef CONFIG_KERNEL_MCS
    case cap_sched_context_cap:
        if (cap_get_capType(cap_b) == cap_sched_context_cap) {
            return (cap_sched_context_cap_get_capSCPtr(cap_a) ==
                    cap_sched_context_cap_get_capSCPtr(cap_b)) &&
                   (cap_sched_context_cap_get_capSCSizeBits(cap_a) ==
                    cap_sched_context_cap_get_capSCSizeBits(cap_b));
        }
        break;
    case cap_sched_control_cap:
        if (cap_get_capType(cap_b) == cap_sched_control_cap) {
            return true;
        }
        break;
#endif
    default:
        if (isArchCap(cap_a) &&
            isArchCap(cap_b)) {
            return Arch_sameRegionAs(cap_a, cap_b);
        }
        break;
    }

    return false;
}

bool_t CONST sameObjectAs(cap_t cap_a, cap_t cap_b)
{
    if (cap_get_capType(cap_a) == cap_untyped_cap) {
        return false;
    }
    if (cap_get_capType(cap_a) == cap_irq_control_cap &&
        cap_get_capType(cap_b) == cap_irq_handler_cap) {
        return false;
    }
    if (isArchCap(cap_a) && isArchCap(cap_b)) {
        return Arch_sameObjectAs(cap_a, cap_b);
    }
    return sameRegionAs(cap_a, cap_b);
}

cap_t CONST updateCapData(bool_t preserve, word_t newData, cap_t cap)
{
    if (isArchCap(cap)) {
        return Arch_updateCapData(preserve, newData, cap);
    }

    switch (cap_get_capType(cap)) {
    case cap_endpoint_cap:
        if (!preserve && cap_endpoint_cap_get_capEPBadge(cap) == 0) {
            return cap_endpoint_cap_set_capEPBadge(cap, newData);
        } else {
            return cap_null_cap_new();
        }

    case cap_notification_cap:
        if (!preserve && cap_notification_cap_get_capNtfnBadge(cap) == 0) {
            return cap_notification_cap_set_capNtfnBadge(cap, newData);
        } else {
            return cap_null_cap_new();
        }

    case cap_cnode_cap: {
        word_t guard, guardSize;
        seL4_CNode_CapData_t w = { .words = { newData } };

        guardSize = seL4_CNode_CapData_get_guardSize(w);

        if (guardSize + cap_cnode_cap_get_capCNodeRadix(cap) > wordBits) {
            return cap_null_cap_new();
        } else {
            cap_t new_cap;

            guard = seL4_CNode_CapData_get_guard(w) & MASK(guardSize);
            new_cap = cap_cnode_cap_set_capCNodeGuard(cap, guard);
            new_cap = cap_cnode_cap_set_capCNodeGuardSize(new_cap,
                                                          guardSize);

            return new_cap;
        }
    }

    default:
        return cap;
    }
}

cap_t CONST maskCapRights(seL4_CapRights_t cap_rights, cap_t cap)
{
    if (isArchCap(cap)) {
        return Arch_maskCapRights(cap_rights, cap);
    }

    switch (cap_get_capType(cap)) {
    case cap_null_cap:
    case cap_domain_cap:
    case cap_cnode_cap:
    case cap_untyped_cap:
    case cap_irq_control_cap:
    case cap_irq_handler_cap:
    case cap_zombie_cap:
    case cap_thread_cap:
#ifdef CONFIG_KERNEL_MCS
    case cap_sched_context_cap:
    case cap_sched_control_cap:
#endif
        return cap;

    case cap_endpoint_cap: {
        cap_t new_cap;

        new_cap = cap_endpoint_cap_set_capCanSend(
                      cap, cap_endpoint_cap_get_capCanSend(cap) &
                      seL4_CapRights_get_capAllowWrite(cap_rights));
        new_cap = cap_endpoint_cap_set_capCanReceive(
                      new_cap, cap_endpoint_cap_get_capCanReceive(cap) &
                      seL4_CapRights_get_capAllowRead(cap_rights));
        new_cap = cap_endpoint_cap_set_capCanGrant(
                      new_cap, cap_endpoint_cap_get_capCanGrant(cap) &
                      seL4_CapRights_get_capAllowGrant(cap_rights));
        new_cap = cap_endpoint_cap_set_capCanGrantReply(
                      new_cap, cap_endpoint_cap_get_capCanGrantReply(cap) &
                      seL4_CapRights_get_capAllowGrantReply(cap_rights));

        return new_cap;
    }

    case cap_notification_cap: {
        cap_t new_cap;

        new_cap = cap_notification_cap_set_capNtfnCanSend(
                      cap, cap_notification_cap_get_capNtfnCanSend(cap) &
                      seL4_CapRights_get_capAllowWrite(cap_rights));
        new_cap = cap_notification_cap_set_capNtfnCanReceive(new_cap,
                                                             cap_notification_cap_get_capNtfnCanReceive(cap) &
                                                             seL4_CapRights_get_capAllowRead(cap_rights));

        return new_cap;
    }
    case cap_reply_cap: {
        cap_t new_cap;

        new_cap = cap_reply_cap_set_capReplyCanGrant(
                      cap, cap_reply_cap_get_capReplyCanGrant(cap) &
                      seL4_CapRights_get_capAllowGrant(cap_rights));
        return new_cap;
    }


    default:
        fail("Invalid cap type"); /* Sentinel for invalid enums */
    }
}

cap_t createObject(object_t t, void *regionBase, word_t userSize, bool_t deviceMemory)
{
    /* Handle architecture-specific objects. */
    if (t >= (object_t) seL4_NonArchObjectTypeCount) {
        return Arch_createObject(t, regionBase, userSize, deviceMemory);
    }

    /* Create objects. */
    switch ((api_object_t)t) {
    case seL4_TCBObject: {
        tcb_t *tcb;
        tcb = TCB_PTR((word_t)regionBase + TCB_OFFSET);
        /** AUXUPD: "(True, ptr_retyps 1
          (Ptr ((ptr_val \<acute>tcb) - ctcb_offset) :: (cte_C[5]) ptr)
            o (ptr_retyp \<acute>tcb))" */

        /* Setup non-zero parts of the TCB. */

        Arch_initContext(&tcb->tcbArch.tcbContext);
#ifndef CONFIG_KERNEL_MCS
        tcb->tcbTimeSlice = CONFIG_TIME_SLICE;
#endif
        tcb->tcbDomain = ksCurDomain;
#ifndef CONFIG_KERNEL_MCS
        /* Initialize the new TCB to the current core */
        SMP_COND_STATEMENT(tcb->tcbAffinity = getCurrentCPUIndex());
#endif
#ifdef CONFIG_DEBUG_BUILD
        strlcpy(TCB_PTR_DEBUG_PTR(tcb)->tcbName, "child of: '", TCB_NAME_LENGTH);
        strlcat(TCB_PTR_DEBUG_PTR(tcb)->tcbName, TCB_PTR_DEBUG_PTR(NODE_STATE(ksCurThread))->tcbName, TCB_NAME_LENGTH);
        strlcat(TCB_PTR_DEBUG_PTR(tcb)->tcbName, "'", TCB_NAME_LENGTH);
        tcbDebugAppend(tcb);
#endif /* CONFIG_DEBUG_BUILD */

        return cap_thread_cap_new(TCB_REF(tcb));
    }

    case seL4_EndpointObject:
        /** AUXUPD: "(True, ptr_retyp
          (Ptr (ptr_val \<acute>regionBase) :: endpoint_C ptr))" */
        return cap_endpoint_cap_new(0, true, true, true, true,
                                    EP_REF(regionBase));

    case seL4_NotificationObject:
        /** AUXUPD: "(True, ptr_retyp
              (Ptr (ptr_val \<acute>regionBase) :: notification_C ptr))" */
        return cap_notification_cap_new(0, true, true,
                                        NTFN_REF(regionBase));

    case seL4_CapTableObject:
        /** AUXUPD: "(True, ptr_arr_retyps (2 ^ (unat \<acute>userSize))
          (Ptr (ptr_val \<acute>regionBase) :: cte_C ptr))" */
        /** GHOSTUPD: "(True, gs_new_cnodes (unat \<acute>userSize)
                                (ptr_val \<acute>regionBase)
                                (4 + unat \<acute>userSize))" */
        return cap_cnode_cap_new(userSize, 0, 0, CTE_REF(regionBase));

    case seL4_UntypedObject:
        /*
         * No objects need to be created; instead, just insert caps into
         * the destination slots.
         */
        return cap_untyped_cap_new(0, !!deviceMemory, userSize, WORD_REF(regionBase));

#ifdef CONFIG_KERNEL_MCS
    case seL4_SchedContextObject:
        memzero(regionBase, BIT(userSize));
        return cap_sched_context_cap_new(SC_REF(regionBase), userSize);

    case seL4_ReplyObject:
        memzero(regionBase, 1UL << seL4_ReplyBits);
        return cap_reply_cap_new(REPLY_REF(regionBase), true);
#endif

    default:
        fail("Invalid object type");
    }
}

void createNewObjects(object_t t, cte_t *parent,
                      cte_t *destCNode, word_t destOffset, word_t destLength,
                      void *regionBase, word_t userSize, bool_t deviceMemory)
{
    word_t objectSize;
    void *nextFreeArea;
    word_t i;
    word_t totalObjectSize UNUSED;

    /* ghost check that we're visiting less bytes than the max object size */
    objectSize = getObjectSize(t, userSize);
    totalObjectSize = destLength << objectSize;
    /** GHOSTUPD: "(gs_get_assn cap_get_capSizeBits_'proc \<acute>ghost'state = 0
        \<or> \<acute>totalObjectSize <= gs_get_assn cap_get_capSizeBits_'proc \<acute>ghost'state, id)" */

    /* Create the objects. */
    nextFreeArea = regionBase;
    for (i = 0; i < destLength; i++) {
        /* Create the object. */
        /** AUXUPD: "(True, typ_region_bytes (ptr_val \<acute> nextFreeArea + ((\<acute> i) << unat (\<acute> objectSize))) (unat (\<acute> objectSize)))" */
        cap_t cap = createObject(t, (void *)((word_t)nextFreeArea + (i << objectSize)), userSize, deviceMemory);

        /* Insert the cap into the user's cspace. */
        insertNewCap(parent, &destCNode[destOffset + i], cap);

        /* Move along to the next region of memory. been merged into a formula of i */
    }
}

#ifdef CONFIG_KERNEL_MCS
exception_t decodeInvocation(word_t invLabel, word_t length,
                             cptr_t capIndex, cte_t *slot, cap_t cap,
                             bool_t block, bool_t call,
                             bool_t canDonate, bool_t firstPhase, word_t *buffer)
#else
exception_t decodeInvocation(word_t invLabel, word_t length,
                             cptr_t capIndex, cte_t *slot, cap_t cap,
                             bool_t block, bool_t call,
                             word_t *buffer)
#endif
{
    if (isArchCap(cap)) {
        return Arch_decodeInvocation(invLabel, length, capIndex,
                                     slot, cap, call, buffer);
    }

    switch (cap_get_capType(cap)) {
    case cap_null_cap:
        userError("Attempted to invoke a null cap #%lu.", capIndex);
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 0;
        return EXCEPTION_SYSCALL_ERROR;

    case cap_zombie_cap:
        userError("Attempted to invoke a zombie cap #%lu.", capIndex);
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 0;
        return EXCEPTION_SYSCALL_ERROR;

    case cap_endpoint_cap:
        if (unlikely(!cap_endpoint_cap_get_capCanSend(cap))) {
            userError("Attempted to invoke a read-only endpoint cap #%lu.",
                      capIndex);
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
#ifdef CONFIG_KERNEL_MCS
        return performInvocation_Endpoint(
                   EP_PTR(cap_endpoint_cap_get_capEPPtr(cap)),
                   cap_endpoint_cap_get_capEPBadge(cap),
                   cap_endpoint_cap_get_capCanGrant(cap),
                   cap_endpoint_cap_get_capCanGrantReply(cap), block, call, canDonate);
#else
        return performInvocation_Endpoint(
                   EP_PTR(cap_endpoint_cap_get_capEPPtr(cap)),
                   cap_endpoint_cap_get_capEPBadge(cap),
                   cap_endpoint_cap_get_capCanGrant(cap),
                   cap_endpoint_cap_get_capCanGrantReply(cap), block, call);
#endif

    case cap_notification_cap: {
        if (unlikely(!cap_notification_cap_get_capNtfnCanSend(cap))) {
            userError("Attempted to invoke a read-only notification cap #%lu.",
                      capIndex);
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performInvocation_Notification(
                   NTFN_PTR(cap_notification_cap_get_capNtfnPtr(cap)),
                   cap_notification_cap_get_capNtfnBadge(cap));
    }

#ifdef CONFIG_KERNEL_MCS
    case cap_reply_cap:
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performInvocation_Reply(
                   NODE_STATE(ksCurThread),
                   REPLY_PTR(cap_reply_cap_get_capReplyPtr(cap)),
                   cap_reply_cap_get_capReplyCanGrant(cap));
#else
    case cap_reply_cap:
        if (unlikely(cap_reply_cap_get_capReplyMaster(cap))) {
            userError("Attempted to invoke an invalid reply cap #%lu.",
                      capIndex);
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return performInvocation_Reply(
                   TCB_PTR(cap_reply_cap_get_capTCBPtr(cap)), slot,
                   cap_reply_cap_get_capReplyCanGrant(cap));

#endif

    case cap_thread_cap:
#ifdef CONFIG_KERNEL_MCS
        if (unlikely(firstPhase)) {
            userError("Cannot invoke thread capabilities in the first phase of an invocation");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
#endif
        return decodeTCBInvocation(invLabel, length, cap, slot, call, buffer);

    case cap_domain_cap:
#ifdef CONFIG_KERNEL_MCS
        if (unlikely(firstPhase)) {
            userError("Cannot invoke domain capabilities in the first phase of an invocation");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
#endif
        return decodeDomainInvocation(invLabel, length, buffer);

    case cap_cnode_cap:
#ifdef CONFIG_KERNEL_MCS
        if (unlikely(firstPhase)) {
            userError("Cannot invoke cnode capabilities in the first phase of an invocation");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
#endif
        return decodeCNodeInvocation(invLabel, length, cap, buffer);

    case cap_untyped_cap:
        return decodeUntypedInvocation(invLabel, length, slot, cap, call, buffer);

    case cap_irq_control_cap:
        return decodeIRQControlInvocation(invLabel, length, slot, buffer);

    case cap_irq_handler_cap:
        return decodeIRQHandlerInvocation(invLabel,
                                          IDX_TO_IRQT(cap_irq_handler_cap_get_capIRQ(cap)));

#ifdef CONFIG_KERNEL_MCS
    case cap_sched_control_cap:
        if (unlikely(firstPhase)) {
            userError("Cannot invoke sched control capabilities in the first phase of an invocation");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
        return decodeSchedControlInvocation(invLabel, cap, length, buffer);

    case cap_sched_context_cap:
        if (unlikely(firstPhase)) {
            userError("Cannot invoke sched context capabilities in the first phase of an invocation");
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
        return decodeSchedContextInvocation(invLabel, cap, buffer);
#endif
    default:
        fail("Invalid cap type");
    }
}

#ifdef CONFIG_KERNEL_MCS
exception_t performInvocation_Endpoint(endpoint_t *ep, word_t badge,
                                       bool_t canGrant, bool_t canGrantReply,
                                       bool_t block, bool_t call, bool_t canDonate)
{
    sendIPC(block, call, badge, canGrant, canGrantReply, canDonate, NODE_STATE(ksCurThread), ep);

    return EXCEPTION_NONE;
}
#else
exception_t performInvocation_Endpoint(endpoint_t *ep, word_t badge,
                                       bool_t canGrant, bool_t canGrantReply,
                                       bool_t block, bool_t call)
{
    sendIPC(block, call, badge, canGrant, canGrantReply, NODE_STATE(ksCurThread), ep);

    return EXCEPTION_NONE;
}
#endif

exception_t performInvocation_Notification(notification_t *ntfn, word_t badge)
{
    sendSignal(ntfn, badge);

    return EXCEPTION_NONE;
}

#ifdef CONFIG_KERNEL_MCS
exception_t performInvocation_Reply(tcb_t *thread, reply_t *reply, bool_t canGrant)
{
    doReplyTransfer(thread, reply, canGrant);
    return EXCEPTION_NONE;
}
#else
exception_t performInvocation_Reply(tcb_t *thread, cte_t *slot, bool_t canGrant)
{
    doReplyTransfer(NODE_STATE(ksCurThread), thread, slot, canGrant);
    return EXCEPTION_NONE;
}
#endif

word_t CONST cap_get_capSizeBits(cap_t cap)
{

    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {
    case cap_untyped_cap:
        return cap_untyped_cap_get_capBlockSize(cap);

    case cap_endpoint_cap:
        return seL4_EndpointBits;

    case cap_notification_cap:
        return seL4_NotificationBits;

    case cap_cnode_cap:
        return cap_cnode_cap_get_capCNodeRadix(cap) + seL4_SlotBits;

    case cap_thread_cap:
        return seL4_TCBBits;

    case cap_zombie_cap: {
        word_t type = cap_zombie_cap_get_capZombieType(cap);
        if (type == ZombieType_ZombieTCB) {
            return seL4_TCBBits;
        }
        return ZombieType_ZombieCNode(type) + seL4_SlotBits;
    }

    case cap_null_cap:
        return 0;

    case cap_domain_cap:
        return 0;

    case cap_reply_cap:
#ifdef CONFIG_KERNEL_MCS
        return seL4_ReplyBits;
#else
        return 0;
#endif

    case cap_irq_control_cap:
#ifdef CONFIG_KERNEL_MCS
    case cap_sched_control_cap:
#endif
        return 0;

    case cap_irq_handler_cap:
        return 0;

#ifdef CONFIG_KERNEL_MCS
    case cap_sched_context_cap:
        return cap_sched_context_cap_get_capSCSizeBits(cap);
#endif

    default:
        return cap_get_archCapSizeBits(cap);
    }

}

/* Returns whether or not this capability has memory associated
 * with it or not. Referring to this as 'being physical' is to
 * match up with the Haskell and abstract specifications */
bool_t CONST cap_get_capIsPhysical(cap_t cap)
{
    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {
    case cap_untyped_cap:
        return true;

    case cap_endpoint_cap:
        return true;

    case cap_notification_cap:
        return true;

    case cap_cnode_cap:
        return true;

    case cap_thread_cap:
#ifdef CONFIG_KERNEL_MCS
    case cap_sched_context_cap:
#endif
        return true;

    case cap_zombie_cap:
        return true;

    case cap_domain_cap:
        return false;

    case cap_reply_cap:
#ifdef CONFIG_KERNEL_MCS
        return true;
#else
        return false;
#endif

    case cap_irq_control_cap:
#ifdef CONFIG_KERNEL_MCS
    case cap_sched_control_cap:
#endif
        return false;

    case cap_irq_handler_cap:
        return false;

    default:
        return cap_get_archCapIsPhysical(cap);
    }
}

void *CONST cap_get_capPtr(cap_t cap)
{
    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {
    case cap_untyped_cap:
        return WORD_PTR(cap_untyped_cap_get_capPtr(cap));

    case cap_endpoint_cap:
        return EP_PTR(cap_endpoint_cap_get_capEPPtr(cap));

    case cap_notification_cap:
        return NTFN_PTR(cap_notification_cap_get_capNtfnPtr(cap));

    case cap_cnode_cap:
        return CTE_PTR(cap_cnode_cap_get_capCNodePtr(cap));

    case cap_thread_cap:
        return TCB_PTR_CTE_PTR(cap_thread_cap_get_capTCBPtr(cap), 0);

    case cap_zombie_cap:
        return CTE_PTR(cap_zombie_cap_get_capZombiePtr(cap));

    case cap_domain_cap:
        return NULL;

    case cap_reply_cap:
#ifdef CONFIG_KERNEL_MCS
        return REPLY_PTR(cap_reply_cap_get_capReplyPtr(cap));
#else
        return NULL;
#endif

    case cap_irq_control_cap:
#ifdef CONFIG_KERNEL_MCS
    case cap_sched_control_cap:
#endif
        return NULL;

    case cap_irq_handler_cap:
        return NULL;

#ifdef CONFIG_KERNEL_MCS
    case cap_sched_context_cap:
        return SC_PTR(cap_sched_context_cap_get_capSCPtr(cap));
#endif

    default:
        return cap_get_archCapPtr(cap);

    }
}

bool_t CONST isCapRevocable(cap_t derivedCap, cap_t srcCap)
{
    if (isArchCap(derivedCap)) {
        return Arch_isCapRevocable(derivedCap, srcCap);
    }
    switch (cap_get_capType(derivedCap)) {
    case cap_endpoint_cap:
        return (cap_endpoint_cap_get_capEPBadge(derivedCap) !=
                cap_endpoint_cap_get_capEPBadge(srcCap));

    case cap_notification_cap:
        return (cap_notification_cap_get_capNtfnBadge(derivedCap) !=
                cap_notification_cap_get_capNtfnBadge(srcCap));

    case cap_irq_handler_cap:
        return (cap_get_capType(srcCap) ==
                cap_irq_control_cap);

    case cap_untyped_cap:
        return true;

    default:
        return false;
    }
}
#line 1 "/home/koc034/Documents/newver/seL4/src/object/reply.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <object/reply.h>

void reply_push(tcb_t *tcb_caller, tcb_t *tcb_callee, reply_t *reply, bool_t canDonate)
{
    sched_context_t *sc_donated = tcb_caller->tcbSchedContext;

    assert(tcb_caller != NULL);
    assert(reply != NULL);
    assert(reply->replyTCB == NULL);

    assert(call_stack_get_callStackPtr(reply->replyPrev) == 0);
    assert(call_stack_get_callStackPtr(reply->replyNext) == 0);

    /* tcb caller should not be in a existing call stack */
    assert(thread_state_get_replyObject(tcb_caller->tcbState) == 0);

    /* unlink callee and reply - they may not have been linked already,
     * if this rendesvous is occuring when seL4_Recv is called,
     * however, no harm in overring 0 with 0 */
    thread_state_ptr_set_replyObject(&tcb_callee->tcbState, 0);

    /* link caller and reply */
    reply->replyTCB = tcb_caller;
    thread_state_ptr_set_replyObject(&tcb_caller->tcbState, REPLY_REF(reply));
    setThreadState(tcb_caller, ThreadState_BlockedOnReply);

    if (sc_donated != NULL && tcb_callee->tcbSchedContext == NULL && canDonate) {
        reply_t *old_caller = sc_donated->scReply;

        /* check stack integrity */
        assert(old_caller == NULL ||
               SC_PTR(call_stack_get_callStackPtr(old_caller->replyNext)) == sc_donated);

        /* push on to stack */
        reply->replyPrev = call_stack_new(REPLY_REF(old_caller), false);
        if (old_caller) {
            old_caller->replyNext = call_stack_new(REPLY_REF(reply), false);
        }
        reply->replyNext = call_stack_new(SC_REF(sc_donated), true);
        sc_donated->scReply = reply;

        /* now do the actual donation */
        schedContext_donate(sc_donated, tcb_callee);
    }
}

/* Pop the head reply from the call stack */
void reply_pop(reply_t *reply, tcb_t *tcb)
{
    assert(reply != NULL);
    assert(thread_state_get_tsType(reply->replyTCB->tcbState) == ThreadState_BlockedOnReply);
    assert(thread_state_get_replyObject(tcb->tcbState) == REPLY_REF(reply));
    assert(reply->replyTCB == tcb);

    /* unlink tcb and reply */
    reply_unlink(reply, tcb);

    word_t next_ptr = call_stack_get_callStackPtr(reply->replyNext);
    word_t prev_ptr = call_stack_get_callStackPtr(reply->replyPrev);

    if (likely(next_ptr != 0)) {
        assert(call_stack_get_isHead(reply->replyNext));

        /* give it back */
        if (tcb->tcbSchedContext == NULL) {
            /* only give the SC back if our SC is NULL. This prevents
             * strange behaviour when a thread is bound to an sc while it is
             * in the BlockedOnReply state. The semantics in this case are that the
             * SC cannot go back to the caller if the caller has received another one */
            schedContext_donate(SC_PTR(next_ptr), tcb);
        }

        SC_PTR(next_ptr)->scReply = REPLY_PTR(prev_ptr);
        if (prev_ptr != 0) {
            REPLY_PTR(prev_ptr)->replyNext = reply->replyNext;
            assert(call_stack_get_isHead(REPLY_PTR(prev_ptr)->replyNext));
        }

        reply->replyPrev = call_stack_new(0, false);
        reply->replyNext = call_stack_new(0, false);
    }
}

/* Remove a reply from the middle of the call stack */
void reply_remove(reply_t *reply, tcb_t *tcb)
{
    assert(reply->replyTCB == tcb);
    assert(thread_state_get_tsType(tcb->tcbState) == ThreadState_BlockedOnReply);
    assert(thread_state_get_replyObject(tcb->tcbState) == REPLY_REF(reply));

    word_t next_ptr = call_stack_get_callStackPtr(reply->replyNext);
    word_t prev_ptr = call_stack_get_callStackPtr(reply->replyPrev);

    if (likely(next_ptr)) {
        if (likely(call_stack_get_isHead(reply->replyNext))) {
            /* head of the call stack -> just pop */
            reply_pop(reply, tcb);
            return;
        }
        /* not the head, remove from middle - break the chain */
        REPLY_PTR(next_ptr)->replyPrev = call_stack_new(0, false);
        reply_unlink(REPLY_PTR(reply), tcb);
    } else {
        /* removing start of call chain */
        reply_unlink(reply, tcb);
    }

    if (prev_ptr) {
        REPLY_PTR(prev_ptr)->replyNext = call_stack_new(0, false);
    }

    reply->replyPrev = call_stack_new(0, false);
    reply->replyNext = call_stack_new(0, false);
}

void reply_remove_tcb(tcb_t *tcb)
{
    assert(thread_state_get_tsType(tcb->tcbState) == ThreadState_BlockedOnReply);
    reply_t *reply = REPLY_PTR(thread_state_get_replyObject(tcb->tcbState));
    word_t next_ptr = call_stack_get_callStackPtr(reply->replyNext);
    word_t prev_ptr = call_stack_get_callStackPtr(reply->replyPrev);

    if (next_ptr) {
        if (call_stack_get_isHead(reply->replyNext)) {
            SC_PTR(next_ptr)->scReply = NULL;
        } else {
            REPLY_PTR(next_ptr)->replyPrev = call_stack_new(0, false);
        }
    }

    if (prev_ptr) {
        REPLY_PTR(prev_ptr)->replyNext = call_stack_new(0, false);
    }

    reply->replyPrev = call_stack_new(0, false);
    reply->replyNext = call_stack_new(0, false);
    reply_unlink(reply, tcb);
}
#line 1 "/home/koc034/Documents/newver/seL4/src/object/schedcontext.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <machine/timer.h>
#include <object/schedcontext.h>

static exception_t invokeSchedContext_UnbindObject(sched_context_t *sc, cap_t cap)
{
    switch (cap_get_capType(cap)) {
    case cap_thread_cap:
        schedContext_unbindTCB(sc, sc->scTcb);
        break;
    case cap_notification_cap:
        schedContext_unbindNtfn(sc);
        break;
    default:
        fail("invalid cap type");
    }

    return EXCEPTION_NONE;
}

static exception_t decodeSchedContext_UnbindObject(sched_context_t *sc)
{
    if (current_extra_caps.excaprefs[0] == NULL) {
        userError("SchedContext_Unbind: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    cap_t cap = current_extra_caps.excaprefs[0]->cap;
    switch (cap_get_capType(cap)) {
    case cap_thread_cap:
        if (sc->scTcb != TCB_PTR(cap_thread_cap_get_capTCBPtr(cap))) {
            userError("SchedContext UnbindObject: object not bound");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        if (sc->scTcb == NODE_STATE(ksCurThread)) {
            userError("SchedContext UnbindObject: cannot unbind sc of current thread");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        break;
    case cap_notification_cap:
        if (sc->scNotification != NTFN_PTR(cap_notification_cap_get_capNtfnPtr(cap))) {
            userError("SchedContext UnbindObject: object not bound");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        break;

    default:
        userError("SchedContext_Unbind: invalid cap");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;

    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeSchedContext_UnbindObject(sc, cap);
}

static exception_t invokeSchedContext_Bind(sched_context_t *sc, cap_t cap)
{
    switch (cap_get_capType(cap)) {
    case cap_thread_cap:
        schedContext_bindTCB(sc, TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)));
        break;
    case cap_notification_cap:
        schedContext_bindNtfn(sc, NTFN_PTR(cap_notification_cap_get_capNtfnPtr(cap)));
        break;
    default:
        fail("invalid cap type");
    }

    return EXCEPTION_NONE;
}

static exception_t decodeSchedContext_Bind(sched_context_t *sc)
{
    if (current_extra_caps.excaprefs[0] == NULL) {
        userError("SchedContext_Bind: Truncated Message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    cap_t cap = current_extra_caps.excaprefs[0]->cap;

    if (sc->scTcb != NULL || sc->scNotification != NULL) {
        userError("SchedContext_Bind: sched context already bound.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    switch (cap_get_capType(cap)) {
    case cap_thread_cap:
        if (TCB_PTR(cap_thread_cap_get_capTCBPtr(cap))->tcbSchedContext != NULL) {
            userError("SchedContext_Bind: tcb already bound.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }

        break;
    case cap_notification_cap:
        if (notification_ptr_get_ntfnSchedContext(NTFN_PTR(cap_notification_cap_get_capNtfnPtr(cap)))) {
            userError("SchedContext_Bind: notification already bound");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        break;
    default:
        userError("SchedContext_Bind: invalid cap.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeSchedContext_Bind(sc, cap);
}

static exception_t invokeSchedContext_Unbind(sched_context_t *sc)
{
    schedContext_unbindAllTCBs(sc);
    schedContext_unbindNtfn(sc);
    if (sc->scReply) {
        sc->scReply->replyNext = call_stack_new(0, false);
        sc->scReply = NULL;
    }
    return EXCEPTION_NONE;
}

#ifdef ENABLE_SMP_SUPPORT
static inline void maybeStallSC(sched_context_t *sc)
{
    if (sc->scTcb) {
        remoteTCBStall(sc->scTcb);
    }
}
#endif

static inline void setConsumed(sched_context_t *sc, word_t *buffer)
{
    time_t consumed = schedContext_updateConsumed(sc);
    word_t length = mode_setTimeArg(0, consumed, buffer, NODE_STATE(ksCurThread));
    setRegister(NODE_STATE(ksCurThread), msgInfoRegister, wordFromMessageInfo(seL4_MessageInfo_new(0, 0, 0, length)));
}

static exception_t invokeSchedContext_Consumed(sched_context_t *sc, word_t *buffer)
{
    setConsumed(sc, buffer);
    return EXCEPTION_NONE;
}

static exception_t invokeSchedContext_YieldTo(sched_context_t *sc, word_t *buffer)
{
    if (sc->scYieldFrom) {
        schedContext_completeYieldTo(sc->scYieldFrom);
        assert(sc->scYieldFrom == NULL);
    }

    /* if the tcb is in the scheduler, it's ready and sufficient.
     * Otherwise, check that it is ready and sufficient and if not,
     * place the thread in the release queue. This way, from this point,
     * if the thread isSchedulable, it is ready and sufficient.*/
    schedContext_resume(sc);

    bool_t return_now = true;
    if (isSchedulable(sc->scTcb)) {
        refill_unblock_check(sc);
        if (SMP_COND_STATEMENT(sc->scCore != getCurrentCPUIndex() ||)
            sc->scTcb->tcbPriority < NODE_STATE(ksCurThread)->tcbPriority) {
            tcbSchedDequeue(sc->scTcb);
            SCHED_ENQUEUE(sc->scTcb);
        } else {
            NODE_STATE(ksCurThread)->tcbYieldTo = sc;
            sc->scYieldFrom = NODE_STATE(ksCurThread);
            tcbSchedDequeue(sc->scTcb);
            tcbSchedEnqueue(NODE_STATE(ksCurThread));
            tcbSchedEnqueue(sc->scTcb);
            rescheduleRequired();

            /* we are scheduling the thread associated with sc,
             * so we don't need to write to the ipc buffer
             * until the caller is scheduled again */
            return_now = false;
        }
    }

    if (return_now) {
        setConsumed(sc, buffer);
    }

    return EXCEPTION_NONE;
}

static exception_t decodeSchedContext_YieldTo(sched_context_t *sc, word_t *buffer)
{
    if (sc->scTcb == NODE_STATE(ksCurThread)) {
        userError("SchedContext_YieldTo: cannot seL4_SchedContext_YieldTo on self");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (sc->scTcb == NULL) {
        userError("SchedContext_YieldTo: cannot yield to an inactive sched context");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (sc->scTcb->tcbPriority > NODE_STATE(ksCurThread)->tcbMCP) {
        userError("SchedContext_YieldTo: insufficient mcp (%lu) to yield to a thread with prio (%lu)",
                  (unsigned long) NODE_STATE(ksCurThread)->tcbMCP, (unsigned long) sc->scTcb->tcbPriority);
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeSchedContext_YieldTo(sc, buffer);
}

exception_t decodeSchedContextInvocation(word_t label, cap_t cap, word_t *buffer)
{
    sched_context_t *sc = SC_PTR(cap_sched_context_cap_get_capSCPtr(cap));

    SMP_COND_STATEMENT((maybeStallSC(sc));)

    switch (label) {
    case SchedContextConsumed:
        /* no decode */
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return invokeSchedContext_Consumed(sc, buffer);
    case SchedContextBind:
        return decodeSchedContext_Bind(sc);
    case SchedContextUnbindObject:
        return decodeSchedContext_UnbindObject(sc);
    case SchedContextUnbind:
        /* no decode */
        if (sc->scTcb == NODE_STATE(ksCurThread)) {
            userError("SchedContext UnbindObject: cannot unbind sc of current thread");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return invokeSchedContext_Unbind(sc);
    case SchedContextYieldTo:
        return decodeSchedContext_YieldTo(sc, buffer);
    default:
        userError("SchedContext invocation: Illegal operation attempted.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }
}

void schedContext_resume(sched_context_t *sc)
{
    assert(!sc || sc->scTcb != NULL);
    if (likely(sc) && isSchedulable(sc->scTcb)) {
        if (!(refill_ready(sc) && refill_sufficient(sc, 0))) {
            assert(!thread_state_get_tcbQueued(sc->scTcb->tcbState));
            postpone(sc);
        }
    }
}

void schedContext_bindTCB(sched_context_t *sc, tcb_t *tcb)
{
    assert(sc->scTcb == NULL);
    assert(tcb->tcbSchedContext == NULL);

    tcb->tcbSchedContext = sc;
    sc->scTcb = tcb;

    SMP_COND_STATEMENT(migrateTCB(tcb, sc->scCore));

    schedContext_resume(sc);
    if (isSchedulable(tcb)) {
        SCHED_ENQUEUE(tcb);
        rescheduleRequired();
        // TODO -- at some stage we should take this call out of any TCB invocations that
        // alter capabilities, so that we can do a direct switch. The prefernce here is to
        // remove seL4_SetSchedParams from using ThreadControl. It's currently out of scope for
        // verification work, so the work around is to use rescheduleRequired()
        //possibleSwitchTo(tcb);
    }
}

void schedContext_unbindTCB(sched_context_t *sc, tcb_t *tcb)
{
    assert(sc->scTcb == tcb);

    /* tcb must already be stalled at this point */
    if (tcb == NODE_STATE(ksCurThread)) {
        rescheduleRequired();
    }

    tcbSchedDequeue(sc->scTcb);
    tcbReleaseRemove(sc->scTcb);

    sc->scTcb->tcbSchedContext = NULL;
    sc->scTcb = NULL;
}

void schedContext_unbindAllTCBs(sched_context_t *sc)
{
    if (sc->scTcb) {
        SMP_COND_STATEMENT(remoteTCBStall(sc->scTcb));
        schedContext_unbindTCB(sc, sc->scTcb);
    }
}

void schedContext_donate(sched_context_t *sc, tcb_t *to)
{
    assert(sc != NULL);
    assert(to != NULL);
    assert(to->tcbSchedContext == NULL);

    tcb_t *from = sc->scTcb;
    if (from) {
        SMP_COND_STATEMENT(remoteTCBStall(from));
        tcbSchedDequeue(from);
        from->tcbSchedContext = NULL;
        if (from == NODE_STATE(ksCurThread) || from == NODE_STATE(ksSchedulerAction)) {
            rescheduleRequired();
        }
    }
    sc->scTcb = to;
    to->tcbSchedContext = sc;

    SMP_COND_STATEMENT(migrateTCB(to, sc->scCore));
}

void schedContext_bindNtfn(sched_context_t *sc, notification_t *ntfn)
{
    notification_ptr_set_ntfnSchedContext(ntfn, SC_REF(sc));
    sc->scNotification = ntfn;
}

void schedContext_unbindNtfn(sched_context_t *sc)
{
    if (sc && sc->scNotification) {
        notification_ptr_set_ntfnSchedContext(sc->scNotification, SC_REF(0));
        sc->scNotification = NULL;
    }
}

time_t schedContext_updateConsumed(sched_context_t *sc)
{
    ticks_t consumed = sc->scConsumed;
    if (consumed >= getMaxTicksToUs()) {
        sc->scConsumed -= getMaxTicksToUs();
        return getMaxTicksToUs();
    } else {
        sc->scConsumed = 0;
        return ticksToUs(consumed);
    }
}

void schedContext_cancelYieldTo(tcb_t *tcb)
{
    if (tcb && tcb->tcbYieldTo) {
        tcb->tcbYieldTo->scYieldFrom = NULL;
        tcb->tcbYieldTo = NULL;
    }
}

void schedContext_completeYieldTo(tcb_t *yielder)
{
    if (yielder && yielder->tcbYieldTo) {
        setConsumed(yielder->tcbYieldTo, lookupIPCBuffer(true, yielder));
        schedContext_cancelYieldTo(yielder);
    }
}
#line 1 "/home/koc034/Documents/newver/seL4/src/object/schedcontrol.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <machine/timer.h>
#include <mode/api/ipc_buffer.h>
#include <object/schedcontext.h>
#include <object/schedcontrol.h>
#include <kernel/sporadic.h>

static exception_t invokeSchedControl_Configure(sched_context_t *target, word_t core, ticks_t budget,
                                                ticks_t period, word_t max_refills, word_t badge)
{

    target->scBadge = badge;

    /* don't modify parameters of tcb while it is in a sorted queue */
    if (target->scTcb) {
        /* possibly stall a remote core */
        SMP_COND_STATEMENT(remoteTCBStall(target->scTcb));
        /* remove from scheduler */
        tcbReleaseRemove(target->scTcb);
        tcbSchedDequeue(target->scTcb);
        /* bill the current consumed amount before adjusting the params */
        if (NODE_STATE_ON_CORE(ksCurSC, target->scCore) == target) {
#ifdef ENABLE_SMP_SUPPORT
            if (target->scCore == getCurrentCPUIndex()) {
#endif /* ENABLE_SMP_SUPPORT */
                /* This could potentially mutate state but if it returns
                 * true no state was modified, thus removing it should
                 * be the same. */
                assert(checkBudget());
                commitTime();
#ifdef ENABLE_SMP_SUPPORT
            } else {
                chargeBudget(NODE_STATE_ON_CORE(ksConsumed, target->scCore), false, target->scCore, false);
                doReschedule(target->scCore);
            }
#endif /* ENABLE_SMP_SUPPORT */
        }
    }

    if (budget == period) {
        /* this is a cool hack: for round robin, we set the
         * period to 0, which means that the budget will always be ready to be refilled
         * and avoids some special casing.
         */
        period = 0;
        max_refills = MIN_REFILLS;
    }

    if (SMP_COND_STATEMENT(core == target->scCore &&) target->scRefillMax > 0 && target->scTcb
        && isRunnable(target->scTcb)) {
        /* the scheduling context is active - it can be used, so
         * we need to preserve the bandwidth */
        refill_update(target, period, budget, max_refills);
    } else {
        /* the scheduling context isn't active - it's budget is not being used, so
         * we can just populate the parameters from now */
        REFILL_NEW(target, max_refills, budget, period, core);
    }

#ifdef ENABLE_SMP_SUPPORT
    target->scCore = core;
    if (target->scTcb) {
        migrateTCB(target->scTcb, target->scCore);
    }
#endif /* ENABLE_SMP_SUPPORT */

    if (target->scTcb && target->scRefillMax > 0) {
        schedContext_resume(target);
        if (SMP_TERNARY(core == CURRENT_CPU_INDEX(), true)) {
            if (isRunnable(target->scTcb) && target->scTcb != NODE_STATE(ksCurThread)) {
                possibleSwitchTo(target->scTcb);
            }
        } else if (isRunnable(target->scTcb)) {
            SCHED_ENQUEUE(target->scTcb);
        }
        if (target->scTcb == NODE_STATE(ksCurThread)) {
            rescheduleRequired();
        }
    }

    return EXCEPTION_NONE;
}

static exception_t decodeSchedControl_Configure(word_t length, cap_t cap, word_t *buffer)
{
    if (current_extra_caps.excaprefs[0] == NULL) {
        userError("SchedControl_Configure: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (length < (TIME_ARG_SIZE * 2) + 2) {
        userError("SchedControl_configure: truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    time_t budget_us = mode_parseTimeArg(0, buffer);
    time_t period_us = mode_parseTimeArg(TIME_ARG_SIZE, buffer);
    word_t extra_refills = getSyscallArg(TIME_ARG_SIZE * 2, buffer);
    word_t badge = getSyscallArg(TIME_ARG_SIZE * 2 + 1, buffer);

    cap_t targetCap = current_extra_caps.excaprefs[0]->cap;
    if (unlikely(cap_get_capType(targetCap) != cap_sched_context_cap)) {
        userError("SchedControl_Configure: target cap not a scheduling context cap");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (budget_us > MAX_BUDGET_US || budget_us < MIN_BUDGET_US) {
        userError("SchedControl_Configure: budget out of range.");
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = MIN_BUDGET_US;
        current_syscall_error.rangeErrorMax = MAX_BUDGET_US;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (period_us > MAX_BUDGET_US || period_us < MIN_BUDGET_US) {
        userError("SchedControl_Configure: period out of range.");
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = MIN_BUDGET_US;
        current_syscall_error.rangeErrorMax = MAX_BUDGET_US;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (budget_us > period_us) {
        userError("SchedControl_Configure: budget must be <= period");
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = MIN_BUDGET_US;
        current_syscall_error.rangeErrorMax = period_us;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (extra_refills + MIN_REFILLS > refill_absolute_max(targetCap)) {
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 0;
        current_syscall_error.rangeErrorMax = refill_absolute_max(targetCap) - MIN_REFILLS;
        userError("Max refills invalid, got %lu, max %lu",
                  extra_refills,
                  current_syscall_error.rangeErrorMax);
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeSchedControl_Configure(SC_PTR(cap_sched_context_cap_get_capSCPtr(targetCap)),
                                        cap_sched_control_cap_get_core(cap),
                                        usToTicks(budget_us),
                                        usToTicks(period_us),
                                        extra_refills + MIN_REFILLS,
                                        badge);
}

exception_t decodeSchedControlInvocation(word_t label, cap_t cap, word_t length, word_t *buffer)
{
    switch (label) {
    case SchedControlConfigure:
        return  decodeSchedControl_Configure(length, cap, buffer);
    default:
        userError("SchedControl invocation: Illegal operation attempted.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }
}
#line 1 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <types.h>
#include <api/failures.h>
#include <api/invocation.h>
#include <api/syscall.h>
#include <sel4/shared_types.h>
#include <machine/io.h>
#include <object/structures.h>
#include <object/objecttype.h>
#include <object/cnode.h>
#ifdef CONFIG_KERNEL_MCS
#include <object/schedcontext.h>
#endif
#include <object/tcb.h>
#include <kernel/cspace.h>
#include <kernel/thread.h>
#include <kernel/vspace.h>
#include <model/statedata.h>
#include <util.h>
#include <string.h>
#include <stdint.h>
#include <arch/smp/ipi_inline.h>

#define NULL_PRIO 0

static exception_t checkPrio(prio_t prio, tcb_t *auth)
{
    prio_t mcp;

    mcp = auth->tcbMCP;

    /* system invariant: existing MCPs are bounded */
    assert(mcp <= seL4_MaxPrio);

    /* can't assign a priority greater than our own mcp */
    if (prio > mcp) {
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = seL4_MinPrio;
        current_syscall_error.rangeErrorMax = mcp;
        return EXCEPTION_SYSCALL_ERROR;
    }

    return EXCEPTION_NONE;
}

static inline void addToBitmap(word_t cpu, word_t dom, word_t prio)
{
    word_t l1index;
    word_t l1index_inverted;

    l1index = prio_to_l1index(prio);
    l1index_inverted = invert_l1index(l1index);

    NODE_STATE_ON_CORE(ksReadyQueuesL1Bitmap[dom], cpu) |= BIT(l1index);
    /* we invert the l1 index when accessed the 2nd level of the bitmap in
       order to increase the liklihood that high prio threads l2 index word will
       be on the same cache line as the l1 index word - this makes sure the
       fastpath is fastest for high prio threads */
    NODE_STATE_ON_CORE(ksReadyQueuesL2Bitmap[dom][l1index_inverted], cpu) |= BIT(prio & MASK(wordRadix));
}

static inline void removeFromBitmap(word_t cpu, word_t dom, word_t prio)
{
    word_t l1index;
    word_t l1index_inverted;

    l1index = prio_to_l1index(prio);
    l1index_inverted = invert_l1index(l1index);
    NODE_STATE_ON_CORE(ksReadyQueuesL2Bitmap[dom][l1index_inverted], cpu) &= ~BIT(prio & MASK(wordRadix));
    if (unlikely(!NODE_STATE_ON_CORE(ksReadyQueuesL2Bitmap[dom][l1index_inverted], cpu))) {
        NODE_STATE_ON_CORE(ksReadyQueuesL1Bitmap[dom], cpu) &= ~BIT(l1index);
    }
}

/* Add TCB to the head of a scheduler queue */
void tcbSchedEnqueue(tcb_t *tcb)
{
#ifdef CONFIG_KERNEL_MCS
    assert(isSchedulable(tcb));
    assert(refill_sufficient(tcb->tcbSchedContext, 0));
#endif

    if (!thread_state_get_tcbQueued(tcb->tcbState)) {
        tcb_queue_t queue;
        dom_t dom;
        prio_t prio;
        word_t idx;

        dom = tcb->tcbDomain;
        prio = tcb->tcbPriority;
        idx = ready_queues_index(dom, prio);
        queue = NODE_STATE_ON_CORE(ksReadyQueues[idx], tcb->tcbAffinity);

        if (!queue.end) { /* Empty list */
            queue.end = tcb;
            addToBitmap(SMP_TERNARY(tcb->tcbAffinity, 0), dom, prio);
        } else {
            queue.head->tcbSchedPrev = tcb;
        }
        tcb->tcbSchedPrev = NULL;
        tcb->tcbSchedNext = queue.head;
        queue.head = tcb;

        NODE_STATE_ON_CORE(ksReadyQueues[idx], tcb->tcbAffinity) = queue;

        thread_state_ptr_set_tcbQueued(&tcb->tcbState, true);
    }
}

/* Add TCB to the end of a scheduler queue */
void tcbSchedAppend(tcb_t *tcb)
{
#ifdef CONFIG_KERNEL_MCS
    assert(isSchedulable(tcb));
    assert(refill_sufficient(tcb->tcbSchedContext, 0));
    assert(refill_ready(tcb->tcbSchedContext));
#endif
    if (!thread_state_get_tcbQueued(tcb->tcbState)) {
        tcb_queue_t queue;
        dom_t dom;
        prio_t prio;
        word_t idx;

        dom = tcb->tcbDomain;
        prio = tcb->tcbPriority;
        idx = ready_queues_index(dom, prio);
        queue = NODE_STATE_ON_CORE(ksReadyQueues[idx], tcb->tcbAffinity);

        if (!queue.head) { /* Empty list */
            queue.head = tcb;
            addToBitmap(SMP_TERNARY(tcb->tcbAffinity, 0), dom, prio);
        } else {
            queue.end->tcbSchedNext = tcb;
        }
        tcb->tcbSchedPrev = queue.end;
        tcb->tcbSchedNext = NULL;
        queue.end = tcb;

        NODE_STATE_ON_CORE(ksReadyQueues[idx], tcb->tcbAffinity) = queue;

        thread_state_ptr_set_tcbQueued(&tcb->tcbState, true);
    }
}

/* Remove TCB from a scheduler queue */
void tcbSchedDequeue(tcb_t *tcb)
{
    if (thread_state_get_tcbQueued(tcb->tcbState)) {
        tcb_queue_t queue;
        dom_t dom;
        prio_t prio;
        word_t idx;

        dom = tcb->tcbDomain;
        prio = tcb->tcbPriority;
        idx = ready_queues_index(dom, prio);
        queue = NODE_STATE_ON_CORE(ksReadyQueues[idx], tcb->tcbAffinity);

        if (tcb->tcbSchedPrev) {
            tcb->tcbSchedPrev->tcbSchedNext = tcb->tcbSchedNext;
        } else {
            queue.head = tcb->tcbSchedNext;
            if (likely(!tcb->tcbSchedNext)) {
                removeFromBitmap(SMP_TERNARY(tcb->tcbAffinity, 0), dom, prio);
            }
        }

        if (tcb->tcbSchedNext) {
            tcb->tcbSchedNext->tcbSchedPrev = tcb->tcbSchedPrev;
        } else {
            queue.end = tcb->tcbSchedPrev;
        }

        NODE_STATE_ON_CORE(ksReadyQueues[idx], tcb->tcbAffinity) = queue;

        thread_state_ptr_set_tcbQueued(&tcb->tcbState, false);
    }
}

#ifdef CONFIG_DEBUG_BUILD
void tcbDebugAppend(tcb_t *tcb)
{
    debug_tcb_t *debug_tcb = TCB_PTR_DEBUG_PTR(tcb);
    /* prepend to the list */
    debug_tcb->tcbDebugPrev = NULL;

    debug_tcb->tcbDebugNext = NODE_STATE_ON_CORE(ksDebugTCBs, tcb->tcbAffinity);

    if (NODE_STATE_ON_CORE(ksDebugTCBs, tcb->tcbAffinity)) {
        TCB_PTR_DEBUG_PTR(NODE_STATE_ON_CORE(ksDebugTCBs, tcb->tcbAffinity))->tcbDebugPrev = tcb;
    }

    NODE_STATE_ON_CORE(ksDebugTCBs, tcb->tcbAffinity) = tcb;
}

void tcbDebugRemove(tcb_t *tcb)
{
    debug_tcb_t *debug_tcb = TCB_PTR_DEBUG_PTR(tcb);

    assert(NODE_STATE_ON_CORE(ksDebugTCBs, tcb->tcbAffinity) != NULL);
    if (tcb == NODE_STATE_ON_CORE(ksDebugTCBs, tcb->tcbAffinity)) {
        NODE_STATE_ON_CORE(ksDebugTCBs, tcb->tcbAffinity) = TCB_PTR_DEBUG_PTR(NODE_STATE_ON_CORE(ksDebugTCBs,
                                                                                                 tcb->tcbAffinity))->tcbDebugNext;
    } else {
        assert(TCB_PTR_DEBUG_PTR(tcb)->tcbDebugPrev);
        TCB_PTR_DEBUG_PTR(debug_tcb->tcbDebugPrev)->tcbDebugNext = debug_tcb->tcbDebugNext;
    }

    if (debug_tcb->tcbDebugNext) {
        TCB_PTR_DEBUG_PTR(debug_tcb->tcbDebugNext)->tcbDebugPrev = debug_tcb->tcbDebugPrev;
    }

    debug_tcb->tcbDebugPrev = NULL;
    debug_tcb->tcbDebugNext = NULL;
}
#endif /* CONFIG_DEBUG_BUILD */

#ifndef CONFIG_KERNEL_MCS
/* Add TCB to the end of an endpoint queue */
tcb_queue_t tcbEPAppend(tcb_t *tcb, tcb_queue_t queue)
{
    if (!queue.head) { /* Empty list */
        queue.head = tcb;
    } else {
        queue.end->tcbEPNext = tcb;
    }
    tcb->tcbEPPrev = queue.end;
    tcb->tcbEPNext = NULL;
    queue.end = tcb;

    return queue;
}
#endif

/* Remove TCB from an endpoint queue */
tcb_queue_t tcbEPDequeue(tcb_t *tcb, tcb_queue_t queue)
{
    if (tcb->tcbEPPrev) {
        tcb->tcbEPPrev->tcbEPNext = tcb->tcbEPNext;
    } else {
        queue.head = tcb->tcbEPNext;
    }

    if (tcb->tcbEPNext) {
        tcb->tcbEPNext->tcbEPPrev = tcb->tcbEPPrev;
    } else {
        queue.end = tcb->tcbEPPrev;
    }

    return queue;
}

#ifdef CONFIG_KERNEL_MCS
void tcbReleaseRemove(tcb_t *tcb)
{
    if (likely(thread_state_get_tcbInReleaseQueue(tcb->tcbState))) {
        if (tcb->tcbSchedPrev) {
            tcb->tcbSchedPrev->tcbSchedNext = tcb->tcbSchedNext;
        } else {
            NODE_STATE_ON_CORE(ksReleaseHead, tcb->tcbAffinity) = tcb->tcbSchedNext;
            /* the head has changed, we might need to set a new timeout */
            NODE_STATE_ON_CORE(ksReprogram, tcb->tcbAffinity) = true;
        }

        if (tcb->tcbSchedNext) {
            tcb->tcbSchedNext->tcbSchedPrev = tcb->tcbSchedPrev;
        }

        tcb->tcbSchedNext = NULL;
        tcb->tcbSchedPrev = NULL;
        thread_state_ptr_set_tcbInReleaseQueue(&tcb->tcbState, false);
    }
}

void tcbReleaseEnqueue(tcb_t *tcb)
{
    assert(thread_state_get_tcbInReleaseQueue(tcb->tcbState) == false);
    assert(thread_state_get_tcbQueued(tcb->tcbState) == false);

    tcb_t *before = NULL;
    tcb_t *after = NODE_STATE_ON_CORE(ksReleaseHead, tcb->tcbAffinity);

    /* find our place in the ordered queue */
    while (after != NULL &&
           refill_head(tcb->tcbSchedContext)->rTime >= refill_head(after->tcbSchedContext)->rTime) {
        before = after;
        after = after->tcbSchedNext;
    }

    if (before == NULL) {
        /* insert at head */
        NODE_STATE_ON_CORE(ksReleaseHead, tcb->tcbAffinity) = tcb;
        NODE_STATE_ON_CORE(ksReprogram, tcb->tcbAffinity) = true;
    } else {
        before->tcbSchedNext = tcb;
    }

    if (after != NULL) {
        after->tcbSchedPrev = tcb;
    }

    tcb->tcbSchedNext = after;
    tcb->tcbSchedPrev = before;

    thread_state_ptr_set_tcbInReleaseQueue(&tcb->tcbState, true);
}

tcb_t *tcbReleaseDequeue(void)
{
    assert(NODE_STATE(ksReleaseHead) != NULL);
    assert(NODE_STATE(ksReleaseHead)->tcbSchedPrev == NULL);
    SMP_COND_STATEMENT(assert(NODE_STATE(ksReleaseHead)->tcbAffinity == getCurrentCPUIndex()));

    tcb_t *detached_head = NODE_STATE(ksReleaseHead);
    NODE_STATE(ksReleaseHead) = NODE_STATE(ksReleaseHead)->tcbSchedNext;

    if (NODE_STATE(ksReleaseHead)) {
        NODE_STATE(ksReleaseHead)->tcbSchedPrev = NULL;
    }

    if (detached_head->tcbSchedNext) {
        detached_head->tcbSchedNext->tcbSchedPrev = NULL;
        detached_head->tcbSchedNext = NULL;
    }

    thread_state_ptr_set_tcbInReleaseQueue(&detached_head->tcbState, false);
    NODE_STATE(ksReprogram) = true;

    return detached_head;
}
#endif

cptr_t PURE getExtraCPtr(word_t *bufferPtr, word_t i)
{
    return (cptr_t)bufferPtr[seL4_MsgMaxLength + 2 + i];
}

void setExtraBadge(word_t *bufferPtr, word_t badge,
                   word_t i)
{
    bufferPtr[seL4_MsgMaxLength + 2 + i] = badge;
}

#ifndef CONFIG_KERNEL_MCS
void setupCallerCap(tcb_t *sender, tcb_t *receiver, bool_t canGrant)
{
    cte_t *replySlot, *callerSlot;
    cap_t masterCap UNUSED, callerCap UNUSED;

    setThreadState(sender, ThreadState_BlockedOnReply);
    replySlot = TCB_PTR_CTE_PTR(sender, tcbReply);
    masterCap = replySlot->cap;
    /* Haskell error: "Sender must have a valid master reply cap" */
    assert(cap_get_capType(masterCap) == cap_reply_cap);
    assert(cap_reply_cap_get_capReplyMaster(masterCap));
    assert(cap_reply_cap_get_capReplyCanGrant(masterCap));
    assert(TCB_PTR(cap_reply_cap_get_capTCBPtr(masterCap)) == sender);
    callerSlot = TCB_PTR_CTE_PTR(receiver, tcbCaller);
    callerCap = callerSlot->cap;
    /* Haskell error: "Caller cap must not already exist" */
    assert(cap_get_capType(callerCap) == cap_null_cap);
    cteInsert(cap_reply_cap_new(canGrant, false, TCB_REF(sender)),
              replySlot, callerSlot);
}

void deleteCallerCap(tcb_t *receiver)
{
    cte_t *callerSlot;

    callerSlot = TCB_PTR_CTE_PTR(receiver, tcbCaller);
    /** GHOSTUPD: "(True, gs_set_assn cteDeleteOne_'proc (ucast cap_reply_cap))" */
    cteDeleteOne(callerSlot);
}
#endif

extra_caps_t current_extra_caps;

exception_t lookupExtraCaps(tcb_t *thread, word_t *bufferPtr, seL4_MessageInfo_t info)
{
    lookupSlot_raw_ret_t lu_ret;
    cptr_t cptr;
    word_t i, length;

    if (!bufferPtr) {
        current_extra_caps.excaprefs[0] = NULL;
        return EXCEPTION_NONE;
    }

    length = seL4_MessageInfo_get_extraCaps(info);

    for (i = 0; i < length; i++) {
        cptr = getExtraCPtr(bufferPtr, i);

        lu_ret = lookupSlot(thread, cptr);
        if (lu_ret.status != EXCEPTION_NONE) {
            current_fault = seL4_Fault_CapFault_new(cptr, false);
            return lu_ret.status;
        }

        current_extra_caps.excaprefs[i] = lu_ret.slot;
    }
    if (i < seL4_MsgMaxExtraCaps) {
        current_extra_caps.excaprefs[i] = NULL;
    }

    return EXCEPTION_NONE;
}

/* Copy IPC MRs from one thread to another */
word_t copyMRs(tcb_t *sender, word_t *sendBuf, tcb_t *receiver,
               word_t *recvBuf, word_t n)
{
    word_t i;

    /* Copy inline words */
    for (i = 0; i < n && i < n_msgRegisters; i++) {
        setRegister(receiver, msgRegisters[i],
                    getRegister(sender, msgRegisters[i]));
    }

    if (!recvBuf || !sendBuf) {
        return i;
    }

    /* Copy out-of-line words */
    for (; i < n; i++) {
        recvBuf[i + 1] = sendBuf[i + 1];
    }

    return i;
}

#ifdef ENABLE_SMP_SUPPORT
/* This checks if the current updated to scheduler queue is changing the previous scheduling
 * decision made by the scheduler. If its a case, an `irq_reschedule_ipi` is sent */
void remoteQueueUpdate(tcb_t *tcb)
{
    /* only ipi if the target is for the current domain */
    if (tcb->tcbAffinity != getCurrentCPUIndex() && tcb->tcbDomain == ksCurDomain) {
        tcb_t *targetCurThread = NODE_STATE_ON_CORE(ksCurThread, tcb->tcbAffinity);

        /* reschedule if the target core is idle or we are waking a higher priority thread (or
         * if a new irq would need to be set on MCS) */
        if (targetCurThread == NODE_STATE_ON_CORE(ksIdleThread, tcb->tcbAffinity)  ||
            tcb->tcbPriority > targetCurThread->tcbPriority
#ifdef CONFIG_KERNEL_MCS
            || NODE_STATE_ON_CORE(ksReprogram, tcb->tcbAffinity)
#endif
           ) {
            ARCH_NODE_STATE(ipiReschedulePending) |= BIT(tcb->tcbAffinity);
        }
    }
}

/* This makes sure the the TCB is not being run on other core.
 * It would request 'IpiRemoteCall_Stall' to switch the core from this TCB
 * We also request the 'irq_reschedule_ipi' to restore the state of target core */
void remoteTCBStall(tcb_t *tcb)
{

    if (
#ifdef CONFIG_KERNEL_MCS
        tcb->tcbSchedContext &&
#endif
        tcb->tcbAffinity != getCurrentCPUIndex() &&
        NODE_STATE_ON_CORE(ksCurThread, tcb->tcbAffinity) == tcb) {
        doRemoteStall(tcb->tcbAffinity);
        ARCH_NODE_STATE(ipiReschedulePending) |= BIT(tcb->tcbAffinity);
    }
}

#ifndef CONFIG_KERNEL_MCS
static exception_t invokeTCB_SetAffinity(tcb_t *thread, word_t affinity)
{
    /* remove the tcb from scheduler queue in case it is already in one
     * and add it to new queue if required */
    tcbSchedDequeue(thread);
    migrateTCB(thread, affinity);
    if (isRunnable(thread)) {
        SCHED_APPEND(thread);
    }
    /* reschedule current cpu if tcb moves itself */
    if (thread == NODE_STATE(ksCurThread)) {
        rescheduleRequired();
    }
    return EXCEPTION_NONE;
}

static exception_t decodeSetAffinity(cap_t cap, word_t length, word_t *buffer)
{
    tcb_t *tcb;
    word_t affinity;

    if (length < 1) {
        userError("TCB SetAffinity: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));

    affinity = getSyscallArg(0, buffer);
    if (affinity >= ksNumCPUs) {
        userError("TCB SetAffinity: Requested CPU does not exist.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeTCB_SetAffinity(tcb, affinity);
}
#endif
#endif /* ENABLE_SMP_SUPPORT */

#ifdef CONFIG_HARDWARE_DEBUG_API
static exception_t invokeConfigureSingleStepping(word_t *buffer, tcb_t *t,
                                                 uint16_t bp_num, word_t n_instrs)
{
    bool_t bp_was_consumed;

    bp_was_consumed = configureSingleStepping(t, bp_num, n_instrs, false);
    if (n_instrs == 0) {
        unsetBreakpointUsedFlag(t, bp_num);
        setMR(NODE_STATE(ksCurThread), buffer, 0, false);
    } else {
        setBreakpointUsedFlag(t, bp_num);
        setMR(NODE_STATE(ksCurThread), buffer, 0, bp_was_consumed);
    }
    return EXCEPTION_NONE;
}

static exception_t decodeConfigureSingleStepping(cap_t cap, word_t *buffer)
{
    uint16_t bp_num;
    word_t n_instrs;
    tcb_t *tcb;
    syscall_error_t syserr;

    tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));

    bp_num = getSyscallArg(0, buffer);
    n_instrs = getSyscallArg(1, buffer);

    syserr = Arch_decodeConfigureSingleStepping(tcb, bp_num, n_instrs, false);
    if (syserr.type != seL4_NoError) {
        current_syscall_error = syserr;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeConfigureSingleStepping(buffer, tcb, bp_num, n_instrs);
}

static exception_t invokeSetBreakpoint(tcb_t *tcb, uint16_t bp_num,
                                       word_t vaddr, word_t type, word_t size, word_t rw)
{
    setBreakpoint(tcb, bp_num, vaddr, type, size, rw);
    /* Signal restore_user_context() to pop the breakpoint context on return. */
    setBreakpointUsedFlag(tcb, bp_num);
    return EXCEPTION_NONE;
}

static exception_t decodeSetBreakpoint(cap_t cap, word_t *buffer)
{
    uint16_t bp_num;
    word_t vaddr, type, size, rw;
    tcb_t *tcb;
    syscall_error_t error;

    tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));
    bp_num = getSyscallArg(0, buffer);
    vaddr = getSyscallArg(1, buffer);
    type = getSyscallArg(2, buffer);
    size = getSyscallArg(3, buffer);
    rw = getSyscallArg(4, buffer);

    /* We disallow the user to set breakpoint addresses that are in the kernel
     * vaddr range.
     */
    if (vaddr >= (word_t)USER_TOP) {
        userError("Debug: Invalid address %lx: bp addresses must be userspace "
                  "addresses.",
                  vaddr);
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (type != seL4_InstructionBreakpoint && type != seL4_DataBreakpoint) {
        userError("Debug: Unknown breakpoint type %lx.", type);
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 2;
        return EXCEPTION_SYSCALL_ERROR;
    } else if (type == seL4_InstructionBreakpoint) {
        if (size != 0) {
            userError("Debug: Instruction bps must have size of 0.");
            current_syscall_error.type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 3;
            return EXCEPTION_SYSCALL_ERROR;
        }
        if (rw != seL4_BreakOnRead) {
            userError("Debug: Instruction bps must be break-on-read.");
            current_syscall_error.type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 4;
            return EXCEPTION_SYSCALL_ERROR;
        }
        if ((seL4_FirstWatchpoint == -1 || bp_num >= seL4_FirstWatchpoint)
            && seL4_FirstBreakpoint != seL4_FirstWatchpoint) {
            userError("Debug: Can't specify a watchpoint ID with type seL4_InstructionBreakpoint.");
            current_syscall_error.type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 2;
            return EXCEPTION_SYSCALL_ERROR;
        }
    } else if (type == seL4_DataBreakpoint) {
        if (size == 0) {
            userError("Debug: Data bps cannot have size of 0.");
            current_syscall_error.type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 3;
            return EXCEPTION_SYSCALL_ERROR;
        }
        if (seL4_FirstWatchpoint != -1 && bp_num < seL4_FirstWatchpoint) {
            userError("Debug: Data watchpoints cannot specify non-data watchpoint ID.");
            current_syscall_error.type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 2;
            return EXCEPTION_SYSCALL_ERROR;
        }
    } else if (type == seL4_SoftwareBreakRequest) {
        userError("Debug: Use a software breakpoint instruction to trigger a "
                  "software breakpoint.");
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 2;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (rw != seL4_BreakOnRead && rw != seL4_BreakOnWrite
        && rw != seL4_BreakOnReadWrite) {
        userError("Debug: Unknown access-type %lu.", rw);
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 3;
        return EXCEPTION_SYSCALL_ERROR;
    }
    if (size != 0 && size != 1 && size != 2 && size != 4 && size != 8) {
        userError("Debug: Invalid size %lu.", size);
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 3;
        return EXCEPTION_SYSCALL_ERROR;
    }
    if (size > 0 && vaddr & (size - 1)) {
        /* Just Don't allow unaligned watchpoints. They are undefined
         * both ARM and x86.
         *
         * X86: Intel manuals, vol3, 17.2.5:
         *  "Two-byte ranges must be aligned on word boundaries; 4-byte
         *   ranges must be aligned on doubleword boundaries"
         *  "Unaligned data or I/O breakpoint addresses do not yield valid
         *   results"
         *
         * ARM: ARMv7 manual, C11.11.44:
         *  "A DBGWVR is programmed with a word-aligned address."
         */
        userError("Debug: Unaligned data watchpoint address %lx (size %lx) "
                  "rejected.\n",
                  vaddr, size);

        current_syscall_error.type = seL4_AlignmentError;
        return EXCEPTION_SYSCALL_ERROR;
    }

    error = Arch_decodeSetBreakpoint(tcb, bp_num, vaddr, type, size, rw);
    if (error.type != seL4_NoError) {
        current_syscall_error = error;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeSetBreakpoint(tcb, bp_num,
                               vaddr, type, size, rw);
}

static exception_t invokeGetBreakpoint(word_t *buffer, tcb_t *tcb, uint16_t bp_num)
{
    getBreakpoint_t res;

    res = getBreakpoint(tcb, bp_num);
    setMR(NODE_STATE(ksCurThread), buffer, 0, res.vaddr);
    setMR(NODE_STATE(ksCurThread), buffer, 1, res.type);
    setMR(NODE_STATE(ksCurThread), buffer, 2, res.size);
    setMR(NODE_STATE(ksCurThread), buffer, 3, res.rw);
    setMR(NODE_STATE(ksCurThread), buffer, 4, res.is_enabled);
    return EXCEPTION_NONE;
}

static exception_t decodeGetBreakpoint(cap_t cap, word_t *buffer)
{
    tcb_t *tcb;
    uint16_t bp_num;
    syscall_error_t error;

    tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));
    bp_num = getSyscallArg(0, buffer);

    error = Arch_decodeGetBreakpoint(tcb, bp_num);
    if (error.type != seL4_NoError) {
        current_syscall_error = error;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeGetBreakpoint(buffer, tcb, bp_num);
}

static exception_t invokeUnsetBreakpoint(tcb_t *tcb, uint16_t bp_num)
{
    /* Maintain the bitfield of in-use breakpoints. */
    unsetBreakpoint(tcb, bp_num);
    unsetBreakpointUsedFlag(tcb, bp_num);
    return EXCEPTION_NONE;
}

static exception_t decodeUnsetBreakpoint(cap_t cap, word_t *buffer)
{
    tcb_t *tcb;
    uint16_t bp_num;
    syscall_error_t error;

    tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));
    bp_num = getSyscallArg(0, buffer);

    error = Arch_decodeUnsetBreakpoint(tcb, bp_num);
    if (error.type != seL4_NoError) {
        current_syscall_error = error;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeUnsetBreakpoint(tcb, bp_num);
}
#endif /* CONFIG_HARDWARE_DEBUG_API */

static exception_t invokeSetTLSBase(tcb_t *thread, word_t tls_base)
{
    setRegister(thread, TLS_BASE, tls_base);
    if (thread == NODE_STATE(ksCurThread)) {
        /* If this is the current thread force a reschedule to ensure that any changes
         * to the TLS_BASE are realized */
        rescheduleRequired();
    }

    return EXCEPTION_NONE;
}

static exception_t decodeSetTLSBase(cap_t cap, word_t length, word_t *buffer)
{
    word_t tls_base;

    if (length < 1) {
        userError("TCB SetTLSBase: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tls_base = getSyscallArg(0, buffer);

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeSetTLSBase(TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), tls_base);
}

/* The following functions sit in the syscall error monad, but include the
 * exception cases for the preemptible bottom end, as they call the invoke
 * functions directly.  This is a significant deviation from the Haskell
 * spec. */
exception_t decodeTCBInvocation(word_t invLabel, word_t length, cap_t cap,
                                cte_t *slot, bool_t call, word_t *buffer)
{
    /* Stall the core if we are operating on a remote TCB that is currently running */
    SMP_COND_STATEMENT(remoteTCBStall(TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)));)

    switch (invLabel) {
    case TCBReadRegisters:
        /* Second level of decoding */
        return decodeReadRegisters(cap, length, call, buffer);

    case TCBWriteRegisters:
        return decodeWriteRegisters(cap, length, buffer);

    case TCBCopyRegisters:
        return decodeCopyRegisters(cap, length, buffer);

    case TCBSuspend:
        /* Jump straight to the invoke */
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return invokeTCB_Suspend(
                   TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)));

    case TCBResume:
        setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        return invokeTCB_Resume(
                   TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)));

    case TCBConfigure:
        return decodeTCBConfigure(cap, length, slot, buffer);

    case TCBSetPriority:
        return decodeSetPriority(cap, length, buffer);

    case TCBSetMCPriority:
        return decodeSetMCPriority(cap, length, buffer);

    case TCBSetSchedParams:
#ifdef CONFIG_KERNEL_MCS
        return decodeSetSchedParams(cap, length, slot, buffer);
#else
        return decodeSetSchedParams(cap, length, buffer);
#endif

    case TCBSetIPCBuffer:
        return decodeSetIPCBuffer(cap, length, slot, buffer);

    case TCBSetSpace:
        return decodeSetSpace(cap, length, slot, buffer);

    case TCBBindNotification:
        return decodeBindNotification(cap);

    case TCBUnbindNotification:
        return decodeUnbindNotification(cap);

#ifdef CONFIG_KERNEL_MCS
    case TCBSetTimeoutEndpoint:
        return decodeSetTimeoutEndpoint(cap, slot);
#else
#ifdef ENABLE_SMP_SUPPORT
    case TCBSetAffinity:
        return decodeSetAffinity(cap, length, buffer);
#endif /* ENABLE_SMP_SUPPORT */
#endif

        /* There is no notion of arch specific TCB invocations so this needs to go here */
#ifdef CONFIG_VTX
    case TCBSetEPTRoot:
        return decodeSetEPTRoot(cap);
#endif

#ifdef CONFIG_HARDWARE_DEBUG_API
    case TCBConfigureSingleStepping:
        return decodeConfigureSingleStepping(cap, buffer);

    case TCBSetBreakpoint:
        return decodeSetBreakpoint(cap, buffer);

    case TCBGetBreakpoint:
        return decodeGetBreakpoint(cap, buffer);

    case TCBUnsetBreakpoint:
        return decodeUnsetBreakpoint(cap, buffer);
#endif

    case TCBSetTLSBase:
        return decodeSetTLSBase(cap, length, buffer);

    default:
        /* Haskell: "throw IllegalOperation" */
        userError("TCB: Illegal operation.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }
}

enum CopyRegistersFlags {
    CopyRegisters_suspendSource = 0,
    CopyRegisters_resumeTarget = 1,
    CopyRegisters_transferFrame = 2,
    CopyRegisters_transferInteger = 3
};

exception_t decodeCopyRegisters(cap_t cap, word_t length, word_t *buffer)
{
    word_t transferArch;
    tcb_t *srcTCB;
    cap_t source_cap;
    word_t flags;

    if (length < 1 || current_extra_caps.excaprefs[0] == NULL) {
        userError("TCB CopyRegisters: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    flags = getSyscallArg(0, buffer);

    transferArch = Arch_decodeTransfer(flags >> 8);

    source_cap = current_extra_caps.excaprefs[0]->cap;

    if (cap_get_capType(source_cap) == cap_thread_cap) {
        srcTCB = TCB_PTR(cap_thread_cap_get_capTCBPtr(source_cap));
    } else {
        userError("TCB CopyRegisters: Invalid source TCB.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeTCB_CopyRegisters(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), srcTCB,
               flags & BIT(CopyRegisters_suspendSource),
               flags & BIT(CopyRegisters_resumeTarget),
               flags & BIT(CopyRegisters_transferFrame),
               flags & BIT(CopyRegisters_transferInteger),
               transferArch);

}

enum ReadRegistersFlags {
    ReadRegisters_suspend = 0
};

exception_t decodeReadRegisters(cap_t cap, word_t length, bool_t call,
                                word_t *buffer)
{
    word_t transferArch, flags, n;
    tcb_t *thread;

    if (length < 2) {
        userError("TCB ReadRegisters: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    flags = getSyscallArg(0, buffer);
    n     = getSyscallArg(1, buffer);

    if (n < 1 || n > n_frameRegisters + n_gpRegisters) {
        userError("TCB ReadRegisters: Attempted to read an invalid number of registers (%d).",
                  (int)n);
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 1;
        current_syscall_error.rangeErrorMax = n_frameRegisters +
                                              n_gpRegisters;
        return EXCEPTION_SYSCALL_ERROR;
    }

    transferArch = Arch_decodeTransfer(flags >> 8);

    thread = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));
    if (thread == NODE_STATE(ksCurThread)) {
        userError("TCB ReadRegisters: Attempted to read our own registers.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeTCB_ReadRegisters(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)),
               flags & BIT(ReadRegisters_suspend),
               n, transferArch, call);
}

enum WriteRegistersFlags {
    WriteRegisters_resume = 0
};

exception_t decodeWriteRegisters(cap_t cap, word_t length, word_t *buffer)
{
    word_t flags, w;
    word_t transferArch;
    tcb_t *thread;

    if (length < 2) {
        userError("TCB WriteRegisters: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    flags = getSyscallArg(0, buffer);
    w     = getSyscallArg(1, buffer);

    if (length - 2 < w) {
        userError("TCB WriteRegisters: Message too short for requested write size (%d/%d).",
                  (int)(length - 2), (int)w);
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    transferArch = Arch_decodeTransfer(flags >> 8);

    thread = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));
    if (thread == NODE_STATE(ksCurThread)) {
        userError("TCB WriteRegisters: Attempted to write our own registers.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeTCB_WriteRegisters(thread,
                                    flags & BIT(WriteRegisters_resume),
                                    w, transferArch, buffer);
}

#ifdef CONFIG_KERNEL_MCS
static bool_t validFaultHandler(cap_t cap)
{
    switch (cap_get_capType(cap)) {
    case cap_endpoint_cap:
        if (!cap_endpoint_cap_get_capCanSend(cap) ||
            (!cap_endpoint_cap_get_capCanGrant(cap) &&
             !cap_endpoint_cap_get_capCanGrantReply(cap))) {
            current_syscall_error.type = seL4_InvalidCapability;
            return false;
        }
        break;
    case cap_null_cap:
        /* just has no fault endpoint */
        break;
    default:
        current_syscall_error.type = seL4_InvalidCapability;
        return false;
    }
    return true;
}
#endif

/* TCBConfigure batches SetIPCBuffer and parts of SetSpace. */
exception_t decodeTCBConfigure(cap_t cap, word_t length, cte_t *slot, word_t *buffer)
{
    cte_t *bufferSlot, *cRootSlot, *vRootSlot;
    cap_t bufferCap, cRootCap, vRootCap;
    deriveCap_ret_t dc_ret;
    word_t cRootData, vRootData, bufferAddr;
#ifdef CONFIG_KERNEL_MCS
#define TCBCONFIGURE_ARGS 3
#else
#define TCBCONFIGURE_ARGS 4
#endif
    if (length < TCBCONFIGURE_ARGS || current_extra_caps.excaprefs[0] == NULL
        || current_extra_caps.excaprefs[1] == NULL
        || current_extra_caps.excaprefs[2] == NULL) {
        userError("TCB Configure: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

#ifdef CONFIG_KERNEL_MCS
    cRootData     = getSyscallArg(0, buffer);
    vRootData     = getSyscallArg(1, buffer);
    bufferAddr    = getSyscallArg(2, buffer);
#else
    cptr_t faultEP       = getSyscallArg(0, buffer);
    cRootData     = getSyscallArg(1, buffer);
    vRootData     = getSyscallArg(2, buffer);
    bufferAddr    = getSyscallArg(3, buffer);
#endif

    cRootSlot  = current_extra_caps.excaprefs[0];
    cRootCap   = current_extra_caps.excaprefs[0]->cap;
    vRootSlot  = current_extra_caps.excaprefs[1];
    vRootCap   = current_extra_caps.excaprefs[1]->cap;
    bufferSlot = current_extra_caps.excaprefs[2];
    bufferCap  = current_extra_caps.excaprefs[2]->cap;

    if (bufferAddr == 0) {
        bufferSlot = NULL;
    } else {
        dc_ret = deriveCap(bufferSlot, bufferCap);
        if (dc_ret.status != EXCEPTION_NONE) {
            return dc_ret.status;
        }
        bufferCap = dc_ret.cap;

        exception_t e = checkValidIPCBuffer(bufferAddr, bufferCap);
        if (e != EXCEPTION_NONE) {
            return e;
        }
    }

    if (slotCapLongRunningDelete(
            TCB_PTR_CTE_PTR(cap_thread_cap_get_capTCBPtr(cap), tcbCTable)) ||
        slotCapLongRunningDelete(
            TCB_PTR_CTE_PTR(cap_thread_cap_get_capTCBPtr(cap), tcbVTable))) {
        userError("TCB Configure: CSpace or VSpace currently being deleted.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (cRootData != 0) {
        cRootCap = updateCapData(false, cRootData, cRootCap);
    }

    dc_ret = deriveCap(cRootSlot, cRootCap);
    if (dc_ret.status != EXCEPTION_NONE) {
        return dc_ret.status;
    }
    cRootCap = dc_ret.cap;

    if (cap_get_capType(cRootCap) != cap_cnode_cap) {
        userError("TCB Configure: CSpace cap is invalid.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (vRootData != 0) {
        vRootCap = updateCapData(false, vRootData, vRootCap);
    }

    dc_ret = deriveCap(vRootSlot, vRootCap);
    if (dc_ret.status != EXCEPTION_NONE) {
        return dc_ret.status;
    }
    vRootCap = dc_ret.cap;

    if (!isValidVTableRoot(vRootCap)) {
        userError("TCB Configure: VSpace cap is invalid.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
#ifdef CONFIG_KERNEL_MCS
    return invokeTCB_ThreadControlCaps(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), slot,
               cap_null_cap_new(), NULL,
               cap_null_cap_new(), NULL,
               cRootCap, cRootSlot,
               vRootCap, vRootSlot,
               bufferAddr, bufferCap,
               bufferSlot, thread_control_caps_update_space |
               thread_control_caps_update_ipc_buffer);
#else
    return invokeTCB_ThreadControl(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), slot,
               faultEP, NULL_PRIO, NULL_PRIO,
               cRootCap, cRootSlot,
               vRootCap, vRootSlot,
               bufferAddr, bufferCap,
               bufferSlot, thread_control_update_space |
               thread_control_update_ipc_buffer);
#endif
}

exception_t decodeSetPriority(cap_t cap, word_t length, word_t *buffer)
{
    if (length < 1 || current_extra_caps.excaprefs[0] == NULL) {
        userError("TCB SetPriority: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    prio_t newPrio = getSyscallArg(0, buffer);
    cap_t authCap = current_extra_caps.excaprefs[0]->cap;

    if (cap_get_capType(authCap) != cap_thread_cap) {
        userError("Set priority: authority cap not a TCB.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcb_t *authTCB = TCB_PTR(cap_thread_cap_get_capTCBPtr(authCap));
    exception_t status = checkPrio(newPrio, authTCB);
    if (status != EXCEPTION_NONE) {
        userError("TCB SetPriority: Requested priority %lu too high (max %lu).",
                  (unsigned long) newPrio, (unsigned long) authTCB->tcbMCP);
        return status;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
#ifdef CONFIG_KERNEL_MCS
    return invokeTCB_ThreadControlSched(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), NULL,
               cap_null_cap_new(), NULL,
               NULL_PRIO, newPrio,
               NULL, thread_control_sched_update_priority);
#else
    return invokeTCB_ThreadControl(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), NULL,
               0, NULL_PRIO, newPrio,
               cap_null_cap_new(), NULL,
               cap_null_cap_new(), NULL,
               0, cap_null_cap_new(),
               NULL, thread_control_update_priority);
#endif
}

exception_t decodeSetMCPriority(cap_t cap, word_t length, word_t *buffer)
{
    if (length < 1 || current_extra_caps.excaprefs[0] == NULL) {
        userError("TCB SetMCPriority: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    prio_t newMcp = getSyscallArg(0, buffer);
    cap_t authCap = current_extra_caps.excaprefs[0]->cap;

    if (cap_get_capType(authCap) != cap_thread_cap) {
        userError("TCB SetMCPriority: authority cap not a TCB.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcb_t *authTCB = TCB_PTR(cap_thread_cap_get_capTCBPtr(authCap));
    exception_t status = checkPrio(newMcp, authTCB);
    if (status != EXCEPTION_NONE) {
        userError("TCB SetMCPriority: Requested maximum controlled priority %lu too high (max %lu).",
                  (unsigned long) newMcp, (unsigned long) authTCB->tcbMCP);
        return status;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
#ifdef CONFIG_KERNEL_MCS
    return invokeTCB_ThreadControlSched(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), NULL,
               cap_null_cap_new(), NULL,
               newMcp, NULL_PRIO,
               NULL, thread_control_sched_update_mcp);
#else
    return invokeTCB_ThreadControl(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), NULL,
               0, newMcp, NULL_PRIO,
               cap_null_cap_new(), NULL,
               cap_null_cap_new(), NULL,
               0, cap_null_cap_new(),
               NULL, thread_control_update_mcp);
#endif
}

#ifdef CONFIG_KERNEL_MCS
exception_t decodeSetTimeoutEndpoint(cap_t cap, cte_t *slot)
{
    if (current_extra_caps.excaprefs[0] == NULL) {
        userError("TCB SetSchedParams: Truncated message.");
        return EXCEPTION_SYSCALL_ERROR;
    }

    cte_t *thSlot = current_extra_caps.excaprefs[0];
    cap_t thCap   = current_extra_caps.excaprefs[0]->cap;

    /* timeout handler */
    if (!validFaultHandler(thCap)) {
        userError("TCB SetTimeoutEndpoint: timeout endpoint cap invalid.");
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeTCB_ThreadControlCaps(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), slot,
               cap_null_cap_new(), NULL,
               thCap, thSlot,
               cap_null_cap_new(), NULL,
               cap_null_cap_new(), NULL,
               0, cap_null_cap_new(), NULL,
               thread_control_caps_update_timeout);
}
#endif

#ifdef CONFIG_KERNEL_MCS
exception_t decodeSetSchedParams(cap_t cap, word_t length, cte_t *slot, word_t *buffer)
#else
exception_t decodeSetSchedParams(cap_t cap, word_t length, word_t *buffer)
#endif
{
    if (length < 2 || current_extra_caps.excaprefs[0] == NULL
#ifdef CONFIG_KERNEL_MCS
        || current_extra_caps.excaprefs[1] == NULL || current_extra_caps.excaprefs[2] == NULL
#endif
       ) {
        userError("TCB SetSchedParams: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    prio_t newMcp = getSyscallArg(0, buffer);
    prio_t newPrio = getSyscallArg(1, buffer);
    cap_t authCap = current_extra_caps.excaprefs[0]->cap;
#ifdef CONFIG_KERNEL_MCS
    cap_t scCap   = current_extra_caps.excaprefs[1]->cap;
    cte_t *fhSlot = current_extra_caps.excaprefs[2];
    cap_t fhCap   = current_extra_caps.excaprefs[2]->cap;
#endif

    if (cap_get_capType(authCap) != cap_thread_cap) {
        userError("TCB SetSchedParams: authority cap not a TCB.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcb_t *authTCB = TCB_PTR(cap_thread_cap_get_capTCBPtr(authCap));
    exception_t status = checkPrio(newMcp, authTCB);
    if (status != EXCEPTION_NONE) {
        userError("TCB SetSchedParams: Requested maximum controlled priority %lu too high (max %lu).",
                  (unsigned long) newMcp, (unsigned long) authTCB->tcbMCP);
        return status;
    }

    status = checkPrio(newPrio, authTCB);
    if (status != EXCEPTION_NONE) {
        userError("TCB SetSchedParams: Requested priority %lu too high (max %lu).",
                  (unsigned long) newPrio, (unsigned long) authTCB->tcbMCP);
        return status;
    }

#ifdef CONFIG_KERNEL_MCS
    tcb_t *tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));
    sched_context_t *sc = NULL;
    switch (cap_get_capType(scCap)) {
    case cap_sched_context_cap:
        sc = SC_PTR(cap_sched_context_cap_get_capSCPtr(scCap));
        if (tcb->tcbSchedContext) {
            userError("TCB Configure: tcb already has a scheduling context.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        if (sc->scTcb) {
            userError("TCB Configure: sched contextext already bound.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        break;
    case cap_null_cap:
        if (tcb == NODE_STATE(ksCurThread)) {
            userError("TCB SetSchedParams: Cannot change sched_context of current thread");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        break;
    default:
        userError("TCB Configure: sched context cap invalid.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 2;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (!validFaultHandler(fhCap)) {
        userError("TCB Configure: fault endpoint cap invalid.");
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 3;
        return EXCEPTION_SYSCALL_ERROR;
    }
#endif
    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
#ifdef CONFIG_KERNEL_MCS
    return invokeTCB_ThreadControlSched(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), slot,
               fhCap, fhSlot,
               newMcp, newPrio,
               sc,
               thread_control_sched_update_mcp |
               thread_control_sched_update_priority |
               thread_control_sched_update_sc |
               thread_control_sched_update_fault);
#else
    return invokeTCB_ThreadControl(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), NULL,
               0, newMcp, newPrio,
               cap_null_cap_new(), NULL,
               cap_null_cap_new(), NULL,
               0, cap_null_cap_new(),
               NULL, thread_control_update_mcp |
               thread_control_update_priority);
#endif
}


exception_t decodeSetIPCBuffer(cap_t cap, word_t length, cte_t *slot, word_t *buffer)
{
    cptr_t cptr_bufferPtr;
    cap_t bufferCap;
    cte_t *bufferSlot;

    if (length < 1 || current_extra_caps.excaprefs[0] == NULL) {
        userError("TCB SetIPCBuffer: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    cptr_bufferPtr  = getSyscallArg(0, buffer);
    bufferSlot = current_extra_caps.excaprefs[0];
    bufferCap  = current_extra_caps.excaprefs[0]->cap;

    if (cptr_bufferPtr == 0) {
        bufferSlot = NULL;
    } else {
        exception_t e;
        deriveCap_ret_t dc_ret;

        dc_ret = deriveCap(bufferSlot, bufferCap);
        if (dc_ret.status != EXCEPTION_NONE) {
            return dc_ret.status;
        }
        bufferCap = dc_ret.cap;
        e = checkValidIPCBuffer(cptr_bufferPtr, bufferCap);
        if (e != EXCEPTION_NONE) {
            return e;
        }
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
#ifdef CONFIG_KERNEL_MCS
    return invokeTCB_ThreadControlCaps(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), slot,
               cap_null_cap_new(), NULL,
               cap_null_cap_new(), NULL,
               cap_null_cap_new(), NULL,
               cap_null_cap_new(), NULL,
               cptr_bufferPtr, bufferCap,
               bufferSlot, thread_control_caps_update_ipc_buffer);
#else
    return invokeTCB_ThreadControl(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), slot,
               0, NULL_PRIO, NULL_PRIO,
               cap_null_cap_new(), NULL,
               cap_null_cap_new(), NULL,
               cptr_bufferPtr, bufferCap,
               bufferSlot, thread_control_update_ipc_buffer);

#endif
}

#ifdef CONFIG_KERNEL_MCS
#define DECODE_SET_SPACE_PARAMS 2
#else
#define DECODE_SET_SPACE_PARAMS 3
#endif
exception_t decodeSetSpace(cap_t cap, word_t length, cte_t *slot, word_t *buffer)
{
    word_t cRootData, vRootData;
    cte_t *cRootSlot, *vRootSlot;
    cap_t cRootCap, vRootCap;
    deriveCap_ret_t dc_ret;

    if (length < DECODE_SET_SPACE_PARAMS || current_extra_caps.excaprefs[0] == NULL
        || current_extra_caps.excaprefs[1] == NULL
#ifdef CONFIG_KERNEL_MCS
        || current_extra_caps.excaprefs[2] == NULL
#endif
       ) {
        userError("TCB SetSpace: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

#ifdef CONFIG_KERNEL_MCS
    cRootData = getSyscallArg(0, buffer);
    vRootData = getSyscallArg(1, buffer);

    cte_t *fhSlot     = current_extra_caps.excaprefs[0];
    cap_t fhCap      = current_extra_caps.excaprefs[0]->cap;
    cRootSlot  = current_extra_caps.excaprefs[1];
    cRootCap   = current_extra_caps.excaprefs[1]->cap;
    vRootSlot  = current_extra_caps.excaprefs[2];
    vRootCap   = current_extra_caps.excaprefs[2]->cap;
#else
    cptr_t faultEP   = getSyscallArg(0, buffer);
    cRootData = getSyscallArg(1, buffer);
    vRootData = getSyscallArg(2, buffer);

    cRootSlot  = current_extra_caps.excaprefs[0];
    cRootCap   = current_extra_caps.excaprefs[0]->cap;
    vRootSlot  = current_extra_caps.excaprefs[1];
    vRootCap   = current_extra_caps.excaprefs[1]->cap;
#endif

    if (slotCapLongRunningDelete(
            TCB_PTR_CTE_PTR(cap_thread_cap_get_capTCBPtr(cap), tcbCTable)) ||
        slotCapLongRunningDelete(
            TCB_PTR_CTE_PTR(cap_thread_cap_get_capTCBPtr(cap), tcbVTable))) {
        userError("TCB SetSpace: CSpace or VSpace currently being deleted.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (cRootData != 0) {
        cRootCap = updateCapData(false, cRootData, cRootCap);
    }

    dc_ret = deriveCap(cRootSlot, cRootCap);
    if (dc_ret.status != EXCEPTION_NONE) {
        return dc_ret.status;
    }
    cRootCap = dc_ret.cap;

    if (cap_get_capType(cRootCap) != cap_cnode_cap) {
        userError("TCB SetSpace: Invalid CNode cap.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (vRootData != 0) {
        vRootCap = updateCapData(false, vRootData, vRootCap);
    }

    dc_ret = deriveCap(vRootSlot, vRootCap);
    if (dc_ret.status != EXCEPTION_NONE) {
        return dc_ret.status;
    }
    vRootCap = dc_ret.cap;

    if (!isValidVTableRoot(vRootCap)) {
        userError("TCB SetSpace: Invalid VSpace cap.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

#ifdef CONFIG_KERNEL_MCS
    /* fault handler */
    if (!validFaultHandler(fhCap)) {
        userError("TCB SetSpace: fault endpoint cap invalid.");
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }
#endif

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
#ifdef CONFIG_KERNEL_MCS
    return invokeTCB_ThreadControlCaps(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), slot,
               fhCap, fhSlot,
               cap_null_cap_new(), NULL,
               cRootCap, cRootSlot,
               vRootCap, vRootSlot,
               0, cap_null_cap_new(), NULL, thread_control_caps_update_space | thread_control_caps_update_fault);
#else
    return invokeTCB_ThreadControl(
               TCB_PTR(cap_thread_cap_get_capTCBPtr(cap)), slot,
               faultEP,
               NULL_PRIO, NULL_PRIO,
               cRootCap, cRootSlot,
               vRootCap, vRootSlot,
               0, cap_null_cap_new(), NULL, thread_control_update_space);
#endif
}

exception_t decodeDomainInvocation(word_t invLabel, word_t length, word_t *buffer)
{
    word_t domain;
    cap_t tcap;

    if (unlikely(invLabel != DomainSetSet)) {
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (unlikely(length == 0)) {
        userError("Domain Configure: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    } else {
        domain = getSyscallArg(0, buffer);
        if (domain >= CONFIG_NUM_DOMAINS) {
            userError("Domain Configure: invalid domain (%lu >= %u).",
                      domain, CONFIG_NUM_DOMAINS);
            current_syscall_error.type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
    }

    if (unlikely(current_extra_caps.excaprefs[0] == NULL)) {
        userError("Domain Configure: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcap = current_extra_caps.excaprefs[0]->cap;
    if (unlikely(cap_get_capType(tcap) != cap_thread_cap)) {
        userError("Domain Configure: thread cap required.");
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    setDomain(TCB_PTR(cap_thread_cap_get_capTCBPtr(tcap)), domain);
    return EXCEPTION_NONE;
}

exception_t decodeBindNotification(cap_t cap)
{
    notification_t *ntfnPtr;
    tcb_t *tcb;
    cap_t ntfn_cap;

    if (current_extra_caps.excaprefs[0] == NULL) {
        userError("TCB BindNotification: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));

    if (tcb->tcbBoundNotification) {
        userError("TCB BindNotification: TCB already has a bound notification.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    ntfn_cap = current_extra_caps.excaprefs[0]->cap;

    if (cap_get_capType(ntfn_cap) == cap_notification_cap) {
        ntfnPtr = NTFN_PTR(cap_notification_cap_get_capNtfnPtr(ntfn_cap));
    } else {
        userError("TCB BindNotification: Notification is invalid.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (!cap_notification_cap_get_capNtfnCanReceive(ntfn_cap)) {
        userError("TCB BindNotification: Insufficient access rights");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if ((tcb_t *)notification_ptr_get_ntfnQueue_head(ntfnPtr)
        || (tcb_t *)notification_ptr_get_ntfnBoundTCB(ntfnPtr)) {
        userError("TCB BindNotification: Notification cannot be bound.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }


    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeTCB_NotificationControl(tcb, ntfnPtr);
}

exception_t decodeUnbindNotification(cap_t cap)
{
    tcb_t *tcb;

    tcb = TCB_PTR(cap_thread_cap_get_capTCBPtr(cap));

    if (!tcb->tcbBoundNotification) {
        userError("TCB UnbindNotification: TCB already has no bound Notification.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeTCB_NotificationControl(tcb, NULL);
}

/* The following functions sit in the preemption monad and implement the
 * preemptible, non-faulting bottom end of a TCB invocation. */
exception_t invokeTCB_Suspend(tcb_t *thread)
{
    suspend(thread);
    return EXCEPTION_NONE;
}

exception_t invokeTCB_Resume(tcb_t *thread)
{
    restart(thread);
    return EXCEPTION_NONE;
}

#ifdef CONFIG_KERNEL_MCS
static NO_INLINE exception_t installTCBCap(tcb_t *target, cap_t tCap, cte_t *slot,
                                        tcb_cnode_index_t index, cap_t newCap, cte_t *srcSlot)
{
    cte_t *rootSlot = TCB_PTR_CTE_PTR(target, index);
    exception_t e = cteDelete(rootSlot, true);
    if (e != EXCEPTION_NONE) {
        return e;
    }

    /* cteDelete on a cap installed in the tcb cannot fail */
    if (sameObjectAs(newCap, srcSlot->cap) &&
        sameObjectAs(tCap, slot->cap)) {
        cteInsert(newCap, srcSlot, rootSlot);
    }
    return e;
}
#endif

#ifdef CONFIG_KERNEL_MCS
exception_t invokeTCB_ThreadControlCaps(tcb_t *target, cte_t *slot,
                                        cap_t fh_newCap, cte_t *fh_srcSlot,
                                        cap_t th_newCap, cte_t *th_srcSlot,
                                        cap_t cRoot_newCap, cte_t *cRoot_srcSlot,
                                        cap_t vRoot_newCap, cte_t *vRoot_srcSlot,
                                        word_t bufferAddr, cap_t bufferCap,
                                        cte_t *bufferSrcSlot,
                                        thread_control_flag_t updateFlags)
{
    exception_t e;
    cap_t tCap = cap_thread_cap_new((word_t)target);

    if (updateFlags & thread_control_caps_update_fault) {
        e = installTCBCap(target, tCap, slot, tcbFaultHandler, fh_newCap, fh_srcSlot);
        if (e != EXCEPTION_NONE) {
            return e;
        }

    }

    if (updateFlags & thread_control_caps_update_timeout) {
        e = installTCBCap(target, tCap, slot, tcbTimeoutHandler, th_newCap, th_srcSlot);
        if (e != EXCEPTION_NONE) {
            return e;
        }
    }

    if (updateFlags & thread_control_caps_update_space) {
        e = installTCBCap(target, tCap, slot, tcbCTable, cRoot_newCap, cRoot_srcSlot);
        if (e != EXCEPTION_NONE) {
            return e;
        }

        e = installTCBCap(target, tCap, slot, tcbVTable, vRoot_newCap, vRoot_srcSlot);
        if (e != EXCEPTION_NONE) {
            return e;
        }
    }

    if (updateFlags & thread_control_caps_update_ipc_buffer) {
        cte_t *bufferSlot;

        bufferSlot = TCB_PTR_CTE_PTR(target, tcbBuffer);
        e = cteDelete(bufferSlot, true);
        if (e != EXCEPTION_NONE) {
            return e;
        }
        target->tcbIPCBuffer = bufferAddr;

        if (bufferSrcSlot && sameObjectAs(bufferCap, bufferSrcSlot->cap) &&
            sameObjectAs(tCap, slot->cap)) {
            cteInsert(bufferCap, bufferSrcSlot, bufferSlot);
        }

        if (target == NODE_STATE(ksCurThread)) {
            rescheduleRequired();
        }
    }

    return EXCEPTION_NONE;
}
#else
exception_t invokeTCB_ThreadControl(tcb_t *target, cte_t *slot,
                                    cptr_t faultep, prio_t mcp, prio_t priority,
                                    cap_t cRoot_newCap, cte_t *cRoot_srcSlot,
                                    cap_t vRoot_newCap, cte_t *vRoot_srcSlot,
                                    word_t bufferAddr, cap_t bufferCap,
                                    cte_t *bufferSrcSlot,
                                    thread_control_flag_t updateFlags)
{
    exception_t e;
    cap_t tCap = cap_thread_cap_new((word_t)target);

    if (updateFlags & thread_control_update_space) {
        target->tcbFaultHandler = faultep;
    }

    if (updateFlags & thread_control_update_mcp) {
        setMCPriority(target, mcp);
    }

    if (updateFlags & thread_control_update_space) {
        cte_t *rootSlot;

        rootSlot = TCB_PTR_CTE_PTR(target, tcbCTable);
        e = cteDelete(rootSlot, true);
        if (e != EXCEPTION_NONE) {
            return e;
        }
        if (sameObjectAs(cRoot_newCap, cRoot_srcSlot->cap) &&
            sameObjectAs(tCap, slot->cap)) {
            cteInsert(cRoot_newCap, cRoot_srcSlot, rootSlot);
        }
    }

    if (updateFlags & thread_control_update_space) {
        cte_t *rootSlot;

        rootSlot = TCB_PTR_CTE_PTR(target, tcbVTable);
        e = cteDelete(rootSlot, true);
        if (e != EXCEPTION_NONE) {
            return e;
        }
        if (sameObjectAs(vRoot_newCap, vRoot_srcSlot->cap) &&
            sameObjectAs(tCap, slot->cap)) {
            cteInsert(vRoot_newCap, vRoot_srcSlot, rootSlot);
        }
    }

    if (updateFlags & thread_control_update_ipc_buffer) {
        cte_t *bufferSlot;

        bufferSlot = TCB_PTR_CTE_PTR(target, tcbBuffer);
        e = cteDelete(bufferSlot, true);
        if (e != EXCEPTION_NONE) {
            return e;
        }
        target->tcbIPCBuffer = bufferAddr;

        if (bufferSrcSlot && sameObjectAs(bufferCap, bufferSrcSlot->cap) &&
            sameObjectAs(tCap, slot->cap)) {
            cteInsert(bufferCap, bufferSrcSlot, bufferSlot);
        }

        if (target == NODE_STATE(ksCurThread)) {
            rescheduleRequired();
        }
    }

    if (updateFlags & thread_control_update_priority) {
        setPriority(target, priority);
    }

    return EXCEPTION_NONE;
}
#endif

#ifdef CONFIG_KERNEL_MCS
exception_t invokeTCB_ThreadControlSched(tcb_t *target, cte_t *slot,
                                         cap_t fh_newCap, cte_t *fh_srcSlot,
                                         prio_t mcp, prio_t priority,
                                         sched_context_t *sc,
                                         thread_control_flag_t updateFlags)
{
    if (updateFlags & thread_control_sched_update_fault) {
        cap_t tCap = cap_thread_cap_new((word_t)target);
        exception_t e = installTCBCap(target, tCap, slot, tcbFaultHandler, fh_newCap, fh_srcSlot);
        if (e != EXCEPTION_NONE) {
            return e;
        }
    }

    if (updateFlags & thread_control_sched_update_mcp) {
        setMCPriority(target, mcp);
    }

    if (updateFlags & thread_control_sched_update_priority) {
        setPriority(target, priority);
    }

    if (updateFlags & thread_control_sched_update_sc) {
        if (sc != NULL && sc != target->tcbSchedContext) {
            schedContext_bindTCB(sc, target);
        } else if (sc == NULL && target->tcbSchedContext != NULL) {
            schedContext_unbindTCB(target->tcbSchedContext, target);
        }
    }

    return EXCEPTION_NONE;
}
#endif

exception_t invokeTCB_CopyRegisters(tcb_t *dest, tcb_t *tcb_src,
                                    bool_t suspendSource, bool_t resumeTarget,
                                    bool_t transferFrame, bool_t transferInteger,
                                    word_t transferArch)
{
    if (suspendSource) {
        suspend(tcb_src);
    }

    if (resumeTarget) {
        restart(dest);
    }

    if (transferFrame) {
        word_t i;
        word_t v;
        word_t pc;

        for (i = 0; i < n_frameRegisters; i++) {
            v = getRegister(tcb_src, frameRegisters[i]);
            setRegister(dest, frameRegisters[i], v);
        }

        pc = getRestartPC(dest);
        setNextPC(dest, pc);
    }

    if (transferInteger) {
        word_t i;
        word_t v;

        for (i = 0; i < n_gpRegisters; i++) {
            v = getRegister(tcb_src, gpRegisters[i]);
            setRegister(dest, gpRegisters[i], v);
        }
    }

    Arch_postModifyRegisters(dest);

    if (dest == NODE_STATE(ksCurThread)) {
        /* If we modified the current thread we may need to reschedule
         * due to changing registers are only reloaded in Arch_switchToThread */
        rescheduleRequired();
    }

    return Arch_performTransfer(transferArch, tcb_src, dest);
}

/* ReadRegisters is a special case: replyFromKernel & setMRs are
 * unfolded here, in order to avoid passing the large reply message up
 * to the top level in a global (and double-copying). We prevent the
 * top-level replyFromKernel_success_empty() from running by setting the
 * thread state. Retype does this too.
 */
exception_t invokeTCB_ReadRegisters(tcb_t *tcb_src, bool_t suspendSource,
                                    word_t n, word_t arch, bool_t call)
{
    word_t i, j;
    exception_t e;
    tcb_t *thread;

    thread = NODE_STATE(ksCurThread);

    if (suspendSource) {
        suspend(tcb_src);
    }

    e = Arch_performTransfer(arch, tcb_src, NODE_STATE(ksCurThread));
    if (e != EXCEPTION_NONE) {
        return e;
    }

    if (call) {
        word_t *ipcBuffer;

        ipcBuffer = lookupIPCBuffer(true, thread);

        setRegister(thread, badgeRegister, 0);

        for (i = 0; i < n && i < n_frameRegisters && i < n_msgRegisters; i++) {
            setRegister(thread, msgRegisters[i],
                        getRegister(tcb_src, frameRegisters[i]));
        }

        if (ipcBuffer != NULL && i < n && i < n_frameRegisters) {
            for (; i < n && i < n_frameRegisters; i++) {
                ipcBuffer[i + 1] = getRegister(tcb_src, frameRegisters[i]);
            }
        }

        j = i;

        for (i = 0; i < n_gpRegisters && i + n_frameRegisters < n
             && i + n_frameRegisters < n_msgRegisters; i++) {
            setRegister(thread, msgRegisters[i + n_frameRegisters],
                        getRegister(tcb_src, gpRegisters[i]));
        }

        if (ipcBuffer != NULL && i < n_gpRegisters
            && i + n_frameRegisters < n) {
            for (; i < n_gpRegisters && i + n_frameRegisters < n; i++) {
                ipcBuffer[i + n_frameRegisters + 1] =
                    getRegister(tcb_src, gpRegisters[i]);
            }
        }

        setRegister(thread, msgInfoRegister, wordFromMessageInfo(
                        seL4_MessageInfo_new(0, 0, 0, i + j)));
    }
    setThreadState(thread, ThreadState_Running);

    return EXCEPTION_NONE;
}

exception_t invokeTCB_WriteRegisters(tcb_t *dest, bool_t resumeTarget,
                                     word_t n, word_t arch, word_t *buffer)
{
    word_t i;
    word_t pc;
    exception_t e;
    bool_t archInfo;

    e = Arch_performTransfer(arch, NODE_STATE(ksCurThread), dest);
    if (e != EXCEPTION_NONE) {
        return e;
    }

    if (n > n_frameRegisters + n_gpRegisters) {
        n = n_frameRegisters + n_gpRegisters;
    }

    archInfo = Arch_getSanitiseRegisterInfo(dest);

    for (i = 0; i < n_frameRegisters && i < n; i++) {
        /* Offset of 2 to get past the initial syscall arguments */
        setRegister(dest, frameRegisters[i],
                    sanitiseRegister(frameRegisters[i],
                                     getSyscallArg(i + 2, buffer), archInfo));
    }

    for (i = 0; i < n_gpRegisters && i + n_frameRegisters < n; i++) {
        setRegister(dest, gpRegisters[i],
                    sanitiseRegister(gpRegisters[i],
                                     getSyscallArg(i + n_frameRegisters + 2,
                                                   buffer), archInfo));
    }

    pc = getRestartPC(dest);
    setNextPC(dest, pc);

    Arch_postModifyRegisters(dest);

    if (resumeTarget) {
        restart(dest);
    }

    if (dest == NODE_STATE(ksCurThread)) {
        /* If we modified the current thread we may need to reschedule
         * due to changing registers are only reloaded in Arch_switchToThread */
        rescheduleRequired();
    }

    return EXCEPTION_NONE;
}

exception_t invokeTCB_NotificationControl(tcb_t *tcb, notification_t *ntfnPtr)
{
    if (ntfnPtr) {
        bindNotification(tcb, ntfnPtr);
    } else {
        unbindNotification(tcb);
    }

    return EXCEPTION_NONE;
}

#ifdef CONFIG_DEBUG_BUILD
void setThreadName(tcb_t *tcb, const char *name)
{
    strlcpy(TCB_PTR_DEBUG_PTR(tcb)->tcbName, name, TCB_NAME_LENGTH);
}
#endif

word_t setMRs_syscall_error(tcb_t *thread, word_t *receiveIPCBuffer)
{
    switch (current_syscall_error.type) {
    case seL4_InvalidArgument:
        return setMR(thread, receiveIPCBuffer, 0,
                     current_syscall_error.invalidArgumentNumber);

    case seL4_InvalidCapability:
        return setMR(thread, receiveIPCBuffer, 0,
                     current_syscall_error.invalidCapNumber);

    case seL4_IllegalOperation:
        return 0;

    case seL4_RangeError:
        setMR(thread, receiveIPCBuffer, 0,
              current_syscall_error.rangeErrorMin);
        return setMR(thread, receiveIPCBuffer, 1,
                     current_syscall_error.rangeErrorMax);

    case seL4_AlignmentError:
        return 0;

    case seL4_FailedLookup:
        setMR(thread, receiveIPCBuffer, 0,
              current_syscall_error.failedLookupWasSource ? 1 : 0);
        return setMRs_lookup_failure(thread, receiveIPCBuffer,
                                     current_lookup_fault, 1);

    case seL4_TruncatedMessage:
    case seL4_DeleteFirst:
    case seL4_RevokeFirst:
        return 0;
    case seL4_NotEnoughMemory:
        return setMR(thread, receiveIPCBuffer, 0,
                     current_syscall_error.memoryLeft);
    default:
        fail("Invalid syscall error");
    }
}
#line 1 "/home/koc034/Documents/newver/seL4/src/object/untyped.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <types.h>
#include <api/failures.h>
#include <api/syscall.h>
#include <api/invocation.h>
#include <machine/io.h>
#include <object/structures.h>
#include <object/untyped.h>
#include <object/objecttype.h>
#include <object/cnode.h>
#include <kernel/cspace.h>
#include <kernel/thread.h>
#include <util.h>

static word_t alignUp(word_t baseValue, word_t alignment)
{
    return (baseValue + (BIT(alignment) - 1)) & ~MASK(alignment);
}

exception_t decodeUntypedInvocation(word_t invLabel, word_t length, cte_t *slot,
                                    cap_t cap, bool_t call, word_t *buffer)
{
    word_t newType, userObjSize, nodeIndex;
    word_t nodeDepth, nodeOffset, nodeWindow;
    cte_t *rootSlot UNUSED;
    exception_t status;
    cap_t nodeCap;
    lookupSlot_ret_t lu_ret;
    word_t nodeSize;
    word_t i;
    cte_t *destCNode;
    word_t freeRef, alignedFreeRef, objectSize, untypedFreeBytes;
    word_t freeIndex;
    bool_t deviceMemory;
    bool_t reset;

    /* Ensure operation is valid. */
    if (invLabel != UntypedRetype) {
        userError("Untyped cap: Illegal operation attempted.");
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Ensure message length valid. */
    if (length < 6 || current_extra_caps.excaprefs[0] == NULL) {
        userError("Untyped invocation: Truncated message.");
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Fetch arguments. */
    newType     = getSyscallArg(0, buffer);
    userObjSize = getSyscallArg(1, buffer);
    nodeIndex   = getSyscallArg(2, buffer);
    nodeDepth   = getSyscallArg(3, buffer);
    nodeOffset  = getSyscallArg(4, buffer);
    nodeWindow  = getSyscallArg(5, buffer);

    rootSlot = current_extra_caps.excaprefs[0];

    /* Is the requested object type valid? */
    if (newType >= seL4_ObjectTypeCount) {
        userError("Untyped Retype: Invalid object type.");
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 0;
        return EXCEPTION_SYSCALL_ERROR;
    }

    objectSize = getObjectSize(newType, userObjSize);

    /* Exclude impossibly large object sizes. getObjectSize can overflow if userObjSize
       is close to 2^wordBits, which is nonsensical in any case, so we check that this
       did not happen. userObjSize will always need to be less than wordBits. */
    if (userObjSize >= wordBits || objectSize > seL4_MaxUntypedBits) {
        userError("Untyped Retype: Invalid object size.");
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 0;
        current_syscall_error.rangeErrorMax = seL4_MaxUntypedBits;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* If the target object is a CNode, is it at least size 1? */
    if (newType == seL4_CapTableObject && userObjSize == 0) {
        userError("Untyped Retype: Requested CapTable size too small.");
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* If the target object is a Untyped, is it at least size 4? */
    if (newType == seL4_UntypedObject && userObjSize < seL4_MinUntypedBits) {
        userError("Untyped Retype: Requested UntypedItem size too small.");
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

#ifdef CONFIG_KERNEL_MCS
    if (newType == seL4_SchedContextObject && userObjSize < seL4_MinSchedContextBits) {
        userError("Untyped retype: Requested a scheduling context too small.");
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }
#endif

    /* Lookup the destination CNode (where our caps will be placed in). */
    if (nodeDepth == 0) {
        nodeCap = current_extra_caps.excaprefs[0]->cap;
    } else {
        cap_t rootCap = current_extra_caps.excaprefs[0]->cap;
        lu_ret = lookupTargetSlot(rootCap, nodeIndex, nodeDepth);
        if (lu_ret.status != EXCEPTION_NONE) {
            userError("Untyped Retype: Invalid destination address.");
            return lu_ret.status;
        }
        nodeCap = lu_ret.slot->cap;
    }

    /* Is the destination actually a CNode? */
    if (cap_get_capType(nodeCap) != cap_cnode_cap) {
        userError("Untyped Retype: Destination cap invalid or read-only.");
        current_syscall_error.type = seL4_FailedLookup;
        current_syscall_error.failedLookupWasSource = 0;
        current_lookup_fault = lookup_fault_missing_capability_new(nodeDepth);
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Is the region where the user wants to put the caps valid? */
    nodeSize = 1ul << cap_cnode_cap_get_capCNodeRadix(nodeCap);
    if (nodeOffset > nodeSize - 1) {
        userError("Untyped Retype: Destination node offset #%d too large.",
                  (int)nodeOffset);
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 0;
        current_syscall_error.rangeErrorMax = nodeSize - 1;
        return EXCEPTION_SYSCALL_ERROR;
    }
    if (nodeWindow < 1 || nodeWindow > CONFIG_RETYPE_FAN_OUT_LIMIT) {
        userError("Untyped Retype: Number of requested objects (%d) too small or large.",
                  (int)nodeWindow);
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 1;
        current_syscall_error.rangeErrorMax = CONFIG_RETYPE_FAN_OUT_LIMIT;
        return EXCEPTION_SYSCALL_ERROR;
    }
    if (nodeWindow > nodeSize - nodeOffset) {
        userError("Untyped Retype: Requested destination window overruns size of node.");
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 1;
        current_syscall_error.rangeErrorMax = nodeSize - nodeOffset;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Ensure that the destination slots are all empty. */
    destCNode = CTE_PTR(cap_cnode_cap_get_capCNodePtr(nodeCap));
    for (i = nodeOffset; i < nodeOffset + nodeWindow; i++) {
        status = ensureEmptySlot(destCNode + i);
        if (status != EXCEPTION_NONE) {
            userError("Untyped Retype: Slot #%d in destination window non-empty.",
                      (int)i);
            return status;
        }
    }

    /*
     * Determine where in the Untyped region we should start allocating new
     * objects.
     *
     * If we have no children, we can start allocating from the beginning of
     * our untyped, regardless of what the "free" value in the cap states.
     * (This may happen if all of the objects beneath us got deleted).
     *
     * If we have children, we just keep allocating from the "free" value
     * recorded in the cap.
     */
    status = ensureNoChildren(slot);
    if (status != EXCEPTION_NONE) {
        freeIndex = cap_untyped_cap_get_capFreeIndex(cap);
        reset = false;
    } else {
        freeIndex = 0;
        reset = true;
    }
    freeRef = GET_FREE_REF(cap_untyped_cap_get_capPtr(cap), freeIndex);

    /*
     * Determine the maximum number of objects we can create, and return an
     * error if we don't have enough space.
     *
     * We don't need to worry about alignment in this case, because if anything
     * fits, it will also fit aligned up (by packing it on the right hand side
     * of the untyped).
     */
    untypedFreeBytes = BIT(cap_untyped_cap_get_capBlockSize(cap)) -
                       FREE_INDEX_TO_OFFSET(freeIndex);

    if ((untypedFreeBytes >> objectSize) < nodeWindow) {
        userError("Untyped Retype: Insufficient memory "
                  "(%lu * %lu bytes needed, %lu bytes available).",
                  (word_t)nodeWindow,
                  (objectSize >= wordBits ? -1 : (1ul << objectSize)),
                  (word_t)(untypedFreeBytes));
        current_syscall_error.type = seL4_NotEnoughMemory;
        current_syscall_error.memoryLeft = untypedFreeBytes;
        return EXCEPTION_SYSCALL_ERROR;
    }

    deviceMemory = cap_untyped_cap_get_capIsDevice(cap);
    if ((deviceMemory && !Arch_isFrameType(newType))
        && newType != seL4_UntypedObject) {
        userError("Untyped Retype: Creating kernel objects with device untyped");
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Align up the free region so that it is aligned to the target object's
     * size. */
    alignedFreeRef = alignUp(freeRef, objectSize);

    /* Perform the retype. */
    setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
    return invokeUntyped_Retype(slot, reset,
                                (void *)alignedFreeRef, newType, userObjSize,
                                destCNode, nodeOffset, nodeWindow, deviceMemory);
}

static exception_t resetUntypedCap(cte_t *srcSlot)
{
    cap_t prev_cap = srcSlot->cap;
    word_t block_size = cap_untyped_cap_get_capBlockSize(prev_cap);
    void *regionBase = WORD_PTR(cap_untyped_cap_get_capPtr(prev_cap));
    int chunk = CONFIG_RESET_CHUNK_BITS;
    word_t offset = FREE_INDEX_TO_OFFSET(cap_untyped_cap_get_capFreeIndex(prev_cap));
    exception_t status;
    bool_t deviceMemory = cap_untyped_cap_get_capIsDevice(prev_cap);

    if (offset == 0) {
        return EXCEPTION_NONE;
    }

    /** AUXUPD: "(True, typ_region_bytes (ptr_val \<acute>regionBase)
        (unat \<acute>block_size))" */
    /** GHOSTUPD: "(True, gs_clear_region (ptr_val \<acute>regionBase)
        (unat \<acute>block_size))" */

    if (deviceMemory || block_size < chunk) {
        if (! deviceMemory) {
            clearMemory(regionBase, block_size);
        }
        srcSlot->cap = cap_untyped_cap_set_capFreeIndex(prev_cap, 0);
    } else {
        for (offset = ROUND_DOWN(offset - 1, chunk);
             offset != - BIT(chunk); offset -= BIT(chunk)) {
            clearMemory(GET_OFFSET_FREE_PTR(regionBase, offset), chunk);
            srcSlot->cap = cap_untyped_cap_set_capFreeIndex(prev_cap, OFFSET_TO_FREE_INDEX(offset));
            status = preemptionPoint();
            if (status != EXCEPTION_NONE) {
                return status;
            }
        }
    }
    return EXCEPTION_NONE;
}

exception_t invokeUntyped_Retype(cte_t *srcSlot,
                                 bool_t reset, void *retypeBase,
                                 object_t newType, word_t userSize,
                                 cte_t *destCNode, word_t destOffset, word_t destLength,
                                 bool_t deviceMemory)
{
    word_t freeRef;
    word_t totalObjectSize;
    void *regionBase = WORD_PTR(cap_untyped_cap_get_capPtr(srcSlot->cap));
    exception_t status;

    if (reset) {
        status = resetUntypedCap(srcSlot);
        if (status != EXCEPTION_NONE) {
            return status;
        }
    }

    /* Update the amount of free space left in this untyped cap.
     *
     * Note that userSize is not necessarily the true size of the object in
     * memory. In the case where newType is seL4_CapTableObject, the size is
     * transformed by getObjectSize. */
    totalObjectSize = destLength << getObjectSize(newType, userSize);
    freeRef = (word_t)retypeBase + totalObjectSize;
    srcSlot->cap = cap_untyped_cap_set_capFreeIndex(srcSlot->cap,
                                                    GET_FREE_INDEX(regionBase, freeRef));

    /* Create new objects and caps. */
    createNewObjects(newType, srcSlot, destCNode, destOffset, destLength,
                     retypeBase, userSize, deviceMemory);

    return EXCEPTION_NONE;
}
#line 1 "/home/koc034/Documents/newver/seL4/src/smp/ipi.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <mode/smp/ipi.h>
#include <smp/ipi.h>
#include <smp/lock.h>

#ifdef ENABLE_SMP_SUPPORT
/* This function switches the core it is called on to the idle thread,
 * in order to avoid IPI storms. If the core is waiting on the lock, the actual
 * switch will not occur until the core attempts to obtain the lock, at which
 * point the core will capture the pending IPI, which is discarded.

 * The core who triggered the store is responsible for triggering a reschedule,
 * or this call will idle forever */
void ipiStallCoreCallback(bool_t irqPath)
{
    if (clh_is_self_in_queue() && !irqPath) {
        /* The current thread is running as we would replace this thread with an idle thread
         *
         * The instruction should be re-executed if we are in kernel to handle syscalls.
         * Also, thread in 'ThreadState_RunningVM' should remain in same state.
         * Note that, 'ThreadState_Restart' does not always result in regenerating exception
         * if we are in kernel to handle them, e.g. hardware single step exception. */
        if (thread_state_ptr_get_tsType(&NODE_STATE(ksCurThread)->tcbState) == ThreadState_Running) {
            setThreadState(NODE_STATE(ksCurThread), ThreadState_Restart);
        }

        SCHED_ENQUEUE_CURRENT_TCB;
        switchToIdleThread();
        NODE_STATE(ksSchedulerAction) = SchedulerAction_ResumeCurrentThread;

        /* Let the cpu requesting this IPI to continue while we waiting on lock */
        big_kernel_lock.node_owners[getCurrentCPUIndex()].ipi = 0;
#ifdef CONFIG_ARCH_RISCV
        ipi_clear_irq(irq_remote_call_ipi);
#endif
        ipi_wait(totalCoreBarrier);

        /* Continue waiting on lock */
        while (big_kernel_lock.node_owners[getCurrentCPUIndex()].next->value != CLHState_Granted) {
            if (clh_is_ipi_pending(getCurrentCPUIndex())) {

                /* Multiple calls for similar reason could result in stack overflow */
                assert((IpiRemoteCall_t)remoteCall != IpiRemoteCall_Stall);
                handleIPI(CORE_IRQ_TO_IRQT(getCurrentCPUIndex(), irq_remote_call_ipi), irqPath);
            }
            arch_pause();
        }

        /* make sure no resource access passes from this point */
        asm volatile("" ::: "memory");

        /* Start idle thread to capture the pending IPI */
        activateThread();
        restore_user_context();
    } else {
        /* We get here either without grabbing the lock from normal interrupt path or from
         * inside the lock while waiting to grab the lock for handling pending interrupt.
         * In latter case, we return to the 'clh_lock_acquire' to grab the lock and
         * handle the pending interrupt. Its valid as interrups are async events! */
        SCHED_ENQUEUE_CURRENT_TCB;
        switchToIdleThread();

        NODE_STATE(ksSchedulerAction) = SchedulerAction_ResumeCurrentThread;
    }
}

void handleIPI(irq_t irq, bool_t irqPath)
{
    if (IRQT_TO_IRQ(irq) == irq_remote_call_ipi) {
        handleRemoteCall(remoteCall, get_ipi_arg(0), get_ipi_arg(1), get_ipi_arg(2), irqPath);
    } else if (IRQT_TO_IRQ(irq) == irq_reschedule_ipi) {
        rescheduleRequired();
#ifdef CONFIG_ARCH_RISCV
        ifence_local();
#endif
    } else {
        fail("Invalid IPI");
    }
}

void doRemoteMaskOp(IpiRemoteCall_t func, word_t data1, word_t data2, word_t data3, word_t mask)
{
    /* make sure the current core is not set in the mask */
    mask &= ~BIT(getCurrentCPUIndex());

    /* this may happen, e.g. the caller tries to map a pagetable in
     * newly created PD which has not been run yet. Guard against them! */
    if (mask != 0) {
        init_ipi_args(func, data1, data2, data3, mask);

        /* make sure no resource access passes from this point */
        asm volatile("" ::: "memory");
        ipi_send_mask(CORE_IRQ_TO_IRQT(0, irq_remote_call_ipi), mask, true);
        ipi_wait(totalCoreBarrier);
    }
}

void doMaskReschedule(word_t mask)
{
    /* make sure the current core is not set in the mask */
    mask &= ~BIT(getCurrentCPUIndex());
    if (mask != 0) {
        ipi_send_mask(CORE_IRQ_TO_IRQT(0, irq_reschedule_ipi), mask, false);
    }
}

void generic_ipi_send_mask(irq_t ipi, word_t mask, bool_t isBlocking)
{
    word_t nr_target_cores = 0;
    uint16_t target_cores[CONFIG_MAX_NUM_NODES];

    while (mask) {
        int index = wordBits - 1 - clzl(mask);
        if (isBlocking) {
            big_kernel_lock.node_owners[index].ipi = 1;
            target_cores[nr_target_cores] = index;
            nr_target_cores++;
        } else {
            ipi_send_target(ipi, cpuIndexToID(index));
        }
        mask &= ~BIT(index);
    }

    if (nr_target_cores > 0) {
        /* sending IPIs... */
        IPI_MEM_BARRIER;
        for (int i = 0; i < nr_target_cores; i++) {
            ipi_send_target(ipi, cpuIndexToID(target_cores[i]));
        }
    }
}
#endif /* ENABLE_SMP_SUPPORT */
#line 1 "/home/koc034/Documents/newver/seL4/src/smp/lock.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <smp/lock.h>

#ifdef ENABLE_SMP_SUPPORT

clh_lock_t big_kernel_lock ALIGN(L1_CACHE_LINE_SIZE);

BOOT_CODE void clh_lock_init(void)
{
    for (int i = 0; i < CONFIG_MAX_NUM_NODES; i++) {
        big_kernel_lock.node_owners[i].node = &big_kernel_lock.nodes[i];
    }

    /* Initialize the CLH head */
    big_kernel_lock.nodes[CONFIG_MAX_NUM_NODES].value = CLHState_Granted;
    big_kernel_lock.head = &big_kernel_lock.nodes[CONFIG_MAX_NUM_NODES];
}

#endif /* ENABLE_SMP_SUPPORT */
#line 1 "/home/koc034/Documents/newver/seL4/src/string.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#include <assert.h>
#include <string.h>

word_t strnlen(const char *s, word_t maxlen)
{
    word_t len;
    for (len = 0; len < maxlen && s[len]; len++);
    return len;
}

word_t strlcpy(char *dest, const char *src, word_t size)
{
    word_t len;
    for (len = 0; len + 1 < size && src[len]; len++) {
        dest[len] = src[len];
    }
    dest[len] = '\0';
    return len;
}

word_t strlcat(char *dest, const char *src, word_t size)
{
    word_t len;
    /* get to the end of dest */
    for (len = 0; len < size && dest[len]; len++);
    /* check that dest was at least 'size' length to prevent inserting
     * a null byte when we shouldn't */
    if (len < size) {
        for (; len + 1 < size && *src; len++, src++) {
            dest[len] = *src;
        }
        dest[len] = '\0';
    }
    return len;
}
#line 1 "/home/koc034/Documents/newver/seL4/src/util.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <stdint.h>
#include <util.h>

/*
 * memzero needs a custom type that allows us to use a word
 * that has the aliasing properties of a char.
 */
typedef unsigned long __attribute__((__may_alias__)) ulong_alias;

/*
 * Zero 'n' bytes of memory starting from 's'.
 *
 * 'n' and 's' must be word aligned.
 */
void memzero(void *s, unsigned long n)
{
    uint8_t *p = s;

    /* Ensure alignment constraints are met. */
    assert((unsigned long)s % sizeof(unsigned long) == 0);
    assert(n % sizeof(unsigned long) == 0);

    /* We will never memzero an area larger than the largest current
       live object */
    /** GHOSTUPD: "(gs_get_assn cap_get_capSizeBits_'proc \<acute>ghost'state = 0
        \<or> \<acute>n <= gs_get_assn cap_get_capSizeBits_'proc \<acute>ghost'state, id)" */

    /* Write out words. */
    while (n != 0) {
        *(ulong_alias *)p = 0;
        p += sizeof(ulong_alias);
        n -= sizeof(ulong_alias);
    }
}

void *VISIBLE memset(void *s, unsigned long c, unsigned long n)
{
    uint8_t *p;

    /*
     * If we are only writing zeros and we are word aligned, we can
     * use the optimized 'memzero' function.
     */
    if (likely(c == 0 && ((unsigned long)s % sizeof(unsigned long)) == 0 && (n % sizeof(unsigned long)) == 0)) {
        memzero(s, n);
    } else {
        /* Otherwise, we use a slower, simple memset. */
        for (p = (uint8_t *)s; n > 0; n--, p++) {
            *p = (uint8_t)c;
        }
    }

    return s;
}

void *VISIBLE memcpy(void *ptr_dst, const void *ptr_src, unsigned long n)
{
    uint8_t *p;
    const uint8_t *q;

    for (p = (uint8_t *)ptr_dst, q = (const uint8_t *)ptr_src; n; n--, p++, q++) {
        *p = *q;
    }

    return ptr_dst;
}

int PURE strncmp(const char *s1, const char *s2, int n)
{
    word_t i;
    int diff;

    for (i = 0; i < n; i++) {
        diff = ((unsigned char *)s1)[i] - ((unsigned char *)s2)[i];
        if (diff != 0 || s1[i] == '\0') {
            return diff;
        }
    }

    return 0;
}

long CONST char_to_long(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

long PURE str_to_long(const char *str)
{
    unsigned int base;
    long res;
    long val = 0;
    char c;

    /*check for "0x" */
    if (*str == '0' && (*(str + 1) == 'x' || *(str + 1) == 'X')) {
        base = 16;
        str += 2;
    } else {
        base = 10;
    }

    if (!*str) {
        return -1;
    }

    c = *str;
    while (c != '\0') {
        res = char_to_long(c);
        if (res == -1 || res >= base) {
            return -1;
        }
        val = val * base + res;
        str++;
        c = *str;
    }

    return val;
}

// The following implementations of CLZ (count leading zeros) and CTZ (count
// trailing zeros) perform a binary search for the first 1 bit from the
// beginning (resp. end) of the input. Initially, the focus is the whole input.
// Then, each iteration determines whether there are any 1 bits set in the
// upper (resp. lower) half of the current focus. If there are (resp. are not),
// then the upper half is shifted into the lower half. Either way, the lower
// half of the current focus becomes the new focus for the next iteration.
// After enough iterations (6 for 64-bit inputs, 5 for 32-bit inputs), the
// focus is reduced to a single bit, and the total number of bits shifted can
// be used to determine the number of zeros before (resp. after) the first 1
// bit.
//
// Although the details vary, the general approach is used in several library
// implementations, including in LLVM and GCC. Wikipedia has some references:
// https://en.wikipedia.org/wiki/Find_first_set
//
// The current implementation avoids branching. The test that determines
// whether the upper (resp. lower) half contains any ones directly produces a
// number which can be used for an unconditional shift. If the upper (resp.
// lower) half is all zeros, the test produces a zero, and the shift is a
// no-op. A branchless implementation has the disadvantage that it requires
// more instructions to execute than one which branches, but the advantage is
// that none will be mispredicted branches. Whether this is a good tradeoff
// depends on the branch predictability and the architecture's pipeline depth.
// The most critical use of clzl in the kernel is in the scheduler priority
// queue. In the absence of a concrete application and hardware implementation
// to evaluate the tradeoff, we somewhat arbitrarily choose a branchless
// implementation. In any case, the compiler might convert this to a branching
// binary.

// Check some assumptions made by the CLZ and CTZ library functions:
compile_assert(clz_ulong_32_or_64, sizeof(unsigned long) == 4 || sizeof(unsigned long) == 8);
compile_assert(clz_ullong_64, sizeof(unsigned long long) == 8);

#ifdef CONFIG_CLZL_IMPL
// Count leading zeros.
// This implementation contains no branches. If the architecture provides an
// instruction to set a register to a boolean value on a comparison, then the
// binary might also avoid branching. A branchless implementation might be
// preferable on architectures with deep pipelines, or when the maximum
// priority of runnable threads frequently varies. However, note that the
// compiler may choose to convert this to a branching implementation.
static CONST inline unsigned clz32(uint32_t x)
{
    // Compiler builtins typically return int, but we use unsigned internally
    // to reduce the number of guards we see in the proofs.
    unsigned count = 32;
    uint32_t mask = UINT32_MAX;

    // Each iteration i (counting backwards) considers the least significant
    // 2^(i+1) bits of x as the current focus. At the first iteration, the
    // focus is the whole input. Each iteration assumes x contains no 1 bits
    // outside its focus. The iteration contains a test which determines
    // whether there are any 1 bits in the upper half (2^i bits) of the focus,
    // setting `bits` to 2^i if there are, or zero if not. Shifting by `bits`
    // then narrows the focus to the lower 2^i bits and satisfies the
    // assumption for the next iteration. After the final iteration, the focus
    // is just the least significant bit, and the most significsnt 1 bit of the
    // original input (if any) has been shifted into this position. The leading
    // zero count can be determined from the total shift.
    //
    // The iterations are given a very regular structure to facilitate proofs,
    // while also generating reasonably efficient binary code.

    // The `if (1)` blocks make it easier to reason by chunks in the proofs.
    if (1) {
        // iteration 4
        mask >>= (1 << 4); // 0x0000ffff
        unsigned bits = ((unsigned)(mask < x)) << 4; // [0, 16]
        x >>= bits; // <= 0x0000ffff
        count -= bits; // [16, 32]
    }
    if (1) {
        // iteration 3
        mask >>= (1 << 3); // 0x000000ff
        unsigned bits = ((unsigned)(mask < x)) << 3; // [0, 8]
        x >>= bits; // <= 0x000000ff
        count -= bits; // [8, 16, 24, 32]
    }
    if (1) {
        // iteration 2
        mask >>= (1 << 2); // 0x0000000f
        unsigned bits = ((unsigned)(mask < x)) << 2; // [0, 4]
        x >>= bits; // <= 0x0000000f
        count -= bits; // [4, 8, 12, ..., 32]
    }
    if (1) {
        // iteration 1
        mask >>= (1 << 1); // 0x00000003
        unsigned bits = ((unsigned)(mask < x)) << 1; // [0, 2]
        x >>= bits; // <= 0x00000003
        count -= bits; // [2, 4, 6, ..., 32]
    }
    if (1) {
        // iteration 0
        mask >>= (1 << 0); // 0x00000001
        unsigned bits = ((unsigned)(mask < x)) << 0; // [0, 1]
        x >>= bits; // <= 0x00000001
        count -= bits; // [1, 2, 3, ..., 32]
    }

    // If the original input was zero, there will have been no shifts, so this
    // gives a result of 32. Otherwise, x is now exactly 1, so subtracting from
    // count gives a result from [0, 1, 2, ..., 31].
    return count - x;
}
#endif

#if defined(CONFIG_CLZL_IMPL) || defined (CONFIG_CLZLL_IMPL)
static CONST inline unsigned clz64(uint64_t x)
{
    unsigned count = 64;
    uint64_t mask = UINT64_MAX;

    // Although we could implement this using clz32, we spell out the
    // iterations in full for slightly better code generation at low
    // optimisation levels, and to allow us to reuse the proof machinery we
    // developed for clz32.
    if (1) {
        // iteration 5
        mask >>= (1 << 5); // 0x00000000ffffffff
        unsigned bits = ((unsigned)(mask < x)) << 5; // [0, 32]
        x >>= bits; // <= 0x00000000ffffffff
        count -= bits; // [32, 64]
    }
    if (1) {
        // iteration 4
        mask >>= (1 << 4); // 0x000000000000ffff
        unsigned bits = ((unsigned)(mask < x)) << 4; // [0, 16]
        x >>= bits; // <= 0x000000000000ffff
        count -= bits; // [16, 32, 48, 64]
    }
    if (1) {
        // iteration 3
        mask >>= (1 << 3); // 0x00000000000000ff
        unsigned bits = ((unsigned)(mask < x)) << 3; // [0, 8]
        x >>= bits; // <= 0x00000000000000ff
        count -= bits; // [8, 16, 24, ..., 64]
    }
    if (1) {
        // iteration 2
        mask >>= (1 << 2); // 0x000000000000000f
        unsigned bits = ((unsigned)(mask < x)) << 2; // [0, 4]
        x >>= bits; // <= 0x000000000000000f
        count -= bits; // [4, 8, 12, ..., 64]
    }
    if (1) {
        // iteration 1
        mask >>= (1 << 1); // 0x0000000000000003
        unsigned bits = ((unsigned)(mask < x)) << 1; // [0, 2]
        x >>= bits; // <= 0x0000000000000003
        count -= bits; // [2, 4, 6, ..., 64]
    }
    if (1) {
        // iteration 0
        mask >>= (1 << 0); // 0x0000000000000001
        unsigned bits = ((unsigned)(mask < x)) << 0; // [0, 1]
        x >>= bits; // <= 0x0000000000000001
        count -= bits; // [1, 2, 3, ..., 64]
    }

    return count - x;
}
#endif

#ifdef CONFIG_CLZL_IMPL
int __clzdi2(unsigned long x)
{
    return sizeof(unsigned long) == 4 ? clz32(x) : clz64(x);
}
#endif

#ifdef CONFIG_CLZLL_IMPL
int __clzti2(unsigned long long x)
{
    return clz64(x);
}
#endif

#ifdef CONFIG_CTZL_IMPL
// Count trailing zeros.
// See comments on clz32.
static CONST inline unsigned ctz32(uint32_t x)
{
    unsigned count = (x == 0);
    uint32_t mask = UINT32_MAX;

    // Each iteration i (counting backwards) considers the least significant
    // 2^(i+1) bits of x as the current focus. At the first iteration, the
    // focus is the whole input. The iteration contains a test which determines
    // whether there are any 1 bits in the lower half (2^i bits) of the focus,
    // setting `bits` to zero if there are, or 2^i if not. Shifting by `bits`
    // then narrows the focus to the lower 2^i bits for the next iteration.
    // After the final iteration, the focus is just the least significant bit,
    // and the least significsnt 1 bit of the original input (if any) has been
    // shifted into this position. The trailing zero count can be determined
    // from the total shift.
    //
    // If the initial input is zero, every iteration causes a shift, for a
    // total shift count of 31, so in that case, we add one for a total count
    // of 32. In the comments, xi is the initial value of x.
    //
    // The iterations are given a very regular structure to facilitate proofs,
    // while also generating reasonably efficient binary code.

    if (1) {
        // iteration 4
        mask >>= (1 << 4); // 0x0000ffff
        unsigned bits = ((unsigned)((x & mask) == 0)) << 4; // [0, 16]
        x >>= bits; // xi != 0 --> x & 0x0000ffff != 0
        count += bits; // if xi != 0 then [0, 16] else 17
    }
    if (1) {
        // iteration 3
        mask >>= (1 << 3); // 0x000000ff
        unsigned bits = ((unsigned)((x & mask) == 0)) << 3; // [0, 8]
        x >>= bits; // xi != 0 --> x & 0x000000ff != 0
        count += bits; // if xi != 0 then [0, 8, 16, 24] else 25
    }
    if (1) {
        // iteration 2
        mask >>= (1 << 2); // 0x0000000f
        unsigned bits = ((unsigned)((x & mask) == 0)) << 2; // [0, 4]
        x >>= bits; // xi != 0 --> x & 0x0000000f != 0
        count += bits; // if xi != 0 then [0, 4, 8, ..., 28] else 29
    }
    if (1) {
        // iteration 1
        mask >>= (1 << 1); // 0x00000003
        unsigned bits = ((unsigned)((x & mask) == 0)) << 1; // [0, 2]
        x >>= bits; // xi != 0 --> x & 0x00000003 != 0
        count += bits; // if xi != 0 then [0, 2, 4, ..., 30] else 31
    }
    if (1) {
        // iteration 0
        mask >>= (1 << 0); // 0x00000001
        unsigned bits = ((unsigned)((x & mask) == 0)) << 0; // [0, 1]
        x >>= bits; // <= xi != 0 --> x & 0x00000001 != 0
        count += bits; // if xi != 0 then [0, 1, 2, ..., 31] else 32
    }

    return count;
}
#endif

#if defined(CONFIG_CTZL_IMPL) || defined (CONFIG_CTZLL_IMPL)
static CONST inline unsigned ctz64(uint64_t x)
{
    unsigned count = (x == 0);
    uint64_t mask = UINT64_MAX;

    if (1) {
        // iteration 5
        mask >>= (1 << 5); // 0x00000000ffffffff
        unsigned bits = ((unsigned)((x & mask) == 0)) << 5; // [0, 32]
        x >>= bits; // xi != 0 --> x & 0x00000000ffffffff != 0
        count += bits; // if xi != 0 then [0, 32] else 33
    }
    if (1) {
        // iteration 4
        mask >>= (1 << 4); // 0x000000000000ffff
        unsigned bits = ((unsigned)((x & mask) == 0)) << 4; // [0, 16]
        x >>= bits; // xi != 0 --> x & 0x000000000000ffff != 0
        count += bits; // if xi != 0 then [0, 16, 32, 48] else 49
    }
    if (1) {
        // iteration 3
        mask >>= (1 << 3); // 0x00000000000000ff
        unsigned bits = ((unsigned)((x & mask) == 0)) << 3; // [0, 8]
        x >>= bits; // <= xi != 0 --> x & 0x00000000000000ff != 0
        count += bits; // if xi != 0 then [0, 8, 16, ..., 56] else 57
    }
    if (1) {
        // iteration 2
        mask >>= (1 << 2); // 0x000000000000000f
        unsigned bits = ((unsigned)((x & mask) == 0)) << 2; // [0, 4]
        x >>= bits; // <= xi != 0 --> x & 0x000000000000000f != 0
        count += bits; // if xi != 0 then [0, 4, 8, ..., 60] else 61
    }
    if (1) {
        // iteration 1
        mask >>= (1 << 1); // 0x0000000000000003
        unsigned bits = ((unsigned)((x & mask) == 0)) << 1; // [0, 2]
        x >>= bits; // <= xi != 0 --> x & 0x0000000000000003 != 0
        count += bits; // if xi != 0 then [0, 2, 4, ..., 62] else 63
    }
    if (1) {
        // iteration 0
        mask >>= (1 << 0); // 0x0000000000000001
        unsigned bits = ((unsigned)((x & mask) == 0)) << 0; // [0, 1]
        x >>= bits; // <= xi != 0 --> x & 0x0000000000000001 != 0
        count += bits; // if xi != 0 then [0, 1, 2, ..., 63] else 64
    }

    return count;
}
#endif

#ifdef CONFIG_CTZL_IMPL
int __ctzdi2(unsigned long x)
{
    return sizeof(unsigned long) == 4 ? ctz32(x) : ctz64(x);
}
#endif

#ifdef CONFIG_CTZLL_IMPL
int __ctzti2(unsigned long long x)
{
    return ctz64(x);
}
#endif
#line 1 "/home/koc034/Documents/newver/l4v/spec/cspec/c/config_sched.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <object/structures.h>
#include <model/statedata.h>

/* Random schedule clagged from Tim's original example. */
const dschedule_t ksDomSchedule[] = {
    { .domain = 0, .length = 15 },
    { .domain = 2, .length = 42 },
    { .domain = 1, .length = 73 },
};

const word_t ksDomScheduleLength = sizeof(ksDomSchedule) / sizeof(dschedule_t);
