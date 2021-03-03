# 1 "kernel_all_copy.c"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "kernel_all_copy.c"
# 1 "/home/koc034/Documents/newver/seL4/src/api/faults.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

# 1 "/home/koc034/Documents/newver/seL4/include/config.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       

# 1 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/config.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       

/* Compile-time configuration parameters. Might be set by the build system. */


# 1 "autoconf/autoconf.h" 1



# 1 "gen_config/kernel/gen_config.h" 1
# 5 "autoconf/autoconf.h" 2
# 13 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/config.h" 2


/* size of the initial thread's root CNode (2^x slots, x >= 4) */




/* number of timer ticks until a thread is preempted  */
# 37 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/config.h"
/* the number of scheduler domains */




/* number of priorities per domain */




/* maximum number of caps that can be created in one retype invocation */




/* chunk size for memory clears during retype, in bits. */




/* maximum number of iterations until we preempt a delete/revoke invocation */




/* address range to flush per preemption work unit */




/* maximum number of untyped caps in bootinfo */
/* WARNING: must match value in libsel4! */
/* CONSTRAINT: (16 * CONFIG_MAX_NUM_BOOTINFO_DEVICE_REGIONS) + (5 * CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS) <= 4036 */
# 81 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/config.h"
/* maximum number of different tracepoints which can be placed in the kernel */




/* maximum number of IOMMU RMRR entries we can record while ACPI parsing */




/* maximum number of IOAPIC supported */




/* Alias CONFIG_MAX_NUM_NODES > 1 to ENABLE_SMP_SUPPORT */
# 107 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/config.h"
/* Configurations requring the kernel log buffer */
# 10 "/home/koc034/Documents/newver/seL4/include/config.h" 2
# 8 "/home/koc034/Documents/newver/seL4/src/api/faults.c" 2
# 1 "/home/koc034/Documents/newver/seL4/include/types.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       

# 1 "/home/koc034/Documents/newver/seL4/include/basic_types.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       

# 1 "/home/koc034/Documents/newver/seL4/include/stdint.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       

# 1 "/home/koc034/Documents/newver/seL4/include/64/mode/stdint.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 10 "/home/koc034/Documents/newver/seL4/include/stdint.h" 2

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef signed long long int64_t;
# 10 "/home/koc034/Documents/newver/seL4/include/basic_types.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/types.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



# 1 "/home/koc034/Documents/newver/seL4/include/assert.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       


# 1 "/home/koc034/Documents/newver/seL4/include/util.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 20 "/home/koc034/Documents/newver/seL4/include/util.h"
/* time constants */
# 55 "/home/koc034/Documents/newver/seL4/include/util.h"
/** MODIFIES: */
void __builtin_unreachable(void);







/* Borrowed from linux/include/linux/compiler.h */







/* need that for compiling with c99 instead of gnu99 */


/* Evaluate a Kconfig-provided configuration setting at compile-time. */






/* Check the existence of a configuration setting, returning one value if it
 * exists and a different one if it does not */





/** MODIFIES:
    FNSPEC
        halt_spec: "\<Gamma> \<turnstile> {} Call halt_'proc {}"
*/
void halt(void) __attribute__((__noreturn__));
void memzero(void *s, unsigned long n);
void *memset(void *s, unsigned long c, unsigned long n) __attribute__((externally_visible));
void *memcpy(void *ptr_dst, const void *ptr_src, unsigned long n) __attribute__((externally_visible));
int __attribute__((__pure__)) strncmp(const char *s1, const char *s2, int n);
long __attribute__((__const__)) char_to_long(char c);
long __attribute__((__pure__)) str_to_long(const char *str);

// Library functions for counting leading/trailing zeros.
// GCC's builtins will emit calls to these functions when the platform
// does not provide suitable inline assembly.
// We only emit function definitions if CONFIG_CLZL_IMPL etc are set.
__attribute__((noinline)) __attribute__((__const__)) int __clzdi2(unsigned long x);
__attribute__((noinline)) __attribute__((__const__)) int __clzti2(unsigned long long x);
__attribute__((noinline)) __attribute__((__const__)) int __ctzdi2(unsigned long x);
__attribute__((noinline)) __attribute__((__const__)) int __ctzti2(unsigned long long x);

// Used for compile-time constants, so should always use the builtin.


// Count leading zeros.
// The CONFIG_CLZ_NO_BUILTIN macro may be used to expose the library function
// to the C parser for verification.
# 132 "/home/koc034/Documents/newver/seL4/include/util.h"
static inline long
__attribute__((__const__)) clzl(unsigned long x)
{

    return __clzdi2(x);



}
# 153 "/home/koc034/Documents/newver/seL4/include/util.h"
static inline long long
__attribute__((__const__)) clzll(unsigned long long x)
{

    return __clzti2(x);



}

// Count trailing zeros.
# 175 "/home/koc034/Documents/newver/seL4/include/util.h"
static inline long
__attribute__((__const__)) ctzl(unsigned long x)
{

// If there is a builtin CLZ, but no builtin CTZ, then CTZ will be implemented
// using the builtin CLZ, rather than the long-form implementation.
// This is typically the fastest way to calculate ctzl on such platforms.

    // Here, there are no builtins we can use, so call the library function.
    return __ctzdi2(x);
# 198 "/home/koc034/Documents/newver/seL4/include/util.h"
}
# 211 "/home/koc034/Documents/newver/seL4/include/util.h"
static inline long long
__attribute__((__const__)) ctzll(unsigned long long x)
{

// See comments on ctzl.

    return __ctzti2(x);
# 228 "/home/koc034/Documents/newver/seL4/include/util.h"
}

int __builtin_popcountl(unsigned long x);

/** DONT_TRANSLATE */
static inline long
__attribute__((__const__)) popcountl(unsigned long mask)
{

    unsigned int count; // c accumulates the total bits set in v
    for (count = 0; mask; count++) {
        mask &= mask - 1; // clear the least significant bit set
    }

    return count;



}



/* Can be used to insert padding to the next L1 cache line boundary */
# 11 "/home/koc034/Documents/newver/seL4/include/assert.h" 2
# 41 "/home/koc034/Documents/newver/seL4/include/assert.h"
/* Create an assert that will trigger a compile error if it fails. */



/* Sometimes compile asserts contain expressions that the C parser cannot
 * handle. For such expressions unverified_compile_assert should be used. */
# 13 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/types.h" 2

# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/64/mode/types.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       





typedef int __assert_failed_long_is_64bits[(sizeof(unsigned long) == 8) ? 1 : -1];
# 15 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/types.h" 2

typedef unsigned long word_t;
typedef signed long sword_t;
typedef word_t vptr_t;
typedef word_t paddr_t;
typedef word_t pptr_t;
typedef word_t cptr_t;
typedef word_t dev_id_t;
typedef word_t cpu_id_t;
typedef word_t node_id_t;
typedef word_t dom_t;

/* for libsel4 headers that the kernel shares */
typedef word_t seL4_Word;
typedef cptr_t seL4_CPtr;
typedef uint32_t seL4_Uint32;
typedef uint8_t seL4_Uint8;
typedef node_id_t seL4_NodeId;
typedef paddr_t seL4_PAddr;
typedef dom_t seL4_Domain;

typedef uint64_t timestamp_t;



typedef struct kernel_frame {
    paddr_t paddr;
    pptr_t pptr;
    int userAvailable;
} kernel_frame_t;
# 11 "/home/koc034/Documents/newver/seL4/include/basic_types.h" 2

enum _bool {
    false = 0,
    true = 1
};
typedef word_t bool_t;

typedef struct region {
    pptr_t start;
    pptr_t end;
} region_t;

typedef struct p_region {
    paddr_t start;
    paddr_t end;
} p_region_t;

typedef struct v_region {
    vptr_t start;
    vptr_t end;
} v_region_t;




/* equivalent to a word_t except that we tell the compiler that we may alias with
 * any other type (similar to a char pointer) */
typedef word_t __attribute__((__may_alias__)) word_t_may_alias;
# 10 "/home/koc034/Documents/newver/seL4/include/types.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/compound_types.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       


# 1 "/home/koc034/Documents/newver/seL4/include/api/types.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




# 1 "/home/koc034/Documents/newver/graph-refine/seL4-example/target/RISCV64-MCS-O1/build/generated/sel4/shared_types_gen.h" 1







struct seL4_CNode_CapData {
    uint64_t words[1];
};
typedef struct seL4_CNode_CapData seL4_CNode_CapData_t;

static inline uint64_t __attribute__((__const__))
seL4_CNode_CapData_get_guard(seL4_CNode_CapData_t seL4_CNode_CapData) {
    uint64_t ret;
    ret = (seL4_CNode_CapData.words[0] & 0xffffffffffffffc0ull) >> 6;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (63)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
seL4_CNode_CapData_get_guardSize(seL4_CNode_CapData_t seL4_CNode_CapData) {
    uint64_t ret;
    ret = (seL4_CNode_CapData.words[0] & 0x3full) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (63)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

struct seL4_CapRights {
    uint64_t words[1];
};
typedef struct seL4_CapRights seL4_CapRights_t;

static inline uint64_t __attribute__((__const__))
seL4_CapRights_get_capAllowGrantReply(seL4_CapRights_t seL4_CapRights) {
    uint64_t ret;
    ret = (seL4_CapRights.words[0] & 0x8ull) >> 3;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (63)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
seL4_CapRights_get_capAllowGrant(seL4_CapRights_t seL4_CapRights) {
    uint64_t ret;
    ret = (seL4_CapRights.words[0] & 0x4ull) >> 2;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (63)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
seL4_CapRights_get_capAllowRead(seL4_CapRights_t seL4_CapRights) {
    uint64_t ret;
    ret = (seL4_CapRights.words[0] & 0x2ull) >> 1;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (63)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
seL4_CapRights_get_capAllowWrite(seL4_CapRights_t seL4_CapRights) {
    uint64_t ret;
    ret = (seL4_CapRights.words[0] & 0x1ull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (63)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

struct seL4_MessageInfo {
    uint64_t words[1];
};
typedef struct seL4_MessageInfo seL4_MessageInfo_t;

static inline seL4_MessageInfo_t __attribute__((__const__))
seL4_MessageInfo_new(uint64_t label, uint64_t capsUnwrapped, uint64_t extraCaps, uint64_t length) {
    seL4_MessageInfo_t seL4_MessageInfo;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;
    ;

    seL4_MessageInfo.words[0] = 0
        | (label & 0xfffffffffffffull) << 12
        | (capsUnwrapped & 0x7ull) << 9
        | (extraCaps & 0x3ull) << 7
        | (length & 0x7full) << 0;

    return seL4_MessageInfo;
}

static inline uint64_t __attribute__((__const__))
seL4_MessageInfo_get_label(seL4_MessageInfo_t seL4_MessageInfo) {
    uint64_t ret;
    ret = (seL4_MessageInfo.words[0] & 0xfffffffffffff000ull) >> 12;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (63)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
seL4_MessageInfo_get_capsUnwrapped(seL4_MessageInfo_t seL4_MessageInfo) {
    uint64_t ret;
    ret = (seL4_MessageInfo.words[0] & 0xe00ull) >> 9;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (63)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline seL4_MessageInfo_t __attribute__((__const__))
seL4_MessageInfo_set_capsUnwrapped(seL4_MessageInfo_t seL4_MessageInfo, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    seL4_MessageInfo.words[0] &= ~0xe00ull;
    seL4_MessageInfo.words[0] |= (v64 << 9) & 0xe00ull;
    return seL4_MessageInfo;
}

static inline uint64_t __attribute__((__const__))
seL4_MessageInfo_get_extraCaps(seL4_MessageInfo_t seL4_MessageInfo) {
    uint64_t ret;
    ret = (seL4_MessageInfo.words[0] & 0x180ull) >> 7;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (63)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline seL4_MessageInfo_t __attribute__((__const__))
seL4_MessageInfo_set_extraCaps(seL4_MessageInfo_t seL4_MessageInfo, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    seL4_MessageInfo.words[0] &= ~0x180ull;
    seL4_MessageInfo.words[0] |= (v64 << 7) & 0x180ull;
    return seL4_MessageInfo;
}

static inline uint64_t __attribute__((__const__))
seL4_MessageInfo_get_length(seL4_MessageInfo_t seL4_MessageInfo) {
    uint64_t ret;
    ret = (seL4_MessageInfo.words[0] & 0x7full) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (63)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline seL4_MessageInfo_t __attribute__((__const__))
seL4_MessageInfo_set_length(seL4_MessageInfo_t seL4_MessageInfo, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    seL4_MessageInfo.words[0] &= ~0x7full;
    seL4_MessageInfo.words[0] |= (v64 << 0) & 0x7full;
    return seL4_MessageInfo;
}
# 13 "/home/koc034/Documents/newver/seL4/include/api/types.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/api/types.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 *
 */

       


# 1 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/objecttype.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       
typedef enum api_object {
    seL4_UntypedObject,
    seL4_TCBObject,
    seL4_EndpointObject,
    seL4_NotificationObject,
    seL4_CapTableObject,

    seL4_SchedContextObject,
    seL4_ReplyObject,

    seL4_NonArchObjectTypeCount,
} seL4_ObjectType;

__attribute__((deprecated("use seL4_NotificationObject"))) static const seL4_ObjectType seL4_AsyncEndpointObject =
    seL4_NotificationObject;

typedef seL4_Word api_object_t;
# 15 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/api/types.h" 2
# 1 "/home/koc034/Documents/newver/seL4/libsel4/sel4_arch_include/riscv64/sel4/sel4_arch/objecttype.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       


# 1 "autoconf/autoconf.h" 1
# 12 "/home/koc034/Documents/newver/seL4/libsel4/sel4_arch_include/riscv64/sel4/sel4_arch/objecttype.h" 2


typedef enum _mode_object {
    seL4_RISCV_Giga_Page = seL4_NonArchObjectTypeCount,



    seL4_ModeObjectTypeCount
} seL4_ModeObjectType;
# 16 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/api/types.h" 2
# 1 "/home/koc034/Documents/newver/seL4/libsel4/arch_include/riscv/sel4/arch/objecttype.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       


# 1 "autoconf/autoconf.h" 1
# 12 "/home/koc034/Documents/newver/seL4/libsel4/arch_include/riscv/sel4/arch/objecttype.h" 2


typedef enum _object {
    seL4_RISCV_4K_Page = seL4_ModeObjectTypeCount,
    seL4_RISCV_Mega_Page,
    seL4_RISCV_PageTableObject,
    seL4_ObjectTypeCount
} seL4_ArchObjectType;

typedef seL4_Word object_t;
# 17 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/api/types.h" 2




enum asidConstants {
    asidInvalid = 0
};



typedef word_t asid_t;
# 14 "/home/koc034/Documents/newver/seL4/include/api/types.h" 2

# 1 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/macros.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       

# 1 "autoconf/autoconf.h" 1
# 10 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/macros.h" 2

/*
 * Some compilers attempt to pack enums into the smallest possible type.
 * For ABI compatibility with the kernel, we need to ensure they remain
 * the same size as a 'long'.
 */
# 16 "/home/koc034/Documents/newver/seL4/include/api/types.h" 2
# 1 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/constants.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       


# 1 "autoconf/autoconf.h" 1
# 11 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/constants.h" 2
# 46 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/constants.h"
enum priorityConstants {
    seL4_InvalidPrio = -1,
    seL4_MinPrio = 0,
    seL4_MaxPrio = 256 - 1
};

/* seL4_MessageInfo_t defined in api/shared_types.bf */

enum seL4_MsgLimits {
    seL4_MsgLengthBits = 7,
    seL4_MsgExtraCapBits = 2
};

enum {
    seL4_MsgMaxLength = 120,
};


/* seL4_CapRights_t defined in shared_types_*.bf */


typedef enum {
    seL4_NoFailure = 0,
    seL4_InvalidRoot,
    seL4_MissingCapability,
    seL4_DepthMismatch,
    seL4_GuardMismatch,
    _enum_pad_seL4_LookupFailureType = (1ULL << ((sizeof(long)*8) - 1)) - 1,
} seL4_LookupFailureType;



/* Minimum size of a scheduling context (2^{n} bytes) */


/* the size of a scheduling context, excluding extra refills */

/* the size of a single extra refill */


/*
 * @brief Calculate the max extra refills a scheduling context can contain for a specific size.
 *
 * @param  size of the schedulding context. Must be >= seL4_MinSchedContextBits
 * @return the max number of extra refills that can be passed to seL4_SchedControl_Configure for
 *         this scheduling context
 */
static inline seL4_Word seL4_MaxExtraRefills(seL4_Word size)
{
    return ((1ul<<(size)) - (10 * sizeof(seL4_Word) + (6 * 8))) / (2 * 8);
}
# 17 "/home/koc034/Documents/newver/seL4/include/api/types.h" 2
# 1 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/shared_types.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       

/* this file is shared between the kernel and libsel4 */

typedef struct seL4_IPCBuffer_ {
    seL4_MessageInfo_t tag;
    seL4_Word msg[seL4_MsgMaxLength];
    seL4_Word userData;
    seL4_Word caps_or_badges[((1ul<<(seL4_MsgExtraCapBits))-1)];
    seL4_CPtr receiveCNode;
    seL4_CPtr receiveIndex;
    seL4_Word receiveDepth;
} seL4_IPCBuffer __attribute__((__aligned__(sizeof(struct seL4_IPCBuffer_))));

typedef enum {
    seL4_CapFault_IP,
    seL4_CapFault_Addr,
    seL4_CapFault_InRecvPhase,
    seL4_CapFault_LookupFailureType,
    seL4_CapFault_BitsLeft,
    seL4_CapFault_DepthMismatch_BitsFound,
    seL4_CapFault_GuardMismatch_GuardFound = seL4_CapFault_DepthMismatch_BitsFound,
    seL4_CapFault_GuardMismatch_BitsFound,
    _enum_pad_seL4_CapFault_Msg = (1ULL << ((sizeof(long)*8) - 1)) - 1,
} seL4_CapFault_Msg;
# 18 "/home/koc034/Documents/newver/seL4/include/api/types.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/machine/io.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 35 "/home/koc034/Documents/newver/seL4/include/machine/io.h"
/* printf will NOT result in output */
# 19 "/home/koc034/Documents/newver/seL4/include/api/types.h" 2

/* seL4_CapRights_t defined in mode/api/shared_types.bf */

typedef word_t prio_t;
typedef uint64_t ticks_t;
typedef uint64_t time_t;

enum domainConstants {
    minDom = 0,
    maxDom = 16 - 1
};

struct cap_transfer {
    cptr_t ctReceiveRoot;
    cptr_t ctReceiveIndex;
    word_t ctReceiveDepth;
};
typedef struct cap_transfer cap_transfer_t;

enum ctLimits {
    capTransferDataSize = 3
};

static inline seL4_CapRights_t __attribute__((__const__)) rightsFromWord(word_t w)
{
    seL4_CapRights_t seL4_CapRights;

    seL4_CapRights.words[0] = w;
    return seL4_CapRights;
}

static inline word_t __attribute__((__const__)) wordFromRights(seL4_CapRights_t seL4_CapRights)
{
    return seL4_CapRights.words[0] & ((1ul << (4))-1ul);
}

static inline cap_transfer_t __attribute__((__pure__)) capTransferFromWords(word_t *wptr)
{
    cap_transfer_t transfer;

    transfer.ctReceiveRoot = (cptr_t)wptr[0];
    transfer.ctReceiveIndex = (cptr_t)wptr[1];
    transfer.ctReceiveDepth = wptr[2];
    return transfer;
}

static inline seL4_MessageInfo_t __attribute__((__const__)) messageInfoFromWord_raw(word_t w)
{
    seL4_MessageInfo_t mi;

    mi.words[0] = w;
    return mi;
}

static inline seL4_MessageInfo_t __attribute__((__const__)) messageInfoFromWord(word_t w)
{
    seL4_MessageInfo_t mi;
    word_t len;

    mi.words[0] = w;

    len = seL4_MessageInfo_get_length(mi);
    if (len > seL4_MsgMaxLength) {
        mi = seL4_MessageInfo_set_length(mi, seL4_MsgMaxLength);
    }

    return mi;
}

static inline word_t __attribute__((__const__)) wordFromMessageInfo(seL4_MessageInfo_t mi)
{
    return mi.words[0];
}
# 11 "/home/koc034/Documents/newver/seL4/include/compound_types.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/object/structures.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




# 1 "/home/koc034/Documents/newver/graph-refine/seL4-example/target/RISCV64-MCS-O1/build/generated/arch/object/structures_gen.h" 1







struct call_stack {
    uint64_t words[1];
};
typedef struct call_stack call_stack_t;

static inline call_stack_t __attribute__((__const__))
call_stack_new(uint64_t callStackPtr, uint64_t isHead) {
    call_stack_t call_stack;

    /* fail if user has passed bits that we will override */
    ;
    ;

    call_stack.words[0] = 0
        | (isHead & 0x1ull) << 48
        | (callStackPtr & 0x7fffffffffull) >> 0;

    return call_stack;
}

static inline uint64_t __attribute__((__const__))
call_stack_get_isHead(call_stack_t call_stack) {
    uint64_t ret;
    ret = (call_stack.words[0] & 0x1000000000000ull) >> 48;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
call_stack_get_callStackPtr(call_stack_t call_stack) {
    uint64_t ret;
    ret = (call_stack.words[0] & 0x7fffffffffull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

struct endpoint {
    uint64_t words[2];
};
typedef struct endpoint endpoint_t;

static inline uint64_t __attribute__((__pure__))
endpoint_ptr_get_epQueue_head(endpoint_t *endpoint_ptr) {
    uint64_t ret;
    ret = (endpoint_ptr->words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
endpoint_ptr_set_epQueue_head(endpoint_t *endpoint_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    endpoint_ptr->words[1] &= ~0xffffffffffffffffull;
    endpoint_ptr->words[1] |= (v64 << 0) & 0xffffffffffffffff;
}

static inline uint64_t __attribute__((__pure__))
endpoint_ptr_get_epQueue_tail(endpoint_t *endpoint_ptr) {
    uint64_t ret;
    ret = (endpoint_ptr->words[0] & 0x7ffffffffcull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline void
endpoint_ptr_set_epQueue_tail(endpoint_t *endpoint_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    endpoint_ptr->words[0] &= ~0x7ffffffffcull;
    endpoint_ptr->words[0] |= (v64 >> 0) & 0x7ffffffffc;
}

static inline uint64_t __attribute__((__pure__))
endpoint_ptr_get_state(endpoint_t *endpoint_ptr) {
    uint64_t ret;
    ret = (endpoint_ptr->words[0] & 0x3ull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
endpoint_ptr_set_state(endpoint_t *endpoint_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    endpoint_ptr->words[0] &= ~0x3ull;
    endpoint_ptr->words[0] |= (v64 << 0) & 0x3;
}

struct mdb_node {
    uint64_t words[2];
};
typedef struct mdb_node mdb_node_t;

static inline mdb_node_t __attribute__((__const__))
mdb_node_new(uint64_t mdbNext, uint64_t mdbRevocable, uint64_t mdbFirstBadged, uint64_t mdbPrev) {
    mdb_node_t mdb_node;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;

    mdb_node.words[0] = 0
        | mdbPrev << 0;;
    mdb_node.words[1] = 0
        | (mdbNext & 0x7ffffffffcull) >> 0
        | (mdbRevocable & 0x1ull) << 1
        | (mdbFirstBadged & 0x1ull) << 0;

    return mdb_node;
}

static inline uint64_t __attribute__((__const__))
mdb_node_get_mdbNext(mdb_node_t mdb_node) {
    uint64_t ret;
    ret = (mdb_node.words[1] & 0x7ffffffffcull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline void
mdb_node_ptr_set_mdbNext(mdb_node_t *mdb_node_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    mdb_node_ptr->words[1] &= ~0x7ffffffffcull;
    mdb_node_ptr->words[1] |= (v64 >> 0) & 0x7ffffffffc;
}

static inline uint64_t __attribute__((__const__))
mdb_node_get_mdbRevocable(mdb_node_t mdb_node) {
    uint64_t ret;
    ret = (mdb_node.words[1] & 0x2ull) >> 1;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline mdb_node_t __attribute__((__const__))
mdb_node_set_mdbRevocable(mdb_node_t mdb_node, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    mdb_node.words[1] &= ~0x2ull;
    mdb_node.words[1] |= (v64 << 1) & 0x2ull;
    return mdb_node;
}

static inline void
mdb_node_ptr_set_mdbRevocable(mdb_node_t *mdb_node_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    mdb_node_ptr->words[1] &= ~0x2ull;
    mdb_node_ptr->words[1] |= (v64 << 1) & 0x2;
}

static inline uint64_t __attribute__((__const__))
mdb_node_get_mdbFirstBadged(mdb_node_t mdb_node) {
    uint64_t ret;
    ret = (mdb_node.words[1] & 0x1ull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline mdb_node_t __attribute__((__const__))
mdb_node_set_mdbFirstBadged(mdb_node_t mdb_node, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    mdb_node.words[1] &= ~0x1ull;
    mdb_node.words[1] |= (v64 << 0) & 0x1ull;
    return mdb_node;
}

static inline void
mdb_node_ptr_set_mdbFirstBadged(mdb_node_t *mdb_node_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    mdb_node_ptr->words[1] &= ~0x1ull;
    mdb_node_ptr->words[1] |= (v64 << 0) & 0x1;
}

static inline uint64_t __attribute__((__const__))
mdb_node_get_mdbPrev(mdb_node_t mdb_node) {
    uint64_t ret;
    ret = (mdb_node.words[0] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline mdb_node_t __attribute__((__const__))
mdb_node_set_mdbPrev(mdb_node_t mdb_node, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    mdb_node.words[0] &= ~0xffffffffffffffffull;
    mdb_node.words[0] |= (v64 << 0) & 0xffffffffffffffffull;
    return mdb_node;
}

static inline void
mdb_node_ptr_set_mdbPrev(mdb_node_t *mdb_node_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    mdb_node_ptr->words[0] &= ~0xffffffffffffffffull;
    mdb_node_ptr->words[0] |= (v64 << 0) & 0xffffffffffffffff;
}

struct notification {
    uint64_t words[5];
};
typedef struct notification notification_t;

static inline uint64_t __attribute__((__pure__))
notification_ptr_get_ntfnSchedContext(notification_t *notification_ptr) {
    uint64_t ret;
    ret = (notification_ptr->words[4] & 0x7fffffffffull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline void
notification_ptr_set_ntfnSchedContext(notification_t *notification_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    notification_ptr->words[4] &= ~0x7fffffffffull;
    notification_ptr->words[4] |= (v64 >> 0) & 0x7fffffffff;
}

static inline uint64_t __attribute__((__pure__))
notification_ptr_get_ntfnBoundTCB(notification_t *notification_ptr) {
    uint64_t ret;
    ret = (notification_ptr->words[3] & 0x7fffffffffull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline void
notification_ptr_set_ntfnBoundTCB(notification_t *notification_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    notification_ptr->words[3] &= ~0x7fffffffffull;
    notification_ptr->words[3] |= (v64 >> 0) & 0x7fffffffff;
}

static inline uint64_t __attribute__((__pure__))
notification_ptr_get_ntfnMsgIdentifier(notification_t *notification_ptr) {
    uint64_t ret;
    ret = (notification_ptr->words[2] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
notification_ptr_set_ntfnMsgIdentifier(notification_t *notification_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    notification_ptr->words[2] &= ~0xffffffffffffffffull;
    notification_ptr->words[2] |= (v64 << 0) & 0xffffffffffffffff;
}

static inline uint64_t __attribute__((__pure__))
notification_ptr_get_ntfnQueue_head(notification_t *notification_ptr) {
    uint64_t ret;
    ret = (notification_ptr->words[1] & 0x7fffffffffull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline void
notification_ptr_set_ntfnQueue_head(notification_t *notification_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    notification_ptr->words[1] &= ~0x7fffffffffull;
    notification_ptr->words[1] |= (v64 >> 0) & 0x7fffffffff;
}

static inline uint64_t __attribute__((__pure__))
notification_ptr_get_ntfnQueue_tail(notification_t *notification_ptr) {
    uint64_t ret;
    ret = (notification_ptr->words[0] & 0xfffffffffe000000ull) >> 25;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline void
notification_ptr_set_ntfnQueue_tail(notification_t *notification_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    notification_ptr->words[0] &= ~0xfffffffffe000000ull;
    notification_ptr->words[0] |= (v64 << 25) & 0xfffffffffe000000;
}

static inline uint64_t __attribute__((__pure__))
notification_ptr_get_state(notification_t *notification_ptr) {
    uint64_t ret;
    ret = (notification_ptr->words[0] & 0x3ull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
notification_ptr_set_state(notification_t *notification_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    notification_ptr->words[0] &= ~0x3ull;
    notification_ptr->words[0] |= (v64 << 0) & 0x3;
}

struct pte {
    uint64_t words[1];
};
typedef struct pte pte_t;

static inline pte_t __attribute__((__const__))
pte_new(uint64_t ppn, uint64_t sw, uint64_t dirty, uint64_t accessed, uint64_t global, uint64_t user, uint64_t execute, uint64_t write, uint64_t read, uint64_t valid) {
    pte_t pte;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;
    ;
    ;
    ;
    ;
    ;
    ;
    ;

    pte.words[0] = 0
        | (ppn & 0xfffffffffffull) << 10
        | (sw & 0x3ull) << 8
        | (dirty & 0x1ull) << 7
        | (accessed & 0x1ull) << 6
        | (global & 0x1ull) << 5
        | (user & 0x1ull) << 4
        | (execute & 0x1ull) << 3
        | (write & 0x1ull) << 2
        | (read & 0x1ull) << 1
        | (valid & 0x1ull) << 0;

    return pte;
}

static inline uint64_t __attribute__((__pure__))
pte_ptr_get_ppn(pte_t *pte_ptr) {
    uint64_t ret;
    ret = (pte_ptr->words[0] & 0x3ffffffffffc00ull) >> 10;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__pure__))
pte_ptr_get_execute(pte_t *pte_ptr) {
    uint64_t ret;
    ret = (pte_ptr->words[0] & 0x8ull) >> 3;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__pure__))
pte_ptr_get_write(pte_t *pte_ptr) {
    uint64_t ret;
    ret = (pte_ptr->words[0] & 0x4ull) >> 2;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__pure__))
pte_ptr_get_read(pte_t *pte_ptr) {
    uint64_t ret;
    ret = (pte_ptr->words[0] & 0x2ull) >> 1;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__pure__))
pte_ptr_get_valid(pte_t *pte_ptr) {
    uint64_t ret;
    ret = (pte_ptr->words[0] & 0x1ull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

struct satp {
    uint64_t words[1];
};
typedef struct satp satp_t;

static inline satp_t __attribute__((__const__))
satp_new(uint64_t mode, uint64_t asid, uint64_t ppn) {
    satp_t satp;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;

    satp.words[0] = 0
        | (mode & 0xfull) << 60
        | (asid & 0xffffull) << 44
        | (ppn & 0xfffffffffffull) << 0;

    return satp;
}

struct thread_state {
    uint64_t words[3];
};
typedef struct thread_state thread_state_t;

static inline uint64_t __attribute__((__pure__))
thread_state_ptr_get_blockingIPCBadge(thread_state_t *thread_state_ptr) {
    uint64_t ret;
    ret = (thread_state_ptr->words[2] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
thread_state_ptr_set_blockingIPCBadge(thread_state_t *thread_state_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    thread_state_ptr->words[2] &= ~0xffffffffffffffffull;
    thread_state_ptr->words[2] |= (v64 << 0) & 0xffffffffffffffff;
}

static inline uint64_t __attribute__((__const__))
thread_state_get_replyObject(thread_state_t thread_state) {
    uint64_t ret;
    ret = (thread_state.words[1] & 0xffffffffe0ull) >> 1;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline void
thread_state_ptr_set_replyObject(thread_state_t *thread_state_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    thread_state_ptr->words[1] &= ~0xffffffffe0ull;
    thread_state_ptr->words[1] |= (v64 << 1) & 0xffffffffe0;
}

static inline uint64_t __attribute__((__pure__))
thread_state_ptr_get_blockingIPCCanGrant(thread_state_t *thread_state_ptr) {
    uint64_t ret;
    ret = (thread_state_ptr->words[1] & 0x10ull) >> 4;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
thread_state_ptr_set_blockingIPCCanGrant(thread_state_t *thread_state_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    thread_state_ptr->words[1] &= ~0x10ull;
    thread_state_ptr->words[1] |= (v64 << 4) & 0x10;
}

static inline uint64_t __attribute__((__pure__))
thread_state_ptr_get_blockingIPCCanGrantReply(thread_state_t *thread_state_ptr) {
    uint64_t ret;
    ret = (thread_state_ptr->words[1] & 0x8ull) >> 3;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
thread_state_ptr_set_blockingIPCCanGrantReply(thread_state_t *thread_state_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    thread_state_ptr->words[1] &= ~0x8ull;
    thread_state_ptr->words[1] |= (v64 << 3) & 0x8;
}

static inline uint64_t __attribute__((__pure__))
thread_state_ptr_get_blockingIPCIsCall(thread_state_t *thread_state_ptr) {
    uint64_t ret;
    ret = (thread_state_ptr->words[1] & 0x4ull) >> 2;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
thread_state_ptr_set_blockingIPCIsCall(thread_state_t *thread_state_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    thread_state_ptr->words[1] &= ~0x4ull;
    thread_state_ptr->words[1] |= (v64 << 2) & 0x4;
}

static inline uint64_t __attribute__((__const__))
thread_state_get_tcbQueued(thread_state_t thread_state) {
    uint64_t ret;
    ret = (thread_state.words[1] & 0x2ull) >> 1;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
thread_state_ptr_set_tcbQueued(thread_state_t *thread_state_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    thread_state_ptr->words[1] &= ~0x2ull;
    thread_state_ptr->words[1] |= (v64 << 1) & 0x2;
}

static inline uint64_t __attribute__((__const__))
thread_state_get_tcbInReleaseQueue(thread_state_t thread_state) {
    uint64_t ret;
    ret = (thread_state.words[1] & 0x1ull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
thread_state_ptr_set_tcbInReleaseQueue(thread_state_t *thread_state_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    thread_state_ptr->words[1] &= ~0x1ull;
    thread_state_ptr->words[1] |= (v64 << 0) & 0x1;
}

static inline uint64_t __attribute__((__const__))
thread_state_get_blockingObject(thread_state_t thread_state) {
    uint64_t ret;
    ret = (thread_state.words[0] & 0x7ffffffff0ull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline uint64_t __attribute__((__pure__))
thread_state_ptr_get_blockingObject(thread_state_t *thread_state_ptr) {
    uint64_t ret;
    ret = (thread_state_ptr->words[0] & 0x7ffffffff0ull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline void
thread_state_ptr_set_blockingObject(thread_state_t *thread_state_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    thread_state_ptr->words[0] &= ~0x7ffffffff0ull;
    thread_state_ptr->words[0] |= (v64 >> 0) & 0x7ffffffff0;
}

static inline uint64_t __attribute__((__const__))
thread_state_get_tsType(thread_state_t thread_state) {
    uint64_t ret;
    ret = (thread_state.words[0] & 0xfull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__pure__))
thread_state_ptr_get_tsType(thread_state_t *thread_state_ptr) {
    uint64_t ret;
    ret = (thread_state_ptr->words[0] & 0xfull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline void
thread_state_ptr_set_tsType(thread_state_t *thread_state_ptr, uint64_t v64) {
    /* fail if user has passed bits that we will override */
    ;
    thread_state_ptr->words[0] &= ~0xfull;
    thread_state_ptr->words[0] |= (v64 << 0) & 0xf;
}

struct vm_attributes {
    uint64_t words[1];
};
typedef struct vm_attributes vm_attributes_t;

static inline uint64_t __attribute__((__const__))
vm_attributes_get_riscvExecuteNever(vm_attributes_t vm_attributes) {
    uint64_t ret;
    ret = (vm_attributes.words[0] & 0x1ull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

struct cap {
    uint64_t words[2];
};
typedef struct cap cap_t;

enum cap_tag {
    cap_null_cap = 0,
    cap_untyped_cap = 2,
    cap_endpoint_cap = 4,
    cap_notification_cap = 6,
    cap_reply_cap = 8,
    cap_cnode_cap = 10,
    cap_thread_cap = 12,
    cap_irq_control_cap = 14,
    cap_irq_handler_cap = 16,
    cap_zombie_cap = 18,
    cap_domain_cap = 20,
    cap_sched_context_cap = 22,
    cap_sched_control_cap = 24,
    cap_frame_cap = 1,
    cap_page_table_cap = 3,
    cap_asid_control_cap = 11,
    cap_asid_pool_cap = 13
};
typedef enum cap_tag cap_tag_t;

static inline uint64_t __attribute__((__const__))
cap_get_capType(cap_t cap) {
    return (cap.words[0] >> 59) & 0x1full;
}

static inline int __attribute__((__const__))
cap_capType_equals(cap_t cap, uint64_t cap_type_tag) {
    return ((cap.words[0] >> 59) & 0x1full) == cap_type_tag;
}

static inline cap_t __attribute__((__const__))
cap_null_cap_new(void) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_null_cap & 0x1full) << 59;
    cap.words[1] = 0;

    return cap;
}

static inline cap_t __attribute__((__const__))
cap_untyped_cap_new(uint64_t capFreeIndex, uint64_t capIsDevice, uint64_t capBlockSize, uint64_t capPtr) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;
    ;
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_untyped_cap & 0x1full) << 59
        | (capPtr & 0x7fffffffffull) >> 0;
    cap.words[1] = 0
        | (capFreeIndex & 0x7fffffffffull) << 25
        | (capIsDevice & 0x1ull) << 6
        | (capBlockSize & 0x3full) << 0;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_untyped_cap_get_capFreeIndex(cap_t cap) {
    uint64_t ret;
   
                           ;

    ret = (cap.words[1] & 0xfffffffffe000000ull) >> 25;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_untyped_cap_set_capFreeIndex(cap_t cap, uint64_t v64) {
   
                           ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[1] &= ~0xfffffffffe000000ull;
    cap.words[1] |= (v64 << 25) & 0xfffffffffe000000ull;
    return cap;
}

static inline void
cap_untyped_cap_ptr_set_capFreeIndex(cap_t *cap_ptr,
                                      uint64_t v64) {
   
                           ;

    /* fail if user has passed bits that we will override */
    ;

    cap_ptr->words[1] &= ~0xfffffffffe000000ull;
    cap_ptr->words[1] |= (v64 << 25) & 0xfffffffffe000000ull;
}

static inline uint64_t __attribute__((__const__))
cap_untyped_cap_get_capIsDevice(cap_t cap) {
    uint64_t ret;
   
                           ;

    ret = (cap.words[1] & 0x40ull) >> 6;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
cap_untyped_cap_get_capBlockSize(cap_t cap) {
    uint64_t ret;
   
                           ;

    ret = (cap.words[1] & 0x3full) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
cap_untyped_cap_get_capPtr(cap_t cap) {
    uint64_t ret;
   
                           ;

    ret = (cap.words[0] & 0x7fffffffffull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_endpoint_cap_new(uint64_t capEPBadge, uint64_t capCanGrantReply, uint64_t capCanGrant, uint64_t capCanSend, uint64_t capCanReceive, uint64_t capEPPtr) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;
    ;
    ;
    ;

    cap.words[0] = 0
        | (capCanGrantReply & 0x1ull) << 58
        | (capCanGrant & 0x1ull) << 57
        | (capCanSend & 0x1ull) << 55
        | (capCanReceive & 0x1ull) << 56
        | (capEPPtr & 0x7fffffffffull) >> 0
        | ((uint64_t)cap_endpoint_cap & 0x1full) << 59;
    cap.words[1] = 0
        | capEPBadge << 0;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_endpoint_cap_get_capEPBadge(cap_t cap) {
    uint64_t ret;
   
                            ;

    ret = (cap.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_endpoint_cap_set_capEPBadge(cap_t cap, uint64_t v64) {
   
                            ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[1] &= ~0xffffffffffffffffull;
    cap.words[1] |= (v64 << 0) & 0xffffffffffffffffull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_endpoint_cap_get_capCanGrantReply(cap_t cap) {
    uint64_t ret;
   
                            ;

    ret = (cap.words[0] & 0x400000000000000ull) >> 58;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_endpoint_cap_set_capCanGrantReply(cap_t cap, uint64_t v64) {
   
                            ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x400000000000000ull;
    cap.words[0] |= (v64 << 58) & 0x400000000000000ull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_endpoint_cap_get_capCanGrant(cap_t cap) {
    uint64_t ret;
   
                            ;

    ret = (cap.words[0] & 0x200000000000000ull) >> 57;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_endpoint_cap_set_capCanGrant(cap_t cap, uint64_t v64) {
   
                            ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x200000000000000ull;
    cap.words[0] |= (v64 << 57) & 0x200000000000000ull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_endpoint_cap_get_capCanReceive(cap_t cap) {
    uint64_t ret;
   
                            ;

    ret = (cap.words[0] & 0x100000000000000ull) >> 56;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_endpoint_cap_set_capCanReceive(cap_t cap, uint64_t v64) {
   
                            ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x100000000000000ull;
    cap.words[0] |= (v64 << 56) & 0x100000000000000ull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_endpoint_cap_get_capCanSend(cap_t cap) {
    uint64_t ret;
   
                            ;

    ret = (cap.words[0] & 0x80000000000000ull) >> 55;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_endpoint_cap_set_capCanSend(cap_t cap, uint64_t v64) {
   
                            ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x80000000000000ull;
    cap.words[0] |= (v64 << 55) & 0x80000000000000ull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_endpoint_cap_get_capEPPtr(cap_t cap) {
    uint64_t ret;
   
                            ;

    ret = (cap.words[0] & 0x7fffffffffull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_notification_cap_new(uint64_t capNtfnBadge, uint64_t capNtfnCanReceive, uint64_t capNtfnCanSend, uint64_t capNtfnPtr) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_notification_cap & 0x1full) << 59
        | (capNtfnCanReceive & 0x1ull) << 58
        | (capNtfnCanSend & 0x1ull) << 57
        | (capNtfnPtr & 0x7fffffffffull) >> 0;
    cap.words[1] = 0
        | capNtfnBadge << 0;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_notification_cap_get_capNtfnBadge(cap_t cap) {
    uint64_t ret;
   
                                ;

    ret = (cap.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_notification_cap_set_capNtfnBadge(cap_t cap, uint64_t v64) {
   
                                ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[1] &= ~0xffffffffffffffffull;
    cap.words[1] |= (v64 << 0) & 0xffffffffffffffffull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_notification_cap_get_capNtfnCanReceive(cap_t cap) {
    uint64_t ret;
   
                                ;

    ret = (cap.words[0] & 0x400000000000000ull) >> 58;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_notification_cap_set_capNtfnCanReceive(cap_t cap, uint64_t v64) {
   
                                ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x400000000000000ull;
    cap.words[0] |= (v64 << 58) & 0x400000000000000ull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_notification_cap_get_capNtfnCanSend(cap_t cap) {
    uint64_t ret;
   
                                ;

    ret = (cap.words[0] & 0x200000000000000ull) >> 57;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_notification_cap_set_capNtfnCanSend(cap_t cap, uint64_t v64) {
   
                                ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x200000000000000ull;
    cap.words[0] |= (v64 << 57) & 0x200000000000000ull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_notification_cap_get_capNtfnPtr(cap_t cap) {
    uint64_t ret;
   
                                ;

    ret = (cap.words[0] & 0x7fffffffffull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_reply_cap_new(uint64_t capReplyPtr, uint64_t capReplyCanGrant) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_reply_cap & 0x1full) << 59
        | (capReplyCanGrant & 0x1ull) << 58;
    cap.words[1] = 0
        | capReplyPtr << 0;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_reply_cap_get_capReplyPtr(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
cap_reply_cap_get_capReplyCanGrant(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[0] & 0x400000000000000ull) >> 58;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_reply_cap_set_capReplyCanGrant(cap_t cap, uint64_t v64) {
   
                         ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x400000000000000ull;
    cap.words[0] |= (v64 << 58) & 0x400000000000000ull;
    return cap;
}

static inline cap_t __attribute__((__const__))
cap_cnode_cap_new(uint64_t capCNodeRadix, uint64_t capCNodeGuardSize, uint64_t capCNodeGuard, uint64_t capCNodePtr) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;
    ;

    cap.words[0] = 0
        | (capCNodeRadix & 0x3full) << 47
        | (capCNodeGuardSize & 0x3full) << 53
        | (capCNodePtr & 0x7ffffffffeull) >> 1
        | ((uint64_t)cap_cnode_cap & 0x1full) << 59;
    cap.words[1] = 0
        | capCNodeGuard << 0;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_cnode_cap_get_capCNodeGuard(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_cnode_cap_set_capCNodeGuard(cap_t cap, uint64_t v64) {
   
                         ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[1] &= ~0xffffffffffffffffull;
    cap.words[1] |= (v64 << 0) & 0xffffffffffffffffull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_cnode_cap_get_capCNodeGuardSize(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[0] & 0x7e0000000000000ull) >> 53;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_cnode_cap_set_capCNodeGuardSize(cap_t cap, uint64_t v64) {
   
                         ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x7e0000000000000ull;
    cap.words[0] |= (v64 << 53) & 0x7e0000000000000ull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_cnode_cap_get_capCNodeRadix(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[0] & 0x1f800000000000ull) >> 47;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
cap_cnode_cap_get_capCNodePtr(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[0] & 0x3fffffffffull) << 1;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_thread_cap_new(uint64_t capTCBPtr) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_thread_cap & 0x1full) << 59
        | (capTCBPtr & 0x7fffffffffull) >> 0;
    cap.words[1] = 0;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_thread_cap_get_capTCBPtr(cap_t cap) {
    uint64_t ret;
   
                          ;

    ret = (cap.words[0] & 0x7fffffffffull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_irq_control_cap_new(void) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_irq_control_cap & 0x1full) << 59;
    cap.words[1] = 0;

    return cap;
}

static inline cap_t __attribute__((__const__))
cap_irq_handler_cap_new(uint64_t capIRQ) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_irq_handler_cap & 0x1full) << 59;
    cap.words[1] = 0
        | (capIRQ & 0xfffull) << 0;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_irq_handler_cap_get_capIRQ(cap_t cap) {
    uint64_t ret;
   
                               ;

    ret = (cap.words[1] & 0xfffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_zombie_cap_new(uint64_t capZombieID, uint64_t capZombieType) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_zombie_cap & 0x1full) << 59
        | (capZombieType & 0x7full) << 0;
    cap.words[1] = 0
        | capZombieID << 0;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_zombie_cap_get_capZombieID(cap_t cap) {
    uint64_t ret;
   
                          ;

    ret = (cap.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_zombie_cap_set_capZombieID(cap_t cap, uint64_t v64) {
   
                          ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[1] &= ~0xffffffffffffffffull;
    cap.words[1] |= (v64 << 0) & 0xffffffffffffffffull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_zombie_cap_get_capZombieType(cap_t cap) {
    uint64_t ret;
   
                          ;

    ret = (cap.words[0] & 0x7full) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_domain_cap_new(void) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_domain_cap & 0x1full) << 59;
    cap.words[1] = 0;

    return cap;
}

static inline cap_t __attribute__((__const__))
cap_sched_context_cap_new(uint64_t capSCPtr, uint64_t capSCSizeBits) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_sched_context_cap & 0x1full) << 59;
    cap.words[1] = 0
        | (capSCPtr & 0x7fffffffffull) << 16
        | (capSCSizeBits & 0x3full) << 10;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_sched_context_cap_get_capSCPtr(cap_t cap) {
    uint64_t ret;
   
                                 ;

    ret = (cap.words[1] & 0x7fffffffff0000ull) >> 16;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
cap_sched_context_cap_get_capSCSizeBits(cap_t cap) {
    uint64_t ret;
   
                                 ;

    ret = (cap.words[1] & 0xfc00ull) >> 10;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_sched_control_cap_new(uint64_t core) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_sched_control_cap & 0x1full) << 59;
    cap.words[1] = 0
        | core << 0;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_sched_control_cap_get_core(cap_t cap) {
    uint64_t ret;
   
                                 ;

    ret = (cap.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_frame_cap_new(uint64_t capFMappedASID, uint64_t capFBasePtr, uint64_t capFSize, uint64_t capFVMRights, uint64_t capFIsDevice, uint64_t capFMappedAddress) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;
    ;
    ;
    ;
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_frame_cap & 0x1full) << 59
        | (capFSize & 0x3ull) << 57
        | (capFVMRights & 0x3ull) << 55
        | (capFIsDevice & 0x1ull) << 54
        | (capFMappedAddress & 0x7fffffffffull) >> 0;
    cap.words[1] = 0
        | (capFMappedASID & 0xffffull) << 48
        | (capFBasePtr & 0x7fffffffffull) << 9;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_frame_cap_get_capFMappedASID(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[1] & 0xffff000000000000ull) >> 48;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_frame_cap_set_capFMappedASID(cap_t cap, uint64_t v64) {
   
                         ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[1] &= ~0xffff000000000000ull;
    cap.words[1] |= (v64 << 48) & 0xffff000000000000ull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_frame_cap_get_capFBasePtr(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[1] & 0xfffffffffe00ull) >> 9;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
cap_frame_cap_get_capFSize(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[0] & 0x600000000000000ull) >> 57;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
cap_frame_cap_get_capFVMRights(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[0] & 0x180000000000000ull) >> 55;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_frame_cap_set_capFVMRights(cap_t cap, uint64_t v64) {
   
                         ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x180000000000000ull;
    cap.words[0] |= (v64 << 55) & 0x180000000000000ull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_frame_cap_get_capFIsDevice(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[0] & 0x40000000000000ull) >> 54;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
cap_frame_cap_get_capFMappedAddress(cap_t cap) {
    uint64_t ret;
   
                         ;

    ret = (cap.words[0] & 0x7fffffffffull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_frame_cap_set_capFMappedAddress(cap_t cap, uint64_t v64) {
   
                         ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x7fffffffffull;
    cap.words[0] |= (v64 >> 0) & 0x7fffffffffull;
    return cap;
}

static inline cap_t __attribute__((__const__))
cap_page_table_cap_new(uint64_t capPTMappedASID, uint64_t capPTBasePtr, uint64_t capPTIsMapped, uint64_t capPTMappedAddress) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;
    ;
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_page_table_cap & 0x1full) << 59
        | (capPTIsMapped & 0x1ull) << 39
        | (capPTMappedAddress & 0x7fffffffffull) >> 0;
    cap.words[1] = 0
        | (capPTMappedASID & 0xffffull) << 48
        | (capPTBasePtr & 0x7fffffffffull) << 9;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_page_table_cap_get_capPTMappedASID(cap_t cap) {
    uint64_t ret;
   
                              ;

    ret = (cap.words[1] & 0xffff000000000000ull) >> 48;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_page_table_cap_set_capPTMappedASID(cap_t cap, uint64_t v64) {
   
                              ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[1] &= ~0xffff000000000000ull;
    cap.words[1] |= (v64 << 48) & 0xffff000000000000ull;
    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_page_table_cap_get_capPTBasePtr(cap_t cap) {
    uint64_t ret;
   
                              ;

    ret = (cap.words[1] & 0xfffffffffe00ull) >> 9;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
cap_page_table_cap_get_capPTIsMapped(cap_t cap) {
    uint64_t ret;
   
                              ;

    ret = (cap.words[0] & 0x8000000000ull) >> 39;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_page_table_cap_set_capPTIsMapped(cap_t cap, uint64_t v64) {
   
                              ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x8000000000ull;
    cap.words[0] |= (v64 << 39) & 0x8000000000ull;
    return cap;
}

static inline void
cap_page_table_cap_ptr_set_capPTIsMapped(cap_t *cap_ptr,
                                      uint64_t v64) {
   
                              ;

    /* fail if user has passed bits that we will override */
    ;

    cap_ptr->words[0] &= ~0x8000000000ull;
    cap_ptr->words[0] |= (v64 << 39) & 0x8000000000ull;
}

static inline uint64_t __attribute__((__const__))
cap_page_table_cap_get_capPTMappedAddress(cap_t cap) {
    uint64_t ret;
   
                              ;

    ret = (cap.words[0] & 0x7fffffffffull) << 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

static inline cap_t __attribute__((__const__))
cap_page_table_cap_set_capPTMappedAddress(cap_t cap, uint64_t v64) {
   
                              ;
    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] &= ~0x7fffffffffull;
    cap.words[0] |= (v64 >> 0) & 0x7fffffffffull;
    return cap;
}

static inline cap_t __attribute__((__const__))
cap_asid_control_cap_new(void) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_asid_control_cap & 0x1full) << 59;
    cap.words[1] = 0;

    return cap;
}

static inline cap_t __attribute__((__const__))
cap_asid_pool_cap_new(uint64_t capASIDBase, uint64_t capASIDPool) {
    cap_t cap;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;

    cap.words[0] = 0
        | ((uint64_t)cap_asid_pool_cap & 0x1full) << 59
        | (capASIDBase & 0xffffull) << 43
        | (capASIDPool & 0x7ffffffffcull) >> 2;
    cap.words[1] = 0;

    return cap;
}

static inline uint64_t __attribute__((__const__))
cap_asid_pool_cap_get_capASIDBase(cap_t cap) {
    uint64_t ret;
   
                             ;

    ret = (cap.words[0] & 0x7fff80000000000ull) >> 43;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
cap_asid_pool_cap_get_capASIDPool(cap_t cap) {
    uint64_t ret;
   
                             ;

    ret = (cap.words[0] & 0x1fffffffffull) << 2;
    /* Possibly sign extend */
    if (__builtin_expect(!!(1 && (ret & (1ull << (38)))), 1)) {
        ret |= 0xffffff8000000000;
    }
    return ret;
}

struct lookup_fault {
    uint64_t words[2];
};
typedef struct lookup_fault lookup_fault_t;

enum lookup_fault_tag {
    lookup_fault_invalid_root = 0,
    lookup_fault_missing_capability = 1,
    lookup_fault_depth_mismatch = 2,
    lookup_fault_guard_mismatch = 3
};
typedef enum lookup_fault_tag lookup_fault_tag_t;

static inline uint64_t __attribute__((__const__))
lookup_fault_get_lufType(lookup_fault_t lookup_fault) {
    return (lookup_fault.words[0] >> 0) & 0x3ull;
}

static inline lookup_fault_t __attribute__((__const__))
lookup_fault_invalid_root_new(void) {
    lookup_fault_t lookup_fault;

    /* fail if user has passed bits that we will override */
    ;

    lookup_fault.words[0] = 0
        | ((uint64_t)lookup_fault_invalid_root & 0x3ull) << 0;
    lookup_fault.words[1] = 0;

    return lookup_fault;
}

static inline lookup_fault_t __attribute__((__const__))
lookup_fault_missing_capability_new(uint64_t bitsLeft) {
    lookup_fault_t lookup_fault;

    /* fail if user has passed bits that we will override */
    ;
    ;

    lookup_fault.words[0] = 0
        | (bitsLeft & 0x7full) << 2
        | ((uint64_t)lookup_fault_missing_capability & 0x3ull) << 0;
    lookup_fault.words[1] = 0;

    return lookup_fault;
}

static inline uint64_t __attribute__((__const__))
lookup_fault_missing_capability_get_bitsLeft(lookup_fault_t lookup_fault) {
    uint64_t ret;
   
                                           ;

    ret = (lookup_fault.words[0] & 0x1fcull) >> 2;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline lookup_fault_t __attribute__((__const__))
lookup_fault_depth_mismatch_new(uint64_t bitsFound, uint64_t bitsLeft) {
    lookup_fault_t lookup_fault;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;

    lookup_fault.words[0] = 0
        | (bitsFound & 0x7full) << 9
        | (bitsLeft & 0x7full) << 2
        | ((uint64_t)lookup_fault_depth_mismatch & 0x3ull) << 0;
    lookup_fault.words[1] = 0;

    return lookup_fault;
}

static inline uint64_t __attribute__((__const__))
lookup_fault_depth_mismatch_get_bitsFound(lookup_fault_t lookup_fault) {
    uint64_t ret;
   
                                       ;

    ret = (lookup_fault.words[0] & 0xfe00ull) >> 9;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
lookup_fault_depth_mismatch_get_bitsLeft(lookup_fault_t lookup_fault) {
    uint64_t ret;
   
                                       ;

    ret = (lookup_fault.words[0] & 0x1fcull) >> 2;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline lookup_fault_t __attribute__((__const__))
lookup_fault_guard_mismatch_new(uint64_t guardFound, uint64_t bitsLeft, uint64_t bitsFound) {
    lookup_fault_t lookup_fault;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;

    lookup_fault.words[0] = 0
        | (bitsLeft & 0x7full) << 9
        | (bitsFound & 0x7full) << 2
        | ((uint64_t)lookup_fault_guard_mismatch & 0x3ull) << 0;
    lookup_fault.words[1] = 0
        | guardFound << 0;

    return lookup_fault;
}

static inline uint64_t __attribute__((__const__))
lookup_fault_guard_mismatch_get_guardFound(lookup_fault_t lookup_fault) {
    uint64_t ret;
   
                                       ;

    ret = (lookup_fault.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
lookup_fault_guard_mismatch_get_bitsLeft(lookup_fault_t lookup_fault) {
    uint64_t ret;
   
                                       ;

    ret = (lookup_fault.words[0] & 0xfe00ull) >> 9;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
lookup_fault_guard_mismatch_get_bitsFound(lookup_fault_t lookup_fault) {
    uint64_t ret;
   
                                       ;

    ret = (lookup_fault.words[0] & 0x1fcull) >> 2;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

struct seL4_Fault {
    uint64_t words[2];
};
typedef struct seL4_Fault seL4_Fault_t;

enum seL4_Fault_tag {
    seL4_Fault_NullFault = 0,
    seL4_Fault_CapFault = 1,
    seL4_Fault_UnknownSyscall = 2,
    seL4_Fault_UserException = 3,
    seL4_Fault_Timeout = 5,
    seL4_Fault_VMFault = 6
};
typedef enum seL4_Fault_tag seL4_Fault_tag_t;

static inline uint64_t __attribute__((__const__))
seL4_Fault_get_seL4_FaultType(seL4_Fault_t seL4_Fault) {
    return (seL4_Fault.words[0] >> 0) & 0xfull;
}

static inline uint64_t __attribute__((__pure__))
seL4_Fault_ptr_get_seL4_FaultType(seL4_Fault_t *seL4_Fault_ptr) {
    return (seL4_Fault_ptr->words[0] >> 0) & 0xfull;
}

static inline seL4_Fault_t __attribute__((__const__))
seL4_Fault_NullFault_new(void) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */
    ;

    seL4_Fault.words[0] = 0
        | ((uint64_t)seL4_Fault_NullFault & 0xfull) << 0;
    seL4_Fault.words[1] = 0;

    return seL4_Fault;
}

static inline void
seL4_Fault_NullFault_ptr_new(seL4_Fault_t *seL4_Fault_ptr) {
    /* fail if user has passed bits that we will override */
    ;

    seL4_Fault_ptr->words[0] = 0
        | ((uint64_t)seL4_Fault_NullFault & 0xfull) << 0;
    seL4_Fault_ptr->words[1] = 0;
}

static inline seL4_Fault_t __attribute__((__const__))
seL4_Fault_CapFault_new(uint64_t address, uint64_t inReceivePhase) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */
    ;
    ;

    seL4_Fault.words[0] = 0
        | (inReceivePhase & 0x1ull) << 63
        | ((uint64_t)seL4_Fault_CapFault & 0xfull) << 0;
    seL4_Fault.words[1] = 0
        | address << 0;

    return seL4_Fault;
}

static inline uint64_t __attribute__((__const__))
seL4_Fault_CapFault_get_address(seL4_Fault_t seL4_Fault) {
    uint64_t ret;
   
                               ;

    ret = (seL4_Fault.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
seL4_Fault_CapFault_get_inReceivePhase(seL4_Fault_t seL4_Fault) {
    uint64_t ret;
   
                               ;

    ret = (seL4_Fault.words[0] & 0x8000000000000000ull) >> 63;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline seL4_Fault_t __attribute__((__const__))
seL4_Fault_UnknownSyscall_new(uint64_t syscallNumber) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */
    ;

    seL4_Fault.words[0] = 0
        | ((uint64_t)seL4_Fault_UnknownSyscall & 0xfull) << 0;
    seL4_Fault.words[1] = 0
        | syscallNumber << 0;

    return seL4_Fault;
}

static inline uint64_t __attribute__((__const__))
seL4_Fault_UnknownSyscall_get_syscallNumber(seL4_Fault_t seL4_Fault) {
    uint64_t ret;
   
                                     ;

    ret = (seL4_Fault.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline seL4_Fault_t __attribute__((__const__))
seL4_Fault_UserException_new(uint64_t number, uint64_t code) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;

    seL4_Fault.words[0] = 0
        | (number & 0xffffffffull) << 32
        | (code & 0xfffffffull) << 4
        | ((uint64_t)seL4_Fault_UserException & 0xfull) << 0;
    seL4_Fault.words[1] = 0;

    return seL4_Fault;
}

static inline uint64_t __attribute__((__const__))
seL4_Fault_UserException_get_number(seL4_Fault_t seL4_Fault) {
    uint64_t ret;
   
                                    ;

    ret = (seL4_Fault.words[0] & 0xffffffff00000000ull) >> 32;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
seL4_Fault_UserException_get_code(seL4_Fault_t seL4_Fault) {
    uint64_t ret;
   
                                    ;

    ret = (seL4_Fault.words[0] & 0xfffffff0ull) >> 4;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline seL4_Fault_t __attribute__((__const__))
seL4_Fault_Timeout_new(uint64_t badge) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */
    ;

    seL4_Fault.words[0] = 0
        | ((uint64_t)seL4_Fault_Timeout & 0xfull) << 0;
    seL4_Fault.words[1] = 0
        | badge << 0;

    return seL4_Fault;
}

static inline uint64_t __attribute__((__const__))
seL4_Fault_Timeout_get_badge(seL4_Fault_t seL4_Fault) {
    uint64_t ret;
   
                              ;

    ret = (seL4_Fault.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline seL4_Fault_t __attribute__((__const__))
seL4_Fault_VMFault_new(uint64_t address, uint64_t FSR, uint64_t instructionFault) {
    seL4_Fault_t seL4_Fault;

    /* fail if user has passed bits that we will override */
    ;
    ;
    ;

    seL4_Fault.words[0] = 0
        | (FSR & 0x1full) << 27
        | (instructionFault & 0x1ull) << 19
        | ((uint64_t)seL4_Fault_VMFault & 0xfull) << 0;
    seL4_Fault.words[1] = 0
        | address << 0;

    return seL4_Fault;
}

static inline uint64_t __attribute__((__const__))
seL4_Fault_VMFault_get_address(seL4_Fault_t seL4_Fault) {
    uint64_t ret;
   
                              ;

    ret = (seL4_Fault.words[1] & 0xffffffffffffffffull) >> 0;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
seL4_Fault_VMFault_get_FSR(seL4_Fault_t seL4_Fault) {
    uint64_t ret;
   
                              ;

    ret = (seL4_Fault.words[0] & 0xf8000000ull) >> 27;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}

static inline uint64_t __attribute__((__const__))
seL4_Fault_VMFault_get_instructionFault(seL4_Fault_t seL4_Fault) {
    uint64_t ret;
   
                              ;

    ret = (seL4_Fault.words[0] & 0x80000ull) >> 19;
    /* Possibly sign extend */
    if (__builtin_expect(!!(0 && (ret & (1ull << (38)))), 0)) {
        ret |= 0x0;
    }
    return ret;
}
# 13 "/home/koc034/Documents/newver/seL4/include/object/structures.h" 2


# 1 "/home/koc034/Documents/newver/seL4/libsel4/arch_include/riscv/sel4/arch/constants.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       
# 16 "/home/koc034/Documents/newver/seL4/include/object/structures.h" 2
# 1 "/home/koc034/Documents/newver/seL4/libsel4/sel4_arch_include/riscv64/sel4/sel4_arch/constants.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       


# 1 "autoconf/autoconf.h" 1
# 12 "/home/koc034/Documents/newver/seL4/libsel4/sel4_arch_include/riscv64/sel4/sel4_arch/constants.h" 2



/* log 2 bits in a word */
# 33 "/home/koc034/Documents/newver/seL4/libsel4/sel4_arch_include/riscv64/sel4/sel4_arch/constants.h"
/* Sv39/Sv48 pages/ptes sizes */
# 48 "/home/koc034/Documents/newver/seL4/libsel4/sel4_arch_include/riscv64/sel4/sel4_arch/constants.h"
/* Untyped size limits */




typedef enum {
    seL4_VMFault_IP,
    seL4_VMFault_Addr,
    seL4_VMFault_PrefetchFault,
    seL4_VMFault_FSR,
    seL4_VMFault_Length,
} seL4_VMFault_Msg;

typedef enum {
    seL4_UnknownSyscall_FaultIP,
    seL4_UnknownSyscall_SP,
    seL4_UnknownSyscall_RA,
    seL4_UnknownSyscall_A0,
    seL4_UnknownSyscall_A1,
    seL4_UnknownSyscall_A2,
    seL4_UnknownSyscall_A3,
    seL4_UnknownSyscall_A4,
    seL4_UnknownSyscall_A5,
    seL4_UnknownSyscall_A6,
    seL4_UnknownSyscall_Syscall,
    seL4_UnknownSyscall_Length,
} seL4_UnknownSyscall_Msg;

typedef enum {
    seL4_UserException_FaultIP,
    seL4_UserException_SP,
    seL4_UserException_Number,
    seL4_UserException_Code,
    seL4_UserException_Length,
} seL4_UserException_Msg;


typedef enum {
    seL4_TimeoutReply_FaultIP,
    seL4_TimeoutReply_LR,
    seL4_TimeoutReply_SP,
    seL4_TimeoutReply_GP,
    seL4_TimeoutReply_s0,
    seL4_TimeoutReply_s1,
    seL4_TimeoutReply_s2,
    seL4_TimeoutReply_s3,
    seL4_TimeoutReply_s4,
    seL4_TimeoutReply_s5,
    seL4_TimeoutReply_s6,
    seL4_TimeoutReply_s7,
    seL4_TimeoutReply_s8,
    seL4_TimeoutReply_s9,
    seL4_TimeoutReply_s10,
    seL4_TimeoutReply_s11,
    seL4_TimeoutReply_a0,
    seL4_TimeoutReply_a1,
    seL4_TimeoutReply_a2,
    seL4_TimeoutReply_a3,
    seL4_TimeoutReply_a4,
    seL4_TimeoutReply_a5,
    seL4_TimeoutReply_a6,
    seL4_TimeoutReply_a7,
    seL4_TimeoutReply_t0,
    seL4_TimeoutReply_t1,
    seL4_TimeoutReply_t2,
    seL4_TimeoutReply_t3,
    seL4_TimeoutReply_t4,
    seL4_TimeoutReply_t5,
    seL4_TimeoutReply_t6,
    seL4_TimeoutReply_TP,
    seL4_TimeoutReply_Length,
} seL4_TimeoutReply_Msg;

typedef enum {
    seL4_Timeout_Data,
    seL4_Timeout_Consumed,
    seL4_Timeout_Length,
} seL4_TimeoutMsg;



/* First address in the virtual address space that is not accessible to user level */
# 17 "/home/koc034/Documents/newver/seL4/include/object/structures.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/benchmark/benchmark_utilisation_.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 18 "/home/koc034/Documents/newver/seL4/include/object/structures.h" 2

enum irq_state {
    IRQInactive = 0,
    IRQSignal = 1,
    IRQTimer = 2,



    IRQReserved
};
typedef word_t irq_state_t;

typedef struct dschedule {
    dom_t domain;
    word_t length;
} dschedule_t;

enum asidSizeConstants {
    asidHighBits = 7,
    asidLowBits = 9
};

/* Arch-independent object types */
enum endpoint_state {
    EPState_Idle = 0,
    EPState_Send = 1,
    EPState_Recv = 2
};
typedef word_t endpoint_state_t;

enum notification_state {
    NtfnState_Idle = 0,
    NtfnState_Waiting = 1,
    NtfnState_Active = 2
};
typedef word_t notification_state_t;
# 68 "/home/koc034/Documents/newver/seL4/include/object/structures.h"
// We would like the actual 'tcb' region (the portion that contains the tcb_t) of the tcb
// to be as large as possible, but it still needs to be aligned. As the TCB object contains
// two sub objects the largest we can make either sub object whilst preserving size alignment
// is half the total size. To halve an object size defined in bits we just subtract 1
//
// A diagram of a TCB kernel object that is created from untyped:
//  _______________________________________
// |     |             |                   |
// |     |             |                   |
// |cte_t|   unused    |       tcb_t       |
// |     |(debug_tcb_t)|                   |
// |_____|_____________|___________________|
// 0     a             b                   c
// a = tcbCNodeEntries * sizeof(cte_t)
// b = BIT(TCB_SIZE_BITS)
// c = BIT(seL4_TCBBits)
//






/* Generate a tcb_t or cte_t pointer from a tcb block reference */




/* Generate a cte_t pointer from a tcb_t pointer */
# 112 "/home/koc034/Documents/newver/seL4/include/object/structures.h"
static inline cap_t __attribute__((__const__)) Zombie_new(word_t number, word_t type, word_t ptr)
{
    word_t mask;

    if (type == (1ul << (6))) {
        mask = ((1ul << (4 + 1))-1ul);
    } else {
        mask = ((1ul << (type + 1))-1ul);
    }

    return cap_zombie_cap_new((ptr & ~mask) | (number & mask), type);
}

static inline word_t __attribute__((__const__)) cap_zombie_cap_get_capZombieBits(cap_t cap)
{
    word_t type = cap_zombie_cap_get_capZombieType(cap);
    if (type == (1ul << (6))) {
        return 4;
    }
    return ((type) & ((1ul << (6))-1ul)); /* cnode radix */
}

static inline word_t __attribute__((__const__)) cap_zombie_cap_get_capZombieNumber(cap_t cap)
{
    word_t radix = cap_zombie_cap_get_capZombieBits(cap);
    return cap_zombie_cap_get_capZombieID(cap) & ((1ul << (radix + 1))-1ul);
}

static inline word_t __attribute__((__const__)) cap_zombie_cap_get_capZombiePtr(cap_t cap)
{
    word_t radix = cap_zombie_cap_get_capZombieBits(cap);
    return cap_zombie_cap_get_capZombieID(cap) & ~((1ul << (radix + 1))-1ul);
}

static inline cap_t __attribute__((__const__)) cap_zombie_cap_set_capZombieNumber(cap_t cap, word_t n)
{
    word_t radix = cap_zombie_cap_get_capZombieBits(cap);
    word_t ptr = cap_zombie_cap_get_capZombieID(cap) & ~((1ul << (radix + 1))-1ul);
    return cap_zombie_cap_set_capZombieID(cap, ptr | (n & ((1ul << (radix + 1))-1ul)));
}

/* Capability table entry (CTE) */
struct cte {
    cap_t cap;
    mdb_node_t cteMDBNode;
};
typedef struct cte cte_t;



/* Thread state */
enum _thread_state {
    ThreadState_Inactive = 0,
    ThreadState_Running,
    ThreadState_Restart,
    ThreadState_BlockedOnReceive,
    ThreadState_BlockedOnSend,
    ThreadState_BlockedOnReply,
    ThreadState_BlockedOnNotification,



    ThreadState_IdleThreadState
};
typedef word_t _thread_state_t;

/* A TCB CNode and a TCB are always allocated together, and adjacently.
 * The CNode comes first. */
enum tcb_cnode_index {
    /* CSpace root */
    tcbCTable = 0,

    /* VSpace root */
    tcbVTable = 1,


    /* IPC buffer cap slot */
    tcbBuffer = 2,

    /* Fault endpoint slot */
    tcbFaultHandler = 3,

    /* Timeout endpoint slot */
    tcbTimeoutHandler = 4,
# 206 "/home/koc034/Documents/newver/seL4/include/object/structures.h"
    tcbCNodeEntries
};
typedef word_t tcb_cnode_index_t;

# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/object/structures.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 17 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/object/structures.h"
# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/hardware.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/64/mode/hardware.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       





/*
 * The top half of the address space is reserved for the kernel. This means that 256 top level
 * entries are for the user, and 256 are for the kernel. This will be further split into the
 * 'regular' kernel window, which contains mappings to physical memory, a small (1GiB) higher
 * kernel image window that we use for running the actual kernel from and a top 1GiB window for
 * kernel device mappings. This means that between PPTR_BASE and
 * KERNEL_ELF_BASE there are 254 entries remaining, which represents how much physical memory
 * can be used.
 *
 * Almost all of the top 256 kernel entries will contain 1GiB page mappings. The only 2 entries
 * that contain a 2nd level PageTable consisting of 2MiB page entries is the entry
 * for the 1GiB Kernel ELF region and the 1GiB region corresponding to the physical memory
 * of the kernel ELF in the kernel window.  The same 2nd level PageTable is used and so both
 * entries refer to the same 1GiB of physical memory.
 * This means that the 1GiB kernel ELF mapping will correspond to physical memory with a 1GiB
 * alignment.
 *
 *                   +-----------------------------+ 2^64
 *                   |        Kernel Devices       |
 *                -> +-------------------KDEV_BASE-+ 2^64 - 1GiB
 *                |  |         Kernel ELF          |
 *            ----|  +-------------KERNEL_ELF_BASE-+ --+ 2^64 - 2GiB + (KERNEL_ELF_PADDR_BASE % 1GiB)
 *            |   |  |                             |
 *            |   -> +-----------------------------+ --+ 2^64 - 2GiB = (KERNEL_ELF_BASE % 1GiB)
 * Shared 1GiB|      |                             |   |
 * table entry|      |           PSpace            |   |
 *            |      |  (direct kernel mappings)   |   +----+
 *            ------>|                             |   |    |
 *                   |                             |   |    |
 *                   +-------------------PPTR_BASE-+ --+ 2^64 - 2^b
 *                   |                             |        |         +-------------------------+
 *                   |                             |        |         |                         |
 *                   |                             |        |         |                         |
 *                   |          Invalid            |        |         |                         |
 *                   |                             |        |         |           not           |
 *                   |                             |        |         |         kernel          |
 *                   |                             |        |         |       addressable       |
 *                   +--------------------USER_TOP-+  2^c   |         |                         |
 *                   |                             |        |         |                         |
 *                   |                             |        |         |                         |
 *                   |                             |        |      +- --------------------------+  PADDR_TOP =
 *                   |                             |        |      |  |                         |    PPTR_TOP - PPTR_BASE
 *                   |                             |        |      |  |                         |
 *                   |                             |        |      |  |                         |
 *                   |            User             |        |      |  |                         |
 *                   |                             |        |      |  |                         |
 *                   |                             |        +------+  +-------------------------+  KDEV_BASE - KERNEL_ELF_BASE + PADDR_LOAD
 *                   |                             |     kernel    |  |        Kernel ELF       |
 *                   |                             |   addressable |  +-------------------------+  KERNEL_ELF_PADDR_BASE
 *                   |                             |               |  |                         |
 *                   |                             |               |  |                         |
 *                   +-----------------------------+  0            +- +-------------------------+  0 PADDR_BASE
 *
 *                      virtual address space                          physical address space
 *
 *
 *  c = one less than number of bits the page tables can translate
 *    = sign extension bit for canonical addresses
 *    (= 47 on x64, 38 on RISCV64 sv39, 47 on RISCV64 sv48)
 *  b = The number of bits used by kernel mapping.
 *    = 38 (half of the 1 level page table) on RISCV64 sc39
 *    = 39 (entire second level page table) on aarch64 / X64 / sv48
 */

/* last accessible virtual address in user space */


/* The first physical address to map into the kernel's physical memory
 * window */


/* The base address in virtual memory to use for the 1:1 physical memory
 * mapping */


/* Top of the physical memory window */


/* The physical memory address to use for mapping the kernel ELF */
/* This represents the physical address that the kernel image will be linked to. This needs to
 * be on a 1gb boundary as we currently require being able to creating a mapping to this address
 * as the largest frame size */


/* The base address in virtual memory to use for the kernel ELF mapping */


/* The base address in virtual memory to use for the kernel device
 * mapping region. These are mapped in the kernel page table. */


/* Place the kernel log buffer at the end of the kernel device page table */
# 118 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/64/mode/hardware.h"
static inline uint64_t riscv_read_time(void)
{
    uint64_t n;
    __asm__ volatile(
        "rdtime %0"
        : "=r"(n));
    return n;
}

static inline uint64_t riscv_read_cycle(void)
{
    uint64_t n;
    __asm__ volatile(
        "rdcycle %0"
        : "=r"(n));
    return n;
}
# 13 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/hardware.h" 2

/* Privileged CSR definitions */
# 31 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/hardware.h"
# 1 "/home/koc034/Documents/newver/seL4/include/linker.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       


# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/linker.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 11 "/home/koc034/Documents/newver/seL4/include/linker.h" 2

/* code that is only used during kernel bootstrapping */


/* read-only data only used during kernel bootstrapping */


/* read/write data only used during kernel bootstrapping */


/* node-local bss data that is only used during kernel bootstrapping */


/* data will be aligned to n bytes in a special BSS section */


/* data that will be mapped into and permitted to be used in the restricted SKIM
 * address space */


/* bss data that is permitted to be used in the restricted SKIM address space */
# 32 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/hardware.h" 2




/* The size is for HiFive Unleashed */







/* MMU RISC-V related definitions. See RISC-V manual priv-1.10 */

/* Extract the n-level PT index from a virtual address. This works for any
 * configured RISC-V system with CONFIG_PT_LEVEL (which can be 2 on Sv32,
 * 3 on Sv38, or 4 on Sv48)
 */



/*
 * These values are defined in RISC-V priv-1.10 manual, they represent the
 * exception codes saved in scause register (by the hardware) on traps.
 */
enum vm_fault_type {
    RISCVInstructionMisaligned = 0,
    RISCVInstructionAccessFault = 1,
    RISCVInstructionIllegal = 2,
    RISCVBreakpoint = 3,
    /* reserved */
    RISCVLoadAccessFault = 5,
    RISCVAddressMisaligned = 6,
    RISCVStoreAccessFault = 7,
    RISCVEnvCall = 8,
    /* 9-11 reserved */
    RISCVInstructionPageFault = 12,
    RISCVLoadPageFault = 13,
    /* 14 - reserved */
    RISCVStorePageFault = 15
                          /* >= 16 reserved */
};
typedef word_t vm_fault_type_t;

enum frameSizeConstants {
    RISCVPageBits = 12,
    RISCVMegaPageBits = 21,

    RISCVGigaPageBits = 30,




};

enum vm_page_size {
    RISCV_4K_Page,
    RISCV_Mega_Page,
    RISCV_Giga_Page,
    RISCV_Tera_Page
};
typedef word_t vm_page_size_t;

static inline word_t __attribute__((__const__)) pageBitsForSize(vm_page_size_t pagesize)
{
    switch (pagesize) {
    case RISCV_4K_Page:
        return RISCVPageBits;

    case RISCV_Mega_Page:
        return RISCVMegaPageBits;


    case RISCV_Giga_Page:
        return RISCVGigaPageBits;







    default:
        halt();
    }
}

static inline void arch_clean_invalidate_caches(void)
{
    /* RISC-V doesn't have an architecture defined way of flushing caches */
}
# 18 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/object/structures.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/registerset.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 18 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/registerset.h"
enum _register {

    ra = 0, LR = 0,

    sp = 1, SP = 1,
    gp = 2, GP = 2,
    tp = 3, TP = 3,
    TLS_BASE = tp,

    t0 = 4,

    nbsendRecvDest = 4,

    t1 = 5,
    t2 = 6,
    s0 = 7,
    s1 = 8,

    /* x10-x17 > a0-a7 */
    a0 = 9, capRegister = 9, badgeRegister = 9,
    a1 = 10, msgInfoRegister = 10,
    a2 = 11,
    a3 = 12,
    a4 = 13,
    a5 = 14,
    a6 = 15,

    replyRegister = 15,

    a7 = 16,
    s2 = 17,
    s3 = 18,
    s4 = 19,
    s5 = 20,
    s6 = 21,
    s7 = 22,
    s8 = 23,
    s9 = 24,
    s10 = 25,
    s11 = 26,

    t3 = 27,
    t4 = 28,
    t5 = 29,
    t6 = 30,

    /* End of GP registers, the following are additional kernel-saved state. */
    SCAUSE = 31,
    SSTATUS = 32,
    FaultIP = 33, /* SEPC */
    NextIP = 34,

    /* TODO: add other user-level CSRs if needed (i.e. to avoid channels) */

    n_contextRegisters
};

typedef uint8_t register_t;

enum messageSizes {
    n_msgRegisters = 4,
    n_frameRegisters = 16,
    n_gpRegisters = 16,
    n_exceptionMessage = 2,
    n_syscallMessage = 10,

    n_timeoutMessage = 32,

};

extern const register_t msgRegisters[] __attribute__((externally_visible));
extern const register_t frameRegisters[] __attribute__((externally_visible));
extern const register_t gpRegisters[] __attribute__((externally_visible));
# 111 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/registerset.h"
struct user_context {
    word_t registers[n_contextRegisters];



};
typedef struct user_context user_context_t;

static inline void Arch_initContext(user_context_t *context)
{
    /* Enable supervisor interrupts (when going to user-mode) */
    context->registers[SSTATUS] = 0x00000020;
}

static inline word_t __attribute__((__const__)) sanitiseRegister(register_t reg, word_t v, bool_t archInfo)
{
    return v;
}
# 19 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/object/structures.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/64/mode/object/structures.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 20 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/object/structures.h" 2



struct asid_pool {
    pte_t *array[(1ul << (asidLowBits))];
};

typedef struct asid_pool asid_pool_t;
# 36 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/object/structures.h"
typedef struct arch_tcb {
    user_context_t tcbContext;
} arch_tcb_t;

enum vm_rights {
    VMKernelOnly = 1,
    VMReadOnly = 2,
    VMReadWrite = 3
};
typedef word_t vm_rights_t;

typedef pte_t vspace_root_t;

/* Generic fastpath.c code expects pde_t for stored_hw_asid
 * that's a workaround in the time being.
 */
typedef pte_t pde_t;
# 67 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/object/structures.h"
static inline bool_t __attribute__((__const__)) cap_get_archCapIsPhysical(cap_t cap)
{
    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {

    case cap_frame_cap:
        return true;

    case cap_page_table_cap:
        return true;

    case cap_asid_control_cap:
        return false;

    case cap_asid_pool_cap:
        return true;

    default:
        /* unreachable */
        return false;
    }
}

static inline word_t __attribute__((__const__)) cap_get_archCapSizeBits(cap_t cap)
{
    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {
    case cap_frame_cap:
        return pageBitsForSize(cap_frame_cap_get_capFSize(cap));

    case cap_page_table_cap:
        return 12;

    case cap_asid_control_cap:
        return 0;

    case cap_asid_pool_cap:
        return 12;

    default:
        ;
        /* Unreachable, but GCC can't figure that out */
        return 0;
    }
}

static inline void *__attribute__((__const__)) cap_get_archCapPtr(cap_t cap)
{
    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {

    case cap_frame_cap:
        return (void *)(cap_frame_cap_get_capFBasePtr(cap));

    case cap_page_table_cap:
        return ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(cap)));

    case cap_asid_control_cap:
        return ((void *)0);

    case cap_asid_pool_cap:
        return ((asid_pool_t*)cap_asid_pool_cap_get_capASIDPool(cap));

    default:
        ;
        /* Unreachable, but GCC can't figure that out */
        return ((void *)0);
    }
}

static inline bool_t __attribute__((__const__)) Arch_isCapRevocable(cap_t derivedCap, cap_t srcCap)
{
    return false;
}
# 211 "/home/koc034/Documents/newver/seL4/include/object/structures.h" 2

struct user_data {
    word_t words[(1ul << (12)) / sizeof(word_t)];
};
typedef struct user_data user_data_t;

struct user_data_device {
    word_t words[(1ul << (12)) / sizeof(word_t)];
};
typedef struct user_data_device user_data_device_t;

static inline word_t __attribute__((__const__)) wordFromVMRights(vm_rights_t vm_rights)
{
    return (word_t)vm_rights;
}

static inline vm_rights_t __attribute__((__const__)) vmRightsFromWord(word_t w)
{
    return (vm_rights_t)w;
}

static inline vm_attributes_t __attribute__((__const__)) vmAttributesFromWord(word_t w)
{
    vm_attributes_t attr;

    attr.words[0] = w;
    return attr;
}


typedef struct sched_context sched_context_t;
typedef struct reply reply_t;


/* TCB: size >= 18 words + sizeof(arch_tcb_t) + 1 word on MCS (aligned to nearest power of 2) */
struct tcb {
    /* arch specific tcb state (including context)*/
    arch_tcb_t tcbArch;

    /* Thread state, 3 words */
    thread_state_t tcbState;

    /* Notification that this TCB is bound to. If this is set, when this TCB waits on
     * any sync endpoint, it may receive a signal from a Notification object.
     * 1 word*/
    notification_t *tcbBoundNotification;

    /* Current fault, 2 words */
    seL4_Fault_t tcbFault;

    /* Current lookup failure, 2 words */
    lookup_fault_t tcbLookupFailure;

    /* Domain, 1 byte (padded to 1 word) */
    dom_t tcbDomain;

    /*  maximum controlled priority, 1 byte (padded to 1 word) */
    prio_t tcbMCP;

    /* Priority, 1 byte (padded to 1 word) */
    prio_t tcbPriority;


    /* scheduling context that this tcb is running on, if it is NULL the tcb cannot
     * be in the scheduler queues, 1 word */
    sched_context_t *tcbSchedContext;

    /* scheduling context that this tcb yielded to */
    sched_context_t *tcbYieldTo;
# 288 "/home/koc034/Documents/newver/seL4/include/object/structures.h"
    /* userland virtual address of thread IPC buffer, 1 word */
    word_t tcbIPCBuffer;






    /* Previous and next pointers for scheduler queues , 2 words */
    struct tcb *tcbSchedNext;
    struct tcb *tcbSchedPrev;
    /* Preivous and next pointers for endpoint and notification queues, 2 words */
    struct tcb *tcbEPNext;
    struct tcb *tcbEPPrev;


    /* if tcb is in a call, pointer to the reply object, 1 word */
    reply_t *tcbReply;





};
typedef struct tcb tcb_t;
# 333 "/home/koc034/Documents/newver/seL4/include/object/structures.h"
typedef struct refill {
    /* Absolute timestamp from when this refill can be used */
    ticks_t rTime;
    /* Amount of ticks that can be used from this refill */
    ticks_t rAmount;
} refill_t;



struct sched_context {
    /* period for this sc -- controls rate at which budget is replenished */
    ticks_t scPeriod;

    /* amount of ticks this sc has been scheduled for since seL4_SchedContext_Consumed
     * was last called or a timeout exception fired */
    ticks_t scConsumed;

    /* core this scheduling context provides time for - 0 if uniprocessor */
    word_t scCore;

    /* thread that this scheduling context is bound to */
    tcb_t *scTcb;

    /* if this is not NULL, it points to the last reply object that was generated
     * when the scheduling context was passed over a Call */
    reply_t *scReply;

    /* notification this scheduling context is bound to
     * (scTcb and scNotification cannot be set at the same time) */
    notification_t *scNotification;

    /* data word that is sent with timeout faults that occur on this scheduling context */
    word_t scBadge;

    /* thread that yielded to this scheduling context */
    tcb_t *scYieldFrom;

    /* Amount of refills this sc tracks */
    word_t scRefillMax;
    /* Index of the head of the refill circular buffer */
    word_t scRefillHead;
    /* Index of the tail of the refill circular buffer */
    word_t scRefillTail;
};

struct reply {
    /* TCB pointed to by this reply object. This pointer reflects two possible relations, depending
     * on the thread state.
     *
     * ThreadState_BlockedOnReply: this tcb is the caller that is blocked on this reply object,
     * ThreadState_BlockedOnRecv: this tcb is the callee blocked on an endpoint with this reply object.
     *
     * The back pointer for this TCB is stored in the thread state.*/
    tcb_t *replyTCB;

    /* 0 if this is the start of the call chain, or points to the
     * previous reply object in a call chain */
    call_stack_t replyPrev;

    /* Either a scheduling context if this reply object is the head of the call chain
     * (the last caller before the server) or another reply object. 0 if no scheduling
     * context was passed along the call chain */
    call_stack_t replyNext;
};


/* Ensure object sizes are sane */
typedef int __assert_failed_cte_size_sane[(sizeof(cte_t) <= (1ul << (5))) ? 1 : -1];
typedef int __assert_failed_tcb_cte_size_sane[((4 + 5) <= (10 - 1)) ? 1 : -1];
typedef int __assert_failed_tcb_size_sane[((1ul << ((10 - 1))) >= sizeof(tcb_t)) ? 1 : -1];

typedef int __assert_failed_tcb_size_not_excessive[((1ul << ((10 - 1) - 1)) < sizeof(tcb_t)) ? 1 : -1];

typedef int __assert_failed_ep_size_sane[(sizeof(endpoint_t) <= (1ul << (4))) ? 1 : -1];
typedef int __assert_failed_notification_size_sane[(sizeof(notification_t) <= (1ul << (6))) ? 1 : -1];

/* Check the IPC buffer is the right size */
typedef int __assert_failed_ipc_buf_size_sane[(sizeof(seL4_IPCBuffer) == (1ul << (10))) ? 1 : -1];

typedef int __assert_failed_sc_core_size_sane[((sizeof(sched_context_t) + 2u *sizeof(refill_t) <= (10 * sizeof(seL4_Word) + (6 * 8)))) ? 1 : -1];

typedef int __assert_failed_reply_size_sane[(sizeof(reply_t) <= (1ul << (5))) ? 1 : -1];
typedef int __assert_failed_refill_size_sane[((sizeof(refill_t) == (2 * 8))) ? 1 : -1];


/* helper functions */

static inline word_t __attribute__((__const__))
isArchCap(cap_t cap)
{
    return (cap_get_capType(cap) % 2);
}
# 12 "/home/koc034/Documents/newver/seL4/include/compound_types.h" 2


struct pde_range {
    pde_t *base;
    word_t length;
};
typedef struct pde_range pde_range_t;

struct pte_range {
    pte_t *base;
    word_t length;
};
typedef struct pte_range pte_range_t;

typedef cte_t *cte_ptr_t;

struct extra_caps {
    cte_ptr_t excaprefs[((1ul<<(seL4_MsgExtraCapBits))-1)];
};
typedef struct extra_caps extra_caps_t;
# 11 "/home/koc034/Documents/newver/seL4/include/types.h" 2
# 9 "/home/koc034/Documents/newver/seL4/src/api/faults.c" 2
# 1 "/home/koc034/Documents/newver/seL4/include/api/faults.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




word_t setMRs_fault(tcb_t *sender, tcb_t *receiver, word_t *receiveIPCBuffer);
word_t Arch_setMRs_fault(tcb_t *sender, tcb_t *receiver, word_t *receiveIPCBuffer, word_t faultType);

bool_t handleFaultReply(tcb_t *receiver, tcb_t *sender);
bool_t Arch_handleFaultReply(tcb_t *receiver, tcb_t *sender, word_t faultType);
# 10 "/home/koc034/Documents/newver/seL4/src/api/faults.c" 2
# 1 "/home/koc034/Documents/newver/seL4/include/api/syscall.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       


# 1 "/home/koc034/Documents/newver/seL4/include/machine.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       

# 1 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

# 1 "gen_headers/plat/machine/devices_gen.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * This file is autogenerated by kernel/tools/hardware_gen.py.
 */
# 21 "gen_headers/plat/machine/devices_gen.h"
/* INTERRUPTS */
/* KERNEL DEVICES */



static const kernel_frame_t __attribute__((__section__(".boot.rodata"))) kernel_devices[] = {
    /* /soc/interrupt-controller@c000000 */
    {
        0xc000000,
        (0xFFFFFFFFC0000000ul + 0x0),
        false, /* userAvailable */
    },
    {
        0xc200000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x200000,
        false, /* userAvailable */
    },
    {
        0xc400000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x400000,
        false, /* userAvailable */
    },
    {
        0xc600000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x600000,
        false, /* userAvailable */
    },
    {
        0xc800000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x800000,
        false, /* userAvailable */
    },
    {
        0xca00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0xa00000,
        false, /* userAvailable */
    },
    {
        0xcc00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0xc00000,
        false, /* userAvailable */
    },
    {
        0xce00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0xe00000,
        false, /* userAvailable */
    },
    {
        0xd000000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x1000000,
        false, /* userAvailable */
    },
    {
        0xd200000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x1200000,
        false, /* userAvailable */
    },
    {
        0xd400000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x1400000,
        false, /* userAvailable */
    },
    {
        0xd600000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x1600000,
        false, /* userAvailable */
    },
    {
        0xd800000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x1800000,
        false, /* userAvailable */
    },
    {
        0xda00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x1a00000,
        false, /* userAvailable */
    },
    {
        0xdc00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x1c00000,
        false, /* userAvailable */
    },
    {
        0xde00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x1e00000,
        false, /* userAvailable */
    },
    {
        0xe000000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x2000000,
        false, /* userAvailable */
    },
    {
        0xe200000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x2200000,
        false, /* userAvailable */
    },
    {
        0xe400000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x2400000,
        false, /* userAvailable */
    },
    {
        0xe600000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x2600000,
        false, /* userAvailable */
    },
    {
        0xe800000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x2800000,
        false, /* userAvailable */
    },
    {
        0xea00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x2a00000,
        false, /* userAvailable */
    },
    {
        0xec00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x2c00000,
        false, /* userAvailable */
    },
    {
        0xee00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x2e00000,
        false, /* userAvailable */
    },
    {
        0xf000000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x3000000,
        false, /* userAvailable */
    },
    {
        0xf200000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x3200000,
        false, /* userAvailable */
    },
    {
        0xf400000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x3400000,
        false, /* userAvailable */
    },
    {
        0xf600000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x3600000,
        false, /* userAvailable */
    },
    {
        0xf800000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x3800000,
        false, /* userAvailable */
    },
    {
        0xfa00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x3a00000,
        false, /* userAvailable */
    },
    {
        0xfc00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x3c00000,
        false, /* userAvailable */
    },
    {
        0xfe00000,
        /* contains PLIC_PPTR */
        0xFFFFFFFFC0000000ul + 0x3e00000,
        false, /* userAvailable */
    },
};

/* PHYSICAL MEMORY */
static const p_region_t __attribute__((__section__(".boot.rodata"))) avail_p_regs[] = {
    { 0x80200000, 0x280000000 }, /* /memory@80000000 */
};
# 8 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 2
# 1 "gen_headers/plat/platform_gen.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */






# 1 "/home/koc034/Documents/newver/seL4/include/machine/interrupt.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       





/**
 * irq_t is an identifier that represents a hardware interrupt.
 * irq handler capabilities refer to an irq_t which is then used by the
 * kernel to track irq state. An irq_t is also used to interface with an
 * interrupt controller driver using the functions below.
 * For most configurations an irq_t is a word_t type and the irq_t values
 * directly map to harware irq numbers and are also used as indexes into the
 * kernel's irq cnode that it uses for tracking state.
 * However on SMP configurations where there can be multiple irq_t identifiers
 * for a single hardware irq number, such as when there are core local interrupts,
 * irq_t cannot be assumed to be only a hardware irq number.
 * In this case, irq_t can be defined as a struct containing additional information.
 *
 * Macros are provided to hide this structural difference across configurations:
 * CORE_IRQ_TO_IRQT: converts from a core id and hw irq number to an irq_t
 * IRQT_TO_IDX: converts an irq_t to an index in the irq cnode. It is also used
 *   to encode the irq_t as a single word_t type for sending over IPIs.
 * IDX_TO_IRQT: converts an index in the irq cnode to an irq_t
 * IRQT_TO_CORE: extracts the core out of an irq_t
 * IRQT_TO_IRQL extracts a hw irq out of an irq_t.
 *
 * It is expected that interrupt controller drivers that support SMP provide
 * implementations of these Macros.
 * Currently only Arm SMP configurations use this scheme.
 */






typedef word_t irq_t;







/**
 * Return a currently pending IRQ.
 *
 * This function can be called multiple times and needs to return the same IRQ
 * until ackInterrupt is called. getActiveIRQ returns irqInvalid if no interrupt
 * is pending. It is assumed that if isIRQPending is true, then getActiveIRQ
 * will not return irqInvalid. irqInvalid is a per platform constant that cannot
 * correspond to an actual IRQ raised by the platform.
 *
 * @return     The active IRQ. irqInvalid if no IRQ is pending.
 */
static inline irq_t getActiveIRQ(void);

/**
 * Checks if an IRQ is currently pending in the hardware.
 *
 * isIRQPending is used to determine whether to preempt long running operations
 * at various preemption points throughout the kernel. If this returns true, it
 * means that if the Kernel were to return to user mode, it would then
 * immediately take an interrupt.
 *
 * @return     True if irq pending, False otherwise.
 */
static inline bool_t isIRQPending(void);

/**
 * maskInterrupt disables and enables IRQs.
 *
 * When an IRQ is disabled, it should not raise an interrupt on the processor.
 *
 * @param[in]  disable  True to disable IRQ, False to enable IRQ
 * @param[in]  irq      The irq to modify
 */
static inline void maskInterrupt(bool_t disable, irq_t irq);

/**
 * Acks the interrupt
 *
 * ackInterrupt is used by the kernel to indicate it has processed the interrupt
 * delivery and getActiveIRQ is now able to return a different IRQ number. Note
 * that this is called after a notification has been signalled to user level,
 * but before user level has handled the cause and does not imply that the cause
 * of the interrupt has been handled.
 *
 * @param[in]  irq   irq to ack
 */
static inline void ackInterrupt(irq_t irq);

/**
 * Called when getActiveIRQ returns irqInvalid while the kernel is handling an
 * interrupt entry. An implementation is not required to do anything here, but
 * can report the spurious IRQ or try prevent it from reoccuring.
 */
static inline void handleSpuriousIRQ(void);

/**
 * Handle a platform-reserved IRQ.
 *
 * Platform specific implementation for handling IRQs for interrupts that are
 * reserved and not made available to user-level. Will be called if getActiveIRQ
 * returns an IRQ number that is reserved. After this function returns,
 * ackInterrupt will likely be immediately called after.
 *
 * @param[in]  irq   The irq
 */
static inline void handleReservedIRQ(irq_t irq);
# 13 "gen_headers/plat/platform_gen.h" 2

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




    INTERRUPT_CORE_TIMER,
    maxIRQ = INTERRUPT_CORE_TIMER,
} platform_interrupt_t;

enum irqNumbers {
    irqInvalid = 0
};




# 1 "/home/koc034/Documents/newver/seL4/include/drivers/irq/riscv_plic0.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
/* tell the kernel we have the set trigger feature */



# 1 "gen_headers/plat/machine/devices_gen.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * This file is autogenerated by kernel/tools/hardware_gen.py.
 */
# 13 "/home/koc034/Documents/newver/seL4/include/drivers/irq/riscv_plic0.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/model/smp.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       


# 1 "/home/koc034/Documents/newver/seL4/include/model/smp.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/model/statedata.h" 1
/*
 * Copyright 2020, DornerWorks
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




# 1 "/home/koc034/Documents/newver/seL4/include/model/statedata.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




# 1 "/home/koc034/Documents/newver/seL4/include/object/tcb.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       


# 1 "/home/koc034/Documents/newver/seL4/include/api/failures.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       


# 1 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/errors.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       

typedef enum {
    seL4_NoError = 0,
    seL4_InvalidArgument,
    seL4_InvalidCapability,
    seL4_IllegalOperation,
    seL4_RangeError,
    seL4_AlignmentError,
    seL4_FailedLookup,
    seL4_TruncatedMessage,
    seL4_DeleteFirst,
    seL4_RevokeFirst,
    seL4_NotEnoughMemory,

    /* This should always be the last item in the list
     * so it gives a count of the number of errors in the
     * enum.
     */
    seL4_NumErrors
} seL4_Error;
# 11 "/home/koc034/Documents/newver/seL4/include/api/failures.h" 2

/* These datatypes differ markedly from haskell, due to the
 * different implementation of the various fault monads */


enum exception {
    EXCEPTION_NONE,
    EXCEPTION_FAULT,
    EXCEPTION_LOOKUP_FAULT,
    EXCEPTION_SYSCALL_ERROR,
    EXCEPTION_PREEMPTED
};
typedef word_t exception_t;

typedef word_t syscall_error_type_t;

struct syscall_error {
    word_t invalidArgumentNumber;
    word_t invalidCapNumber;
    word_t rangeErrorMin;
    word_t rangeErrorMax;
    word_t memoryLeft;
    bool_t failedLookupWasSource;

    syscall_error_type_t type;
};
typedef struct syscall_error syscall_error_t;
# 47 "/home/koc034/Documents/newver/seL4/include/api/failures.h"
extern lookup_fault_t current_lookup_fault;
extern seL4_Fault_t current_fault;
extern syscall_error_t current_syscall_error;
# 11 "/home/koc034/Documents/newver/seL4/include/object/tcb.h" 2


# 1 "/home/koc034/Documents/newver/seL4/include/machine/registerset.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       






typedef enum {
    MessageID_Syscall,
    MessageID_Exception,

    MessageID_TimeoutReply,

} MessageID_t;






extern const register_t fault_messages[][(((n_syscallMessage)>((((n_timeoutMessage)>(n_exceptionMessage))?(n_timeoutMessage):(n_exceptionMessage))))?(n_syscallMessage):((((n_timeoutMessage)>(n_exceptionMessage))?(n_timeoutMessage):(n_exceptionMessage))))] __attribute__((externally_visible));

static inline void setRegister(tcb_t *thread, register_t reg, word_t w)
{
    thread->tcbArch.tcbContext.registers[reg] = w;
}

static inline word_t __attribute__((__pure__)) getRegister(tcb_t *thread, register_t reg)
{
    return thread->tcbArch.tcbContext.registers[reg];
}


word_t getNBSendRecvDest(void);
# 14 "/home/koc034/Documents/newver/seL4/include/object/tcb.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/object/cnode.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       





exception_t decodeCNodeInvocation(word_t invLabel, word_t length,
                                  cap_t cap, word_t *buffer);
exception_t invokeCNodeRevoke(cte_t *destSlot);
exception_t invokeCNodeDelete(cte_t *destSlot);
exception_t invokeCNodeCancelBadgedSends(cap_t cap);
exception_t invokeCNodeInsert(cap_t cap, cte_t *srcSlot, cte_t *destSlot);
exception_t invokeCNodeMove(cap_t cap, cte_t *srcSlot, cte_t *destSlot);
exception_t invokeCNodeRotate(cap_t cap1, cap_t cap2, cte_t *slot1,
                              cte_t *slot2, cte_t *slot3);
void cteInsert(cap_t newCap, cte_t *srcSlot, cte_t *destSlot);
void cteMove(cap_t newCap, cte_t *srcSlot, cte_t *destSlot);
void capSwapForDelete(cte_t *slot1, cte_t *slot2);
void cteSwap(cap_t cap1, cte_t *slot1, cap_t cap2, cte_t *slot2);
exception_t cteRevoke(cte_t *slot);
exception_t cteDelete(cte_t *slot, bool_t exposed);
void cteDeleteOne(cte_t *slot);
void insertNewCap(cte_t *parent, cte_t *slot, cap_t cap);
bool_t __attribute__((__pure__)) isMDBParentOf(cte_t *cte_a, cte_t *cte_b);
exception_t ensureNoChildren(cte_t *slot);
exception_t ensureEmptySlot(cte_t *slot);
bool_t __attribute__((__pure__)) isFinalCapability(cte_t *cte);
bool_t __attribute__((__pure__)) slotCapLongRunningDelete(cte_t *slot);
cte_t *getReceiveSlots(tcb_t *thread, word_t *buffer);
cap_transfer_t __attribute__((__pure__)) loadCapTransfer(word_t *buffer);
# 15 "/home/koc034/Documents/newver/seL4/include/object/tcb.h" 2







struct tcb_queue {
    tcb_t *head;
    tcb_t *end;
};
typedef struct tcb_queue tcb_queue_t;

static inline unsigned int setMR(tcb_t *receiver, word_t *receiveIPCBuffer,
                                 unsigned int offset, word_t reg)
{
    if (offset >= n_msgRegisters) {
        if (receiveIPCBuffer) {
            receiveIPCBuffer[offset + 1] = reg;
            return offset + 1;
        } else {
            return n_msgRegisters;
        }
    } else {
        setRegister(receiver, msgRegisters[offset], reg);
        return offset + 1;
    }
}

void tcbSchedEnqueue(tcb_t *tcb);
void tcbSchedAppend(tcb_t *tcb);
void tcbSchedDequeue(tcb_t *tcb);






void tcbReleaseRemove(tcb_t *tcb);
void tcbReleaseEnqueue(tcb_t *tcb);
tcb_t *tcbReleaseDequeue(void);
# 81 "/home/koc034/Documents/newver/seL4/include/object/tcb.h"
/* Add TCB into the priority ordered endpoint queue */
static inline tcb_queue_t tcbEPAppend(tcb_t *tcb, tcb_queue_t queue)
{
    /* start at the back of the queue as FIFO is the common case */
    tcb_t *before = queue.end;
    tcb_t *after = ((void *)0);

    /* find a place to put the tcb */
    while (__builtin_expect(!!(before != ((void *)0) && tcb->tcbPriority > before->tcbPriority), 0)) {
        after = before;
        before = after->tcbEPPrev;
    }

    if (__builtin_expect(!!(before == ((void *)0)), 0)) {
        /* insert at head */
        queue.head = tcb;
    } else {
        before->tcbEPNext = tcb;
    }

    if (__builtin_expect(!!(after == ((void *)0)), 1)) {
        /* insert at tail */
        queue.end = tcb;
    } else {
        after->tcbEPPrev = tcb;
    }

    tcb->tcbEPNext = after;
    tcb->tcbEPPrev = before;

    return queue;
}

tcb_queue_t tcbEPDequeue(tcb_t *tcb, tcb_queue_t queue);
# 124 "/home/koc034/Documents/newver/seL4/include/object/tcb.h"
word_t copyMRs(tcb_t *sender, word_t *sendBuf, tcb_t *receiver,
               word_t *recvBuf, word_t n);
exception_t decodeTCBInvocation(word_t invLabel, word_t length, cap_t cap,
                                cte_t *slot, bool_t call, word_t *buffer);
exception_t decodeCopyRegisters(cap_t cap, word_t length, word_t *buffer);
exception_t decodeReadRegisters(cap_t cap, word_t length, bool_t call,
                                word_t *buffer);
exception_t decodeWriteRegisters(cap_t cap, word_t length, word_t *buffer);
exception_t decodeTCBConfigure(cap_t cap, word_t length,
                               cte_t *slot, word_t *buffer);
exception_t decodeSetPriority(cap_t cap, word_t length, word_t *buffer);
exception_t decodeSetMCPriority(cap_t cap, word_t length, word_t *buffer);

exception_t decodeSetSchedParams(cap_t cap, word_t length, cte_t *slot, word_t *buffer);



exception_t decodeSetIPCBuffer(cap_t cap, word_t length,
                               cte_t *slot, word_t *buffer);
exception_t decodeSetSpace(cap_t cap, word_t length,
                           cte_t *slot, word_t *buffer);
exception_t decodeDomainInvocation(word_t invLabel, word_t length, word_t *buffer);
exception_t decodeBindNotification(cap_t cap);
exception_t decodeUnbindNotification(cap_t cap);

exception_t decodeSetTimeoutEndpoint(cap_t cap, cte_t *slot);




enum thread_control_caps_flag {
    thread_control_caps_update_ipc_buffer = 0x1,
    thread_control_caps_update_space = 0x2,
    thread_control_caps_update_fault = 0x4,
    thread_control_caps_update_timeout = 0x8,
};

enum thread_control_sched_flag {
    thread_control_sched_update_priority = 0x1,
    thread_control_sched_update_mcp = 0x2,
    thread_control_sched_update_sc = 0x4,
    thread_control_sched_update_fault = 0x8,
};
# 181 "/home/koc034/Documents/newver/seL4/include/object/tcb.h"
typedef word_t thread_control_flag_t;

exception_t invokeTCB_Suspend(tcb_t *thread);
exception_t invokeTCB_Resume(tcb_t *thread);

exception_t invokeTCB_ThreadControlCaps(tcb_t *target, cte_t *slot,
                                        cap_t fh_newCap, cte_t *fh_srcSlot,
                                        cap_t th_newCap, cte_t *th_srcSlot,
                                        cap_t cRoot_newCap, cte_t *cRoot_srcSlot,
                                        cap_t vRoot_newCap, cte_t *vRoot_srcSlot,
                                        word_t bufferAddr, cap_t bufferCap,
                                        cte_t *bufferSrcSlot,
                                        thread_control_flag_t updateFlags);
exception_t invokeTCB_ThreadControlSched(tcb_t *target, cte_t *slot,
                                         cap_t fh_newCap, cte_t *fh_srcSlot,
                                         prio_t mcp, prio_t priority,
                                         sched_context_t *sc,
                                         thread_control_flag_t updateFlags);
# 207 "/home/koc034/Documents/newver/seL4/include/object/tcb.h"
exception_t invokeTCB_CopyRegisters(tcb_t *dest, tcb_t *src,
                                    bool_t suspendSource, bool_t resumeTarget,
                                    bool_t transferFrame, bool_t transferInteger,
                                    word_t transferArch);
exception_t invokeTCB_ReadRegisters(tcb_t *src, bool_t suspendSource,
                                    word_t n, word_t arch, bool_t call);
exception_t invokeTCB_WriteRegisters(tcb_t *dest, bool_t resumeTarget,
                                     word_t n, word_t arch, word_t *buffer);
exception_t invokeTCB_NotificationControl(tcb_t *tcb, notification_t *ntfnPtr);

cptr_t __attribute__((__pure__)) getExtraCPtr(word_t *bufferPtr, word_t i);
void setExtraBadge(word_t *bufferPtr, word_t badge, word_t i);

exception_t lookupExtraCaps(tcb_t *thread, word_t *bufferPtr, seL4_MessageInfo_t info);
word_t setMRs_syscall_error(tcb_t *thread, word_t *receiveIPCBuffer);
word_t __attribute__((__const__)) Arch_decodeTransfer(word_t flags);
exception_t __attribute__((__const__)) Arch_performTransfer(word_t arch, tcb_t *tcb_src,
                                       tcb_t *tcb_dest);
# 13 "/home/koc034/Documents/newver/seL4/include/model/statedata.h" 2
# 38 "/home/koc034/Documents/newver/seL4/include/model/statedata.h"
/* UP states are declared as VISIBLE so that they are accessible in assembly */
# 58 "/home/koc034/Documents/newver/seL4/include/model/statedata.h"

extern tcb_queue_t ksReadyQueues[(16 * 256)] __attribute__((externally_visible));
extern word_t ksReadyQueuesL1Bitmap[16] __attribute__((externally_visible));
extern word_t ksReadyQueuesL2Bitmap[16][((256 + (1ul << (6)) - 1) / (1ul << (6)))] __attribute__((externally_visible));
extern tcb_t *ksCurThread __attribute__((externally_visible));
extern tcb_t *ksIdleThread __attribute__((externally_visible));
extern tcb_t *ksSchedulerAction __attribute__((externally_visible));


extern tcb_t *ksReleaseHead __attribute__((externally_visible));
extern time_t ksConsumed __attribute__((externally_visible));
extern time_t ksCurTime __attribute__((externally_visible));
extern bool_t ksReprogram __attribute__((externally_visible));
extern sched_context_t *ksCurSC __attribute__((externally_visible));
# 92 "/home/koc034/Documents/newver/seL4/include/model/statedata.h"
;

extern word_t ksNumCPUs;






extern word_t ksWorkUnitsCompleted;
extern irq_state_t intStateIRQTable[];
extern cte_t intStateIRQNode[];

extern const dschedule_t ksDomSchedule[];
extern const word_t ksDomScheduleLength;
extern word_t ksDomScheduleIdx;
extern dom_t ksCurDomain;

extern ticks_t ksDomainTime;



extern word_t tlbLockCount __attribute__((externally_visible));

extern char ksIdleThreadTCB[1][(1ul << (10))];


extern char ksIdleThreadSC[1][(1ul << (8))];
# 15 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/model/statedata.h" 2





/* TODO: add RISCV-dependent fields here */
/* Bitmask of all cores should receive the reschedule IPI */
extern word_t ipiReschedulePending __attribute__((externally_visible));
;

extern asid_pool_t *riscvKSASIDTable[(1ul << (asidHighBits))];

/* Kernel Page Tables */
extern pte_t kernel_root_pageTable[(1ul << (9))] __attribute__((externally_visible));

/* We need to introduce a level2 pagetable in order to map the BBL to a separate
 * page entry to avoid PMP exception. */

extern pte_t kernel_image_level2_pt[(1ul << (9))];
extern pte_t kernel_image_level2_dev_pt[(1ul << (9))];
# 12 "/home/koc034/Documents/newver/seL4/include/model/smp.h" 2
# 11 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/model/smp.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/kernel/stack.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/64/mode/kernel/stack.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 12 "/home/koc034/Documents/newver/seL4/include/kernel/stack.h" 2

/* These are the stacks used in kernel, shared between architectures/modes.
 * CONFIG_KERNEL_STACK_BITS is defined in kernel/Kconfig. The physical/offset
 * address of the stack is per-arch-mode aligned. KERNEL_STACK_ALIGNMENT is
 * defined for each arch/mode in <mode/kernel/stack.h>
 */
extern char kernel_stack_alloc[1][(1ul << (12))];
# 12 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/model/smp.h" 2
# 14 "/home/koc034/Documents/newver/seL4/include/drivers/irq/riscv_plic0.h" 2

/* The memory map is based on the PLIC section in
 * https://static.dev.sifive.com/U54-MC-RVCoreIP.pdf
 */
# 43 "/home/koc034/Documents/newver/seL4/include/drivers/irq/riscv_plic0.h"
/* SiFive U54-MC has 5 cores, and the first core does not
 * have supervisor mode. Therefore, we need to compensate
 * for the addresses.
 */
# 57 "/home/koc034/Documents/newver/seL4/include/drivers/irq/riscv_plic0.h"
static inline void write_sie(word_t value)
{
    __asm__ volatile("csrw sie,  %0" :: "r"(value));
}

static inline word_t read_sie(void)
{
    word_t temp;
    __asm__ volatile("csrr %0, sie" : "=r"(temp));
    return temp;
}

static inline uint32_t readl(uint64_t addr)
{
    return *((volatile uint32_t *)(addr));
}

static inline void writel(uint32_t val, uint64_t addr)
{
    *((volatile uint32_t *)(addr)) = val;
}

static inline word_t plic_enable_offset(word_t hart_id, word_t context_id)
{
    word_t addr = ((0x2000 + hart_id * 0x100 + context_id * 0x80) - 0x80);
    return addr;
}


static inline word_t plic_thres_offset(word_t hart_id, word_t context_id)
{
    word_t addr = ((0x200000 + hart_id * 0x2000 + context_id * 0x1000) - 0x1000);
    return addr;
}

static inline word_t plic_claim_offset(word_t hart_id, word_t context_id)
{
    word_t addr = plic_thres_offset(hart_id, context_id) + 0x4;
    return addr;
}

static inline bool_t plic_pending_interrupt(word_t interrupt)
{
    word_t addr = (0xFFFFFFFFC0000000ul + 0x0) + 0x1000 + (interrupt / 32) * 4;
    word_t bit = interrupt % 32;
    if (readl(addr) & (1ul << (bit))) {
        return true;
    } else {
        return false;
    }
}

static inline word_t get_hart_id(void)
{



    return 1;

}

static inline irq_t plic_get_claim(void)
{
    /* Read the claim register for our HART interrupt context */
    word_t hart_id = get_hart_id();
    return readl((0xFFFFFFFFC0000000ul + 0x0) + plic_claim_offset(hart_id, 1));
}

static inline void plic_complete_claim(irq_t irq)
{
    /* Complete the IRQ claim by writing back to the claim register. */
    word_t hart_id = get_hart_id();
    writel(irq, (0xFFFFFFFFC0000000ul + 0x0) + plic_claim_offset(hart_id, 1));
}

static inline void plic_mask_irq(bool_t disable, irq_t irq)
{
    uint64_t addr = 0;
    uint32_t val = 0;
    uint32_t bit = 0;

    word_t hart_id = get_hart_id();
    addr = (0xFFFFFFFFC0000000ul + 0x0) + plic_enable_offset(hart_id, 1) + (irq / 32) * 4;
    bit = irq % 32;

    val = readl(addr);
    if (disable) {
        val &= ~(1ul << (bit));
    } else {
        val |= (1ul << (bit));
    }
    writel(val, addr);
}

static inline void plic_init_hart(void)
{

    word_t hart_id = get_hart_id();

    for (int i = 1; i <= PLIC_MAX_IRQ; i++) {
        /* Disable interrupts */
        plic_mask_irq(true, i);
    }

    /* Set threshold to zero */
    writel(0, ((0xFFFFFFFFC0000000ul + 0x0) + plic_thres_offset(hart_id, 1)));
}

static inline void plic_init_controller(void)
{

    for (int i = 1; i <= PLIC_MAX_IRQ; i++) {
        /* Clear all pending bits */
        if (plic_pending_interrupt(i)) {
            readl((0xFFFFFFFFC0000000ul + 0x0) + plic_claim_offset((1), 1));
            writel(i, (0xFFFFFFFFC0000000ul + 0x0) + plic_claim_offset((1), 1));
        }
    }

    /* Set the priorities of all interrupts to 1 */
    for (int i = 1; i <= PLIC_MAX_IRQ + 1; i++) {
        writel(2, (0xFFFFFFFFC0000000ul + 0x0) + 0x0 + 0x4 * i);
    }

}


/*
 * Provide a dummy definition of set trigger as the Hifive platform currently
 * has all global interrupt positive-level triggered.
 */
static inline void plic_irq_set_trigger(irq_t irq, bool_t edge_triggered)
{
}
# 47 "gen_headers/plat/platform_gen.h" 2
# 8 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 2
# 10 "/home/koc034/Documents/newver/seL4/include/machine.h" 2

# 1 "/home/koc034/Documents/newver/seL4/include/hardware.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
       

/* Each architecture defines a set of constants in #defines. These
 * constants describe the memory regions of the kernel's portion of the
 * address space including the physical memory window, the kernel ELF
 * region, and the device region.
 *
 *  - USER_TOP: The first address after the end of user memory
 *
 *  - PADDR_BASE: The first physical address mapped in the kernel's
 *    physical memory window.
 *  - PPTR_BASE: The first virtual address of the kernel's physical
 *    memory window.
 *  - PPTR_TOP: The first virtual address after the end of the kernel's
 *    physical memory window.
 *
 *  - KERNEL_ELF_PADDR_BASE: The first physical address used to map the
 *    initial kernel image. The kernel ELF is mapped contiguously
 *    starting at this address.
 *  - KERNEL_ELF_BASE: The first virtual address used to map the initial
 *    kernel image.
 *
 *  - KDEV_BASE: The first virtual address used to map devices.
 */

/* The offset from a physical address to a virtual address in the
 * physical memory window. */


/* The last address in the physical memory region mapped into the
 * physical memory window */


/* The kernel base offset is a way to translate the kernel image segment
 * from virtual to physical. This translation must be a single offset
 * for for the entire segment (i.e. the kernel image must be contiguous
 * both virtually and physically) */




/* This symbol is generated by the linker and marks the last valid
 * address in the kernel's virtual region */
extern char ki_end[];
# 12 "/home/koc034/Documents/newver/seL4/include/machine.h" 2

/* When translating a physical address into an address accessible to the
 * kernel via virtual addressing we always use the mapping of the memory
 * into the physical memory window, even if the mapping originally
 * referred to a kernel virtual address. */
static inline void *__attribute__((__const__)) ptrFromPAddr(paddr_t paddr)
{
    return (void *)(paddr + (0xFFFFFFC000000000ul - 0x0ul));
}

/* When obtaining a physical address from a reference to any object in
 * the physical mapping window, this function must be used. */
static inline paddr_t __attribute__((__const__)) addrFromPPtr(void *pptr)
{
    return (paddr_t)pptr - (0xFFFFFFC000000000ul - 0x0ul);
}

static inline region_t __attribute__((__const__)) paddr_to_pptr_reg(p_region_t p_reg)
{
    return (region_t) {
        p_reg.start + (0xFFFFFFC000000000ul - 0x0ul), p_reg.end + (0xFFFFFFC000000000ul - 0x0ul)
    };
}

static inline p_region_t __attribute__((__const__)) pptr_to_paddr_reg(region_t reg)
{
    return (p_region_t) {
        reg.start - (0xFFFFFFC000000000ul - 0x0ul), reg.end - (0xFFFFFFC000000000ul - 0x0ul)
    };
}




# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/64/mode/machine.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       

/* Place holder for 64-bit machine header */
# 46 "/home/koc034/Documents/newver/seL4/include/machine.h" 2
# 11 "/home/koc034/Documents/newver/seL4/include/api/syscall.h" 2


# 1 "/home/koc034/Documents/newver/seL4/include/kernel/vspace.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
       


# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/kernel/vspace.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       





cap_t create_it_address_space(cap_t root_cnode_cap, v_region_t it_v_reg);
void map_it_pt_cap(cap_t vspace_cap, cap_t pt_cap);
void map_it_frame_cap(cap_t vspace_cap, cap_t frame_cap);
void map_kernel_window(void);
void map_kernel_frame(paddr_t paddr, pptr_t vaddr, vm_rights_t vm_rights);
void activate_kernel_vspace(void);
void write_it_asid_pool(cap_t it_ap_cap, cap_t it_lvl1pt_cap);


/* ==================== BOOT CODE FINISHES HERE ==================== */


void idle_thread(void);


struct lookupPTSlot_ret {
    pte_t *ptSlot;
    word_t ptBitsLeft;
};

typedef struct lookupPTSlot_ret lookupPTSlot_ret_t;

struct findVSpaceForASID_ret {
    exception_t status;
    pte_t *vspace_root;
};
typedef struct findVSpaceForASID_ret findVSpaceForASID_ret_t;

void copyGlobalMappings(pte_t *newlvl1pt);
word_t *__attribute__((__pure__)) lookupIPCBuffer(bool_t isReceiver, tcb_t *thread);
lookupPTSlot_ret_t lookupPTSlot(pte_t *lvl1pt, vptr_t vptr);
exception_t handleVMFault(tcb_t *thread, vm_fault_type_t vm_faultType);
void unmapPageTable(asid_t, vptr_t vaddr, pte_t *pt);
void unmapPage(vm_page_size_t page_size, asid_t asid, vptr_t vptr, pptr_t pptr);
void deleteASID(asid_t asid, pte_t *vspace);
void deleteASIDPool(asid_t asid_base, asid_pool_t *pool);
bool_t __attribute__((__const__)) isValidVTableRoot(cap_t cap);
exception_t checkValidIPCBuffer(vptr_t vptr, cap_t cap);
vm_rights_t __attribute__((__const__)) maskVMRights(vm_rights_t vm_rights,
                               seL4_CapRights_t cap_rights_mask);
exception_t decodeRISCVMMUInvocation(word_t label, word_t length, cptr_t cptr,
                                     cte_t *cte, cap_t cap, word_t *buffer);
exception_t performPageTableInvocationMap(cap_t cap, cte_t *ctSlot,
                                          pte_t lvl1pt, pte_t *ptSlot);
exception_t performPageTableInvocationUnmap(cap_t cap, cte_t *ctSlot);
exception_t performPageInvocationMapPTE(cap_t cap, cte_t *ctSlot,
                                        pte_t pte, pte_t *base);
exception_t performPageInvocationUnmap(cap_t cap, cte_t *ctSlot);
void setVMRoot(tcb_t *tcb);
# 10 "/home/koc034/Documents/newver/seL4/include/kernel/vspace.h" 2
# 14 "/home/koc034/Documents/newver/seL4/include/api/syscall.h" 2
# 1 "gen_headers/arch/api/syscall.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */


/* This header was generated by kernel/tools/syscall_header_gen.py.
 *
 * To add a system call number, edit kernel/include/api/syscall.xml
 *
 */
# 38 "gen_headers/arch/api/syscall.h"
enum syscall {
    SysCall = -1,
    SysReplyRecv = -2,
    SysNBSendRecv = -3,
    SysNBSendWait = -4,
    SysSend = -5,
    SysNBSend = -6,
    SysRecv = -7,
    SysNBRecv = -8,
    SysWait = -9,
    SysNBWait = -10,
    SysYield = -11,
# 91 "gen_headers/arch/api/syscall.h"
};
typedef word_t syscall_t;

/* System call names */
# 15 "/home/koc034/Documents/newver/seL4/include/api/syscall.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/api/debug.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 16 "/home/koc034/Documents/newver/seL4/include/api/syscall.h" 2
# 32 "/home/koc034/Documents/newver/seL4/include/api/syscall.h"
exception_t handleSyscall(syscall_t syscall);
exception_t handleInterruptEntry(void);
exception_t handleUnknownSyscall(word_t w);
exception_t handleUserLevelFault(word_t w_a, word_t w_b);
exception_t handleVMFaultEvent(vm_fault_type_t vm_faultType);

static inline word_t __attribute__((__pure__)) getSyscallArg(word_t i, word_t *ipc_buffer)
{
    if (i < n_msgRegisters) {
        return getRegister(ksCurThread, msgRegisters[i]);
    }

    ;
    return ipc_buffer[i + 1];
}

extern extra_caps_t current_extra_caps;
# 11 "/home/koc034/Documents/newver/seL4/src/api/faults.c" 2
# 1 "/home/koc034/Documents/newver/seL4/include/kernel/thread.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       






# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/sbi.h" 1
/* SPDX-License-Identifier: BSD-3-Clause */

/* Copyright (c) 2010-2017, The Regents of the University of California
 * (Regents).  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Regents nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * IN NO EVENT SHALL REGENTS BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT,
 * SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING
 * OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF REGENTS HAS
 * BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * REGENTS SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE. THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED
 * HEREUNDER IS PROVIDED "AS IS". REGENTS HAS NO OBLIGATION TO PROVIDE
 * MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 */

/* This file is copied from RISC-V tools/linux project, it might change for
 * new spec releases.
 */

       
# 48 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/sbi.h"
static inline word_t sbi_call(word_t cmd,
                              word_t arg_0,
                              word_t arg_1,
                              word_t arg_2)
{
    register word_t a0 __asm__("a0") = arg_0;
    register word_t a1 __asm__("a1") = arg_1;
    register word_t a2 __asm__("a2") = arg_2;
    register word_t a7 __asm__("a7") = cmd;
    register word_t result __asm__("a0");
    __asm__ volatile("ecall"
                 : "=r"(result)
                 : "r"(a0), "r"(a1), "r"(a2), "r"(a7)
                 : "memory");
    return result;
}

/* Lazy implementations until SBI is finalized */




static inline void sbi_console_putchar(int ch)
{
    sbi_call(1, ch, 0, 0);
}

static inline int sbi_console_getchar(void)
{
    return (int)(sbi_call(2, 0, 0, 0));
}

static inline void sbi_set_timer(unsigned long long stime_value)
{



    sbi_call(0, stime_value, 0, 0);

}

static inline void sbi_shutdown(void)
{
    sbi_call(8, 0, 0, 0);
}

static inline void sbi_clear_ipi(void)
{
    sbi_call(3, 0, 0, 0);
}

static inline void sbi_send_ipi(const unsigned long *hart_mask)
{
    sbi_call(4, (word_t)hart_mask, 0, 0);
}

static inline void sbi_remote_fence_i(const unsigned long *hart_mask)
{
    sbi_call(5, (word_t)hart_mask, 0, 0);
}

static inline void sbi_remote_sfence_vma(const unsigned long *hart_mask,
                                         unsigned long start,
                                         unsigned long size)
{
    sbi_call(6, (word_t)hart_mask, 0, 0);
}

static inline void sbi_remote_sfence_vma_asid(const unsigned long *hart_mask,
                                              unsigned long start,
                                              unsigned long size,
                                              unsigned long asid)
{
    sbi_call(7, (word_t)hart_mask, 0, 0);
}
# 16 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine.h" 2
# 97 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine.h"
static inline void sfence(void)
{
    __asm__ volatile("sfence.vma" ::: "memory");
}

static inline void hwASIDFlush(asid_t asid)
{
    __asm__ volatile("sfence.vma x0, %0" :: "r"(asid): "memory");
}



word_t __attribute__((__pure__)) getRestartPC(tcb_t *thread);
void setNextPC(tcb_t *thread, word_t v);

/* Cleaning memory before user-level access */
static inline void clearMemory(void *ptr, unsigned int bits)
{
    memzero(ptr, (1ul << (bits)));
}

static inline void write_satp(word_t value)
{
    __asm__ volatile("csrw satp, %0" :: "rK"(value));
}

static inline void write_stvec(word_t value)
{
    __asm__ volatile("csrw stvec, %0" :: "rK"(value));
}

static inline word_t read_stval(void)
{
    word_t temp;
    __asm__ volatile("csrr %0, stval" : "=r"(temp));
    return temp;
}

static inline word_t read_scause(void)
{
    word_t temp;
    __asm__ volatile("csrr %0, scause" : "=r"(temp));
    return temp;
}

static inline word_t read_sepc(void)
{
    word_t temp;
    __asm__ volatile("csrr %0, sepc" : "=r"(temp));
    return temp;
}

static inline word_t read_sstatus(void)
{
    word_t temp;
    __asm__ volatile("csrr %0, sstatus" : "=r"(temp));
    return temp;
}

static inline word_t read_sip(void)
{
    word_t temp;
    __asm__ volatile("csrr %0, sip" : "=r"(temp));
    return temp;
}

static inline void set_sie_mask(word_t mask_high)
{
    word_t temp;
    __asm__ volatile("csrrs %0, sie, %1" : "=r"(temp) : "rK"(mask_high));
}

static inline void clear_sie_mask(word_t mask_low)
{
    word_t temp;
    __asm__ volatile("csrrc %0, sie, %1" : "=r"(temp) : "rK"(mask_low));
}
# 198 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine.h"
static inline void setVSpaceRoot(paddr_t addr, asid_t asid)
{
    satp_t satp = satp_new(8, /* mode */
                           asid, /* asid */
                           addr >> 12); /* PPN */

    write_satp(satp.words[0]);

    /* Order read/write operations */



    sfence();

}

static inline void Arch_finaliseInterrupt(void)
{
}

int get_num_avail_p_regs(void);
p_region_t *get_avail_p_regs(void);
int get_num_dev_p_regs(void);
p_region_t get_dev_p_reg(word_t i);
void map_kernel_devices(void);

static inline void setInterruptMode(irq_t irq, bool_t levelTrigger, bool_t polarityLow) { }
/** MODIFIES: [*] */
void initTimer(void);
/* L2 cache control */
void initL2Cache(void);
void initLocalIRQController(void);
void initIRQController(void);
void setIRQTrigger(irq_t irq, bool_t trigger);
# 245 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine.h"
void plat_cleanL2Range(paddr_t start, paddr_t end);

void plat_invalidateL2Range(paddr_t start, paddr_t end);

void plat_cleanInvalidateL2Range(paddr_t start, paddr_t end);

static inline void *__attribute__((__const__)) paddr_to_kpptr(paddr_t paddr)
{
    ;
    ;
    return (void *)(paddr + ((0xFFFFFFFF80000000ul + ((0x80000000 + 0x4000000ul) & ((1ul << (30))-1ul))) - (0x80000000 + 0x4000000ul)));
}

static inline paddr_t __attribute__((__const__)) kpptr_to_paddr(void *pptr)
{
    ;
    return (paddr_t)pptr - ((0xFFFFFFFF80000000ul + ((0x80000000 + 0x4000000ul) & ((1ul << (30))-1ul))) - (0x80000000 + 0x4000000ul));
}

/* Update the value of the actual regsiter to hold the expected value */
static inline void Arch_setTLSRegister(word_t tls_base)
{
    /* The register is always reloaded upon return from kernel. */
    setRegister(ksCurThread, TLS_BASE, tls_base);
}
# 13 "/home/koc034/Documents/newver/seL4/include/kernel/thread.h" 2

# 1 "/home/koc034/Documents/newver/seL4/include/kernel/sporadic.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
/* This header presents the interface for sporadic servers,
 * implemented according to Stankcovich et. al in
 * "Defects of the POSIX Spoardic Server and How to correct them",
 * although without the priority management.
 *
 * Briefly, a sporadic server is a period and a queue of refills. Each
 * refill consists of an amount, and a period. No thread is allowed to consume
 * more than amount ticks per period.
 *
 * The sum of all refill amounts in the refill queue is always the budget of the scheduling context -
 * that is it should never change, unless it is being updated / configured.
 *
 * Every time budget is consumed, that amount of budget is scheduled
 * for reuse in period time. If the refill queue is full (the queue's
 * minimum size is 2, and can be configured by the user per scheduling context
 * above this) the next refill is merged.
 */




# 1 "/home/koc034/Documents/newver/seL4/include/machine/timer.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       


# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/timer.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




# 1 "/home/koc034/Documents/newver/seL4/include/64/mode/util.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       





static inline __attribute__((__const__)) uint64_t div64(uint64_t numerator, uint32_t denominator)
{
    return numerator / denominator;
}
# 13 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/timer.h" 2



/* The scheduler clock is greater than 1MHz */


static inline __attribute__((__const__)) time_t getKernelWcetUs(void)
{
    /* Copied from x86_64. Hopefully it's an overestimate here. */
    return 10u;
}

static inline __attribute__((__pure__)) ticks_t usToTicks(time_t us)
{
    return us * (1000000llu / (1000llu * 1000llu));
}

static inline __attribute__((__pure__)) time_t ticksToUs(ticks_t ticks)
{
    return div64(ticks, (1000000llu / (1000llu * 1000llu)));
}

static inline __attribute__((__pure__)) ticks_t getTimerPrecision(void)
{
    return usToTicks(1);
}

static inline __attribute__((__const__)) ticks_t getMaxTicksToUs(void)
{
    return (0xFFFFFFFFFFFFFFFF) / (1000000llu / (1000llu * 1000llu));
}

static inline __attribute__((__pure__)) time_t getMaxUsToTicks(void)
{
    return usToTicks(getMaxTicksToUs());
}

/* Read the current time from the timer. */
static inline ticks_t getCurrentTime(void)
{
    return riscv_read_time();
}

/* set the next deadline irq - deadline is absolute */
static inline void setDeadline(ticks_t deadline)
{
    ;
    /* Setting the timer acknowledges any existing IRQs */
    sbi_set_timer(deadline);
}

/* ack previous deadline irq */
static inline void ackDeadlineIRQ(void)
{
}
# 11 "/home/koc034/Documents/newver/seL4/include/machine/timer.h" 2





/* Read the current time from the timer. */
/** MODIFIES: [*] */
static inline ticks_t getCurrentTime(void);
/* set the next deadline irq - deadline is absolute */
/** MODIFIES: [*] */
static inline void setDeadline(ticks_t deadline);
/* ack previous deadline irq */
/** MODIFIES: [*] */
static inline void ackDeadlineIRQ(void);

/* get the expected wcet of the kernel for this platform */
static __attribute__((__pure__)) inline ticks_t getKernelWcetTicks(void)
{
    return usToTicks(getKernelWcetUs());
}
# 30 "/home/koc034/Documents/newver/seL4/include/kernel/sporadic.h" 2


/* To do an operation in the kernel, the thread must have
 * at least this much budget - see comment on refill_sufficient */
# 42 "/home/koc034/Documents/newver/seL4/include/kernel/sporadic.h"
/* Short hand for accessing refill queue items */
static inline refill_t *refill_index(sched_context_t *sc, word_t index)
{
    return ((refill_t *)(((word_t) (sc)) + sizeof(sched_context_t))) + index;
}
static inline refill_t *refill_head(sched_context_t *sc)
{
    return refill_index(sc, sc->scRefillHead);
}
static inline refill_t *refill_tail(sched_context_t *sc)
{
    return refill_index(sc, sc->scRefillTail);
}


/* Scheduling context objects consist of a sched_context_t at the start, followed by a
 * circular buffer of refills. As scheduling context objects are of variable size, the
 * amount of refill_ts that can fit into a scheduling context object is also variable.
 *
 * @return the maximum number of refill_t data structures that can fit into this
 * specific scheduling context object.
 */
static inline word_t refill_absolute_max(cap_t sc_cap)
{
    return ((1ul << (cap_sched_context_cap_get_capSCSizeBits(sc_cap))) - sizeof(sched_context_t)) / sizeof(refill_t);
}

/* @return the current amount of empty slots in the refill buffer */
static inline word_t refill_size(sched_context_t *sc)
{
    if (sc->scRefillHead <= sc->scRefillTail) {
        return (sc->scRefillTail - sc->scRefillHead + 1u);
    }
    return sc->scRefillTail + 1u + (sc->scRefillMax - sc->scRefillHead);
}

/* @return true if the circular buffer of refills is current full (all slots in the
 * buffer are currently being used */
static inline bool_t refill_full(sched_context_t *sc)
{
    return refill_size(sc) == sc->scRefillMax;
}

/* @return true if the ciruclar buffer only contains 1 used slot */
static inline bool_t refill_single(sched_context_t *sc)
{
    return sc->scRefillHead == sc->scRefillTail;
}

/* Return the amount of budget this scheduling context
 * has available if usage is charged to it. */
static inline ticks_t refill_capacity(sched_context_t *sc, ticks_t usage)
{
    if (__builtin_expect(!!(usage > refill_head(sc)->rAmount), 0)) {
        return 0;
    }

    return refill_head(sc)->rAmount - usage;
}

/*
 * Return true if the head refill has sufficient capacity
 * to enter and exit the kernel after usage is charged to it.
 */
static inline bool_t refill_sufficient(sched_context_t *sc, ticks_t usage)
{
    return refill_capacity(sc, usage) >= (2u * getKernelWcetTicks() * 1);
}

/*
 * Return true if the head refill is eligible to be used.
 * This indicates if the thread bound to the sc can be placed
 * into the scheduler, otherwise it needs to go into the release queue
 * to wait.
 */
static inline bool_t refill_ready(sched_context_t *sc)
{
    return refill_head(sc)->rTime <= (ksCurTime + getKernelWcetTicks());
}

/* Create a new refill in a non-active sc */




void refill_new(sched_context_t *sc, word_t max_refills, ticks_t budget, ticks_t period);



/* Update refills in an active sc without violating bandwidth constraints */
void refill_update(sched_context_t *sc, ticks_t new_period, ticks_t new_budget, word_t new_max_refills);


/* Charge `usage` to the current scheduling context.
 * This function should only be called only when charging `used` will deplete
 * the head refill, resulting in refill_sufficient failing.
 *
 * @param usage the amount of time to charge.
 */
void refill_budget_check(ticks_t used);

/*
 * Charge a the current scheduling context `used` amount from its
 * current refill. This will split the refill, leaving whatever is
 * left over at the head of the refill. This is only called when charging
 * `used` will not deplete the head refill.
 */
void refill_split_check(ticks_t used);

/*
 * This is called when a thread is eligible to start running: it
 * iterates through the refills queue and merges any
 * refills that overlap.
 */
void refill_unblock_check(sched_context_t *sc);
# 15 "/home/koc034/Documents/newver/seL4/include/kernel/thread.h" 2




static inline __attribute__((__const__)) word_t ready_queues_index(word_t dom, word_t prio)
{
    if (16 > 1) {
        return dom * 256 + prio;
    } else {
        ;
        return prio;
    }
}

static inline __attribute__((__const__)) word_t prio_to_l1index(word_t prio)
{
    return (prio >> 6);
}

static inline __attribute__((__const__)) word_t l1index_to_prio(word_t l1index)
{
    return (l1index << 6);
}

static inline bool_t __attribute__((__pure__)) isRunnable(const tcb_t *thread)
{
    switch (thread_state_get_tsType(thread->tcbState)) {
    case ThreadState_Running:
    case ThreadState_Restart:



        return true;

    default:
        return false;
    }
}

static inline __attribute__((__const__)) word_t invert_l1index(word_t l1index)
{
    word_t inverted = (((256 + (1ul << (6)) - 1) / (1ul << (6))) - 1 - l1index);
    ;
    return inverted;
}

static inline prio_t getHighestPrio(word_t dom)
{
    word_t l1index;
    word_t l2index;
    word_t l1index_inverted;

    /* it's undefined to call clzl on 0 */
    ;

    l1index = (1ul << (6)) - 1 - clzl(ksReadyQueuesL1Bitmap[dom]);
    l1index_inverted = invert_l1index(l1index);
    ;
    l2index = (1ul << (6)) - 1 - clzl(ksReadyQueuesL2Bitmap[dom][l1index_inverted]);
    return (l1index_to_prio(l1index) | l2index);
}

static inline bool_t isHighestPrio(word_t dom, prio_t prio)
{
    return ksReadyQueuesL1Bitmap[dom] == 0 ||
           prio >= getHighestPrio(dom);
}

static inline bool_t __attribute__((__pure__)) isBlocked(const tcb_t *thread)
{
    switch (thread_state_get_tsType(thread->tcbState)) {
    case ThreadState_BlockedOnReceive:
    case ThreadState_BlockedOnSend:
    case ThreadState_BlockedOnNotification:
    case ThreadState_BlockedOnReply:
        return true;

    default:
        return false;
    }
}

static inline bool_t __attribute__((__pure__)) isStopped(const tcb_t *thread)
{
    switch (thread_state_get_tsType(thread->tcbState)) {
    case ThreadState_Inactive:
    case ThreadState_BlockedOnReceive:
    case ThreadState_BlockedOnSend:
    case ThreadState_BlockedOnNotification:
    case ThreadState_BlockedOnReply:
        return true;

    default:
        return false;
    }
}


static inline bool_t __attribute__((__pure__)) isRoundRobin(sched_context_t *sc)
{
    return sc->scPeriod == 0;
}

static inline bool_t isCurDomainExpired(void)
{
    return 16 > 1 &&
           ksDomainTime < (ksConsumed + (2u * getKernelWcetTicks() * 1));
}

static inline void commitTime(void)
{
    if (ksCurSC->scRefillMax) {
        if (__builtin_expect(!!(ksConsumed > 0), 1)) {
            /* if this function is called the head refil must be sufficient to
             * charge ksConsumed */
            ;
            /* and it must be ready to use */
            ;

            if (isRoundRobin(ksCurSC)) {
                /* for round robin threads, there are only two refills: the HEAD, which is what
                 * we are consuming, and the tail, which is what we have consumed */
                ;
                refill_head(ksCurSC)->rAmount -= ksConsumed;
                refill_tail(ksCurSC)->rAmount += ksConsumed;
            } else {
                refill_split_check(ksConsumed);
            }
            ;
            ;
        }
        ksCurSC->scConsumed += ksConsumed;
    }
    if (16 > 1) {
        ;
        ;
        if (ksConsumed < ksDomainTime) {
            ksDomainTime -= ksConsumed;
        } else {
            ksDomainTime = 0;
        }
    }

    ksConsumed = 0llu;
}

static inline bool_t __attribute__((__pure__)) isSchedulable(const tcb_t *thread)
{
    return isRunnable(thread) &&
           thread->tcbSchedContext != ((void *)0) &&
           thread->tcbSchedContext->scRefillMax > 0 &&
           !thread_state_get_tcbInReleaseQueue(thread->tcbState);
}




void configureIdleThread(tcb_t *tcb);
void activateThread(void);
void suspend(tcb_t *target);
void restart(tcb_t *target);
void doIPCTransfer(tcb_t *sender, endpoint_t *endpoint,
                   word_t badge, bool_t grant, tcb_t *receiver);

void doReplyTransfer(tcb_t *sender, reply_t *reply, bool_t grant);




void doNormalTransfer(tcb_t *sender, word_t *sendBuffer, endpoint_t *endpoint,
                      word_t badge, bool_t canGrant, tcb_t *receiver,
                      word_t *receiveBuffer);
void doFaultTransfer(word_t badge, tcb_t *sender, tcb_t *receiver,
                     word_t *receiverIPCBuffer);
void doNBRecvFailedTransfer(tcb_t *thread);
void schedule(void);
void chooseThread(void);
void switchToThread(tcb_t *thread);
void switchToIdleThread(void);
void setDomain(tcb_t *tptr, dom_t dom);
void setPriority(tcb_t *tptr, prio_t prio);
void setMCPriority(tcb_t *tptr, prio_t mcp);
void scheduleTCB(tcb_t *tptr);
void possibleSwitchTo(tcb_t *tptr);
void setThreadState(tcb_t *tptr, _thread_state_t ts);
void rescheduleRequired(void);

/* declare that the thread has had its registers (in its user_context_t) modified and it
 * should ignore any 'efficient' restores next time it is run, and instead restore all
 * registers into their correct place */
void Arch_postModifyRegisters(tcb_t *tptr);

/* Updates a threads FaultIP to match its NextIP. This is used to indicate that a
 * thread has completed its fault and by updating the restartPC means that if the thread
 * should get restarted in the future for any reason it is restart in such a way as to
 * not cause the fault again. */
static inline void updateRestartPC(tcb_t *tcb)
{
    setRegister(tcb, FaultIP, getRegister(tcb, NextIP));
}


/* End the timeslice for the current thread.
 * This will recharge the threads timeslice and place it at the
 * end of the scheduling queue for its priority.
 */
void endTimeslice(bool_t can_timeout_fault);

/* called when a thread has used up its head refill */
void chargeBudget(ticks_t consumed, bool_t canTimeoutFault, word_t core, bool_t isCurCPU);

/* Update the kernels timestamp and stores in ksCurTime.
 * The difference between the previous kernel timestamp and the one just read
 * is stored in ksConsumed.
 *
 * Should be called on every kernel entry
 * where threads can be billed.
 */
static inline void updateTimestamp(void)
{
    time_t prev = ksCurTime;
    ksCurTime = getCurrentTime();
    ksConsumed += (ksCurTime - prev);
}

/* Check if the current thread/domain budget has expired.
 * if it has, bill the thread, add it to the scheduler and
 * set up a reschedule.
 *
 * @return true if the thread/domain has enough budget to
 *              get through the current kernel operation.
 */
static inline bool_t checkBudget(void)
{
    /* currently running thread must have available capacity */
    ;

    ticks_t capacity = refill_capacity(ksCurSC, ksConsumed);
    /* if the budget isn't enough, the timeslice for this SC is over. For
     * round robin threads this is sufficient, however for periodic threads
     * we also need to check there is space to schedule the replenishment - if the refill
     * is full then the timeslice is also over as the rest of the budget is forfeit. */
    if (__builtin_expect(!!(capacity >= (2u * getKernelWcetTicks() * 1) && (isRoundRobin(ksCurSC) || !refill_full(ksCurSC))), 1)
                                                                             ) {
        if (__builtin_expect(!!(isCurDomainExpired()), 0)) {
            ksReprogram = true;
            rescheduleRequired();
            return false;
        }
        return true;
    }

    chargeBudget(ksConsumed, true, 0, true);
    return false;
}

/* Everything checkBudget does, but also set the thread
 * state to ThreadState_Restart. To be called from kernel entries
 * where the operation should be restarted once the current thread
 * has budget again.
 */

static inline bool_t checkBudgetRestart(void)
{
    ;
    bool_t result = checkBudget();
    if (!result && isRunnable(ksCurThread)) {
        setThreadState(ksCurThread, ThreadState_Restart);
    }
    return result;
}


/* Set the next kernel tick, which is either the end of the current
 * domains timeslice OR the end of the current threads timeslice.
 */
void setNextInterrupt(void);

/* Wake any periodic threads that are ready for budget recharge */
void awaken(void);
/* Place the thread bound to this scheduling context in the release queue
 * of periodic threads waiting for budget recharge */
void postpone(sched_context_t *sc);
# 12 "/home/koc034/Documents/newver/seL4/src/api/faults.c" 2
# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/kernel/thread.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       

# 1 "/home/koc034/Documents/newver/seL4/include/object.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       


# 1 "/home/koc034/Documents/newver/seL4/include/object/objecttype.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       





# 1 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine/hardware.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 14 "/home/koc034/Documents/newver/seL4/include/object/objecttype.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/object/cap.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       

struct deriveCap_ret {
    exception_t status;
    cap_t cap;
};
typedef struct deriveCap_ret deriveCap_ret_t;

struct finaliseCap_ret {
    cap_t remainder;
    /* potential cap holding information for cleanup that needs to be happen *after* a
     * cap has been deleted. Where deleted here means been removed from the slot in emptySlot */
    cap_t cleanupInfo;
};
typedef struct finaliseCap_ret finaliseCap_ret_t;
# 15 "/home/koc034/Documents/newver/seL4/include/object/objecttype.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/object/objecttype.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       







deriveCap_ret_t Arch_deriveCap(cte_t *slot, cap_t cap);
cap_t __attribute__((__const__)) Arch_updateCapData(bool_t preserve, word_t data, cap_t cap);
cap_t __attribute__((__const__)) Arch_maskCapRights(seL4_CapRights_t cap_rights_mask, cap_t cap);
finaliseCap_ret_t Arch_finaliseCap(cap_t cap, bool_t final);
bool_t __attribute__((__const__)) Arch_sameRegionAs(cap_t cap_a, cap_t cap_b);
bool_t __attribute__((__const__)) Arch_sameObjectAs(cap_t cap_a, cap_t cap_b);
cap_t Arch_createObject(object_t t, void *regionBase, word_t userSize, bool_t deviceMemory);
exception_t Arch_decodeInvocation(word_t label, word_t length,
                                  cptr_t cptr, cte_t *slot, cap_t cap,
                                  bool_t call, word_t *buffer);
void Arch_prepareThreadDelete(tcb_t *thread);
word_t Arch_getObjectSize(word_t t);
bool_t Arch_isFrameType(word_t type);

static inline void Arch_postCapDeletion(cap_t cap)
{
}
# 16 "/home/koc034/Documents/newver/seL4/include/object/objecttype.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/object/interrupt.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/object/interrupt.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       





static inline void handleReservedIRQ(irq_t irq)
{



}

exception_t Arch_decodeIRQControlInvocation(word_t invLabel, word_t length,
                                            cte_t *srcSlot, word_t *buffer);
exception_t Arch_checkIRQ(word_t irq_w);
# 13 "/home/koc034/Documents/newver/seL4/include/object/interrupt.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

# 1 "gen_headers/plat/machine/devices_gen.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * This file is autogenerated by kernel/tools/hardware_gen.py.
 */
# 8 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 2
# 1 "gen_headers/plat/platform_gen.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 8 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 2
# 14 "/home/koc034/Documents/newver/seL4/include/object/interrupt.h" 2

exception_t decodeIRQControlInvocation(word_t invLabel, word_t length,
                                       cte_t *srcSlot, word_t *buffer);
exception_t invokeIRQControl(irq_t irq, cte_t *handlerSlot, cte_t *controlSlot);
exception_t decodeIRQHandlerInvocation(word_t invLabel, irq_t irq);
void invokeIRQHandler_AckIRQ(irq_t irq);
void invokeIRQHandler_SetIRQHandler(irq_t irq, cap_t cap, cte_t *slot);
void invokeIRQHandler_ClearIRQHandler(irq_t irq);
void deletingIRQHandler(irq_t irq);
void deletedIRQHandler(irq_t irq);
void handleInterrupt(irq_t irq);
bool_t isIRQActive(irq_t irq);
void setIRQState(irq_state_t irqState, irq_t irq);
# 17 "/home/koc034/Documents/newver/seL4/include/object/objecttype.h" 2

deriveCap_ret_t deriveCap(cte_t *slot, cap_t cap);
finaliseCap_ret_t finaliseCap(cap_t cap, bool_t final, bool_t exposed);
bool_t __attribute__((__const__)) hasCancelSendRights(cap_t cap);
bool_t __attribute__((__const__)) sameRegionAs(cap_t cap_a, cap_t cap_b);
bool_t __attribute__((__const__)) sameObjectAs(cap_t cap_a, cap_t cap_b);
cap_t __attribute__((__const__)) updateCapData(bool_t preserve, word_t newData, cap_t cap);
cap_t __attribute__((__const__)) maskCapRights(seL4_CapRights_t seL4_CapRights, cap_t cap);
cap_t createObject(object_t t, void *regionBase, word_t, bool_t deviceMemory);
void createNewObjects(object_t t, cte_t *parent,
                      cte_t *destCNode, word_t destOffset, word_t destLength,
                      void *regionBase, word_t userSize, bool_t deviceMemory);

exception_t decodeInvocation(word_t invLabel, word_t length,
                             cptr_t capIndex, cte_t *slot, cap_t cap,
                             bool_t block, bool_t call,
                             bool_t canDonate, bool_t firstPhase, word_t *buffer);
exception_t performInvocation_Endpoint(endpoint_t *ep, word_t badge,
                                       bool_t canGrant, bool_t canGrantReply,
                                       bool_t block, bool_t call, bool_t canDonate);
exception_t performInvocation_Notification(notification_t *ntfn,
                                           word_t badge);
exception_t performInvocation_Reply(tcb_t *thread, reply_t *reply, bool_t canGrant);
# 51 "/home/koc034/Documents/newver/seL4/include/object/objecttype.h"
word_t getObjectSize(word_t t, word_t userObjSize);

static inline void postCapDeletion(cap_t cap)
{
    if (cap_get_capType(cap) == cap_irq_handler_cap) {
        irq_t irq = (cap_irq_handler_cap_get_capIRQ(cap));
        deletedIRQHandler(irq);
    } else if (isArchCap(cap)) {
        Arch_postCapDeletion(cap);
    }
}

word_t __attribute__((__const__)) cap_get_capSizeBits(cap_t cap);
bool_t __attribute__((__const__)) cap_get_capIsPhysical(cap_t cap);
void *__attribute__((__const__)) cap_get_capPtr(cap_t cap);
bool_t __attribute__((__const__)) isCapRevocable(cap_t derivedCap, cap_t srcCap);
# 11 "/home/koc034/Documents/newver/seL4/include/object.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/object/notification.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




void sendSignal(notification_t *ntfnPtr, word_t badge);
void receiveSignal(tcb_t *thread, cap_t cap, bool_t isBlocking);
void cancelAllSignals(notification_t *ntfnPtr);
void cancelSignal(tcb_t *threadPtr, notification_t *ntfnPtr);
void completeSignal(notification_t *ntfnPtr, tcb_t *tcb);
void unbindMaybeNotification(notification_t *ntfnPtr);
void unbindNotification(tcb_t *tcb);
void bindNotification(tcb_t *tcb, notification_t *ntfnPtr);

void reorderNTFN(notification_t *notification, tcb_t *thread);

static inline void maybeReturnSchedContext(notification_t *ntfnPtr, tcb_t *tcb)
{

    sched_context_t *sc = ((sched_context_t *) (notification_ptr_get_ntfnSchedContext(ntfnPtr)));
    if (sc == tcb->tcbSchedContext) {
        tcb->tcbSchedContext = ((void *)0);
        sc->scTcb = ((void *)0);
        /* If the current thread returns its sched context then it should not
           by default continue running. */
        if (tcb == ksCurThread) {
            rescheduleRequired();
        }
    }
}
# 12 "/home/koc034/Documents/newver/seL4/include/object.h" 2

# 1 "/home/koc034/Documents/newver/seL4/include/object/endpoint.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




static inline tcb_queue_t __attribute__((__pure__)) ep_ptr_get_queue(endpoint_t *epptr)
{
    tcb_queue_t queue;

    queue.head = (tcb_t *)endpoint_ptr_get_epQueue_head(epptr);
    queue.end = (tcb_t *)endpoint_ptr_get_epQueue_tail(epptr);

    return queue;
}


void sendIPC(bool_t blocking, bool_t do_call, word_t badge,
             bool_t canGrant, bool_t canGrantReply, bool_t canDonate, tcb_t *thread,
             endpoint_t *epptr);
void receiveIPC(tcb_t *thread, cap_t cap, bool_t isBlocking, cap_t replyCPtr);
void reorderEP(endpoint_t *epptr, tcb_t *thread);






void cancelIPC(tcb_t *tptr);
void cancelAllIPC(endpoint_t *epptr);
void cancelBadgedSends(endpoint_t *epptr, word_t badge);
void replyFromKernel_error(tcb_t *thread);
void replyFromKernel_success_empty(tcb_t *thread);
# 14 "/home/koc034/Documents/newver/seL4/include/object.h" 2




# 1 "/home/koc034/Documents/newver/seL4/include/object/untyped.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 16 "/home/koc034/Documents/newver/seL4/include/object/untyped.h"
/* It is assumed that every untyped is within seL4_MinUntypedBits and seL4_MaxUntypedBits
 * (inclusive). This means that every untyped stored as seL4_MinUntypedBits
 * subtracted from its size before it is stored in capBlockSize, and
 * capFreeIndex counts in chunks of size 2^seL4_MinUntypedBits. The seL4_MaxUntypedBits
 * is the minimal untyped that can be stored when considering both how
 * many bits of capBlockSize there are, and the largest offset that can
 * be stored in capFreeIndex */







exception_t decodeUntypedInvocation(word_t invLabel, word_t length,
                                    cte_t *slot, cap_t cap,
                                    bool_t call, word_t *buffer);
exception_t invokeUntyped_Retype(cte_t *srcSlot, bool_t reset,
                                 void *retypeBase, object_t newType, word_t userSize,
                                 cte_t *destCNode, word_t destOffset, word_t destLength,
                                 bool_t deviceMemory);
# 19 "/home/koc034/Documents/newver/seL4/include/object.h" 2
# 11 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/kernel/thread.h" 2

void Arch_switchToThread(tcb_t *tcb);
void Arch_switchToIdleThread(void);
void Arch_configureIdleThread(tcb_t *tcb);
void Arch_activateIdleThread(tcb_t *tcb);

static inline bool_t __attribute__((__const__)) Arch_getSanitiseRegisterInfo(tcb_t *thread)
{
    return 0;
}
# 13 "/home/koc034/Documents/newver/seL4/src/api/faults.c" 2
# 1 "/home/koc034/Documents/newver/seL4/include/machine/debug.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 14 "/home/koc034/Documents/newver/seL4/src/api/faults.c" 2

# 1 "/home/koc034/Documents/newver/seL4/include/64/mode/api/ipc_buffer.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




static inline time_t mode_parseTimeArg(word_t i, word_t *buffer)
{
    return getSyscallArg(i, buffer);
}

static inline word_t mode_setTimeArg(word_t i, time_t time, word_t *buffer, tcb_t *thread)
{
    return setMR(thread, buffer, i, time);
}
# 16 "/home/koc034/Documents/newver/seL4/src/api/faults.c" 2
# 1 "/home/koc034/Documents/newver/seL4/include/object/schedcontext.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
       





exception_t decodeSchedContextInvocation(word_t label, cap_t cap, word_t *buffer);

/* Bind a tcb and a scheduling context. This allows a tcb to enter the scheduler.
 * If the tcb is runnable, insert into scheduler
 *
 * @param sc the scheduling context to bind
 * @param tcb the tcb to bind
 *
 * @pre  the scheduling context must not already be bound to a tcb,
 *       tcb->tcbSchedContext == NULL && sc->scTcb == NULL
 * @post tcb->tcbSchedContext == sc && sc->scTcb == tcb
 */
void schedContext_bindTCB(sched_context_t *sc, tcb_t *tcb);

/* Unbind a specific tcb from a scheduling context. If the tcb is runnable,
 * remove from the scheduler.
 *
 * @param sc  scheduling context to unbind
 * @param tcb the tcb to unbind
 *
 * @pre   the tcb is bound to the sc,
 *        (sc->scTcb == tcb && tcb->tcbSchedContext == sc);
 * @post  (tcb->tcbSchedContext == NULL && sc->scTcb == NULL)
 */
void schedContext_unbindTCB(sched_context_t *sc, tcb_t *tcb);

/*
 * Unbind any tcb from a scheduling context. If the tcb bound to the scheduling
 * context is runnable, remove from the scheduler.
 *
 * @param sc the scheduling context to unbind
 * @post  (sc->scTcb == NULL)
 */
void schedContext_unbindAllTCBs(sched_context_t *sc);

/*
 * Resume a scheduling context. This will check if a the tcb bound to the scheduling context
 * is runnable, if so, it will then check if the budget is due to be recharged and do so.
 * If the scheduling context has insufficient budget the bound tcb is placed in the release queue.
 *
 * @pre (sc != NULL)
 */
void schedContext_resume(sched_context_t *sc);

/*
 * Donate sc to tcb.
 *
 * @pre (sc != NULL && tcb != NULL)
 * @post (sc->scTcb == tcb && tcb->tcbSchedContext == sc)
 */
void schedContext_donate(sched_context_t *sc, tcb_t *to);

/* Bind scheduling context to a notification */
void schedContext_bindNtfn(sched_context_t *sc, notification_t *ntfn);
/* unbind scheduling context from a notification */
void schedContext_unbindNtfn(sched_context_t *sc);

time_t schedContext_updateConsumed(sched_context_t *sc);
void schedContext_completeYieldTo(tcb_t *yielder);
void schedContext_cancelYieldTo(tcb_t *yielder);
# 17 "/home/koc034/Documents/newver/seL4/src/api/faults.c" 2


/* consistency with libsel4 */
typedef int __assert_failed_InvalidRoot[(lookup_fault_invalid_root + 1 == seL4_InvalidRoot) ? 1 : -1];
typedef int __assert_failed_MissingCapability[(lookup_fault_missing_capability + 1 == seL4_MissingCapability) ? 1 : -1];
typedef int __assert_failed_DepthMismatch[(lookup_fault_depth_mismatch + 1 == seL4_DepthMismatch) ? 1 : -1];
typedef int __assert_failed_GuardMismatch[(lookup_fault_guard_mismatch + 1 == seL4_GuardMismatch) ? 1 : -1];
typedef int __assert_failed_seL4_UnknownSyscall_Syscall[((word_t) n_syscallMessage == seL4_UnknownSyscall_Syscall) ? 1 : -1];
typedef int __assert_failed_seL4_UserException_Number[((word_t) n_exceptionMessage == seL4_UserException_Number) ? 1 : -1];
typedef int __assert_failed_seL4_UserException_Code[((word_t) n_exceptionMessage + 1 == seL4_UserException_Code) ? 1 : -1];

static inline unsigned int
setMRs_lookup_failure(tcb_t *receiver, word_t *receiveIPCBuffer,
                      lookup_fault_t luf, unsigned int offset)
{
    word_t lufType = lookup_fault_get_lufType(luf);
    word_t i;

    i = setMR(receiver, receiveIPCBuffer, offset, lufType + 1);

    /* check constants match libsel4 */
    if (offset == seL4_CapFault_LookupFailureType) {
        ;
        ;
        ;
        ;
    } else {
        ;
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
        halt();
    }
}

static inline void copyMRsFaultReply(tcb_t *sender, tcb_t *receiver, MessageID_t id, word_t length)
{
    word_t i;
    bool_t archInfo;

    archInfo = Arch_getSanitiseRegisterInfo(receiver);

    for (i = 0; i < (((length)<(n_msgRegisters))?(length):(n_msgRegisters)); i++) {
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
    for (i = 0; i < (((length)<(n_msgRegisters))?(length):(n_msgRegisters)); i++) {
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
        copyMRsFaultReply(sender, receiver, MessageID_Syscall, (((length)<(n_syscallMessage))?(length):(n_syscallMessage)));
        return (label == 0);

    case seL4_Fault_UserException:
        copyMRsFaultReply(sender, receiver, MessageID_Exception, (((length)<(n_exceptionMessage))?(length):(n_exceptionMessage)));
        return (label == 0);


    case seL4_Fault_Timeout:
        copyMRsFaultReply(sender, receiver, MessageID_TimeoutReply, (((length)<(n_timeoutMessage))?(length):(n_timeoutMessage)));
        return (label == 0);
# 186 "/home/koc034/Documents/newver/seL4/src/api/faults.c"
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
# 256 "/home/koc034/Documents/newver/seL4/src/api/faults.c"
    default:
        return Arch_setMRs_fault(sender, receiver, receiveIPCBuffer,
                                 seL4_Fault_get_seL4_FaultType(sender->tcbFault));
    }
}
# 1 "/home/koc034/Documents/newver/seL4/src/api/syscall.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */



# 1 "/home/koc034/Documents/newver/seL4/include/benchmark/benchmark.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       

# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/benchmark.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 10 "/home/koc034/Documents/newver/seL4/include/benchmark/benchmark.h" 2



# 1 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/benchmark_tracepoints_types.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       


# 1 "autoconf/autoconf.h" 1
# 11 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/benchmark_tracepoints_types.h" 2
# 14 "/home/koc034/Documents/newver/seL4/include/benchmark/benchmark.h" 2
# 10 "/home/koc034/Documents/newver/seL4/src/api/syscall.c" 2

# 1 "/home/koc034/Documents/newver/seL4/include/benchmark/benchmark_track.h" 1
/*
 * Copyright 2016, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



# 1 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/benchmark_track_types.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       




# 1 "autoconf/autoconf.h" 1
# 13 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/benchmark_track_types.h" 2
# 12 "/home/koc034/Documents/newver/seL4/include/benchmark/benchmark_track.h" 2


# 1 "/home/koc034/Documents/newver/seL4/include/kernel/cspace.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       






struct lookupCap_ret {
    exception_t status;
    cap_t cap;
};
typedef struct lookupCap_ret lookupCap_ret_t;

struct lookupCapAndSlot_ret {
    exception_t status;
    cap_t cap;
    cte_t *slot;
};
typedef struct lookupCapAndSlot_ret lookupCapAndSlot_ret_t;

struct lookupSlot_raw_ret {
    exception_t status;
    cte_t *slot;
};
typedef struct lookupSlot_raw_ret lookupSlot_raw_ret_t;

struct lookupSlot_ret {
    exception_t status;
    cte_t *slot;
};
typedef struct lookupSlot_ret lookupSlot_ret_t;

struct resolveAddressBits_ret {
    exception_t status;
    cte_t *slot;
    word_t bitsRemaining;
};
typedef struct resolveAddressBits_ret resolveAddressBits_ret_t;

lookupCap_ret_t lookupCap(tcb_t *thread, cptr_t cPtr);
lookupCapAndSlot_ret_t lookupCapAndSlot(tcb_t *thread, cptr_t cPtr);
lookupSlot_raw_ret_t lookupSlot(tcb_t *thread, cptr_t capptr);
lookupSlot_ret_t lookupSlotForCNodeOp(bool_t isSource,
                                      cap_t root, cptr_t capptr,
                                      word_t depth);
lookupSlot_ret_t lookupSourceSlot(cap_t root, cptr_t capptr,
                                  word_t depth);
lookupSlot_ret_t lookupTargetSlot(cap_t root, cptr_t capptr,
                                  word_t depth);
lookupSlot_ret_t lookupPivotSlot(cap_t root, cptr_t capptr,
                                 word_t depth);
resolveAddressBits_ret_t resolveAddressBits(cap_t nodeCap,
                                            cptr_t capptr,
                                            word_t n_bits);
# 15 "/home/koc034/Documents/newver/seL4/include/benchmark/benchmark_track.h" 2
# 12 "/home/koc034/Documents/newver/seL4/src/api/syscall.c" 2
# 1 "/home/koc034/Documents/newver/seL4/include/benchmark/benchmark_utilisation.h" 1
/*
 * Copyright 2016, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



# 1 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/benchmark_utilisation_types.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       


# 1 "autoconf/autoconf.h" 1
# 11 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/benchmark_utilisation_types.h" 2
# 12 "/home/koc034/Documents/newver/seL4/include/benchmark/benchmark_utilisation.h" 2
# 13 "/home/koc034/Documents/newver/seL4/src/api/syscall.c" 2




# 1 "/home/koc034/Documents/newver/seL4/include/kernel/faulthandler.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




static inline bool_t validTimeoutHandler(tcb_t *tptr)
{
    return cap_get_capType((((cte_t *)((word_t)(tptr)&~((1ul << (10))-1ul)))+(tcbTimeoutHandler))->cap) == cap_endpoint_cap;
}

void handleTimeout(tcb_t *tptr);
void handleNoFaultHandler(tcb_t *tptr);
bool_t sendFaultIPC(tcb_t *tptr, cap_t handlerCap, bool_t can_donate);




void handleFault(tcb_t *tptr);
# 18 "/home/koc034/Documents/newver/seL4/src/api/syscall.c" 2






# 1 "/home/koc034/Documents/newver/seL4/include/string.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



word_t strnlen(const char *s, word_t maxlen);
word_t strlcpy(char *dest, const char *src, word_t size);
word_t strlcat(char *dest, const char *src, word_t size);
# 25 "/home/koc034/Documents/newver/seL4/src/api/syscall.c" 2
# 1 "/home/koc034/Documents/newver/seL4/include/kernel/traps.h" 1
/*
 * Copyright 2016, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/kernel/traps.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




static inline void arch_c_entry_hook(void)
{
}

static inline void arch_c_exit_hook(void)
{
}

void c_handle_syscall(word_t cptr, word_t msgInfo, word_t unused1, word_t unused2, word_t unused3, word_t unused4,
                      word_t unused5, syscall_t syscall)
__attribute__((externally_visible)) __attribute__((__noreturn__));

void c_handle_interrupt(void)
__attribute__((externally_visible)) __attribute__((__noreturn__));

void c_handle_exception(void)
__attribute__((externally_visible)) __attribute__((__noreturn__));

void restore_user_context(void)
__attribute__((externally_visible)) __attribute__((__noreturn__));

void handle_exception(void);
# 12 "/home/koc034/Documents/newver/seL4/include/kernel/traps.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/smp/lock.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       






# 1 "/home/koc034/Documents/newver/seL4/include/smp/ipi.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



# 1 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

# 1 "gen_headers/plat/machine/devices_gen.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * This file is autogenerated by kernel/tools/hardware_gen.py.
 */
# 8 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 2
# 1 "gen_headers/plat/platform_gen.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 8 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 2
# 12 "/home/koc034/Documents/newver/seL4/include/smp/ipi.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/smp/ipi.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 13 "/home/koc034/Documents/newver/seL4/include/smp/ipi.h" 2
# 15 "/home/koc034/Documents/newver/seL4/include/smp/lock.h" 2
# 13 "/home/koc034/Documents/newver/seL4/include/kernel/traps.h" 2

/* This C function should be the first thing called from C after entry from
 * assembly. It provides a single place to do any entry work that is not
 * done in assembly for various reasons */
static inline void c_entry_hook(void)
{
    arch_c_entry_hook();



}

/* This C function should be the last thing called from C before exiting
 * the kernel (be it to assembly or returning to user space). It provides
 * a place to provide any additional instrumentation or functionality
 * in C before leaving the kernel */
static inline void c_exit_hook(void)
{
# 44 "/home/koc034/Documents/newver/seL4/include/kernel/traps.h"
    arch_c_exit_hook();
}
# 26 "/home/koc034/Documents/newver/seL4/src/api/syscall.c" 2






/* The haskell function 'handleEvent' is split into 'handleXXX' variants
 * for each event causing a kernel entry */

exception_t handleInterruptEntry(void)
{
    irq_t irq;

    irq = getActiveIRQ();

    if (1) {
        updateTimestamp();
        checkBudget();
    }


    if ((irq) != (irqInvalid)) {
        handleInterrupt(irq);
        Arch_finaliseInterrupt();
    } else {



        handleSpuriousIRQ();
    }


    if (1) {

        schedule();
        activateThread();

    }


    return EXCEPTION_NONE;
}

exception_t handleUnknownSyscall(word_t w)
{
# 313 "/home/koc034/Documents/newver/seL4/src/api/syscall.c"
    updateTimestamp(); if (__builtin_expect(!!(checkBudgetRestart()), 1)) { { current_fault = seL4_Fault_UnknownSyscall_new(w); handleFault(ksCurThread); } }
# 330 "/home/koc034/Documents/newver/seL4/src/api/syscall.c"
    schedule();
    activateThread();

    return EXCEPTION_NONE;
}

exception_t handleUserLevelFault(word_t w_a, word_t w_b)
{
    updateTimestamp(); if (__builtin_expect(!!(checkBudgetRestart()), 1)) { { current_fault = seL4_Fault_UserException_new(w_a, w_b); handleFault(ksCurThread); } }



    schedule();
    activateThread();

    return EXCEPTION_NONE;
}

exception_t handleVMFaultEvent(vm_fault_type_t vm_faultType)
{
    updateTimestamp(); if (__builtin_expect(!!(checkBudgetRestart()), 1)) { { exception_t status = handleVMFault(ksCurThread, vm_faultType); if (status != EXCEPTION_NONE) { handleFault(ksCurThread); } } }
# 359 "/home/koc034/Documents/newver/seL4/src/api/syscall.c"
    schedule();
    activateThread();

    return EXCEPTION_NONE;
}


static exception_t handleInvocation(bool_t isCall, bool_t isBlocking, bool_t canDonate, bool_t firstPhase, cptr_t cptr)



{
    seL4_MessageInfo_t info;
    lookupCapAndSlot_ret_t lu_ret;
    word_t *buffer;
    exception_t status;
    word_t length;
    tcb_t *thread;

    thread = ksCurThread;

    info = messageInfoFromWord(getRegister(thread, msgInfoRegister));




    /* faulting section */
    lu_ret = lookupCapAndSlot(thread, cptr);

    if (__builtin_expect(!!(lu_ret.status != EXCEPTION_NONE), 0)) {
        ;
        current_fault = seL4_Fault_CapFault_new(cptr, false);

        if (isBlocking) {
            handleFault(thread);
        }

        return EXCEPTION_NONE;
    }

    buffer = lookupIPCBuffer(false, thread);

    status = lookupExtraCaps(thread, buffer, info);

    if (__builtin_expect(!!(status != EXCEPTION_NONE), 0)) {
        ;
        if (isBlocking) {
            handleFault(thread);
        }
        return EXCEPTION_NONE;
    }

    /* Syscall error/Preemptible section */
    length = seL4_MessageInfo_get_length(info);
    if (__builtin_expect(!!(length > n_msgRegisters && !buffer), 0)) {
        length = n_msgRegisters;
    }

    status = decodeInvocation(seL4_MessageInfo_get_label(info), length,
                              cptr, lu_ret.slot, lu_ret.cap,
                              isBlocking, isCall,
                              canDonate, firstPhase, buffer);






    if (__builtin_expect(!!(status == EXCEPTION_PREEMPTED), 0)) {
        return status;
    }

    if (__builtin_expect(!!(status == EXCEPTION_SYSCALL_ERROR), 0)) {
        if (isCall) {
            replyFromKernel_error(thread);
        }
        return EXCEPTION_NONE;
    }

    if (__builtin_expect(!!(thread_state_get_tsType(thread->tcbState) == ThreadState_Restart), 0)
                                                                             ) {
        if (isCall) {
            replyFromKernel_success_empty(thread);
        }
        setThreadState(thread, ThreadState_Running);
    }

    return EXCEPTION_NONE;
}


static inline lookupCap_ret_t lookupReply(void)
{
    word_t replyCPtr = getRegister(ksCurThread, replyRegister);
    lookupCap_ret_t lu_ret = lookupCap(ksCurThread, replyCPtr);
    if (__builtin_expect(!!(lu_ret.status != EXCEPTION_NONE), 0)) {
        ;
        current_fault = seL4_Fault_CapFault_new(replyCPtr, true);
        handleFault(ksCurThread);
        return lu_ret;
    }

    if (__builtin_expect(!!(cap_get_capType(lu_ret.cap) != cap_reply_cap), 0)) {
        ;
        current_fault = seL4_Fault_CapFault_new(replyCPtr, true);
        handleFault(ksCurThread);
        lu_ret.status = EXCEPTION_FAULT;
        return lu_ret;
    }

    return lu_ret;
}
# 509 "/home/koc034/Documents/newver/seL4/src/api/syscall.c"
static void handleRecv(bool_t isBlocking, bool_t canReply)



{
    word_t epCPtr;
    lookupCap_ret_t lu_ret;

    epCPtr = getRegister(ksCurThread, capRegister);

    lu_ret = lookupCap(ksCurThread, epCPtr);

    if (__builtin_expect(!!(lu_ret.status != EXCEPTION_NONE), 0)) {
        /* current_lookup_fault has been set by lookupCap */
        current_fault = seL4_Fault_CapFault_new(epCPtr, true);
        handleFault(ksCurThread);
        return;
    }

    switch (cap_get_capType(lu_ret.cap)) {
    case cap_endpoint_cap:
        if (__builtin_expect(!!(!cap_endpoint_cap_get_capCanReceive(lu_ret.cap)), 0)) {
            current_lookup_fault = lookup_fault_missing_capability_new(0);
            current_fault = seL4_Fault_CapFault_new(epCPtr, true);
            handleFault(ksCurThread);
            break;
        }


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
        receiveIPC(ksCurThread, ep_cap, isBlocking, reply_cap);




        break;

    case cap_notification_cap: {
        notification_t *ntfnPtr;
        tcb_t *boundTCB;
        ntfnPtr = ((notification_t *)(cap_notification_cap_get_capNtfnPtr(lu_ret.cap)));
        boundTCB = (tcb_t *)notification_ptr_get_ntfnBoundTCB(ntfnPtr);
        if (__builtin_expect(!!(!cap_notification_cap_get_capNtfnCanReceive(lu_ret.cap) || (boundTCB && boundTCB != ksCurThread)), 0)
                                                                          ) {
            current_lookup_fault = lookup_fault_missing_capability_new(0);
            current_fault = seL4_Fault_CapFault_new(epCPtr, true);
            handleFault(ksCurThread);
            break;
        }

        receiveSignal(ksCurThread, lu_ret.cap, isBlocking);
        break;
    }
    default:
        current_lookup_fault = lookup_fault_missing_capability_new(0);
        current_fault = seL4_Fault_CapFault_new(epCPtr, true);
        handleFault(ksCurThread);
        break;
    }
}


static inline void mcsIRQ(irq_t irq)
{
    if ((irq) == INTERRUPT_CORE_TIMER) {
        /* if this is a timer irq we must update the time as we need to reprogram the timer, and we
         * can't lose the time that has just been used by the kernel. */
        updateTimestamp();
    }

    /* at this point we could be handling a timer interrupt which actually ends the current
     * threads timeslice. However, preemption is possible on revoke, which could have deleted
     * the current thread and/or the current scheduling context, rendering them invalid. */
    if (isSchedulable(ksCurThread)) {
        /* if the thread is schedulable, the tcb and scheduling context are still valid */
        checkBudget();
    } else if (ksCurSC->scRefillMax) {
        /* otherwise, if the thread is not schedulable, the SC could be valid - charge it if so */
        chargeBudget(ksConsumed, false, 0, true);
    }

}






static void handleYield(void)
{

    /* Yield the current remaining budget */
    ticks_t consumed = ksCurSC->scConsumed + ksConsumed;
    chargeBudget(refill_head(ksCurSC)->rAmount, false, 0, true);
    /* Manually updated the scConsumed so that the full timeslice isn't added, just what was consumed */
    ksCurSC->scConsumed = consumed;





}

exception_t handleSyscall(syscall_t syscall)
{
    exception_t ret;
    irq_t irq;
    updateTimestamp(); if (__builtin_expect(!!(checkBudgetRestart()), 1)) { { switch (syscall) { case SysSend: ret = handleInvocation(false, true, false, false, getRegister(ksCurThread, capRegister)); if (__builtin_expect(!!(ret != EXCEPTION_NONE), 0)) { irq = getActiveIRQ(); if ((irq) != (irqInvalid)) { mcsIRQ(irq); handleInterrupt(irq); Arch_finaliseInterrupt(); } } break; case SysNBSend: ret = handleInvocation(false, false, false, false, getRegister(ksCurThread, capRegister)); if (__builtin_expect(!!(ret != EXCEPTION_NONE), 0)) { irq = getActiveIRQ(); if ((irq) != (irqInvalid)) { mcsIRQ(irq); handleInterrupt(irq); Arch_finaliseInterrupt(); } } break; case SysCall: ret = handleInvocation(true, true, true, false, getRegister(ksCurThread, capRegister)); if (__builtin_expect(!!(ret != EXCEPTION_NONE), 0)) { irq = getActiveIRQ(); if ((irq) != (irqInvalid)) { mcsIRQ(irq); handleInterrupt(irq); Arch_finaliseInterrupt(); } } break; case SysRecv: handleRecv(true, true); break; case SysWait: handleRecv(true, false); break; case SysNBWait: handleRecv(false, false); break; case SysReplyRecv: { cptr_t reply = getRegister(ksCurThread, replyRegister); ret = handleInvocation(false, false, true, true, reply); /* reply cannot error and is not preemptible */ ; handleRecv(true, true); break; } case SysNBSendRecv: { cptr_t dest = getNBSendRecvDest(); ret = handleInvocation(false, false, true, true, dest); if (__builtin_expect(!!(ret != EXCEPTION_NONE), 0)) { irq = getActiveIRQ(); if ((irq) != (irqInvalid)) { mcsIRQ(irq); handleInterrupt(irq); Arch_finaliseInterrupt(); } break; } handleRecv(true, true); break; } case SysNBSendWait: ret = handleInvocation(false, false, true, true, getRegister(ksCurThread, replyRegister)); if (__builtin_expect(!!(ret != EXCEPTION_NONE), 0)) { irq = getActiveIRQ(); if ((irq) != (irqInvalid)) { mcsIRQ(irq); handleInterrupt(irq); Arch_finaliseInterrupt(); } break; } handleRecv(true, false); break; case SysNBRecv: handleRecv(false, true); break; case SysYield: handleYield(); break; default: halt(); } } }
# 739 "/home/koc034/Documents/newver/seL4/src/api/syscall.c"
    schedule();
    activateThread();

    return EXCEPTION_NONE;
}
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/api/benchmark.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/api/faults.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 20 "/home/koc034/Documents/newver/seL4/src/arch/riscv/api/faults.c"
bool_t Arch_handleFaultReply(tcb_t *receiver, tcb_t *sender, word_t faultType)
{
    switch (faultType) {
    case seL4_Fault_VMFault:
        return true;

    default:
        halt();
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
        halt();
    }
}
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/c_traps.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */



# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/fastpath/fastpath.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 18 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/fastpath/fastpath.h"
# 1 "/home/koc034/Documents/newver/seL4/include/machine/fpu.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/fpu.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/smp/ipi_inline.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 13 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/machine/fpu.h" 2

static inline void set_fs_off(void)
{
    __asm__ volatile("csrc sstatus, %0" :: "rK"(0x00006000));
}
# 13 "/home/koc034/Documents/newver/seL4/include/machine/fpu.h" 2
# 19 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/fastpath/fastpath.h" 2

void slowpath(syscall_t syscall)
__attribute__((__noreturn__));

void fastpath_call(word_t cptr, word_t r_msgInfo)
__attribute__((__noreturn__));


void fastpath_reply_recv(word_t cptr, word_t r_msgInfo, word_t reply)



__attribute__((__noreturn__));

/* Use macros to not break verification */



static inline void __attribute__((always_inline)) switchToThread_fp(tcb_t *thread, pte_t *vroot, pte_t stored_hw_asid)
{
    asid_t asid = (asid_t)(stored_hw_asid.words[0]);

    setVSpaceRoot(addrFromPPtr(vroot), asid);

    ksCurThread = thread;
}

static inline void mdb_node_ptr_mset_mdbNext_mdbRevocable_mdbFirstBadged(
    mdb_node_t *node_ptr, word_t mdbNext,
    word_t mdbRevocable, word_t mdbFirstBadged)
{
    node_ptr->words[1] = mdbNext | (mdbRevocable << 1) | mdbFirstBadged;
}

static inline void mdb_node_ptr_set_mdbPrev_np(mdb_node_t *node_ptr, word_t mdbPrev)
{
    node_ptr->words[0] = mdbPrev;
}

static inline bool_t isValidVTableRoot_fp(cap_t vspace_root_cap)
{
    return cap_capType_equals(vspace_root_cap, cap_page_table_cap) &&
           cap_page_table_cap_get_capPTIsMapped(vspace_root_cap);
}

/* This is an accelerated check that msgLength, which appears
   in the bottom of the msgInfo word, is <= 4 and that msgExtraCaps
   which appears above it is zero. We are assuming that n_msgRegisters == 4
   for this check to be useful. By masking out the bottom 3 bits, we are
   really checking that n + 3 <= MASK(3), i.e. n + 3 <= 7 or n <= 4. */
typedef int __assert_failed_n_msgRegisters_eq_4[(n_msgRegisters == 4) ? 1 : -1];
static inline int
fastpath_mi_check(word_t msgInfo)
{
    return (msgInfo & ((1ul << (seL4_MsgLengthBits + seL4_MsgExtraCapBits))-1ul)) > 4;
}

static inline void fastpath_copy_mrs(word_t length, tcb_t *src, tcb_t *dest)
{
    word_t i;
    register_t reg;

    /* assuming that length < n_msgRegisters */
    for (i = 0; i < length; i ++) {
        /* assuming that the message registers simply increment */
        reg = msgRegisters[0] + i;
        setRegister(dest, reg, getRegister(src, reg));
    }
}

static inline int fastpath_reply_cap_check(cap_t cap)
{
    return cap_capType_equals(cap, cap_reply_cap);
}

/** DONT_TRANSLATE */
static inline void __attribute__((__noreturn__)) __attribute__((always_inline)) fastpath_restore(word_t badge, word_t msgInfo, tcb_t *cur_thread)
{
    do {} while (0);
# 106 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/fastpath/fastpath.h"
    c_exit_hook();






    register word_t badge_reg __asm__("a0") = badge;
    register word_t msgInfo_reg __asm__("a1") = msgInfo;
    register word_t cur_thread_reg __asm__("t0") = ((word_t)(cur_thread));

    __asm__ volatile(
        "ld" "  ra, (0*%[REGSIZE])(t0)  \n"
        "ld" "  sp, (1*%[REGSIZE])(t0)  \n"
        "ld" "  gp, (2*%[REGSIZE])(t0)  \n"
        /* skip tp */
        /* skip x5/t0 */
        "ld" "  t2, (6*%[REGSIZE])(t0)  \n"
        "ld" "  s0, (7*%[REGSIZE])(t0)  \n"
        "ld" "  s1, (8*%[REGSIZE])(t0)  \n"
        "ld" "  a2, (11*%[REGSIZE])(t0) \n"
        "ld" "  a3, (12*%[REGSIZE])(t0) \n"
        "ld" "  a4, (13*%[REGSIZE])(t0) \n"
        "ld" "  a5, (14*%[REGSIZE])(t0) \n"
        "ld" "  a6, (15*%[REGSIZE])(t0) \n"
        "ld" "  a7, (16*%[REGSIZE])(t0) \n"
        "ld" "  s2, (17*%[REGSIZE])(t0) \n"
        "ld" "  s3, (18*%[REGSIZE])(t0) \n"
        "ld" "  s4, (19*%[REGSIZE])(t0) \n"
        "ld" "  s5, (20*%[REGSIZE])(t0) \n"
        "ld" "  s6, (21*%[REGSIZE])(t0) \n"
        "ld" "  s7, (22*%[REGSIZE])(t0) \n"
        "ld" "  s8, (23*%[REGSIZE])(t0) \n"
        "ld" "  s9, (24*%[REGSIZE])(t0) \n"
        "ld" "  s10, (25*%[REGSIZE])(t0)\n"
        "ld" "  s11, (26*%[REGSIZE])(t0)\n"
        "ld" "  t3, (27*%[REGSIZE])(t0) \n"
        "ld" "  t4, (28*%[REGSIZE])(t0) \n"
        "ld" "  t5, (29*%[REGSIZE])(t0) \n"
        "ld" "  t6, (30*%[REGSIZE])(t0) \n"
        /* Get next restored tp */
        "ld" "  t1, (3*%[REGSIZE])(t0)  \n"
        /* get restored tp */
        "add tp, t1, x0  \n"
        /* get sepc */
        "ld" "  t1, (34*%[REGSIZE])(t0)\n"
        "csrw sepc, t1  \n"

        /* Write back sscratch with cur_thread_reg to get it back on the next trap entry */
        "csrw sscratch, t0\n"

        "ld" "  t1, (32*%[REGSIZE])(t0) \n"
        "csrw sstatus, t1\n"

        "ld" "  t1, (5*%[REGSIZE])(t0) \n"
        "ld" "  t0, (4*%[REGSIZE])(t0) \n"
        "sret"
        : /* no output */
        : "r"(cur_thread_reg),
        [REGSIZE] "i"(sizeof(word_t)),
        "r"(badge_reg),
        "r"(msgInfo_reg)
        : "memory"
    );

    __builtin_unreachable();
}
# 11 "/home/koc034/Documents/newver/seL4/src/arch/riscv/c_traps.c" 2
# 21 "/home/koc034/Documents/newver/seL4/src/arch/riscv/c_traps.c"
/** DONT_TRANSLATE */
void __attribute__((externally_visible)) __attribute__((__noreturn__)) restore_user_context(void)
{
    word_t cur_thread_reg = (word_t) ksCurThread->tcbArch.tcbContext.registers;
    c_exit_hook();
    do {} while (0);
# 41 "/home/koc034/Documents/newver/seL4/src/arch/riscv/c_traps.c"
    __asm__ volatile(
        "mv t0, %[cur_thread]       \n"
        "ld" " ra, (0*%[REGSIZE])(t0)  \n"
        "ld" "  sp, (1*%[REGSIZE])(t0)  \n"
        "ld" "  gp, (2*%[REGSIZE])(t0)  \n"
        /* skip tp */
        /* skip x5/t0 */
        /* no-op store conditional to clear monitor state */
        /* this may succeed in implementations with very large reservations, but the saved ra is dead */
        "sc.w zero, zero, (t0)\n"
        "ld" "  t2, (6*%[REGSIZE])(t0)  \n"
        "ld" "  s0, (7*%[REGSIZE])(t0)  \n"
        "ld" "  s1, (8*%[REGSIZE])(t0)  \n"
        "ld" "  a0, (9*%[REGSIZE])(t0) \n"
        "ld" "  a1, (10*%[REGSIZE])(t0) \n"
        "ld" "  a2, (11*%[REGSIZE])(t0) \n"
        "ld" "  a3, (12*%[REGSIZE])(t0) \n"
        "ld" "  a4, (13*%[REGSIZE])(t0) \n"
        "ld" "  a5, (14*%[REGSIZE])(t0) \n"
        "ld" "  a6, (15*%[REGSIZE])(t0) \n"
        "ld" "  a7, (16*%[REGSIZE])(t0) \n"
        "ld" "  s2, (17*%[REGSIZE])(t0) \n"
        "ld" "  s3, (18*%[REGSIZE])(t0) \n"
        "ld" "  s4, (19*%[REGSIZE])(t0) \n"
        "ld" "  s5, (20*%[REGSIZE])(t0) \n"
        "ld" "  s6, (21*%[REGSIZE])(t0) \n"
        "ld" "  s7, (22*%[REGSIZE])(t0) \n"
        "ld" "  s8, (23*%[REGSIZE])(t0) \n"
        "ld" "  s9, (24*%[REGSIZE])(t0) \n"
        "ld" "  s10, (25*%[REGSIZE])(t0)\n"
        "ld" "  s11, (26*%[REGSIZE])(t0)\n"
        "ld" "  t3, (27*%[REGSIZE])(t0) \n"
        "ld" "  t4, (28*%[REGSIZE])(t0) \n"
        "ld" "  t5, (29*%[REGSIZE])(t0) \n"
        "ld" "  t6, (30*%[REGSIZE])(t0) \n"
        /* Get next restored tp */
        "ld" "  t1, (3*%[REGSIZE])(t0)  \n"
        /* get restored tp */
        "add tp, t1, x0  \n"
        /* get sepc */
        "ld" "  t1, (34*%[REGSIZE])(t0)\n"
        "csrw sepc, t1  \n"

        /* Write back sscratch with cur_thread_reg to get it back on the next trap entry */
        "csrw sscratch, t0         \n"

        "ld" "  t1, (32*%[REGSIZE])(t0) \n"
        "csrw sstatus, t1\n"

        "ld" "  t1, (5*%[REGSIZE])(t0) \n"
        "ld" "  t0, (4*%[REGSIZE])(t0) \n"
        "sret"
        : /* no output */
        : [REGSIZE] "i"(sizeof(word_t)),
        [cur_thread] "r"(cur_thread_reg)
        : "memory"
    );

    __builtin_unreachable();
}

void __attribute__((externally_visible)) __attribute__((__noreturn__)) c_handle_interrupt(void)
{
    do {} while (0);

    c_entry_hook();

    handleInterruptEntry();

    restore_user_context();
    __builtin_unreachable();
}

void __attribute__((externally_visible)) __attribute__((__noreturn__)) c_handle_exception(void)
{
    do {} while (0);

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
# 139 "/home/koc034/Documents/newver/seL4/src/arch/riscv/c_traps.c"
        handleUserLevelFault(scause, 0);
        break;
    }

    restore_user_context();
    __builtin_unreachable();
}

void __attribute__((__noreturn__)) slowpath(syscall_t syscall)
{
    /* check for undefined syscall */
    if (__builtin_expect(!!(syscall < (-11) || syscall > (-1)), 0)) {
        handleUnknownSyscall(syscall);
    } else {
        handleSyscall(syscall);
    }

    restore_user_context();
    __builtin_unreachable();
}

void __attribute__((externally_visible)) __attribute__((__noreturn__)) c_handle_syscall(word_t cptr, word_t msgInfo, word_t unused1, word_t unused2, word_t unused3,
                                       word_t unused4, word_t reply, syscall_t syscall)
{
    do {} while (0);

    c_entry_hook();


    if (syscall == (syscall_t)SysCall) {
        fastpath_call(cptr, msgInfo);
        __builtin_unreachable();
    } else if (syscall == (syscall_t)SysReplyRecv) {

        fastpath_reply_recv(cptr, msgInfo, reply);



        __builtin_unreachable();
    }

    slowpath(syscall);
    __builtin_unreachable();
}
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/idle.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */




void idle_thread(void)
{
    while (1) {
        __asm__ volatile("wfi");
    }
}

/** DONT_TRANSLATE */
void __attribute__((externally_visible)) __attribute__((noinline)) halt(void)
{




    sbi_shutdown();

    __builtin_unreachable();
}
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/boot.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */


# 1 "/home/koc034/Documents/newver/seL4/include/kernel/boot.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 1 "/home/koc034/Documents/newver/seL4/include/bootinfo.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



# 1 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/bootinfo_types.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

       


# 1 "autoconf/autoconf.h" 1
# 11 "/home/koc034/Documents/newver/seL4/libsel4/include/sel4/bootinfo_types.h" 2


/* caps with fixed slot positions in the root CNode */

enum {
    seL4_CapNull = 0, /* null cap */
    seL4_CapInitThreadTCB = 1, /* initial thread's TCB cap */
    seL4_CapInitThreadCNode = 2, /* initial thread's root CNode cap */
    seL4_CapInitThreadVSpace = 3, /* initial thread's VSpace cap */
    seL4_CapIRQControl = 4, /* global IRQ controller cap */
    seL4_CapASIDControl = 5, /* global ASID controller cap */
    seL4_CapInitThreadASIDPool = 6, /* initial thread's ASID pool cap */
    seL4_CapIOPortControl = 7, /* global IO port control cap (null cap if not supported) */
    seL4_CapIOSpace = 8, /* global IO space cap (null cap if no IOMMU support) */
    seL4_CapBootInfoFrame = 9, /* bootinfo frame cap */
    seL4_CapInitThreadIPCBuffer = 10, /* initial thread's IPC buffer frame cap */
    seL4_CapDomain = 11, /* global domain controller cap */
    seL4_CapSMMUSIDControl = 12, /*global SMMU SID controller cap, null cap if not supported*/
    seL4_CapSMMUCBControl = 13, /*global SMMU CB controller cap, null cap if not supported*/

    seL4_CapInitThreadSC = 14, /* initial thread's scheduling context cap */
    seL4_NumInitialCaps = 15



};

/* Legacy code will have assumptions on the vspace root being a Page Directory
 * type, so for now we define one to the other */


/* types */
typedef seL4_Word seL4_SlotPos;

typedef struct seL4_SlotRegion {
    seL4_SlotPos start; /* first CNode slot position OF region */
    seL4_SlotPos end; /* first CNode slot position AFTER region */
} seL4_SlotRegion;

typedef struct seL4_UntypedDesc {
    seL4_Word paddr; /* physical address of untyped cap  */
    seL4_Uint8 sizeBits;/* size (2^n) bytes of each untyped */
    seL4_Uint8 isDevice;/* whether the untyped is a device  */
    seL4_Uint8 padding[sizeof(seL4_Word) - 2 * sizeof(seL4_Uint8)];
} seL4_UntypedDesc;

typedef struct seL4_BootInfo {
    seL4_Word extraLen; /* length of any additional bootinfo information */
    seL4_NodeId nodeID; /* ID [0..numNodes-1] of the seL4 node (0 if uniprocessor) */
    seL4_Word numNodes; /* number of seL4 nodes (1 if uniprocessor) */
    seL4_Word numIOPTLevels; /* number of IOMMU PT levels (0 if no IOMMU support) */
    seL4_IPCBuffer *ipcBuffer; /* pointer to initial thread's IPC buffer */
    seL4_SlotRegion empty; /* empty slots (null caps) */
    seL4_SlotRegion sharedFrames; /* shared-frame caps (shared between seL4 nodes) */
    seL4_SlotRegion userImageFrames; /* userland-image frame caps */
    seL4_SlotRegion userImagePaging; /* userland-image paging structure caps */
    seL4_SlotRegion ioSpaceCaps; /* IOSpace caps for ARM SMMU */
    seL4_SlotRegion extraBIPages; /* caps for any pages used to back the additional bootinfo information */
    seL4_Word initThreadCNodeSizeBits; /* initial thread's root CNode size (2^n slots) */
    seL4_Domain initThreadDomain; /* Initial thread's domain ID */

    seL4_SlotRegion schedcontrol; /* Caps to sched_control for each node */

    seL4_SlotRegion untyped; /* untyped-object caps (untyped caps) */
    seL4_UntypedDesc untypedList[50]; /* information about each untyped */
    /* the untypedList should be the last entry in this struct, in order
     * to make this struct easier to represent in other languages */
} seL4_BootInfo;

/* If extraLen > 0 then 4K after the start of bootinfo is a region of extraLen additional
 * bootinfo structures. Bootinfo structures are arch/platform specific and may or may not
 * exist in any given execution. */
typedef struct seL4_BootInfoHeader {
    /* identifier of the following chunk. IDs are arch/platform specific */
    seL4_Word id;
    /* length of the chunk, including this header */
    seL4_Word len;
} seL4_BootInfoHeader;

/* Bootinfo identifiers share a global namespace, even if they are arch or platform specific
 * and are enumerated here */
# 12 "/home/koc034/Documents/newver/seL4/include/bootinfo.h" 2






/* adjust constants in config.h if this assert fails */
typedef int __assert_failed_bi_size[(sizeof(seL4_BootInfo) <= (1ul << (12))) ? 1 : -1];
# 9 "/home/koc034/Documents/newver/seL4/include/kernel/boot.h" 2
# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/bootinfo.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       


/* The maximum number of reserved regions is:
 * - 1 for each physical memory region (MAX_NUM_FREEMEM_REG)
 * - 1 for each kernel device (ARRAY_SIZE(kernel_devices))
 * - 1 for each mode-reserved region. (MODE_RESERVED)
 * - 1 each for kernel, dtb, and user image. (3)
 */
# 10 "/home/koc034/Documents/newver/seL4/include/kernel/boot.h" 2
# 21 "/home/koc034/Documents/newver/seL4/include/kernel/boot.h"
/*
 * Resolve naming differences between the abstract specifications
 * of the bootstrapping phase and the runtime phase of the kernel.
 */
typedef cte_t slot_t;
typedef cte_t *slot_ptr_t;



/* (node-local) state accessed only during bootstrapping */

typedef struct ndks_boot {
    p_region_t reserved[(16 + (sizeof(kernel_devices) / sizeof(kernel_devices[0])) + 0 + 3)];
    word_t resv_count;
    region_t freemem[16];
    seL4_BootInfo *bi_frame;
    seL4_SlotPos slot_pos_cur;
    seL4_SlotPos slot_pos_max;
} ndks_boot_t;

extern ndks_boot_t ndks_boot;

/* function prototypes */

static inline bool_t is_reg_empty(region_t reg)
{
    return reg.start == reg.end;
}

void init_freemem(word_t n_available, const p_region_t *available,
                  word_t n_reserved, region_t *reserved,
                  v_region_t it_v_reg, word_t extra_bi_size_bits);
bool_t reserve_region(p_region_t reg);
bool_t insert_region(region_t reg);
void write_slot(slot_ptr_t slot_ptr, cap_t cap);
cap_t create_root_cnode(void);
bool_t provide_cap(cap_t root_cnode_cap, cap_t cap);
cap_t create_it_asid_pool(cap_t root_cnode_cap);
void write_it_pd_pts(cap_t root_cnode_cap, cap_t it_pd_cap);
bool_t create_idle_thread(void);
bool_t create_untypeds_for_region(cap_t root_cnode_cap, bool_t device_memory, region_t reg,
                                  seL4_SlotPos first_untyped_slot);
bool_t create_device_untypeds(cap_t root_cnode_cap, seL4_SlotPos slot_pos_before);
bool_t create_kernel_untypeds(cap_t root_cnode_cap, region_t boot_mem_reuse_reg, seL4_SlotPos first_untyped_slot);
void bi_finalise(void);
void create_domain_cap(cap_t root_cnode_cap);

cap_t create_ipcbuf_frame_cap(cap_t root_cnode_cap, cap_t pd_cap, vptr_t vptr);
word_t calculate_extra_bi_size_bits(word_t extra_size);
void populate_bi_frame(node_id_t node_id, word_t num_nodes, vptr_t ipcbuf_vptr,
                       word_t extra_bi_size_bits);
void create_bi_frame_cap(cap_t root_cnode_cap, cap_t pd_cap, vptr_t vptr);


bool_t init_sched_control(cap_t root_cnode_cap, word_t num_nodes);


typedef struct create_frames_of_region_ret {
    seL4_SlotRegion region;
    bool_t success;
} create_frames_of_region_ret_t;

create_frames_of_region_ret_t
create_frames_of_region(
    cap_t root_cnode_cap,
    cap_t pd_cap,
    region_t reg,
    bool_t do_map,
    sword_t pv_offset
);

cap_t
create_it_pd_pts(
    cap_t root_cnode_cap,
    v_region_t ui_v_reg,
    vptr_t ipcbuf_vptr,
    vptr_t bi_frame_vptr
);

tcb_t *
create_initial_thread(
    cap_t root_cnode_cap,
    cap_t it_pd_cap,
    vptr_t ui_v_entry,
    vptr_t bi_frame_vptr,
    vptr_t ipcbuf_vptr,
    cap_t ipcbuf_cap
);

void init_core_state(tcb_t *scheduler_action);

/* state tracking the memory allocated for root server objects */
typedef struct {
    pptr_t cnode;
    pptr_t vspace;
    pptr_t asid_pool;
    pptr_t ipc_buf;
    pptr_t boot_info;
    pptr_t extra_bi;
    pptr_t tcb;

    pptr_t sc;

    region_t paging;
} rootserver_mem_t;

extern rootserver_mem_t rootserver;

/* get the number of paging structures required to cover it_v_reg, with
 * the paging structure covering `bits` of the address range - for a 4k page
 * `bits` would be 12 */
static inline __attribute__((__section__(".boot.text"))) word_t get_n_paging(v_region_t v_reg, word_t bits)
{
    vptr_t start = (((v_reg.start) >> (bits)) << (bits));
    vptr_t end = (((((v_reg.end) - 1ul) >> (bits)) + 1ul) << (bits));
    return (end - start) / (1ul << (bits));
}

/* allocate a page table sized structure from rootserver.paging */
static inline __attribute__((__section__(".boot.text"))) pptr_t it_alloc_paging(void)
{
    pptr_t allocated = rootserver.paging.start;
    rootserver.paging.start += (1ul << (12));
    ;
    return allocated;
}

/* return the amount of paging structures required to cover v_reg */
word_t arch_get_n_paging(v_region_t it_veg);

/* Create pptrs for all root server objects, starting at pptr, to cover the
 * virtual memory region v_reg, and any extra boot info. */
void create_rootserver_objects(pptr_t start, v_region_t v_reg, word_t extra_bi_size_bits);
# 10 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/boot.c" 2




# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/kernel/boot.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       




cap_t create_unmapped_it_frame_cap(pptr_t pptr, bool_t use_large);
cap_t create_mapped_it_frame_cap(cap_t pd_cap, pptr_t pptr, vptr_t vptr, asid_t asid, bool_t use_large,
                                 bool_t executable);

void init_kernel(
    paddr_t ui_p_reg_start,
    paddr_t ui_p_reg_end,
    sword_t pv_offset,
    vptr_t v_entry,
    paddr_t dtb_addr_p,
    uint32_t dtb_size





);
# 15 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/boot.c" 2






/* pointer to the end of boot code/data in kernel image */
/* need a fake array to get the pointer from the linker script */
extern char ki_boot_end[1];
/* pointer to end of kernel image */
extern char ki_end[1];





/* kernel image + [extra bootinfo] + user image */

__attribute__((__section__(".boot.data"))) static region_t res_reg[3];

__attribute__((__section__(".boot.text"))) static bool_t create_untypeds(cap_t root_cnode_cap, region_t boot_mem_reuse_reg)
{
    seL4_SlotPos slot_pos_before;
    seL4_SlotPos slot_pos_after;

    slot_pos_before = ndks_boot.slot_pos_cur;
    create_device_untypeds(root_cnode_cap, slot_pos_before);
    bool_t res = create_kernel_untypeds(root_cnode_cap, boot_mem_reuse_reg, slot_pos_before);

    slot_pos_after = ndks_boot.slot_pos_cur;
    ndks_boot.bi_frame->untyped = (seL4_SlotRegion) {
        slot_pos_before, slot_pos_after
    };
    return res;

}

__attribute__((__section__(".boot.text"))) cap_t create_mapped_it_frame_cap(cap_t pd_cap, pptr_t pptr, vptr_t vptr, asid_t asid, bool_t
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
              asid, /* capFMappedASID       */
              pptr, /* capFBasePtr          */
              frame_size, /* capFSize             */
              wordFromVMRights(VMReadWrite), /* capFVMRights         */
              0, /* capFIsDevice         */
              vptr /* capFMappedAddress    */
          );

    map_it_frame_cap(pd_cap, cap);
    return cap;
}

__attribute__((__section__(".boot.text"))) static void arch_init_freemem(region_t ui_reg, v_region_t ui_v_reg,
                                        region_t dtb_reg, word_t extra_bi_size_bits)
{
    // This looks a bit awkward as our symbols are a reference in the kernel image window, but
    // we want to do all allocations in terms of the main kernel window, so we do some translation
    res_reg[0].start = (pptr_t)ptrFromPAddr(kpptr_to_paddr((void *)(0xFFFFFFFF80000000ul + ((0x80000000 + 0x4000000ul) & ((1ul << (30))-1ul)))));
    res_reg[0].end = (pptr_t)ptrFromPAddr(kpptr_to_paddr((void *)ki_end));

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

__attribute__((__section__(".boot.text"))) static void init_irqs(cap_t root_cnode_cap)
{
    irq_t i;

    for (i = 0; i <= maxIRQ; i++) {
        if (i != irqInvalid) {
            /* IRQ 0 is irqInvalid */
            setIRQState(IRQInactive, i);
        }
    }
    setIRQState(IRQTimer, INTERRUPT_CORE_TIMER);




    /* provide the IRQ control cap */
    write_slot((((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapIRQControl)), cap_irq_control_cap_new());
}

/* ASM symbol for the CPU initialisation trap. */
extern char trap_entry[1];

/* This and only this function initialises the CPU. It does NOT initialise any kernel state. */
# 134 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/boot.c"
__attribute__((__section__(".boot.text"))) static void init_cpu(void)
{

    activate_kernel_vspace();
    /* Write trap entry address to stvec */
    write_stvec((word_t)trap_entry);
    initLocalIRQController();




    /* disable FPU access */
    set_fs_off();




}

/* This and only this function initialises the platform. It does NOT initialise any kernel state. */

__attribute__((__section__(".boot.text"))) static void init_plat(void)
{
    initIRQController();
}
# 188 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/boot.c"
/* Main kernel initialisation function. */

static __attribute__((__section__(".boot.text"))) bool_t try_init_kernel(
    paddr_t ui_p_reg_start,
    paddr_t ui_p_reg_end,
    uint32_t pv_offset,
    vptr_t v_entry,
    paddr_t dtb_addr_start,
    paddr_t dtb_addr_end
)
{
    cap_t root_cnode_cap;
    cap_t it_pd_cap;
    cap_t it_ap_cap;
    cap_t ipcbuf_cap;
    p_region_t boot_mem_reuse_p_reg = ((p_region_t) {
        kpptr_to_paddr((void *)(0xFFFFFFFF80000000ul + ((0x80000000 + 0x4000000ul) & ((1ul << (30))-1ul)))), kpptr_to_paddr(ki_boot_end)
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
    ui_v_reg.end = (word_t)(ui_p_reg_end - pv_offset);

    ipcbuf_vptr = ui_v_reg.end;
    bi_frame_vptr = ipcbuf_vptr + (1ul << (12));
    extra_bi_frame_vptr = bi_frame_vptr + (1ul << (12));

    /* If no DTB was provided, skip allocating extra bootinfo */
    p_region_t dtb_p_reg = {
        dtb_addr_start, (((((dtb_addr_end) - 1ul) >> (12)) + 1ul) << (12))
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
    it_v_reg.end = extra_bi_frame_vptr + (1ul << (extra_bi_size_bits));

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
    populate_bi_frame(0, 1, ipcbuf_vptr, extra_bi_size);

    /* put DTB in the bootinfo block, if present. */
    seL4_BootInfoHeader header;
    if (dtb_reg.start) {
        header.id = 6;
        header.len = extra_bi_size;
        *(seL4_BootInfoHeader *)(rootserver.extra_bi + extra_bi_offset) = header;
        extra_bi_offset += sizeof(header);
        memcpy((void *)(rootserver.extra_bi + extra_bi_offset), (void *)dtb_reg.start,
               dtb_reg.end - dtb_reg.start);
        extra_bi_offset += (dtb_reg.end - dtb_reg.start);
    }

    if (extra_bi_size > extra_bi_offset) {
        /* provide a chunk for any leftover padding in the extended boot info */
        header.id = 0;
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
                addrFromPPtr((void *)extra_bi_region.start) - extra_bi_frame_vptr
            );
        if (!extra_bi_ret.success) {
            return false;
        }
        ndks_boot.bi_frame->extraBIPages = extra_bi_ret.region;
    }


    init_sched_control(root_cnode_cap, 1);


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


    ksCurTime = getCurrentTime();


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

    if (initial == ((void *)0)) {
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
    ndks_boot.bi_frame->sharedFrames = (seL4_SlotRegion){ .start = 0, .end = 0 };

    /* finalise the bootinfo frame */
    bi_finalise();

    ksNumCPUs = 1;

    ;
    ;

    ((void)(0));
    return true;
}

__attribute__((__section__(".boot.text"))) __attribute__((externally_visible)) void init_kernel(
    paddr_t ui_p_reg_start,
    paddr_t ui_p_reg_end,
    sword_t pv_offset,
    vptr_t v_entry,
    paddr_t dtb_addr_p,
    uint32_t dtb_size





)
{
    bool_t result;
    paddr_t dtb_end_p = 0;

    if (dtb_addr_p) {
        dtb_end_p = dtb_addr_p + dtb_size;
    }
# 441 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/boot.c"
    result = try_init_kernel(ui_p_reg_start,
                             ui_p_reg_end,
                             pv_offset,
                             v_entry,
                             dtb_addr_p,
                             dtb_end_p);

    if (!result) {
        halt();
    }


    ksCurTime = getCurrentTime();
    ksConsumed = 0;


    schedule();
    activateThread();
}
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/thread.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 16 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/thread.c"
extern char kernel_stack_alloc[1][(1ul << (12))];

void Arch_switchToThread(tcb_t *tcb)
{
    setVMRoot(tcb);
}

__attribute__((__section__(".boot.text"))) void Arch_configureIdleThread(tcb_t *tcb)
{
    setRegister(tcb, NextIP, (word_t)(&idle_thread));

    /* Enable interrupts and keep working in supervisor mode */
    setRegister(tcb, SSTATUS, (word_t) 0x00000100 | 0x00000020);
# 37 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/thread.c"
    setRegister(tcb, SP, (word_t)kernel_stack_alloc + (1ul << (12)));

}

void Arch_switchToIdleThread(void)
{
    tcb_t *tcb = ksIdleThread;

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
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/vspace.c"
/*
 * Copyright 2020, DornerWorks
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 18 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/vspace.c"
# 1 "/home/koc034/Documents/newver/seL4/include/model/preemption.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       



exception_t preemptionPoint(void);
# 19 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/vspace.c" 2



# 1 "gen_headers/arch/api/invocation.h" 1

/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 ** SPDX-License-Identifier: GPL-2.0-only
 */

/* This header was generated by kernel/tools/invocation_header_gen.py.
 *
 * To add an invocation call number, edit libsel4/include/interfaces/sel4.xml.
 *
 */


# 1 "gen_headers/arch/api/sel4_invocation.h" 1

/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 ** SPDX-License-Identifier: GPL-2.0-only
 */

/* This header was generated by kernel/tools/invocation_header_gen.py.
 *
 * To add an invocation call number, edit libsel4/include/interfaces/sel4.xml.
 *
 */


# 1 "gen_headers/api/invocation.h" 1

/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 ** SPDX-License-Identifier: GPL-2.0-only
 */

/* This header was generated by kernel/tools/invocation_header_gen.py.
 *
 * To add an invocation call number, edit libsel4/include/interfaces/sel4.xml.
 *
 */



enum invocation_label {
    InvalidInvocation,
    UntypedRetype,
    TCBReadRegisters,
    TCBWriteRegisters,
    TCBCopyRegisters,




    TCBConfigure,

    TCBSetPriority,
    TCBSetMCPriority,




    TCBSetSchedParams,


    TCBSetTimeoutEndpoint,

    TCBSetIPCBuffer,




    TCBSetSpace,

    TCBSuspend,
    TCBResume,
    TCBBindNotification,
    TCBUnbindNotification,
# 64 "gen_headers/api/invocation.h"
    TCBSetTLSBase,
    CNodeRevoke,
    CNodeDelete,
    CNodeCancelBadgedSends,
    CNodeCopy,
    CNodeMint,
    CNodeMove,
    CNodeMutate,
    CNodeRotate,



    IRQIssueIRQHandler,
    IRQAckIRQ,
    IRQSetIRQHandler,
    IRQClearIRQHandler,
    DomainSetSet,

    SchedControlConfigure,


    SchedContextBind,


    SchedContextUnbind,


    SchedContextUnbindObject,


    SchedContextConsumed,


    SchedContextYieldTo,

    nInvocationLabels
};
# 15 "gen_headers/arch/api/sel4_invocation.h" 2
enum sel4_arch_invocation_label {
    nSeL4ArchInvocationLabels = nInvocationLabels
};
# 15 "gen_headers/arch/api/invocation.h" 2
enum arch_invocation_label {
    RISCVPageTableMap = nSeL4ArchInvocationLabels,
    RISCVPageTableUnmap,
    RISCVPageMap,
    RISCVPageUnmap,
    RISCVPageGetAddress,
    RISCVASIDControlMakePool,
    RISCVASIDPoolAssign,
    RISCVIRQIssueIRQHandlerTrigger,
    nArchInvocationLabels
};
# 23 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/vspace.c" 2







struct resolve_ret {
    paddr_t frameBase;
    vm_page_size_t frameSize;
    bool_t valid;
};
typedef struct resolve_ret resolve_ret_t;

static exception_t performPageGetAddress(void *vbase_ptr);

static word_t __attribute__((__const__)) RISCVGetWriteFromVMRights(vm_rights_t vm_rights)
{
    /* Write-only frame cap rights not currently supported. */
    return vm_rights == VMReadWrite;
}

static inline word_t __attribute__((__const__)) RISCVGetReadFromVMRights(vm_rights_t vm_rights)
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
                   0, /* sw */
                   1, /* dirty */
                   1, /* accessed */
                   1, /* global */
                   0, /* user */
                   exec, /* execute */
                   write, /* write */
                   read, /* read */
                   1 /* valid */
                  );
}

/* ==================== BOOT CODE STARTS HERE ==================== */

__attribute__((__section__(".boot.text"))) void map_kernel_frame(paddr_t paddr, pptr_t vaddr, vm_rights_t vm_rights)
{





    if (vaddr >= 0xFFFFFFFFC0000000ul) {
        /* Map devices in 2nd-level page table */
        paddr = (((paddr) >> ((((9) * (((3) - 1) - (1))) + 12))) << ((((9) * (((3) - 1) - (1))) + 12)));
        ;
        kernel_image_level2_dev_pt[(((vaddr) >> (((9) * (((3) - 1) - (1))) + 12)) & ((1ul << (9))-1ul))] = pte_next(paddr, true);
    } else {
        paddr = (((paddr) >> ((((9) * (((3) - 1) - (0))) + 12))) << ((((9) * (((3) - 1) - (0))) + 12)));
        ;
        kernel_root_pageTable[(((vaddr) >> (((9) * (((3) - 1) - (0))) + 12)) & ((1ul << (9))-1ul))] = pte_next(paddr, true);
    }

}

__attribute__((__section__(".boot.text"))) __attribute__((externally_visible)) void map_kernel_window(void)
{
    /* mapping of KERNEL_ELF_BASE (virtual address) to kernel's
     * KERNEL_ELF_PHYS_BASE  */
    ;

    /* kernel window starts at PPTR_BASE */
    word_t pptr = 0xFFFFFFC000000000ul;

    /* first we map in memory from PADDR_BASE */
    word_t paddr = 0x0ul;
    while (pptr < 0xFFFFFFFF80000000ul) {
        ;
        ;

        kernel_root_pageTable[(((pptr) >> (((9) * (((3) - 1) - (0))) + 12)) & ((1ul << (9))-1ul))] = pte_next(paddr, true);

        pptr += (1ul << ((((9) * (((3) - 1) - ((0)))) + 12)));
        paddr += (1ul << ((((9) * (((3) - 1) - ((0)))) + 12)));
    }
    /* now we should be mapping the 1GiB kernel base */
    ;
    pptr = ((((0xFFFFFFFF80000000ul + ((0x80000000 + 0x4000000ul) & ((1ul << (30))-1ul)))) >> ((((9) * (((3) - 1) - (0))) + 12))) << ((((9) * (((3) - 1) - (0))) + 12)));
    paddr = ((((0x80000000 + 0x4000000ul)) >> ((((9) * (((3) - 1) - (0))) + 12))) << ((((9) * (((3) - 1) - (0))) + 12)));
# 140 "/home/koc034/Documents/newver/seL4/src/arch/riscv/kernel/vspace.c"
    word_t index = 0;
    /* The kernel image are mapped twice, locating the two indexes in the
     * root page table, pointing them to the same second level page table.
     */
    kernel_root_pageTable[((((0x80000000 + 0x4000000ul) + (0xFFFFFFC000000000ul - 0x0ul)) >> (((9) * (((3) - 1) - (0))) + 12)) & ((1ul << (9))-1ul))] =
        pte_next(kpptr_to_paddr(kernel_image_level2_pt), false);
    kernel_root_pageTable[(((pptr) >> (((9) * (((3) - 1) - (0))) + 12)) & ((1ul << (9))-1ul))] =
        pte_next(kpptr_to_paddr(kernel_image_level2_pt), false);
    while (pptr < 0xFFFFFFFF80000000ul + (1ul << ((((9) * (((3) - 1) - ((0)))) + 12)))) {
        kernel_image_level2_pt[index] = pte_next(paddr, true);
        index++;
        pptr += (1ul << ((((9) * (((3) - 1) - ((1)))) + 12)));
        paddr += (1ul << ((((9) * (((3) - 1) - ((1)))) + 12)));
    }

    /* Map kernel device page table */
    kernel_root_pageTable[(((0xFFFFFFFFC0000000ul) >> (((9) * (((3) - 1) - (0))) + 12)) & ((1ul << (9))-1ul))] =
        pte_next(kpptr_to_paddr(kernel_image_level2_dev_pt), false);


    /* There should be 1GiB free where we put device mapping */
    ;
    map_kernel_devices();
}

__attribute__((__section__(".boot.text"))) void map_it_pt_cap(cap_t vspace_cap, cap_t pt_cap)
{
    lookupPTSlot_ret_t pt_ret;
    pte_t *targetSlot;
    vptr_t vptr = cap_page_table_cap_get_capPTMappedAddress(pt_cap);
    pte_t *lvl1pt = ((pte_t *)((pptr_t)cap_get_capPtr(vspace_cap)));

    /* pt to be mapped */
    pte_t *pt = ((pte_t *)((pptr_t)cap_get_capPtr(pt_cap)));

    /* Get PT slot to install the address in */
    pt_ret = lookupPTSlot(lvl1pt, vptr);

    targetSlot = pt_ret.ptSlot;

    *targetSlot = pte_new(
                      (addrFromPPtr(pt) >> 12),
                      0, /* sw */
                      1, /* dirty */
                      1, /* accessed */
                      0, /* global */
                      0, /* user */
                      0, /* execute */
                      0, /* write */
                      0, /* read */
                      1 /* valid */
                  );
    sfence();
}

__attribute__((__section__(".boot.text"))) void map_it_frame_cap(cap_t vspace_cap, cap_t frame_cap)
{
    pte_t *lvl1pt = ((pte_t *)((pptr_t)cap_get_capPtr(vspace_cap)));
    pte_t *frame_pptr = ((pte_t *)((pptr_t)cap_get_capPtr(frame_cap)));
    vptr_t frame_vptr = cap_frame_cap_get_capFMappedAddress(frame_cap);

    /* We deal with a frame as 4KiB */
    lookupPTSlot_ret_t lu_ret = lookupPTSlot(lvl1pt, frame_vptr);
    ;

    pte_t *targetSlot = lu_ret.ptSlot;

    *targetSlot = pte_new(
                      (addrFromPPtr(frame_pptr) >> 12),
                      0, /* sw */
                      1, /* dirty */
                      1, /* accessed */
                      0, /* global */
                      1, /* user */
                      1, /* execute */
                      1, /* write */
                      1, /* read */
                      1 /* valid */
                  );
    sfence();
}

__attribute__((__section__(".boot.text"))) cap_t create_unmapped_it_frame_cap(pptr_t pptr, bool_t use_large)
{
    cap_t cap = cap_frame_cap_new(
                    asidInvalid, /* capFMappedASID       */
                    pptr, /* capFBasePtr          */
                    0, /* capFSize             */
                    0, /* capFVMRights         */
                    0,
                    0 /* capFMappedAddress    */
                );

    return cap;
}

/* Create a page table for the initial thread */
static __attribute__((__section__(".boot.text"))) cap_t create_it_pt_cap(cap_t vspace_cap, pptr_t pptr, vptr_t vptr, asid_t asid)
{
    cap_t cap;
    cap = cap_page_table_cap_new(
              asid, /* capPTMappedASID      */
              pptr, /* capPTBasePtr         */
              1, /* capPTIsMapped        */
              vptr /* capPTMappedAddress   */
          );

    map_it_pt_cap(vspace_cap, cap);
    return cap;
}

__attribute__((__section__(".boot.text"))) word_t arch_get_n_paging(v_region_t it_v_reg)
{
    word_t n = 0;
    for (int i = 0; i < 3 - 1; i++) {
        n += get_n_paging(it_v_reg, (((9) * (((3) - 1) - (i))) + 12));
    }
    return n;
}

/* Create an address space for the initial thread.
 * This includes page directory and page tables */
__attribute__((__section__(".boot.text"))) cap_t create_it_address_space(cap_t root_cnode_cap, v_region_t it_v_reg)
{
    cap_t lvl1pt_cap;
    vptr_t pt_vptr;

    copyGlobalMappings(((pte_t *)(rootserver.vspace)));

    lvl1pt_cap =
        cap_page_table_cap_new(
            1, /* capPTMappedASID    */
            (word_t) rootserver.vspace, /* capPTBasePtr       */
            1, /* capPTIsMapped      */
            (word_t) rootserver.vspace /* capPTMappedAddress */
        );

    seL4_SlotPos slot_pos_before = ndks_boot.slot_pos_cur;
    write_slot((((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapInitThreadVSpace)), lvl1pt_cap);

    /* create all n level PT caps necessary to cover userland image in 4KiB pages */
    for (int i = 0; i < 3 - 1; i++) {

        for (pt_vptr = (((it_v_reg.start) >> ((((9) * (((3) - 1) - (i))) + 12))) << ((((9) * (((3) - 1) - (i))) + 12)));
             pt_vptr < it_v_reg.end;
             pt_vptr += (1ul << ((((9) * (((3) - 1) - ((i)))) + 12)))) {
            if (!provide_cap(root_cnode_cap,
                             create_it_pt_cap(lvl1pt_cap, it_alloc_paging(), pt_vptr, 1))
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

__attribute__((__section__(".boot.text"))) void activate_kernel_vspace(void)
{
    setVSpaceRoot(kpptr_to_paddr(&kernel_root_pageTable), 0);
}

__attribute__((__section__(".boot.text"))) void write_it_asid_pool(cap_t it_ap_cap, cap_t it_lvl1pt_cap)
{
    asid_pool_t *ap = ((asid_pool_t*)(pptr_t)cap_get_capPtr(it_ap_cap));
    ap->array[1] = ((pte_t *)((pptr_t)cap_get_capPtr(it_lvl1pt_cap)));
    riscvKSASIDTable[1 >> asidLowBits] = ap;
}

/* ==================== BOOT CODE FINISHES HERE ==================== */

static findVSpaceForASID_ret_t findVSpaceForASID(asid_t asid)
{
    findVSpaceForASID_ret_t ret;
    asid_pool_t *poolPtr;
    pte_t *vspace_root;

    poolPtr = riscvKSASIDTable[asid >> asidLowBits];
    if (!poolPtr) {
        current_lookup_fault = lookup_fault_invalid_root_new();

        ret.vspace_root = ((void *)0);
        ret.status = EXCEPTION_LOOKUP_FAULT;
        return ret;
    }

    vspace_root = poolPtr->array[asid & ((1ul << (asidLowBits))-1ul)];
    if (!vspace_root) {
        current_lookup_fault = lookup_fault_invalid_root_new();

        ret.vspace_root = ((void *)0);
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

    for (i = (((0xFFFFFFC000000000ul) >> (((9) * (((3) - 1) - (0))) + 12)) & ((1ul << (9))-1ul)); i < (1ul << (9)); i++) {
        newLvl1pt[i] = global_kernel_vspace[i];
    }
}

word_t *__attribute__((__pure__)) lookupIPCBuffer(bool_t isReceiver, tcb_t *thread)
{
    word_t w_bufferPtr;
    cap_t bufferCap;
    vm_rights_t vm_rights;

    w_bufferPtr = thread->tcbIPCBuffer;
    bufferCap = (((cte_t *)((word_t)(thread)&~((1ul << (10))-1ul)))+(tcbBuffer))->cap;

    if (__builtin_expect(!!(cap_get_capType(bufferCap) != cap_frame_cap), 0)) {
        return ((void *)0);
    }
    if (__builtin_expect(!!(cap_frame_cap_get_capFIsDevice(bufferCap)), 0)) {
        return ((void *)0);
    }

    vm_rights = cap_frame_cap_get_capFVMRights(bufferCap);
    if (__builtin_expect(!!(vm_rights == VMReadWrite || (!isReceiver && vm_rights == VMReadOnly)), 1)
                                                        ) {
        word_t basePtr, pageBits;

        basePtr = cap_frame_cap_get_capFBasePtr(bufferCap);
        pageBits = pageBitsForSize(cap_frame_cap_get_capFSize(bufferCap));
        return (word_t *)(basePtr + (w_bufferPtr & ((1ul << (pageBits))-1ul)));
    } else {
        return ((void *)0);
    }
}

static inline pte_t *getPPtrFromHWPTE(pte_t *pte)
{
    return ((pte_t *)(ptrFromPAddr(pte_ptr_get_ppn(pte) << 12)));
}

lookupPTSlot_ret_t lookupPTSlot(pte_t *lvl1pt, vptr_t vptr)
{
    lookupPTSlot_ret_t ret;

    word_t level = 3 - 1;
    pte_t *pt = lvl1pt;

    /* this is how many bits we potentially have left to decode. Initially we have the
     * full address space to decode, and every time we walk this will be reduced. The
     * final value of this after the walk is the size of the frame that can be inserted,
     * or already exists, in ret.ptSlot. The following formulation is an invariant of
     * the loop: */
    ret.ptBitsLeft = 9 * level + 12;
    ret.ptSlot = pt + ((vptr >> ret.ptBitsLeft) & ((1ul << (9))-1ul));

    while (isPTEPageTable(ret.ptSlot) && __builtin_expect(!!(0 < level), 1)) {
        level--;
        ret.ptBitsLeft -= 9;
        pt = getPPtrFromHWPTE(ret.ptSlot);
        ret.ptSlot = pt + ((vptr >> ret.ptBitsLeft) & ((1ul << (9))-1ul));
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
        halt();
    }
}

void deleteASIDPool(asid_t asid_base, asid_pool_t *pool)
{
    /* Haskell error: "ASID pool's base must be aligned" */
    ;

    if (riscvKSASIDTable[asid_base >> asidLowBits] == pool) {
        riscvKSASIDTable[asid_base >> asidLowBits] = ((void *)0);
        setVMRoot(ksCurThread);
    }
}

static exception_t performASIDControlInvocation(void *frame, cte_t *slot, cte_t *parent, asid_t asid_base)
{
    /** AUXUPD: "(True, typ_region_bytes (ptr_val \<acute>frame) 12)" */
    /** GHOSTUPD: "(True, gs_clear_region (ptr_val \<acute>frame) 12)" */
    cap_untyped_cap_ptr_set_capFreeIndex(&(parent->cap),
                                         ((1ul << ((cap_untyped_cap_get_capBlockSize(parent->cap)) - 4))));

    memzero(frame, (1ul << (pageBitsForSize(RISCV_4K_Page))));
    /** AUXUPD: "(True, ptr_retyps 1 (Ptr (ptr_val \<acute>frame) :: asid_pool_C ptr))" */

    cteInsert(
        cap_asid_pool_cap_new(
            asid_base, /* capASIDBase  */
            ((word_t)(frame)) /* capASIDPool  */
        ),
        parent,
        slot
    );
    /* Haskell error: "ASID pool's base must be aligned" */
    ;
    riscvKSASIDTable[asid_base >> asidLowBits] = (asid_pool_t *)frame;

    return EXCEPTION_NONE;
}

static exception_t performASIDPoolInvocation(asid_t asid, asid_pool_t *poolPtr, cte_t *vspaceCapSlot)
{
    cap_t cap = vspaceCapSlot->cap;
    pte_t *regionBase = ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(cap)));
    cap = cap_page_table_cap_set_capPTMappedASID(cap, asid);
    cap = cap_page_table_cap_set_capPTMappedAddress(cap, 0);
    cap = cap_page_table_cap_set_capPTIsMapped(cap, 1);
    vspaceCapSlot->cap = cap;

    copyGlobalMappings(regionBase);

    poolPtr->array[asid & ((1ul << (asidLowBits))-1ul)] = regionBase;

    return EXCEPTION_NONE;
}

void deleteASID(asid_t asid, pte_t *vspace)
{
    asid_pool_t *poolPtr;

    poolPtr = riscvKSASIDTable[asid >> asidLowBits];
    if (poolPtr != ((void *)0) && poolPtr->array[asid & ((1ul << (asidLowBits))-1ul)] == vspace) {
        hwASIDFlush(asid);
        poolPtr->array[asid & ((1ul << (asidLowBits))-1ul)] = ((void *)0);
        setVMRoot(ksCurThread);
    }
}

void unmapPageTable(asid_t asid, vptr_t vptr, pte_t *target_pt)
{
    findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
    if (__builtin_expect(!!(find_ret.status != EXCEPTION_NONE), 0)) {
        /* nothing to do */
        return;
    }
    /* We won't ever unmap a top level page table */
    ;
    pte_t *ptSlot = ((void *)0);
    pte_t *pt = find_ret.vspace_root;

    for (word_t i = 0; i < 3 - 1 && pt != target_pt; i++) {
        ptSlot = pt + (((vptr) >> (((9) * (((3) - 1) - (i))) + 12)) & ((1ul << (9))-1ul));
        if (__builtin_expect(!!(!isPTEPageTable(ptSlot)), 0)) {
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
    ;
    *ptSlot = pte_new(
                  0, /* phy_address */
                  0, /* sw */
                  0, /* dirty */
                  0, /* accessed */
                  0, /* global */
                  0, /* user */
                  0, /* execute */
                  0, /* write */
                  0, /* read */
                  0 /* valid */
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
    lookupPTSlot_ret_t lu_ret;

    find_ret = findVSpaceForASID(asid);
    if (find_ret.status != EXCEPTION_NONE) {
        return;
    }

    lu_ret = lookupPTSlot(find_ret.vspace_root, vptr);
    if (__builtin_expect(!!(lu_ret.ptBitsLeft != pageBitsForSize(page_size)), 0)) {
        return;
    }
    if (!pte_ptr_get_valid(lu_ret.ptSlot) || isPTEPageTable(lu_ret.ptSlot)
        || (pte_ptr_get_ppn(lu_ret.ptSlot) << 12) != addrFromPPtr((void *)pptr)) {
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
    findVSpaceForASID_ret_t find_ret;

    threadRoot = (((cte_t *)((word_t)(tcb)&~((1ul << (10))-1ul)))+(tcbVTable))->cap;

    if (cap_get_capType(threadRoot) != cap_page_table_cap) {
        setVSpaceRoot(kpptr_to_paddr(&kernel_root_pageTable), 0);
        return;
    }

    lvl1pt = ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(threadRoot)));

    asid = cap_page_table_cap_get_capPTMappedASID(threadRoot);
    find_ret = findVSpaceForASID(asid);
    if (__builtin_expect(!!(find_ret.status != EXCEPTION_NONE || find_ret.vspace_root != lvl1pt), 0)) {
        setVSpaceRoot(kpptr_to_paddr(&kernel_root_pageTable), 0);
        return;
    }

    setVSpaceRoot(addrFromPPtr(lvl1pt), asid);
}

bool_t __attribute__((__const__)) isValidVTableRoot(cap_t cap)
{
    return (cap_get_capType(cap) == cap_page_table_cap &&
            cap_page_table_cap_get_capPTIsMapped(cap));
}

exception_t checkValidIPCBuffer(vptr_t vptr, cap_t cap)
{
    if (__builtin_expect(!!(cap_get_capType(cap) != cap_frame_cap), 0)) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (__builtin_expect(!!(cap_frame_cap_get_capFIsDevice(cap)), 0)) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (__builtin_expect(!!(!(!((vptr) & ((1ul << (10))-1ul)))), 0)) {
       
                            ;
        current_syscall_error.type = seL4_AlignmentError;
        return EXCEPTION_SYSCALL_ERROR;
    }

    return EXCEPTION_NONE;
}

vm_rights_t __attribute__((__const__)) maskVMRights(vm_rights_t vm_rights, seL4_CapRights_t cap_rights_mask)
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

static pte_t __attribute__((__const__)) makeUserPTE(paddr_t paddr, bool_t executable, vm_rights_t vm_rights)
{
    word_t write = RISCVGetWriteFromVMRights(vm_rights);
    word_t read = RISCVGetReadFromVMRights(vm_rights);
    if (__builtin_expect(!!(!read && !write && !executable), 0)) {
        return pte_pte_invalid_new();
    } else {
        return pte_new(
                   paddr >> 12,
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

static inline bool_t __attribute__((__const__)) checkVPAlignment(vm_page_size_t sz, word_t w)
{
    return (w & ((1ul << (pageBitsForSize(sz)))-1ul)) == 0;
}

static exception_t decodeRISCVPageTableInvocation(word_t label, word_t length,
                                                  cte_t *cte, cap_t cap, word_t *buffer)
{
    if (label == RISCVPageTableUnmap) {
        if (__builtin_expect(!!(!isFinalCapability(cte)), 0)) {
            ;
            current_syscall_error.type = seL4_RevokeFirst;
            return EXCEPTION_SYSCALL_ERROR;
        }
        /* Ensure that if the page table is mapped, it is not a top level table */
        if (__builtin_expect(!!(cap_page_table_cap_get_capPTIsMapped(cap)), 1)) {
            asid_t asid = cap_page_table_cap_get_capPTMappedASID(cap);
            findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
            pte_t *pte = ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(cap)));
            if (__builtin_expect(!!(find_ret.status == EXCEPTION_NONE && find_ret.vspace_root == pte), 0)
                                                     ) {
                ;
                current_syscall_error.type = seL4_RevokeFirst;
                return EXCEPTION_SYSCALL_ERROR;
            }
        }

        setThreadState(ksCurThread, ThreadState_Restart);
        return performPageTableInvocationUnmap(cap, cte);
    }

    if (__builtin_expect(!!((label != RISCVPageTableMap)), 0)) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (__builtin_expect(!!(length < 2 || current_extra_caps.excaprefs[0] == ((void *)0)), 0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }
    if (__builtin_expect(!!(cap_page_table_cap_get_capPTIsMapped(cap)), 0)) {
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 0;
        return EXCEPTION_SYSCALL_ERROR;
    }

    word_t vaddr = getSyscallArg(0, buffer);
    cap_t lvl1ptCap = current_extra_caps.excaprefs[0]->cap;

    if (__builtin_expect(!!(cap_get_capType(lvl1ptCap) != cap_page_table_cap || cap_page_table_cap_get_capPTIsMapped(lvl1ptCap) == asidInvalid), 0)
                                                                                ) {
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;

        return EXCEPTION_SYSCALL_ERROR;
    }

    pte_t *lvl1pt = ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(lvl1ptCap)));
    asid_t asid = cap_page_table_cap_get_capPTMappedASID(lvl1ptCap);

    if (__builtin_expect(!!(vaddr >= 0x0000003ffffff000), 0)) {
        ;
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 0;

        return EXCEPTION_SYSCALL_ERROR;
    }

    findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
    if (__builtin_expect(!!(find_ret.status != EXCEPTION_NONE), 0)) {
        ;
        current_syscall_error.type = seL4_FailedLookup;
        current_syscall_error.failedLookupWasSource = false;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (__builtin_expect(!!(find_ret.vspace_root != lvl1pt), 0)) {
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    lookupPTSlot_ret_t lu_ret = lookupPTSlot(lvl1pt, vaddr);

    /* if there is already something mapped (valid is set) or we have traversed far enough
     * that a page table is not valid to map then tell the user that they ahve to delete
     * something before they can put a PT here */
    if (lu_ret.ptBitsLeft == 12 || pte_ptr_get_valid(lu_ret.ptSlot)) {
        ;
        current_syscall_error.type = seL4_DeleteFirst;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Get the slot to install the PT in */
    pte_t *ptSlot = lu_ret.ptSlot;

    paddr_t paddr = addrFromPPtr(
                        ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(cap))));
    pte_t pte = pte_new((paddr >> 12),
                        0, /* sw */
                        1, /* dirty */
                        1, /* accessed */
                        0, /* global */
                        0, /* user */
                        0, /* execute */
                        0, /* write */
                        0, /* read */
                        1 /* valid */
                       );

    cap = cap_page_table_cap_set_capPTIsMapped(cap, 1);
    cap = cap_page_table_cap_set_capPTMappedASID(cap, asid);
    cap = cap_page_table_cap_set_capPTMappedAddress(cap, (vaddr & ~((1ul << (lu_ret.ptBitsLeft))-1ul)));

    setThreadState(ksCurThread, ThreadState_Restart);
    return performPageTableInvocationMap(cap, cte, pte, ptSlot);
}

static exception_t decodeRISCVFrameInvocation(word_t label, word_t length,
                                              cte_t *cte, cap_t cap, word_t *buffer)
{
    switch (label) {
    case RISCVPageMap: {
        if (__builtin_expect(!!(length < 3 || current_extra_caps.excaprefs[0] == ((void *)0)), 0)) {
            ;
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }

        word_t vaddr = getSyscallArg(0, buffer);
        word_t w_rightsMask = getSyscallArg(1, buffer);
        vm_attributes_t attr = vmAttributesFromWord(getSyscallArg(2, buffer));
        cap_t lvl1ptCap = current_extra_caps.excaprefs[0]->cap;

        vm_page_size_t frameSize = cap_frame_cap_get_capFSize(cap);
        vm_rights_t capVMRights = cap_frame_cap_get_capFVMRights(cap);

        if (__builtin_expect(!!(cap_get_capType(lvl1ptCap) != cap_page_table_cap || !cap_page_table_cap_get_capPTIsMapped(lvl1ptCap)), 0)
                                                                      ) {
            ;
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return EXCEPTION_SYSCALL_ERROR;
        }

        pte_t *lvl1pt = ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(lvl1ptCap)));
        asid_t asid = cap_page_table_cap_get_capPTMappedASID(lvl1ptCap);

        findVSpaceForASID_ret_t find_ret = findVSpaceForASID(asid);
        if (__builtin_expect(!!(find_ret.status != EXCEPTION_NONE), 0)) {
            ;
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = false;
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (__builtin_expect(!!(find_ret.vspace_root != lvl1pt), 0)) {
            ;
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return EXCEPTION_SYSCALL_ERROR;
        }

        /* check the vaddr is valid */
        word_t vtop = vaddr + (1ul << (pageBitsForSize(frameSize))) - 1;
        if (__builtin_expect(!!(vtop >= 0x0000003ffffff000), 0)) {
            current_syscall_error.type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
        if (__builtin_expect(!!(!checkVPAlignment(frameSize, vaddr)), 0)) {
            current_syscall_error.type = seL4_AlignmentError;
            return EXCEPTION_SYSCALL_ERROR;
        }

        /* Check if this page is already mapped */
        lookupPTSlot_ret_t lu_ret = lookupPTSlot(lvl1pt, vaddr);
        if (__builtin_expect(!!(lu_ret.ptBitsLeft != pageBitsForSize(frameSize)), 0)) {
            current_lookup_fault = lookup_fault_missing_capability_new(lu_ret.ptBitsLeft);
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = false;
            return EXCEPTION_SYSCALL_ERROR;
        }

        asid_t frame_asid = cap_frame_cap_get_capFMappedASID(cap);
        if (__builtin_expect(!!(frame_asid != asidInvalid), 0)) {
            /* this frame is already mapped */
            if (frame_asid != asid) {
                ;
                current_syscall_error.type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 1;
                return EXCEPTION_SYSCALL_ERROR;
            }
            word_t mapped_vaddr = cap_frame_cap_get_capFMappedAddress(cap);
            if (__builtin_expect(!!(mapped_vaddr != vaddr), 0)) {
                ;
                current_syscall_error.type = seL4_InvalidArgument;
                current_syscall_error.invalidArgumentNumber = 0;
                return EXCEPTION_SYSCALL_ERROR;
            }
            /* this check is redundant, as lookupPTSlot does not stop on a page
             * table PTE */
            if (__builtin_expect(!!(isPTEPageTable(lu_ret.ptSlot)), 0)) {
                ;
                current_syscall_error.type = seL4_DeleteFirst;
                return EXCEPTION_SYSCALL_ERROR;
            }
        } else {
            /* check this vaddr isn't already mapped */
            if (__builtin_expect(!!(pte_ptr_get_valid(lu_ret.ptSlot)), 0)) {
                ;
                current_syscall_error.type = seL4_DeleteFirst;
                return EXCEPTION_SYSCALL_ERROR;
            }
        }

        vm_rights_t vmRights = maskVMRights(capVMRights, rightsFromWord(w_rightsMask));
        paddr_t frame_paddr = addrFromPPtr((void *) cap_frame_cap_get_capFBasePtr(cap));
        cap = cap_frame_cap_set_capFMappedASID(cap, asid);
        cap = cap_frame_cap_set_capFMappedAddress(cap, vaddr);

        bool_t executable = !vm_attributes_get_riscvExecuteNever(attr);
        pte_t pte = makeUserPTE(frame_paddr, executable, vmRights);
        setThreadState(ksCurThread, ThreadState_Restart);
        return performPageInvocationMapPTE(cap, cte, pte, lu_ret.ptSlot);
    }

    case RISCVPageUnmap: {
        setThreadState(ksCurThread, ThreadState_Restart);
        return performPageInvocationUnmap(cap, cte);
    }

    case RISCVPageGetAddress: {

        /* Check that there are enough message registers */
        ;

        setThreadState(ksCurThread, ThreadState_Restart);
        return performPageGetAddress((void *)cap_frame_cap_get_capFBasePtr(cap));
    }

    default:
        ;
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
        word_t i;
        asid_t asid_base;
        word_t index;
        word_t depth;
        cap_t untyped;
        cap_t root;
        cte_t *parentSlot;
        cte_t *destSlot;
        lookupSlot_ret_t lu_ret;
        void *frame;
        exception_t status;

        if (label != RISCVASIDControlMakePool) {
            current_syscall_error.type = seL4_IllegalOperation;

            return EXCEPTION_SYSCALL_ERROR;
        }

        if (length < 2 || current_extra_caps.excaprefs[0] == ((void *)0)
            || current_extra_caps.excaprefs[1] == ((void *)0)) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }

        index = getSyscallArg(0, buffer);
        depth = getSyscallArg(1, buffer);
        parentSlot = current_extra_caps.excaprefs[0];
        untyped = parentSlot->cap;
        root = current_extra_caps.excaprefs[1]->cap;

        /* Find first free pool */
        for (i = 0; i < (1ul << (asidHighBits)) && riscvKSASIDTable[i]; i++);

        if (i == (1ul << (asidHighBits))) {
            /* no unallocated pool is found */
            current_syscall_error.type = seL4_DeleteFirst;

            return EXCEPTION_SYSCALL_ERROR;
        }

        asid_base = i << asidLowBits;

        if (cap_get_capType(untyped) != cap_untyped_cap ||
            cap_untyped_cap_get_capBlockSize(untyped) != 12 ||
            cap_untyped_cap_get_capIsDevice(untyped)) {
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;

            return EXCEPTION_SYSCALL_ERROR;
        }

        status = ensureNoChildren(parentSlot);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        frame = ((word_t *)(cap_untyped_cap_get_capPtr(untyped)));

        lu_ret = lookupTargetSlot(root, index, depth);
        if (lu_ret.status != EXCEPTION_NONE) {
            return lu_ret.status;
        }
        destSlot = lu_ret.slot;

        status = ensureEmptySlot(destSlot);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        setThreadState(ksCurThread, ThreadState_Restart);
        return performASIDControlInvocation(frame, destSlot, parentSlot, asid_base);
    }

    case cap_asid_pool_cap: {
        cap_t vspaceCap;
        cte_t *vspaceCapSlot;
        asid_pool_t *pool;
        word_t i;
        asid_t asid;

        if (label != RISCVASIDPoolAssign) {
            current_syscall_error.type = seL4_IllegalOperation;

            return EXCEPTION_SYSCALL_ERROR;
        }
        if (current_extra_caps.excaprefs[0] == ((void *)0)) {
            current_syscall_error.type = seL4_TruncatedMessage;

            return EXCEPTION_SYSCALL_ERROR;
        }

        vspaceCapSlot = current_extra_caps.excaprefs[0];
        vspaceCap = vspaceCapSlot->cap;

        if (__builtin_expect(!!(cap_get_capType(vspaceCap) != cap_page_table_cap || cap_page_table_cap_get_capPTIsMapped(vspaceCap)), 0)

                                                                ) {
            ;
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

        if (pool != ((asid_pool_t*)cap_asid_pool_cap_get_capASIDPool(cap))) {
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        /* Find first free ASID */
        asid = cap_asid_pool_cap_get_capASIDBase(cap);
        for (i = 0; i < (1ul << (asidLowBits)) && (asid + i == 0 || pool->array[i]); i++);

        if (i == (1ul << (asidLowBits))) {
            current_syscall_error.type = seL4_DeleteFirst;

            return EXCEPTION_SYSCALL_ERROR;
        }

        asid += i;

        setThreadState(ksCurThread, ThreadState_Restart);
        return performASIDPoolInvocation(asid, pool, vspaceCapSlot);
    }
    default:
        halt();
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
        pte_t *pt = ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(cap)));
        unmapPageTable(
            cap_page_table_cap_get_capPTMappedASID(cap),
            cap_page_table_cap_get_capPTMappedAddress(cap),
            pt
        );
        clearMemory((void *)pt, 12);
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
    setRegister(ksCurThread, msgRegisters[0], capFBasePtr);
    setRegister(ksCurThread, msgInfoRegister,
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
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/machine/fpu.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/machine/hardware.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 31 "/home/koc034/Documents/newver/seL4/src/arch/riscv/machine/hardware.c"
word_t __attribute__((__pure__)) getRestartPC(tcb_t *thread)
{
    return getRegister(thread, FaultIP);
}

void setNextPC(tcb_t *thread, word_t v)
{
    setRegister(thread, NextIP, v);
}

__attribute__((__section__(".boot.text"))) int get_num_avail_p_regs(void)
{
    return sizeof(avail_p_regs) / sizeof(p_region_t);
}

__attribute__((__section__(".boot.text"))) p_region_t *get_avail_p_regs(void)
{
    return (p_region_t *) avail_p_regs;
}

__attribute__((__section__(".boot.text"))) void map_kernel_devices(void)
{
    if (kernel_devices == ((void *)0)) {
        return;
    }

    for (int i = 0; i < (sizeof(kernel_devices) / sizeof(kernel_frame_t)); i++) {
        map_kernel_frame(kernel_devices[i].paddr, kernel_devices[i].pptr,
                         VMKernelOnly);
        if (!kernel_devices[i].userAvailable) {
            p_region_t reg = {
                .start = kernel_devices[i].paddr,
                .end = kernel_devices[i].paddr + (1 << 21),
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
    if (sip & (1ul << (9))) {
        return plic_get_claim();





    } else if (sip & (1ul << (5))) {
        return INTERRUPT_CORE_TIMER;
    }

    return irqInvalid;
}

static uint32_t active_irq[1] = { irqInvalid };


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
    if (!(((active_irq[0])) <= maxIRQ && (active_irq[0])!= irqInvalid)) {
        active_irq[0] = getNewActiveIRQ();
    }

    if ((((active_irq[0])) <= maxIRQ && (active_irq[0])!= irqInvalid)) {
        irq = active_irq[0];
    } else {
        irq = irqInvalid;
    }

    return irq;
}


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
    return (sip & ((1ul << (5)) | (1ul << (9))));
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
    ;
    if (irq == INTERRUPT_CORE_TIMER) {
        if (disable) {
            clear_sie_mask((1ul << (5)));
        } else {
            set_sie_mask((1ul << (5)));
        }




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
    ;
    active_irq[0] = irqInvalid;

    if (irq == INTERRUPT_CORE_TIMER) {
        /* Reprogramming the timer has cleared the interrupt. */
        return;
    }





}
# 256 "/home/koc034/Documents/newver/seL4/src/arch/riscv/machine/hardware.c"
void plat_cleanL2Range(paddr_t start, paddr_t end)
{
}
void plat_invalidateL2Range(paddr_t start, paddr_t end)
{
}

void plat_cleanInvalidateL2Range(paddr_t start, paddr_t end)
{
}

__attribute__((__section__(".boot.text"))) void initL2Cache(void)
{
}

__attribute__((__section__(".boot.text"))) void initLocalIRQController(void)
{
    ((void)(0));


    /* Init per-hart PLIC */
    plic_init_hart();


    word_t sie = 0;
    sie |= (1ul << (9));
    sie |= (1ul << (5));






    set_sie_mask(sie);
}

__attribute__((__section__(".boot.text"))) void initIRQController(void)
{
    ((void)(0));

    plic_init_controller();
}

static inline void handleSpuriousIRQ(void)
{
    /* Do nothing */
    ((void)(0));
}
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/machine/io.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/machine/registerset.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */




const register_t msgRegisters[] = {
    a2, a3, a4, a5
};
typedef int __assert_failed_consistent_message_registers[(sizeof(msgRegisters) / sizeof(msgRegisters[0]) == n_msgRegisters) ? 1 : -1];


 ;

const register_t frameRegisters[] = {
    FaultIP, ra, sp, gp,
    s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11,
};
typedef int __assert_failed_consistent_frame_registers[(sizeof(frameRegisters) / sizeof(frameRegisters[0]) == n_frameRegisters) ? 1 : -1];


 ;

const register_t gpRegisters[] = {
    a0, a1, a2, a3, a4, a5, a6, a7,
    t0, t1, t2, t3, t4, t5, t6,
    tp,
};
typedef int __assert_failed_consistent_gp_registers[(sizeof(gpRegisters) / sizeof(gpRegisters[0]) == n_gpRegisters) ? 1 : -1];


 ;


word_t getNBSendRecvDest(void)
{
    return getRegister(ksCurThread, nbsendRecvDest);
}
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/model/statedata.c"
/*
 * Copyright 2020, DornerWorks
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 17 "/home/koc034/Documents/newver/seL4/src/arch/riscv/model/statedata.c"
/* The top level asid mapping table */
asid_pool_t *riscvKSASIDTable[(1ul << (asidHighBits))];

/* Kernel Page Tables */
pte_t kernel_root_pageTable[(1ul << (9))] __attribute__((__aligned__((1ul << (12))))) __attribute__((__section__(".bss.aligned")));


pte_t kernel_image_level2_pt[(1ul << (9))] __attribute__((__aligned__((1ul << (12))))) __attribute__((__section__(".bss.aligned")));
pte_t kernel_image_level2_dev_pt[(1ul << (9))] __attribute__((__aligned__((1ul << (12))))) __attribute__((__section__(".bss.aligned")));




;
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/object/interrupt.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */






exception_t Arch_checkIRQ(word_t irq)
{
    if (irq > maxIRQ || irq == irqInvalid) {
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 1;
        current_syscall_error.rangeErrorMax = maxIRQ;
        ;
        return EXCEPTION_SYSCALL_ERROR;
    }
    return EXCEPTION_NONE;
}

static exception_t Arch_invokeIRQControl(irq_t irq, cte_t *handlerSlot, cte_t *controlSlot, bool_t trigger)
{

    setIRQTrigger(irq, trigger);

    return invokeIRQControl(irq, handlerSlot, controlSlot);
}

exception_t Arch_decodeIRQControlInvocation(word_t invLabel, word_t length,
                                            cte_t *srcSlot, word_t *buffer)
{
    if (invLabel == RISCVIRQIssueIRQHandlerTrigger) {
        if (length < 4 || current_extra_caps.excaprefs[0] == ((void *)0)) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (!1) {
            ;
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
            ;
            return EXCEPTION_SYSCALL_ERROR;
        }

        lookupSlot_ret_t lu_ret = lookupTargetSlot(cnodeCap, index, depth);
        if (lu_ret.status != EXCEPTION_NONE) {
           
                                                        ;
            return lu_ret.status;
        }

        cte_t *destSlot = lu_ret.slot;

        status = ensureEmptySlot(destSlot);
        if (status != EXCEPTION_NONE) {
           
                                                        ;
            return status;
        }

        setThreadState(ksCurThread, ThreadState_Restart);
        return Arch_invokeIRQControl(irq, destSlot, srcSlot, trigger);
    } else {
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }
}
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/object/objecttype.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 16 "/home/koc034/Documents/newver/seL4/src/arch/riscv/object/objecttype.c"
deriveCap_ret_t Arch_deriveCap(cte_t *slot, cap_t cap)
{
    deriveCap_ret_t ret;

    switch (cap_get_capType(cap)) {

    case cap_page_table_cap:
        if (cap_page_table_cap_get_capPTIsMapped(cap)) {
            ret.cap = cap;
            ret.status = EXCEPTION_NONE;
        } else {
            ;
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
        halt();
    }
}

cap_t __attribute__((__const__)) Arch_updateCapData(bool_t preserve, word_t data, cap_t cap)
{
    return cap;
}

cap_t __attribute__((__const__)) Arch_maskCapRights(seL4_CapRights_t cap_rights_mask, cap_t cap)
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
            pte_t *pte = ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(cap)));
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
                ((asid_pool_t*)cap_asid_pool_cap_get_capASIDPool(cap))
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

bool_t __attribute__((__const__)) Arch_sameRegionAs(cap_t cap_a, cap_t cap_b)
{
    switch (cap_get_capType(cap_a)) {
    case cap_frame_cap:
        if (cap_get_capType(cap_b) == cap_frame_cap) {
            word_t botA, botB, topA, topB;
            botA = cap_frame_cap_get_capFBasePtr(cap_a);
            botB = cap_frame_cap_get_capFBasePtr(cap_b);
            topA = botA + ((1ul << (pageBitsForSize(cap_frame_cap_get_capFSize(cap_a))))-1ul);
            topB = botB + ((1ul << (pageBitsForSize(cap_frame_cap_get_capFSize(cap_b))))-1ul) ;
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


bool_t __attribute__((__const__)) Arch_sameObjectAs(cap_t cap_a, cap_t cap_b)
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
        return 12;
    case seL4_RISCV_Mega_Page:
        return 21;

    case seL4_RISCV_Giga_Page:
        return 30;





    default:
        halt();
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
                   asidInvalid, /* capFMappedASID       */
                   (word_t) regionBase, /* capFBasePtr          */
                   RISCV_4K_Page, /* capFSize             */
                   wordFromVMRights(VMReadWrite), /* capFVMRights         */
                   deviceMemory, /* capFIsDevice         */
                   0 /* capFMappedAddress    */
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
                   asidInvalid, /* capFMappedASID       */
                   (word_t) regionBase, /* capFBasePtr          */
                   RISCV_Mega_Page, /* capFSize             */
                   wordFromVMRights(VMReadWrite), /* capFVMRights         */
                   deviceMemory, /* capFIsDevice         */
                   0 /* capFMappedAddress    */
               );
    }


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
                   asidInvalid, /* capFMappedASID       */
                   (word_t) regionBase, /* capFBasePtr          */
                   RISCV_Giga_Page, /* capFSize             */
                   wordFromVMRights(VMReadWrite), /* capFVMRights         */
                   deviceMemory, /* capFIsDevice         */
                   0 /* capFMappedAddress    */
               );
    }


    case seL4_RISCV_PageTableObject:
        /** AUXUPD: "(True, ptr_retyps 1
              (Ptr (ptr_val \<acute>regionBase) :: (pte_C[512]) ptr))" */
        return cap_page_table_cap_new(
                   asidInvalid, /* capPTMappedASID    */
                   (word_t)regionBase, /* capPTBasePtr       */
                   0, /* capPTIsMapped      */
                   0 /* capPTMappedAddress */
               );

    default:
        /*
         * This is a conflation of the haskell error: "Arch.createNewCaps
         * got an API type" and the case where an invalid object type is
         * passed (which is impossible in haskell).
         */
        halt();
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



}

bool_t Arch_isFrameType(word_t type)
{
    switch (type) {




    case seL4_RISCV_Giga_Page:

    case seL4_RISCV_Mega_Page:
    case seL4_RISCV_4K_Page:
        return true;
    default:
        return false;
    }
}
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/object/tcb.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2015, 2016 Hesham Almatary <heshamelmatary@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 15 "/home/koc034/Documents/newver/seL4/src/arch/riscv/object/tcb.c"
word_t __attribute__((__const__)) Arch_decodeTransfer(word_t flags)
{
    return 0;
}

exception_t __attribute__((__const__)) Arch_performTransfer(word_t arch, tcb_t *tcb_src, tcb_t *tcb_dest)
{
    return EXCEPTION_NONE;
}
# 1 "/home/koc034/Documents/newver/seL4/src/arch/riscv/smp/ipi.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */


# 1 "/home/koc034/Documents/newver/seL4/include/arch/riscv/arch/64/mode/smp/ipi.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       
# 9 "/home/koc034/Documents/newver/seL4/src/arch/riscv/smp/ipi.c" 2
# 1 "/home/koc034/Documents/newver/seL4/src/assert.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 1 "/home/koc034/Documents/newver/seL4/src/benchmark/benchmark_track.c"
/*
 * Copyright 2016, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 1 "/home/koc034/Documents/newver/seL4/src/benchmark/benchmark_utilisation.c"
/*
 * Copyright 2016, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 1 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */


# 1 "/home/koc034/Documents/newver/seL4/include/fastpath/fastpath.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       

/* Fastpath cap lookup.  Returns a null_cap on failure. */
static inline cap_t __attribute__((always_inline)) lookup_fp(cap_t cap, cptr_t cptr)
{
    word_t cptr2;
    cte_t *slot;
    word_t guardBits, radixBits, bits;
    word_t radix, capGuard;

    bits = 0;

    if (__builtin_expect(!!(! cap_capType_equals(cap, cap_cnode_cap)), 0)) {
        return cap_null_cap_new();
    }

    do {
        guardBits = cap_cnode_cap_get_capCNodeGuardSize(cap);
        radixBits = cap_cnode_cap_get_capCNodeRadix(cap);
        cptr2 = cptr << bits;

        capGuard = cap_cnode_cap_get_capCNodeGuard(cap);

        /* Check the guard. Depth mismatch check is deferred.
           The 32MinusGuardSize encoding contains an exception
           when the guard is 0, when 32MinusGuardSize will be
           reported as 0 also. In this case we skip the check */
        if (__builtin_expect(!!(guardBits), 1) && __builtin_expect(!!(cptr2 >> ((1ul << (6)) - guardBits) != capGuard), 0)) {
            return cap_null_cap_new();
        }

        radix = cptr2 << guardBits >> ((1ul << (6)) - radixBits);
        slot = ((cte_t *)(cap_cnode_cap_get_capCNodePtr(cap))) + radix;

        cap = slot->cap;
        bits += guardBits + radixBits;

    } while (__builtin_expect(!!(bits < (1ul << (6)) && cap_capType_equals(cap, cap_cnode_cap)), 0));

    if (__builtin_expect(!!(bits > (1ul << (6))), 0)) {
        /* Depth mismatch. We've overshot wordBits bits. The lookup we've done is
           safe, but wouldn't be allowed by the slowpath. */
        return cap_null_cap_new();
    }

    return cap;
}
/* make sure the fastpath functions conform with structure_*.bf */
static inline void thread_state_ptr_set_tsType_np(thread_state_t *ts_ptr, word_t tsType)
{
    ts_ptr->words[0] = tsType;
}

static inline void thread_state_ptr_mset_blockingObject_tsType(thread_state_t *ts_ptr,
                                                               word_t ep_ref,
                                                               word_t tsType)
{
    ts_ptr->words[0] = ep_ref | tsType;
}
# 82 "/home/koc034/Documents/newver/seL4/include/fastpath/fastpath.h"
static inline void endpoint_ptr_mset_epQueue_tail_state(endpoint_t *ep_ptr, word_t epQueue_tail,
                                                        word_t state)
{
    ep_ptr->words[0] = epQueue_tail | state;
}

static inline void endpoint_ptr_set_epQueue_head_np(endpoint_t *ep_ptr, word_t epQueue_head)
{
    ep_ptr->words[1] = epQueue_head;
}


static inline void thread_state_ptr_set_replyObject_np(thread_state_t *ts_ptr, word_t reply)
{
    ;
    ;

    thread_state_ptr_set_replyObject(ts_ptr, ((word_t) (reply)));



}

static inline reply_t *thread_state_get_replyObject_np(thread_state_t ts)
{
    ;
    ;

    return ((reply_t *) (thread_state_get_replyObject(ts)));



}
# 9 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c" 2

# 1 "/home/koc034/Documents/newver/seL4/include/object/reply.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       





/* Unlink a reply from its tcb */
static inline void reply_unlink(reply_t *reply, tcb_t *tcb)
{
    /* check the tcb and reply are linked correctly */
    ;
    ;

    thread_state_ptr_set_replyObject(&tcb->tcbState, ((word_t) (0)));
    reply->replyTCB = ((void *)0);
    setThreadState(tcb, ThreadState_Inactive);
}

/* Push a reply object onto the call stack */
void reply_push(tcb_t *tcb_caller, tcb_t *tcb_callee, reply_t *reply, bool_t canDonate);
/* Pop the head reply from the call stack */
void reply_pop(reply_t *reply, tcb_t *tcb);
/* Remove a reply from the call stack - replyTCB must be in ThreadState_BlockedOnReply */
void reply_remove(reply_t *reply, tcb_t *tcb);
/* Remove a specific tcb, and the reply it is blocking on, from the call stack */
void reply_remove_tcb(tcb_t *tcb);
# 11 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c" 2
# 24 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
void __attribute__((__noreturn__)) fastpath_call(word_t cptr, word_t msgInfo)
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
    fault_type = seL4_Fault_get_seL4_FaultType(ksCurThread->tcbFault);

    /* Check there's no extra caps, the length is ok and there's no
     * saved fault. */
    if (__builtin_expect(!!(fastpath_mi_check(msgInfo) || fault_type != seL4_Fault_NullFault), 0)
                                                    ) {
        slowpath(SysCall);
    }

    /* Lookup the cap */
    ep_cap = lookup_fp((((cte_t *)((word_t)(ksCurThread)&~((1ul << (10))-1ul)))+(tcbCTable))->cap, cptr);

    /* Check it's an endpoint */
    if (__builtin_expect(!!(!cap_capType_equals(ep_cap, cap_endpoint_cap) || !cap_endpoint_cap_get_capCanSend(ep_cap)), 0)
                                                          ) {
        slowpath(SysCall);
    }

    /* Get the endpoint address */
    ep_ptr = ((endpoint_t *)(cap_endpoint_cap_get_capEPPtr(ep_cap)));

    /* Get the destination thread, which is only going to be valid
     * if the endpoint is valid. */
    dest = ((tcb_t *)(endpoint_ptr_get_epQueue_head(ep_ptr)));

    /* Check that there's a thread waiting to receive */
    if (__builtin_expect(!!(endpoint_ptr_get_state(ep_ptr) != EPState_Recv), 0)) {
        slowpath(SysCall);
    }

    /* ensure we are not single stepping the destination in ia32 */






    /* Get destination thread.*/
    newVTable = (((cte_t *)((word_t)(dest)&~((1ul << (10))-1ul)))+(tcbVTable))->cap;

    /* Get vspace root. */
    cap_pd = ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(newVTable)));

    /* Ensure that the destination has a valid VTable. */
    if (__builtin_expect(!!(! isValidVTableRoot_fp(newVTable)), 0)) {
        slowpath(SysCall);
    }
# 108 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
    /* Get HW ASID */
    stored_hw_asid.words[0] = cap_page_table_cap_get_capPTMappedASID(newVTable);


    /* let gcc optimise this out for 1 domain */
    dom = maxDom ? ksCurDomain : 0;
    /* ensure only the idle thread or lower prio threads are present in the scheduler */
    if (__builtin_expect(!!(dest->tcbPriority < ksCurThread->tcbPriority && !isHighestPrio(dom, dest->tcbPriority)), 0)
                                                        ) {
        slowpath(SysCall);
    }

    /* Ensure that the endpoint has has grant or grant-reply rights so that we can
     * create the reply cap */
    if (__builtin_expect(!!(!cap_endpoint_cap_get_capCanGrant(ep_cap) && !cap_endpoint_cap_get_capCanGrantReply(ep_cap)), 0)
                                                                ) {
        slowpath(SysCall);
    }







    /* Ensure the original caller is in the current domain and can be scheduled directly. */
    if (__builtin_expect(!!(dest->tcbDomain != ksCurDomain && maxDom), 0)) {
        slowpath(SysCall);
    }


    if (__builtin_expect(!!(dest->tcbSchedContext != ((void *)0)), 0)) {
        slowpath(SysCall);
    }

    reply_t *reply = thread_state_get_replyObject_np(dest->tcbState);
    if (__builtin_expect(!!(reply == ((void *)0)), 0)) {
        slowpath(SysCall);
    }
# 156 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
    /*
     * --- POINT OF NO RETURN ---
     *
     * At this stage, we have committed to performing the IPC.
     */





    /* Dequeue the destination. */
    endpoint_ptr_set_epQueue_head_np(ep_ptr, ((word_t)(dest->tcbEPNext)));
    if (__builtin_expect(!!(dest->tcbEPNext), 0)) {
        dest->tcbEPNext->tcbEPPrev = ((void *)0);
    } else {
        endpoint_ptr_mset_epQueue_tail_state(ep_ptr, 0, EPState_Idle);
    }

    badge = cap_endpoint_cap_get_capEPBadge(ep_cap);

    /* Unlink dest <-> reply, link src (cur thread) <-> reply */
    thread_state_ptr_set_tsType_np(&ksCurThread->tcbState,
                                   ThreadState_BlockedOnReply);

    thread_state_ptr_set_replyObject_np(&dest->tcbState, 0);
    thread_state_ptr_set_replyObject_np(&ksCurThread->tcbState, ((word_t) (reply)));
    reply->replyTCB = ksCurThread;

    sched_context_t *sc = ksCurThread->tcbSchedContext;
    sc->scTcb = dest;
    dest->tcbSchedContext = sc;
    ksCurThread->tcbSchedContext = ((void *)0);

    reply_t *old_caller = sc->scReply;
    reply->replyPrev = call_stack_new(((word_t) (sc->scReply)), false);
    if (__builtin_expect(!!(old_caller), 0)) {
        old_caller->replyNext = call_stack_new(((word_t) (reply)), false);
    }
    reply->replyNext = call_stack_new(((word_t) (sc)), true);
    sc->scReply = reply;
# 212 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
    fastpath_copy_mrs(length, ksCurThread, dest);

    /* Dest thread is set Running, but not queued. */
    thread_state_ptr_set_tsType_np(&dest->tcbState,
                                   ThreadState_Running);
    switchToThread_fp(dest, cap_pd, stored_hw_asid);

    msgInfo = wordFromMessageInfo(seL4_MessageInfo_set_capsUnwrapped(info, 0));

    fastpath_restore(badge, msgInfo, ksCurThread);
}
# 231 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
void __attribute__((__noreturn__)) fastpath_reply_recv(word_t cptr, word_t msgInfo, word_t reply)



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
    fault_type = seL4_Fault_get_seL4_FaultType(ksCurThread->tcbFault);

    /* Check there's no extra caps, the length is ok and there's no
     * saved fault. */
    if (__builtin_expect(!!(fastpath_mi_check(msgInfo) || fault_type != seL4_Fault_NullFault), 0)
                                                    ) {
        slowpath(SysReplyRecv);
    }

    /* Lookup the cap */
    ep_cap = lookup_fp((((cte_t *)((word_t)(ksCurThread)&~((1ul << (10))-1ul)))+(tcbCTable))->cap,
                       cptr);

    /* Check it's an endpoint */
    if (__builtin_expect(!!(!cap_capType_equals(ep_cap, cap_endpoint_cap) || !cap_endpoint_cap_get_capCanReceive(ep_cap)), 0)
                                                             ) {
        slowpath(SysReplyRecv);
    }


    /* lookup the reply object */
    cap_t reply_cap = lookup_fp((((cte_t *)((word_t)(ksCurThread)&~((1ul << (10))-1ul)))+(tcbCTable))->cap, reply);

    /* check it's a reply object */
    if (__builtin_expect(!!(!cap_capType_equals(reply_cap, cap_reply_cap)), 0)) {
        slowpath(SysReplyRecv);
    }


    /* Check there is nothing waiting on the notification */
    if (__builtin_expect(!!(ksCurThread->tcbBoundNotification && notification_ptr_get_state(ksCurThread->tcbBoundNotification) == NtfnState_Active), 0)
                                                                                                               ) {
        slowpath(SysReplyRecv);
    }

    /* Get the endpoint address */
    ep_ptr = ((endpoint_t *)(cap_endpoint_cap_get_capEPPtr(ep_cap)));

    /* Check that there's not a thread waiting to send */
    if (__builtin_expect(!!(endpoint_ptr_get_state(ep_ptr) == EPState_Send), 0)) {
        slowpath(SysReplyRecv);
    }


    /* Get the reply address */
    reply_t *reply_ptr = ((reply_t *) (cap_reply_cap_get_capReplyPtr(reply_cap)));
    /* check that its valid and at the head of the call chain
       and that the current thread's SC is going to be donated. */
    if (__builtin_expect(!!(reply_ptr->replyTCB == ((void *)0) || call_stack_get_isHead(reply_ptr->replyNext) == 0 || ((sched_context_t *) (call_stack_get_callStackPtr(reply_ptr->replyNext))) != ksCurThread->tcbSchedContext), 0)

                                                                                                                       ) {
        slowpath(SysReplyRecv);
    }

    /* Determine who the caller is. */
    caller = reply_ptr->replyTCB;
# 321 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
    /* ensure we are not single stepping the caller in ia32 */






    /* Check that the caller has not faulted, in which case a fault
       reply is generated instead. */
    fault_type = seL4_Fault_get_seL4_FaultType(caller->tcbFault);
    if (__builtin_expect(!!(fault_type != seL4_Fault_NullFault), 0)) {
        slowpath(SysReplyRecv);
    }

    /* Get destination thread.*/
    newVTable = (((cte_t *)((word_t)(caller)&~((1ul << (10))-1ul)))+(tcbVTable))->cap;

    /* Get vspace root. */
    cap_pd = ((pte_t *)(cap_page_table_cap_get_capPTBasePtr(newVTable)));

    /* Ensure that the destination has a valid MMU. */
    if (__builtin_expect(!!(! isValidVTableRoot_fp(newVTable)), 0)) {
        slowpath(SysReplyRecv);
    }
# 363 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
    stored_hw_asid.words[0] = cap_page_table_cap_get_capPTMappedASID(newVTable);


    /* Ensure the original caller can be scheduled directly. */
    dom = maxDom ? ksCurDomain : 0;
    if (__builtin_expect(!!(!isHighestPrio(dom, caller->tcbPriority)), 0)) {
        slowpath(SysReplyRecv);
    }
# 379 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
    /* Ensure the original caller is in the current domain and can be scheduled directly. */
    if (__builtin_expect(!!(caller->tcbDomain != ksCurDomain && maxDom), 0)) {
        slowpath(SysReplyRecv);
    }


    if (__builtin_expect(!!(caller->tcbSchedContext != ((void *)0)), 0)) {
        slowpath(SysReplyRecv);
    }
# 398 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
    /* not possible to set reply object and not be blocked */
    ;


    /*
     * --- POINT OF NO RETURN ---
     *
     * At this stage, we have committed to performing the IPC.
     */





    /* Set thread state to BlockedOnReceive */
    thread_state_ptr_mset_blockingObject_tsType(
        &ksCurThread->tcbState, (word_t)ep_ptr, ThreadState_BlockedOnReceive);

    /* unlink reply object from caller */
    thread_state_ptr_set_replyObject_np(&caller->tcbState, 0);
    /* set the reply object */
    thread_state_ptr_set_replyObject_np(&ksCurThread->tcbState, ((word_t) (reply_ptr)));
    reply_ptr->replyTCB = ksCurThread;





    /* Place the thread in the endpoint queue */
    endpointTail = ((tcb_t *)(endpoint_ptr_get_epQueue_tail(ep_ptr)));
    if (__builtin_expect(!!(!endpointTail), 1)) {
        ksCurThread->tcbEPPrev = ((void *)0);
        ksCurThread->tcbEPNext = ((void *)0);

        /* Set head/tail of queue and endpoint state. */
        endpoint_ptr_set_epQueue_head_np(ep_ptr, ((word_t)(ksCurThread)));
        endpoint_ptr_mset_epQueue_tail_state(ep_ptr, ((word_t)(ksCurThread)),
                                             EPState_Recv);
    } else {

        /* Update queue. */
        tcb_queue_t queue = tcbEPAppend(ksCurThread, ep_ptr_get_queue(ep_ptr));
        endpoint_ptr_set_epQueue_head_np(ep_ptr, ((word_t)(queue.head)));
        endpoint_ptr_mset_epQueue_tail_state(ep_ptr, ((word_t)(queue.end)), EPState_Recv);
# 452 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
    }


    /* update call stack */
    word_t prev_ptr = call_stack_get_callStackPtr(reply_ptr->replyPrev);
    sched_context_t *sc = ksCurThread->tcbSchedContext;
    ksCurThread->tcbSchedContext = ((void *)0);
    caller->tcbSchedContext = sc;
    sc->scTcb = caller;

    sc->scReply = ((reply_t *) (prev_ptr));
    if (__builtin_expect(!!(((reply_t *) (prev_ptr)) != ((void *)0)), 0)) {
        sc->scReply->replyNext = reply_ptr->replyNext;
    }

    /* TODO neccessary? */
    reply_ptr->replyPrev.words[0] = 0;
    reply_ptr->replyNext.words[0] = 0;
# 479 "/home/koc034/Documents/newver/seL4/src/fastpath/fastpath.c"
    /* I know there's no fault, so straight to the transfer. */

    /* Replies don't have a badge. */
    badge = 0;

    fastpath_copy_mrs(length, ksCurThread, caller);

    /* Dest thread is set Running, but not queued. */
    thread_state_ptr_set_tsType_np(&caller->tcbState,
                                   ThreadState_Running);
    switchToThread_fp(caller, cap_pd, stored_hw_asid);

    msgInfo = wordFromMessageInfo(seL4_MessageInfo_set_capsUnwrapped(info, 0));

    fastpath_restore(badge, msgInfo, ksCurThread);
}
# 1 "/home/koc034/Documents/newver/seL4/src/inlines.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */




lookup_fault_t current_lookup_fault;
seL4_Fault_t current_fault;
syscall_error_t current_syscall_error;
# 1 "/home/koc034/Documents/newver/seL4/src/kernel/boot.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 20 "/home/koc034/Documents/newver/seL4/src/kernel/boot.c"
/* (node-local) state accessed only during bootstrapping */
ndks_boot_t ndks_boot __attribute__((__section__(".boot.bss")));

rootserver_mem_t rootserver __attribute__((__section__(".boot.bss")));
static region_t rootserver_mem __attribute__((__section__(".boot.bss")));

__attribute__((__section__(".boot.text"))) static void merge_regions(void)
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

__attribute__((__section__(".boot.text"))) bool_t reserve_region(p_region_t reg)
{
    word_t i;
    ;
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
            if (ndks_boot.resv_count + 1 >= (16 + (sizeof(kernel_devices) / sizeof(kernel_devices[0])) + 0 + 3)) {
                ((void)(0))
                                                                 ;
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

    if (i + 1 == (16 + (sizeof(kernel_devices) / sizeof(kernel_devices[0])) + 0 + 3)) {
        ((void)(0))
                                                         ;
        return false;
    }

    ndks_boot.reserved[i] = reg;
    ndks_boot.resv_count++;

    return true;
}

__attribute__((__section__(".boot.text"))) bool_t insert_region(region_t reg)
{
    word_t i;

    ;
    if (is_reg_empty(reg)) {
        return true;
    }
    for (i = 0; i < 16; i++) {
        if (is_reg_empty(ndks_boot.freemem[i])) {
            reserve_region(pptr_to_paddr_reg(reg));
            ndks_boot.freemem[i] = reg;
            return true;
        }
    }
# 122 "/home/koc034/Documents/newver/seL4/src/kernel/boot.c"
    ((void)(0))
                                                        ;

    return false;
}

__attribute__((__section__(".boot.text"))) static pptr_t alloc_rootserver_obj(word_t size_bits, word_t n)
{
    pptr_t allocated = rootserver_mem.start;
    /* allocated memory must be aligned */
    ;
    rootserver_mem.start += (n * (1ul << (size_bits)));
    /* we must not have run out of memory */
    ;
    memzero((void *) allocated, n * (1ul << (size_bits)));
    return allocated;
}

__attribute__((__section__(".boot.text"))) static word_t rootserver_max_size_bits(word_t extra_bi_size_bits)
{
    word_t cnode_size_bits = 19 + 5;
    word_t max = (((cnode_size_bits)>(12))?(cnode_size_bits):(12));
    return (((max)>(extra_bi_size_bits))?(max):(extra_bi_size_bits));
}

__attribute__((__section__(".boot.text"))) static word_t calculate_rootserver_size(v_region_t v_reg, word_t extra_bi_size_bits)
{
    /* work out how much memory we need for root server objects */
    word_t size = (1ul << (19 + 5));
    size += (1ul << (10)); // root thread tcb
    size += 2 * (1ul << (12)); // boot info + ipc buf
    size += (1ul << (12));
    size += extra_bi_size_bits > 0 ? (1ul << (extra_bi_size_bits)) : 0;
    size += (1ul << (12)); // root vspace

    size += (1ul << (8)); // root sched context

    /* for all archs, seL4_PageTable Bits is the size of all non top-level paging structures */
    return size + arch_get_n_paging(v_reg) * (1ul << (12));
}

__attribute__((__section__(".boot.text"))) static void maybe_alloc_extra_bi(word_t cmp_size_bits, word_t extra_bi_size_bits)
{
    if (extra_bi_size_bits >= cmp_size_bits && rootserver.extra_bi == 0) {
        rootserver.extra_bi = alloc_rootserver_obj(extra_bi_size_bits, 1);
    }
}

__attribute__((__section__(".boot.text"))) void create_rootserver_objects(pptr_t start, v_region_t v_reg, word_t extra_bi_size_bits)
{
    /* the largest object the PD, the root cnode, or the extra boot info */
    word_t cnode_size_bits = 19 + 5;
    word_t max = rootserver_max_size_bits(extra_bi_size_bits);

    word_t size = calculate_rootserver_size(v_reg, extra_bi_size_bits);
    rootserver_mem.start = start;
    rootserver_mem.end = start + size;

    maybe_alloc_extra_bi(max, extra_bi_size_bits);

    /* the root cnode is at least 4k, so it could be larger or smaller than a pd. */

    rootserver.cnode = alloc_rootserver_obj(cnode_size_bits, 1);
    maybe_alloc_extra_bi(12, extra_bi_size_bits);
    rootserver.vspace = alloc_rootserver_obj(12, 1);






    /* at this point we are up to creating 4k objects - which is the min size of
     * extra_bi so this is the last chance to allocate it */
    maybe_alloc_extra_bi(12, extra_bi_size_bits);
    rootserver.asid_pool = alloc_rootserver_obj(12, 1);
    rootserver.ipc_buf = alloc_rootserver_obj(12, 1);
    rootserver.boot_info = alloc_rootserver_obj(12, 1);

    /* TCBs on aarch32 can be larger than page tables in certain configs */




    /* paging structures are 4k on every arch except aarch32 (1k) */
    word_t n = arch_get_n_paging(v_reg);
    rootserver.paging.start = alloc_rootserver_obj(12, n);
    rootserver.paging.end = rootserver.paging.start + n * (1ul << (12));

    /* for most archs, TCBs are smaller than page tables */

    rootserver.tcb = alloc_rootserver_obj(10, 1);



    rootserver.sc = alloc_rootserver_obj(8, 1);

    /* we should have allocated all our memory */
    ;
}

__attribute__((__section__(".boot.text"))) void write_slot(slot_ptr_t slot_ptr, cap_t cap)
{
    slot_ptr->cap = cap;

    slot_ptr->cteMDBNode = mdb_node_new(0, false, false, 0);
    mdb_node_ptr_set_mdbRevocable(&slot_ptr->cteMDBNode, true);
    mdb_node_ptr_set_mdbFirstBadged(&slot_ptr->cteMDBNode, true);
}

/* Our root CNode needs to be able to fit all the initial caps and not
 * cover all of memory.
 */
typedef int __assert_failed_root_cnode_size_valid[(19 < 32 - 5 && (1ul << (19)) >= seL4_NumInitialCaps && (1ul << (19)) >= (12 - 5)) ? 1 : -1];




__attribute__((__section__(".boot.text"))) cap_t
create_root_cnode(void)
{
    /* write the number of root CNode slots to global state */
    ndks_boot.slot_pos_max = (1ul << (19));

    cap_t cap =
        cap_cnode_cap_new(
            19, /* radix      */
            (1ul << (6)) - 19, /* guard size */
            0, /* guard      */
            rootserver.cnode /* pptr       */
        );

    /* write the root CNode cap into the root CNode */
    write_slot((((slot_ptr_t)(rootserver.cnode)) + (seL4_CapInitThreadCNode)), cap);

    return cap;
}

/* Check domain scheduler assumptions. */
typedef int __assert_failed_num_domains_valid[(16 >= 1 && 16 <= 256) ? 1 : -1];

typedef int __assert_failed_num_priorities_valid[(256 >= 1 && 256 <= 256) ? 1 : -1];


__attribute__((__section__(".boot.text"))) void
create_domain_cap(cap_t root_cnode_cap)
{
    /* Check domain scheduler assumptions. */
    ;
    for (word_t i = 0; i < ksDomScheduleLength; i++) {
        ;
        ;
    }

    cap_t cap = cap_domain_cap_new();
    write_slot((((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapDomain)), cap);
}


__attribute__((__section__(".boot.text"))) cap_t create_ipcbuf_frame_cap(cap_t root_cnode_cap, cap_t pd_cap, vptr_t vptr)
{
    clearMemory((void *)rootserver.ipc_buf, 12);

    /* create a cap of it and write it into the root CNode */
    cap_t cap = create_mapped_it_frame_cap(pd_cap, rootserver.ipc_buf, vptr, 1, false, false);
    write_slot((((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapInitThreadIPCBuffer)), cap);

    return cap;
}

__attribute__((__section__(".boot.text"))) void create_bi_frame_cap(cap_t root_cnode_cap, cap_t pd_cap, vptr_t vptr)
{
    /* create a cap of it and write it into the root CNode */
    cap_t cap = create_mapped_it_frame_cap(pd_cap, rootserver.boot_info, vptr, 1, false, false);
    write_slot((((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapBootInfoFrame)), cap);
}

__attribute__((__section__(".boot.text"))) word_t calculate_extra_bi_size_bits(word_t extra_size)
{
    if (extra_size == 0) {
        return 0;
    }

    word_t clzl_ret = clzl((((((extra_size) - 1ul) >> (12)) + 1ul) << (12)));
    word_t msb = 64 - 1 - clzl_ret;
    /* If region is bigger than a page, make sure we overallocate rather than underallocate */
    if (extra_size > (1ul << (msb))) {
        msb++;
    }
    return msb;
}

__attribute__((__section__(".boot.text"))) void populate_bi_frame(node_id_t node_id, word_t num_nodes, vptr_t ipcbuf_vptr,
                                 word_t extra_bi_size)
{
    clearMemory((void *) rootserver.boot_info, 12);
    if (extra_bi_size) {
        clearMemory((void *) rootserver.extra_bi, calculate_extra_bi_size_bits(extra_bi_size));
    }

    /* initialise bootinfo-related global state */
    ndks_boot.bi_frame = ((seL4_BootInfo*)(rootserver.boot_info));
    ndks_boot.slot_pos_cur = seL4_NumInitialCaps;
    ((seL4_BootInfo*)(rootserver.boot_info))->nodeID = node_id;
    ((seL4_BootInfo*)(rootserver.boot_info))->numNodes = num_nodes;
    ((seL4_BootInfo*)(rootserver.boot_info))->numIOPTLevels = 0;
    ((seL4_BootInfo*)(rootserver.boot_info))->ipcBuffer = (seL4_IPCBuffer *) ipcbuf_vptr;
    ((seL4_BootInfo*)(rootserver.boot_info))->initThreadCNodeSizeBits = 19;
    ((seL4_BootInfo*)(rootserver.boot_info))->initThreadDomain = ksDomSchedule[ksDomScheduleIdx].domain;
    ((seL4_BootInfo*)(rootserver.boot_info))->extraLen = extra_bi_size;
}

__attribute__((__section__(".boot.text"))) bool_t provide_cap(cap_t root_cnode_cap, cap_t cap)
{
    if (ndks_boot.slot_pos_cur >= ndks_boot.slot_pos_max) {
        ((void)(0));
        return false;
    }
    write_slot((((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (ndks_boot.slot_pos_cur)), cap);
    ndks_boot.slot_pos_cur++;
    return true;
}

__attribute__((__section__(".boot.text"))) create_frames_of_region_ret_t create_frames_of_region(
    cap_t root_cnode_cap,
    cap_t pd_cap,
    region_t reg,
    bool_t do_map,
    sword_t pv_offset
)
{
    pptr_t f;
    cap_t frame_cap;
    seL4_SlotPos slot_pos_before;
    seL4_SlotPos slot_pos_after;

    slot_pos_before = ndks_boot.slot_pos_cur;

    for (f = reg.start; f < reg.end; f += (1ul << (12))) {
        if (do_map) {
            frame_cap = create_mapped_it_frame_cap(pd_cap, f, addrFromPPtr((void *)(f - pv_offset)), 1, false, true);
        } else {
            frame_cap = create_unmapped_it_frame_cap(f, false);
        }
        if (!provide_cap(root_cnode_cap, frame_cap))
            return (create_frames_of_region_ret_t) {
            (seL4_SlotRegion){ .start = 0, .end = 0 }, false
        };
    }

    slot_pos_after = ndks_boot.slot_pos_cur;

    return (create_frames_of_region_ret_t) {
        (seL4_SlotRegion) { slot_pos_before, slot_pos_after }, true
    };
}

__attribute__((__section__(".boot.text"))) cap_t create_it_asid_pool(cap_t root_cnode_cap)
{
    cap_t ap_cap = cap_asid_pool_cap_new(1 >> asidLowBits, rootserver.asid_pool);
    write_slot((((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapInitThreadASIDPool)), ap_cap);

    /* create ASID control cap */
    write_slot(
        (((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapASIDControl)),
        cap_asid_control_cap_new()
    );

    return ap_cap;
}


__attribute__((__section__(".boot.text"))) static bool_t configure_sched_context(tcb_t *tcb, sched_context_t *sc_pptr, ticks_t timeslice, word_t core)
{
    tcb->tcbSchedContext = sc_pptr;
    refill_new(tcb->tcbSchedContext, 2u, timeslice, 0);

    tcb->tcbSchedContext->scTcb = tcb;
    return true;
}

__attribute__((__section__(".boot.text"))) bool_t init_sched_control(cap_t root_cnode_cap, word_t num_nodes)
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


__attribute__((__section__(".boot.text"))) bool_t create_idle_thread(void)
{
    pptr_t pptr;




        pptr = (pptr_t) &ksIdleThreadTCB[0];
        ksIdleThread = ((tcb_t *)(pptr + (1ul << ((10 - 1)))));
        configureIdleThread(ksIdleThread);



        ;

        bool_t result = configure_sched_context(ksIdleThread, ((sched_context_t *) (&ksIdleThreadSC[0])),
                                                usToTicks(5 * 1000llu), 0);
       
        if (!result) {
            ((void)(0));
            return false;
        }




    return true;
}

__attribute__((__section__(".boot.text"))) tcb_t *create_initial_thread(cap_t root_cnode_cap, cap_t it_pd_cap, vptr_t ui_v_entry, vptr_t bi_frame_vptr,
                                       vptr_t ipcbuf_vptr, cap_t ipcbuf_cap)
{
    tcb_t *tcb = ((tcb_t *)(rootserver.tcb + (1ul << ((10 - 1)))));




    Arch_initContext(&tcb->tcbArch.tcbContext);

    /* derive a copy of the IPC buffer cap for inserting */
    deriveCap_ret_t dc_ret = deriveCap((((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapInitThreadIPCBuffer)), ipcbuf_cap);
    if (dc_ret.status != EXCEPTION_NONE) {
        ((void)(0));
        return ((void *)0);
    }

    /* initialise TCB (corresponds directly to abstract specification) */
    cteInsert(
        root_cnode_cap,
        (((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapInitThreadCNode)),
        (((slot_ptr_t)(rootserver.tcb)) + (tcbCTable))
    );
    cteInsert(
        it_pd_cap,
        (((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapInitThreadVSpace)),
        (((slot_ptr_t)(rootserver.tcb)) + (tcbVTable))
    );
    cteInsert(
        dc_ret.cap,
        (((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapInitThreadIPCBuffer)),
        (((slot_ptr_t)(rootserver.tcb)) + (tcbBuffer))
    );
    tcb->tcbIPCBuffer = ipcbuf_vptr;

    setRegister(tcb, capRegister, bi_frame_vptr);
    setNextPC(tcb, ui_v_entry);

    /* initialise TCB */

    if (!configure_sched_context(tcb, ((sched_context_t *) (rootserver.sc)), usToTicks(5 * 1000llu), 0)) {
        return ((void *)0);
    }


    tcb->tcbPriority = seL4_MaxPrio;
    tcb->tcbMCP = seL4_MaxPrio;
    tcb->tcbDomain = ksDomSchedule[ksDomScheduleIdx].domain;



    setThreadState(tcb, ThreadState_Running);

    ksCurDomain = ksDomSchedule[ksDomScheduleIdx].domain;

    ksDomainTime = usToTicks(ksDomSchedule[ksDomScheduleIdx].length * 1000llu);



    ;





    /* create initial thread's TCB cap */
    cap_t cap = cap_thread_cap_new(((word_t)(tcb)));
    write_slot((((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapInitThreadTCB)), cap);


    cap = cap_sched_context_cap_new(((word_t) (tcb->tcbSchedContext)), 8);
    write_slot((((slot_ptr_t)((pptr_t)cap_get_capPtr(root_cnode_cap))) + (seL4_CapInitThreadSC)), cap);





    return tcb;
}

__attribute__((__section__(".boot.text"))) void init_core_state(tcb_t *scheduler_action)
{
# 548 "/home/koc034/Documents/newver/seL4/src/kernel/boot.c"
    ksSchedulerAction = scheduler_action;
    ksCurThread = ksIdleThread;

    ksCurSC = ksCurThread->tcbSchedContext;
    ksConsumed = 0;
    ksReprogram = true;
    ksReleaseHead = ((void *)0);
    ksCurTime = getCurrentTime();

}

__attribute__((__section__(".boot.text"))) static bool_t provide_untyped_cap(
    cap_t root_cnode_cap,
    bool_t device_memory,
    pptr_t pptr,
    word_t size_bits,
    seL4_SlotPos first_untyped_slot
)
{
    bool_t ret;
    cap_t ut_cap;
    word_t i = ndks_boot.slot_pos_cur - first_untyped_slot;
    if (i < 50) {
        ndks_boot.bi_frame->untypedList[i] = (seL4_UntypedDesc) {
            addrFromPPtr((void *)pptr), size_bits, device_memory, {0}
        };
        ut_cap = cap_untyped_cap_new(((1ul << ((size_bits) - 4))),
                                     device_memory, size_bits, pptr);
        ret = provide_cap(root_cnode_cap, ut_cap);
    } else {
        ((void)(0));
        ret = true;
    }
    return ret;
}

__attribute__((__section__(".boot.text"))) bool_t create_untypeds_for_region(
    cap_t root_cnode_cap,
    bool_t device_memory,
    region_t reg,
    seL4_SlotPos first_untyped_slot
)
{
    word_t align_bits;
    word_t size_bits;

    while (!is_reg_empty(reg)) {
        /* Determine the maximum size of the region */
        size_bits = 64 - 1 - clzl(reg.end - reg.start);

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
        if (size_bits > 38) {
            size_bits = 38;
        }

        if (size_bits >= 4) {
            if (!provide_untyped_cap(root_cnode_cap, device_memory, reg.start, size_bits, first_untyped_slot)) {
                return false;
            }
        }
        reg.start += (1ul << (size_bits));
    }
    return true;
}

__attribute__((__section__(".boot.text"))) bool_t create_device_untypeds(cap_t root_cnode_cap, seL4_SlotPos slot_pos_before)
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

    if (start < 549755813887) {
        region_t reg = paddr_to_pptr_reg((p_region_t) {
            start, 549755813887
        });
        /*
         * The auto-generated bitfield code will get upset if the
         * end pptr is larger than the maximum pointer size for this architecture.
         */
        if (reg.end > 0xFFFFFFFF80000000ul) {
            reg.end = 0xFFFFFFFF80000000ul;
        }
        if (!create_untypeds_for_region(root_cnode_cap, true, reg, slot_pos_before)) {
            return false;
        }
    }
    return true;
}

__attribute__((__section__(".boot.text"))) bool_t create_kernel_untypeds(cap_t root_cnode_cap, region_t boot_mem_reuse_reg,
                                        seL4_SlotPos first_untyped_slot)
{
    word_t i;
    region_t reg;

    /* if boot_mem_reuse_reg is not empty, we can create UT objs from boot code/data frames */
    if (!create_untypeds_for_region(root_cnode_cap, false, boot_mem_reuse_reg, first_untyped_slot)) {
        return false;
    }

    /* convert remaining freemem into UT objects and provide the caps */
    for (i = 0; i < 16; i++) {
        reg = ndks_boot.freemem[i];
        ndks_boot.freemem[i] = (region_t){ .start = 0, .end = 0 };
        if (!create_untypeds_for_region(root_cnode_cap, false, reg, first_untyped_slot)) {
            return false;
        }
    }

    return true;
}

__attribute__((__section__(".boot.text"))) void bi_finalise(void)
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
    if (addrFromPPtr((void *)p) > (0xFFFFFFFF80000000ul - (0xFFFFFFC000000000ul - 0x0ul))) {
        p = 0xFFFFFFFF80000000ul;
    }
    return p;
}

/* we can't delcare arrays on the stack, so this is space for
 * the below function to use. */
static __attribute__((__section__(".boot.data"))) region_t avail_reg[16];
/**
 * Dynamically initialise the available memory on the platform.
 * A region represents an area of memory.
 */
__attribute__((__section__(".boot.text"))) void init_freemem(word_t n_available, const p_region_t *available,
                            word_t n_reserved, region_t *reserved,
                            v_region_t it_v_reg, word_t extra_bi_size_bits)
{
    /* Force ordering and exclusivity of reserved regions */
    for (word_t i = 0; n_reserved > 0 && i < n_reserved - 1; i++) {
        ;
        ;
    }

    /* Force ordering and exclusivity of available regions */
    ;
    for (word_t i = 0; i < n_available - 1; i++) {
        ;
        ;
    }

    for (word_t i = 0; i < 16; i++) {
        ndks_boot.freemem[i] = (region_t){ .start = 0, .end = 0 };
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
                avail_reg[a].start = (((avail_reg[a].end)<(reserved[r].end))?(avail_reg[a].end):(reserved[r].end));
                reserve_region(pptr_to_paddr_reg(reserved[r]));
                r++;
            } else {
                ;
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
    word_t i = 16 - 1;
    if (!is_reg_empty(ndks_boot.freemem[i])) {
        ((void)(0));
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
        pptr_t start = (((ndks_boot.freemem[i].end - size) >> (max)) << (max));
        if (start >= ndks_boot.freemem[i].start) {
            create_rootserver_objects(start, it_v_reg, extra_bi_size_bits);
            if (i < 16) {
                ndks_boot.freemem[next].end = ndks_boot.freemem[i].end;
                ndks_boot.freemem[next].start = start + size;
            }
            ndks_boot.freemem[i].end = start;
            break;
        } else if (i < 16) {
            ndks_boot.freemem[next] = ndks_boot.freemem[i];
        }
    }
}
# 1 "/home/koc034/Documents/newver/seL4/src/kernel/cspace.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 15 "/home/koc034/Documents/newver/seL4/src/kernel/cspace.c"
lookupCap_ret_t lookupCap(tcb_t *thread, cptr_t cPtr)
{
    lookupSlot_raw_ret_t lu_ret;
    lookupCap_ret_t ret;

    lu_ret = lookupSlot(thread, cPtr);
    if (__builtin_expect(!!(lu_ret.status != EXCEPTION_NONE), 0)) {
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
    if (__builtin_expect(!!(lu_ret.status != EXCEPTION_NONE), 0)) {
        ret.status = lu_ret.status;
        ret.slot = ((void *)0);
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

    threadRoot = (((cte_t *)((word_t)(thread)&~((1ul << (10))-1ul)))+(tcbCTable))->cap;
    res_ret = resolveAddressBits(threadRoot, capptr, (1ul << (6)));

    ret.status = res_ret.status;
    ret.slot = res_ret.slot;
    return ret;
}

lookupSlot_ret_t lookupSlotForCNodeOp(bool_t isSource, cap_t root, cptr_t capptr,
                                      word_t depth)
{
    resolveAddressBits_ret_t res_ret;
    lookupSlot_ret_t ret;

    ret.slot = ((void *)0);

    if (__builtin_expect(!!(cap_get_capType(root) != cap_cnode_cap), 0)) {
        current_syscall_error.type = seL4_FailedLookup;
        current_syscall_error.failedLookupWasSource = isSource;
        current_lookup_fault = lookup_fault_invalid_root_new();
        ret.status = EXCEPTION_SYSCALL_ERROR;
        return ret;
    }

    if (__builtin_expect(!!(depth < 1 || depth > (1ul << (6))), 0)) {
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 1;
        current_syscall_error.rangeErrorMax = (1ul << (6));
        ret.status = EXCEPTION_SYSCALL_ERROR;
        return ret;
    }
    res_ret = resolveAddressBits(root, capptr, depth);
    if (__builtin_expect(!!(res_ret.status != EXCEPTION_NONE), 0)) {
        current_syscall_error.type = seL4_FailedLookup;
        current_syscall_error.failedLookupWasSource = isSource;
        /* current_lookup_fault will have been set by resolveAddressBits */
        ret.status = EXCEPTION_SYSCALL_ERROR;
        return ret;
    }

    if (__builtin_expect(!!(res_ret.bitsRemaining != 0), 0)) {
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
    ret.slot = ((void *)0);

    if (__builtin_expect(!!(cap_get_capType(nodeCap) != cap_cnode_cap), 0)) {
        current_lookup_fault = lookup_fault_invalid_root_new();
        ret.status = EXCEPTION_LOOKUP_FAULT;
        return ret;
    }

    while (1) {
        radixBits = cap_cnode_cap_get_capCNodeRadix(nodeCap);
        guardBits = cap_cnode_cap_get_capCNodeGuardSize(nodeCap);
        levelBits = radixBits + guardBits;

        /* Haskell error: "All CNodes must resolve bits" */
        ;

        capGuard = cap_cnode_cap_get_capCNodeGuard(nodeCap);

        /* sjw --- the MASK(5) here is to avoid the case where n_bits = 32
           and guardBits = 0, as it violates the C spec to >> by more
           than 31 */

        guard = (capptr >> ((n_bits - guardBits) & ((1ul << (6))-1ul))) & ((1ul << (guardBits))-1ul);
        if (__builtin_expect(!!(guardBits > n_bits || guard != capGuard), 0)) {
            current_lookup_fault =
                lookup_fault_guard_mismatch_new(capGuard, n_bits, guardBits);
            ret.status = EXCEPTION_LOOKUP_FAULT;
            return ret;
        }

        if (__builtin_expect(!!(levelBits > n_bits), 0)) {
            current_lookup_fault =
                lookup_fault_depth_mismatch_new(levelBits, n_bits);
            ret.status = EXCEPTION_LOOKUP_FAULT;
            return ret;
        }

        offset = (capptr >> (n_bits - levelBits)) & ((1ul << (radixBits))-1ul);
        slot = ((cte_t *)(cap_cnode_cap_get_capCNodePtr(nodeCap))) + offset;

        if (__builtin_expect(!!(n_bits <= levelBits), 1)) {
            ret.status = EXCEPTION_NONE;
            ret.slot = slot;
            ret.bitsRemaining = 0;
            return ret;
        }

        /** GHOSTUPD: "(\<acute>levelBits > 0, id)" */

        n_bits -= levelBits;
        nodeCap = slot->cap;

        if (__builtin_expect(!!(cap_get_capType(nodeCap) != cap_cnode_cap), 0)) {
            ret.status = EXCEPTION_NONE;
            ret.slot = slot;
            ret.bitsRemaining = n_bits;
            return ret;
        }
    }

    ret.status = EXCEPTION_NONE;
    return ret;
}
# 1 "/home/koc034/Documents/newver/seL4/src/kernel/faulthandler.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 15 "/home/koc034/Documents/newver/seL4/src/kernel/faulthandler.c"
void handleFault(tcb_t *tptr)
{
    bool_t hasFaultHandler = sendFaultIPC(tptr, (((cte_t *)((word_t)(tptr)&~((1ul << (10))-1ul)))+(tcbFaultHandler))->cap,
                                          tptr->tcbSchedContext != ((void *)0));
    if (!hasFaultHandler) {
        handleNoFaultHandler(tptr);
    }
}

void handleTimeout(tcb_t *tptr)
{
    ;
    sendFaultIPC(tptr, (((cte_t *)((word_t)(tptr)&~((1ul << (10))-1ul)))+(tcbTimeoutHandler))->cap, false);
}

bool_t sendFaultIPC(tcb_t *tptr, cap_t handlerCap, bool_t can_donate)
{
    if (cap_get_capType(handlerCap) == cap_endpoint_cap) {
        ;
       
                                                                 ;

        tptr->tcbFault = current_fault;
        sendIPC(true, false,
                cap_endpoint_cap_get_capEPBadge(handlerCap),
                cap_endpoint_cap_get_capCanGrant(handlerCap),
                cap_endpoint_cap_get_capCanGrantReply(handlerCap),
                can_donate, tptr,
                ((endpoint_t *)(cap_endpoint_cap_get_capEPPtr(handlerCap))));

        return true;
    } else {
        ;
        return false;
    }
}
# 144 "/home/koc034/Documents/newver/seL4/src/kernel/faulthandler.c"
void handleNoFaultHandler(tcb_t *tptr)




{
# 170 "/home/koc034/Documents/newver/seL4/src/kernel/faulthandler.c"
    setThreadState(tptr, ThreadState_Inactive);
}
# 1 "/home/koc034/Documents/newver/seL4/src/kernel/sporadic.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */





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
# 98 "/home/koc034/Documents/newver/seL4/src/kernel/sporadic.c"
/* compute the sum of a refill queue */
static __attribute__((unused)) ticks_t refill_sum(sched_context_t *sc)
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
    ;

    __attribute__((unused)) word_t prev_size = refill_size(sc);
    refill_t refill = *refill_head(sc);
    sc->scRefillHead = refill_next(sc, sc->scRefillHead);

    /* sanity */
    ;
    ;
    return refill;
}

/* add item to tail of refill queue */
static inline void refill_add_tail(sched_context_t *sc, refill_t refill)
{
    /* cannot add beyond queue size */
    ;

    word_t new_tail = refill_next(sc, sc->scRefillTail);
    sc->scRefillTail = new_tail;
    *refill_tail(sc) = refill;

    /* sanity */
    ;
}

static inline void maybe_add_empty_tail(sched_context_t *sc)
{
    if (isRoundRobin(sc)) {
        /* add an empty refill - we track the used up time here */
        refill_t empty_tail = { .rTime = ksCurTime};
        refill_add_tail(sc, empty_tail);
        ;
    }
}




void refill_new(sched_context_t *sc, word_t max_refills, ticks_t budget, ticks_t period)

{
    sc->scPeriod = period;
    sc->scRefillHead = 0;
    sc->scRefillTail = 0;
    sc->scRefillMax = max_refills;
    ;
    /* full budget available */
    refill_head(sc)->rAmount = budget;
    /* budget can be used from now */
    refill_head(sc)->rTime = ksCurTime;
    maybe_add_empty_tail(sc);
    ;
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
    ;

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
        refill_head(sc)->rTime = ksCurTime;
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

    ;
}

static __attribute__((noinline)) void schedule_used(sched_context_t *sc, refill_t new)
{
    /* schedule the used amount */
    if (new.rAmount < (2u * getKernelWcetTicks() * 1) && !refill_single(sc)) {
        /* used amount is to small - merge with last and delay */
        refill_tail(sc)->rAmount += new.rAmount;
        refill_tail(sc)->rTime = (((new.rTime)>(refill_tail(sc)->rTime))?(new.rTime):(refill_tail(sc)->rTime));
    } else if (new.rTime <= refill_tail(sc)->rTime) {
        refill_tail(sc)->rAmount += new.rAmount;
    } else {
        refill_add_tail(sc, new);
    }
}

static __attribute__((noinline)) void ensure_sufficient_head(sched_context_t *sc)
{
    /* ensure the refill head is sufficient, such that when we wake in awaken,
     * there is enough budget to run */
    while (refill_head(sc)->rAmount < (2u * getKernelWcetTicks() * 1) || refill_full(sc)) {
        refill_t refill = refill_pop_head(sc);
        refill_head(sc)->rAmount += refill.rAmount;
        /* this loop is guaranteed to terminate as the sum of
         * rAmount in a refill must be >= MIN_BUDGET */
    }
}

void refill_budget_check(ticks_t usage)
{
    sched_context_t *sc = ksCurSC;
    /* this function should only be called when the sc is out of budget */
    ticks_t capacity = refill_capacity(ksCurSC, usage);
    ;
    ;
    ;

    if (capacity == 0) {
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

    ;
}

void refill_split_check(ticks_t usage)
{
    sched_context_t *sc = ksCurSC;
    /* invalid to call this on a NULL sc */
    ;
    /* something is seriously wrong if this is called and no
     * time has been used */
    ;
    ;
    ;

    ;

    /* first deal with the remaining budget of the current replenishment */
    ticks_t remnant = refill_head(sc)->rAmount - usage;

    /* set up a new replenishment structure */
    refill_t new = (refill_t) {
        .rAmount = usage, .rTime = refill_head(sc)->rTime + sc->scPeriod
    };

    if (refill_size(sc) == sc->scRefillMax || remnant < (2u * getKernelWcetTicks() * 1)) {
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
        ;
    } else {
        /* leave remnant as reduced replenishment */
        ;
        /* split the head refill  */
        refill_head(sc)->rAmount = remnant;
        schedule_used(sc, new);
    }

    ;
}


static bool_t refill_unblock_check_mergable(sched_context_t *sc)
{
    ticks_t amount = refill_head(sc)->rAmount;
    ticks_t tail = ksCurTime + amount;
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
    ;
    if (refill_ready(sc)) {
        refill_head(sc)->rTime = ksCurTime;
        ksReprogram = true;

        /* merge available replenishments */
        while (refill_unblock_check_mergable(sc)) {
            ticks_t amount = refill_head(sc)->rAmount;
            refill_pop_head(sc);
            refill_head(sc)->rAmount += amount;
            refill_head(sc)->rTime = ksCurTime;
        }

        ;
    }
    ;
}
# 1 "/home/koc034/Documents/newver/seL4/src/kernel/stack.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */



__attribute__((externally_visible)) __attribute__((__aligned__(8)))
char kernel_stack_alloc[1][(1ul << (12))];
# 1 "/home/koc034/Documents/newver/seL4/src/kernel/thread.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 24 "/home/koc034/Documents/newver/seL4/src/kernel/thread.c"
static seL4_MessageInfo_t
transferCaps(seL4_MessageInfo_t info,
             endpoint_t *endpoint, tcb_t *receiver,
             word_t *receiveBuffer);

__attribute__((__section__(".boot.text"))) void configureIdleThread(tcb_t *tcb)
{
    Arch_configureIdleThread(tcb);
    setThreadState(tcb, ThreadState_IdleThreadState);
}

void activateThread(void)
{

    if (__builtin_expect(!!(ksCurThread->tcbYieldTo), 0)) {
        schedContext_completeYieldTo(ksCurThread);
        ;
    }


    switch (thread_state_get_tsType(ksCurThread->tcbState)) {
    case ThreadState_Running:



        break;

    case ThreadState_Restart: {
        word_t pc;

        pc = getRestartPC(ksCurThread);
        setNextPC(ksCurThread, pc);
        setThreadState(ksCurThread, ThreadState_Running);
        break;
    }

    case ThreadState_IdleThreadState:
        Arch_activateIdleThread(ksCurThread);
        break;

    default:
        halt();
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

    tcbReleaseRemove(target);
    schedContext_cancelYieldTo(target);

}

void restart(tcb_t *target)
{
    if (isStopped(target)) {
        cancelIPC(target);

        setThreadState(target, ThreadState_Restart);
        schedContext_resume(target->tcbSchedContext);
        if (isSchedulable(target)) {
            possibleSwitchTo(target);
        }






    }
}

void doIPCTransfer(tcb_t *sender, endpoint_t *endpoint, word_t badge,
                   bool_t grant, tcb_t *receiver)
{
    void *receiveBuffer, *sendBuffer;

    receiveBuffer = lookupIPCBuffer(true, receiver);

    if (__builtin_expect(!!(seL4_Fault_get_seL4_FaultType(sender->tcbFault) == seL4_Fault_NullFault), 1)) {
        sendBuffer = lookupIPCBuffer(false, sender);
        doNormalTransfer(sender, sendBuffer, endpoint, badge, grant,
                         receiver, receiveBuffer);
    } else {
        doFaultTransfer(badge, sender, receiver, receiveBuffer);
    }
}


void doReplyTransfer(tcb_t *sender, reply_t *reply, bool_t grant)



{

    if (reply->replyTCB == ((void *)0) ||
        thread_state_get_tsType(reply->replyTCB->tcbState) != ThreadState_BlockedOnReply) {
        /* nothing to do */
        return;
    }

    tcb_t *receiver = reply->replyTCB;
    reply_remove(reply, receiver);
    ;
    ;





    word_t fault_type = seL4_Fault_get_seL4_FaultType(receiver->tcbFault);
    if (__builtin_expect(!!(fault_type == seL4_Fault_NullFault), 1)) {
        doIPCTransfer(sender, ((void *)0), 0, grant, receiver);

        setThreadState(receiver, ThreadState_Running);






    } else {




        bool_t restart = handleFaultReply(receiver, sender);
        receiver->tcbFault = seL4_Fault_NullFault_new();
        if (restart) {
            setThreadState(receiver, ThreadState_Restart);



        } else {
            setThreadState(receiver, ThreadState_Inactive);
        }
    }


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
        if (__builtin_expect(!!(status != EXCEPTION_NONE), 0)) {
            current_extra_caps.excaprefs[0] = ((void *)0);
        }
    } else {
        current_extra_caps.excaprefs[0] = ((void *)0);
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

    if (__builtin_expect(!!(!current_extra_caps.excaprefs[0] || !receiveBuffer), 1)) {
        return info;
    }

    destSlot = getReceiveSlots(receiver, receiveBuffer);

    for (i = 0; i < ((1ul<<(seL4_MsgExtraCapBits))-1) && current_extra_caps.excaprefs[i] != ((void *)0); i++) {
        cte_t *slot = current_extra_caps.excaprefs[i];
        cap_t cap = slot->cap;

        if (cap_get_capType(cap) == cap_endpoint_cap &&
            ((endpoint_t *)(cap_endpoint_cap_get_capEPPtr(cap))) == endpoint) {
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

            destSlot = ((void *)0);
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

    ksReprogram = true;

    ksWorkUnitsCompleted = 0;
    ksCurDomain = ksDomSchedule[ksDomScheduleIdx].domain;

    ksDomainTime = usToTicks(ksDomSchedule[ksDomScheduleIdx].length * 1000llu);



}


static void switchSchedContext(void)
{
    if (__builtin_expect(!!(ksCurSC != ksCurThread->tcbSchedContext), 0) && ksCurSC->scRefillMax) {
        ksReprogram = true;
        refill_unblock_check(ksCurThread->tcbSchedContext);

        ;
        ;
    }

    if (ksReprogram) {
        /* if we are reprogamming, we have acted on the new kernel time and cannot
         * rollback -> charge the current thread */
        commitTime();
    }

    ksCurSC = ksCurThread->tcbSchedContext;
}


static void scheduleChooseNewThread(void)
{
    if (ksDomainTime == 0) {
        nextDomain();
    }
    chooseThread();
}

void schedule(void)
{

    awaken();


    if (ksSchedulerAction != ((tcb_t*)0)) {
        bool_t was_runnable;
        if (isSchedulable(ksCurThread)) {
            was_runnable = true;
            tcbSchedEnqueue(ksCurThread);
        } else {
            was_runnable = false;
        }

        if (ksSchedulerAction == ((tcb_t*) 1)) {
            scheduleChooseNewThread();
        } else {
            tcb_t *candidate = ksSchedulerAction;
            ;
            /* Avoid checking bitmap when ksCurThread is higher prio, to
             * match fast path.
             * Don't look at ksCurThread prio when it's idle, to respect
             * information flow in non-fastpath cases. */
            bool_t fastfail =
                ksCurThread == ksIdleThread
                || (candidate->tcbPriority < ksCurThread->tcbPriority);
            if (fastfail &&
                !isHighestPrio(ksCurDomain, candidate->tcbPriority)) {
                tcbSchedEnqueue(candidate);
                /* we can't, need to reschedule */
                ksSchedulerAction = ((tcb_t*) 1);
                scheduleChooseNewThread();
            } else if (was_runnable && candidate->tcbPriority == ksCurThread->tcbPriority) {
                /* We append the candidate at the end of the scheduling queue, that way the
                 * current thread, that was enqueued at the start of the scheduling queue
                 * will get picked during chooseNewThread */
                tcbSchedAppend(candidate);
                ksSchedulerAction = ((tcb_t*) 1);
                scheduleChooseNewThread();
            } else {
                ;
                switchToThread(candidate);
            }
        }
    }
    ksSchedulerAction = ((tcb_t*)0);






    switchSchedContext();

    if (ksReprogram) {
        setNextInterrupt();
        ksReprogram = false;
    }

}

void chooseThread(void)
{
    word_t prio;
    word_t dom;
    tcb_t *thread;

    if (16 > 1) {
        dom = ksCurDomain;
    } else {
        dom = 0;
    }

    if (__builtin_expect(!!(ksReadyQueuesL1Bitmap[dom]), 1)) {
        prio = getHighestPrio(dom);
        thread = ksReadyQueues[ready_queues_index(dom, prio)].head;
        ;
        ;

        ;
        ;

        switchToThread(thread);
    } else {
        switchToIdleThread();
    }
}

void switchToThread(tcb_t *thread)
{

    ;
    ;
    ;
    ;





    Arch_switchToThread(thread);
    tcbSchedDequeue(thread);
    ksCurThread = thread;
}

void switchToIdleThread(void)
{



    Arch_switchToIdleThread();
    ksCurThread = ksIdleThread;
}

void setDomain(tcb_t *tptr, dom_t dom)
{
    tcbSchedDequeue(tptr);
    tptr->tcbDomain = dom;
    if (isSchedulable(tptr)) {
        tcbSchedEnqueue(tptr);
    }
    if (tptr == ksCurThread) {
        rescheduleRequired();
    }
}

void setMCPriority(tcb_t *tptr, prio_t mcp)
{
    tptr->tcbMCP = mcp;
}

void setPriority(tcb_t *tptr, prio_t prio)
{
    switch (thread_state_get_tsType(tptr->tcbState)) {
    case ThreadState_Running:
    case ThreadState_Restart:
        if (thread_state_get_tcbQueued(tptr->tcbState) || tptr == ksCurThread) {
            tcbSchedDequeue(tptr);
            tptr->tcbPriority = prio;
            tcbSchedEnqueue(tptr);
            rescheduleRequired();
        } else {
            tptr->tcbPriority = prio;
        }
        break;
    case ThreadState_BlockedOnReceive:
    case ThreadState_BlockedOnSend:
        tptr->tcbPriority = prio;
        reorderEP(((endpoint_t *)(thread_state_get_blockingObject(tptr->tcbState))), tptr);
        break;
    case ThreadState_BlockedOnNotification:
        tptr->tcbPriority = prio;
        reorderNTFN(((notification_t *)(thread_state_get_blockingObject(tptr->tcbState))), tptr);
        break;
    default:
        tptr->tcbPriority = prio;
        break;
    }
}
# 515 "/home/koc034/Documents/newver/seL4/src/kernel/thread.c"
/* Note that this thread will possibly continue at the end of this kernel
 * entry. Do not queue it yet, since a queue+unqueue operation is wasteful
 * if it will be picked. Instead, it waits in the 'ksSchedulerAction' site
 * on which the scheduler will take action. */
void possibleSwitchTo(tcb_t *target)
{

    if (target->tcbSchedContext != ((void *)0) && !thread_state_get_tcbInReleaseQueue(target->tcbState)) {

        if (ksCurDomain != target->tcbDomain
            ) {
            tcbSchedEnqueue(target);
        } else if (ksSchedulerAction != ((tcb_t*)0)) {
            /* Too many threads want special treatment, use regular queues. */
            rescheduleRequired();
            tcbSchedEnqueue(target);
        } else {
            ksSchedulerAction = target;
        }

    }


}

void setThreadState(tcb_t *tptr, _thread_state_t ts)
{
    thread_state_ptr_set_tsType(&tptr->tcbState, ts);
    scheduleTCB(tptr);
}

void scheduleTCB(tcb_t *tptr)
{
    if (tptr == ksCurThread &&
        ksSchedulerAction == ((tcb_t*)0) &&
        !isSchedulable(tptr)) {
        rescheduleRequired();
    }
}


void postpone(sched_context_t *sc)
{
    tcbSchedDequeue(sc->scTcb);
    tcbReleaseEnqueue(sc->scTcb);
    ksReprogram = true;
}

void setNextInterrupt(void)
{
    time_t next_interrupt = ksCurTime +
                            refill_head(ksCurThread->tcbSchedContext)->rAmount;

    if (16 > 1) {
        next_interrupt = (((next_interrupt)<(ksCurTime + ksDomainTime))?(next_interrupt):(ksCurTime + ksDomainTime));
    }

    if (ksReleaseHead != ((void *)0)) {
        next_interrupt = (((refill_head(ksReleaseHead->tcbSchedContext)->rTime)<(next_interrupt))?(refill_head(ksReleaseHead->tcbSchedContext)->rTime):(next_interrupt));
    }

    setDeadline(next_interrupt - getTimerPrecision());
}

void chargeBudget(ticks_t consumed, bool_t canTimeoutFault, word_t core, bool_t isCurCPU)
{

    if (isRoundRobin(ksCurSC)) {
        ;
        refill_head(ksCurSC)->rAmount += refill_tail(ksCurSC)->rAmount;
        refill_tail(ksCurSC)->rAmount = 0;
    } else {
        refill_budget_check(consumed);
    }

    ;
    ksCurSC->scConsumed += consumed;
    ksConsumed = 0;
    if (isCurCPU && __builtin_expect(!!(isSchedulable(ksCurThread)), 1)) {
        ;
        endTimeslice(canTimeoutFault);
        rescheduleRequired();
        ksReprogram = true;
    }
}

void endTimeslice(bool_t can_timeout_fault)
{
    if (can_timeout_fault && !isRoundRobin(ksCurSC) && validTimeoutHandler(ksCurThread)) {
        current_fault = seL4_Fault_Timeout_new(ksCurSC->scBadge);
        handleTimeout(ksCurThread);
    } else if (refill_ready(ksCurSC) && refill_sufficient(ksCurSC, 0)) {
        /* apply round robin */
        ;
        ;
        tcbSchedAppend(ksCurThread);
    } else {
        /* postpone until ready */
        postpone(ksCurSC);
    }
}
# 645 "/home/koc034/Documents/newver/seL4/src/kernel/thread.c"
void rescheduleRequired(void)
{
    if (ksSchedulerAction != ((tcb_t*)0)
        && ksSchedulerAction != ((tcb_t*) 1)

        && isSchedulable(ksSchedulerAction)

       ) {

        ;
        ;

        tcbSchedEnqueue(ksSchedulerAction);
    }
    ksSchedulerAction = ((tcb_t*) 1);
}


void awaken(void)
{
    while (__builtin_expect(!!(ksReleaseHead != ((void *)0) && refill_ready(ksReleaseHead->tcbSchedContext)), 0)) {
        tcb_t *awakened = tcbReleaseDequeue();
        /* the currently running thread cannot have just woken up */
        ;
        /* round robin threads should not be in the release queue */
        ;
        /* threads should wake up on the correct core */
        ;
        /* threads HEAD refill should always be > MIN_BUDGET */
        ;
        possibleSwitchTo(awakened);
        /* changed head of release queue -> need to reprogram */
        ksReprogram = true;
    }
}
# 1 "/home/koc034/Documents/newver/seL4/src/machine/fpu.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 1 "/home/koc034/Documents/newver/seL4/src/machine/io.c"
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
# 1 "/home/koc034/Documents/newver/seL4/src/machine/registerset.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */



const register_t fault_messages[][(((n_syscallMessage)>((((n_timeoutMessage)>(n_exceptionMessage))?(n_timeoutMessage):(n_exceptionMessage))))?(n_syscallMessage):((((n_timeoutMessage)>(n_exceptionMessage))?(n_timeoutMessage):(n_exceptionMessage))))] = {
    [MessageID_Syscall] = { [seL4_UnknownSyscall_FaultIP] = FaultIP, [seL4_UnknownSyscall_SP] = SP, [seL4_UnknownSyscall_RA] = LR, [seL4_UnknownSyscall_A0] = a0, [seL4_UnknownSyscall_A1] = a1, [seL4_UnknownSyscall_A2] = a2, [seL4_UnknownSyscall_A3] = a3, [seL4_UnknownSyscall_A4] = a4, [seL4_UnknownSyscall_A5] = a5, [seL4_UnknownSyscall_A6] = a6,},
    [MessageID_Exception] = { [seL4_UserException_FaultIP] = FaultIP, [seL4_UserException_SP] = SP, },

    [MessageID_TimeoutReply] = { [seL4_TimeoutReply_FaultIP] = FaultIP, [seL4_TimeoutReply_LR] = LR, [seL4_TimeoutReply_SP] = SP, [seL4_TimeoutReply_GP] = GP, [seL4_TimeoutReply_s0] = s0, [seL4_TimeoutReply_s1] = s1, [seL4_TimeoutReply_s2] = s2, [seL4_TimeoutReply_s3] = s3, [seL4_TimeoutReply_s4] = s4, [seL4_TimeoutReply_s5] = s5, [seL4_TimeoutReply_s6] = s6, [seL4_TimeoutReply_s7] = s7, [seL4_TimeoutReply_s8] = s8, [seL4_TimeoutReply_s9] = s9, [seL4_TimeoutReply_s10] = s10, [seL4_TimeoutReply_s11] = s11, [seL4_TimeoutReply_a0] = a0, [seL4_TimeoutReply_a1] = a1, [seL4_TimeoutReply_a2] = a2, [seL4_TimeoutReply_a3] = a3, [seL4_TimeoutReply_a4] = a4, [seL4_TimeoutReply_a5] = a5, [seL4_TimeoutReply_a6] = a6, [seL4_TimeoutReply_a7] = a7, [seL4_TimeoutReply_t0] = t0, [seL4_TimeoutReply_t1] = t1, [seL4_TimeoutReply_t2] = t2, [seL4_TimeoutReply_t3] = t3, [seL4_TimeoutReply_t4] = t4, [seL4_TimeoutReply_t5] = t5, [seL4_TimeoutReply_t6] = t6, [seL4_TimeoutReply_TP] = TP, },

};
# 1 "/home/koc034/Documents/newver/seL4/src/model/preemption.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */







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
    if (ksWorkUnitsCompleted >= 100) {
        ksWorkUnitsCompleted = 0;
        if (isIRQPending()) {
            return EXCEPTION_PREEMPTED;

        } else {
            updateTimestamp();
            if (!checkBudget()) {
                return EXCEPTION_PREEMPTED;
            }

        }
    }

    return EXCEPTION_NONE;
}
# 1 "/home/koc034/Documents/newver/seL4/src/model/smp.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 1 "/home/koc034/Documents/newver/seL4/src/model/statedata.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */


# 1 "/home/koc034/Documents/newver/seL4/include/api/debug.h" 1
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 9 "/home/koc034/Documents/newver/seL4/src/model/statedata.c" 2

# 1 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

# 1 "gen_headers/plat/machine/devices_gen.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * This file is autogenerated by kernel/tools/hardware_gen.py.
 */
# 8 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 2
# 1 "gen_headers/plat/platform_gen.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 8 "/home/koc034/Documents/newver/seL4/include/plat/default/plat/machine.h" 2
# 11 "/home/koc034/Documents/newver/seL4/src/model/statedata.c" 2






/* Collective cpu states, including both pre core architecture dependant and independent data */
;

/* Global count of how many cpus there are */
word_t ksNumCPUs;

/* Pointer to the head of the scheduler queue for each priority */
tcb_queue_t ksReadyQueues[(16 * 256)];
word_t ksReadyQueuesL1Bitmap[16];
word_t ksReadyQueuesL2Bitmap[16][((256 + (1ul << (6)) - 1) / (1ul << (6)))];
typedef int __assert_failed_ksReadyQueuesL1BitmapBigEnough[((((256 + (1ul << (6)) - 1) / (1ul << (6))) - 1) <= (1ul << (6))) ? 1 : -1];

/* Head of the queue of threads waiting for their budget to be replenished */
tcb_t * ksReleaseHead;


/* Current thread TCB pointer */
tcb_t * ksCurThread;

/* Idle thread TCB pointer */
tcb_t * ksIdleThread;

/* Values of 0 and ~0 encode ResumeCurrentThread and ChooseNewThread
 * respectively; other values encode SwitchToThread and must be valid
 * tcb pointers */
tcb_t * ksSchedulerAction;
# 51 "/home/koc034/Documents/newver/seL4/src/model/statedata.c"
/* the amount of time passed since the kernel time was last updated */
ticks_t ksConsumed;
/* whether we need to reprogram the timer before exiting the kernel */
bool_t ksReprogram;
/* the current kernel time (recorded on kernel entry) */
ticks_t ksCurTime;
/* current scheduling context pointer */
sched_context_t * ksCurSC;
# 73 "/home/koc034/Documents/newver/seL4/src/model/statedata.c"
/* Units of work we have completed since the last time we checked for
 * pending interrupts */
word_t ksWorkUnitsCompleted;

irq_state_t intStateIRQTable[(maxIRQ + 1)];
/* CNode containing interrupt handler endpoints - like all seL4 objects, this CNode needs to be
 * of a size that is a power of 2 and aligned to its size. */
cte_t intStateIRQNode[(1ul << ((6)))] __attribute__((__aligned__((1ul << ((6) + 5)))));
typedef int __assert_failed_irqCNodeSize[(sizeof(intStateIRQNode) >= (((maxIRQ + 1)) *sizeof(cte_t))) ? 1 : -1];;

/* Currently active domain */
dom_t ksCurDomain;

/* Domain timeslice remaining */

ticks_t ksDomainTime;




/* An index into ksDomSchedule for active domain and length. */
word_t ksDomScheduleIdx;

/* Only used by lockTLBEntry */
word_t tlbLockCount = 0;

/* Idle thread. */
__attribute__((__section__("._idle_thread"))) char ksIdleThreadTCB[1][(1ul << (10))] __attribute__((__aligned__((1ul << ((10 - 1))))));


/* Idle thread Schedcontexts */
char ksIdleThreadSC[1][(1ul << (8))] __attribute__((__aligned__((1ul << (8)))));
# 1 "/home/koc034/Documents/newver/seL4/src/object/cnode.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */




# 1 "gen_headers/api/invocation.h" 1

/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 ** SPDX-License-Identifier: GPL-2.0-only
 */

/* This header was generated by kernel/tools/invocation_header_gen.py.
 *
 * To add an invocation call number, edit libsel4/include/interfaces/sel4.xml.
 *
 */
# 11 "/home/koc034/Documents/newver/seL4/src/object/cnode.c" 2
# 25 "/home/koc034/Documents/newver/seL4/src/object/cnode.c"
struct finaliseSlot_ret {
    exception_t status;
    bool_t success;
    cap_t cleanupInfo;
};
typedef struct finaliseSlot_ret finaliseSlot_ret_t;

static finaliseSlot_ret_t finaliseSlot(cte_t *slot, bool_t exposed);
static void emptySlot(cte_t *slot, cap_t cleanupInfo);
static exception_t reduceZombie(cte_t *slot, bool_t exposed);







exception_t decodeCNodeInvocation(word_t invLabel, word_t length, cap_t cap,
                                  word_t *buffer)
{
    lookupSlot_ret_t lu_ret;
    cte_t *destSlot;
    word_t index, w_bits;
    exception_t status;

    /* Haskell error: "decodeCNodeInvocation: invalid cap" */
    ;

    if (invLabel < CNodeRevoke || invLabel > CNodeRotate) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (length < 2) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }
    index = getSyscallArg(0, buffer);
    w_bits = getSyscallArg(1, buffer);

    lu_ret = lookupTargetSlot(cap, index, w_bits);
    if (lu_ret.status != EXCEPTION_NONE) {
        ;
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

        if (length < 4 || current_extra_caps.excaprefs[0] == ((void *)0)) {
            ;
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }
        srcIndex = getSyscallArg(2, buffer);
        srcDepth = getSyscallArg(3, buffer);

        srcRoot = current_extra_caps.excaprefs[0]->cap;

        status = ensureEmptySlot(destSlot);
        if (status != EXCEPTION_NONE) {
            ;
            return status;
        }

        lu_ret = lookupSourceSlot(srcRoot, srcIndex, srcDepth);
        if (lu_ret.status != EXCEPTION_NONE) {
            ;
            return lu_ret.status;
        }
        srcSlot = lu_ret.slot;

        if (cap_get_capType(srcSlot->cap) == cap_null_cap) {
            ;
            current_syscall_error.type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 1;
            current_lookup_fault =
                lookup_fault_missing_capability_new(srcDepth);
            return EXCEPTION_SYSCALL_ERROR;
        }

        switch (invLabel) {
        case CNodeCopy:

            if (length < 5) {
                ;
                current_syscall_error.type = seL4_TruncatedMessage;
                return EXCEPTION_SYSCALL_ERROR;
            }

            cap_rights = rightsFromWord(getSyscallArg(4, buffer));
            srcCap = maskCapRights(cap_rights, srcSlot->cap);
            dc_ret = deriveCap(srcSlot, srcCap);
            if (dc_ret.status != EXCEPTION_NONE) {
                ;
                return dc_ret.status;
            }
            newCap = dc_ret.cap;
            isMove = false;

            break;

        case CNodeMint:
            if (length < 6) {
                ;
                current_syscall_error.type = seL4_TruncatedMessage;
                return EXCEPTION_SYSCALL_ERROR;
            }

            cap_rights = rightsFromWord(getSyscallArg(4, buffer));
            capData = getSyscallArg(5, buffer);
            srcCap = maskCapRights(cap_rights, srcSlot->cap);
            dc_ret = deriveCap(srcSlot,
                               updateCapData(false, capData, srcCap));
            if (dc_ret.status != EXCEPTION_NONE) {
                ;
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
                ;
                current_syscall_error.type = seL4_TruncatedMessage;
                return EXCEPTION_SYSCALL_ERROR;
            }

            capData = getSyscallArg(4, buffer);
            newCap = updateCapData(true, capData, srcSlot->cap);
            isMove = true;

            break;

        default:
            ;
            return EXCEPTION_NONE;
        }

        if (cap_get_capType(newCap) == cap_null_cap) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(ksCurThread, ThreadState_Restart);
        if (isMove) {
            return invokeCNodeMove(newCap, srcSlot, destSlot);
        } else {
            return invokeCNodeInsert(newCap, srcSlot, destSlot);
        }
    }

    if (invLabel == CNodeRevoke) {
        setThreadState(ksCurThread, ThreadState_Restart);
        return invokeCNodeRevoke(destSlot);
    }

    if (invLabel == CNodeDelete) {
        setThreadState(ksCurThread, ThreadState_Restart);
        return invokeCNodeDelete(destSlot);
    }
# 218 "/home/koc034/Documents/newver/seL4/src/object/cnode.c"
    if (invLabel == CNodeCancelBadgedSends) {
        cap_t destCap;

        destCap = destSlot->cap;

        if (!hasCancelSendRights(destCap)) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        setThreadState(ksCurThread, ThreadState_Restart);
        return invokeCNodeCancelBadgedSends(destCap);
    }

    if (invLabel == CNodeRotate) {
        word_t pivotNewData, pivotIndex, pivotDepth;
        word_t srcNewData, srcIndex, srcDepth;
        cte_t *pivotSlot, *srcSlot;
        cap_t pivotRoot, srcRoot, newSrcCap, newPivotCap;

        if (length < 8 || current_extra_caps.excaprefs[0] == ((void *)0)
            || current_extra_caps.excaprefs[1] == ((void *)0)) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }
        pivotNewData = getSyscallArg(2, buffer);
        pivotIndex = getSyscallArg(3, buffer);
        pivotDepth = getSyscallArg(4, buffer);
        srcNewData = getSyscallArg(5, buffer);
        srcIndex = getSyscallArg(6, buffer);
        srcDepth = getSyscallArg(7, buffer);

        pivotRoot = current_extra_caps.excaprefs[0]->cap;
        srcRoot = current_extra_caps.excaprefs[1]->cap;

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
            ;
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
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }

        if (cap_get_capType(newPivotCap) == cap_null_cap) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(ksCurThread, ThreadState_Restart);
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
# 392 "/home/koc034/Documents/newver/seL4/src/object/cnode.c"
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
                                                 ((1ul << ((cap_untyped_cap_get_capBlockSize(srcCap)) - 4))));
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

    newMDB = mdb_node_set_mdbPrev(srcMDB, ((word_t)(srcSlot)));
    newMDB = mdb_node_set_mdbRevocable(newMDB, newCapIsRevocable);
    newMDB = mdb_node_set_mdbFirstBadged(newMDB, newCapIsRevocable);

    /* Haskell error: "cteInsert to non-empty destination" */
    ;
    /* Haskell error: "cteInsert: mdb entry must be empty" */
   
                                                                       ;

    /* Prevent parent untyped cap from being used again if creating a child
     * untyped from it. */
    setUntypedCapAsFull(srcCap, newCap, srcSlot);

    destSlot->cap = newCap;
    destSlot->cteMDBNode = newMDB;
    mdb_node_ptr_set_mdbNext(&srcSlot->cteMDBNode, ((word_t)(destSlot)));
    if (mdb_node_get_mdbNext(newMDB)) {
        mdb_node_ptr_set_mdbPrev(
            &((cte_t *)(mdb_node_get_mdbNext(newMDB)))->cteMDBNode,
            ((word_t)(destSlot)));
    }
}

void cteMove(cap_t newCap, cte_t *srcSlot, cte_t *destSlot)
{
    mdb_node_t mdb;
    word_t prev_ptr, next_ptr;

    /* Haskell error: "cteMove to non-empty destination" */
    ;
    /* Haskell error: "cteMove: mdb entry must be empty" */
   
                                                                       ;

    mdb = srcSlot->cteMDBNode;
    destSlot->cap = newCap;
    srcSlot->cap = cap_null_cap_new();
    destSlot->cteMDBNode = mdb;
    srcSlot->cteMDBNode = mdb_node_new(0, false, false, 0);

    prev_ptr = mdb_node_get_mdbPrev(mdb);
    if (prev_ptr)
        mdb_node_ptr_set_mdbNext(
            &((cte_t *)(prev_ptr))->cteMDBNode,
            ((word_t)(destSlot)));

    next_ptr = mdb_node_get_mdbNext(mdb);
    if (next_ptr)
        mdb_node_ptr_set_mdbPrev(
            &((cte_t *)(next_ptr))->cteMDBNode,
            ((word_t)(destSlot)));
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
            &((cte_t *)(prev_ptr))->cteMDBNode,
            ((word_t)(slot2)));

    next_ptr = mdb_node_get_mdbNext(mdb1);
    if (next_ptr)
        mdb_node_ptr_set_mdbPrev(
            &((cte_t *)(next_ptr))->cteMDBNode,
            ((word_t)(slot2)));

    mdb2 = slot2->cteMDBNode;
    slot1->cteMDBNode = mdb2;
    slot2->cteMDBNode = mdb1;

    prev_ptr = mdb_node_get_mdbPrev(mdb2);
    if (prev_ptr)
        mdb_node_ptr_set_mdbNext(
            &((cte_t *)(prev_ptr))->cteMDBNode,
            ((word_t)(slot1)));

    next_ptr = mdb_node_get_mdbNext(mdb2);
    if (next_ptr)
        mdb_node_ptr_set_mdbPrev(
            &((cte_t *)(next_ptr))->cteMDBNode,
            ((word_t)(slot1)));
}

exception_t cteRevoke(cte_t *slot)
{
    cte_t *nextPtr;
    exception_t status;

    /* there is no need to check for a NullCap as NullCaps are
       always accompanied by null mdb pointers */
    for (nextPtr = ((cte_t *)(mdb_node_get_mdbNext(slot->cteMDBNode)));
         nextPtr && isMDBParentOf(slot, nextPtr);
         nextPtr = ((cte_t *)(mdb_node_get_mdbNext(slot->cteMDBNode)))) {
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
        prev = ((cte_t *)(mdb_node_get_mdbPrev(mdbNode)));
        next = ((cte_t *)(mdb_node_get_mdbNext(mdbNode)));

        if (prev) {
            mdb_node_ptr_set_mdbNext(&prev->cteMDBNode, ((word_t)(next)));
        }
        if (next) {
            mdb_node_ptr_set_mdbPrev(&next->cteMDBNode, ((word_t)(prev)));
        }
        if (next)
            mdb_node_ptr_set_mdbFirstBadged(&next->cteMDBNode,
                                            mdb_node_get_mdbFirstBadged(next->cteMDBNode) ||
                                            mdb_node_get_mdbFirstBadged(mdbNode));
        slot->cap = cap_null_cap_new();
        slot->cteMDBNode = mdb_node_new(0, false, false, 0);

        postCapDeletion(cleanupInfo);
    }
}

static inline bool_t __attribute__((__const__)) capRemovable(cap_t cap, cte_t *slot)
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
        halt();
    }
}

static inline bool_t __attribute__((__const__)) capCyclicZombie(cap_t cap, cte_t *slot)
{
    return cap_get_capType(cap) == cap_zombie_cap &&
           ((cte_t *)(cap_zombie_cap_get_capZombiePtr(cap))) == slot;
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

    ;
    ptr = (cte_t *)cap_zombie_cap_get_capZombiePtr(slot->cap);
    n = cap_zombie_cap_get_capZombieNumber(slot->cap);
    type = cap_zombie_cap_get_capZombieType(slot->cap);

    /* Haskell error: "reduceZombie: expected unremovable zombie" */
    ;

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
                ;
                slot->cap =
                    cap_zombie_cap_set_capZombieNumber(slot->cap, n - 1);
            } else {
                /* Haskell error:
                 * "Expected new Zombie to be self-referential."
                 */
                ;
            }
            break;
        }

        default:
            halt();
        }
    } else {
        /* Haskell error: "Cyclic zombie passed to unexposed reduceZombie" */
        ;

        if (cap_get_capType(ptr->cap) == cap_zombie_cap) {
            /* Haskell error: "Moving self-referential Zombie aside." */
            ;
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
        finaliseCap_ret_t fc_ret __attribute__((unused));

        /** GHOSTUPD: "(gs_get_assn cteDeleteOne_'proc \<acute>ghost'state = (-1)
            \<or> gs_get_assn cteDeleteOne_'proc \<acute>ghost'state = \<acute>cap_type, id)" */

        final = isFinalCapability(slot);
        fc_ret = finaliseCap(slot->cap, final, true);
        /* Haskell error: "cteDeleteOne: cap should be removable" */
       
                                                                   ;
        emptySlot(slot, cap_null_cap_new());
    }
}

void insertNewCap(cte_t *parent, cte_t *slot, cap_t cap)
{
    cte_t *next;

    next = ((cte_t *)(mdb_node_get_mdbNext(parent->cteMDBNode)));
    slot->cap = cap;
    slot->cteMDBNode = mdb_node_new(((word_t)(next)), true, true, ((word_t)(parent)));
    if (next) {
        mdb_node_ptr_set_mdbPrev(&next->cteMDBNode, ((word_t)(slot)));
    }
    mdb_node_ptr_set_mdbNext(&parent->cteMDBNode, ((word_t)(slot)));
}
# 775 "/home/koc034/Documents/newver/seL4/src/object/cnode.c"
bool_t __attribute__((__pure__)) isMDBParentOf(cte_t *cte_a, cte_t *cte_b)
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

        next = ((cte_t *)(mdb_node_get_mdbNext(slot->cteMDBNode)));
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

bool_t __attribute__((__pure__)) isFinalCapability(cte_t *cte)
{
    mdb_node_t mdb;
    bool_t prevIsSameObject;

    mdb = cte->cteMDBNode;

    if (mdb_node_get_mdbPrev(mdb) == 0) {
        prevIsSameObject = false;
    } else {
        cte_t *prev;

        prev = ((cte_t *)(mdb_node_get_mdbPrev(mdb)));
        prevIsSameObject = sameObjectAs(prev->cap, cte->cap);
    }

    if (prevIsSameObject) {
        return false;
    } else {
        if (mdb_node_get_mdbNext(mdb) == 0) {
            return true;
        } else {
            cte_t *next;

            next = ((cte_t *)(mdb_node_get_mdbNext(mdb)));
            return !sameObjectAs(cte->cap, next->cap);
        }
    }
}

bool_t __attribute__((__pure__)) slotCapLongRunningDelete(cte_t *slot)
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
        return ((void *)0);
    }

    ct = loadCapTransfer(buffer);
    cptr = ct.ctReceiveRoot;

    luc_ret = lookupCap(thread, cptr);
    if (luc_ret.status != EXCEPTION_NONE) {
        return ((void *)0);
    }
    cnode = luc_ret.cap;

    lus_ret = lookupTargetSlot(cnode, ct.ctReceiveIndex, ct.ctReceiveDepth);
    if (lus_ret.status != EXCEPTION_NONE) {
        return ((void *)0);
    }
    slot = lus_ret.slot;

    if (cap_get_capType(slot->cap) != cap_null_cap) {
        return ((void *)0);
    }

    return slot;
}

cap_transfer_t __attribute__((__pure__)) loadCapTransfer(word_t *buffer)
{
    const int offset = seL4_MsgMaxLength + ((1ul<<(seL4_MsgExtraCapBits))-1) + 2;
    return capTransferFromWords(buffer + offset);
}
# 1 "/home/koc034/Documents/newver/seL4/src/object/endpoint.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 19 "/home/koc034/Documents/newver/seL4/src/object/endpoint.c"
static inline void ep_ptr_set_queue(endpoint_t *epptr, tcb_queue_t queue)
{
    endpoint_ptr_set_epQueue_head(epptr, (word_t)queue.head);
    endpoint_ptr_set_epQueue_tail(epptr, (word_t)queue.end);
}


void sendIPC(bool_t blocking, bool_t do_call, word_t badge,
             bool_t canGrant, bool_t canGrantReply, bool_t canDonate, tcb_t *thread, endpoint_t *epptr)




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
                &thread->tcbState, ((word_t)(epptr)));
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
        ;

        /* Dequeue the first TCB */
        queue = tcbEPDequeue(dest, queue);
        ep_ptr_set_queue(epptr, queue);

        if (!queue.head) {
            endpoint_ptr_set_state(epptr, EPState_Idle);
        }

        /* Do the transfer */
        doIPCTransfer(thread, epptr, badge, canGrant, dest);


        reply_t *reply = ((reply_t *) (thread_state_get_replyObject(dest->tcbState)));
        if (reply) {
            reply_unlink(reply, dest);
        }

        if (do_call ||
            seL4_Fault_ptr_get_seL4_FaultType(&thread->tcbFault) != seL4_Fault_NullFault) {
            if (reply != ((void *)0) && (canGrant || canGrantReply)) {
                reply_push(thread, dest, reply, canDonate);
            } else {
                setThreadState(thread, ThreadState_Inactive);
            }
        } else if (canDonate && dest->tcbSchedContext == ((void *)0)) {
            schedContext_donate(thread->tcbSchedContext, dest);
        }

        /* blocked threads should have enough budget to get out of the kernel */
        ;
        ;
        setThreadState(dest, ThreadState_Running);
        possibleSwitchTo(dest);
# 121 "/home/koc034/Documents/newver/seL4/src/object/endpoint.c"
        break;
    }
    }
}


void receiveIPC(tcb_t *thread, cap_t cap, bool_t isBlocking, cap_t replyCap)



{
    endpoint_t *epptr;
    notification_t *ntfnPtr;

    /* Haskell error "receiveIPC: invalid cap" */
    ;

    epptr = ((endpoint_t *)(cap_endpoint_cap_get_capEPPtr(cap)));


    reply_t *replyPtr = ((void *)0);
    if (cap_get_capType(replyCap) == cap_reply_cap) {
        replyPtr = ((reply_t *) (cap_reply_cap_get_capReplyPtr(replyCap)));
        if (__builtin_expect(!!(replyPtr->replyTCB != ((void *)0) && replyPtr->replyTCB != thread), 0)) {
            ;
            cancelIPC(replyPtr->replyTCB);
        }
    }


    /* Check for anything waiting in the notification */
    ntfnPtr = thread->tcbBoundNotification;
    if (ntfnPtr && notification_ptr_get_state(ntfnPtr) == NtfnState_Active) {
        completeSignal(ntfnPtr, thread);
    } else {

        /* If this is a blocking recv and we didn't have a pending notification,
         * then if we are running on an SC from a bound notification, then we
         * need to return it so that we can passively wait on the EP for potentially
         * SC donations from client threads.
         */
        if (ntfnPtr && isBlocking) {
            maybeReturnSchedContext(ntfnPtr, thread);
        }

        switch (endpoint_ptr_get_state(epptr)) {
        case EPState_Idle:
        case EPState_Recv: {
            tcb_queue_t queue;

            if (isBlocking) {
                /* Set thread state to BlockedOnReceive */
                thread_state_ptr_set_tsType(&thread->tcbState,
                                            ThreadState_BlockedOnReceive);
                thread_state_ptr_set_blockingObject(
                    &thread->tcbState, ((word_t)(epptr)));

                thread_state_ptr_set_replyObject(&thread->tcbState, ((word_t) (replyPtr)));
                if (replyPtr) {
                    replyPtr->replyTCB = thread;
                }




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
            ;

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


            if (do_call ||
                seL4_Fault_get_seL4_FaultType(sender->tcbFault) != seL4_Fault_NullFault) {
                if ((canGrant || canGrantReply) && replyPtr != ((void *)0)) {
                    bool_t canDonate = sender->tcbSchedContext != ((void *)0)
                                       && seL4_Fault_get_seL4_FaultType(sender->tcbFault) != seL4_Fault_Timeout;
                    reply_push(sender, thread, replyPtr, canDonate);
                } else {
                    setThreadState(sender, ThreadState_Inactive);
                }
            } else {
                setThreadState(sender, ThreadState_Running);
                possibleSwitchTo(sender);
                ;
            }
# 262 "/home/koc034/Documents/newver/seL4/src/object/endpoint.c"
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
# 285 "/home/koc034/Documents/newver/seL4/src/object/endpoint.c"
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


    /* cancel ipc cancels all faults */
    seL4_Fault_NullFault_ptr_new(&tptr->tcbFault);


    switch (thread_state_ptr_get_tsType(state)) {
    case ThreadState_BlockedOnSend:
    case ThreadState_BlockedOnReceive: {
        /* blockedIPCCancel state */
        endpoint_t *epptr;
        tcb_queue_t queue;

        epptr = ((endpoint_t *)(thread_state_ptr_get_blockingObject(state)));

        /* Haskell error "blockedIPCCancel: endpoint must not be idle" */
        ;

        /* Dequeue TCB */
        queue = ep_ptr_get_queue(epptr);
        queue = tcbEPDequeue(tptr, queue);
        ep_ptr_set_queue(epptr, queue);

        if (!queue.head) {
            endpoint_ptr_set_state(epptr, EPState_Idle);
        }


        reply_t *reply = ((reply_t *) (thread_state_get_replyObject(tptr->tcbState)));
        if (reply != ((void *)0)) {
            reply_unlink(reply, tptr);
        }

        setThreadState(tptr, ThreadState_Inactive);
        break;
    }

    case ThreadState_BlockedOnNotification:
        cancelSignal(tptr,
                     ((notification_t *)(thread_state_ptr_get_blockingObject(state))));
        break;

    case ThreadState_BlockedOnReply: {

        reply_remove_tcb(tptr);
# 360 "/home/koc034/Documents/newver/seL4/src/object/endpoint.c"
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
        tcb_t *thread = ((tcb_t *)(endpoint_ptr_get_epQueue_head(epptr)));

        /* Make endpoint idle */
        endpoint_ptr_set_state(epptr, EPState_Idle);
        endpoint_ptr_set_epQueue_head(epptr, 0);
        endpoint_ptr_set_epQueue_tail(epptr, 0);

        /* Set all blocked threads to restart */
        for (; thread; thread = thread->tcbEPNext) {

            reply_t *reply = ((reply_t *) (thread_state_get_replyObject(thread->tcbState)));
            if (reply != ((void *)0)) {
                reply_unlink(reply, thread);
            }
            if (seL4_Fault_get_seL4_FaultType(thread->tcbFault) == seL4_Fault_NullFault) {
                setThreadState(thread, ThreadState_Restart);
                possibleSwitchTo(thread);
            } else {
                setThreadState(thread, ThreadState_Inactive);
            }




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

            /* senders do not have reply objects in their state, and we are only cancelling sends */
            ;
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







        }
        ep_ptr_set_queue(epptr, queue);

        if (queue.head) {
            endpoint_ptr_set_state(epptr, EPState_Send);
        }

        rescheduleRequired();

        break;
    }

    default:
        halt();
    }
}


void reorderEP(endpoint_t *epptr, tcb_t *thread)
{
    tcb_queue_t queue = ep_ptr_get_queue(epptr);
    queue = tcbEPDequeue(thread, queue);
    queue = tcbEPAppend(thread, queue);
    ep_ptr_set_queue(epptr, queue);
}
# 1 "/home/koc034/Documents/newver/seL4/src/object/interrupt.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */




# 1 "gen_headers/api/invocation.h" 1

/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 ** SPDX-License-Identifier: GPL-2.0-only
 */

/* This header was generated by kernel/tools/invocation_header_gen.py.
 *
 * To add an invocation call number, edit libsel4/include/interfaces/sel4.xml.
 *
 */
# 11 "/home/koc034/Documents/newver/seL4/src/object/interrupt.c" 2
# 23 "/home/koc034/Documents/newver/seL4/src/object/interrupt.c"
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

        if (length < 3 || current_extra_caps.excaprefs[0] == ((void *)0)) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }
        irq_w = getSyscallArg(0, buffer);
        irq = (irq_w);
        index = getSyscallArg(1, buffer);
        depth = getSyscallArg(2, buffer);

        cnodeCap = current_extra_caps.excaprefs[0]->cap;

        status = Arch_checkIRQ(irq_w);
        if (status != EXCEPTION_NONE) {
            return status;
        }

        if (isIRQActive(irq)) {
            current_syscall_error.type = seL4_RevokeFirst;
            ;
            return EXCEPTION_SYSCALL_ERROR;
        }

        lu_ret = lookupTargetSlot(cnodeCap, index, depth);
        if (lu_ret.status != EXCEPTION_NONE) {
           
                                                                     ;
            return lu_ret.status;
        }
        destSlot = lu_ret.slot;

        status = ensureEmptySlot(destSlot);
        if (status != EXCEPTION_NONE) {
           
                                                                     ;
            return status;
        }

        setThreadState(ksCurThread, ThreadState_Restart);
        return invokeIRQControl(irq, destSlot, srcSlot);
    } else {
        return Arch_decodeIRQControlInvocation(invLabel, length, srcSlot, buffer);
    }
}

exception_t invokeIRQControl(irq_t irq, cte_t *handlerSlot, cte_t *controlSlot)
{
    setIRQState(IRQSignal, irq);
    cteInsert(cap_irq_handler_cap_new((irq)), controlSlot, handlerSlot);

    return EXCEPTION_NONE;
}

exception_t decodeIRQHandlerInvocation(word_t invLabel, irq_t irq)
{
    switch (invLabel) {
    case IRQAckIRQ:
        setThreadState(ksCurThread, ThreadState_Restart);
        invokeIRQHandler_AckIRQ(irq);
        return EXCEPTION_NONE;

    case IRQSetIRQHandler: {
        cap_t ntfnCap;
        cte_t *slot;

        if (current_extra_caps.excaprefs[0] == ((void *)0)) {
            current_syscall_error.type = seL4_TruncatedMessage;
            return EXCEPTION_SYSCALL_ERROR;
        }
        ntfnCap = current_extra_caps.excaprefs[0]->cap;
        slot = current_extra_caps.excaprefs[0];

        if (cap_get_capType(ntfnCap) != cap_notification_cap ||
            !cap_notification_cap_get_capNtfnCanSend(ntfnCap)) {
            if (cap_get_capType(ntfnCap) != cap_notification_cap) {
                ;
            } else {
                ;
            }
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(ksCurThread, ThreadState_Restart);
        invokeIRQHandler_SetIRQHandler(irq, ntfnCap, slot);
        return EXCEPTION_NONE;
    }

    case IRQClearIRQHandler:
        setThreadState(ksCurThread, ThreadState_Restart);
        invokeIRQHandler_ClearIRQHandler(irq);
        return EXCEPTION_NONE;

    default:
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }
}

void invokeIRQHandler_AckIRQ(irq_t irq)
{

    plic_complete_claim(irq);
# 147 "/home/koc034/Documents/newver/seL4/src/object/interrupt.c"
}

void invokeIRQHandler_SetIRQHandler(irq_t irq, cap_t cap, cte_t *slot)
{
    cte_t *irqSlot;

    irqSlot = intStateIRQNode + (irq);
    /** GHOSTUPD: "(True, gs_set_assn cteDeleteOne_'proc (-1))" */
    cteDeleteOne(irqSlot);
    cteInsert(cap, slot, irqSlot);
}

void invokeIRQHandler_ClearIRQHandler(irq_t irq)
{
    cte_t *irqSlot;

    irqSlot = intStateIRQNode + (irq);
    /** GHOSTUPD: "(True, gs_set_assn cteDeleteOne_'proc (-1))" */
    cteDeleteOne(irqSlot);
}

void deletingIRQHandler(irq_t irq)
{
    cte_t *slot;

    slot = intStateIRQNode + (irq);
    /** GHOSTUPD: "(True, gs_set_assn cteDeleteOne_'proc (ucast cap_notification_cap))" */
    cteDeleteOne(slot);
}

void deletedIRQHandler(irq_t irq)
{
    setIRQState(IRQInactive, irq);
}

void handleInterrupt(irq_t irq)
{
    if (__builtin_expect(!!((irq) > maxIRQ), 0)) {
        /* mask, ack and pretend it didn't happen. We assume that because
         * the interrupt controller for the platform returned this IRQ that
         * it is safe to use in mask and ack operations, even though it is
         * above the claimed maxIRQ. i.e. we're assuming maxIRQ is wrong */
        ((void)(0));
        maskInterrupt(true, irq);
        ackInterrupt(irq);
        return;
    }
    switch (intStateIRQTable[(irq)]) {
    case IRQSignal: {
        cap_t cap;

        cap = intStateIRQNode[(irq)].cap;

        if (cap_get_capType(cap) == cap_notification_cap &&
            cap_notification_cap_get_capNtfnCanSend(cap)) {
            sendSignal(((notification_t *)(cap_notification_cap_get_capNtfnPtr(cap))),
                       cap_notification_cap_get_capNtfnBadge(cap));
        } else {



        }



        break;
    }

    case IRQTimer:

        ackDeadlineIRQ();
        ksReprogram = true;




        break;







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



        break;

    default:
        /* No corresponding haskell error */
        halt();
    }

    ackInterrupt(irq);
}

bool_t isIRQActive(irq_t irq)
{
    return intStateIRQTable[(irq)] != IRQInactive;
}

void setIRQState(irq_state_t irqState, irq_t irq)
{
    intStateIRQTable[(irq)] = irqState;






    maskInterrupt(irqState == IRQInactive, irq);
}
# 1 "/home/koc034/Documents/newver/seL4/src/object/notification.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 19 "/home/koc034/Documents/newver/seL4/src/object/notification.c"
static inline tcb_queue_t __attribute__((__pure__)) ntfn_ptr_get_queue(notification_t *ntfnPtr)
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


static inline void maybeDonateSchedContext(tcb_t *tcb, notification_t *ntfnPtr)
{
    if (tcb->tcbSchedContext == ((void *)0)) {
        sched_context_t *sc = ((sched_context_t *) (notification_ptr_get_ntfnSchedContext(ntfnPtr)));
        if (sc != ((void *)0) && sc->scTcb == ((void *)0)) {
            schedContext_donate(sc, tcb);
            if (sc != ksCurSC) {
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
# 76 "/home/koc034/Documents/newver/seL4/src/object/notification.c"
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
                maybeDonateSchedContext(tcb, ntfnPtr); if (isSchedulable(tcb)) { { possibleSwitchTo(tcb); } }
# 108 "/home/koc034/Documents/newver/seL4/src/object/notification.c"
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
        ;

        /* Dequeue TCB */
        ntfn_queue = tcbEPDequeue(dest, ntfn_queue);
        ntfn_ptr_set_queue(ntfnPtr, ntfn_queue);

        /* set the thread state to idle if the queue is empty */
        if (!ntfn_queue.head) {
            notification_ptr_set_state(ntfnPtr, NtfnState_Idle);
        }

        setThreadState(dest, ThreadState_Running);
        setRegister(dest, badgeRegister, badge);
        maybeDonateSchedContext(dest, ntfnPtr); if (isSchedulable(dest)) { { possibleSwitchTo(dest); } }


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

    ntfnPtr = ((notification_t *)(cap_notification_cap_get_capNtfnPtr(cap)));

    switch (notification_ptr_get_state(ntfnPtr)) {
    case NtfnState_Idle:
    case NtfnState_Waiting: {
        tcb_queue_t ntfn_queue;

        if (isBlocking) {
            /* Block thread on notification object */
            thread_state_ptr_set_tsType(&thread->tcbState,
                                        ThreadState_BlockedOnNotification);
            thread_state_ptr_set_blockingObject(&thread->tcbState,
                                                ((word_t)(ntfnPtr)));

            maybeReturnSchedContext(ntfnPtr, thread);

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

        maybeDonateSchedContext(thread, ntfnPtr);

        break;
    }
}

void cancelAllSignals(notification_t *ntfnPtr)
{
    if (notification_ptr_get_state(ntfnPtr) == NtfnState_Waiting) {
        tcb_t *thread = ((tcb_t *)(notification_ptr_get_ntfnQueue_head(ntfnPtr)));

        notification_ptr_set_state(ntfnPtr, NtfnState_Idle);
        notification_ptr_set_ntfnQueue_head(ntfnPtr, 0);
        notification_ptr_set_ntfnQueue_tail(ntfnPtr, 0);

        /* Set all waiting threads to Restart */
        for (; thread; thread = thread->tcbEPNext) {
            setThreadState(thread, ThreadState_Restart);

            possibleSwitchTo(thread);



        }
        rescheduleRequired();
    }
}

void cancelSignal(tcb_t *threadPtr, notification_t *ntfnPtr)
{
    tcb_queue_t ntfn_queue;

    /* Haskell error "cancelSignal: notification object must be in a waiting" state */
    ;

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

    if (__builtin_expect(!!(tcb && notification_ptr_get_state(ntfnPtr) == NtfnState_Active), 1)) {
        badge = notification_ptr_get_ntfnMsgIdentifier(ntfnPtr);
        setRegister(tcb, badgeRegister, badge);
        notification_ptr_set_state(ntfnPtr, NtfnState_Idle);

        maybeDonateSchedContext(tcb, ntfnPtr);

    } else {
        halt();
    }
}

static inline void doUnbindNotification(notification_t *ntfnPtr, tcb_t *tcbptr)
{
    notification_ptr_set_ntfnBoundTCB(ntfnPtr, (word_t) 0);
    tcbptr->tcbBoundNotification = ((void *)0);
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


void reorderNTFN(notification_t *ntfnPtr, tcb_t *thread)
{
    tcb_queue_t queue = ntfn_ptr_get_queue(ntfnPtr);
    queue = tcbEPDequeue(thread, queue);
    queue = tcbEPAppend(thread, queue);
    ntfn_ptr_set_queue(ntfnPtr, queue);
}
# 1 "/home/koc034/Documents/newver/seL4/src/object/objecttype.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 22 "/home/koc034/Documents/newver/seL4/src/object/objecttype.c"
# 1 "/home/koc034/Documents/newver/seL4/include/object/schedcontrol.h" 1
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

       





exception_t decodeSchedControlInvocation(word_t label, cap_t cap, word_t length, word_t *buffer);
# 23 "/home/koc034/Documents/newver/seL4/src/object/objecttype.c" 2
# 33 "/home/koc034/Documents/newver/seL4/src/object/objecttype.c"
word_t getObjectSize(word_t t, word_t userObjSize)
{
    if (t >= seL4_NonArchObjectTypeCount) {
        return Arch_getObjectSize(t);
    } else {
        switch (t) {
        case seL4_TCBObject:
            return 10;
        case seL4_EndpointObject:
            return 4;
        case seL4_NotificationObject:
            return 6;
        case seL4_CapTableObject:
            return 5 + userObjSize;
        case seL4_UntypedObject:
            return userObjSize;

        case seL4_SchedContextObject:
            return userObjSize;
        case seL4_ReplyObject:
            return 5;

        default:
            halt();
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
            cancelAllIPC(((endpoint_t *)(cap_endpoint_cap_get_capEPPtr(cap))));
        }

        fc_ret.remainder = cap_null_cap_new();
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;

    case cap_notification_cap:
        if (final) {
            notification_t *ntfn = ((notification_t *)(cap_notification_cap_get_capNtfnPtr(cap)));

            schedContext_unbindNtfn(((sched_context_t *) (notification_ptr_get_ntfnSchedContext(ntfn))));

            unbindMaybeNotification(ntfn);
            cancelAllSignals(ntfn);
        }
        fc_ret.remainder = cap_null_cap_new();
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;

    case cap_reply_cap:

        if (final) {
            reply_t *reply = ((reply_t *) (cap_reply_cap_get_capReplyPtr(cap)));
            if (reply && reply->replyTCB) {
                switch (thread_state_get_tsType(reply->replyTCB->tcbState)) {
                case ThreadState_BlockedOnReply:
                    reply_remove(reply, reply->replyTCB);
                    break;
                case ThreadState_BlockedOnReceive:
                    reply_unlink(reply, reply->replyTCB);
                    break;
                default:
                    halt();
                }
            }
        }
        fc_ret.remainder = cap_null_cap_new();
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;

    case cap_null_cap:
    case cap_domain_cap:
        fc_ret.remainder = cap_null_cap_new();
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;
    }

    if (exposed) {
        halt();
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

            tcb = ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap)));
           
            cte_ptr = (((cte_t *)((word_t)(tcb)&~((1ul << (10))-1ul)))+(tcbCTable));
            unbindNotification(tcb);

            if (tcb->tcbSchedContext) {
                schedContext_completeYieldTo(tcb->tcbSchedContext->scYieldFrom);
                schedContext_unbindTCB(tcb->tcbSchedContext, tcb);
            }

            suspend(tcb);



            Arch_prepareThreadDelete(tcb);
            fc_ret.remainder =
                Zombie_new(
                    tcbCNodeEntries,
                    (1ul << (6)),
                    ((word_t)(cte_ptr))
                );
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        break;
    }


    case cap_sched_context_cap:
        if (final) {
            sched_context_t *sc = ((sched_context_t *) (cap_sched_context_cap_get_capSCPtr(cap)));
            schedContext_unbindAllTCBs(sc);
            schedContext_unbindNtfn(sc);
            if (sc->scReply) {
                ;
                sc->scReply->replyNext = call_stack_new(0, false);
                sc->scReply = ((void *)0);
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


    case cap_zombie_cap:
        fc_ret.remainder = cap;
        fc_ret.cleanupInfo = cap_null_cap_new();
        return fc_ret;

    case cap_irq_handler_cap:
        if (final) {
            irq_t irq = (cap_irq_handler_cap_get_capIRQ(cap));

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

bool_t __attribute__((__const__)) hasCancelSendRights(cap_t cap)
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

bool_t __attribute__((__const__)) sameRegionAs(cap_t cap_a, cap_t cap_b)
{
    switch (cap_get_capType(cap_a)) {
    case cap_untyped_cap:
        if (cap_get_capIsPhysical(cap_b)) {
            word_t aBase, bBase, aTop, bTop;

            aBase = (word_t)((word_t *)(cap_untyped_cap_get_capPtr(cap_a)));
            bBase = (word_t)cap_get_capPtr(cap_b);

            aTop = aBase + ((1ul << (cap_untyped_cap_get_capBlockSize(cap_a)))-1ul);
            bTop = bBase + ((1ul << (cap_get_capSizeBits(cap_b)))-1ul);

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

            return cap_reply_cap_get_capReplyPtr(cap_a) ==
                   cap_reply_cap_get_capReplyPtr(cap_b);




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

    default:
        if (isArchCap(cap_a) &&
            isArchCap(cap_b)) {
            return Arch_sameRegionAs(cap_a, cap_b);
        }
        break;
    }

    return false;
}

bool_t __attribute__((__const__)) sameObjectAs(cap_t cap_a, cap_t cap_b)
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

cap_t __attribute__((__const__)) updateCapData(bool_t preserve, word_t newData, cap_t cap)
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

        if (guardSize + cap_cnode_cap_get_capCNodeRadix(cap) > (1ul << (6))) {
            return cap_null_cap_new();
        } else {
            cap_t new_cap;

            guard = seL4_CNode_CapData_get_guard(w) & ((1ul << (guardSize))-1ul);
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

cap_t __attribute__((__const__)) maskCapRights(seL4_CapRights_t cap_rights, cap_t cap)
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

    case cap_sched_context_cap:
    case cap_sched_control_cap:

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
        halt(); /* Sentinel for invalid enums */
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
        tcb = ((tcb_t *)((word_t)regionBase + (1ul << ((10 - 1)))));
        /** AUXUPD: "(True, ptr_retyps 1
          (Ptr ((ptr_val \<acute>tcb) - ctcb_offset) :: (cte_C[5]) ptr)
            o (ptr_retyp \<acute>tcb))" */

        /* Setup non-zero parts of the TCB. */

        Arch_initContext(&tcb->tcbArch.tcbContext);



        tcb->tcbDomain = ksCurDomain;
# 541 "/home/koc034/Documents/newver/seL4/src/object/objecttype.c"
        return cap_thread_cap_new(((word_t)(tcb)));
    }

    case seL4_EndpointObject:
        /** AUXUPD: "(True, ptr_retyp
          (Ptr (ptr_val \<acute>regionBase) :: endpoint_C ptr))" */
        return cap_endpoint_cap_new(0, true, true, true, true,
                                    ((word_t)(regionBase)));

    case seL4_NotificationObject:
        /** AUXUPD: "(True, ptr_retyp
              (Ptr (ptr_val \<acute>regionBase) :: notification_C ptr))" */
        return cap_notification_cap_new(0, true, true,
                                        ((word_t)(regionBase)));

    case seL4_CapTableObject:
        /** AUXUPD: "(True, ptr_arr_retyps (2 ^ (unat \<acute>userSize))
          (Ptr (ptr_val \<acute>regionBase) :: cte_C ptr))" */
        /** GHOSTUPD: "(True, gs_new_cnodes (unat \<acute>userSize)
                                (ptr_val \<acute>regionBase)
                                (4 + unat \<acute>userSize))" */
        return cap_cnode_cap_new(userSize, 0, 0, ((word_t)(regionBase)));

    case seL4_UntypedObject:
        /*
         * No objects need to be created; instead, just insert caps into
         * the destination slots.
         */
        return cap_untyped_cap_new(0, !!deviceMemory, userSize, ((word_t)(regionBase)));


    case seL4_SchedContextObject:
        memzero(regionBase, (1ul << (userSize)));
        return cap_sched_context_cap_new(((word_t) (regionBase)), userSize);

    case seL4_ReplyObject:
        memzero(regionBase, 1UL << 5);
        return cap_reply_cap_new(((word_t) (regionBase)), true);


    default:
        halt();
    }
}

void createNewObjects(object_t t, cte_t *parent,
                      cte_t *destCNode, word_t destOffset, word_t destLength,
                      void *regionBase, word_t userSize, bool_t deviceMemory)
{
    word_t objectSize;
    void *nextFreeArea;
    word_t i;
    word_t totalObjectSize __attribute__((unused));

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


exception_t decodeInvocation(word_t invLabel, word_t length,
                             cptr_t capIndex, cte_t *slot, cap_t cap,
                             bool_t block, bool_t call,
                             bool_t canDonate, bool_t firstPhase, word_t *buffer)






{
    if (isArchCap(cap)) {
        return Arch_decodeInvocation(invLabel, length, capIndex,
                                     slot, cap, call, buffer);
    }

    switch (cap_get_capType(cap)) {
    case cap_null_cap:
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 0;
        return EXCEPTION_SYSCALL_ERROR;

    case cap_zombie_cap:
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 0;
        return EXCEPTION_SYSCALL_ERROR;

    case cap_endpoint_cap:
        if (__builtin_expect(!!(!cap_endpoint_cap_get_capCanSend(cap)), 0)) {
           
                               ;
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(ksCurThread, ThreadState_Restart);

        return performInvocation_Endpoint(
                   ((endpoint_t *)(cap_endpoint_cap_get_capEPPtr(cap))),
                   cap_endpoint_cap_get_capEPBadge(cap),
                   cap_endpoint_cap_get_capCanGrant(cap),
                   cap_endpoint_cap_get_capCanGrantReply(cap), block, call, canDonate);
# 669 "/home/koc034/Documents/newver/seL4/src/object/objecttype.c"
    case cap_notification_cap: {
        if (__builtin_expect(!!(!cap_notification_cap_get_capNtfnCanSend(cap)), 0)) {
           
                               ;
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(ksCurThread, ThreadState_Restart);
        return performInvocation_Notification(
                   ((notification_t *)(cap_notification_cap_get_capNtfnPtr(cap))),
                   cap_notification_cap_get_capNtfnBadge(cap));
    }


    case cap_reply_cap:
        setThreadState(ksCurThread, ThreadState_Restart);
        return performInvocation_Reply(
                   ksCurThread,
                   ((reply_t *) (cap_reply_cap_get_capReplyPtr(cap))),
                   cap_reply_cap_get_capReplyCanGrant(cap));
# 708 "/home/koc034/Documents/newver/seL4/src/object/objecttype.c"
    case cap_thread_cap:

        if (__builtin_expect(!!(firstPhase), 0)) {
            ;
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        return decodeTCBInvocation(invLabel, length, cap, slot, call, buffer);

    case cap_domain_cap:

        if (__builtin_expect(!!(firstPhase), 0)) {
            ;
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        return decodeDomainInvocation(invLabel, length, buffer);

    case cap_cnode_cap:

        if (__builtin_expect(!!(firstPhase), 0)) {
            ;
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }

        return decodeCNodeInvocation(invLabel, length, cap, buffer);

    case cap_untyped_cap:
        return decodeUntypedInvocation(invLabel, length, slot, cap, call, buffer);

    case cap_irq_control_cap:
        return decodeIRQControlInvocation(invLabel, length, slot, buffer);

    case cap_irq_handler_cap:
        return decodeIRQHandlerInvocation(invLabel,
                                          (cap_irq_handler_cap_get_capIRQ(cap)));


    case cap_sched_control_cap:
        if (__builtin_expect(!!(firstPhase), 0)) {
            ;
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
        return decodeSchedControlInvocation(invLabel, cap, length, buffer);

    case cap_sched_context_cap:
        if (__builtin_expect(!!(firstPhase), 0)) {
            ;
            current_syscall_error.type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
        return decodeSchedContextInvocation(invLabel, cap, buffer);

    default:
        halt();
    }
}


exception_t performInvocation_Endpoint(endpoint_t *ep, word_t badge,
                                       bool_t canGrant, bool_t canGrantReply,
                                       bool_t block, bool_t call, bool_t canDonate)
{
    sendIPC(block, call, badge, canGrant, canGrantReply, canDonate, ksCurThread, ep);

    return EXCEPTION_NONE;
}
# 795 "/home/koc034/Documents/newver/seL4/src/object/objecttype.c"
exception_t performInvocation_Notification(notification_t *ntfn, word_t badge)
{
    sendSignal(ntfn, badge);

    return EXCEPTION_NONE;
}


exception_t performInvocation_Reply(tcb_t *thread, reply_t *reply, bool_t canGrant)
{
    doReplyTransfer(thread, reply, canGrant);
    return EXCEPTION_NONE;
}
# 816 "/home/koc034/Documents/newver/seL4/src/object/objecttype.c"
word_t __attribute__((__const__)) cap_get_capSizeBits(cap_t cap)
{

    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {
    case cap_untyped_cap:
        return cap_untyped_cap_get_capBlockSize(cap);

    case cap_endpoint_cap:
        return 4;

    case cap_notification_cap:
        return 6;

    case cap_cnode_cap:
        return cap_cnode_cap_get_capCNodeRadix(cap) + 5;

    case cap_thread_cap:
        return 10;

    case cap_zombie_cap: {
        word_t type = cap_zombie_cap_get_capZombieType(cap);
        if (type == (1ul << (6))) {
            return 10;
        }
        return ((type) & ((1ul << (6))-1ul)) + 5;
    }

    case cap_null_cap:
        return 0;

    case cap_domain_cap:
        return 0;

    case cap_reply_cap:

        return 5;




    case cap_irq_control_cap:

    case cap_sched_control_cap:

        return 0;

    case cap_irq_handler_cap:
        return 0;


    case cap_sched_context_cap:
        return cap_sched_context_cap_get_capSCSizeBits(cap);


    default:
        return cap_get_archCapSizeBits(cap);
    }

}

/* Returns whether or not this capability has memory associated
 * with it or not. Referring to this as 'being physical' is to
 * match up with the Haskell and abstract specifications */
bool_t __attribute__((__const__)) cap_get_capIsPhysical(cap_t cap)
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

    case cap_sched_context_cap:

        return true;

    case cap_zombie_cap:
        return true;

    case cap_domain_cap:
        return false;

    case cap_reply_cap:

        return true;




    case cap_irq_control_cap:

    case cap_sched_control_cap:

        return false;

    case cap_irq_handler_cap:
        return false;

    default:
        return cap_get_archCapIsPhysical(cap);
    }
}

void *__attribute__((__const__)) cap_get_capPtr(cap_t cap)
{
    cap_tag_t ctag;

    ctag = cap_get_capType(cap);

    switch (ctag) {
    case cap_untyped_cap:
        return ((word_t *)(cap_untyped_cap_get_capPtr(cap)));

    case cap_endpoint_cap:
        return ((endpoint_t *)(cap_endpoint_cap_get_capEPPtr(cap)));

    case cap_notification_cap:
        return ((notification_t *)(cap_notification_cap_get_capNtfnPtr(cap)));

    case cap_cnode_cap:
        return ((cte_t *)(cap_cnode_cap_get_capCNodePtr(cap)));

    case cap_thread_cap:
        return (((cte_t *)((word_t)(cap_thread_cap_get_capTCBPtr(cap))&~((1ul << (10))-1ul)))+(0));

    case cap_zombie_cap:
        return ((cte_t *)(cap_zombie_cap_get_capZombiePtr(cap)));

    case cap_domain_cap:
        return ((void *)0);

    case cap_reply_cap:

        return ((reply_t *) (cap_reply_cap_get_capReplyPtr(cap)));




    case cap_irq_control_cap:

    case cap_sched_control_cap:

        return ((void *)0);

    case cap_irq_handler_cap:
        return ((void *)0);


    case cap_sched_context_cap:
        return ((sched_context_t *) (cap_sched_context_cap_get_capSCPtr(cap)));


    default:
        return cap_get_archCapPtr(cap);

    }
}

bool_t __attribute__((__const__)) isCapRevocable(cap_t derivedCap, cap_t srcCap)
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
# 1 "/home/koc034/Documents/newver/seL4/src/object/reply.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */



void reply_push(tcb_t *tcb_caller, tcb_t *tcb_callee, reply_t *reply, bool_t canDonate)
{
    sched_context_t *sc_donated = tcb_caller->tcbSchedContext;

    ;
    ;
    ;

    ;
    ;

    /* tcb caller should not be in a existing call stack */
    ;

    /* unlink callee and reply - they may not have been linked already,
     * if this rendesvous is occuring when seL4_Recv is called,
     * however, no harm in overring 0 with 0 */
    thread_state_ptr_set_replyObject(&tcb_callee->tcbState, 0);

    /* link caller and reply */
    reply->replyTCB = tcb_caller;
    thread_state_ptr_set_replyObject(&tcb_caller->tcbState, ((word_t) (reply)));
    setThreadState(tcb_caller, ThreadState_BlockedOnReply);

    if (sc_donated != ((void *)0) && tcb_callee->tcbSchedContext == ((void *)0) && canDonate) {
        reply_t *old_caller = sc_donated->scReply;

        /* check stack integrity */
       
                                                                                        ;

        /* push on to stack */
        reply->replyPrev = call_stack_new(((word_t) (old_caller)), false);
        if (old_caller) {
            old_caller->replyNext = call_stack_new(((word_t) (reply)), false);
        }
        reply->replyNext = call_stack_new(((word_t) (sc_donated)), true);
        sc_donated->scReply = reply;

        /* now do the actual donation */
        schedContext_donate(sc_donated, tcb_callee);
    }
}

/* Pop the head reply from the call stack */
void reply_pop(reply_t *reply, tcb_t *tcb)
{
    ;
    ;
    ;
    ;

    /* unlink tcb and reply */
    reply_unlink(reply, tcb);

    word_t next_ptr = call_stack_get_callStackPtr(reply->replyNext);
    word_t prev_ptr = call_stack_get_callStackPtr(reply->replyPrev);

    if (__builtin_expect(!!(next_ptr != 0), 1)) {
        ;

        /* give it back */
        if (tcb->tcbSchedContext == ((void *)0)) {
            /* only give the SC back if our SC is NULL. This prevents
             * strange behaviour when a thread is bound to an sc while it is
             * in the BlockedOnReply state. The semantics in this case are that the
             * SC cannot go back to the caller if the caller has received another one */
            schedContext_donate(((sched_context_t *) (next_ptr)), tcb);
        }

        ((sched_context_t *) (next_ptr))->scReply = ((reply_t *) (prev_ptr));
        if (prev_ptr != 0) {
            ((reply_t *) (prev_ptr))->replyNext = reply->replyNext;
            ;
        }

        reply->replyPrev = call_stack_new(0, false);
        reply->replyNext = call_stack_new(0, false);
    }
}

/* Remove a reply from the middle of the call stack */
void reply_remove(reply_t *reply, tcb_t *tcb)
{
    ;
    ;
    ;

    word_t next_ptr = call_stack_get_callStackPtr(reply->replyNext);
    word_t prev_ptr = call_stack_get_callStackPtr(reply->replyPrev);

    if (__builtin_expect(!!(next_ptr), 1)) {
        if (__builtin_expect(!!(call_stack_get_isHead(reply->replyNext)), 1)) {
            /* head of the call stack -> just pop */
            reply_pop(reply, tcb);
            return;
        }
        /* not the head, remove from middle - break the chain */
        ((reply_t *) (next_ptr))->replyPrev = call_stack_new(0, false);
        reply_unlink(((reply_t *) (reply)), tcb);
    } else {
        /* removing start of call chain */
        reply_unlink(reply, tcb);
    }

    if (prev_ptr) {
        ((reply_t *) (prev_ptr))->replyNext = call_stack_new(0, false);
    }

    reply->replyPrev = call_stack_new(0, false);
    reply->replyNext = call_stack_new(0, false);
}

void reply_remove_tcb(tcb_t *tcb)
{
    ;
    reply_t *reply = ((reply_t *) (thread_state_get_replyObject(tcb->tcbState)));
    word_t next_ptr = call_stack_get_callStackPtr(reply->replyNext);
    word_t prev_ptr = call_stack_get_callStackPtr(reply->replyPrev);

    if (next_ptr) {
        if (call_stack_get_isHead(reply->replyNext)) {
            ((sched_context_t *) (next_ptr))->scReply = ((void *)0);
        } else {
            ((reply_t *) (next_ptr))->replyPrev = call_stack_new(0, false);
        }
    }

    if (prev_ptr) {
        ((reply_t *) (prev_ptr))->replyNext = call_stack_new(0, false);
    }

    reply->replyPrev = call_stack_new(0, false);
    reply->replyNext = call_stack_new(0, false);
    reply_unlink(reply, tcb);
}
# 1 "/home/koc034/Documents/newver/seL4/src/object/schedcontext.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */




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
        halt();
    }

    return EXCEPTION_NONE;
}

static exception_t decodeSchedContext_UnbindObject(sched_context_t *sc)
{
    if (current_extra_caps.excaprefs[0] == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    cap_t cap = current_extra_caps.excaprefs[0]->cap;
    switch (cap_get_capType(cap)) {
    case cap_thread_cap:
        if (sc->scTcb != ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap)))) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        if (sc->scTcb == ksCurThread) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        break;
    case cap_notification_cap:
        if (sc->scNotification != ((notification_t *)(cap_notification_cap_get_capNtfnPtr(cap)))) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        break;

    default:
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;

    }

    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeSchedContext_UnbindObject(sc, cap);
}

static exception_t invokeSchedContext_Bind(sched_context_t *sc, cap_t cap)
{
    switch (cap_get_capType(cap)) {
    case cap_thread_cap:
        schedContext_bindTCB(sc, ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))));
        break;
    case cap_notification_cap:
        schedContext_bindNtfn(sc, ((notification_t *)(cap_notification_cap_get_capNtfnPtr(cap))));
        break;
    default:
        halt();
    }

    return EXCEPTION_NONE;
}

static exception_t decodeSchedContext_Bind(sched_context_t *sc)
{
    if (current_extra_caps.excaprefs[0] == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    cap_t cap = current_extra_caps.excaprefs[0]->cap;

    if (sc->scTcb != ((void *)0) || sc->scNotification != ((void *)0)) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    switch (cap_get_capType(cap)) {
    case cap_thread_cap:
        if (((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap)))->tcbSchedContext != ((void *)0)) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }

        break;
    case cap_notification_cap:
        if (notification_ptr_get_ntfnSchedContext(((notification_t *)(cap_notification_cap_get_capNtfnPtr(cap))))) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        break;
    default:
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeSchedContext_Bind(sc, cap);
}

static exception_t invokeSchedContext_Unbind(sched_context_t *sc)
{
    schedContext_unbindAllTCBs(sc);
    schedContext_unbindNtfn(sc);
    if (sc->scReply) {
        sc->scReply->replyNext = call_stack_new(0, false);
        sc->scReply = ((void *)0);
    }
    return EXCEPTION_NONE;
}
# 147 "/home/koc034/Documents/newver/seL4/src/object/schedcontext.c"
static inline void setConsumed(sched_context_t *sc, word_t *buffer)
{
    time_t consumed = schedContext_updateConsumed(sc);
    word_t length = mode_setTimeArg(0, consumed, buffer, ksCurThread);
    setRegister(ksCurThread, msgInfoRegister, wordFromMessageInfo(seL4_MessageInfo_new(0, 0, 0, length)));
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
        ;
    }

    /* if the tcb is in the scheduler, it's ready and sufficient.
     * Otherwise, check that it is ready and sufficient and if not,
     * place the thread in the release queue. This way, from this point,
     * if the thread isSchedulable, it is ready and sufficient.*/
    schedContext_resume(sc);

    bool_t return_now = true;
    if (isSchedulable(sc->scTcb)) {
        refill_unblock_check(sc);
        if (
            sc->scTcb->tcbPriority < ksCurThread->tcbPriority) {
            tcbSchedDequeue(sc->scTcb);
            tcbSchedEnqueue(sc->scTcb);
        } else {
            ksCurThread->tcbYieldTo = sc;
            sc->scYieldFrom = ksCurThread;
            tcbSchedDequeue(sc->scTcb);
            tcbSchedEnqueue(ksCurThread);
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
    if (sc->scTcb == ksCurThread) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (sc->scTcb == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (sc->scTcb->tcbPriority > ksCurThread->tcbMCP) {
       
                                                                                                          ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeSchedContext_YieldTo(sc, buffer);
}

exception_t decodeSchedContextInvocation(word_t label, cap_t cap, word_t *buffer)
{
    sched_context_t *sc = ((sched_context_t *) (cap_sched_context_cap_get_capSCPtr(cap)));

   

    switch (label) {
    case SchedContextConsumed:
        /* no decode */
        setThreadState(ksCurThread, ThreadState_Restart);
        return invokeSchedContext_Consumed(sc, buffer);
    case SchedContextBind:
        return decodeSchedContext_Bind(sc);
    case SchedContextUnbindObject:
        return decodeSchedContext_UnbindObject(sc);
    case SchedContextUnbind:
        /* no decode */
        if (sc->scTcb == ksCurThread) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        setThreadState(ksCurThread, ThreadState_Restart);
        return invokeSchedContext_Unbind(sc);
    case SchedContextYieldTo:
        return decodeSchedContext_YieldTo(sc, buffer);
    default:
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }
}

void schedContext_resume(sched_context_t *sc)
{
    ;
    if (__builtin_expect(!!(sc), 1) && isSchedulable(sc->scTcb)) {
        if (!(refill_ready(sc) && refill_sufficient(sc, 0))) {
            ;
            postpone(sc);
        }
    }
}

void schedContext_bindTCB(sched_context_t *sc, tcb_t *tcb)
{
    ;
    ;

    tcb->tcbSchedContext = sc;
    sc->scTcb = tcb;

    ;

    schedContext_resume(sc);
    if (isSchedulable(tcb)) {
        tcbSchedEnqueue(tcb);
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
    ;

    /* tcb must already be stalled at this point */
    if (tcb == ksCurThread) {
        rescheduleRequired();
    }

    tcbSchedDequeue(sc->scTcb);
    tcbReleaseRemove(sc->scTcb);

    sc->scTcb->tcbSchedContext = ((void *)0);
    sc->scTcb = ((void *)0);
}

void schedContext_unbindAllTCBs(sched_context_t *sc)
{
    if (sc->scTcb) {
        ;
        schedContext_unbindTCB(sc, sc->scTcb);
    }
}

void schedContext_donate(sched_context_t *sc, tcb_t *to)
{
    ;
    ;
    ;

    tcb_t *from = sc->scTcb;
    if (from) {
        ;
        tcbSchedDequeue(from);
        from->tcbSchedContext = ((void *)0);
        if (from == ksCurThread || from == ksSchedulerAction) {
            rescheduleRequired();
        }
    }
    sc->scTcb = to;
    to->tcbSchedContext = sc;

    ;
}

void schedContext_bindNtfn(sched_context_t *sc, notification_t *ntfn)
{
    notification_ptr_set_ntfnSchedContext(ntfn, ((word_t) (sc)));
    sc->scNotification = ntfn;
}

void schedContext_unbindNtfn(sched_context_t *sc)
{
    if (sc && sc->scNotification) {
        notification_ptr_set_ntfnSchedContext(sc->scNotification, ((word_t) (0)));
        sc->scNotification = ((void *)0);
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
        tcb->tcbYieldTo->scYieldFrom = ((void *)0);
        tcb->tcbYieldTo = ((void *)0);
    }
}

void schedContext_completeYieldTo(tcb_t *yielder)
{
    if (yielder && yielder->tcbYieldTo) {
        setConsumed(yielder->tcbYieldTo, lookupIPCBuffer(true, yielder));
        schedContext_cancelYieldTo(yielder);
    }
}
# 1 "/home/koc034/Documents/newver/seL4/src/object/schedcontrol.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */







static exception_t invokeSchedControl_Configure(sched_context_t *target, word_t core, ticks_t budget,
                                                ticks_t period, word_t max_refills, word_t badge)
{

    target->scBadge = badge;

    /* don't modify parameters of tcb while it is in a sorted queue */
    if (target->scTcb) {
        /* possibly stall a remote core */
        ;
        /* remove from scheduler */
        tcbReleaseRemove(target->scTcb);
        tcbSchedDequeue(target->scTcb);
        /* bill the current consumed amount before adjusting the params */
        if (ksCurSC == target) {



                /* This could potentially mutate state but if it returns
                 * true no state was modified, thus removing it should
                 * be the same. */
                ;
                commitTime();






        }
    }

    if (budget == period) {
        /* this is a cool hack: for round robin, we set the
         * period to 0, which means that the budget will always be ready to be refilled
         * and avoids some special casing.
         */
        period = 0;
        max_refills = 2u;
    }

    if ( target->scRefillMax > 0 && target->scTcb
        && isRunnable(target->scTcb)) {
        /* the scheduling context is active - it can be used, so
         * we need to preserve the bandwidth */
        refill_update(target, period, budget, max_refills);
    } else {
        /* the scheduling context isn't active - it's budget is not being used, so
         * we can just populate the parameters from now */
        refill_new(target, max_refills, budget, period);
    }
# 72 "/home/koc034/Documents/newver/seL4/src/object/schedcontrol.c"
    if (target->scTcb && target->scRefillMax > 0) {
        schedContext_resume(target);
        if (true) {
            if (isRunnable(target->scTcb) && target->scTcb != ksCurThread) {
                possibleSwitchTo(target->scTcb);
            }
        } else if (isRunnable(target->scTcb)) {
            tcbSchedEnqueue(target->scTcb);
        }
        if (target->scTcb == ksCurThread) {
            rescheduleRequired();
        }
    }

    return EXCEPTION_NONE;
}

static exception_t decodeSchedControl_Configure(word_t length, cap_t cap, word_t *buffer)
{
    if (current_extra_caps.excaprefs[0] == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (length < ((sizeof(ticks_t) / sizeof(word_t)) * 2) + 2) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    time_t budget_us = mode_parseTimeArg(0, buffer);
    time_t period_us = mode_parseTimeArg((sizeof(ticks_t) / sizeof(word_t)), buffer);
    word_t extra_refills = getSyscallArg((sizeof(ticks_t) / sizeof(word_t)) * 2, buffer);
    word_t badge = getSyscallArg((sizeof(ticks_t) / sizeof(word_t)) * 2 + 1, buffer);

    cap_t targetCap = current_extra_caps.excaprefs[0]->cap;
    if (__builtin_expect(!!(cap_get_capType(targetCap) != cap_sched_context_cap), 0)) {
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (budget_us > ((60 * 60 * 1000llu * 1000llu)) || budget_us < (2u * getKernelWcetUs() * 1)) {
        ;
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = (2u * getKernelWcetUs() * 1);
        current_syscall_error.rangeErrorMax = ((60 * 60 * 1000llu * 1000llu));
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (period_us > ((60 * 60 * 1000llu * 1000llu)) || period_us < (2u * getKernelWcetUs() * 1)) {
        ;
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = (2u * getKernelWcetUs() * 1);
        current_syscall_error.rangeErrorMax = ((60 * 60 * 1000llu * 1000llu));
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (budget_us > period_us) {
        ;
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = (2u * getKernelWcetUs() * 1);
        current_syscall_error.rangeErrorMax = period_us;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (extra_refills + 2u > refill_absolute_max(targetCap)) {
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 0;
        current_syscall_error.rangeErrorMax = refill_absolute_max(targetCap) - 2u;
       

                                                      ;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeSchedControl_Configure(((sched_context_t *) (cap_sched_context_cap_get_capSCPtr(targetCap))),
                                        cap_sched_control_cap_get_core(cap),
                                        usToTicks(budget_us),
                                        usToTicks(period_us),
                                        extra_refills + 2u,
                                        badge);
}

exception_t decodeSchedControlInvocation(word_t label, cap_t cap, word_t length, word_t *buffer)
{
    switch (label) {
    case SchedControlConfigure:
        return decodeSchedControl_Configure(length, cap, buffer);
    default:
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }
}
# 1 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */




# 1 "gen_headers/api/invocation.h" 1

/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 ** SPDX-License-Identifier: GPL-2.0-only
 */

/* This header was generated by kernel/tools/invocation_header_gen.py.
 *
 * To add an invocation call number, edit libsel4/include/interfaces/sel4.xml.
 *
 */
# 11 "/home/koc034/Documents/newver/seL4/src/object/tcb.c" 2
# 32 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
static exception_t checkPrio(prio_t prio, tcb_t *auth)
{
    prio_t mcp;

    mcp = auth->tcbMCP;

    /* system invariant: existing MCPs are bounded */
    ;

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

    ksReadyQueuesL1Bitmap[dom] |= (1ul << (l1index));
    /* we invert the l1 index when accessed the 2nd level of the bitmap in
       order to increase the liklihood that high prio threads l2 index word will
       be on the same cache line as the l1 index word - this makes sure the
       fastpath is fastest for high prio threads */
    ksReadyQueuesL2Bitmap[dom][l1index_inverted] |= (1ul << (prio & ((1ul << (6))-1ul)));
}

static inline void removeFromBitmap(word_t cpu, word_t dom, word_t prio)
{
    word_t l1index;
    word_t l1index_inverted;

    l1index = prio_to_l1index(prio);
    l1index_inverted = invert_l1index(l1index);
    ksReadyQueuesL2Bitmap[dom][l1index_inverted] &= ~(1ul << (prio & ((1ul << (6))-1ul)));
    if (__builtin_expect(!!(!ksReadyQueuesL2Bitmap[dom][l1index_inverted]), 0)) {
        ksReadyQueuesL1Bitmap[dom] &= ~(1ul << (l1index));
    }
}

/* Add TCB to the head of a scheduler queue */
void tcbSchedEnqueue(tcb_t *tcb)
{

    ;
    ;


    if (!thread_state_get_tcbQueued(tcb->tcbState)) {
        tcb_queue_t queue;
        dom_t dom;
        prio_t prio;
        word_t idx;

        dom = tcb->tcbDomain;
        prio = tcb->tcbPriority;
        idx = ready_queues_index(dom, prio);
        queue = ksReadyQueues[idx];

        if (!queue.end) { /* Empty list */
            queue.end = tcb;
            addToBitmap(0, dom, prio);
        } else {
            queue.head->tcbSchedPrev = tcb;
        }
        tcb->tcbSchedPrev = ((void *)0);
        tcb->tcbSchedNext = queue.head;
        queue.head = tcb;

        ksReadyQueues[idx] = queue;

        thread_state_ptr_set_tcbQueued(&tcb->tcbState, true);
    }
}

/* Add TCB to the end of a scheduler queue */
void tcbSchedAppend(tcb_t *tcb)
{

    ;
    ;
    ;

    if (!thread_state_get_tcbQueued(tcb->tcbState)) {
        tcb_queue_t queue;
        dom_t dom;
        prio_t prio;
        word_t idx;

        dom = tcb->tcbDomain;
        prio = tcb->tcbPriority;
        idx = ready_queues_index(dom, prio);
        queue = ksReadyQueues[idx];

        if (!queue.head) { /* Empty list */
            queue.head = tcb;
            addToBitmap(0, dom, prio);
        } else {
            queue.end->tcbSchedNext = tcb;
        }
        tcb->tcbSchedPrev = queue.end;
        tcb->tcbSchedNext = ((void *)0);
        queue.end = tcb;

        ksReadyQueues[idx] = queue;

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
        queue = ksReadyQueues[idx];

        if (tcb->tcbSchedPrev) {
            tcb->tcbSchedPrev->tcbSchedNext = tcb->tcbSchedNext;
        } else {
            queue.head = tcb->tcbSchedNext;
            if (__builtin_expect(!!(!tcb->tcbSchedNext), 1)) {
                removeFromBitmap(0, dom, prio);
            }
        }

        if (tcb->tcbSchedNext) {
            tcb->tcbSchedNext->tcbSchedPrev = tcb->tcbSchedPrev;
        } else {
            queue.end = tcb->tcbSchedPrev;
        }

        ksReadyQueues[idx] = queue;

        thread_state_ptr_set_tcbQueued(&tcb->tcbState, false);
    }
}
# 241 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
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


void tcbReleaseRemove(tcb_t *tcb)
{
    if (__builtin_expect(!!(thread_state_get_tcbInReleaseQueue(tcb->tcbState)), 1)) {
        if (tcb->tcbSchedPrev) {
            tcb->tcbSchedPrev->tcbSchedNext = tcb->tcbSchedNext;
        } else {
            ksReleaseHead = tcb->tcbSchedNext;
            /* the head has changed, we might need to set a new timeout */
            ksReprogram = true;
        }

        if (tcb->tcbSchedNext) {
            tcb->tcbSchedNext->tcbSchedPrev = tcb->tcbSchedPrev;
        }

        tcb->tcbSchedNext = ((void *)0);
        tcb->tcbSchedPrev = ((void *)0);
        thread_state_ptr_set_tcbInReleaseQueue(&tcb->tcbState, false);
    }
}

void tcbReleaseEnqueue(tcb_t *tcb)
{
    ;
    ;

    tcb_t *before = ((void *)0);
    tcb_t *after = ksReleaseHead;

    /* find our place in the ordered queue */
    while (after != ((void *)0) &&
           refill_head(tcb->tcbSchedContext)->rTime >= refill_head(after->tcbSchedContext)->rTime) {
        before = after;
        after = after->tcbSchedNext;
    }

    if (before == ((void *)0)) {
        /* insert at head */
        ksReleaseHead = tcb;
        ksReprogram = true;
    } else {
        before->tcbSchedNext = tcb;
    }

    if (after != ((void *)0)) {
        after->tcbSchedPrev = tcb;
    }

    tcb->tcbSchedNext = after;
    tcb->tcbSchedPrev = before;

    thread_state_ptr_set_tcbInReleaseQueue(&tcb->tcbState, true);
}

tcb_t *tcbReleaseDequeue(void)
{
    ;
    ;
    ;

    tcb_t *detached_head = ksReleaseHead;
    ksReleaseHead = ksReleaseHead->tcbSchedNext;

    if (ksReleaseHead) {
        ksReleaseHead->tcbSchedPrev = ((void *)0);
    }

    if (detached_head->tcbSchedNext) {
        detached_head->tcbSchedNext->tcbSchedPrev = ((void *)0);
        detached_head->tcbSchedNext = ((void *)0);
    }

    thread_state_ptr_set_tcbInReleaseQueue(&detached_head->tcbState, false);
    ksReprogram = true;

    return detached_head;
}


cptr_t __attribute__((__pure__)) getExtraCPtr(word_t *bufferPtr, word_t i)
{
    return (cptr_t)bufferPtr[seL4_MsgMaxLength + 2 + i];
}

void setExtraBadge(word_t *bufferPtr, word_t badge,
                   word_t i)
{
    bufferPtr[seL4_MsgMaxLength + 2 + i] = badge;
}
# 382 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
extra_caps_t current_extra_caps;

exception_t lookupExtraCaps(tcb_t *thread, word_t *bufferPtr, seL4_MessageInfo_t info)
{
    lookupSlot_raw_ret_t lu_ret;
    cptr_t cptr;
    word_t i, length;

    if (!bufferPtr) {
        current_extra_caps.excaprefs[0] = ((void *)0);
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
    if (i < ((1ul<<(seL4_MsgExtraCapBits))-1)) {
        current_extra_caps.excaprefs[i] = ((void *)0);
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
# 746 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
static exception_t invokeSetTLSBase(tcb_t *thread, word_t tls_base)
{
    setRegister(thread, TLS_BASE, tls_base);
    if (thread == ksCurThread) {
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
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tls_base = getSyscallArg(0, buffer);

    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeSetTLSBase(((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))), tls_base);
}

/* The following functions sit in the syscall error monad, but include the
 * exception cases for the preemptible bottom end, as they call the invoke
 * functions directly.  This is a significant deviation from the Haskell
 * spec. */
exception_t decodeTCBInvocation(word_t invLabel, word_t length, cap_t cap,
                                cte_t *slot, bool_t call, word_t *buffer)
{
    /* Stall the core if we are operating on a remote TCB that is currently running */
   

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
        setThreadState(ksCurThread, ThreadState_Restart);
        return invokeTCB_Suspend(
                   ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))));

    case TCBResume:
        setThreadState(ksCurThread, ThreadState_Restart);
        return invokeTCB_Resume(
                   ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))));

    case TCBConfigure:
        return decodeTCBConfigure(cap, length, slot, buffer);

    case TCBSetPriority:
        return decodeSetPriority(cap, length, buffer);

    case TCBSetMCPriority:
        return decodeSetMCPriority(cap, length, buffer);

    case TCBSetSchedParams:

        return decodeSetSchedParams(cap, length, slot, buffer);




    case TCBSetIPCBuffer:
        return decodeSetIPCBuffer(cap, length, slot, buffer);

    case TCBSetSpace:
        return decodeSetSpace(cap, length, slot, buffer);

    case TCBBindNotification:
        return decodeBindNotification(cap);

    case TCBUnbindNotification:
        return decodeUnbindNotification(cap);


    case TCBSetTimeoutEndpoint:
        return decodeSetTimeoutEndpoint(cap, slot);







        /* There is no notion of arch specific TCB invocations so this needs to go here */
# 864 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
    case TCBSetTLSBase:
        return decodeSetTLSBase(cap, length, buffer);

    default:
        /* Haskell: "throw IllegalOperation" */
        ;
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

    if (length < 1 || current_extra_caps.excaprefs[0] == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    flags = getSyscallArg(0, buffer);

    transferArch = Arch_decodeTransfer(flags >> 8);

    source_cap = current_extra_caps.excaprefs[0]->cap;

    if (cap_get_capType(source_cap) == cap_thread_cap) {
        srcTCB = ((tcb_t *)(cap_thread_cap_get_capTCBPtr(source_cap)));
    } else {
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeTCB_CopyRegisters(
               ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))), srcTCB,
               flags & (1ul << (CopyRegisters_suspendSource)),
               flags & (1ul << (CopyRegisters_resumeTarget)),
               flags & (1ul << (CopyRegisters_transferFrame)),
               flags & (1ul << (CopyRegisters_transferInteger)),
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
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    flags = getSyscallArg(0, buffer);
    n = getSyscallArg(1, buffer);

    if (n < 1 || n > n_frameRegisters + n_gpRegisters) {
       
                         ;
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 1;
        current_syscall_error.rangeErrorMax = n_frameRegisters +
                                              n_gpRegisters;
        return EXCEPTION_SYSCALL_ERROR;
    }

    transferArch = Arch_decodeTransfer(flags >> 8);

    thread = ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap)));
    if (thread == ksCurThread) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeTCB_ReadRegisters(
               ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))),
               flags & (1ul << (ReadRegisters_suspend)),
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
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    flags = getSyscallArg(0, buffer);
    w = getSyscallArg(1, buffer);

    if (length - 2 < w) {
       
                                            ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    transferArch = Arch_decodeTransfer(flags >> 8);

    thread = ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap)));
    if (thread == ksCurThread) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeTCB_WriteRegisters(thread,
                                    flags & (1ul << (WriteRegisters_resume)),
                                    w, transferArch, buffer);
}


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


/* TCBConfigure batches SetIPCBuffer and parts of SetSpace. */
exception_t decodeTCBConfigure(cap_t cap, word_t length, cte_t *slot, word_t *buffer)
{
    cte_t *bufferSlot, *cRootSlot, *vRootSlot;
    cap_t bufferCap, cRootCap, vRootCap;
    deriveCap_ret_t dc_ret;
    word_t cRootData, vRootData, bufferAddr;





    if (length < 3 || current_extra_caps.excaprefs[0] == ((void *)0)
        || current_extra_caps.excaprefs[1] == ((void *)0)
        || current_extra_caps.excaprefs[2] == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }


    cRootData = getSyscallArg(0, buffer);
    vRootData = getSyscallArg(1, buffer);
    bufferAddr = getSyscallArg(2, buffer);







    cRootSlot = current_extra_caps.excaprefs[0];
    cRootCap = current_extra_caps.excaprefs[0]->cap;
    vRootSlot = current_extra_caps.excaprefs[1];
    vRootCap = current_extra_caps.excaprefs[1]->cap;
    bufferSlot = current_extra_caps.excaprefs[2];
    bufferCap = current_extra_caps.excaprefs[2]->cap;

    if (bufferAddr == 0) {
        bufferSlot = ((void *)0);
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
            (((cte_t *)((word_t)(cap_thread_cap_get_capTCBPtr(cap))&~((1ul << (10))-1ul)))+(tcbCTable))) ||
        slotCapLongRunningDelete(
            (((cte_t *)((word_t)(cap_thread_cap_get_capTCBPtr(cap))&~((1ul << (10))-1ul)))+(tcbVTable)))) {
        ;
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
        ;
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
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);

    return invokeTCB_ThreadControlCaps(
               ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))), slot,
               cap_null_cap_new(), ((void *)0),
               cap_null_cap_new(), ((void *)0),
               cRootCap, cRootSlot,
               vRootCap, vRootSlot,
               bufferAddr, bufferCap,
               bufferSlot, thread_control_caps_update_space |
               thread_control_caps_update_ipc_buffer);
# 1145 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
}

exception_t decodeSetPriority(cap_t cap, word_t length, word_t *buffer)
{
    if (length < 1 || current_extra_caps.excaprefs[0] == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    prio_t newPrio = getSyscallArg(0, buffer);
    cap_t authCap = current_extra_caps.excaprefs[0]->cap;

    if (cap_get_capType(authCap) != cap_thread_cap) {
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcb_t *authTCB = ((tcb_t *)(cap_thread_cap_get_capTCBPtr(authCap)));
    exception_t status = checkPrio(newPrio, authTCB);
    if (status != EXCEPTION_NONE) {
       
                                                                           ;
        return status;
    }

    setThreadState(ksCurThread, ThreadState_Restart);

    return invokeTCB_ThreadControlSched(
               ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))), ((void *)0),
               cap_null_cap_new(), ((void *)0),
               0, newPrio,
               ((void *)0), thread_control_sched_update_priority);
# 1189 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
}

exception_t decodeSetMCPriority(cap_t cap, word_t length, word_t *buffer)
{
    if (length < 1 || current_extra_caps.excaprefs[0] == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    prio_t newMcp = getSyscallArg(0, buffer);
    cap_t authCap = current_extra_caps.excaprefs[0]->cap;

    if (cap_get_capType(authCap) != cap_thread_cap) {
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcb_t *authTCB = ((tcb_t *)(cap_thread_cap_get_capTCBPtr(authCap)));
    exception_t status = checkPrio(newMcp, authTCB);
    if (status != EXCEPTION_NONE) {
       
                                                                          ;
        return status;
    }

    setThreadState(ksCurThread, ThreadState_Restart);

    return invokeTCB_ThreadControlSched(
               ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))), ((void *)0),
               cap_null_cap_new(), ((void *)0),
               newMcp, 0,
               ((void *)0), thread_control_sched_update_mcp);
# 1233 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
}


exception_t decodeSetTimeoutEndpoint(cap_t cap, cte_t *slot)
{
    if (current_extra_caps.excaprefs[0] == ((void *)0)) {
        ;
        return EXCEPTION_SYSCALL_ERROR;
    }

    cte_t *thSlot = current_extra_caps.excaprefs[0];
    cap_t thCap = current_extra_caps.excaprefs[0]->cap;

    /* timeout handler */
    if (!validFaultHandler(thCap)) {
        ;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeTCB_ThreadControlCaps(
               ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))), slot,
               cap_null_cap_new(), ((void *)0),
               thCap, thSlot,
               cap_null_cap_new(), ((void *)0),
               cap_null_cap_new(), ((void *)0),
               0, cap_null_cap_new(), ((void *)0),
               thread_control_caps_update_timeout);
}



exception_t decodeSetSchedParams(cap_t cap, word_t length, cte_t *slot, word_t *buffer)



{
    if (length < 2 || current_extra_caps.excaprefs[0] == ((void *)0)

        || current_extra_caps.excaprefs[1] == ((void *)0) || current_extra_caps.excaprefs[2] == ((void *)0)

       ) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    prio_t newMcp = getSyscallArg(0, buffer);
    prio_t newPrio = getSyscallArg(1, buffer);
    cap_t authCap = current_extra_caps.excaprefs[0]->cap;

    cap_t scCap = current_extra_caps.excaprefs[1]->cap;
    cte_t *fhSlot = current_extra_caps.excaprefs[2];
    cap_t fhCap = current_extra_caps.excaprefs[2]->cap;


    if (cap_get_capType(authCap) != cap_thread_cap) {
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcb_t *authTCB = ((tcb_t *)(cap_thread_cap_get_capTCBPtr(authCap)));
    exception_t status = checkPrio(newMcp, authTCB);
    if (status != EXCEPTION_NONE) {
       
                                                                          ;
        return status;
    }

    status = checkPrio(newPrio, authTCB);
    if (status != EXCEPTION_NONE) {
       
                                                                           ;
        return status;
    }


    tcb_t *tcb = ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap)));
    sched_context_t *sc = ((void *)0);
    switch (cap_get_capType(scCap)) {
    case cap_sched_context_cap:
        sc = ((sched_context_t *) (cap_sched_context_cap_get_capSCPtr(scCap)));
        if (tcb->tcbSchedContext) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        if (sc->scTcb) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        break;
    case cap_null_cap:
        if (tcb == ksCurThread) {
            ;
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
        }
        break;
    default:
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 2;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (!validFaultHandler(fhCap)) {
        ;
        current_syscall_error.type = seL4_InvalidCapability;
        current_syscall_error.invalidCapNumber = 3;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);

    return invokeTCB_ThreadControlSched(
               ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))), slot,
               fhCap, fhSlot,
               newMcp, newPrio,
               sc,
               thread_control_sched_update_mcp |
               thread_control_sched_update_priority |
               thread_control_sched_update_sc |
               thread_control_sched_update_fault);
# 1371 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
}


exception_t decodeSetIPCBuffer(cap_t cap, word_t length, cte_t *slot, word_t *buffer)
{
    cptr_t cptr_bufferPtr;
    cap_t bufferCap;
    cte_t *bufferSlot;

    if (length < 1 || current_extra_caps.excaprefs[0] == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    cptr_bufferPtr = getSyscallArg(0, buffer);
    bufferSlot = current_extra_caps.excaprefs[0];
    bufferCap = current_extra_caps.excaprefs[0]->cap;

    if (cptr_bufferPtr == 0) {
        bufferSlot = ((void *)0);
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

    setThreadState(ksCurThread, ThreadState_Restart);

    return invokeTCB_ThreadControlCaps(
               ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))), slot,
               cap_null_cap_new(), ((void *)0),
               cap_null_cap_new(), ((void *)0),
               cap_null_cap_new(), ((void *)0),
               cap_null_cap_new(), ((void *)0),
               cptr_bufferPtr, bufferCap,
               bufferSlot, thread_control_caps_update_ipc_buffer);
# 1427 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
}






exception_t decodeSetSpace(cap_t cap, word_t length, cte_t *slot, word_t *buffer)
{
    word_t cRootData, vRootData;
    cte_t *cRootSlot, *vRootSlot;
    cap_t cRootCap, vRootCap;
    deriveCap_ret_t dc_ret;

    if (length < 2 || current_extra_caps.excaprefs[0] == ((void *)0)
        || current_extra_caps.excaprefs[1] == ((void *)0)

        || current_extra_caps.excaprefs[2] == ((void *)0)

       ) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }


    cRootData = getSyscallArg(0, buffer);
    vRootData = getSyscallArg(1, buffer);

    cte_t *fhSlot = current_extra_caps.excaprefs[0];
    cap_t fhCap = current_extra_caps.excaprefs[0]->cap;
    cRootSlot = current_extra_caps.excaprefs[1];
    cRootCap = current_extra_caps.excaprefs[1]->cap;
    vRootSlot = current_extra_caps.excaprefs[2];
    vRootCap = current_extra_caps.excaprefs[2]->cap;
# 1473 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
    if (slotCapLongRunningDelete(
            (((cte_t *)((word_t)(cap_thread_cap_get_capTCBPtr(cap))&~((1ul << (10))-1ul)))+(tcbCTable))) ||
        slotCapLongRunningDelete(
            (((cte_t *)((word_t)(cap_thread_cap_get_capTCBPtr(cap))&~((1ul << (10))-1ul)))+(tcbVTable)))) {
        ;
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
        ;
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
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }


    /* fault handler */
    if (!validFaultHandler(fhCap)) {
        ;
        current_syscall_error.invalidCapNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }


    setThreadState(ksCurThread, ThreadState_Restart);

    return invokeTCB_ThreadControlCaps(
               ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap))), slot,
               fhCap, fhSlot,
               cap_null_cap_new(), ((void *)0),
               cRootCap, cRootSlot,
               vRootCap, vRootSlot,
               0, cap_null_cap_new(), ((void *)0), thread_control_caps_update_space | thread_control_caps_update_fault);
# 1541 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
}

exception_t decodeDomainInvocation(word_t invLabel, word_t length, word_t *buffer)
{
    word_t domain;
    cap_t tcap;

    if (__builtin_expect(!!(invLabel != DomainSetSet), 0)) {
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (__builtin_expect(!!(length == 0), 0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    } else {
        domain = getSyscallArg(0, buffer);
        if (domain >= 16) {
           
                                                 ;
            current_syscall_error.type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 0;
            return EXCEPTION_SYSCALL_ERROR;
        }
    }

    if (__builtin_expect(!!(current_extra_caps.excaprefs[0] == ((void *)0)), 0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcap = current_extra_caps.excaprefs[0]->cap;
    if (__builtin_expect(!!(cap_get_capType(tcap) != cap_thread_cap), 0)) {
        ;
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);
    setDomain(((tcb_t *)(cap_thread_cap_get_capTCBPtr(tcap))), domain);
    return EXCEPTION_NONE;
}

exception_t decodeBindNotification(cap_t cap)
{
    notification_t *ntfnPtr;
    tcb_t *tcb;
    cap_t ntfn_cap;

    if (current_extra_caps.excaprefs[0] == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    tcb = ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap)));

    if (tcb->tcbBoundNotification) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    ntfn_cap = current_extra_caps.excaprefs[0]->cap;

    if (cap_get_capType(ntfn_cap) == cap_notification_cap) {
        ntfnPtr = ((notification_t *)(cap_notification_cap_get_capNtfnPtr(ntfn_cap)));
    } else {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if (!cap_notification_cap_get_capNtfnCanReceive(ntfn_cap)) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    if ((tcb_t *)notification_ptr_get_ntfnQueue_head(ntfnPtr)
        || (tcb_t *)notification_ptr_get_ntfnBoundTCB(ntfnPtr)) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }


    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeTCB_NotificationControl(tcb, ntfnPtr);
}

exception_t decodeUnbindNotification(cap_t cap)
{
    tcb_t *tcb;

    tcb = ((tcb_t *)(cap_thread_cap_get_capTCBPtr(cap)));

    if (!tcb->tcbBoundNotification) {
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeTCB_NotificationControl(tcb, ((void *)0));
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


static __attribute__((noinline)) exception_t installTCBCap(tcb_t *target, cap_t tCap, cte_t *slot,
                                        tcb_cnode_index_t index, cap_t newCap, cte_t *srcSlot)
{
    cte_t *rootSlot = (((cte_t *)((word_t)(target)&~((1ul << (10))-1ul)))+(index));
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

        bufferSlot = (((cte_t *)((word_t)(target)&~((1ul << (10))-1ul)))+(tcbBuffer));
        e = cteDelete(bufferSlot, true);
        if (e != EXCEPTION_NONE) {
            return e;
        }
        target->tcbIPCBuffer = bufferAddr;

        if (bufferSrcSlot && sameObjectAs(bufferCap, bufferSrcSlot->cap) &&
            sameObjectAs(tCap, slot->cap)) {
            cteInsert(bufferCap, bufferSrcSlot, bufferSlot);
        }

        if (target == ksCurThread) {
            rescheduleRequired();
        }
    }

    return EXCEPTION_NONE;
}
# 1823 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
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
        if (sc != ((void *)0) && sc != target->tcbSchedContext) {
            schedContext_bindTCB(sc, target);
        } else if (sc == ((void *)0) && target->tcbSchedContext != ((void *)0)) {
            schedContext_unbindTCB(target->tcbSchedContext, target);
        }
    }

    return EXCEPTION_NONE;
}


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

    if (dest == ksCurThread) {
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

    thread = ksCurThread;

    if (suspendSource) {
        suspend(tcb_src);
    }

    e = Arch_performTransfer(arch, tcb_src, ksCurThread);
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

        if (ipcBuffer != ((void *)0) && i < n && i < n_frameRegisters) {
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

        if (ipcBuffer != ((void *)0) && i < n_gpRegisters
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

    e = Arch_performTransfer(arch, ksCurThread, dest);
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

    if (dest == ksCurThread) {
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
# 2040 "/home/koc034/Documents/newver/seL4/src/object/tcb.c"
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
        halt();
    }
}
# 1 "/home/koc034/Documents/newver/seL4/src/object/untyped.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */





# 1 "gen_headers/api/invocation.h" 1

/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 ** SPDX-License-Identifier: GPL-2.0-only
 */

/* This header was generated by kernel/tools/invocation_header_gen.py.
 *
 * To add an invocation call number, edit libsel4/include/interfaces/sel4.xml.
 *
 */
# 12 "/home/koc034/Documents/newver/seL4/src/object/untyped.c" 2
# 21 "/home/koc034/Documents/newver/seL4/src/object/untyped.c"
static word_t alignUp(word_t baseValue, word_t alignment)
{
    return (baseValue + ((1ul << (alignment)) - 1)) & ~((1ul << (alignment))-1ul);
}

exception_t decodeUntypedInvocation(word_t invLabel, word_t length, cte_t *slot,
                                    cap_t cap, bool_t call, word_t *buffer)
{
    word_t newType, userObjSize, nodeIndex;
    word_t nodeDepth, nodeOffset, nodeWindow;
    cte_t *rootSlot __attribute__((unused));
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
        ;
        current_syscall_error.type = seL4_IllegalOperation;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Ensure message length valid. */
    if (length < 6 || current_extra_caps.excaprefs[0] == ((void *)0)) {
        ;
        current_syscall_error.type = seL4_TruncatedMessage;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Fetch arguments. */
    newType = getSyscallArg(0, buffer);
    userObjSize = getSyscallArg(1, buffer);
    nodeIndex = getSyscallArg(2, buffer);
    nodeDepth = getSyscallArg(3, buffer);
    nodeOffset = getSyscallArg(4, buffer);
    nodeWindow = getSyscallArg(5, buffer);

    rootSlot = current_extra_caps.excaprefs[0];

    /* Is the requested object type valid? */
    if (newType >= seL4_ObjectTypeCount) {
        ;
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 0;
        return EXCEPTION_SYSCALL_ERROR;
    }

    objectSize = getObjectSize(newType, userObjSize);

    /* Exclude impossibly large object sizes. getObjectSize can overflow if userObjSize
       is close to 2^wordBits, which is nonsensical in any case, so we check that this
       did not happen. userObjSize will always need to be less than wordBits. */
    if (userObjSize >= (1ul << (6)) || objectSize > 38) {
        ;
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 0;
        current_syscall_error.rangeErrorMax = 38;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* If the target object is a CNode, is it at least size 1? */
    if (newType == seL4_CapTableObject && userObjSize == 0) {
        ;
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* If the target object is a Untyped, is it at least size 4? */
    if (newType == seL4_UntypedObject && userObjSize < 4) {
        ;
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }


    if (newType == seL4_SchedContextObject && userObjSize < 8) {
        ;
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }


    /* Lookup the destination CNode (where our caps will be placed in). */
    if (nodeDepth == 0) {
        nodeCap = current_extra_caps.excaprefs[0]->cap;
    } else {
        cap_t rootCap = current_extra_caps.excaprefs[0]->cap;
        lu_ret = lookupTargetSlot(rootCap, nodeIndex, nodeDepth);
        if (lu_ret.status != EXCEPTION_NONE) {
            ;
            return lu_ret.status;
        }
        nodeCap = lu_ret.slot->cap;
    }

    /* Is the destination actually a CNode? */
    if (cap_get_capType(nodeCap) != cap_cnode_cap) {
        ;
        current_syscall_error.type = seL4_FailedLookup;
        current_syscall_error.failedLookupWasSource = 0;
        current_lookup_fault = lookup_fault_missing_capability_new(nodeDepth);
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Is the region where the user wants to put the caps valid? */
    nodeSize = 1ul << cap_cnode_cap_get_capCNodeRadix(nodeCap);
    if (nodeOffset > nodeSize - 1) {
       
                                  ;
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 0;
        current_syscall_error.rangeErrorMax = nodeSize - 1;
        return EXCEPTION_SYSCALL_ERROR;
    }
    if (nodeWindow < 1 || nodeWindow > 256) {
       
                                  ;
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 1;
        current_syscall_error.rangeErrorMax = 256;
        return EXCEPTION_SYSCALL_ERROR;
    }
    if (nodeWindow > nodeSize - nodeOffset) {
        ;
        current_syscall_error.type = seL4_RangeError;
        current_syscall_error.rangeErrorMin = 1;
        current_syscall_error.rangeErrorMax = nodeSize - nodeOffset;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Ensure that the destination slots are all empty. */
    destCNode = ((cte_t *)(cap_cnode_cap_get_capCNodePtr(nodeCap)));
    for (i = nodeOffset; i < nodeOffset + nodeWindow; i++) {
        status = ensureEmptySlot(destCNode + i);
        if (status != EXCEPTION_NONE) {
           
                             ;
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
    freeRef = ((word_t)(((word_t)(cap_untyped_cap_get_capPtr(cap))) + ((freeIndex)<<4)));

    /*
     * Determine the maximum number of objects we can create, and return an
     * error if we don't have enough space.
     *
     * We don't need to worry about alignment in this case, because if anything
     * fits, it will also fit aligned up (by packing it on the right hand side
     * of the untyped).
     */
    untypedFreeBytes = (1ul << (cap_untyped_cap_get_capBlockSize(cap))) -
                       ((freeIndex)<<4);

    if ((untypedFreeBytes >> objectSize) < nodeWindow) {
       



                                             ;
        current_syscall_error.type = seL4_NotEnoughMemory;
        current_syscall_error.memoryLeft = untypedFreeBytes;
        return EXCEPTION_SYSCALL_ERROR;
    }

    deviceMemory = cap_untyped_cap_get_capIsDevice(cap);
    if ((deviceMemory && !Arch_isFrameType(newType))
        && newType != seL4_UntypedObject) {
        ;
        current_syscall_error.type = seL4_InvalidArgument;
        current_syscall_error.invalidArgumentNumber = 1;
        return EXCEPTION_SYSCALL_ERROR;
    }

    /* Align up the free region so that it is aligned to the target object's
     * size. */
    alignedFreeRef = alignUp(freeRef, objectSize);

    /* Perform the retype. */
    setThreadState(ksCurThread, ThreadState_Restart);
    return invokeUntyped_Retype(slot, reset,
                                (void *)alignedFreeRef, newType, userObjSize,
                                destCNode, nodeOffset, nodeWindow, deviceMemory);
}

static exception_t resetUntypedCap(cte_t *srcSlot)
{
    cap_t prev_cap = srcSlot->cap;
    word_t block_size = cap_untyped_cap_get_capBlockSize(prev_cap);
    void *regionBase = ((word_t *)(cap_untyped_cap_get_capPtr(prev_cap)));
    int chunk = 8;
    word_t offset = ((cap_untyped_cap_get_capFreeIndex(prev_cap))<<4);
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
        for (offset = (((offset - 1) >> (chunk)) << (chunk));
             offset != - (1ul << (chunk)); offset -= (1ul << (chunk))) {
            clearMemory(((void *)(((word_t)(regionBase)) + (offset))), chunk);
            srcSlot->cap = cap_untyped_cap_set_capFreeIndex(prev_cap, ((offset)>>4));
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
    void *regionBase = ((word_t *)(cap_untyped_cap_get_capPtr(srcSlot->cap)));
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
                                                    (((word_t)(freeRef) - (word_t)(regionBase))>>4));

    /* Create new objects and caps. */
    createNewObjects(newType, srcSlot, destCNode, destOffset, destLength,
                     retypeBase, userSize, deviceMemory);

    return EXCEPTION_NONE;
}
# 1 "/home/koc034/Documents/newver/seL4/src/smp/ipi.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 1 "/home/koc034/Documents/newver/seL4/src/smp/lock.c"
/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
# 1 "/home/koc034/Documents/newver/seL4/src/string.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */





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
# 1 "/home/koc034/Documents/newver/seL4/src/util.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */





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
    ;
    ;

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

void *__attribute__((externally_visible)) memset(void *s, unsigned long c, unsigned long n)
{
    uint8_t *p;

    /*
     * If we are only writing zeros and we are word aligned, we can
     * use the optimized 'memzero' function.
     */
    if (__builtin_expect(!!(c == 0 && ((unsigned long)s % sizeof(unsigned long)) == 0 && (n % sizeof(unsigned long)) == 0), 1)) {
        memzero(s, n);
    } else {
        /* Otherwise, we use a slower, simple memset. */
        for (p = (uint8_t *)s; n > 0; n--, p++) {
            *p = (uint8_t)c;
        }
    }

    return s;
}

void *__attribute__((externally_visible)) memcpy(void *ptr_dst, const void *ptr_src, unsigned long n)
{
    uint8_t *p;
    const uint8_t *q;

    for (p = (uint8_t *)ptr_dst, q = (const uint8_t *)ptr_src; n; n--, p++, q++) {
        *p = *q;
    }

    return ptr_dst;
}

int __attribute__((__pure__)) strncmp(const char *s1, const char *s2, int n)
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

long __attribute__((__const__)) char_to_long(char c)
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

long __attribute__((__pure__)) str_to_long(const char *str)
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
typedef int __assert_failed_clz_ulong_32_or_64[(sizeof(unsigned long) == 4 || sizeof(unsigned long) == 8) ? 1 : -1];;
typedef int __assert_failed_clz_ullong_64[(sizeof(unsigned long long) == 8) ? 1 : -1];;


// Count leading zeros.
// This implementation contains no branches. If the architecture provides an
// instruction to set a register to a boolean value on a comparison, then the
// binary might also avoid branching. A branchless implementation might be
// preferable on architectures with deep pipelines, or when the maximum
// priority of runnable threads frequently varies. However, note that the
// compiler may choose to convert this to a branching implementation.
static __attribute__((__const__)) inline unsigned clz32(uint32_t x)
{
    // Compiler builtins typically return int, but we use unsigned internally
    // to reduce the number of guards we see in the proofs.
    unsigned count = 32;
    uint32_t mask = (0xFFFFFFFF);

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



static __attribute__((__const__)) inline unsigned clz64(uint64_t x)
{
    unsigned count = 64;
    uint64_t mask = (0xFFFFFFFFFFFFFFFF);

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



int __clzdi2(unsigned long x)
{
    return sizeof(unsigned long) == 4 ? clz32(x) : clz64(x);
}
# 315 "/home/koc034/Documents/newver/seL4/src/util.c"
// Count trailing zeros.
// See comments on clz32.
static __attribute__((__const__)) inline unsigned ctz32(uint32_t x)
{
    unsigned count = (x == 0);
    uint32_t mask = (0xFFFFFFFF);

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



static __attribute__((__const__)) inline unsigned ctz64(uint64_t x)
{
    unsigned count = (x == 0);
    uint64_t mask = (0xFFFFFFFFFFFFFFFF);

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



int __ctzdi2(unsigned long x)
{
    return sizeof(unsigned long) == 4 ? ctz32(x) : ctz64(x);
}
# 1 "/home/koc034/Documents/newver/l4v/spec/cspec/c/config_sched.c"
/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */




/* Random schedule clagged from Tim's original example. */
const dschedule_t ksDomSchedule[] = {
    { .domain = 0, .length = 15 },
    { .domain = 2, .length = 42 },
    { .domain = 1, .length = 73 },
};

const word_t ksDomScheduleLength = sizeof(ksDomSchedule) / sizeof(dschedule_t);
