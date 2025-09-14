/* define to avoid error that ucontext is "deprecated" (it's unavoidable with
 * sigaction!) */
#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE
#include "substitute.h"
#include "substitute-internal.h"
#include "cbit/htab.h"
#include "execmem.h"
#include "darwin/manual-syscall.h"
#include "darwin/mach-decls.h"
#include "ptrauth_helpers.h"
#include <mach/mach.h>
#ifndef __MigPackStructs
#error wtf
#endif
#include <mach/mig.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <signal.h>
#include <pthread.h>

#define MACH_MSG_OPTION_NONE    0x00000000

#define MACH_SEND_MSG           0x00000001
#define MACH_RCV_MSG            0x00000002

#define MACH_RCV_LARGE          0x00000004
#define MACH_RCV_LARGE_IDENTITY 0x00000008

#define MACH_SEND_TIMEOUT       0x00000010
#define MACH_SEND_OVERRIDE      0x00000020
#define MACH_SEND_INTERRUPT     0x00000040
#define MACH_SEND_NOTIFY        0x00000080
#define MACH_SEND_ALWAYS        0x00010000
#define MACH_SEND_FILTER_NONFATAL        0x00010000
#define MACH_SEND_TRAILER       0x00020000
#define MACH_SEND_NOIMPORTANCE  0x00040000
#define MACH_SEND_NODENAP       MACH_SEND_NOIMPORTANCE
#define MACH_SEND_IMPORTANCE    0x00080000
#define MACH_SEND_SYNC_OVERRIDE 0x00100000
#define MACH_SEND_PROPAGATE_QOS 0x00200000
#define MACH_SEND_SYNC_USE_THRPRI   MACH_SEND_PROPAGATE_QOS
#define MACH_SEND_KERNEL        0x00400000
#define MACH_SEND_SYNC_BOOTSTRAP_CHECKIN    0x00800000

#define MACH_RCV_TIMEOUT        0x00000100
#define MACH_RCV_NOTIFY         0x00000000
#define MACH_RCV_INTERRUPT      0x00000400
#define MACH_RCV_VOUCHER        0x00000800
#define MACH_RCV_OVERWRITE      0x00000000
#define MACH_RCV_GUARDED_DESC   0x00001000
#define MACH_RCV_SYNC_WAIT      0x00004000
#define MACH_RCV_SYNC_PEEK      0x00008000
#define MACH_MSG_STRICT_REPLY   0x00000200

#define LIBSYSCALL_MSGV_AUX_MAX_SIZE 128

typedef uint64_t mach_msg_option64_t;

enum mach_msg_option64_t {
        MACH64_MSG_OPTION_NONE                 = 0x0ull,
        MACH64_SEND_MSG                        = MACH_SEND_MSG,
        MACH64_RCV_MSG                         = MACH_RCV_MSG,
        MACH64_RCV_LARGE                       = MACH_RCV_LARGE,
        MACH64_RCV_LARGE_IDENTITY              = MACH_RCV_LARGE_IDENTITY,
        MACH64_SEND_TIMEOUT                    = MACH_SEND_TIMEOUT,
        MACH64_SEND_OVERRIDE                   = MACH_SEND_OVERRIDE,
        MACH64_SEND_INTERRUPT                  = MACH_SEND_INTERRUPT,
        MACH64_SEND_NOTIFY                     = MACH_SEND_NOTIFY,
        MACH64_SEND_ALWAYS                     = MACH_SEND_ALWAYS,
        MACH64_SEND_IMPORTANCE                 = MACH_SEND_IMPORTANCE,
        MACH64_SEND_KERNEL                     = MACH_SEND_KERNEL,
        MACH64_SEND_FILTER_NONFATAL            = MACH_SEND_FILTER_NONFATAL,
        MACH64_SEND_TRAILER                    = MACH_SEND_TRAILER,
        MACH64_SEND_NOIMPORTANCE               = MACH_SEND_NOIMPORTANCE,
        MACH64_SEND_NODENAP                    = MACH_SEND_NODENAP,
        MACH64_SEND_SYNC_OVERRIDE              = MACH_SEND_SYNC_OVERRIDE,
        MACH64_SEND_PROPAGATE_QOS              = MACH_SEND_PROPAGATE_QOS,
        MACH64_SEND_SYNC_BOOTSTRAP_CHECKIN     = MACH_SEND_SYNC_BOOTSTRAP_CHECKIN,
        MACH64_RCV_TIMEOUT                     = MACH_RCV_TIMEOUT,
        MACH64_RCV_INTERRUPT                   = MACH_RCV_INTERRUPT,
        MACH64_RCV_VOUCHER                     = MACH_RCV_VOUCHER,
        MACH64_RCV_GUARDED_DESC                = MACH_RCV_GUARDED_DESC,
        MACH64_RCV_SYNC_WAIT                   = MACH_RCV_SYNC_WAIT,
        MACH64_RCV_SYNC_PEEK                   = MACH_RCV_SYNC_PEEK,
        MACH64_MSG_STRICT_REPLY                = MACH_MSG_STRICT_REPLY,

        MACH64_MSG_VECTOR                      = 0x0000000100000000ull,
        MACH64_SEND_KOBJECT_CALL               = 0x0000000200000000ull,
        MACH64_SEND_MQ_CALL                    = 0x0000000400000000ull,
        MACH64_SEND_ANY                        = 0x0000000800000000ull,
        MACH64_SEND_DK_CALL                    = 0x0000001000000000ull,
        MACH64_RCV_LINEAR_VECTOR               = 0x1000000000000000ull,
        MACH64_RCV_STACK                       = 0x2000000000000000ull,
        MACH64_PEEK_MSG                        = 0x4000000000000000ull,
        MACH64_MACH_MSG2                       = 0x8000000000000000ull
};

#define LIBMACH_OPTIONS64 (MACH64_SEND_INTERRUPT|MACH64_RCV_INTERRUPT)

typedef uint32_t mach_msgv_index_t;
enum mach_msgv_index_t {
    MACH_MSGV_IDX_MSG = 0,
    MACH_MSGV_IDX_AUX = 1,
};


typedef struct {
    mach_msg_size_t         msgdh_size;
    uint32_t                msgdh_reserved;
} mach_msg_aux_header_t;

typedef struct {
    /* a mach_msg_header_t* or mach_msg_aux_header_t* */
    mach_vm_address_t               msgv_data;
    /* if msgv_rcv_addr is non-zero, use it as rcv address instead */
    mach_vm_address_t               msgv_rcv_addr;
    mach_msg_size_t                 msgv_send_size;
    mach_msg_size_t                 msgv_rcv_size;
} mach_msg_vector_t;

static mach_msg_return_t manual_mach_msg2_internal(void *data, mach_msg_option64_t option64, uint64_t msgh_bits_and_send_size, uint64_t msgh_remote_and_local_port, uint64_t msgh_voucher_and_id, uint64_t desc_count_and_rcv_name, uint64_t rcv_size_and_priority, uint64_t timeout);

int manual_sigreturn(void *, int);
GEN_SYSCALL(sigreturn, 184);
__typeof__(mmap) manual_mmap;
GEN_SYSCALL(mmap, 197);
__typeof__(mprotect) manual_mprotect;
GEN_SYSCALL(mprotect, 74);
__typeof__(mach_msg) manual_old_mach_msg;
GEN_SYSCALL(old_mach_msg, -31);
mach_msg_return_t manual_mach_msg2_trap(void *data, mach_msg_option64_t option64, uint64_t msgh_bits_and_send_size, uint64_t msgh_remote_and_local_port, uint64_t msgh_voucher_and_id, uint64_t desc_count_and_rcv_name, uint64_t rcv_size_and_priority, uint64_t timeout);
GEN_SYSCALL(mach_msg2_trap, -47);
__typeof__(mach_thread_self) manual_thread_self;
GEN_SYSCALL(thread_self, -27);
__attribute__((weak_import)) extern mach_msg_return_t (*mach_msg2_internal)(void *data, mach_msg_option64_t option64, uint64_t msgh_bits_and_send_size, uint64_t msgh_remote_and_local_port, uint64_t msgh_voucher_and_id, uint64_t desc_count_and_rcv_name, uint64_t rcv_size_and_priority, uint64_t timeout);

extern int __sigaction(int, struct __sigaction * __restrict,
                       struct sigaction * __restrict);

static inline mach_msg_return_t manual_mach_msg2(
        void *data,
        mach_msg_option64_t option64,
        mach_msg_header_t header,
        mach_msg_size_t send_size,
        mach_msg_size_t rcv_size,
        mach_port_t rcv_name,
        uint64_t timeout,
        uint32_t priority)
{
    mach_msg_base_t *base;
    mach_msg_size_t descriptors;

    if (option64 & MACH64_MSG_VECTOR) {
        base = (mach_msg_base_t *)((mach_msg_vector_t *)data)->msgv_data;
    } else {
        base = (mach_msg_base_t *)data;
    }

    if ((option64 & MACH64_SEND_MSG) && (base->header.msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        descriptors = base->body.msgh_descriptor_count;
    } else {
        descriptors = 0;
    }

#define MACH_MSG2_SHIFT_ARGS(lo, hi) ((uint64_t)hi << 32 | (uint32_t)lo)
    return manual_mach_msg2_internal(data, option64,
            MACH_MSG2_SHIFT_ARGS(header.msgh_bits, send_size),
            MACH_MSG2_SHIFT_ARGS(header.msgh_remote_port, header.msgh_local_port),
            MACH_MSG2_SHIFT_ARGS(header.msgh_voucher_port, header.msgh_id),
            MACH_MSG2_SHIFT_ARGS(descriptors, rcv_name),
            MACH_MSG2_SHIFT_ARGS(rcv_size, priority), timeout);
#undef MACH_MSG2_SHIFT_ARGS
}

static inline mach_msg_option64_t
mach_msg_options_after_interruption(mach_msg_option64_t option64)
{
    if ((option64 & MACH64_SEND_MSG) && (option64 & MACH64_RCV_MSG)) {
        option64 &= ~MACH64_RCV_SYNC_WAIT;
    }
    option64 &= ~(LIBMACH_OPTIONS64 | MACH64_SEND_MSG);
    return option64;
}

static mach_msg_return_t manual_mach_msg2_internal(
        void *data,
        mach_msg_option64_t option64,
        uint64_t msgh_bits_and_send_size,
        uint64_t msgh_remote_and_local_port,
        uint64_t msgh_voucher_and_id,
        uint64_t desc_count_and_rcv_name,
        uint64_t rcv_size_and_priority,
        uint64_t timeout)
{
    mach_msg_return_t mr;

    mr = manual_mach_msg2_trap(data,
            option64 & ~LIBMACH_OPTIONS64,
            msgh_bits_and_send_size,
            msgh_remote_and_local_port,
            msgh_voucher_and_id,
            desc_count_and_rcv_name,
            rcv_size_and_priority,
            timeout);


    if (mr == MACH_MSG_SUCCESS) {
        return MACH_MSG_SUCCESS;
        }

    if ((option64 & MACH64_SEND_INTERRUPT) == 0) {
        while (mr == MACH_SEND_INTERRUPTED) {
            mr = manual_mach_msg2_trap(data,
                    option64 & ~LIBMACH_OPTIONS64,
                    msgh_bits_and_send_size,
                    msgh_remote_and_local_port,
                    msgh_voucher_and_id,
                    desc_count_and_rcv_name,
                    rcv_size_and_priority,
                    timeout);
        }
    }

    if ((option64 & MACH64_RCV_INTERRUPT) == 0) {
        while (mr == MACH_RCV_INTERRUPTED) {
            mr = manual_mach_msg2_trap(data,
                    mach_msg_options_after_interruption(option64),
                    msgh_bits_and_send_size & 0xffffffffull, /* zero send size */
                    msgh_remote_and_local_port,
                    msgh_voucher_and_id,
                    desc_count_and_rcv_name,
                    rcv_size_and_priority,
                    timeout);
        }
    }

    return mr;

}

static mach_msg_return_t manual_new_mach_msg_overwrite(
        mach_msg_header_t *msg,
        mach_msg_option_t option,
        mach_msg_size_t send_size,
        mach_msg_size_t rcv_limit,
        mach_port_t rcv_name,
        mach_msg_timeout_t timeout,
        mach_port_t notify,
        mach_msg_header_t *rcv_msg,
        __unused mach_msg_size_t rcv_scatter_size)
{
    mach_msg_return_t mr;
    mach_msg_aux_header_t *aux;
    mach_msg_vector_t vecs[2];

    uint8_t inline_aux_buf[LIBSYSCALL_MSGV_AUX_MAX_SIZE];

    mach_msg_priority_t priority = 0;
    mach_msg_size_t aux_sz = 0;
    mach_msg_option64_t option64 = (mach_msg_option64_t)option;

    aux = (mach_msg_aux_header_t *)inline_aux_buf;
#if 0
    if (voucher_mach_msg_fill_aux_supported() &&
            (option64 & MACH64_RCV_MSG) && (option64 & MACH64_RCV_VOUCHER)) {
        option64 |= MACH64_MSG_VECTOR;
        if (!(aux = _os_tsd_get_direct(__TSD_MACH_MSG_AUX))) {
            aux = malloc(LIBSYSCALL_MSGV_AUX_MAX_SIZE);
            if (aux) {
                /* will be freed during TSD teardown */
                _os_tsd_set_direct(__TSD_MACH_MSG_AUX, aux);
            } else {
                /* revert to use on stack buffer */
                aux = (mach_msg_aux_header_t *)inline_aux_buf;
                option64 &= ~MACH64_MSG_VECTOR;
            }
        }
    }
#endif

    if ((option64 & MACH64_RCV_MSG) && rcv_msg != NULL) {
        option64 |= MACH64_MSG_VECTOR;
    }

#if 0
    if ((option64 & MACH64_SEND_MSG) &&
            /* this returns 0 for Libsyscall_static due to weak linking */
            ((aux_sz = voucher_mach_msg_fill_aux(aux, LIBSYSCALL_MSGV_AUX_MAX_SIZE)) != 0)) {
        option64 |= MACH64_MSG_VECTOR;
    }
#endif

    if (option64 & MACH64_MSG_VECTOR) {
        vecs[MACH_MSGV_IDX_MSG] = (mach_msg_vector_t){
            .msgv_data = (mach_vm_address_t)msg,
                .msgv_rcv_addr = (mach_vm_address_t)rcv_msg, /* if 0, just use msg as rcv address */
                .msgv_send_size = send_size,
                .msgv_rcv_size = rcv_limit,
        };
        vecs[MACH_MSGV_IDX_AUX] = (mach_msg_vector_t){
            .msgv_data = (mach_vm_address_t)aux,
                .msgv_rcv_addr = 0,
                .msgv_send_size = aux_sz,
                .msgv_rcv_size = LIBSYSCALL_MSGV_AUX_MAX_SIZE,
        };
    }

    if (option64 & MACH64_SEND_MSG) {
        priority = (mach_msg_priority_t)notify;
    }

    if ((option64 & MACH64_RCV_MSG) &&
            !(option64 & MACH64_SEND_MSG) &&
            (option64 & MACH64_RCV_SYNC_WAIT)) {
        msg->msgh_remote_port = notify;
    }
    option64 |= MACH64_SEND_MQ_CALL;
    if (option64 & MACH64_MSG_VECTOR) {
        mr = manual_mach_msg2(vecs, option64, *msg, 2, 2,
                rcv_name, timeout, priority);
    } else {
        mr = manual_mach_msg2(msg, option64, *msg, send_size,
                rcv_limit, rcv_name, timeout, priority);
    }

    return mr;
}

static mach_msg_return_t manual_new_mach_msg(
        mach_msg_header_t *msg,
        mach_msg_option_t option,
        mach_msg_size_t send_size,
        mach_msg_size_t rcv_limit,
        mach_port_t rcv_name,
        mach_msg_timeout_t timeout,
        mach_port_t notify)
{
    return manual_new_mach_msg_overwrite(msg, option, send_size, rcv_limit, rcv_name, timeout, notify, NULL, 0);
}

static void manual_memcpy(void *restrict dest, const void *src, size_t len) {
    /* volatile to avoid compiler transformation to call to memcpy */
    volatile uint8_t *d8 = dest;
    const uint8_t *s8 = src;
    while (len--)
        *d8++ = *s8++;
}

static inline mach_msg_return_t manual_mach_msg(
        mach_msg_header_t *msg,
        mach_msg_option64_t option,
        mach_msg_size_t send_size,
        mach_msg_size_t rcv_limit,
        mach_port_t rcv_name,
        mach_msg_timeout_t timeout,
        mach_port_t notify)
{
    if ((volatile void *)&mach_msg2_internal != NULL) {
        return manual_mach_msg2(msg, option, *msg, send_size, rcv_limit, rcv_name, timeout, notify);
    } else {
        return manual_old_mach_msg(msg, option&0xFFFFFFFF, send_size, rcv_limit, rcv_name, timeout, notify);
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#include "../generated/manual-mach.inc.h"
#pragma GCC diagnostic pop

#define port_hash(portp) (*(portp))
#define port_eq(port1p, port2p) (*(port1p) == *(port2p))
#define port_null(portp) (*(portp) == MACH_PORT_NULL)
DECL_STATIC_HTAB_KEY(mach_port_t, mach_port_t, port_hash, port_eq, port_null, 0);
struct empty {};
DECL_HTAB(mach_port_set, mach_port_t, struct empty);

/* This should only run on the main thread, so just use globals. */
static HTAB_STORAGE(mach_port_set) g_suspended_ports;
static struct sigaction old_segv, old_bus;
static execmem_pc_patch_callback g_pc_patch_callback;
static void *g_pc_patch_callback_ctx;
static mach_port_t g_suspending_thread;

int execmem_alloc_unsealed(uintptr_t hint, void **page_p, size_t *size_p) {
    *size_p = PAGE_SIZE;
    *page_p = mmap((void *) hint, *size_p, PROT_READ | PROT_WRITE,
                   MAP_ANON | MAP_SHARED, -1, 0);
    if (*page_p == MAP_FAILED) {
        LOG("execmem_alloc_unsealed failed");
        return SUBSTITUTE_ERR_VM;
    }
    return SUBSTITUTE_OK;
}

int execmem_seal(void *page) {
    if (mprotect(page, PAGE_SIZE, PROT_READ | PROT_EXEC)) {
        LOG("execmem_seal failed");
        return SUBSTITUTE_ERR_VM;
    }
    return SUBSTITUTE_OK;
}

void execmem_free(void *page) {
    munmap(page, PAGE_SIZE);
}

#if defined(__x86_64__)
    typedef struct __darwin_x86_thread_state64 native_thread_state;
    #define NATIVE_THREAD_STATE_FLAVOR x86_THREAD_STATE64
#elif defined(__i386__)
    typedef struct __darwin_i386_thread_state native_thread_state;
    #define NATIVE_THREAD_STATE_FLAVOR x86_THREAD_STATE32
#elif defined(__arm__)
    typedef struct __darwin_arm_thread_state native_thread_state;
    #define NATIVE_THREAD_STATE_FLAVOR ARM_THREAD_STATE
#elif defined(__arm64__)
    typedef struct __darwin_arm_thread_state64 native_thread_state;
    #define NATIVE_THREAD_STATE_FLAVOR ARM_THREAD_STATE64
#else
    #error ?
#endif

/* returns whether it changed */
static bool apply_one_pcp_with_state(native_thread_state *state,
                                     execmem_pc_patch_callback callback,
                                     void *ctx) {

    uintptr_t *pcp;
#if defined(__x86_64__)
    pcp = (uintptr_t *) &state->__rip;
#elif defined(__i386__)
    pcp = (uintptr_t *) &state->__eip;
#elif defined(__arm__) || defined(__arm64__)
#if __DARWIN_OPAQUE_ARM_THREAD_STATE64
    uintptr_t unauth_pc;
    // ????
    unauth_pc = __darwin_arm_thread_state64_get_pc(*state);
    pcp = &unauth_pc;
#else
    pcp = (uintptr_t *) &state->__pc;
#endif
#endif
    uintptr_t old = *pcp;
#ifdef __arm__
    /* thumb */
    if (state->__cpsr & 0x20)
        old |= 1;
#endif
    uintptr_t new = callback(ctx, *pcp);
    bool changed = new != old;
    *pcp = new;
#ifdef __arm__
    *pcp &= ~1;
    state->__cpsr = (state->__cpsr & ~0x20) | ((new & 1) * 0x20);
#endif
#if __DARWIN_OPAQUE_ARM_THREAD_STATE64
    // Sign it ourselves, then have it be resigned by the macro.
    // Waste of cycles, but it's the proper way to do it.
    __darwin_arm_thread_state64_set_pc_fptr(*state, make_sym_callable((void *)unauth_pc));
#endif
    return changed;
}

static int apply_one_pcp(mach_port_t thread, execmem_pc_patch_callback callback,
                         void *ctx, mach_port_t reply_port) {
    native_thread_state state;
    mach_msg_type_number_t real_cnt = sizeof(state) / sizeof(int);
    mach_msg_type_number_t cnt = real_cnt;
    kern_return_t kr = manual_thread_get_state(thread, NATIVE_THREAD_STATE_FLAVOR,
                                               (thread_state_t) &state, &cnt,
                                               reply_port);
    if (kr == KERN_TERMINATED)
        return SUBSTITUTE_OK;
    if (kr || cnt != real_cnt)
        return SUBSTITUTE_ERR_ADJUSTING_THREADS;;

    if (apply_one_pcp_with_state(&state, callback, ctx)) {
        kr = manual_thread_set_state(thread, NATIVE_THREAD_STATE_FLAVOR,
                                     (thread_state_t) &state, real_cnt,
                                     reply_port);
        if (kr)
            return SUBSTITUTE_ERR_ADJUSTING_THREADS;
    }
    return SUBSTITUTE_OK;
}

static void resume_other_threads();

static int stop_other_threads() {
    /* pthread_main should have already been checked. */

    int ret;
    mach_port_t self = mach_thread_self();

    /* The following shenanigans are for catching any new threads that are
     * created while we're looping, without suspending anything twice.  Keep
     * looping until only threads we already suspended before this loop are
     * there. */
    HTAB_STORAGE_INIT(&g_suspended_ports, mach_port_set);
    struct htab_mach_port_set *suspended_set = &g_suspended_ports.h;

    bool got_new;
    do {
        got_new = false;

        thread_act_port_array_t ports;
        mach_msg_type_number_t nports;

        kern_return_t kr = task_threads(mach_task_self(), &ports, &nports);
        if (kr) { /* ouch */
            ret = SUBSTITUTE_ERR_ADJUSTING_THREADS;
            goto fail;
        }

        for (mach_msg_type_number_t i = 0; i < nports; i++) {
            mach_port_t port = ports[i];
            struct htab_bucket_mach_port_set *bucket;
            if (port == self ||
                (bucket = htab_setbucket_mach_port_set(suspended_set, &port),
                 bucket->key)) {
                /* already suspended, ignore */
                mach_port_deallocate(mach_task_self(), port);
            } else {
                got_new = true;
                kr = thread_suspend(port);
                if (kr == KERN_TERMINATED) {
                    /* too late */
                    mach_port_deallocate(mach_task_self(), port);
                } else if (kr) {
                    ret = SUBSTITUTE_ERR_ADJUSTING_THREADS;
                    for (; i < nports; i++)
                        mach_port_deallocate(mach_task_self(), ports[i]);
                    vm_deallocate(mach_task_self(), (vm_address_t) ports,
                                  nports * sizeof(*ports));
                    goto fail;
                }
                bucket->key = port;
            }
        }
        vm_deallocate(mach_task_self(), (vm_address_t) ports,
                      nports * sizeof(*ports));
    } while(got_new);

    /* Success - keep the set around for when we're done. */
    return SUBSTITUTE_OK;

fail:
    resume_other_threads();
    return ret;
}

static void resume_other_threads() {
    struct htab_mach_port_set *suspended_set = &g_suspended_ports.h;
    HTAB_FOREACH(suspended_set, mach_port_t *threadp,
                 UNUSED struct empty *_,
                 mach_port_set) {
        thread_resume(*threadp);
        mach_port_deallocate(mach_task_self(), *threadp);
    }
    htab_free_storage_mach_port_set(suspended_set);
}

/* note: unusual prototype since we are avoiding _sigtramp */
static void segfault_handler(UNUSED void *func, int style, int sig,
                             UNUSED siginfo_t *sinfo, void *uap_) {
    ucontext_t *uap = uap_;
    if (manual_thread_self() == g_suspending_thread) {
        /* The patcher itself segfaulted.  Oops.  Reset the signal so the
         * process exits rather than going into an infinite loop. */
        signal(sig, SIG_DFL);
        goto sigreturn;
    }
    /* We didn't catch it before it segfaulted so have to fix it up here. */
    apply_one_pcp_with_state(&uap->uc_mcontext->__ss, g_pc_patch_callback,
                             g_pc_patch_callback_ctx);
    /* just let it continue, whatever */
sigreturn:
    if (manual_sigreturn(uap, style))
        abort();
}

static int init_pc_patch(execmem_pc_patch_callback callback, void *ctx) {
    g_suspending_thread = mach_thread_self();
    g_pc_patch_callback = callback;
    g_pc_patch_callback_ctx = ctx;
    int ret;
    if ((ret = stop_other_threads()))
        return ret;

    struct __sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = (void *) 0xdeadbeef;
    sa.sa_tramp = segfault_handler;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NODEFER | SA_SIGINFO;

    if (__sigaction(SIGSEGV, &sa, &old_segv))
        return SUBSTITUTE_ERR_ADJUSTING_THREADS;
    if (__sigaction(SIGBUS, &sa, &old_bus)) {
        sigaction(SIGSEGV, &old_segv, NULL);
        return SUBSTITUTE_ERR_ADJUSTING_THREADS;
    }
    return SUBSTITUTE_OK;
}

static int run_pc_patch(mach_port_t reply_port) {
    int ret;

    struct htab_mach_port_set *suspended_set = &g_suspended_ports.h;
    HTAB_FOREACH(suspended_set, mach_port_t *threadp,
                 UNUSED struct empty *_,
                 mach_port_set) {
        if ((ret = apply_one_pcp(*threadp, g_pc_patch_callback,
                                 g_pc_patch_callback_ctx, reply_port)))
            return ret;
    }

    return SUBSTITUTE_OK;
}

static int finish_pc_patch() {
    if (sigaction(SIGBUS, &old_bus, NULL) ||
        sigaction(SIGSEGV, &old_segv, NULL))
        return SUBSTITUTE_ERR_ADJUSTING_THREADS;

    resume_other_threads();
    return SUBSTITUTE_OK;
}

static int compare_dsts(const void *a, const void *b) {
    void *dst_a = ((struct execmem_foreign_write *) a)->dst;
    void *dst_b = ((struct execmem_foreign_write *) b)->dst;
    return dst_a < dst_b ? -1 : dst_a > dst_b ? 1 : 0;
}

static kern_return_t get_page_info(uintptr_t ptr, vm_prot_t *prot_p,
                                   vm_inherit_t *inherit_p) {

    vm_address_t region = (vm_address_t) ptr;
    vm_size_t region_len = 0;
    struct vm_region_submap_short_info_64 info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t max_depth = 99999;
    kern_return_t kr = vm_region_recurse_64(mach_task_self(), &region, &region_len,
                                            &max_depth,
                                            (vm_region_recurse_info_t) &info,
                                            &info_count);
    *prot_p = info.protection & (PROT_READ | PROT_WRITE | PROT_EXEC);
    *inherit_p = info.inheritance;
    return kr;
}

int execmem_foreign_write_with_pc_patch(struct execmem_foreign_write *writes,
                                        size_t nwrites,
                                        execmem_pc_patch_callback callback,
                                        void *callback_ctx) {
    int ret;

    qsort(writes, nwrites, sizeof(*writes), compare_dsts);

    mach_port_t task_self = mach_task_self();
    mach_port_t reply_port = mig_get_reply_port();

    if (callback) {
        /* Set the segfault handler - stopping all other threads before
         * doing so in case they were using it for something (this
         * happens).  One might think the latter makes segfaults
         * impossible, but we can't prevent injectors from making new
         * threads that might run during this process.  Hopefully no
         * *injected* threads try to use segfault handlers for something!
         */
        if ((ret = init_pc_patch(callback, callback_ctx)))
            return ret;
    }

    size_t last;
    for (size_t first = 0; first < nwrites; first = last + 1) {
        const struct execmem_foreign_write *first_write = &writes[first];
        uintptr_t page_start = (uintptr_t) first_write->dst & ~PAGE_MASK;
        uintptr_t page_end = ((uintptr_t) first_write->dst +
                              first_write->len - 1) & ~PAGE_MASK;

        last = first;
        while (last + 1 < nwrites) {
            const struct execmem_foreign_write *write = &writes[last + 1];
            uintptr_t this_start = (uintptr_t) write->dst & ~PAGE_MASK;
            uintptr_t this_end = ((uintptr_t) write->dst +
                                  first_write->len - 1) & ~PAGE_MASK;
            if (page_start <= this_start && this_start <= page_end) {
                if (this_end > page_end)
                    page_end = this_end;
            } else if (page_start <= this_end && this_end <= page_end) {
                if (this_start < page_start)
                    page_start = this_start;
            } else {
                break;
            }
            last++;
        }
        size_t len = page_end - page_start + PAGE_SIZE;

        vm_prot_t prot;
        vm_inherit_t inherit;
        /* Assume that a single patch region will be pages of all the same
         * protection, since the alternative is probably someone doing
         * something wrong. */
        kern_return_t kr = get_page_info(page_start, &prot, &inherit);
        if (kr) {
            /* Weird; this probably means the region doesn't exist, but we should
             * have already read from the memory in order to generate the patch. */
            LOG("Weird; this probably means the region doesn't exist");
            ret = SUBSTITUTE_ERR_VM;
            goto fail;
        }
        size_t page_chunk = len;
        void *new = MAP_FAILED;
retry_chunk:
        for (int shift=0; shift<len; shift += page_chunk) {
            /* Instead of trying to set the existing region to write, which may
            * fail due to max_protection, we make a fresh copy and remap it over
            * the original. */
            new = mmap(NULL, page_chunk, PROT_READ | PROT_WRITE,
                            MAP_ANON | MAP_SHARED, -1, 0);
            if (new == MAP_FAILED) {
                LOG("mmap failed");
                ret = SUBSTITUTE_ERR_VM;
                goto fail;
            }
            /* Ideally, if the original page wasn't mapped anywhere else, no actual
            * copy will take place: new will be CoW, then we unmap the original so
            * new becomes the sole owner before actually writing.  Though, for all
            * I know, these trips through the VM system could be slower than just
            * memcpying a page or two... */
            kr = vm_copy(task_self, page_start+shift, page_chunk, (vm_address_t) new);
            if (kr) {
                LOG("vm_copy failed");
                ret = SUBSTITUTE_ERR_VM;
                goto fail_unmap;
            }
            /* Start of danger zone: between the mmap PROT_NONE and remap, we avoid
            * using any standard library functions in case the user is trying to
            * hook one of them.  (This includes the mmap, since there's an epilog
            * after the actual syscall instruction.)
            * This includes the signal handler! */
            void *mmret = manual_mmap((void *) page_start+shift, page_chunk, PROT_NONE,
                                    MAP_ANON | MAP_SHARED | MAP_FIXED, -1, 0);
            /* MAP_FAILED is a userspace construct */
            if ((uintptr_t) mmret & 0xfff) {
                ret = SUBSTITUTE_ERR_VM;
                goto fail_unmap;
            }
            /* Write patches to the copy. */
            for (size_t i = first; i <= last; i++) {
                struct execmem_foreign_write *write = &writes[i];
                ptrdiff_t off = (uintptr_t) write->dst - page_start;
                size_t plen = write->len;
                // Patch does not touch this chunk
                if (off > shift+page_chunk || off+plen < shift) {
                    continue;
                }
                // Patch starts in previous chunk
                if (shift && off < shift) {
                    plen = off+plen-page_chunk;
                    off = shift;
                }
                // Patch extends into next chunk
                if (off+plen-shift > page_chunk) {
                    plen = shift+page_chunk-off;
                }
                manual_memcpy(new + off - shift, (const void *)((uintptr_t)write->src + ( write->len - plen )), plen);
            }
            if (callback) {
                /* Actually run the callback for any threads which are paused at an
                * affected PC, or are running and don't get scheduled by the
                * kernel in time to segfault.  Any thread which moves to an
                * affected PC *after* run_pc_patch() is assumed to do so by
                * calling the function in question, so they can't get past the
                * first instruction and it doesn't matter whether or not they're
                * patched.  (A call instruction within the affected region would
                * break this assumption, as then a thread could move to an
                * affected PC by returning. */
                if ((ret = run_pc_patch(reply_port)))
                    goto fail_unmap;
            }

            /* Protect new like the original, and move it into place. */
            if (manual_mprotect(new, page_chunk, prot)) {
                LOG("manual_mprotect failed");
                ret = SUBSTITUTE_ERR_VM;
                goto fail_unmap;
            }
            vm_prot_t c, m;
            mach_vm_address_t target = page_start + shift;
            kr = manual_mach_vm_remap(mach_task_self(), &target, page_chunk, 0,
                                      VM_FLAGS_OVERWRITE, task_self,
                                      (mach_vm_address_t) new, /*copy*/ TRUE,
                                      &c, &m, inherit, reply_port);
            if (kr) {
                LOG("manual_mach_vm_remap failed");
                ret = SUBSTITUTE_ERR_VM;
                goto fail_unmap;
            }
            /* Danger zone over.  Ignore errors when unmapping the temporary buffer. */
            munmap(new, page_chunk);
            new = MAP_FAILED;
            vm_prot_t nprot;
            vm_inherit_t ninherit;
            kr = get_page_info(page_start, &nprot, &ninherit);
            if (kr) {
                LOG("get_page_info failed");
                ret = SUBSTITUTE_ERR_VM;
                goto fail;
            }
            if (nprot != prot || ninherit != inherit) {
                if (page_chunk != PAGE_SIZE) {
                    LOG("permissions wrong on remapped page; retrying with small chunk size");
                    page_chunk = PAGE_SIZE;
                    goto retry_chunk;
                }
                LOG("nprot != prot || ninherit != inherit");
                ret = SUBSTITUTE_ERR_VM;
                goto fail;
            }
        }

        continue;

    fail_unmap:
        /* This is probably useless, since the original page is gone
         * forever (intentionally, see above).  May as well arrange the
         * deck chairs, though. */
        if (new != MAP_FAILED) {
            munmap(new, page_chunk);
        }
        goto fail;
    }

    ret = 0;

fail:
    if (callback) {
        /* Other threads are no longer in danger of segfaulting, so put
         * back the old segfault handler. */
        int ret2;
        if ((ret2 = finish_pc_patch()))
            return ret2;
    }

    return ret;
}

