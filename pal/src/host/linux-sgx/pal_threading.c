/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to create, exit and yield a thread.
 */

#include <stddef.h>

#include "api.h"
#include "list.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "spinlock.h"

static spinlock_t g_thread_list_lock = INIT_SPINLOCK_UNLOCKED;
DEFINE_LISTP(pal_handle_thread);
static LISTP_TYPE(pal_handle_thread) g_thread_list = LISTP_INIT;

struct thread_param {
    int (*callback)(void*);
    void* param;
};

extern uintptr_t g_enclave_base;

/* Initialization wrapper of a newly-created thread. This function finds a newly-created thread in
 * g_thread_list, initializes its TCB/TLS, and jumps into the callback-to-run. Gramine uses GCC's
 * stack protector that looks for a canary at gs:[0x8], but this function starts with a default
 * canary and then updates it to a random one, so we disable stack protector here. */
__attribute_no_stack_protector
void pal_start_thread(void) {
    struct pal_handle_thread* new_thread = NULL;
    struct pal_handle_thread* tmp;

    spinlock_lock(&g_thread_list_lock);
    LISTP_FOR_EACH_ENTRY(tmp, &g_thread_list, list)
        if (!tmp->tcs) {
            new_thread = tmp;
            __atomic_store_n(&new_thread->tcs,
                             (void*)(g_enclave_base + GET_ENCLAVE_TCB(tcs_offset)),
                             __ATOMIC_RELEASE);
            break;
        }
    spinlock_unlock(&g_thread_list_lock);

    if (!new_thread)
        return;

    struct thread_param* thread_param = (struct thread_param*)new_thread->param;
    int (*callback)(void*) = thread_param->callback;
    const void* param = thread_param->param;
    free(thread_param);
    new_thread->param = NULL;

    SET_ENCLAVE_TCB(thread, new_thread);
    SET_ENCLAVE_TCB(ready_for_exceptions, 1UL);

    /* each newly-created thread (including the first thread) has its own random stack canary */
    uint64_t stack_protector_canary;
    int ret = _PalRandomBitsRead(&stack_protector_canary, sizeof(stack_protector_canary));
    if (ret < 0) {
        log_error("_PalRandomBitsRead() failed: %s", pal_strerror(ret));
        _PalProcessExit(1);
    }
    pal_set_tcb_stack_canary(stack_protector_canary);
    PAL_TCB* pal_tcb = pal_get_tcb();
    memset(&pal_tcb->libos_tcb, 0, sizeof(pal_tcb->libos_tcb));
    callback((void*)param);
    _PalThreadExit(/*clear_child_tid=*/NULL);
    /* UNREACHABLE */
}

int _PalThreadCreate(PAL_HANDLE* handle, int (*callback)(void*), void* param) {
    int ret;
    PAL_HANDLE new_thread = calloc(1, HANDLE_SIZE(thread));
    if (!new_thread)
        return -PAL_ERROR_NOMEM;

    init_handle_hdr(new_thread, PAL_TYPE_THREAD);

    new_thread->thread.tcs = NULL;
    INIT_LIST_HEAD(&new_thread->thread, list);
    struct thread_param* thread_param = malloc(sizeof(struct thread_param));
    if (!thread_param) {
        ret = -PAL_ERROR_NOMEM;
        goto out_err;
    }
    thread_param->callback = callback;
    thread_param->param    = param;
    new_thread->thread.param = (void*)thread_param;

    spinlock_lock(&g_thread_list_lock);
    LISTP_ADD_TAIL(&new_thread->thread, &g_thread_list, list);
    spinlock_unlock(&g_thread_list_lock);

    ret = ocall_clone_thread();
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        spinlock_lock(&g_thread_list_lock);
        LISTP_DEL(&new_thread->thread, &g_thread_list, list);
        spinlock_unlock(&g_thread_list_lock);
        goto out_err;
    }

    /* There can be subtle race between the parent and child so hold the parent until child updates
     * its tcs. */
    while (!__atomic_load_n(&new_thread->thread.tcs, __ATOMIC_ACQUIRE))
        CPU_RELAX();

    *handle = new_thread;
    return 0;
out_err:
    free(thread_param);
    free(new_thread);
    return ret;
}

/* PAL call PalThreadYieldExecution. Yield the execution of the current thread. */
void _PalThreadYieldExecution(void) {
    ocall_sched_yield();
}

/* _PalThreadExit for internal use: Thread exiting */
noreturn void _PalThreadExit(int* clear_child_tid) {
    struct pal_handle_thread* exiting_thread = GET_ENCLAVE_TCB(thread);

    if (exiting_thread->rakis_io_uring){
      RAKIS_SET_ATOMIC(&exiting_thread->rakis_io_uring, NULL);
    }

    /* thread is ready to exit, must inform LibOS by erasing clear_child_tid;
     * note that we don't do it now (because this thread still occupies SGX
     * TCS slot) but during handle_thread_reset in assembly code */
    SET_ENCLAVE_TCB(clear_child_tid, clear_child_tid);
    static_assert(sizeof(*clear_child_tid) == 4, "unexpected clear_child_tid size");

    /* main thread is not part of the g_thread_list */
    if (exiting_thread != &g_pal_public_state.first_thread->thread) {
        spinlock_lock(&g_thread_list_lock);
        LISTP_DEL(exiting_thread, &g_thread_list, list);
        spinlock_unlock(&g_thread_list_lock);
    }

    ocall_exit(0, /*is_exitgroup=*/false);
}

int _PalThreadResume(PAL_HANDLE thread_handle) {
    int ret = ocall_resume_thread(thread_handle->thread.tcs);
    return ret < 0 ? unix_to_pal_error(ret) : ret;
}

int _PalThreadSetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    int ret = ocall_sched_setaffinity(thread->thread.tcs, cpu_mask, cpu_mask_len);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

int _PalThreadGetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    int ret = ocall_sched_getaffinity(thread->thread.tcs, cpu_mask, cpu_mask_len);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    /* Verify that the CPU affinity mask contains only online cores. */
    size_t threads_count = g_pal_public_state.topo_info.threads_cnt;
    for (size_t i = 0; i < cpu_mask_len; i++) {
        for (size_t j = 0; j < BITS_IN_TYPE(__typeof__(*cpu_mask)); j++) {
            size_t thread_idx = i * BITS_IN_TYPE(__typeof__(*cpu_mask)) + j;
            if (thread_idx >= threads_count) {
                break;
            }
            if ((cpu_mask[i] & (1ul << j))
                    && !g_pal_public_state.topo_info.threads[thread_idx].is_online) {
                return -PAL_ERROR_INVAL;
            }
        }
    }

    return 0;
}

struct handle_ops g_thread_ops = {
    /* nothing */
};
