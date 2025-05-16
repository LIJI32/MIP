#include <stdio.h>
#include <stdbool.h>
#include <alloca.h>
#include <mach/mach_vm.h>
#include <mach/thread_state.h>
#include <mach/vm_map.h>
#include <sys/sysctl.h>
#include <injector/payloads/injected.h>
#include "inject.h"

#ifndef __x86_64__
typedef struct {
    uint64_t    __rax;
    uint64_t    __rbx;
    uint64_t    __rcx;
    uint64_t    __rdx;
    uint64_t    __rdi;
    uint64_t    __rsi;
    uint64_t    __rbp;
    uint64_t    __rsp;
    uint64_t    __r8;
    uint64_t    __r9;
    uint64_t    __r10;
    uint64_t    __r11;
    uint64_t    __r12;
    uint64_t    __r13;
    uint64_t    __r14;
    uint64_t    __r15;
    uint64_t    __rip;
    uint64_t    __rflags;
    uint64_t    __cs;
    uint64_t    __fs;
    uint64_t    __gs;
} x86_thread_state64_t;
#endif

typedef struct {
    uint64_t unknown[8];
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t flags;
} rosetta_state_t;


kern_return_t thread_get_state_x86_64(mach_port_t task, mach_port_t thread, x86_thread_state64_t *state)
{
#ifdef __x86_64__
    mach_msg_type_number_t size = x86_THREAD_STATE64_COUNT;
    return thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)state, &size);
#else
    arm_thread_state64_t arm_state;
    mach_msg_type_number_t size = ARM_THREAD_STATE64_COUNT;
    kern_return_t ret = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t) &arm_state, &size);
    if (ret) return ret;
    
    /* Verify a "safe" injection state: the highest bit of X18 is set if we're
       outside of JIT code, then we know the registers stored in the Rosetta
       State buffer are up to date. Also, X28 *should* have the value of RIP
       during most instructions, so make sure it points to `retq`. */
    if (!(arm_state.__x[18] & (1ULL << 63))) return -1;
    uint8_t opcode = 0;
    mach_vm_size_t read_size = sizeof(opcode);
    ret = mach_vm_read_overwrite(task, arm_state.__x[28], read_size, (mach_vm_address_t) &opcode, &read_size);
    if (ret) return ret;
    if (opcode != 0xc3) return -2;
    
    rosetta_state_t rosetta_state;
    read_size = sizeof(rosetta_state);
    ret = mach_vm_read_overwrite(task, (arm_state.__x[18] & ~(1ULL << 63)), read_size, (mach_vm_address_t) &rosetta_state, &read_size);
    
    if (ret) return ret;
    
    state->__rax = rosetta_state.rax;
    state->__rcx = rosetta_state.rcx;
    state->__rdx = rosetta_state.rdx;
    state->__rbx = rosetta_state.rbx;
    state->__rsp = rosetta_state.rsp;
    state->__rbp = rosetta_state.rbp;
    state->__rsi = rosetta_state.rsi;
    state->__rdi = rosetta_state.rdi;
    state->__r8  = rosetta_state.r8;
    state->__r9  = rosetta_state.r9;
    state->__r10 = rosetta_state.r10;
    state->__r11 = rosetta_state.r11;
    state->__r12 = rosetta_state.r12;
    state->__r13 = rosetta_state.r13;
    state->__r14 = rosetta_state.r14;
    state->__r15 = rosetta_state.r15;
    state->__rip = arm_state.__x[28];
    
    
    // Todo: convert flags from ARM to Intel, find the segment registers
        
    return 0;
#endif
}

kern_return_t thread_set_state_x86_64(mach_port_t task, mach_port_t thread, const x86_thread_state64_t *state)
{
#ifdef __x86_64__
    return thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)state, x86_THREAD_STATE64_COUNT);
#else
    arm_thread_state64_t arm_state;
    mach_msg_type_number_t size = ARM_THREAD_STATE64_COUNT;
    kern_return_t ret = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t) &arm_state, &size);
    if (ret) return ret;
    if (!(arm_state.__x[18] & (1ULL << 63))) return -1;
    rosetta_state_t rosetta_state;
    mach_vm_size_t read_size = sizeof(rosetta_state);
    ret = mach_vm_read_overwrite(task, (arm_state.__x[18] & ~(1ULL << 63)), read_size, (mach_vm_address_t) &rosetta_state, &read_size);
    
    if (ret) return ret;
    
    rosetta_state.rax = state->__rax;
    rosetta_state.rcx = state->__rcx;
    rosetta_state.rdx = state->__rdx;
    rosetta_state.rbx = state->__rbx;
    rosetta_state.rsp = state->__rsp;
    rosetta_state.rbp = state->__rbp;
    rosetta_state.rsi = state->__rsi;
    rosetta_state.rdi = state->__rdi;
    rosetta_state.r8  = state->__r8;
    rosetta_state.r9  = state->__r9;
    rosetta_state.r10 = state->__r10;
    rosetta_state.r11 = state->__r11;
    rosetta_state.r12 = state->__r12;
    rosetta_state.r13 = state->__r13;
    rosetta_state.r14 = state->__r14;
    rosetta_state.r15 = state->__r15;
    
    return mach_vm_write(task, (arm_state.__x[18] & ~(1ULL << 63)), (vm_offset_t)&rosetta_state, sizeof(rosetta_state));
#endif
}

kern_return_t inject_call_to_thread_x86_64(mach_port_t task, mach_port_t thread, uint64_t function, uint64_t ret_addr)
{
    x86_thread_state64_t state;
    kern_return_t ret = KERN_SUCCESS;
    
    ret = thread_suspend(thread);
    if (ret) goto exit;
    
    ret = thread_get_state_x86_64(task, thread, &state);
    if (ret) goto exit;
    
    if (state.__rsp & 7) {
        ret = KERN_INVALID_ADDRESS;
        goto exit;
    }
    
#ifdef __x86_64__
    /* Push PC */
    state.__rsp -= sizeof(state.__rip);
    mach_vm_write(task, state.__rsp, (vm_offset_t)&state.__rip, sizeof(state.__rip));
    
    /* x86-64 stack % 16 must be 8 bytes after a call instruction */
    if ((state.__rsp & 0xF) == 0) {
        /* Push a nop function as a return address, for alignment */
        state.__rsp -= sizeof(state.__rip);
        mach_vm_write(task, state.__rsp, (vm_offset_t)&ret_addr, sizeof(ret_addr));
    }
    
    /* Update PC */
    state.__rip = function;
#else
    /* Push a NOP function as a return address for alignment, followed by our call */
    state.__rsp -= sizeof(state.__rip) * 2;
    uint64_t stack[2] = {
        ret_addr,
        function,
    };
    mach_vm_write(task, state.__rsp, (vm_offset_t)&stack, sizeof(stack));
#endif
    
    ret = thread_set_state_x86_64(task, thread, &state);
    if (ret) goto exit;
    
exit:
    thread_resume(thread);
    return ret;
}

#ifndef __x86_64__
kern_return_t inject_call_to_thread_arm(mach_port_t task, mach_port_t thread, uint64_t function, uint64_t ret_addr)
{
    arm_thread_state64_t state;
    mach_msg_type_number_t size = ARM_THREAD_STATE64_COUNT;
    kern_return_t ret = KERN_SUCCESS;
    
    ret = thread_suspend(thread);
    if (ret) goto exit;
    
    ret = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t) &state, &size);
    if (ret) goto exit;
    
    thread_convert_thread_state(thread, THREAD_CONVERT_THREAD_STATE_TO_SELF, ARM_THREAD_STATE64, (thread_state_t)&state, size, (thread_state_t)&state, &size);

    /* Save PC to FP */
    __darwin_arm_thread_state64_set_fp(state, (void *)((uint64_t)state.__opaque_pc & 0xFFFFFFFFFFF));
    
    /* Update PC */
    __darwin_arm_thread_state64_set_pc_fptr(state, ptrauth_sign_unauthenticated((void *)function, ptrauth_key_function_pointer, 0));
    
    thread_convert_thread_state(thread, THREAD_CONVERT_THREAD_STATE_FROM_SELF, ARM_THREAD_STATE64, (thread_state_t)&state, size, (thread_state_t)&state, &size);
    ret = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t) &state, size);
    if (ret) goto exit;
    
exit:
    thread_resume(thread);
    return ret;
}
#endif

#ifdef __x86_64__
kern_return_t inject_call_to_thread_i386(mach_port_t task, mach_port_t thread, uint32_t function, uint32_t ret_addr)
{
    x86_thread_state32_t state;
    mach_msg_type_number_t size = x86_THREAD_STATE32_COUNT;
    kern_return_t ret = KERN_SUCCESS;

    ret = thread_suspend(thread);
    if (ret) goto exit;

    ret = thread_get_state(thread, x86_THREAD_STATE32, (thread_state_t) &state, &size);
    if (ret) goto exit;

    if (state.__esp & 3) {
        ret = KERN_INVALID_ADDRESS;
        goto exit;
    }

    /* Push PC */
    state.__esp -= sizeof(state.__eip);
    mach_vm_write(task, state.__esp, (vm_offset_t)&state.__eip, sizeof(state.__eip));

    /* x86-32 stack % 16 must be 0xC bytes after a call instruction */
    while ((state.__esp & 0xF) != 0xC) {
        /* Push a nop function as a return address, for alignment */
        state.__esp -= sizeof(state.__eip);
        mach_vm_write(task, state.__esp, (vm_offset_t)&ret_addr, sizeof(ret_addr));
    }

    /* Update PC */
    state.__eip = function;
    ret = thread_set_state(thread, x86_THREAD_STATE32, (thread_state_t) &state, size);
    if (ret) goto exit;

exit:
    thread_resume(thread);
    return ret;
}
#endif

kern_return_t get_thread_port_for_task(mach_port_t task, mach_port_t *thread)
{
    thread_array_t thread_list = NULL;
    mach_msg_type_number_t thread_list_count = 0;
    kern_return_t ret = task_threads(task, &thread_list, &thread_list_count);
    if (ret) return ret;
    /* The first thread returned is the first thread created in the task, which is the main thread.
       This was verified in the kernel sources. */
    *thread = thread_list[0];
    for (unsigned i = 1; i < thread_list_count; i++) {
        mach_port_destroy(mach_task_self(), thread_list[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t) thread_list, thread_list_count * sizeof(thread_list[0]));
    return KERN_SUCCESS;
}

static bool is_arm(mach_port_t task)
{
#ifdef __x86_64__
    return false;
#else
    pid_t pid;
    pid_for_task(task, &pid);
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    
    struct kinfo_proc proc;
    size_t buf_size = sizeof(proc);

    if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), &proc, &buf_size, NULL, 0) < 0) {
        perror("Failure calling sysctl");
        return false;
    }
    
    return !(proc.kp_proc.p_flag & P_TRANSLATED);
#endif
}

kern_return_t inject_stub_to_task(mach_port_t task, mach_vm_address_t *addr, mach_vm_address_t *ret_addr,
                                  const char *argument, bool is_arm, bool *is_32_bit)
{
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    struct task_dyld_info info;
    kern_return_t ret = task_info(task, TASK_DYLD_INFO, (task_info_t) &info, &count);
    if (ret) return ret;
    *is_32_bit = info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_32;
    
    uint8_t *code = NULL;
    size_t code_size = 0;
#ifdef __x86_64__
    if (*is_32_bit) {
        code_size = &injected_i386_end - &injected_i386_start + 1; // +1 for the injected ret instruction, for stack alignment
        code = alloca(code_size);
        memcpy(code, &injected_i386_start, code_size);
        code[code_size - 1] = 0xc3; // ret;
        
        uint32_t dyld_magic = DYLD_MAGIC_32;
        *(uint32_t*) memmem(code, code_size, &dyld_magic, sizeof(dyld_magic)) = (uint32_t)info.all_image_info_addr;
        
        strcpy(memmem(code, code_size, ARGUMENT_MAGIC_STR, sizeof(ARGUMENT_MAGIC_STR)), argument);
    }
    else
#endif
    if (is_arm) {
        code_size = &injected_arm_end - &injected_arm_start;
        code = alloca(code_size);
        memcpy(code, &injected_arm_start, code_size);
        
        uint64_t dyld_magic = DYLD_MAGIC_64;
        *(uint64_t*) memmem(code, code_size, &dyld_magic, sizeof(dyld_magic)) = info.all_image_info_addr;
        
        strcpy(memmem(code, code_size, ARGUMENT_MAGIC_STR, sizeof(ARGUMENT_MAGIC_STR)), argument);
    }
    else {
        code_size = &injected_x86_64_end - &injected_x86_64_start + 1; // +1 for the injected ret instruction, for stack alignment
        code = alloca(code_size);
        memcpy(code, &injected_x86_64_start, code_size - 1);
        code[code_size - 1] = 0xc3; // ret;
        
        uint64_t dyld_magic = DYLD_MAGIC_64;
        *(uint64_t*) memmem(code, code_size, &dyld_magic, sizeof(dyld_magic)) = info.all_image_info_addr;
        
        strcpy(memmem(code, code_size, ARGUMENT_MAGIC_STR, sizeof(ARGUMENT_MAGIC_STR)), argument);
    }
    
    ret = mach_vm_allocate(task, addr, code_size, VM_FLAGS_ANYWHERE);
    if (ret) return ret;
    
    ret = mach_vm_write(task, *addr, (vm_offset_t) code, (mach_msg_type_number_t) code_size);
    if (ret) return ret;
    
    vm_prot_t prot = VM_PROT_READ | VM_PROT_EXECUTE;
#ifndef __x86_64__
    if (!is_arm) {
        prot |= VM_PROT_WRITE;
    }
#endif
    
    ret = vm_protect(task, *addr, code_size, FALSE, prot);
    if (ret) return ret;
    
    *ret_addr = *addr + code_size - 1;
    
    return KERN_SUCCESS;
}

kern_return_t inject_to_task(mach_port_t task, const char *argument)
{
    mach_port_t thread;
    kern_return_t ret = KERN_SUCCESS;
    
    if (strlen(argument) + 1 > ARGUMENT_MAX_LENGTH) {
        return KERN_INVALID_ARGUMENT;
    }
    
    if ((ret = get_thread_port_for_task(task, &thread))) {
        return ret;
    }
    
    mach_vm_address_t code_addr = 0;
    mach_vm_address_t ret_addr = 0;
    bool is_32_bit = false;
    bool arm = is_arm(task);
    
    if ((ret = inject_stub_to_task(task, &code_addr, &ret_addr, argument, arm, &is_32_bit))) {
        mach_port_destroy(mach_task_self(), thread);
        return ret;
    }
    
#ifndef __x86_64__
    if (arm) {
        ret = inject_call_to_thread_arm(task, thread, code_addr, ret_addr);
    }
#else
    if (is_32_bit) {
        ret = inject_call_to_thread_i386(task, thread, (uint32_t)code_addr, (uint32_t)ret_addr);
    }
#endif
    else {
        ret = inject_call_to_thread_x86_64(task, thread, code_addr, ret_addr);
    }
    
    mach_port_destroy(mach_task_self(), thread);
    return ret;
}
