#include <stdio.h>
#include <stdbool.h>
#include <alloca.h>
#include <mach/mach_vm.h>
#include <mach/thread_state.h>
#include <mach/vm_map.h>
#include <injector/payloads/injected.h>
#include "inject.h"

kern_return_t inject_call_to_thread_64(mach_port_t task, mach_port_t thread, uint64_t function, uint64_t ret_addr)
{
    x86_thread_state64_t state;
    mach_msg_type_number_t size = x86_THREAD_STATE64_COUNT;
    kern_return_t ret = KERN_SUCCESS;
    
    ret = thread_suspend(thread);
    if (ret) goto exit;
    
    ret = thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t) &state, &size);
    if (ret) goto exit;
    
    if (state.__rsp & 7) {
        ret = KERN_INVALID_ADDRESS;
        goto exit;
    }
    
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
    ret = thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t) &state, size);
    if (ret) goto exit;
    
exit:
    thread_resume(thread);
    return ret;
}

kern_return_t inject_call_to_thread_32(mach_port_t task, mach_port_t thread, uint32_t function, uint32_t ret_addr)
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

kern_return_t get_thread_port_for_task(mach_port_t task, mach_port_t *thread)
{
    thread_array_t thread_list = NULL;
    mach_msg_type_number_t thread_list_count = 0;
    kern_return_t ret = task_threads(task, &thread_list, &thread_list_count);
    if (ret) return ret;
    /* The first thread returned is the first thread created in the task, which is the main thread.
       This was verified in the kernel sources. */
    *thread = thread_list[0];
    vm_deallocate(mach_task_self(), (vm_address_t) thread_list, thread_list_count * sizeof(thread_list[0]));
    return KERN_SUCCESS;
}

kern_return_t inject_stub_to_task(mach_port_t task, mach_vm_address_t *addr, mach_vm_address_t *ret_addr,
                                  const char *argument, bool *is_32_bit)
{
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    struct task_dyld_info info;
    kern_return_t ret = task_info(task, TASK_DYLD_INFO, (task_info_t) &info, &count);
    if (ret) return ret;
    *is_32_bit = info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_32;
    
    uint8_t *code = NULL;
    size_t code_size = 0;
    if (*is_32_bit) {
        code_size = &injected32_end - &injected32_start + 1; // +1 for the injected ret instruction, for stack alignment
        code = alloca(code_size);
        memcpy(code, &injected32_start, code_size);
        code[code_size - 1] = 0xc3; // ret;
        
        uint32_t dyld_magic = DYLD_MAGIC_32;
        *(uint32_t*) memmem(code, code_size, &dyld_magic, sizeof(dyld_magic)) = (uint32_t)info.all_image_info_addr;
        
        strcpy(memmem(code, code_size, ARGUMENT_MAGIC_STR, sizeof(ARGUMENT_MAGIC_STR)), argument);
    }
    else {
        code_size = &injected64_end - &injected64_start + 1; // +1 for the injected ret instruction, for stack alignment
        code = alloca(code_size);
        memcpy(code, &injected64_start, code_size - 1);
        code[code_size - 1] = 0xc3; // ret;
        
        uint64_t dyld_magic = 'DYLD'* 0x100000001;
        *(uint64_t*) memmem(code, code_size, &dyld_magic, sizeof(dyld_magic)) = info.all_image_info_addr;
        
        strcpy(memmem(code, code_size, ARGUMENT_MAGIC_STR, sizeof(ARGUMENT_MAGIC_STR)), argument);
    }
    
    ret = mach_vm_allocate(task, addr, code_size, VM_FLAGS_ANYWHERE);
    if (ret) return ret;
    
    ret = mach_vm_write(task, *addr, (vm_offset_t) code, (mach_msg_type_number_t) code_size);
    if (ret) return ret;
    
    ret = vm_protect(task, *addr, code_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
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
    if ((ret = inject_stub_to_task(task, &code_addr, &ret_addr, argument, &is_32_bit))) {
        return ret;
    }
    
    if (is_32_bit) {
        return inject_call_to_thread_32(task, thread, (uint32_t)code_addr, (uint32_t)ret_addr);
    }
    
    return inject_call_to_thread_64(task, thread, code_addr, ret_addr);
}
