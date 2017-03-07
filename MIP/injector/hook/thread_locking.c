#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/mach_init.h>
#include <mach/vm_map.h>

#include "thread_locking.h"

kern_return_t suspend_all_other_threads(void)
{
    mach_port_t self = mach_thread_self();
    thread_array_t thread_list = NULL;
    mach_msg_type_number_t thread_list_count = 0;
    kern_return_t ret = task_threads(mach_task_self(), &thread_list, &thread_list_count);
    if (ret) return ret;
    for (int i = 0; i < thread_list_count; i++) {
        if (thread_list[i] != self) {
            thread_suspend(thread_list[i]);
        }
    }
    vm_deallocate(mach_task_self(), (vm_address_t) thread_list, thread_list_count * sizeof(thread_list[0]));
    return KERN_SUCCESS;
}

kern_return_t resume_all_other_threads(void)
{
    mach_port_t self = mach_thread_self();
    thread_array_t thread_list = NULL;
    mach_msg_type_number_t thread_list_count = 0;
    kern_return_t ret = task_threads(mach_task_self(), &thread_list, &thread_list_count);
    if (ret) return ret;
    for (int i = 0; i < thread_list_count; i++) {
        if (thread_list[i] != self) {
            thread_resume(thread_list[i]);
        }
    }
    vm_deallocate(mach_task_self(), (vm_address_t) thread_list, thread_list_count * sizeof(thread_list[0]));
    return KERN_SUCCESS;
}
