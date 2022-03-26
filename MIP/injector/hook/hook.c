#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "thread_locking.h"
#include "hook.h"

#ifdef __x86_64__

static int opcode_size(const uint8_t *code)
{
    /* 1-byte prefix */
    if (*code >= 0x40 && *code <= 0x4F) {
        return 1 + opcode_size(code + 1);
    }
    
    /* Register push/pop */
    if (*code >= 0x50 && *code <= 0x5F) {
        return 1;
    }
    
    /* Register PUSH/POP */
    if (*code >= 0x50 && *code <= 0x5F) {
        return 1;
    }
    
    /* MOV reg, reg */
    if (*code == 0x89) {
        return 2;
    }
    
    /* Various ops between a register and a 32-bit imm */
    if (*code == 0x81) {
        return 6;
    }
    
    return INT32_MIN;
}

void *hook_function(uint8_t *old, uint8_t *new)
{
    size_t page_size = getpagesize();
    
    struct __attribute__((packed))
    {
        uint16_t movabs_rax;
        void *new;
        uint16_t jmp_rax;
    } trampoline = {0xb848, new, 0xE0FF};
    
    size_t size_to_copy = 0;
    while (size_to_copy < sizeof(trampoline)) {
        int current_opcode_size = opcode_size(old + size_to_copy);
        if (current_opcode_size < 0) return NULL; // Encountered an unsupported opcode
        size_to_copy += current_opcode_size;
    }
    
    /* This trampoline is a bit longer, but does not modify registers */
    struct __attribute__((packed))
    {
        uint8_t pushq;
        uint32_t old_low;
        uint32_t movd_rsp_4;
        uint32_t old_high;
        uint8_t ret;
    } back_trampoline = {0x68, (uint32_t)(uintptr_t)(old + size_to_copy),
                         0x042444c7, (uint32_t)((uintptr_t)(old + size_to_copy) >> 32),
                         0xc3};
    
    uint8_t *unhooked = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 0, 0);
    memcpy(unhooked, old, size_to_copy);
    memcpy(unhooked + size_to_copy, &back_trampoline, sizeof(back_trampoline));
    mprotect(unhooked, page_size, PROT_READ | PROT_EXEC);

    /* We have to make sure nobody else is calling the hooked function or anything else we mprotect while we are
       modifying code. However this will still crash one of the threads has its PC pointed to the middle of the
       trampoline. */
    suspend_all_other_threads();
    void *old_page = (void*)(((uintptr_t)old) & ~(page_size - 1));
    
    /* Function might be on a page boundry */
    mprotect(old_page, page_size * 2, PROT_READ | PROT_WRITE);
    memcpy(old, &trampoline, sizeof(trampoline));
    mprotect(old_page, page_size * 2, PROT_READ | PROT_EXEC);
    
    resume_all_other_threads();
    
    return unhooked;
}

#else
void *hook_function(uint8_t *old, uint8_t *new)
{
    return NULL;
}
#endif
