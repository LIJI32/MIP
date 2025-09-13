#include "injected.h"
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <dlfcn.h>

/* These values are overwritten on a per-injection basis by the injector */
/* Must not be defined as consts, or the compiler will optimize them. */
__attribute__((section("__TEXT,__const"))) struct dyld_all_image_infos *dyld_info = (typeof(dyld_info)) DYLD_MAGIC_64;

__attribute__((section("__TEXT,__const"))) char argument[ARGUMENT_MAX_LENGTH] = ARGUMENT_MAGIC_STR;

/* The preserve_all calling convention does not save the flags register, so we use
   these ASM functions to save and restore it outselves. They must be called as
   early and as late as possible, respectively, so instructions that modify flags
   won't destory the state. */

static const struct mach_header_64 *get_header_by_path(const char *name)
{
    for (unsigned i = 0; i < dyld_info->infoArrayCount; i++) {
        if (strcmp(dyld_info->infoArray[i].imageFilePath, name) == 0) {
            return (const struct mach_header_64 *) dyld_info->infoArray[i].imageLoadAddress;
        }
    }
    return NULL;
}

static const void *get_symbol_from_header(const struct mach_header_64 *header, const char *symbol)
{
    if (!header) {
        return NULL;
    }
    
    /* Get the required commands */
    
    const struct symtab_command *symtab = NULL;
    const struct segment_command_64 *first = NULL;
    const struct segment_command_64 *linkedit = NULL;
    const struct load_command *cmd = (typeof(cmd))(header + 1);
    
    for (unsigned i = 0; i < header->ncmds; i++, cmd = (typeof(cmd)) ((char*) cmd + cmd->cmdsize)) {
        if (cmd->cmd == LC_SEGMENT_64) {
            if (!first && ((typeof(first))cmd)->filesize ) {
                first = (typeof(first)) cmd;
            }
            if (strcmp(((typeof(linkedit)) cmd)->segname, "__LINKEDIT") == 0) {
                linkedit = (typeof(linkedit)) cmd;
            }
        }
        else if (cmd->cmd == LC_SYMTAB) {
            symtab = (typeof (symtab)) cmd;
        }
        if (symtab && linkedit) break;
    }
    
    if (!symtab || !linkedit) return NULL;
    
    const char *string_table =
        ((const char *) header + symtab->stroff - linkedit->fileoff + linkedit->vmaddr - first->vmaddr);
    const struct nlist_64 *symbols = (typeof (symbols))
        ((const char *) header + symtab->symoff - linkedit->fileoff + linkedit->vmaddr - first->vmaddr);
    
    for (unsigned i = 0; i < symtab->nsyms; i++) {
        if (strcmp(string_table + symbols[i].n_un.n_strx, symbol) == 0) {
            return (char *)header + symbols[i].n_value - first->vmaddr;
        }
    }
    
    return NULL;
}

#ifdef ROSETTA
void __attribute__((naked)) late_inject(void)
{
    __asm__ ("push %rsp\n"
             "push %r11\n"
             "pushfq\n"
             "call _c_late_inject\n"
             "popfq\n"
             "pop %r11\n"
             "ret");
}

/* In Rosetta, __TEXT segments are RWX, so we can put our data in __TEXT,
   and to properly generate payloads, everything must be in one segment. */
static __attribute__((section("__TEXT,__data"))) uintptr_t *stack_ret = NULL;
static __attribute__((section("__TEXT,__data"))) uintptr_t ret_address = 0;

void __attribute__((preserve_all)) c_late_inject(void)
{
    *stack_ret = ret_address;
    typeof(dlopen) *$dlopen = NULL;
    $dlopen = get_symbol_from_header(get_header_by_path("/usr/lib/system/libdyld.dylib"), "_dlopen");
    
    if ($dlopen) {
        $dlopen(argument, RTLD_NOW);
    }
}
#endif

void __attribute__((preserve_all)) c_entry(void)
{
#ifdef ROSETTA
    /*
      For some reason, calling `dlopen` from the usual `lsdinjector` context,
      specifically while using the Rosetta runtime, some Mach port connection
      gets screwed up, which ends up crashing the next time it is used. If we
      detect this scenario,  we inject the dlopen call to  after we return to
      _LSApplicationCheckIn, which is safe.
    */
    uintptr_t _LSApplicationCheckIn = (uintptr_t) get_symbol_from_header(
        get_header_by_path("/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/LaunchServices"),
        "__LSApplicationCheckIn");
        
    if (_LSApplicationCheckIn) {
        uintptr_t *stack = __builtin_frame_address(4);
        for (unsigned i = 0; i < 128; i++) {
            /* TODO: This will work for lsdinjector, but this can probably be improved.
               It might have false positives (and even crashes) on some manual `inject`
               scenarios. */
            if (stack[i] > _LSApplicationCheckIn && stack[i] < _LSApplicationCheckIn + 8192) {
                ret_address = stack[i];
                stack_ret = &stack[i];
                stack[i] = (uintptr_t)&late_inject;
                return;
            }
        }
    }
#endif
    
    typeof(dlopen) *$dlopen = NULL;

    /* We can't call dyld`dlopen when dyld3 is being used, so we must find libdyld`dlopen and call that instead */
    $dlopen = get_symbol_from_header(get_header_by_path("/usr/lib/system/libdyld.dylib"), "_dlopen");
    
    if ($dlopen) {
        $dlopen(argument, RTLD_NOW);
    }
}

void __attribute__((naked)) entry(void)
{
    __asm__ ("push %rax\n" // Alignment dummy
             "push %r11\n"
             "pushfq\n"
             "call _c_entry\n"
             "popfq\n"
             "pop %r11\n"
             "pop %rax\n" // Alignment dummy
             "ret\n");
}


/* Taken from Apple's libc */

int strcmp(const char *s1, const char *s2)
{
    while (*s1 == *s2++)
        if (*s1++ == 0)
            return (0);
    return (*(const unsigned char *)s1 - *(const unsigned char *)(s2 - 1));
}
