#include "injected.h"
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <dlfcn.h>

/* These values are overwritten on a per-injection basis by the injector */
/* Must not be defined as consts, or the compiler will optimize them. */
struct dyld_all_image_infos *dyld_info = (typeof(dyld_info)) DYLD_MAGIC_64;

char argument[ARGUMENT_MAX_LENGTH] = ARGUMENT_MAGIC_STR;

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

void c_entry(void)
{
    typeof(dlopen) *$dlopen = NULL;
    
    /* We can't call dyld`dlopen when dyld3 is being used, so we must find libdyld`dlopen and call that instead */
    $dlopen = get_symbol_from_header(get_header_by_path("/usr/lib/system/libdyld.dylib"), "_dlopen");
    $dlopen = ptrauth_sign_unauthenticated($dlopen, ptrauth_key_function_pointer, 0);

    
    if ($dlopen) {
        $dlopen(argument, RTLD_NOW);
    }
}

void __attribute__((naked)) entry(void)
{
    __asm__(
            "stp  x0,  x1, [sp,#-16]!\n"
            "stp  x2,  x3, [sp,#-16]!\n"
            "stp  x4,  x5, [sp,#-16]!\n"
            "stp  x6,  x7, [sp,#-16]!\n"
            "stp  x8,  x9, [sp,#-16]!\n"
            "stp x10, x11, [sp,#-16]!\n"
            "stp x12, x13, [sp,#-16]!\n"
            "stp x14, x15, [sp,#-16]!\n"
            "stp x16, x17, [sp,#-16]!\n"
            "stp x18, x19, [sp,#-16]!\n"
            "stp x20, x21, [sp,#-16]!\n"
            "stp x22, x23, [sp,#-16]!\n"
            "stp x24, x25, [sp,#-16]!\n"
            "stp x26, x27, [sp,#-16]!\n"
            "stp x28, x29, [sp,#-16]!\n"
            "stp  q0,  q1, [sp,#-16]!\n"
            "stp  q2,  q3, [sp,#-16]!\n"
            "stp  q4,  q5, [sp,#-16]!\n"
            "stp  q6,  q7, [sp,#-16]!\n"
            "stp  q8,  q9, [sp,#-16]!\n"
            "stp q10, q11, [sp,#-16]!\n"
            "stp q12, q13, [sp,#-16]!\n"
            "stp q14, q15, [sp,#-16]!\n"
            "stp q16, q17, [sp,#-16]!\n"
            "stp q18, q19, [sp,#-16]!\n"
            "stp q20, q21, [sp,#-16]!\n"
            "stp q22, q23, [sp,#-16]!\n"
            "stp q24, q25, [sp,#-16]!\n"
            "stp q26, q27, [sp,#-16]!\n"
            "stp q28, q29, [sp,#-16]!\n"
            "stp q30, q31, [sp,#-16]!\n"
            "mrs x0, nzcv\n"
            "stp x0, lr, [sp,#-16]!\n"
            "bl _c_entry\n"
            "ldp x0, lr, [sp], #16\n"
            "msr nzcv, x0\n"
            "ldp q30, q31, [sp], #16\n"
            "ldp q28, q29, [sp], #16\n"
            "ldp q26, q27, [sp], #16\n"
            "ldp q24, q25, [sp], #16\n"
            "ldp q22, q23, [sp], #16\n"
            "ldp q20, q21, [sp], #16\n"
            "ldp q18, q19, [sp], #16\n"
            "ldp q16, q17, [sp], #16\n"
            "ldp q14, q15, [sp], #16\n"
            "ldp q12, q13, [sp], #16\n"
            "ldp q10, q11, [sp], #16\n"
            "ldp  q8,  q9, [sp], #16\n"
            "ldp  q6,  q7, [sp], #16\n"
            "ldp  q4,  q5, [sp], #16\n"
            "ldp  q2,  q3, [sp], #16\n"
            "ldp  q0,  q1, [sp], #16\n"
            "ldp x28, x29, [sp], #16\n"
            "ldp x26, x27, [sp], #16\n"
            "ldp x24, x25, [sp], #16\n"
            "ldp x22, x23, [sp], #16\n"
            "ldp x20, x21, [sp], #16\n"
            "ldp x18, x19, [sp], #16\n"
            "ldp x16, x17, [sp], #16\n"
            "ldp x14, x15, [sp], #16\n"
            "ldp x12, x13, [sp], #16\n"
            "ldp x10, x11, [sp], #16\n"
            "ldp  x8,  x9, [sp], #16\n"
            "ldp  x6,  x7, [sp], #16\n"
            "ldp  x4,  x5, [sp], #16\n"
            "ldp  x2,  x3, [sp], #16\n"
            "ldp  x0,  x1, [sp], #16\n"
            "br  x18\n"
            );
}


/* Taken from Apple's libc */

int 
strcmp(s1, s2)
const char *s1, *s2;
{
    while (*s1 == *s2++)
        if (*s1++ == 0)
            return (0);
    return (*(const unsigned char *)s1 - *(const unsigned char *)(s2 - 1));
}
