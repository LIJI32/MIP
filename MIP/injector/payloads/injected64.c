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

/* The preserve_all calling convention does not save the flags register, so we use
   these ASM functions to save and restore it outselves. They must be called as
   early and as late as possible, respectively, so instructions that modify flags
   won't destory the state. */

uint64_t get_flags(void);
void set_flags(uint64_t);

__asm__ (
         "_get_flags: \n"
         "    pushfq \n"
         "    pop %rax \n"
         "    ret \n"
         
         "_set_flags: \n"
         "    push %rdi \n"
         "    popfq \n"
         "    ret \n"
         );

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

void __attribute__((preserve_all)) entry(void)
{
    uint64_t flags = get_flags();
    
    typeof(dlopen) *$dlopen = NULL;
    
    /* We can't call dyld`dlopen when dyld3 is being used, so we must find libdyld`dlopen and call that instead */
    $dlopen = get_symbol_from_header(get_header_by_path("/usr/lib/system/libdyld.dylib"), "_dlopen");
    
    if ($dlopen) {
        $dlopen(argument, RTLD_NOW);
    }
	
    set_flags(flags);
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
