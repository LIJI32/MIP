#include "injected.h"
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <string.h>
#include <dlfcn.h>

/* These values are overwritten on a per-injection basis by the injector */
/* Must not be defined as consts, or the compiler will optimize them. */
struct {
    uint32_t version;
    uint32_t infoArrayCount;
    uint64_t infoArray;
    uint64_t notification;
    uint8_t processDetachedFromSharedRegion;
    uint8_t libSystemInitialized;
    uint8_t pad[6];
    uint64_t dyldImageLoadAddress;
} * dyld_info = (typeof(dyld_info)) DYLD_MAGIC_64;

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

void __attribute__((preserve_all)) entry(void)
{
    uint64_t flags = get_flags();
    uint64_t const_size = 0;
    
    /* dyld's __DATA,__const section contain an array that maps internal function names (e.g. __dyld_dlopen)
     to actual function pointers. This array is used by the internal dyld lookup function, which is evntually
     used by libdyld. */
    void **const_pointer = (void **)getsectdatafromheader_64((void *)dyld_info->dyldImageLoadAddress,
                                                             "__DATA",
                                                             "__const",
                                                             &const_size);
    
    typeof(dlopen) *$dlopen = NULL;
    
    for (; const_size && $dlopen == NULL; const_size -= sizeof(*const_pointer), const_pointer++) {
        /* The const contains other data, which might be NULL. It seems that all other data in that section is pointers,
         so using strcmp is safe. (The other string is const in length) */
        if (*const_pointer == NULL) continue;
        
        /* In case we ever need it: dlsym's internal name is __dyld_dlsym */
        if (strcmp(*const_pointer, "__dyld_dlopen") == 0) {
            $dlopen = const_pointer[1];
            continue;
        }
    }
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

/* Taken from Apple's getsecbyname.c */

char * 
getsectdatafromheader_64(
                         const struct mach_header_64 *mhp,
                         const char *segname,
                         const char *sectname,
                         uint64_t *size)
{
    const struct section_64 *sp;
    
    sp = getsectbynamefromheader_64(mhp, segname, sectname);
    if(sp == NULL){
        *size = 0;
        return(NULL);
    }
    *size = sp->size;
    /* In Apple's version, mhp was not added, which made completely no sense. */
    return((char *)mhp + ((uintptr_t)(sp->addr)));
}

const struct section_64 *
getsectbynamefromheader_64(
                           const struct mach_header_64 *mhp,
                           const char *segname,
                           const char *sectname)
{
    struct segment_command_64 *sgp;
    struct section_64 *sp;
    uint32_t i, j;
    
    sgp = (struct segment_command_64 *)
    ((char *)mhp + sizeof(struct mach_header_64));
    for(i = 0; i < mhp->ncmds; i++){
        if(sgp->cmd == LC_SEGMENT_64)
            if(strcmp(sgp->segname, segname) == 0 ||
               mhp->filetype == MH_OBJECT){
                sp = (struct section_64 *)((char *)sgp +
                                           sizeof(struct segment_command_64));
                for(j = 0; j < sgp->nsects; j++){
                    if(strcmp(sp->sectname, sectname) == 0 &&
                       strcmp(sp->segname, segname) == 0)
                        return(sp);
                    sp = (struct section_64 *)((char *)sp +
                                               sizeof(struct section_64));
                }
            }
        sgp = (struct segment_command_64 *)((char *)sgp + sgp->cmdsize);
    }
    return((struct section_64 *)0);
}
