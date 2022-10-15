#include "substitute.h"
#include "substitute-internal.h"
#include "execmem.h"
#include "ptrauth_helpers.h"
#include <os/log.h>
#include <mach-o/dyld.h>

EXPORT
void *SubGetImageByName(const char *filename) __asm__("_MSGetImageByName");
void *SubGetImageByName(const char *filename) {
    return substitute_open_image(filename);
}

EXPORT
void *SubFindSymbol(void *image, const char *name) __asm__("_MSFindSymbol");
void *SubFindSymbol(void *image, const char *name) {
    if (!image) {
        const char *s = "SubFindSymbol: 'any image' specified, which is incredibly slow - like, 2ms on a fast x86.  I'm going to do it since it seems to be somewhat common, but you should be ashamed of yourself.";
        LOG("%s", s);
        fprintf(stderr, "%s\n", s);
        /* and it isn't thread safe, but neither is MS */
        for(uint32_t i = 0; i < _dyld_image_count(); i++) {
            const char *im_name = _dyld_get_image_name(i);
            struct substitute_image *im = substitute_open_image(im_name);
            if (!im) {
                fprintf(stderr, "(btw, couldn't open %s?)\n", im_name);
                continue;
            }
            void *r = SubFindSymbol(im, name);
            substitute_close_image(im);
            if (r)
                return r;
        }
        return NULL;
    }

    void *ptr;
    if (substitute_find_private_syms(image, &name, &ptr, 1))
        return NULL;
    return ptr;
}

#ifdef TARGET_DIS_SUPPORTED
EXPORT
void SubHookFunction(void *symbol, void *replace, void **result)
    __asm__("_MSHookFunction");
void SubHookFunction(void *symbol, void *replace, void **result) {
    if (symbol == NULL || replace == NULL) {
        substitute_info("SubHookFunction: called with a NULL pointer. Don't do that.\n");
    }
    struct substitute_function_hook hook = {symbol, replace, result};
    int ret = substitute_hook_functions(&hook, 1, NULL,
                                        SUBSTITUTE_NO_THREAD_SAFETY);
    if (ret && ret != SUBSTITUTE_ERR_VM) {
        substitute_info("SubHookFunction: substitute_hook_functions returned %s (%p)\n",
                         substitute_strerror(ret), make_sym_readable(symbol));
    }
}
#endif

EXPORT
void SubHookMemory(void *target, const void *data, size_t size)
    __asm__("_MSHookMemory");

void SubHookMemory(void *target, const void *data, size_t size) {
    if (size == 0) return;

    if (target == NULL || data == NULL) {
        substitute_info("SubHookMemory: called with a NULL pointer. Don't do that.\n");
    }
    struct execmem_foreign_write write = {target, data, size};
    int ret = execmem_foreign_write_with_pc_patch(&write, 1, NULL, NULL);

    if (ret) {
        substitute_info("SubHookMemory: execmem_foreign_write_with_pc_patch returned %s\n",
                         substitute_strerror(ret));
    }
}

EXPORT
void SubHookMessageEx(Class _class, SEL sel, IMP imp, IMP *result)
    __asm__("_MSHookMessageEx");

void SubHookMessageEx(Class _class, SEL sel, IMP imp, IMP *result) {
    int ret = substitute_hook_objc_message(_class, sel, imp, result, NULL);
    if (ret) {
        if (ret != SUBSTITUTE_ERR_NO_SUCH_SELECTOR) {
            substitute_info("SubHookMessageEx: substitute_hook_objc_message returned %s\n",
            substitute_strerror(ret));
        }
        if (result) *result = nil;
    }
}
