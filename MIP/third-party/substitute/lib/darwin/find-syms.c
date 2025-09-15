#ifdef __APPLE__

#include <stdbool.h>
#include <ptrauth.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/mman.h>
#include <limits.h>
#include <fcntl.h>
#include "ptrauth_helpers.h"

#include "substitute.h"
#include "substitute-internal.h"
#include "dyld_cache_format.h"

static pthread_once_t dyld_inspect_once = PTHREAD_ONCE_INIT;
static pthread_once_t all_image_infos_once = PTHREAD_ONCE_INIT;
/* and its fruits: */
static uintptr_t (*ImageLoaderMachO_getSlide)(void *);
static const struct mach_header *(*ImageLoaderMachO_machHeader)(void *);
static bool (*dyld_validImage)(void *);
/*MegaDylib methods*/
static uintptr_t (*ImageLoaderMegaDylib_getSlide)(void*);
static void *(*ImageLoaderMegaDylib_getIndexedMachHeader)(void*, unsigned index);
static void *(*ImageLoaderMegaDylib_isCacheHandle)(void*proxy, void* handle, unsigned* index, uint8_t* flags);
static void **dyld_sAllCacheImagesProxy;
/*dyld3 methods */
static bool isUsingDyld3;
static bool isUsingDyld4;
static uintptr_t (*dyld3_MachOLoaded_getSlide)(const void *);
static struct mach_header_64 *(*dyld4_Loader_loadAddress)(const void *dlhandle, const void *runtimeState);
static int (*dyld4_Loader_validLoader)(const void *runtimeState, const void *dlhandle);
static void **dyld4_runtimeState_addr;


static const struct dyld_cache_header *_Atomic s_cur_shared_cache_hdr;
static struct dyld_cache_header l_s_cur_shared_cache_hdr;
static int s_cur_shared_cache_fd;
static pthread_once_t s_open_cache_once = PTHREAD_ONCE_INIT;
static struct dyld_cache_local_symbols_info s_cache_local_symbols_info;
static bool dyld_cache_local_symbols_entry_is64;
static struct dyld_cache_local_symbols_entry_32 *s_cache_local_symbols_entries_32;
static struct dyld_cache_local_symbols_entry_64 *s_cache_local_symbols_entries_64;
static const struct dyld_all_image_infos *_aii;

static void dyld_get_all_image_infos_once(void) {
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == KERN_SUCCESS) {
        _aii = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    } else {
        substitute_panic("couldn't find dyld_all_image_infos");
    }
}

static const struct dyld_all_image_infos *_aii;
const struct dyld_all_image_infos *dyld_get_all_image_infos() {
    pthread_once(&all_image_infos_once, dyld_get_all_image_infos_once);
    return _aii;
}

static bool oscf_try_dir(const char *dir, const char *arch,
                         const struct dyld_cache_header *dch) {
    char path[PATH_MAX];
    bool usingDetachedSymbols = true;
    if (snprintf(path, sizeof(path), "%s/%s%s.symbols", dir,
                 DYLD_SHARED_CACHE_BASE_NAME, arch) >= sizeof(path))
        return false;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        usingDetachedSymbols = false;
        if (snprintf(path, sizeof(path), "%s/%s%s", dir,
                     DYLD_SHARED_CACHE_BASE_NAME, arch) >= sizeof(path))
            return false;
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            return false;
        }
    }
    struct dyld_cache_header this_dch;
    if (read(fd, &this_dch, sizeof(this_dch)) != sizeof(this_dch))
        goto fail;
    if (usingDetachedSymbols) {
        if (memcmp(this_dch.uuid, dch->symbolSubCacheUUID, 16)) {
            goto fail;
        }
        dyld_cache_local_symbols_entry_is64 = true;
    } else {
        if (memcmp(this_dch.uuid, dch->uuid, 16)) {
            goto fail;
        }
    }
    struct dyld_cache_header *lch = &l_s_cur_shared_cache_hdr;
    if (pread(fd, lch, sizeof(*lch), 0) != sizeof(*lch)) {
        goto fail;
    }
    struct dyld_cache_local_symbols_info *lsi = &s_cache_local_symbols_info;
    if (pread(fd, lsi, sizeof(*lsi), lch->localSymbolsOffset) != sizeof(*lsi)) {
        goto fail;
    }
    if (lsi->nlistOffset > lch->localSymbolsSize ||
        lsi->nlistCount > (lch->localSymbolsSize - lsi->nlistOffset)
                           / sizeof(substitute_sym) ||
        lsi->stringsOffset > lch->localSymbolsSize ||
        lsi->stringsSize > lch->localSymbolsSize - lsi->stringsOffset) {
        /* bad format */
        goto fail;
    }
    uint32_t count = lsi->entriesCount;
    if (count > 1000000) {
        goto fail;
    }
    size_t lses_size = count * (dyld_cache_local_symbols_entry_is64?sizeof(struct dyld_cache_local_symbols_entry_64):sizeof(struct dyld_cache_local_symbols_entry_32));
    void *lses;

    if (!(lses = malloc(lses_size))) {
        goto fail;
    }
    if (pread(fd, lses, lses_size, lch->localSymbolsOffset + lsi->entriesOffset)
        != lses_size) {
        free(lses);
        goto fail;
    }

    s_cur_shared_cache_fd = fd;
    if (dyld_cache_local_symbols_entry_is64) {
        s_cache_local_symbols_entries_32 = NULL;
        s_cache_local_symbols_entries_64 = lses;
    } else {
        s_cache_local_symbols_entries_32 = lses;
        s_cache_local_symbols_entries_64 = NULL;
    }
    return true;

fail:
    memset(lsi, 0, sizeof(*lsi));
    close(fd);
    return false;
}

static void open_shared_cache_file_once() {
    s_cur_shared_cache_fd = -1;
    const struct dyld_cache_header *dch = s_cur_shared_cache_hdr;
    if (memcmp(dch->magic, "dyld_v1 ", 8)) {
        return;
    }
    if (dch->localSymbolsSize < sizeof(struct dyld_cache_local_symbols_info)) {
        // Probably ios15+ split cache
        //return;
    }
    const char *archp = &dch->magic[8];
    while (*archp == ' ')
        archp++;
    static char filename[32];
    const char *env_dir = getenv("DYLD_SHARED_CACHE_DIR");
    if (env_dir) {
        if (oscf_try_dir(env_dir, archp, dch))
            return;
    }
#if __IPHONE_OS_VERSION_MIN_REQUIRED
    if (!oscf_try_dir(IPHONE_DYLD_SHARED_CACHE_DIR, archp, dch)) {
        oscf_try_dir(IPHONE_DYLD_SHARED_CACHE_DIR_OLD, archp, dch);
    }
#else
    oscf_try_dir(MACOSX_DYLD_SHARED_CACHE_DIR, archp, dch);
#endif
}

static bool ul_mmap(int fd, off_t offset, size_t size,
                    void *data_p, void **mapping_p, size_t *mapping_size_p) {
    int pmask = getpagesize() - 1;
    int page_off = offset & pmask;
    off_t map_offset = offset & ~pmask;
    size_t map_size = ((offset + size + pmask) & ~pmask) - map_offset;
    void *mapping = mmap(NULL, map_size, PROT_READ, MAP_SHARED, fd, map_offset);
    if (mapping == MAP_FAILED)
        return false;
    *(void **) data_p = (char *) mapping + page_off;
    *mapping_p = mapping;
    *mapping_size_p = map_size;
    return true;
}

static bool get_shared_cache_syms(const void *hdr,
                                  const substitute_sym **syms_p,
                                  const char **strs_p,
                                  size_t *nsyms_p,
                                  void **mapping_p,
                                  size_t *mapping_size_p) {
    pthread_once(&s_open_cache_once, open_shared_cache_file_once);
    int fd = s_cur_shared_cache_fd;
    if (fd == -1) {
        return false;
    }
    const struct dyld_cache_header *dch = s_cur_shared_cache_hdr;
    const struct dyld_cache_local_symbols_info *lsi = &s_cache_local_symbols_info;
    struct dyld_cache_local_symbols_entry_32 *lse_32;
    struct dyld_cache_local_symbols_entry_64 *lse_64;
    if (dyld_cache_local_symbols_entry_is64) {
        for (uint32_t i = 0; i < lsi->entriesCount; i++) {
            lse_64 = &s_cache_local_symbols_entries_64[i];
            if (lse_64->dylibOffset == (uintptr_t) hdr - (uintptr_t) dch)
                goto got_lse;
        }
    } else {
        for (uint32_t i = 0; i < lsi->entriesCount; i++) {
            lse_32 = &s_cache_local_symbols_entries_32[i];
            if (lse_32->dylibOffset == (uintptr_t) hdr - (uintptr_t) dch)
                goto got_lse;
        }
    }
    return false;
got_lse:
    /* map - we don't do this persistently to avoid wasting address space on
     * iOS (my random OS X 10.10 blob pushes 55MB) */
    if (dyld_cache_local_symbols_entry_is64) {
        if (lse_64->nlistStartIndex > lsi->nlistCount ||
                lsi->nlistCount - lse_64->nlistStartIndex < lse_64->nlistCount) {
            return false;
        }
    } else {
        if (lse_32->nlistStartIndex > lsi->nlistCount ||
                lsi->nlistCount - lse_32->nlistStartIndex < lse_32->nlistCount) {
            return false;
        }
    }

    struct dyld_cache_header *lch = &l_s_cur_shared_cache_hdr;
    char *ls_data;
    if (!ul_mmap(fd, lch->localSymbolsOffset, lch->localSymbolsSize,
                 &ls_data, mapping_p, mapping_size_p)) {
        return false;
    }
    const substitute_sym *syms = (void *) (ls_data + lsi->nlistOffset);

    if (dyld_cache_local_symbols_entry_is64) {
        *syms_p = syms + lse_64->nlistStartIndex;
        *nsyms_p = lse_64->nlistCount;
    } else {
        *syms_p = syms + lse_32->nlistStartIndex;
        *nsyms_p = lse_32->nlistCount;
    }
    *strs_p = ls_data + lsi->stringsOffset;
    return true;
}


static const struct dyld_cache_header *get_cur_shared_cache_hdr() {
    const struct dyld_cache_header *dch = s_cur_shared_cache_hdr;
    if (!dch) {
        /* race is OK */
        uint64_t start_address = 0;
        if (syscall(294, &start_address)) /* shared_region_check_np */
            dch = (void *) 1;
        else
            dch = (void *) (uintptr_t) start_address;
        s_cur_shared_cache_hdr = dch;
    }
    return dch == (void *) 1 ? NULL : dch;
}

static bool addr_in_shared_cache(const void *addr) {
    const struct dyld_cache_header *dch = get_cur_shared_cache_hdr();
    if (!dch) {
        return false;
    }

    if (dch->mappingOffset <= 0x118) {
        uint32_t mapping_count = dch->mappingCount;
        const struct dyld_cache_mapping_info *mappings =
            (void *) ((char *) dch + dch->mappingOffset);
        intptr_t slide = (uintptr_t) dch - (uintptr_t) mappings[0].address;

        for (uint32_t i = 0; i < mapping_count; i++) {
            const struct dyld_cache_mapping_info *mapping = &mappings[i];
            uintptr_t diff = (uintptr_t) addr -
                ((uintptr_t) mapping->address + slide);
            if (diff < mapping->size)
                return true;
        }
    } else {
        uint32_t mapping_count = dch->mappingCount;
        intptr_t slide = (uintptr_t) dch - dch->sharedRegionStart;
        uintptr_t sharedRegionStart = (uintptr_t)dch;
        uintptr_t sharedRegionEnd = (uintptr_t)dch + dch->sharedRegionSize;
        if ((uintptr_t)addr >= sharedRegionStart && (uintptr_t)addr <= sharedRegionEnd)
            return true;
    }
    return false;
}

static void *sym_to_ptr(const substitute_sym *sym, intptr_t slide) {
    uintptr_t addr = sym->n_value;
    addr += slide;
    if (sym->n_desc & N_ARM_THUMB_DEF)
        addr |= 1;
    return (void *) addr;
}

static void find_syms_raw(const void *hdr, intptr_t *restrict slide,
                          const char **restrict names, void **restrict syms,
                          size_t nsyms) {
    memset(syms, 0, sizeof(*syms) * nsyms);

    void *mapping = NULL;
    size_t mapping_size = 0;
    const substitute_sym *cache_syms = NULL;
    const char *cache_strs = NULL;
    size_t ncache_syms = 0;
    if (addr_in_shared_cache(hdr))
        get_shared_cache_syms(hdr, &cache_syms, &cache_strs, &ncache_syms,
                              &mapping, &mapping_size);

    /* note: no verification at all */
    const mach_header_x *mh = hdr;
    uint32_t ncmds = mh->ncmds;
    struct load_command *lc = (void *) (mh + 1);
    struct symtab_command syc;
    for (uint32_t i = 0; i < ncmds; i++) {
        if (lc->cmd == LC_SYMTAB) {
            syc = *(struct symtab_command *) lc;
            goto ok;
        }
        lc = (void *) lc + lc->cmdsize;
    }
    return; /* no symtab, no symbols */
ok: ;
    substitute_sym *symtab = NULL;
    const char *strtab = NULL;
    lc = (void *) (mh + 1);
    for (uint32_t i = 0; i < ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_X) {
            segment_command_x *sc = (void *) lc;
            if (syc.symoff - sc->fileoff < sc->filesize)
                symtab = (void *) sc->vmaddr + syc.symoff - sc->fileoff;
            if (syc.stroff - sc->fileoff < sc->filesize)
                strtab = (void *) sc->vmaddr + syc.stroff - sc->fileoff;
            if (*slide == -1) {
                // used only for dyld
                *slide = (uintptr_t) hdr - sc->vmaddr;
            }
            if (symtab && strtab)
                goto ok2;
        }
        lc = (void *) lc + lc->cmdsize;
    }
    return; /* uh... weird */
ok2: ;
    symtab = (void *) symtab + *slide;
    strtab = (void *) strtab + *slide;
    size_t found_syms = 0;

    for (int type = 0; type <= 1; type++) {
        const substitute_sym *this_symtab = type ? cache_syms : symtab;
        const char *this_strtab = type ? cache_strs : strtab;
        size_t this_nsyms = type ? ncache_syms : syc.nsyms;
        /* This could be optimized for efficiency with a large number of
         * names... */
        for (uint32_t i = 0; i < this_nsyms; i++) {
            const substitute_sym *sym = &this_symtab[i];
            uint32_t strx = sym->n_un.n_strx;
            const char *name = strx == 0 ? "" : this_strtab + strx;
            for (size_t j = 0; j < nsyms; j++) {
                if (!syms[j] && !strcmp(name, names[j])) {
                    syms[j] = sym_to_ptr(sym, *slide);
                    if (++found_syms == nsyms)
                        goto end;
                }
            }
        }
    }

end:
    if (mapping_size)
        munmap(mapping, mapping_size);
}

/* This is a mess because the usual _dyld_image_count loop is not thread safe.
 * Since it uses a std::vector and (a) erases from it (making it possible for a
 * loop to skip entries) and (b) and doesn't even lock it in
 * _dyld_get_image_header etc., this is true even if the image is guaranteed to
 * be found, including the possibility to crash.  How do we solve this?
 * Inception - we steal dyld's private symbols...  We could avoid the symbols
 * by calling the vtable of dlopen handles, but that seems unstable.  As is,
 * the method used is somewhat convoluted in an attempt to maximize stability.
 */

const void *dyld_hdr;
static void inspect_dyld() {
    const struct dyld_all_image_infos *aii = dyld_get_all_image_infos();
    dyld_hdr = aii->dyldImageLoadAddress;
#if TARGET_OS_SIMULATOR
    if (strstr(_dyld_get_image_name(0), "dyld_sim")) {
        dyld_hdr = _dyld_get_image_header(0);
    }
#endif

    const void *libdyld_hdr = NULL;
    intptr_t libdyld_slide = 0;
    for(uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *im_name = _dyld_get_image_name(i);
        if (strstr(im_name, "/usr/lib/system/libdyld.dylib")) {
            libdyld_hdr = _dyld_get_image_header(i);
            libdyld_slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }

    const char *names[] = { "__ZNK16ImageLoaderMachO8getSlideEv",
                             "__ZNK16ImageLoaderMachO10machHeaderEv",
                             "__ZN4dyldL20sAllCacheImagesProxyE",
                             "__ZN20ImageLoaderMegaDylib13isCacheHandleEPvPjPh",
                             "__ZNK20ImageLoaderMegaDylib8getSlideEv",
                             "__ZNK20ImageLoaderMegaDylib20getIndexedMachHeaderEj",
                             "__ZNK5dyld311MachOLoaded8getSlideEv",
                             "__ZNK5dyld46Loader11loadAddressERNS_12RuntimeStateE",
                             "__ZNK5dyld46Loader11loadAddressERKNS_12RuntimeStateE",
                             "__ZN5dyld44APIs11validLoaderEPKNS_6LoaderE",
    };

    struct {
        void *__ZNK16ImageLoaderMachO8getSlideEv;
        void *__ZNK16ImageLoaderMachO10machHeaderEv;
        void *__ZN4dyldL20sAllCacheImagesProxyE;
        void *__ZN20ImageLoaderMegaDylib13isCacheHandleEPvPjPh;
        void *__ZNK20ImageLoaderMegaDylib8getSlideEv;
        void *__ZNK20ImageLoaderMegaDylib20getIndexedMachHeaderEj;
        void *__ZNK5dyld311MachOLoaded8getSlideEv;
        void *__ZNK5dyld46Loader11loadAddressERNS_12RuntimeStateE;
        void *__ZNK5dyld46Loader11loadAddressERKNS_12RuntimeStateE;
        void *__ZN5dyld44APIs11validLoaderEPKNS_6LoaderE;
    } syms;

    intptr_t dyld_slide = -1;
    find_syms_raw(dyld_hdr, &dyld_slide, names, (void**)&syms, sizeof(syms) / sizeof(void *));
    if (syms.__ZNK5dyld311MachOLoaded8getSlideEv && (syms.__ZNK5dyld46Loader11loadAddressERNS_12RuntimeStateE || syms.__ZNK5dyld46Loader11loadAddressERKNS_12RuntimeStateE) && syms.__ZN5dyld44APIs11validLoaderEPKNS_6LoaderE) {
        isUsingDyld4 = true;
        dyld3_MachOLoaded_getSlide = make_sym_callable(syms.__ZNK5dyld311MachOLoaded8getSlideEv);
        dyld4_Loader_loadAddress = make_sym_callable(syms.__ZNK5dyld46Loader11loadAddressERNS_12RuntimeStateE ? syms.__ZNK5dyld46Loader11loadAddressERNS_12RuntimeStateE : syms.__ZNK5dyld46Loader11loadAddressERKNS_12RuntimeStateE);
        dyld4_Loader_validLoader = make_sym_callable(syms.__ZN5dyld44APIs11validLoaderEPKNS_6LoaderE);
    } else {
        if (!syms.__ZNK16ImageLoaderMachO8getSlideEv || !syms.__ZNK16ImageLoaderMachO10machHeaderEv)
            substitute_panic("couldn't find ImageLoader methods\n");
        ImageLoaderMachO_getSlide = make_sym_callable(syms.__ZNK16ImageLoaderMachO8getSlideEv);
        ImageLoaderMachO_machHeader = make_sym_callable(syms.__ZNK16ImageLoaderMachO10machHeaderEv);
        dyld_sAllCacheImagesProxy = syms.__ZN4dyldL20sAllCacheImagesProxyE;
        ImageLoaderMegaDylib_isCacheHandle = make_sym_callable(syms.__ZN20ImageLoaderMegaDylib13isCacheHandleEPvPjPh);
        ImageLoaderMegaDylib_getSlide = make_sym_callable(syms.__ZNK20ImageLoaderMegaDylib8getSlideEv);
        ImageLoaderMegaDylib_getIndexedMachHeader = make_sym_callable(syms.__ZNK20ImageLoaderMegaDylib20getIndexedMachHeaderEj);
    }


    if (libdyld_hdr == NULL){
        return;
    }
    const char *libdyld_names[] = {
        "_gUseDyld3",
        "__ZNK5dyld311MachOLoaded8getSlideEv",
        "__ZN5dyld45gDyldE",
        "__ZN5dyld45gAPIsE",
    };
    struct {
        bool *_gUseDyld3;
        void *__ZNK5dyld311MachOLoaded8getSlideEv;
        void *__ZN5dyld45gDyldE;
        void *__ZN5dyld45gAPIsE;
    } libdyld_syms;

    find_syms_raw(libdyld_hdr, &libdyld_slide, libdyld_names, (void**)&libdyld_syms, sizeof(libdyld_syms) / sizeof(void *));

    if (libdyld_syms._gUseDyld3) {
        isUsingDyld3 = *libdyld_syms._gUseDyld3;
    }
    if (libdyld_syms.__ZNK5dyld311MachOLoaded8getSlideEv) {
        dyld3_MachOLoaded_getSlide = make_sym_callable(libdyld_syms.__ZNK5dyld311MachOLoaded8getSlideEv);
    }
    if (libdyld_syms.__ZN5dyld45gDyldE) {
        dyld4_runtimeState_addr = libdyld_syms.__ZN5dyld45gDyldE;
    } else if (libdyld_syms.__ZN5dyld45gAPIsE) {
        dyld4_runtimeState_addr = libdyld_syms.__ZN5dyld45gAPIsE;
    } else if (isUsingDyld4) {
        substitute_panic("couldn't find dyld4::runtimeState\n");
    }
}

/* 'dlhandle' keeps the image alive */
EXPORT
struct substitute_image *substitute_open_image(const char *filename) {
    pthread_once(&dyld_inspect_once, inspect_dyld);

    void *dlhandle = dlopen(filename, RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
    if (!dlhandle) {
        dlerror();
        return NULL;
    }

    void* image;
    if (isUsingDyld4) {
        dlhandle = ptrauth_strip(dlhandle, ptrauth_key_process_dependent_data);
        uint64_t dladdr = ((uint64_t)dlhandle & -2LL) ^ (uint64_t)dyld_hdr;
        if (!dyld4_Loader_validLoader(*dyld4_runtimeState_addr, (const void *)dladdr)) {
            dladdr = (uint64_t)dlhandle >> 1; // iOS15
            if (!dyld4_Loader_validLoader(*dyld4_runtimeState_addr, (const void *)dladdr)) {
                substitute_panic("substitute_open_image: Unable to find valid loader addr from handle\n");
            }
        }
        image = dyld4_Loader_loadAddress((const void *)dladdr, *dyld4_runtimeState_addr);
    } else if (isUsingDyld3) {
        image = (void*)((((uintptr_t)dlhandle) & (-2)) << 5);
    } else {
        image = (void*)(((uintptr_t)dlhandle) & (-4));
    }
    unsigned index;
    uint8_t mode;
    const void *image_header = NULL;
    intptr_t slide;
    if (dyld3_MachOLoaded_getSlide != NULL && (isUsingDyld3 || isUsingDyld4)) {
        uint32_t magic = *((uint32_t *)image);
        if ((magic == MH_MAGIC || magic == MH_MAGIC_64) && dyld3_MachOLoaded_getSlide != NULL){
            image_header = (const void *)image;

            slide = dyld3_MachOLoaded_getSlide(image_header);
        } else {
            substitute_panic("image does not have magic, not image?");
        }
    } else if (ImageLoaderMegaDylib_isCacheHandle != NULL && dyld_sAllCacheImagesProxy != NULL &&
            ImageLoaderMegaDylib_isCacheHandle(*dyld_sAllCacheImagesProxy, image, &index, &mode)) {
        if (ImageLoaderMegaDylib_getSlide == NULL || ImageLoaderMegaDylib_getIndexedMachHeader == NULL)
            substitute_panic("couldn't find ImageLoaderMegaDylib methods\n");
        slide = ImageLoaderMegaDylib_getSlide(*dyld_sAllCacheImagesProxy);
        image_header = ImageLoaderMegaDylib_getIndexedMachHeader(*dyld_sAllCacheImagesProxy, index);
    } else {
        image_header = ImageLoaderMachO_machHeader(image);
        slide = ImageLoaderMachO_getSlide(image);
    }

    dlclose(dlhandle);
    if (!image_header)
        return NULL;

    struct substitute_image *im = malloc(sizeof(*im));
    if (!im)
        return NULL;
    im->slide = slide;
    im->image_header = image_header;
    return im;
}

EXPORT
void substitute_close_image(struct substitute_image *im) {
    free(im);
}

EXPORT
int substitute_find_private_syms(struct substitute_image *im,
                                 const char **restrict names,
                                 void **restrict syms,
                                 size_t nsyms) {
    find_syms_raw(im->image_header, &im->slide, names, syms, nsyms);
    return SUBSTITUTE_OK;
}
#endif /* __APPLE__ */
