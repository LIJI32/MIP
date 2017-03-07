#include <mach/task.h>
#include <mach/mach_init.h>
#include <stddef.h>
#include "symbols.h"

struct sCSTypeRef {
    void *csCppData;
    void *csCppObj;
};

struct sCSRange {
    unsigned long long location;
    unsigned long long length;
};
typedef struct sCSRange CSRange;

typedef struct sCSTypeRef CSTypeRef;
typedef CSTypeRef CSSymbolRef;
typedef CSTypeRef CSSymbolOwnerRef;
typedef CSTypeRef CSSymbolicatorRef;

typedef int (^CSSymbolOwnerIterator)(CSSymbolOwnerRef owner);

CSSymbolicatorRef CSSymbolicatorCreateWithTask(task_t task);
CSSymbolRef CSSymbolOwnerGetSymbolWithName(CSSymbolOwnerRef owner, const char* name);
int CSSymbolicatorForeachSymbolOwnerAtTime(CSSymbolicatorRef cs, uint64_t time, CSSymbolOwnerIterator it);
CSRange CSSymbolGetRange(CSSymbolRef sym);

void *get_symbol(const char *name)
{
    CSSymbolicatorRef symbolicator =  CSSymbolicatorCreateWithTask(mach_task_self());
    void __block *ret = NULL;
    CSSymbolicatorForeachSymbolOwnerAtTime(symbolicator, 0, ^int(CSSymbolOwnerRef owner) {
        /* Return value seems to be ignored. */
        if (ret) return 0;
        ret = (void*)CSSymbolGetRange(CSSymbolOwnerGetSymbolWithName(owner, name)).location;
        return 0;
    });
    return ret;
}
