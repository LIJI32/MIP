#ifndef injected64_h
#define injected64_h

#define DYLD_MAGIC_32 ('DYLD')
#define DYLD_MAGIC_64 ('DYLD'* 0x100000001)
#define ARGUMENT_MAGIC_STR "ARGUMENT"
#define ARGUMENT_MAX_LENGTH 256

extern char injected32_start __asm("section$start$__INJECTED32$__injected32");
extern char injected32_end __asm("section$end$__INJECTED32$__injected32");
extern char injected64_start __asm("section$start$__INJECTED64$__injected64");
extern char injected64_end __asm("section$end$__INJECTED64$__injected64");

#endif /* injected64_h */
