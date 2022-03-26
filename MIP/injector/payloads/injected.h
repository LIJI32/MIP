#ifndef injected_x86_h
#define injected_x86_h

#define DYLD_MAGIC_32 ('DYLD')
#define DYLD_MAGIC_64 ('DYLD'* 0x100000001)
#define ARGUMENT_MAGIC_STR "ARGUMENT"
#define ARGUMENT_MAX_LENGTH 256

extern char injected_arm_start __asm("section$start$__INJ_arm64e$__inj_arm64e");
extern char injected_arm_end __asm("section$end$__INJ_arm64e$__inj_arm64e");
extern char injected_x86_64_start __asm("section$start$__INJ_x86_64$__inj_x86_64");
extern char injected_x86_64_end __asm("section$end$__INJ_x86_64$__inj_x86_64");
extern char injected_i386_start __asm("section$start$__INJ_i386$__inj_i386");
extern char injected_i386_end __asm("section$end$__INJ_i386$__inj_i386");

#endif /* injected_x86_h */
