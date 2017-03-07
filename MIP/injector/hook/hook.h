#ifndef hook_h
#define hook_h

/* This is a VERY simple x86-64 function hooker that only supports function starting with a very limited set of
   instructions; sepcific variations of push, pop and mov. If it encounters an unsupported instruction, it will
   return NULL as the pointer to the unhooked function. Since this isn't a general purpose function hooker and
   is only used to hook a specific function in launchservicesd, this is more than enough.
 */

void *hook_function(uint8_t *old, uint8_t *new);

#endif
