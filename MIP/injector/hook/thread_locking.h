/* Makes unsafe code thread-safe by pausing all other threads*/
#include <mach/kern_return.h>

kern_return_t suspend_all_other_threads(void);
kern_return_t resume_all_other_threads(void);
