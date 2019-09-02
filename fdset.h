
#ifndef fdset_h
#define fdset_h

#include <stdint.h>
#include <sys/cdefs.h>
__BEGIN_DECLS

void* fdset_get(uint32_t* nr, uint32_t cycle);
// keep should be an uint32_t[3], and should be zero
// before passed to fdset_join2, and should be avaliable
// until the last fdset_join2 returns
int fdset_join2(void* set, volatile int32_t* flag, int32_t* keep);
void fdset_put(void* set);

__END_DECLS
#endif
