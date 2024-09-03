#include "rakis/common.h"

#ifndef RAKIS_VERIFICATION
#define RAKIS_COPY_UNTRUSTED_VALUE(untrusted_ptr) ({                          \
    __typeof__(*(untrusted_ptr)) val;                                        \
    rakis_memcpy__untrusted(&val, (untrusted_ptr), sizeof(val));   \
    val;                                                                     \
    })
#else
#define RAKIS_COPY_UNTRUSTED_VALUE(untrusted_ptr) (*(untrusted_ptr))
#endif


void rakis_memcpy__untrusted(void* ptr, const void* uptr, size_t size);
