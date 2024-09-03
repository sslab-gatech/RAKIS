#include "rakis/rakis_memcpy.h"

#ifdef RAKIS_VERIFICATION
#include "rakis/fv/host.h"
#else
#include "libos_utils.h"
#endif

/*
 * Reading from untrusted memory
 * mostly copied from enclave_framework.c
 * these functions should work with either direct or sgx though
 */

RAKIS_INLINE
void rakis_copy_u64s(void* dst, const void* untrusted_src, size_t count){
  assert((uintptr_t)untrusted_src % 8 == 0);
  __asm__ volatile (
      "rep movsq\n"
      : "+D"(dst), "+S"(untrusted_src), "+c"(count)
      :
      : "memory", "cc"
      );
}

void rakis_memcpy__untrusted(void* ptr, const void* uptr, size_t size){
  if (size == 0) {
    return;
  }

#ifdef RAKIS_VERIFICATION
  memcpy(ptr, uptr, size);
#else
  /*
   * This should be simple `memcpy(ptr, uptr, size)`, but CVE-2022-21233 (INTEL-SA-00657).
   * To mitigate this issue, all reads of untrusted memory from within the enclave must be done
   * in 8-byte chunks aligned to 8-bytes boundary. Since x64 allocates memory in pages of
   * (at least) 0x1000 in size, we can safely 8-align the pointer down and the size up.
   */
  size_t copy_len;
  size_t prefix_misalignment = (uintptr_t)uptr & 7;
  if (prefix_misalignment) {
    /* Beginning of the copied range is misaligned. */
    char prefix_val[8] = { 0 };
    rakis_copy_u64s(prefix_val, (char*)uptr - prefix_misalignment, /*count=*/1);

    copy_len = MIN(sizeof(prefix_val) - prefix_misalignment, size);
    memcpy(ptr, prefix_val + prefix_misalignment, copy_len);
    ptr = (char*)ptr + copy_len;
    uptr = (const char*)uptr + copy_len;
    size -= copy_len;

    if (size == 0) {
      return;
    }
  }
  assert((uintptr_t)uptr % 8 == 0);

  size_t suffix_misalignment = size & 7;
  copy_len = size - suffix_misalignment;
  assert(copy_len % 8 == 0);
  rakis_copy_u64s(ptr, uptr, copy_len / 8);
  ptr = (char*)ptr + copy_len;
  uptr = (const char*)uptr + copy_len;
  size -= copy_len;

  assert(size == suffix_misalignment);
  if (suffix_misalignment) {
    /* End of the copied range is misaligned. */
    char suffix_val[8] = { 0 };
    rakis_copy_u64s(suffix_val, uptr, /*count=*/1);
    memcpy(ptr, suffix_val, suffix_misalignment);
  }
#endif
}
