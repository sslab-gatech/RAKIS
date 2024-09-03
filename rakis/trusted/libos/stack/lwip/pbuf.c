
/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"

#include "lwip/pbuf.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/netif.h"

#include "rakis/stack/rakis_misc.h"
#include "rakis/pktbpool.h"
#include "rakis/atomics.h"

#ifdef RAKIS_VERIFICATION
#include "rakis/fv/host.h"
#endif

#include <string.h>

u16_t pbuf_clen(const struct pbuf *p) {
  u16_t len;

  len = 0;
  while (p != NULL) {
    ++len;
    p = p->next;
  }
  return len;
}

struct pbuf * pbuf_alloc(pbuf_layer layer, u16_t length){
  struct pbuf *p;
  u16_t offset = LWIP_MEM_ALIGN_SIZE((u16_t)layer);
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_alloc(length=%"U16_F")\n", length));

  mem_size_t payload_len = (mem_size_t)(offset + LWIP_MEM_ALIGN_SIZE(length));
  if (payload_len < LWIP_MEM_ALIGN_SIZE(length)) {
    return NULL;
  }

  p = (struct pbuf *)pktb_malloc(RAKIS_GET_THREAD_STRG(mempool), payload_len);
  if (p == NULL) {
    return NULL;
  }

  p->payload += offset;
  p->tot_len = p->len = length;
  LWIP_ASSERT("asked size: %d, set size: %d", length == p->len);

  LWIP_ASSERT("pbuf_alloc: pbuf->payload properly aligned",
      ((mem_ptr_t)p->payload % MEM_ALIGNMENT) == 0);
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_alloc(length=%"U16_F") == %p\n", length, (void *)p));
  return p;
}

struct pbuf* pbuf_alloc_ref(void){
  struct pbuf *p;

  p = (struct pbuf *)pktb_malloc(RAKIS_GET_THREAD_STRG(mempool), 0);
  if (p == NULL) {
    LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                ("pbuf_alloc_reference: Could not allocate MEMP_PBUF for PBUF_%s.\n",
                 "REF"));
    return NULL;
  }

  return p;
}

struct pbuf * pbuf_alloced_custom(u16_t length, struct pbuf_custom *p, void *payload_mem) {
  p->pbuf.next = NULL;
  p->pbuf.payload = payload_mem;
  p->pbuf.tot_len = length;
  p->pbuf.len = length;
  RAKIS_SET_ATOMIC(&p->pbuf.ref,  1);
  p->pbuf.if_idx = NETIF_NO_INDEX;
  return &p->pbuf;
}

void pbuf_trim(struct pbuf *p, u16_t new_len) {

  LWIP_ASSERT("pbuf_realloc: p != NULL", p != NULL);
  LWIP_ASSERT("pbuf_realloc: p->next == NULL", p->next == NULL);
  LWIP_ASSERT("pbuf_realloc: p->len == p->tot_len", p->len == p->tot_len);

  /* desired length larger than current length? */
  if (new_len >= p->tot_len) {
    return;
  }

  p->tot_len = p->len = new_len;
}

u8_t pbuf_add_header(struct pbuf *p, size_t header_size_increment){
  u16_t increment_magnitude;

  LWIP_ASSERT("p != NULL", p != NULL);
  if ((p == NULL) || (header_size_increment > 0xFFFF)) {
    return 1;
  }
  if (header_size_increment == 0) {
    return 0;
  }

  increment_magnitude = (u16_t)header_size_increment;
  /* Do not allow tot_len to wrap as a result. */
  if ((u16_t)(increment_magnitude + p->tot_len) < increment_magnitude) {
    return 1;
  }

  /* modify pbuf fields */
  p->payload = p->payload - header_size_increment;
  p->len = (u16_t)(p->len + increment_magnitude);
  p->tot_len = (u16_t)(p->tot_len + increment_magnitude);

  return 0;
}

u8_t pbuf_remove_header(struct pbuf *p, size_t header_size_decrement){
  void *payload;
  u16_t increment_magnitude;

  LWIP_ASSERT("p != NULL", p != NULL);
  if ((p == NULL) || (header_size_decrement > 0xFFFF)) {
    return 1;
  }

  if (header_size_decrement == 0) {
    return 0;
  }

  increment_magnitude = (u16_t)header_size_decrement;
  /* Check that we aren't going to move off the end of the pbuf */
  LWIP_ERROR("increment_magnitude <= p->len", (increment_magnitude <= p->len), return 1;);

  /* remember current payload pointer */
  payload = p->payload;
  LWIP_UNUSED_ARG(payload); /* only used in LWIP_DEBUGF below */

  /* increase payload pointer (guarded by length check above) */
  p->payload = (u8_t *)p->payload + header_size_decrement;
  /* modify pbuf length fields */
  p->len = (u16_t)(p->len - increment_magnitude);
  p->tot_len = (u16_t)(p->tot_len - increment_magnitude);

  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_remove_header: old %p new %p (%"U16_F")\n",
              (void *)payload, (void *)p->payload, increment_magnitude));

  return 0;
}

u8_t pbuf_free(struct pbuf *p) {
  RAKIS_STAT_INC(pktbpool_free_pbuf);
  struct pbuf *q;
  u8_t count;

  if (p == NULL) {
    LWIP_ASSERT("p != NULL", p != NULL);
    /* if assertions are disabled, proceed with debug output */
    LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_LEVEL_SERIOUS,
                ("pbuf_free(p == NULL) was called.\n"));
    return 0;
  }
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_free(%p)\n", (void *)p));

  count = 0;
  /* de-allocate all consecutive pbufs from the head of the chain that
   * obtain a zero reference count after decrementing*/
  while (p != NULL) {
    LWIP_PBUF_REF_T ref;
    /* decrease reference count (number of pointers to pbuf) */
    ref = RAKIS_DEC_ATOMIC(&p->ref);
    /* this pbuf is no longer referenced to? */
    if (ref == 0) {
      /* remember next pbuf in chain for next iteration */
      q = p->next;
      LWIP_DEBUGF( PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_free: deallocating %p\n", (void *)p));

      struct pbuf_custom *pc = (struct pbuf_custom *)p;
      LWIP_ASSERT("pc->custom_free_function != NULL", pc->custom_free_function != NULL);
      pc->custom_free_function(p);
      count++;

      /* proceed to next pbuf */
      p = q;
      /* p->ref > 0, this pbuf is still referenced to */
      /* (and so the remaining pbufs in chain as well) */
    } else {
      LWIP_DEBUGF( PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_free: %p has ref %"U16_F", ending here.\n", (void *)p, (u16_t)ref));
      /* stop walking through the chain */
      p = NULL;
    }
  }
  /* return number of de-allocated pbufs */
  return count;
}

/**
 * @ingroup pbuf
 * Increment the reference count of the pbuf.
 *
 * @param p pbuf to increase reference counter of
 *
 */
static void pbuf_ref(struct pbuf *p) {
  /* pbuf given? */
  if (p != NULL) {
    LWIP_PBUF_REF_T ref = RAKIS_INC_ATOMIC(&p->ref);
    LWIP_ASSERT("pbuf ref overflow", ref > 0);
  }
}

void pbuf_cat(struct pbuf *h, struct pbuf *t) {
  struct pbuf *p;

  LWIP_ERROR("(h != NULL) && (t != NULL) (programmer violates API)",
             ((h != NULL) && (t != NULL)), return;);

  /* proceed to last pbuf of chain */
  for (p = h; p->next != NULL; p = p->next) {
    /* add total length of second chain to all totals of first chain */
    p->tot_len = (u16_t)(p->tot_len + t->tot_len);
  }
  /* { p is last pbuf of first h chain, p->next == NULL } */
  LWIP_ASSERT("p->tot_len == p->len (of last pbuf in chain)", p->tot_len == p->len);
  LWIP_ASSERT("p->next == NULL", p->next == NULL);
  /* add total length of second chain to last pbuf total of first chain */
  p->tot_len = (u16_t)(p->tot_len + t->tot_len);
  /* chain last pbuf of head (p) with first of tail (t) */
  p->next = t;
  /* p->next now references t, but the caller will drop its reference to t,
   * so netto there is no change to the reference count of t.
   */
}

void pbuf_chain(struct pbuf *h, struct pbuf *t) {
  pbuf_cat(h, t);
  /* t is now referenced by h */
  pbuf_ref(t);
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_chain: %p references %p\n", (void *)h, (void *)t));
}

/**
 * @ingroup pbuf
 * Copy (part of) the contents of a packet buffer
 * to an application supplied buffer.
 *
 * @param buf the pbuf from which to copy data
 * @param dataptr the application supplied buffer
 * @param len length of data to copy (dataptr must be big enough). No more
 * than buf->tot_len will be copied, irrespective of len
 * @param offset offset into the packet buffer from where to begin copying len bytes
 * @return the number of bytes copied, or 0 on failure
 */
u16_t pbuf_copy_partial(const struct pbuf *buf, void *dataptr, u16_t len, u16_t offset) {
  const struct pbuf *p;
  u16_t left = 0;
  u16_t buf_copy_len;
  u16_t copied_total = 0;

  LWIP_ERROR("pbuf_copy_partial: invalid buf", (buf != NULL), return 0;);
  LWIP_ERROR("pbuf_copy_partial: invalid dataptr", (dataptr != NULL), return 0;);

  /* Note some systems use byte copy if dataptr or one of the pbuf payload pointers are unaligned. */
  for (p = buf; len != 0 && p != NULL; p = p->next) {
    if ((offset != 0) && (offset >= p->len)) {
      /* don't copy from this buffer -> on to the next */
      offset = (u16_t)(offset - p->len);
    } else {
      /* copy from this buffer. maybe only partially. */
      buf_copy_len = (u16_t)(p->len - offset);
      if (buf_copy_len > len) {
        buf_copy_len = len;
      }
      /* copy the necessary parts of the buffer */
      MEMCPY(&((char *)dataptr)[left], &((char *)p->payload)[offset], buf_copy_len);
      copied_total = (u16_t)(copied_total + buf_copy_len);
      left = (u16_t)(left + buf_copy_len);
      len = (u16_t)(len - buf_copy_len);
      offset = 0;
    }
  }
  return copied_total;
}

static err_t pbuf_copy_partial_pbuf(struct pbuf *p_to, const struct pbuf *p_from, u16_t copy_len, u16_t offset) {
  size_t offset_to = offset, offset_from = 0, len_calc;
  u16_t len;

  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_copy_partial_pbuf(%p, %p, %"U16_F", %"U16_F")\n",
              (const void *)p_to, (const void *)p_from, copy_len, offset));

  /* is the copy_len in range? */
  LWIP_ERROR("pbuf_copy_partial_pbuf: copy_len bigger than source", ((p_from != NULL) &&
             (p_from->tot_len >= copy_len)), return ERR_ARG;);
  /* is the target big enough to hold the source? */
  LWIP_ERROR("pbuf_copy_partial_pbuf: target not big enough", ((p_to != NULL) &&
             (p_to->tot_len >= (offset + copy_len))), return ERR_ARG;);

  /* iterate through pbuf chain */
  do {
    /* copy one part of the original chain */
    if ((p_to->len - offset_to) >= (p_from->len - offset_from)) {
      /* complete current p_from fits into current p_to */
      len_calc = p_from->len - offset_from;
    } else {
      /* current p_from does not fit into current p_to */
      len_calc = p_to->len - offset_to;
    }
    len = (u16_t)LWIP_MIN(copy_len, len_calc);
    MEMCPY((u8_t *)p_to->payload + offset_to, (u8_t *)p_from->payload + offset_from, len);
    offset_to += len;
    offset_from += len;
    copy_len -= len;
    LWIP_ASSERT("offset_to <= p_to->len", offset_to <= p_to->len);
    LWIP_ASSERT("offset_from <= p_from->len", offset_from <= p_from->len);
    if (offset_from >= p_from->len) {
      /* on to next p_from (if any) */
      offset_from = 0;
      p_from = p_from->next;
      LWIP_ERROR("p_from != NULL", (p_from != NULL) || (copy_len == 0), return ERR_ARG;);
    }
    if (offset_to == p_to->len) {
      /* on to next p_to (if any) */
      offset_to = 0;
      p_to = p_to->next;
      LWIP_ERROR("p_to != NULL", (p_to != NULL) || (copy_len == 0), return ERR_ARG;);
    }

    if ((p_from != NULL) && (p_from->len == p_from->tot_len)) {
      /* don't copy more than one packet! */
      LWIP_ERROR("pbuf_copy_partial_pbuf() does not allow packet queues!",
                 (p_from->next == NULL), return ERR_VAL;);
    }
    if ((p_to != NULL) && (p_to->len == p_to->tot_len)) {
      /* don't copy more than one packet! */
      LWIP_ERROR("pbuf_copy_partial_pbuf() does not allow packet queues!",
                 (p_to->next == NULL), return ERR_VAL;);
    }
  } while (copy_len);
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_copy_partial_pbuf: copy complete.\n"));
  return ERR_OK;
}

static err_t pbuf_copy(struct pbuf *p_to, const struct pbuf *p_from) {
  LWIP_DEBUGF(PBUF_DEBUG | LWIP_DBG_TRACE, ("pbuf_copy(%p, %p)\n",
              (const void *)p_to, (const void *)p_from));

  LWIP_ERROR("pbuf_copy: invalid source", p_from != NULL, return ERR_ARG;);
  return pbuf_copy_partial_pbuf(p_to, p_from, p_from->tot_len, 0);
}

struct pbuf * pbuf_clone(pbuf_layer layer, struct pbuf *p) {
  struct pbuf *q;
  err_t err;
  q = pbuf_alloc(layer, p->tot_len);
  if (q == NULL) {
    return NULL;
  }

  err = pbuf_copy(q, p);
  LWIP_UNUSED_ARG(err); /* in case of LWIP_NOASSERT */
  LWIP_ASSERT("pbuf_copy failed", err == ERR_OK);
  return q;
}
