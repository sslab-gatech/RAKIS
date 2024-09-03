#include "rakis/stack/rakis_event.h"
#include "pal.h"

struct rakis_event* rakis_event_create(void){
  struct rakis_event* event = (struct rakis_event*)malloc(sizeof(struct rakis_event));
  if(event == NULL){
    return NULL;
  }

  int succ = 0;
  succ = PalEventCreate((PAL_HANDLE*)(&event->handle), false, false);
  if(succ != 0){
    free(event);
    return NULL;
  }

  return event;
}

void rakis_event_destroy(struct rakis_event* event){
  PalObjectClose(event->handle);
  free(event);
}

void rakis_event_set(struct rakis_event* event){
  PalEventSet(event->handle);
}

void rakis_event_reset(struct rakis_event* event){
  PalEventClear(event->handle);
}

int rakis_event_wait(struct rakis_event* event, unsigned long* timeout){
  int ret = PalEventWait(event->handle, timeout);
  if(ret == 0){
    return 0;
  }else if(ret == -PAL_ERROR_TRYAGAIN){
    return RAKIS_EVENT_TIMEOUT;
  }
  return -1;
}
