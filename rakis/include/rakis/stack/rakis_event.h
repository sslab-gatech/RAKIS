#ifndef RAKIS_EVENT_H
#define RAKIS_EVENT_H

#define RAKIS_EVENT_TIMEOUT -1

struct rakis_event{
  void* handle;
};

struct rakis_event* rakis_event_create(void);
void rakis_event_destroy(struct rakis_event* event);
void rakis_event_set(struct rakis_event* event);
void rakis_event_reset(struct rakis_event* event);
int rakis_event_wait(struct rakis_event* event, unsigned long* timeout);

#endif
