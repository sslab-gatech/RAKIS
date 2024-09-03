#include "pal.h"
#include "pal_internal.h"
#include "rakis/pal.h"

int PalRAKISInit(struct rakis_config* rakis_config, struct rakis_pal* rakis_pal){
  return _PalRAKISInit(rakis_config, rakis_pal);
}

void PalRAKISMonitorThreadStart(struct rakis_monitor_pal* rakis_monitor_pal){
  _PalRAKISMonitorThreadStart(rakis_monitor_pal);
}

