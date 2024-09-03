#include "pal.h"
#include "pal_internal.h"
#include "rakis/host_init.h"
#include "rakis/io_uring.h"
#include "rakis/monitor.h"
#include "rakis/pal.h"

int _PalRAKISInit(struct rakis_config* rakis_config, struct rakis_pal* rakis_pal){

  int ret;
  ret = rakis_host_init(rakis_config, rakis_pal);
  if (ret < 0) {
    log_error("rakis host init failed");
    return ret;
  }

  ret = rakis_initialization_data_checker(rakis_config, rakis_pal);
  if(ret < 0){
    log_error("Possibly malicious host!.. RAKIS Could not verify netif initialization results");
    return ret;
  }

  ret = rakis_init_pal_io_urings(&rakis_config->io_urings_cfg, rakis_pal);
  if(ret < 0){
    log_error("Could not init rakis pal iourings");
    return ret;
  }

  struct pal_public_state* pal_public_state = PalGetPalPublicState();
  pal_public_state->rakis_status = &rakis_config->status;

  return 0;
}

void _PalRAKISMonitorThreadStart(struct rakis_monitor_pal* rakis_monitor_pal){
  rakis_monitor_start(rakis_monitor_pal);
  _PalThreadExit(NULL);
  while(1);
}

