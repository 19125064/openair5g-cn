#include <stdio.h>

#include "intertask_interface.h"
//#include "amf_app_ue_context.h"
#include "amf_app_defs.h" 
#include "amf_app_statistics.h"

#include "log.h"

int amf_app_statistics_display (
  void)
{   
  OAILOG_DEBUG (LOG_AMF_APP, "======================================= STATISTICS ============================================\n\n");
  OAILOG_DEBUG (LOG_AMF_APP, "               |   Current Status| Added since last display|  Removed since last display |\n");
  OAILOG_DEBUG (LOG_AMF_APP, "Connected gNBs | %10u      |     %10u              |    %10u               |\n",amf_app_desc.nb_gnb_connected,
                                          amf_app_desc.nb_gnb_connected_since_last_stat,amf_app_desc.nb_gnb_released_since_last_stat);
  OAILOG_DEBUG (LOG_AMF_APP, "Attached UEs   | %10u      |     %10u              |    %10u               |\n",amf_app_desc.nb_ue_attached,
                                          amf_app_desc.nb_ue_attached_since_last_stat,amf_app_desc.nb_ue_detached_since_last_stat);
  OAILOG_DEBUG (LOG_AMF_APP, "Connected UEs  | %10u      |     %10u              |    %10u               |\n",amf_app_desc.nb_ue_connected,
                                          amf_app_desc.nb_ue_connected_since_last_stat,amf_app_desc.nb_ue_disconnected_since_last_stat);
  OAILOG_DEBUG (LOG_AMF_APP, "Default Bearers| %10u      |     %10u              |    %10u               |\n",amf_app_desc.nb_default_eps_bearers,
                                          amf_app_desc.nb_eps_bearers_established_since_last_stat,amf_app_desc.nb_eps_bearers_released_since_last_stat);
  //OAILOG_DEBUG (LOG_AMF_APP, "S1-U Bearers   | %10u      |     %10u              |    %10u               |\n\n",amf_app_desc.nb_s1u_bearers,
  //                                        amf_app_desc.nb_s1u_bearers_established_since_last_stat,amf_app_desc.nb_s1u_bearers_released_since_last_stat);
  OAILOG_DEBUG (LOG_AMF_APP, "======================================= STATISTICS ============================================\n\n");
  
  amf_stats_write_lock (&amf_app_desc);
 
  // resetting stats for next display     
  amf_app_desc.nb_gnb_connected_since_last_stat = 0; 
  amf_app_desc.nb_gnb_released_since_last_stat  = 0;
  amf_app_desc.nb_ue_connected_since_last_stat  = 0;
  amf_app_desc.nb_ue_disconnected_since_last_stat  = 0; 
  amf_app_desc.nb_s1u_bearers_established_since_last_stat = 0;
  amf_app_desc.nb_s1u_bearers_released_since_last_stat = 0;
  amf_app_desc.nb_eps_bearers_established_since_last_stat = 0;
  amf_app_desc.nb_eps_bearers_released_since_last_stat = 0;
  amf_app_desc.nb_ue_attached_since_last_stat = 0;
  amf_app_desc.nb_ue_detached_since_last_stat = 0;
  
  amf_stats_unlock(&amf_app_desc);
  
  return 0;
}

// Number of Connected gNBs 
void update_amf_app_stats_connected_gnb_add(void)
{
  #if 0
  amf_stats_write_lock (&amf_app_desc);
  (amf_app_desc.nb_gnb_connected)++;
  (amf_app_desc.nb_gnb_connected_since_last_stat)++;
  amf_stats_unlock(&amf_app_desc);

  #endif

   __sync_fetch_and_add(&amf_app_desc.nb_gnb_connected, 1);
   __sync_fetch_and_add(&amf_app_desc.nb_gnb_connected_since_last_stat, 1);
  
  return;
}
void update_amf_app_stats_connected_gnb_sub(void)
{
  #if 0
  amf_stats_write_lock (&amf_app_desc);
  if (amf_app_desc.nb_gnb_connected !=0)
    (amf_app_desc.nb_gnb_connected)--;
  (amf_app_desc.nb_gnb_released_since_last_stat)--;
  amf_stats_unlock(&amf_app_desc);
  #endif

  __sync_fetch_and_sub(&amf_app_desc.nb_gnb_connected, 1);
  __sync_fetch_and_sub(&amf_app_desc.nb_gnb_connected_since_last_stat, 1);
 
  return;
} 
