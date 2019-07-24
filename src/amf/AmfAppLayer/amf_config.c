#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <libconfig.h>
  
#include <arpa/inet.h>          /* To provide inet_addr */

#include "assertions.h"
#include "dynamic_memory_check.h"
#include "log.h"
#include "intertask_interface.h"
#include "amf_config.h"
#include "intertask_interface_conf.h"
#include "sctp_default_values.h"
#include "common_defs.h"
#include "amf_default_values.h"
#include "bupt_config.h"


amf_config_t                            amf_config = {.rw_lock = PTHREAD_RWLOCK_INITIALIZER, 0};


static void amf_config_init (amf_config_t * config_pP)
{
  memset(&amf_config, 0, sizeof(amf_config));
  pthread_rwlock_init (&config_pP->rw_lock, NULL);
  config_pP->log_config.output             = NULL;
  config_pP->log_config.is_output_thread_safe = false;
  config_pP->log_config.color              = false;
  //config_pP->log_config.udp_log_level      = MAX_LOG_LEVEL; // Means invalid
  //config_pP->log_config.gtpv1u_log_level   = MAX_LOG_LEVEL; // will not overwrite existing log levels if AMF and S-GW bundled in same executable
  //config_pP->log_config.gtpv2c_log_level   = MAX_LOG_LEVEL;
  config_pP->log_config.sctp_log_level     = MAX_LOG_LEVEL;
  config_pP->log_config.ngap_log_level     = MAX_LOG_LEVEL;
  config_pP->log_config.nas_log_level      = MAX_LOG_LEVEL;
  config_pP->log_config.amf_app_log_level  = MAX_LOG_LEVEL;
  //config_pP->log_config.spgw_app_log_level = MAX_LOG_LEVEL;
  //config_pP->log_config.s11_log_level      = MAX_LOG_LEVEL;
  //config_pP->log_config.s6a_log_level      = MAX_LOG_LEVEL;
  //config_pP->log_config.util_log_level     = MAX_LOG_LEVEL;
  //config_pP->log_config.msc_log_level      = MAX_LOG_LEVEL;
  config_pP->log_config.itti_log_level     = MAX_LOG_LEVEL;
                               
  config_pP->log_config.asn1_verbosity_level = 0;
  config_pP->config_file = NULL;
  config_pP->max_gnbs = 2;
  config_pP->max_ues = 2;
  config_pP->unauthenticated_imsi_supported = 0;
  /*
   * 5GS network feature support
   */
  config_pP->_5gs_network_feature_support.emergency_bearer_services_in_ng_mode = 0;
  config_pP->_5gs_network_feature_support.extended_service_request = 0;
  config_pP->_5gs_network_feature_support.ims_voice_over_ps_session_in_ng = 0;
  config_pP->_5gs_network_feature_support.location_services_via_5gc = 0;

  config_pP->ngap_config.port_number = NGAP_PORT_NUMBER;

  /*
   * IP configuration
   */
  config_pP->ipv4.if_name_ng_amf = NULL;
  config_pP->ipv4.ng_amf = 0;
  config_pP->itti_config.queue_size = ITTI_QUEUE_MAX_ELEMENTS;
  config_pP->itti_config.log_file = NULL;
  config_pP->sctp_config.in_streams = SCTP_IN_STREAMS;
  config_pP->sctp_config.out_streams = SCTP_OUT_STREAMS;
  config_pP->relative_capacity = RELATIVE_CAPACITY;
  config_pP->amf_statistic_timer = AMF_STATISTIC_TIMER_S;
/*
  config_pP->gummei.nb = 1;
  config_pP->gummei.gummei[0].mme_code = AMFC;
  config_pP->gummei.gummei[0].mme_gid = AMFGID;
  config_pP->gummei.gummei[0].plmn.mcc_digit1 = 0;
  config_pP->gummei.gummei[0].plmn.mcc_digit2 = 0;
  config_pP->gummei.gummei[0].plmn.mcc_digit3 = 1;
  config_pP->gummei.gummei[0].plmn.mcc_digit1 = 0;
  config_pP->gummei.gummei[0].plmn.mcc_digit2 = 1;
  config_pP->gummei.gummei[0].plmn.mcc_digit3 = 0x0F;
*/

  /*
   * Set the TAI
   */
  config_pP->served_tai.nb_tai = 1;
  config_pP->served_tai.plmn_mcc = calloc (1, sizeof (*config_pP->served_tai.plmn_mcc));
  config_pP->served_tai.plmn_mnc = calloc (1, sizeof (*config_pP->served_tai.plmn_mnc));
  config_pP->served_tai.plmn_mnc_len = calloc (1, sizeof (*config_pP->served_tai.plmn_mnc_len));
  config_pP->served_tai.tac = calloc (1, sizeof (*config_pP->served_tai.tac));
  //config_pP->served_tai.plmn_mcc[0] = PLMN_MCC;
  //config_pP->served_tai.plmn_mnc[0] = PLMN_MNC;
  //config_pP->served_tai.plmn_mnc_len[0] = PLMN_MNC_LEN;
  //config_pP->served_tai.tac[0] = PLMN_TAC;
  //config_pP->ngap_config.outcome_drop_timer_sec = NGAP_OUTCOME_TIMER_DEFAULT;
}


static int amf_config_parse_file (amf_config_t * config_pP)
{
  config_t                                cfg = {0};
  config_setting_t                       *setting_amf = NULL;
  config_setting_t                       *setting = NULL;
  config_setting_t                       *subsetting = NULL;
  config_setting_t                       *sub2setting = NULL;

  int                                     aint = 0;
  int                                     i = 0,n = 0,
                                          stop_index = 0,
                                          num = 0;
  
  const char                             *astring = NULL;
  const char                             *tac = NULL;
  const char                             *mcc = NULL;
  const char                             *mnc = NULL;
  const char                             *sst = NULL;
  const char                             *sd = NULL;
  const char                             *amf_region_id= NULL;
  const char                             *amf_set_id= NULL;
  const char                             *amf_pointer = NULL;
  char                                   *if_name_ng_amf = NULL;
  char                                   *ng_amf = NULL;
  bool                                    swap = false;
  bstring                                 address = NULL;
  bstring                                 cidr = NULL;
  bstring                                 mask = NULL;
  struct in_addr                          in_addr_var = {0};

  config_init(&cfg);
  if(config_pP->config_file != NULL){
    if (!config_read_file (&cfg, bdata(config_pP->config_file))) {
      OAILOG_ERROR (LOG_CONFIG, ": %s:%d - %s\n", bdata(config_pP->config_file), config_error_line (&cfg), config_error_text (&cfg));
      config_destroy (&cfg);
      AssertFatal (1 == 0, "Failed to parse AMF configuration file %s!\n", bdata(config_pP->config_file));
    }
  }else{
    OAILOG_ERROR (LOG_CONFIG, " No AMF configuration file provided!\n");
    config_destroy (&cfg);
    AssertFatal (0, "No AMF configuration file provided!\n");
  }

  setting_amf = config_lookup(&cfg,AMF_CONFIG_STRING_AMF_CONFIG);//search AMF:{} in amf.conf
  if(setting_amf){
    setting = config_setting_get_member(setting_amf,LOG_CONFIG_STRING_LOGGING);//search LOGGING:{} in AMF:{}
    if(setting){
      if (config_setting_lookup_string (setting, LOG_CONFIG_STRING_OUTPUT, (const char **)&astring)) {//search string OUTPUT value
        if(astring){
          if (config_pP->log_config.output) {
            bassigncstr(config_pP->log_config.output , astring); 
          }else{
            config_pP->log_config.output = bfromcstr(astring); 
          }
        } 
      }
      if (config_setting_lookup_string (setting, LOG_CONFIG_STRING_OUTPUT_THREAD_SAFE, (const char **)&astring)) {
        if(astring){
          if (strcasecmp (astring, "yes") == 0) {
            config_pP->log_config.is_output_thread_safe = true;
          }else{
            config_pP->log_config.is_output_thread_safe = false;
          }
        }
      }
      if (config_setting_lookup_string (setting, LOG_CONFIG_STRING_COLOR, (const char **)&astring)) {
        if (0 == strcasecmp("true", astring)) config_pP->log_config.color = true;
        else config_pP->log_config.color = false;
      }
      if (config_setting_lookup_string (setting, LOG_CONFIG_STRING_SCTP_LOG_LEVEL, (const char **)&astring))
        config_pP->log_config.sctp_log_level = OAILOG_LEVEL_STR2INT (astring);
      if (config_setting_lookup_string (setting, LOG_CONFIG_STRING_NGAP_LOG_LEVEL, (const char **)&astring))
        config_pP->log_config.ngap_log_level = OAILOG_LEVEL_STR2INT (astring);
      if (config_setting_lookup_string (setting, LOG_CONFIG_STRING_NAS_LOG_LEVEL, (const char **)&astring))
        config_pP->log_config.nas_log_level = OAILOG_LEVEL_STR2INT (astring);
      if (config_setting_lookup_string (setting, LOG_CONFIG_STRING_AMF_APP_LOG_LEVEL, (const char **)&astring))
        config_pP->log_config.amf_app_log_level = OAILOG_LEVEL_STR2INT (astring);
      if (config_setting_lookup_string (setting, LOG_CONFIG_STRING_UTIL_LOG_LEVEL, (const char **)&astring))
        config_pP->log_config.util_log_level = OAILOG_LEVEL_STR2INT (astring);
      if (config_setting_lookup_string (setting, LOG_CONFIG_STRING_ITTI_LOG_LEVEL, (const char **)&astring))
        config_pP->log_config.itti_log_level = OAILOG_LEVEL_STR2INT (astring);

    }
    if ((config_setting_lookup_string (setting_amf, AMF_CONFIG_STRING_RUN_MODE, (const char **)&astring))) {
      if (strcasecmp (astring, AMF_CONFIG_STRING_RUN_MODE_TEST) == 0)
        config_pP->run_mode = RUN_MODE_TEST;
      else
        config_pP->run_mode = RUN_MODE_OTHER;
    }
    if ((config_setting_lookup_string (setting_amf, AMF_CONFIG_STRING_REALM, (const char **)&astring))) {
      config_pP->realm = bfromcstr (astring);
    } 
    if ((config_setting_lookup_string (setting_amf, AMF_CONFIG_STRING_LOCAL_AMF_NAME, (const char **)&astring))) {
      config_pP->amf_name = bfromcstr (astring);
    } 
    if ((config_setting_lookup_string (setting_amf,AMF_CONFIG_STRING_PID_DIRECTORY,(const char **)&astring))) {
      config_pP->pid_dir = bfromcstr (astring);
    }
    if ((config_setting_lookup_int (setting_amf, AMF_CONFIG_STRING_MAXGNB, &aint))) {
      config_pP->max_gnbs = (uint32_t) aint;
    }
    if ((config_setting_lookup_int (setting_amf, AMF_CONFIG_STRING_MAXUE, &aint))) {
      config_pP->max_ues = (uint32_t) aint;
    } 
    if ((config_setting_lookup_int (setting_amf, AMF_CONFIG_STRING_RELATIVE_CAPACITY, &aint))) {
      config_pP->relative_capacity = (uint8_t) aint;
    }
    if ((config_setting_lookup_int (setting_amf, AMF_CONFIG_STRING_STATISTIC_TIMER, &aint))) {
      config_pP->amf_statistic_timer = (uint32_t) aint;
    }
    if ((config_setting_lookup_string (setting_amf, _5GS_NETWORK_FEATURE_SUPPORT_EMERGENCY_BEARER_SERVICES_IN_NG_MODE, (const char **)&astring))) {
      if (strcasecmp (astring, "yes") == 0)
        config_pP->_5gs_network_feature_support.emergency_bearer_services_in_ng_mode = 1;
      else
        config_pP->_5gs_network_feature_support.emergency_bearer_services_in_ng_mode = 0;
    }
    if ((config_setting_lookup_string (setting_amf, _5GS_NETWORK_FEATURE_SUPPORT_EXTENDED_SERVICE_REQUEST, (const char **)&astring))) {
      if (strcasecmp (astring, "yes") == 0)
        config_pP->_5gs_network_feature_support.extended_service_request = 1;
      else
        config_pP->_5gs_network_feature_support.extended_service_request = 0;
    }
    if ((config_setting_lookup_string (setting_amf, _5GS_NETWORK_FEATURE_SUPPORT_IMS_VOICE_OVER_PS_SESSION_IN_NG, (const char **)&astring))) {
      if (strcasecmp (astring, "yes") == 0)
        config_pP->_5gs_network_feature_support.ims_voice_over_ps_session_in_ng = 1;
      else
        config_pP->_5gs_network_feature_support.ims_voice_over_ps_session_in_ng = 0;
    }
    if ((config_setting_lookup_string (setting_amf, _5GS_NETWORK_FEATURE_SUPPORT_LOCATION_SERVICES_VIA_5GC, (const char **)&astring))) {
      if (strcasecmp (astring, "yes") == 0)
        config_pP->_5gs_network_feature_support.location_services_via_5gc = 1;
      else
        config_pP->_5gs_network_feature_support.location_services_via_5gc = 0;
    }

    if ((config_setting_lookup_string (setting_amf, AMF_CONFIG_STRING_UNAUTHENTICATED_IMSI_SUPPORTED, (const char **)&astring))) {
      if (strcasecmp (astring, "yes") == 0)
        config_pP->unauthenticated_imsi_supported = 1;
      else
        config_pP->unauthenticated_imsi_supported = 0;
    }
    // ITTI SETTING
    setting = config_setting_get_member (setting_amf, AMF_CONFIG_STRING_INTERTASK_INTERFACE_CONFIG);
    if (setting != NULL) {
      if ((config_setting_lookup_int (setting, AMF_CONFIG_STRING_INTERTASK_INTERFACE_QUEUE_SIZE, &aint))) {
        config_pP->itti_config.queue_size = (uint32_t) aint;
      }
    }
    // SCTP SETTING
    setting = config_setting_get_member (setting_amf, AMF_CONFIG_STRING_SCTP_CONFIG);
    if (setting != NULL) {
      if ((config_setting_lookup_int (setting, AMF_CONFIG_STRING_SCTP_INSTREAMS, &aint))) {
        config_pP->sctp_config.in_streams = (uint16_t) aint;
      }
      if ((config_setting_lookup_int (setting, AMF_CONFIG_STRING_SCTP_OUTSTREAMS, &aint))) {
        config_pP->sctp_config.out_streams = (uint16_t) aint;
      }
    }
    // NGAP SETTING
    setting = config_setting_get_member (setting_amf, AMF_CONFIG_STRING_NGAP_CONFIG);
    if (setting != NULL) {
      if ((config_setting_lookup_int (setting, AMF_CONFIG_STRING_NGAP_OUTCOME_TIMER, &aint))) {
        config_pP->ngap_config.outcome_drop_timer_sec = (uint8_t) aint;
      }
      if ((config_setting_lookup_int (setting, AMF_CONFIG_STRING_NGAP_PORT, &aint))) {
        config_pP->ngap_config.port_number = (uint16_t) aint;
      }
    }
    //GUAMFI_LIST
    setting = config_setting_get_member (setting_amf, AMF_CONFIG_STRING_GUAMI_LIST);
    if (setting != NULL) {
      num = config_setting_length (setting);
      if (config_pP->guami.nb_gummi != num) {
        if (config_pP->guami.plmn_mcc != NULL)
          free_wrapper ((void**) &config_pP->served_tai.plmn_mcc);
        if (config_pP->guami.plmn_mnc != NULL)
          free_wrapper ((void**) &config_pP->guami.plmn_mnc);
        if (config_pP->guami.plmn_mnc_len != NULL)
          free_wrapper ((void**) &config_pP->guami.plmn_mnc_len);
		
        if (config_pP->guami.amf_region_id != NULL)
          free_wrapper ((void**) &config_pP->guami.amf_region_id);
		
		if (config_pP->guami.amf_set_id != NULL)
          free_wrapper ((void**) &config_pP->guami.amf_set_id);
		
		if (config_pP->guami.amf_pointer != NULL)
          free_wrapper ((void**) &config_pP->guami.amf_pointer);
		
        config_pP->guami.plmn_mcc = calloc (num, sizeof (*config_pP->guami.plmn_mcc));
        config_pP->guami.plmn_mnc = calloc (num, sizeof (*config_pP->guami.plmn_mnc));
        config_pP->guami.plmn_mnc_len = calloc (num, sizeof (*config_pP->guami.plmn_mnc_len));
        config_pP->guami.amf_region_id = calloc (num, sizeof (*config_pP->guami.amf_region_id));
		config_pP->guami.amf_set_id = calloc (num, sizeof (*config_pP->guami.amf_set_id));
		config_pP->guami.amf_pointer = calloc (num, sizeof (*config_pP->guami.amf_pointer));
      }
      config_pP->guami.nb_gummi = num;
      //AssertFatal(16 >= num , "Too many gummai configured %d", num);
      for (i = 0; i < num; i++) {
        sub2setting = config_setting_get_elem (setting, i);

        if (sub2setting != NULL) {
          if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_STRING_MCC, &mcc))) {
            config_pP->guami.plmn_mcc[i] = (uint16_t) atoi (mcc);
          }
          if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_STRING_MNC, &mnc))) {
            config_pP->guami.plmn_mnc[i] = (uint16_t) atoi (mnc);
            config_pP->guami.plmn_mnc_len[i] = strlen (mnc);
            AssertFatal ((config_pP->guami.plmn_mnc_len[i] == 2) || (config_pP->guami.plmn_mnc_len[i] == 3),
                "Bad MNC length %u, must be 2 or 3", config_pP->guami.plmn_mnc_len[i]);
          }
          if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_AMF_REGION_ID, &amf_region_id))) 
		  {
             config_pP->guami.amf_region_id[i] = (uint16_t) atoi (amf_region_id);
          }

		  if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_AMF_SET_ID, &amf_set_id)))
		  {
             config_pP->guami.amf_set_id[i] = (uint16_t) atoi (amf_set_id);
		  }

		  if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_AMF_POINTER, &amf_pointer))) 
		  {
            config_pP->guami.amf_pointer[i] = (uint16_t) atoi (amf_pointer);
          }
        }
      }
    }

    //AMF_SUPPORT_PLMN_IDENTITY_LIST setting
    setting = config_setting_get_member (setting_amf, AMF_SUPPORT_PLMN_IDENTITY_LIST);
    if (setting != NULL) 
	{
       num = config_setting_length (setting);
       if (config_pP->plmn_identity.nb_plmn_identity != num) 
	   {
          if (config_pP->plmn_identity.plmn_mcc != NULL)
              free_wrapper ((void**) &config_pP->plmn_identity.plmn_mcc);
		  if (config_pP->plmn_identity.plmn_mnc != NULL)
             free_wrapper ((void**) &config_pP->plmn_identity.plmn_mnc);
          if (config_pP->plmn_identity.plmn_mnc_len != NULL)
              free_wrapper ((void**) &config_pP->plmn_identity.plmn_mnc_len);
          if (config_pP->plmn_identity.tac != NULL)
              free_wrapper ((void**) &config_pP->plmn_identity.tac);

		  config_pP->plmn_identity.plmn_mcc = calloc (num, sizeof (*config_pP->plmn_identity.plmn_mcc));
          config_pP->plmn_identity.plmn_mnc = calloc (num, sizeof (*config_pP->plmn_identity.plmn_mnc));
          config_pP->plmn_identity.plmn_mnc_len = calloc (num, sizeof (*config_pP->plmn_identity.plmn_mnc_len));
		  config_pP->plmn_identity.tac      = calloc (num, sizeof (*config_pP->plmn_identity.tac));
       }

	   config_pP->plmn_identity.nb_plmn_identity = num;
       //AssertFatal(16 >= num , "Too many gummai configured %d", num);
       for (i = 0; i < num; i++) 
	   {
           sub2setting = config_setting_get_elem (setting, i);

           if (sub2setting != NULL) {
           if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_STRING_MCC, &mcc))) 
		   {
               config_pP->plmn_identity.plmn_mcc[i] = (uint16_t) atoi (mcc);  
           }
           if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_STRING_MNC, &mnc)))
		   {
			   config_pP->plmn_identity.plmn_mnc[i] = (uint16_t) atoi (mnc);
               config_pP->plmn_identity.plmn_mnc_len[i] = strlen (mnc);
               AssertFatal ((config_pP->plmn_identity.plmn_mnc_len[i] == 2) || (config_pP->plmn_identity.plmn_mnc_len[i] == 3),
                "Bad MNC length %u, must be 2 or 3", config_pP->plmn_identity.plmn_mnc_len[i]);
           }
		   if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_STRING_TAC, &tac))) 
		   {
              config_pP->plmn_identity.tac[i] = (uint16_t) atoi (tac);
           }
        }
       }
    }
	
	//AMF_SUPPORT_SLICE_LIST setting
    setting = config_setting_get_member (setting_amf, AMF_SUPPORT_SLICE_LIST);
    if (setting != NULL)
	{
       num = config_setting_length (setting);
       if (config_pP->slice_list.nb_slice != num) 
	   {
          if (config_pP->slice_list.SST != NULL)
             free_wrapper ((void**) &config_pP->slice_list.SST);
		  
		  if (config_pP->slice_list.SD != NULL)
             free_wrapper ((void**) &config_pP->slice_list.SD);

		  config_pP->slice_list.SST = calloc (num, sizeof (*config_pP->slice_list.SST));
		  config_pP->slice_list.SD  = calloc (num, sizeof (*config_pP->slice_list.SD));
       }

	   config_pP->slice_list.nb_slice = num;
	   for (i = 0; i < num; i++) 
	   {
           sub2setting = config_setting_get_elem (setting, i);
           if (sub2setting != NULL) 
		   {
              if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_STRING_SST, &sst))) 
		      {
                 config_pP->slice_list.SST[i] = (uint16_t) atoi (sst);
              }
			  if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_STRING_SD, &sd))) 
		      {
                 config_pP->slice_list.SD[i] = (uint16_t) atoi (sd);
              }
           }
	   }
    }
	

	
    // TAI list setting
    setting = config_setting_get_member (setting_amf, AMF_CONFIG_STRING_TAI_LIST);
    if (setting != NULL) {
      num = config_setting_length (setting);
      if (config_pP->served_tai.nb_tai != num) {
        if (config_pP->served_tai.plmn_mcc != NULL)
          free_wrapper ((void**) &config_pP->served_tai.plmn_mcc);
        if (config_pP->served_tai.plmn_mnc != NULL)
          free_wrapper ((void**) &config_pP->served_tai.plmn_mnc);
        if (config_pP->served_tai.plmn_mnc_len != NULL)
          free_wrapper ((void**) &config_pP->served_tai.plmn_mnc_len);
        if (config_pP->served_tai.tac != NULL)
          free_wrapper ((void**) &config_pP->served_tai.tac);
        config_pP->served_tai.plmn_mcc = calloc (num, sizeof (*config_pP->served_tai.plmn_mcc));
        config_pP->served_tai.plmn_mnc = calloc (num, sizeof (*config_pP->served_tai.plmn_mnc));
        config_pP->served_tai.plmn_mnc_len = calloc (num, sizeof (*config_pP->served_tai.plmn_mnc_len));
        config_pP->served_tai.tac = calloc (num, sizeof (*config_pP->served_tai.tac));
      }
      config_pP->served_tai.nb_tai = num;
      AssertFatal(16 >= num , "Too many TAIs configured %d", num);
      for (i = 0; i < num; i++) {
        sub2setting = config_setting_get_elem (setting, i);

        if (sub2setting != NULL) {
          if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_STRING_MCC, &mcc))) {
            config_pP->served_tai.plmn_mcc[i] = (uint16_t) atoi (mcc);
          }
          if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_STRING_MNC, &mnc))) {
            config_pP->served_tai.plmn_mnc[i] = (uint16_t) atoi (mnc);
            config_pP->served_tai.plmn_mnc_len[i] = strlen (mnc);
            AssertFatal ((config_pP->served_tai.plmn_mnc_len[i] == 2) || (config_pP->served_tai.plmn_mnc_len[i] == 3),
                "Bad MNC length %u, must be 2 or 3", config_pP->served_tai.plmn_mnc_len[i]);
          }
          if ((config_setting_lookup_string (sub2setting, AMF_CONFIG_STRING_TAC, &tac))) {
            config_pP->served_tai.tac[i] = (uint16_t) atoi (tac);
            //AssertFatal(TAC_IS_VALID(config_pP->served_tai.tac[i]), "Invalid TAC value "TAC_FMT, config_pP->served_tai.tac[i]);
          }
        }
      }
	
	
      num  = 0;
      // sort TAI list
      n = config_pP->served_tai.nb_tai;
      do {
        stop_index = 0; 
        for (i = 1; i < n; i++) {
          swap = false;
          if (config_pP->served_tai.plmn_mcc[i-1] > config_pP->served_tai.plmn_mcc[i]) {
            swap = true;
          } else if (config_pP->served_tai.plmn_mcc[i-1] == config_pP->served_tai.plmn_mcc[i]) {
            if (config_pP->served_tai.plmn_mnc[i-1] > config_pP->served_tai.plmn_mnc[i]) {
              swap = true;
            } else  if (config_pP->served_tai.plmn_mnc[i-1] == config_pP->served_tai.plmn_mnc[i]) {
              if (config_pP->served_tai.tac[i-1] > config_pP->served_tai.tac[i]) {
                swap = true;
              }
            }
          }
          if (true == swap) {
            uint16_t swap16;
            swap16 = config_pP->served_tai.plmn_mcc[i-1];
            config_pP->served_tai.plmn_mcc[i-1] = config_pP->served_tai.plmn_mcc[i];
            config_pP->served_tai.plmn_mcc[i]   = swap16;
            
            swap16 = config_pP->served_tai.plmn_mnc[i-1];
            config_pP->served_tai.plmn_mnc[i-1] = config_pP->served_tai.plmn_mnc[i];
            config_pP->served_tai.plmn_mnc[i]   = swap16;
            
            swap16 = config_pP->served_tai.tac[i-1];
            config_pP->served_tai.tac[i-1] = config_pP->served_tai.tac[i];
            config_pP->served_tai.tac[i]   = swap16;
            
            stop_index = i;
          }
        } 
        n = stop_index;
      } while (0 != n);

      // helper for determination of list type (global view), we could make sublists with different types, but keep things simple for now
      config_pP->served_tai.list_type = TRACKING_AREA_IDENTITY_LIST_TYPE_ONE_PLMN_CONSECUTIVE_TACS;
      for (i = 1; i < config_pP->served_tai.nb_tai; i++) {
        if ((config_pP->served_tai.plmn_mcc[i] != config_pP->served_tai.plmn_mcc[0]) ||
            (config_pP->served_tai.plmn_mnc[i] != config_pP->served_tai.plmn_mnc[0])){
          config_pP->served_tai.list_type = TRACKING_AREA_IDENTITY_LIST_TYPE_MANY_PLMNS;
          break;
        } else if ((config_pP->served_tai.plmn_mcc[i] != config_pP->served_tai.plmn_mcc[i-1]) ||
                   (config_pP->served_tai.plmn_mnc[i] != config_pP->served_tai.plmn_mnc[i-1])) {
          config_pP->served_tai.list_type = TRACKING_AREA_IDENTITY_LIST_TYPE_MANY_PLMNS;
          break;
        }
        if (config_pP->served_tai.tac[i] != (config_pP->served_tai.tac[i-1] + 1)) {
          config_pP->served_tai.list_type = TRACKING_AREA_IDENTITY_LIST_TYPE_ONE_PLMN_NON_CONSECUTIVE_TACS;
        }
      }
    }

    // NETWORK INTERFACE SETTING
    setting = config_setting_get_member (setting_amf, AMF_CONFIG_STRING_NETWORK_INTERFACES_CONFIG);

    if (setting != NULL) {
      if ((config_setting_lookup_string (setting, AMF_CONFIG_STRING_INTERFACE_NAME_FOR_NG_AMF, (const char **)&if_name_ng_amf)
           && config_setting_lookup_string (setting, AMF_CONFIG_STRING_IPV4_ADDRESS_FOR_NG_AMF, (const char **)&ng_amf)
          )
        ) {
        config_pP->ipv4.if_name_ng_amf = bfromcstr(if_name_ng_amf);
        cidr = bfromcstr (ng_amf);
        struct bstrList *list = bsplit (cidr, '/');
        AssertFatal(2 == list->qty, "Bad CIDR address %s", bdata(cidr));
        address = list->entry[0];
        mask    = list->entry[1];
        IPV4_STR_ADDR_TO_INT_NWBO (bdata(address), config_pP->ipv4.ng_amf, "BAD IP ADDRESS FORMAT FOR NG-AMF !\n");
        config_pP->ipv4.netmask_ng_amf = atoi ((const char*)mask->data);
        bstrListDestroy(list);
        in_addr_var.s_addr = config_pP->ipv4.ng_amf;
        OAILOG_INFO (LOG_AMF_APP, "Parsing configuration file found NG-AMF: %s/%d on %s\n",
                       inet_ntoa (in_addr_var), config_pP->ipv4.netmask_ng_amf, bdata(config_pP->ipv4.if_name_ng_amf));
      }
    }
  }

  OAILOG_SET_CONFIG(&config_pP->log_config);
  config_destroy (&cfg);

  return 0;
}

static void amf_config_display (amf_config_t * config_pP)
{
  OAILOG_INFO (LOG_CONFIG, "==== BUPT %s v%s ====\n", PACKAGE_NAME_BUPT_TEST, PACKAGE_VERSION_BUPT_TEST);
  OAILOG_INFO (LOG_CONFIG, "Configuration:\n");
  OAILOG_INFO (LOG_CONFIG, "- File .................................: %s\n", bdata(config_pP->config_file));
  OAILOG_INFO (LOG_CONFIG, "- Realm ................................: %s\n", bdata(config_pP->realm));
  OAILOG_INFO (LOG_CONFIG, "- Amf_Name .............................: %s\n", bdata(config_pP->amf_name));
  OAILOG_INFO (LOG_CONFIG, "- Run mode .............................: %s\n", (RUN_MODE_TEST == config_pP->run_mode) ? "TEST":"NORMAL");
  OAILOG_INFO (LOG_CONFIG, "- Max gNBs .............................: %u\n", config_pP->max_gnbs);
  OAILOG_INFO (LOG_CONFIG, "- Max UEs ..............................: %u\n", config_pP->max_ues);
  OAILOG_INFO (LOG_CONFIG, "- IMS voice over PS session in NG ......: %s\n", config_pP->_5gs_network_feature_support.ims_voice_over_ps_session_in_ng == 0 ? "false" : "true");
  OAILOG_INFO (LOG_CONFIG, "- Emergency bearer services in NG mode .: %s\n", config_pP->_5gs_network_feature_support.emergency_bearer_services_in_ng_mode == 0 ? "false" : "true");
  OAILOG_INFO (LOG_CONFIG, "- Location services via 5gc ............: %s\n", config_pP->_5gs_network_feature_support.location_services_via_5gc == 0 ? "false" : "true");
  OAILOG_INFO (LOG_CONFIG, "- Extended service request .............: %s\n", config_pP->_5gs_network_feature_support.extended_service_request == 0 ? "false" : "true");
  OAILOG_INFO (LOG_CONFIG, "- Unauth IMSI support ..................: %s\n", config_pP->unauthenticated_imsi_supported == 0 ? "false" : "true");
  OAILOG_INFO (LOG_CONFIG, "- Relative capa ........................: %u\n", config_pP->relative_capacity);
  OAILOG_INFO (LOG_CONFIG, "- Statistics timer .....................: %u (seconds)\n\n", config_pP->amf_statistic_timer);
  OAILOG_INFO (LOG_CONFIG, "- NG-AMF:\n");
  OAILOG_INFO (LOG_CONFIG, "    port number ......: %d\n", config_pP->ngap_config.port_number);
  OAILOG_INFO (LOG_CONFIG, "- IP:\n");
  OAILOG_INFO (LOG_CONFIG, "    ng-AMF iface .....: %s\n", bdata(config_pP->ipv4.if_name_ng_amf));
  OAILOG_INFO (LOG_CONFIG, "    ng-AMF ip ........: %s\n", inet_ntoa (*((struct in_addr *)&config_pP->ipv4.ng_amf)));
  OAILOG_INFO (LOG_CONFIG, "- ITTI:\n");
  OAILOG_INFO (LOG_CONFIG, "    queue size .......: %u (bytes)\n", config_pP->itti_config.queue_size);
  OAILOG_INFO (LOG_CONFIG, "    log file .........: %s\n", bdata(config_pP->itti_config.log_file));
  OAILOG_INFO (LOG_CONFIG, "- SCTP:\n");
  OAILOG_INFO (LOG_CONFIG, "    in streams .......: %u\n", config_pP->sctp_config.in_streams);
  OAILOG_INFO (LOG_CONFIG, "    out streams ......: %u\n", config_pP->sctp_config.out_streams);
}

static void usage (char *target)
{
  //OAILOG_INFO (LOG_CONFIG, "==== EURECOM %s version: %s ====\n", PACKAGE_NAME, PACKAGE_VERSION);
  //OAILOG_INFO (LOG_CONFIG, "Please report any bug to: %s\n", PACKAGE_BUGREPORT);
  OAILOG_INFO (LOG_CONFIG, "Usage: %s [options]\n", target);
  OAILOG_INFO (LOG_CONFIG, "Available options:\n");
  OAILOG_INFO (LOG_CONFIG, "-h      Print this help and return\n");
  OAILOG_INFO (LOG_CONFIG, "-c<path>\n");
  OAILOG_INFO (LOG_CONFIG, "        Set the configuration file for mme\n");
  OAILOG_INFO (LOG_CONFIG, "        See template in UTILS/CONF\n");
  OAILOG_INFO (LOG_CONFIG, "-K<file>\n");
  OAILOG_INFO (LOG_CONFIG, "        Output intertask messages to provided file\n");
  //OAILOG_INFO (LOG_CONFIG, "-V      Print %s version and return\n", PACKAGE_NAME);
  OAILOG_INFO (LOG_CONFIG, "-v[1-2] Debug level:\n");
  OAILOG_INFO (LOG_CONFIG, "            1 -> ASN1 XER printf on and ASN1 debug off\n");
  OAILOG_INFO (LOG_CONFIG, "            2 -> ASN1 XER printf on and ASN1 debug on\n");
}


int
amf_config_parse_opt_line (
  int argc,
  char *argv[],
  amf_config_t * config_pP)
{
  int                                     c;
      
  amf_config_init (config_pP);
  
  /*
   * Parsing command line
   */
  while ((c = getopt (argc, argv, "c:hi:K:v:V")) != -1) {
    switch (c) {
    case 'c':{
        /*
         * Store the given configuration file. If no file is given,
         * * * * then the default values will be used.
         */
        config_pP->config_file = blk2bstr(optarg, strlen(optarg));
        OAILOG_DEBUG (LOG_CONFIG, "%s amf_config.config_file %s\n", __FUNCTION__, bdata(config_pP->config_file));
      }
      break;
  
    case 'v':{
        config_pP->log_config.asn1_verbosity_level = atoi (optarg);
      } 
      break;
    
    case 'V':{
        //OAILOG_DEBUG (LOG_CONFIG, "==== EURECOM %s v%s ====" "Please report any bug to: %s\n", PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_BUGREPORT);
      }
      break;

    case 'K':
      config_pP->itti_config.log_file = blk2bstr (optarg, strlen(optarg));;
      OAILOG_DEBUG (LOG_CONFIG, "%s amf_config.itti_config.log_file %s\n", __FUNCTION__, bdata(config_pP->itti_config.log_file));
      break;

    case 'h':                  /* Fall through */
    default:
      usage (argv[0]);
      exit (0);
    }
  }

  /*
   * Parse the configuration file using libconfig
   */

  if (!config_pP->config_file) {
    config_pP->config_file = bfromcstr("/usr/local/etc/oai/amf.conf");
  }
  if (amf_config_parse_file (config_pP) != 0) {
    return -1;
  }

  /*
   * Display the configuration
   */

  amf_config_display (config_pP);

  return 0;
}
