#ifndef _AMF_APP_CONFIG_H_
#define _AMF_APP_CONFIG_H_

#include <pthread.h>
#include <stdint.h>

#include "log.h"

#define AMF_CONFIG_STRING_PID_DIRECTORY                  "PID_DIRECTORY"
#define AMF_CONFIG_STRING_AMF_CONFIG                     "AMF"
#define AMF_CONFIG_STRING_RUN_MODE                       "RUN_MODE"
#define AMF_CONFIG_STRING_RUN_MODE_TEST                  "TEST"
#define AMF_CONFIG_STRING_REALM                          "REALM"
//#define AMF_CONFIG_STRING_MAXENB                         "MAXENB"
#define AMF_CONFIG_STRING_MAXGNB                         "MAXGNB"
#define AMF_CONFIG_STRING_MAXUE                          "MAXUE"
#define AMF_CONFIG_STRING_RELATIVE_CAPACITY              "RELATIVE_CAPACITY"
#define AMF_CONFIG_STRING_STATISTIC_TIMER                "AMF_STATISTIC_TIMER"

#define AMF_CONFIG_STRING_EMERGENCY_REGISTRATION_SUPPORTED     "EMERGENCY_REGISTRATION_SUPPORTED"
#define AMF_CONFIG_STRING_UNAUTHENTICATED_IMSI_SUPPORTED "UNAUTHENTICATED_IMSI_SUPPORTED"
        
#define _5GS_NETWORK_FEATURE_SUPPORT_IMS_VOICE_OVER_PS_SESSION_IN_NG       "_5GS_NETWORK_FEATURE_SUPPORT_IMS_VOICE_OVER_PS_SESSION_IN_NG"
#define _5GS_NETWORK_FEATURE_SUPPORT_EMERGENCY_BEARER_SERVICES_IN_NG_MODE  "_5GS_NETWORK_FEATURE_SUPPORT_EMERGENCY_BEARER_SERVICES_IN_NG_MODE"
#define _5GS_NETWORK_FEATURE_SUPPORT_LOCATION_SERVICES_VIA_5GC             "_5GS_NETWORK_FEATURE_SUPPORT_LOCATION_SERVICES_VIA_5GC"
#define _5GS_NETWORK_FEATURE_SUPPORT_EXTENDED_SERVICE_REQUEST              "_5GS_NETWORK_FEATURE_SUPPORT_EXTENDED_SERVICE_REQUEST"


#define AMF_CONFIG_STRING_INTERTASK_INTERFACE_CONFIG     "INTERTASK_INTERFACE"
#define AMF_CONFIG_STRING_INTERTASK_INTERFACE_QUEUE_SIZE "ITTI_QUEUE_SIZE"

#define AMF_CONFIG_STRING_SCTP_CONFIG                    "SCTP"
#define AMF_CONFIG_STRING_SCTP_INSTREAMS                 "SCTP_INSTREAMS"
#define AMF_CONFIG_STRING_SCTP_OUTSTREAMS                "SCTP_OUTSTREAMS"

#define AMF_CONFIG_STRING_NGAP_CONFIG                    "NGAP"
#define AMF_CONFIG_STRING_NGAP_OUTCOME_TIMER             "NGAP_OUTCOME_TIMER"
#define AMF_CONFIG_STRING_NGAP_PORT                      "NGAP_PORT"

#define AMF_CONFIG_STRING_GUAMFI_LIST                    "GUAMFI_LIST"
#define AMF_CONFIG_STRING_AMF_CODE                       "AMF_CODE"
#define AMF_CONFIG_STRING_AMF_GID                        "AMF_GID"
#define AMF_CONFIG_STRING_TAI_LIST                       "TAI_LIST"
#define AMF_CONFIG_STRING_MCC                            "MCC"
#define AMF_CONFIG_STRING_MNC                            "MNC"
#define AMF_CONFIG_STRING_TAC                            "TAC"
#define AMF_CONFIG_AMF_REGION_ID                         "AMF_REGION_ID"
#define AMF_CONFIG_AMF_SET_ID 	                         "AMF_SET_ID"
#define AMF_CONFIG_AMF_POINTER                        	 "AMF_POINTER" 


#define AMF_CONFIG_STRING_NETWORK_INTERFACES_CONFIG      "NETWORK_INTERFACES"
#define AMF_CONFIG_STRING_INTERFACE_NAME_FOR_NG_AMF      "AMF_INTERFACE_NAME_FOR_NG_AMF"
#define AMF_CONFIG_STRING_IPV4_ADDRESS_FOR_NG_AMF        "AMF_IPV4_ADDRESS_FOR_NG_AMF"


#define AMF_CONFIG_STRING_NAS_CONFIG                     "NAS"
#define AMF_CONFIG_STRING_NAS_SUPPORTED_INTEGRITY_ALGORITHM_LIST  "ORDERED_SUPPORTED_INTEGRITY_ALGORITHM_LIST"
#define AMF_CONFIG_STRING_NAS_SUPPORTED_CIPHERING_ALGORITHM_LIST  "ORDERED_SUPPORTED_CIPHERING_ALGORITHM_LIST"



typedef enum {
  RUN_MODE_TEST = 0,
  RUN_MODE_OTHER
} run_mode_t;

typedef struct amf_config_s {
  /* Reader/writer lock for this configuration */
  pthread_rwlock_t rw_lock;


  bstring config_file;
  bstring pid_dir;
  bstring realm;

  run_mode_t  run_mode;

  uint32_t max_gnbs;
  uint32_t max_ues;

  uint8_t relative_capacity;

  uint32_t amf_statistic_timer;

  uint8_t unauthenticated_imsi_supported;

  struct {
    uint8_t ims_voice_over_ps_session_in_ng;
    uint8_t emergency_bearer_services_in_ng_mode;
    uint8_t location_services_via_5gc;
    uint8_t extended_service_request;
  } _5gs_network_feature_support;

  struct {
    uint8_t   nb_gummi;
	uint16_t *plmn_mcc;
    uint16_t *plmn_mnc;
    uint16_t *plmn_mnc_len;
    //uint16_t *tac;
    uint16_t *amf_region_id;
	uint16_t *amf_set_id;
	uint16_t *amf_pointer;
    //gummei_t gummei[MAX_GUAMFI];
  } gummei;

#define TRACKING_AREA_IDENTITY_LIST_TYPE_ONE_PLMN_NON_CONSECUTIVE_TACS 0x00
#define TRACKING_AREA_IDENTITY_LIST_TYPE_ONE_PLMN_CONSECUTIVE_TACS     0x01
#define TRACKING_AREA_IDENTITY_LIST_TYPE_MANY_PLMNS                    0x02
  struct {
    uint8_t   list_type;
    uint8_t   nb_tai;
    uint16_t *plmn_mcc;
    uint16_t *plmn_mnc;
    uint16_t *plmn_mnc_len;
    uint16_t *tac;
  } served_tai;

  struct {
    uint16_t in_streams;
    uint16_t out_streams;
  } sctp_config;


  struct {
    uint16_t port_number;
#define NGAP_PORT_NUMBER 36412
    uint8_t  outcome_drop_timer_sec;
  } ngap_config;

  struct {
    bstring    if_name_ng_amf;
    ipv4_nbo_t ng_amf;
    int        netmask_ng_amf;

  } ipv4;

  struct {
    uint32_t  queue_size;
    bstring   log_file;
  } itti_config;

  struct {
    uint8_t  prefered_integrity_algorithm[8];
    uint8_t  prefered_ciphering_algorithm[8];
    uint32_t t3402_min;
    uint32_t t3412_min;
    uint32_t t3485_sec;
    uint32_t t3486_sec;
    uint32_t t3489_sec;
    uint32_t t3495_sec;
  } nas_config;

  log_config_t log_config;
} amf_config_t;

extern amf_config_t amf_config;
int amf_config_parse_opt_line(int argc, char *argv[], amf_config_t *amf_config);

#endif
