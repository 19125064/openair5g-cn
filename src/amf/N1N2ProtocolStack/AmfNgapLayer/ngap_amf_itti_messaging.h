#include <stdint.h>
#include <string.h>

#include "bstrlib.h"
#include "assertions.h"
#include "common_defs.h"
#include "log.h"
#include "intertask_interface.h"
#include "common_types.h"
#include "ngap_common.h"

#ifndef FILE_NGAP_AMF_ITTI_MESSAGING_SEEN
#define FILE_NGAP_AMF_ITTI_MESSAGING_SEEN

int ngap_amf_itti_send_sctp_request(STOLEN_REF bstring *payload,
                                    const  uint32_t sctp_assoc_id_t,
                                    const sctp_stream_id_t stream,
                                    const amf_ue_ngap_id_t ue_id);

int ngap_amf_itti_nas_uplink_data_ind(const amf_ue_ngap_id_t ue_id,
                                      STOLEN_REF bstring *payload,
                                      const tai_t      const* tai,
                                      const cgi_t     const* cgi);

static inline void ngap_amf_itti_amf_app_initial_ue_message(
  const sctp_assoc_id_t      assoc_id,
  const uint32_t             gnb_id,
  const ran_ue_ngap_id_t     ran_ue_ngap_id,
  const amf_ue_ngap_id_t     amf_ue_ngap_id,
  const uint8_t * const      nas_msg,
  const size_t               nas_msg_length,
  const nr_tai_t             const*  nr_tai,
  const nr_cgi_t             const*  nr_cgi,
  const long                 rrc_cause,
  const fiveG_s_tmsi_t       const*  fiveG_s_tmsi,
  const amf_set_id_t         const*  amfSetID,
  const allowed_nssai_t      const*  allowedNSSAI)
{
  MessageDef  * message_p = NULL;
  OAILOG_FUNC_IN(LOG_NGAP);
  AssertFatal((nas_msg_length<1000),"Bad length for NAS message %lu",nas_msg_length);
  message_p = itti_alloc_new_message(TASK_NGAP,AMF_APP_INITIAL_UE_MESSAGE);
  
  AMF_APP_INITIAL_UE_MESSAGE(message_p).sctp_assoc_id                = assoc_id;
  AMF_APP_INITIAL_UE_MESSAGE(message_p).gnb_id                       = gnb_id;
  AMF_APP_INITIAL_UE_MESSAGE(message_p).ran_ue_ngap_id               = ran_ue_ngap_id;
  AMF_APP_INITIAL_UE_MESSAGE(message_p).amf_ue_ngap_id               = amf_ue_ngap_id;
  AMF_APP_INITIAL_UE_MESSAGE(message_p).nas                          = blk2bstr(nas_msg,nas_msg_length);
  AMF_APP_INITIAL_UE_MESSAGE(message_p).tai                          = *nr_tai;
  AMF_APP_INITIAL_UE_MESSAGE(message_p).cgi                          = *nr_cgi;
  AMF_APP_INITIAL_UE_MESSAGE(message_p).as_cause                     = rrc_cause; 
  AMF_APP_INITIAL_UE_MESSAGE(message_p).transparent.ran_ue_ngap_id   = ran_ue_ngap_id;
  AMF_APP_INITIAL_UE_MESSAGE(message_p).transparent.amf_ue_ngap_id   = amf_ue_ngap_id;
  AMF_APP_INITIAL_UE_MESSAGE(message_p).transparent.nr_cgi           = *nr_cgi;
  
  if(!fiveG_s_tmsi)
  {
      AMF_APP_INITIAL_UE_MESSAGE(message_p).is_fiveG_s_tmsi_valid    = false;
  }
  else
  {
      AMF_APP_INITIAL_UE_MESSAGE(message_p).is_fiveG_s_tmsi_valid    = true;
	  AMF_APP_INITIAL_UE_MESSAGE(message_p).fiveG_s_tmsi             = *fiveG_s_tmsi;
  }

  if(!amfSetID)
  {
      AMF_APP_INITIAL_UE_MESSAGE(message_p).is_amf_set_id_valid      = false;
  }
  else
  {
      AMF_APP_INITIAL_UE_MESSAGE(message_p).is_amf_set_id_valid      = true;
	  AMF_APP_INITIAL_UE_MESSAGE(message_p).amf_set_id               = *amfSetID;
  }
  
  if(!allowedNSSAI)
  {
      AMF_APP_INITIAL_UE_MESSAGE(message_p).is_allowed_nssai_valid   = false;
  }
  else
  {
      AMF_APP_INITIAL_UE_MESSAGE(message_p).is_allowed_nssai_valid   = true;
	  AMF_APP_INITIAL_UE_MESSAGE(message_p).allowedNSSAI             = *allowedNSSAI;
  }
      
  itti_send_msg_to_task(TASK_AMF_APP, INSTANCE_DEFAULT, message_p);
  OAILOG_FUNC_RETURN (LOG_NGAP,0);
}

#endif
