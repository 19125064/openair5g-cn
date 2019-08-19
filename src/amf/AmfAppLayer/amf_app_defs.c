#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_types.h"
#include "amf_app_defs.h" 
#include "common_defs.h"
#include "log.h"

static void notify_ngap_new_ue_amf_ngap_id_association (amf_ue_ngap_id_t amf_ue_ngap_id,ran_ue_ngap_id_t ran_ue_ngap_id, sctp_assoc_id_t sctp_assoc_id);

void amf_app_handle_initial_ue_message       (itti_amf_app_initial_ue_message_t * const conn_est_ind_pP){
  OAILOG_FUNC_IN(LOG_AMF_APP);
  notify_ngap_new_ue_amf_ngap_id_association(0x80,conn_est_ind_pP->ran_ue_ngap_id,conn_est_ind_pP->sctp_assoc_id);

  int i = 0;
  bstring nas_msg = conn_est_ind_pP->nas;

  #if 0
  printf("gnb id(%d)\n",conn_est_ind_pP->gnb_id);
  printf("assoc id(%d)\n",conn_est_ind_pP->sctp_assoc_id);
  printf("nas test in amf_app_handle_initial_ue_message\n");
  printf("nas len(%d)\n",blength(nas_msg));
  #endif
  uint8_t * buffer = (uint8_t *)(bdata(nas_msg));

  #if 0
  for(;i<blength(nas_msg);i++)
    printf("0x%x ",buffer[i]);
  printf("\n");
  #endif

#if 1
  MessageDef                             *message_p = NULL;
  //message_p = itti_alloc_new_message (TASK_AMF_APP, NAS_INITIAL_UE_MESSAGE);
  message_p = itti_alloc_new_message (TASK_AMF_APP, NGAP_DATA_IND);
  NGAP_UL_DATA_IND(message_p).nas_msg = nas_msg;
  itti_send_msg_to_task (TASK_NAS_AMF, INSTANCE_DEFAULT, message_p);
#endif
 OAILOG_FUNC_RETURN(LOG_AMF_APP,0);
}


static void notify_ngap_new_ue_amf_ngap_id_association (amf_ue_ngap_id_t amf_ue_ngap_id,ran_ue_ngap_id_t ran_ue_ngap_id, sctp_assoc_id_t sctp_assoc_id)
{
  MessageDef                             *message_p = NULL;
  itti_amf_app_ngap_amf_ue_id_notification_t *notification_p = NULL;

  OAILOG_FUNC_IN (LOG_AMF_APP);
  message_p = itti_alloc_new_message (TASK_AMF_APP, AMF_APP_NGAP_AMF_UE_ID_NOTIFICATION);
  notification_p = &message_p->ittiMsg.amf_app_ngap_amf_ue_id_notification;
  memset (notification_p, 0, sizeof (itti_amf_app_ngap_amf_ue_id_notification_t));
  notification_p->ran_ue_ngap_id = ran_ue_ngap_id;
  notification_p->amf_ue_ngap_id = amf_ue_ngap_id;
  notification_p->sctp_assoc_id  = sctp_assoc_id;

  itti_send_msg_to_task (TASK_NGAP, INSTANCE_DEFAULT, message_p);
  OAILOG_DEBUG (LOG_AMF_APP, " Sent AMF_APP_NGAP_AMF_UE_ID_NOTIFICATION to NGAP for UE Id %u\n", notification_p->amf_ue_ngap_id);
  OAILOG_FUNC_RETURN (LOG_AMF_APP,0);
}
