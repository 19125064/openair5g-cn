

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "log.h"
#include "intertask_interface.h"
#include "amf_config.h"
#include "nas_amf.h"
#include "mmData.h"
#include "nas_message.h"
#include "common_defs.h"
//#include "nas_network.h"
//#include "nas_proc.h"
//#include "emm_main.h"
//#include "nas_timer.h"


static void *nas_intertask_interface (void *args_p)
{
  itti_mark_task_ready (TASK_NAS_AMF);
  OAILOG_START_USE ();
  while (1) {
    MessageDef                             *received_message_p = NULL;

    itti_receive_msg (TASK_NAS_AMF, &received_message_p);

    switch (ITTI_MSG_ID (received_message_p)) {
      case NAS_INITIAL_UE_MESSAGE:
      case NGAP_DATA_IND:
        OAILOG_DEBUG(LOG_NAS,"NGAP_DATA_IND\n");
        if(blength(NGAP_UL_DATA_IND(received_message_p).nas_msg) > 0){
          //struct mm_data_context_s              *mm_ctx = NULL;
          //fivegmm_security_context_t             *security_context = NULL;
          nas_message_decode_status_t             decode_status = {0};
          int                                     decoder_rc = 0;
          int                                     rc = RETURNerror;

        fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
        security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA0;
        security->dl_count.overflow = 0xffff;
        security->dl_count.seq_num =  0x23;
        security->knas_enc[0] = 0x14;
        security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA0;
        security->knas_int[0] = 0x41;

          //mm_ctx = mm_data_context_get (&_mm_data, NGAP_UL_DATA_IND(received_message_p).ue_id);
/*          if (mm_ctx) {
            OAILOG_INFO (LOG_NAS_MM, "MM - got context %p\n", mm_ctx);
            if (IS_MM_CTXT_PRESENT_SECURITY(mm_ctx)) {
              security_context = &mm_ctx->_security;
            }
          }
*/
          nas_message_t  decoded_nas_msg;
          memset (&decoded_nas_msg,               0, sizeof (nas_message_t));
          decoder_rc = nas_message_decode (/*nas_msg_buffer*/(NGAP_UL_DATA_IND(received_message_p).nas_msg)->data,&decoded_nas_msg,blength(NGAP_UL_DATA_IND(received_message_p).nas_msg),security,&decode_status);
          bdestroy(NGAP_UL_DATA_IND(received_message_p).nas_msg);
          if (decoder_rc < TLV_FATAL_ERROR) {
            //*emm_cause = EMM_CAUSE_PROTOCOL_ERROR;
            OAILOG_FUNC_RETURN (LOG_NAS, decoder_rc);
          } else if (decoder_rc == TLV_UNEXPECTED_IEI) {
            //*emm_cause = EMM_CAUSE_IE_NOT_IMPLEMENTED;
          } else if (decoder_rc < 0) {
              //*emm_cause = EMM_CAUSE_PROTOCOL_ERROR;
          }
          amf_handle_nas_mm_message(&decoded_nas_msg, NGAP_UL_DATA_IND(received_message_p).tai, NGAP_UL_DATA_IND(received_message_p).cgi, &decode_status);
 
        }
      break;
      case NAS_MM_DL_DATA_REQ:
      break;
    }
  }
}






int nas_amf_init (amf_config_t * amf_config_p)
{
  OAILOG_FUNC_IN(LOG_NAS); 
  OAILOG_DEBUG (LOG_NAS, "Initializing NAS task interface\n");
  //nas_network_initialize (mme_config_p);
  
  if (itti_create_task (TASK_NAS_AMF, &nas_intertask_interface, NULL) < 0) {
    OAILOG_ERROR (LOG_NAS, "Create task failed");
    OAILOG_DEBUG (LOG_NAS, "Initializing NAS task interface: FAILED\n");
    return -1;
  }
  
  OAILOG_DEBUG (LOG_NAS, "Initializing NAS task interface: DONE\n");
  OAILOG_FUNC_RETURN(LOG_NAS,0);
  //return 0;
}
