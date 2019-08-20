#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "assertions.h"
#include "hashtable.h"
#include "log.h"
#include "conversions.h"
#include "intertask_interface.h"
#include "asn1_conversions.h"
#include "ngap_common.h"
#include "ngap_amf_encoder.h"
#include "ngap_amf_itti_messaging.h"
#include "ngap_amf.h"
#include "dynamic_memory_check.h"

extern hash_table_ts_t g_ngap_amf_id2assoc_id_coll;

/*
int
ngap_amf_handle_initial_ue_message (
  const sctp_assoc_id_t assoc_id,
  const sctp_stream_id_t stream,
  struct ngap_message_s *message)
{
  InitialUEMessage_IEs_t    *initialUEMessage_p = NULL;
  ue_description_t          *ue_ref = NULL;
  gnb_description_t         *gnb_ref = NULL;
  ran_ue_ngap_id_t           ran_ue_ngap_id = 0;

  OAILOG_FUNC_IN(LOG_NGAP);

  initialUEMessage_p = &message->msg.initialUEMessage_IEs;
  OAILOG_INFO (LOG_NGAP, "Received NGAP INITIAL_UE_MESSAGE RAN_UE_NGAP_ID " RAN_UE_NGAP_ID_FMT "\n", (ran_ue_ngap_id_t)initialUEMessage_p->ran_ue_ngap_id);

  if((gnb_ref = ngap_is_gnb_assoc_id_in_list(assoc_id)) == NULL){
    OAILOG_ERROR (LOG_NGAP, "Unknown gNB on assoc_id %d\n", assoc_id);
    OAILOG_FUNC_RETURN (LOG_NGAP, RETURNerror);
  }
  ran_ue_ngap_id = (ran_ue_ngap_id_t)(initialUEMessage_p->ran_ue_ngap_id & 0x00ffffff);
  OAILOG_INFO (LOG_NGAP, "New Initial UE message received with RAN UE NGAP ID: " RAN_UE_NGAP_ID_FMT "\n", ran_ue_ngap_id);

  ue_ref = ngap_is_ue_gnb_id_in_list (gnb_ref, ran_ue_ngap_id);
  if(ue_ref == NULL){
   //IDs ???i
    tai_t                                   tai = {.plmn = {0}, .tac = INVALID_TAC_0000};
    cgi_t                                  cgi = {.plmn = {0}, .cell_identity = {0}};

    if((ue_ref = ngap_new_ue(assoc_id,ran_ue_ngap_id)) == NULL){
      OAILOG_ERROR (LOG_NGAP, "NGAP:Initial UE Message- Failed to allocate NGAP UE Context, ran_ue_ngap_id:" RAN_UE_NGAP_ID_FMT "\n", ran_ue_ngap_id);
      OAILOG_FUNC_RETURN (LOG_NGAP, RETURNerror);
    }
    ue_ref->ng_ue_state = NGAP_UE_WAITING_CSR;
    ue_ref->ran_ue_ngap_id = ran_ue_ngap_id;
    ue_ref->amf_ue_ngap_id = INVALID_AMF_UE_NGAP_ID;  //be ready allocated by AMF
    ue_ref->ngap_ue_context_rel_timer.id = NGAP_TIMER_INACTIVE_ID;
    ue_ref->ngap_ue_context_rel_timer.sec = NGAP_UE_CONTEXT_REL_COMP_TIMER;
    ue_ref->sctp_stream_recv = stream;
    ue_ref->sctp_stream_send = ue_ref->gnb->next_sctp_stream;
    ue_ref->gnb->next_sctp_stream += 1;
    if(ue_ref->gnb->next_sctp_stream >= ue_ref->gnb->instreams){
      ue_ref->gnb->next_sctp_stream = 1;
    }
    //ngap_dump_gnb(ue_ref->gnb);

    //TAI
    if(&initialUEMessage_p->userLocationInformation.present == UserLocationInformation_PR_userLocationInformationNR){
      OCTET_STRING_TO_TAC (&initialUEMessage_p->userLocationInformation.choice.userLocationInformationNR.tAI.tAC, tai.tac);
      DevAssert (initialUEMessage_p->userLocationInformation.choice.userLocationInformationNR.tAI.pLMNIdentity.size == 3);
      TBCD_TO_PLMN_T(&initialUEMessage_p->userLocationInformation.choice.userLocationInformationNR.tAI.pLMNIdentity, &tai.plmn);
    }

    //CGI
    DevAssert (initialUEMessage_p->userLocationInformation.choice.userLocationInformationNR.nR_CGI.pLMNIdentity.size == 3);
    TBCD_TO_PLMN_T(&initialUEMessage_p->userLocationInformation.choice.userLocationInformationNR.nR_CGI.pLMNIdentity, &cgi.plmn);
    BIT_STRING_TO_CELL_IDENTITY (&initialUEMessage_p->userLocationInformation.choice.userLocationInformationNR.nR_CGI.nRCellIdentity, cgi.cell_identity);
   
    if(initialUEMessage_p->presenceMask & INITIALUEMESSAGE_IES_FIVEG_S_TMSI_PRESENT){} 
    if(initialUEMessage_p->presenceMask & INITIALUEMESSAGE_IES_AMFSETID_PRESENT){} 
    if(initialUEMessage_p->presenceMask & INITIALUEMESSAGE_IES_UECONTEXTREQUEST_PRESENT){} 
    if(initialUEMessage_p->presenceMask & INITIALUEMESSAGE_IES_ALLOWEDNSSAI_PRESENT){}
    ngap_amf_itti_amf_app_initial_ue_message(
      assoc_id,
      ue_ref->gnb->gnb_id,
      ue_ref->ran_ue_ngap_id,
      ue_ref->amf_ue_ngap_id,
      initialUEMessage_p->nas_pdu.buf,
      initialUEMessage_p->nas_pdu.size,
      &tai,
      &cgi,
      initialUEMessage_p->rrcEstablishmentCause,
      NULL,
      NULL,
      NULL,
      NULL
      ); 
  }

}
*/

int
ngap_generate_downlink_nas_transport (
  const ran_ue_ngap_id_t ran_ue_ngap_id,
  const amf_ue_ngap_id_t ue_id,
  STOLEN_REF bstring *payload)
{
  ue_description_t                       *ue_ref = NULL;
  uint32_t                                length = 1000;
  uint8_t                                *buffer_p = calloc(1,length);
  void                                   *id = NULL;
      
  OAILOG_FUNC_IN (LOG_NGAP);

  // Try to retrieve SCTP assoication id using amf_ue_ngap_id
  if (HASH_TABLE_OK ==  hashtable_ts_get (&g_ngap_amf_id2assoc_id_coll, (const hash_key_t)ue_id, (void **)&id)) {
    sctp_assoc_id_t sctp_assoc_id = (sctp_assoc_id_t)(uintptr_t)id;
    gnb_description_t  *gnb_ref = ngap_is_gnb_assoc_id_in_list (sctp_assoc_id);
    if (gnb_ref) {
      ue_ref = ngap_is_ue_gnb_id_in_list (gnb_ref,ran_ue_ngap_id);
    } else {
      OAILOG_ERROR (LOG_NGAP, "No gNB for SCTP association id %d \n", sctp_assoc_id);
      OAILOG_FUNC_RETURN (LOG_NGAP, RETURNerror);
    } 
  }   
  // TODO remove soon:
  if (!ue_ref) {
    ue_ref = ngap_is_ue_amf_id_in_list (ue_id);
  }     
  // finally!
  if (!ue_ref) {
  //if (ue_ref) {
    /*
     * If the UE-associated logical S1-connection is not established,
     * * * * the AMF shall allocate a unique AMF UE NGAP ID to be used for the UE.
     */
    OAILOG_WARNING (LOG_NGAP, "Unknown UE AMF ID " AMF_UE_NGAP_ID_FMT ", This case is not handled right now\n", ue_id);
    OAILOG_FUNC_RETURN (LOG_NGAP, RETURNerror);
  } else {
    /*
     * We have fount the UE in the list.
     * * * * Create new IE list message and encode it.
     */

    Ngap_DownlinkNASTransport_t          *ngapDownlinkNASTransport     = NULL;
    Ngap_DownlinkNASTransport_IEs_t      *ngapDownlinkNASTransportIEs  = NULL;

    Ngap_NGAP_PDU_t   pdu = {0};

    pdu.present = Ngap_NGAP_PDU_PR_initiatingMessage;
    pdu.choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
    pdu.choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_DownlinkNASTransport;
    pdu.choice.initiatingMessage->criticality = Ngap_Criticality_notify;
    pdu.choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_DownlinkNASTransport;
    ngapDownlinkNASTransport = &pdu.choice.initiatingMessage->value.choice.DownlinkNASTransport;
//amf_ue_ngap_id IE 
    ngapDownlinkNASTransportIEs = calloc(1, sizeof(Ngap_DownlinkNASTransport_IEs_t));
    ngapDownlinkNASTransportIEs->id = Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
    ngapDownlinkNASTransportIEs->value.present = Ngap_DownlinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID;
    Ngap_AMF_UE_NGAP_ID_t amf_ue_ngap_id;
    memset(&amf_ue_ngap_id, 0 , sizeof(Ngap_AMF_UE_NGAP_ID_t));
    amf_ue_ngap_id.buf = (uint8_t*)calloc(1,4*sizeof(uint8_t));
    *amf_ue_ngap_id.buf = 80;//(int)ue_ref->amf_ue_ngap_id; 
    amf_ue_ngap_id.size = 4;//4 octets
    ngapDownlinkNASTransportIEs->value.choice.AMF_UE_NGAP_ID = amf_ue_ngap_id;
    ASN_SEQUENCE_ADD(&ngapDownlinkNASTransport->protocolIEs, ngapDownlinkNASTransportIEs);
//ran_ue_ngap_id IE
    ngapDownlinkNASTransportIEs = calloc(1, sizeof(Ngap_DownlinkNASTransport_IEs_t));
    ngapDownlinkNASTransportIEs->id = Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
    ngapDownlinkNASTransportIEs->value.present = Ngap_DownlinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID;  
    Ngap_RAN_UE_NGAP_ID_t ran_ue_ngap_id_ie;
    memset(&ran_ue_ngap_id_ie, 0 , sizeof(Ngap_RAN_UE_NGAP_ID_t));
    ran_ue_ngap_id_ie = ue_ref->ran_ue_ngap_id; 
    ngapDownlinkNASTransportIEs->value.choice.RAN_UE_NGAP_ID = ran_ue_ngap_id_ie;
    ASN_SEQUENCE_ADD(&ngapDownlinkNASTransport->protocolIEs, ngapDownlinkNASTransportIEs);
//NAS-PDU IE
    ngapDownlinkNASTransportIEs = calloc(1, sizeof(Ngap_DownlinkNASTransport_IEs_t));
    ngapDownlinkNASTransportIEs->id = Ngap_ProtocolIE_ID_id_NAS_PDU;
    ngapDownlinkNASTransportIEs->value.present = Ngap_DownlinkNASTransport_IEs__value_PR_NAS_PDU;
    OCTET_STRING_fromBuf(&ngapDownlinkNASTransportIEs->value.choice.NAS_PDU,(char *)bdata(*payload), blength(*payload));
    ASN_SEQUENCE_ADD(&ngapDownlinkNASTransport->protocolIEs, ngapDownlinkNASTransportIEs); 
    bdestroy(*payload);
    *payload = NULL;

    asn_enc_rval_t er;
	
	//asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, &pdu);  //asn_printf
	
    er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, &pdu, buffer_p, length);
#if 1
        int i=0;
        uint8_t * buffer = (uint8_t*)buffer_p;
        //for(;i<er.encoded;buffer+=sizeof(uint8_t),i++)
        //  printf("%x",*((uint8_t*)buffer));
        //printf("\n");
#if 0
             {
               MessagesIds message_id = MESSAGES_ID_MAX;
               Ngap_NGAP_PDU_t decoded_pdu = {0};

               bstring b = blk2bstr(buffer_p, er.encoded);


               printf("NGAP_SetupRequest-------------decode, length:%d\n", er.encoded);
               ngap_amf_decode_pdu(&decoded_pdu, b,  &message_id);
               //ngap_amf_handle_message(0,0,&decoded_pdu);
             }
#endif
#endif

#if 0
    if(ngap_amf_encode_pdu (&pdu, &buffer_p, &length) < 0){
      OAILOG_FUNC_RETURN (LOG_NGAP, RETURNerror);
    }
#endif
    //OAILOG_NOTICE (LOG_NGAP, "Send NGAP DOWNLINK_NAS_TRANSPORT message ue_id = " AMF_UE_NGAP_ID_FMT " AMF_UE_NGAP_ID = " AMF_UE_NGAP_ID_FMT " gNB_UE_NGAP_ID = " RAN_UE_NGAP_ID_FMT "\n",
    //            ue_id, (amf_ue_ngap_id_t)ue_ref->amf_ue_ngap_id, (ran_ue_ngap_id_t)ue_ref->ran_ue_ngap_id);
    OAILOG_DEBUG(LOG_NGAP,"NGAP Downlink NAS message length(%d)\n",er.encoded);
    bstring b = blk2bstr(buffer_p,er.encoded);
    //printf("ngap_amf_itti_send_sctp_request\n");
    //printf("assoc_id (%d)\n",ue_ref->gnb->sctp_assoc_id);
    //ngap_amf_itti_send_sctp_request (&b , ran_ue_ngap_id, 1, ran_ue_ngap_id);
    ngap_amf_itti_send_sctp_request (&b , ue_ref->gnb->sctp_assoc_id, ue_ref->sctp_stream_send, ue_ref->amf_ue_ngap_id);
  }

  OAILOG_FUNC_RETURN (LOG_NGAP, RETURNok);
}

void      
ngap_handle_amf_ue_id_notification (
  const itti_amf_app_ngap_amf_ue_id_notification_t * const notification_p)
{           
          
  OAILOG_FUNC_IN (LOG_NGAP);
  DevAssert (notification_p != NULL);
  ngap_notified_new_ue_amf_ngap_id_association (
                          notification_p->sctp_assoc_id, notification_p->ran_ue_ngap_id, notification_p->amf_ue_ngap_id);
  OAILOG_FUNC_OUT (LOG_NGAP);
}
