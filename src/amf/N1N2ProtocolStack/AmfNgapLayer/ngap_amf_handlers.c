#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "ngap_amf_handlers.h"
#include "log.h"
#include "ngap_amf.h"
#include "common_defs.h"
#include "assertions.h"
#include "ngap_amf_itti_messaging.h"
#include "ngap_amf_ta.h"
#include "ngap_common.h"
#include "ngap_amf_nas_procedures.h"
#include "Ngap_NGAP-PDU.h"
#include "Ngap_SliceSupportItem.h"
#include "sctp_gNB_defs.h"
#include "Ngap_CriticalityDiagnostics-IE-Item.h"
#include "Ngap_CriticalityDiagnostics-IE-List.h"
#include "ngap_amf_setup_failure.h"
#include "ngap_amf_setup_response.h"
#include "ngap_amf_downlink_nas_transport.h"

#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_InitiatingMessage.h"
#include "Ngap_BroadcastPLMNItem.h"
#include "Ngap_GNB-ID.h"
#include "Ngap_GlobalGNB-ID.h"
#include "Ngap_PagingDRX.h"
#include "Ngap_SliceSupportItem.h"
#include "Ngap_SupportedTAItem.h"
#include "Ngap_UnsuccessfulOutcome.h"
#include "Ngap_GlobalRANNodeID.h"

#include  "Ngap_CriticalityDiagnostics-IE-Item.h"
#include  "Ngap_EUTRACellIdentity.h"
#include  "Ngap_TimeStamp.h"
#include  "Ngap_EUTRA-CGI.h"
#include  "Ngap_UserLocationInformationEUTRA.h"
#include  "Ngap_UserLocationInformationNR.h"
#include  "Ngap_UserLocationInformationN3IWF.h"
#include  "Ngap_UEContextRequest.h"

#include  "Ngap_AllowedNSSAI-Item.h"

#include  "asn1_conversions.h"
#include  "conversions.h"
#include  "amf_config.h"
#include  "Ngap_AMFSetID.h"
#include  "Ngap_Cause.h"
#include  "Ngap_NRCellIdentity.h"

extern hash_table_ts_t g_ngap_gnb_coll;
extern uint32_t nb_gnb_associated;
static const char * const ng_gnb_state_str [] = {"NGAP_INIT", "NGAP_RESETTING", "NGAP_READY", "NGAP_SHUTDOWN"};


ngap_message_decoded_callback   messages_callback[][3] = {
    {0,0,0}, /*AMFConfigurationUpdate*/
    {0,0,0}, /*AMFStatusIndication*/
    {0,0,0}, /*CellTrafficTrace*/
    {0,0,0}, /*DeactivateTrace*/
    {0,0,0}, /*DownlinkNASTransport*/
    
    {0,0,0}, /*DownlinkNonUEAssociatedNRPPaTransport*/
    {0,0,0}, /*DownlinkRANConfigurationTransfer*/
    {0,0,0}, /*DownlinkRANStatusTransfer*/
    {0,0,0}, /*DownlinkUEAssociatedNRPPaTransport*/
    {0,0,0},//{ngap_amf_handle_error_indication,0,0}, /*ErrorIndication*/
    
    {0,0,0}, /*HandoverCancel*/
    {0,0,0}, /*HandoverNotification*/
    {0,0,0}, /*HandoverPreparation*/
    {0,0,0}, /*HandoverResourceAllocation*/
    {0,0,0},//{
     //0,ngap_amf_handle_initial_context_setup_response,
     //ngap_amf_handle_initial_context_setup_failure}, /*InitialContextSetup*/
    {ngap_amf_handle_ng_initial_ue_message,0,0},//{ngap_amf_handle_initial_ue_message,0,0}, /*InitialUEMessage*/
    {0,0,0}, /*LocationReportingControl*/
    {0,0,0}, /*LocationReportingFailureIndication*/
    {0,0,0}, /*LocationReport*/
    {0,0,0}, /*NASNonDeliveryIndication*/
    
    {0,0,0}, /*NGReset*/
    {ngap_amf_handle_ng_setup_request,0,0}, /*NGSetup*/
    {0,0,0}, /*OverloadStart*/
	{0,0,0}, /*OverloadStop*/
    {0,0,0}, /*Paging*/
    
    {0,0,0},//{ngap_amf_handle_path_switch_request,0,0}, /*PathSwitchRequest*
    {0,0,0}, /*PDUSessionResourceModify*/
    {0,0,0}, /*PDUSessionResourceModifyIndication*/
    {0,0,0}, /*PDUSessionResourceRelease*/
    {0,0,0}, /*PDUSessionResourceSetup*/
    
    {0,0,0}, /*PDUSessionResourceNotify*/
    {0,0,0}, /*PrivateMessage*/
    {0,0,0}, /*PWSCancel*/
    {0,0,0}, /*PWSFailureIndication*/
    {0,0,0}, /*PWSRestartIndication*/

	
    {0,0,0}, /*RANConfigurationUpdate*/
    {0,0,0}, /*RerouteNASRequest*/
    {0,0,0}, /*RRCInactiveTransitionReport*/
    {0,0,0}, /*TraceFailureIndication*/
    {0,0,0}, /*TraceStart*/

	
    {0,0,0}, /*UEContextModification*/
    {0,0,0},//{0,ngap_amf_handle_ue_context_release_complete,0}, /*UEContextRelease*/
    {0,0,0},//{ngap_amf_handle_ue_context_release_request,0,0}, /*UEContextReleaseRequest*/
    {0,0,0}, /*UERadioCapabilityCheck*/
    {0,0,0},//{ngap_amf_handle_ue_radio_cap_indication,0,0}, /*UERadioCapabilityInfoIndication*/

	
    {0,0,0}, /*UETNLABindingRelease*/
    {ngap_amf_handle_ng_uplink_nas_transport,0,0},//{ngap_amf_handle_uplink_nas_transport,0,0}, /*UplinkNASTransport*/
    {0,0,0}, /*UplinkNonUEAssociatedNRPPaTransport*/
    {0,0,0}, /*UplinkRANConfigurationTransfer*/
    {0,0,0}, /*UplinkRANStatusTransfer*/

	
    {0,0,0}, /*UplinkUEAssociatedNRPPaTransport*/
    {0,0,0}, /*WriteReplaceWarning*/
	{0,0,0}, /*WriteReplaceWarning*/
	{0,0,0}, /*WriteReplaceWarning*/
	{0,0,0}, /*WriteReplaceWarning*/
	
	{0,0,0}, /*WriteReplaceWarning*/
	{0,0,0}, /*WriteReplaceWarning*/
	{0,0,0}, /*WriteReplaceWarning*/
	{0,0,0}, /*WriteReplaceWarning*/
	{0,0,0} /*WriteReplaceWarning*/
	
};

const char                             *ngap_direction2String[] = {
  "",                           /* Nothing */
  "Originating message",        /* originating message */
  "Successfull outcome",        /* successfull outcome */
  "UnSuccessfull outcome",      /* successfull outcome */
};


void test_ngap_amf_itti_nas_uplink_data_ind(bstring *nas_msg)
{
	tai_t	tai;
    tai.plmn.mcc_digit2 = 1;
	tai.plmn.mcc_digit1 = 1;
	tai.plmn.mcc_digit3 = 1;
	tai.plmn.mcc_digit3 = 1;
	tai.plmn.mcc_digit2 = 2;
	tai.plmn.mcc_digit1 = 1;
	tai.tac = 0x80;
					
	cgi_t  cgi;
	cgi.plmn.mcc_digit2 = 1;
	cgi.plmn.mcc_digit1 = 1;
	cgi.plmn.mcc_digit3 = 1;
	cgi.plmn.mcc_digit3 = 1;
	cgi.plmn.mcc_digit2 = 2;
	cgi.plmn.mcc_digit1 = 1;
	cgi.cell_identity.gnb_id = 0x04 ; 
	cgi.cell_identity.cell_id = 0x04; 
	cgi.cell_identity.empty = 0x04; 
			  
	ngap_amf_itti_nas_uplink_data_ind(60, nas_msg, &tai, &cgi);
}

int   check_NGAP_pdu_constraints(Ngap_NGAP_PDU_t *pdu) {
    int ret;
    char errbuf[512];
    size_t errlen =sizeof(errbuf);
    ret = asn_check_constraints(&asn_DEF_Ngap_NGAP_PDU, pdu, errbuf, &errlen);
    if(ret != 0) 
	{
        OAILOG_ERROR(LOG_NGAP,"Constraint validation  failed:%s\n", errbuf);
    }
	return ret;
}



int
ngap_amf_handle_message(
    const sctp_assoc_id_t assoc_id,
    const sctp_stream_id_t stream,
	Ngap_NGAP_PDU_t *pdu){
  
  int procedureCode = 0, present = pdu->present;
  switch(present){
    case Ngap_NGAP_PDU_PR_initiatingMessage:
      procedureCode = pdu->choice.initiatingMessage->procedureCode;
      break;
    case Ngap_NGAP_PDU_PR_successfulOutcome:
      procedureCode = pdu->choice.successfulOutcome->procedureCode;
      break;
    case Ngap_NGAP_PDU_PR_unsuccessfulOutcome:
      procedureCode = pdu->choice.unsuccessfulOutcome->procedureCode;
      break;
	default:
	  printf("ngap_amf_handle_message unknown protocol %d\n",present);
	  return -1;
  }
  if ((procedureCode > (sizeof (messages_callback) / (3 * sizeof (ngap_message_decoded_callback)))) || (present > Ngap_NGAP_PDU_PR_unsuccessfulOutcome)) {
    //OAILOG_DEBUG (LOG_NGAP, "[SCTP %d] Either procedureCode %d or direction %d exceed expected\n", assoc_id, (int)pdu->choice.initiatingMessage->procedureCode, (int)pdu->present);
    return -1;  
  }             

  if (messages_callback[procedureCode][present - 1] == NULL) {
    //OAILOG_DEBUG (LOG_NGAP, "[SCTP %d] No handler for procedureCode %d in %s\n", assoc_id, (int)pdu->choice.initiatingMessage->procedureCode, ngap_direction2String[(int)pdu->present]);
    return -2;
  }     
  return (*messages_callback[procedureCode][present - 1]) (assoc_id, stream, pdu);
 
}


//------------------------------------------------------------------------------
/*
int
ngap_amf_set_cause (
  Ngap_Cause_t * cause_p,
  const Ngap_Cause_PR cause_type,
  const long cause_value)
{
  
  DevAssert (cause_p != NULL);
  cause_p->present = cause_type;

  switch (cause_type) {
  case Cause_PR_radioNetwork:
    cause_p->choice.radioNetwork = cause_value;
    break;

  case Cause_PR_transport:
    cause_p->choice.transport = cause_value;
    break;

  case Cause_PR_nas:
    cause_p->choice.nas = cause_value;
    break;

  case Cause_PR_protocol:
    cause_p->choice.protocol = cause_value;
    break;

  case Cause_PR_misc:
    cause_p->choice.misc = cause_value;
    break;

  default:
    return -1;
  }

  return 0;
}
*/

//------------------------------------------------------------------------------
/*
int
ngap_amf_generate_ng_setup_failure (
    const sctp_assoc_id_t assoc_id,
    const Ngap_Cause_PR cause_type,
    const long cause_value,
    const long time_to_wait)
{
	
  uint8_t                                *buffer_p = 0;
  uint32_t                                length = 0;
  ngap_message                            message = { 0 };
  NGSetupFailureIEs_t                    *ng_setup_failure_p = NULL;
  int                                     rc = RETURNok;

  OAILOG_FUNC_IN (LOG_NGAP);
  ng_setup_failure_p = &message.msg.ngSetupFailureIEs;
  message.procedureCode = Ngap_ProcedureCode_id_NGSetup;
  message.direction = NGAP_PDU_PR_unsuccessfulOutcome;
  ngap_amf_set_cause (&ng_setup_failure_p->cause, cause_type, cause_value);
*/
  /*
   * Include the optional field time to wait only if the value is > -1
   */
 /*
	if (time_to_wait > -1) {
    ng_setup_failure_p->presenceMask |= NGSETUPFAILUREIES_TIMETOWAIT_PRESENT;
    ng_setup_failure_p->timeToWait = time_to_wait;
  }

  if (ngap_amf_encode_pdu (&message, &buffer_p, &length) < 0) {
    OAILOG_ERROR (LOG_NGAP, "Failed to encode ng setup failure\n");
    OAILOG_FUNC_RETURN (LOG_NGAP, RETURNerror);
  }

  bstring b = blk2bstr(buffer_p, length);
  rc =  ngap_amf_itti_send_sctp_request (&b, assoc_id, 0, INVALID_AMF_UE_NGAP_ID);
  OAILOG_FUNC_RETURN (LOG_NGAP, rc);
  
}
*/
int ngap_handle_sctp_disconnection(const sctp_assoc_id_t assoc_id)
{
    OAILOG_FUNC_IN (LOG_NGAP);

    gnb_description_t   * gnb_association = NULL;
	/*
       * Checking that the assoc id has a valid gNB attached to.
     */
    //@1
    if((gnb_association = ngap_is_gnb_assoc_id_in_list(assoc_id)) == NULL) 
	{
        OAILOG_ERROR (LOG_NGAP, "No gNB attached to this assoc_id: %d\n", assoc_id);
        OAILOG_FUNC_RETURN (LOG_NGAP, RETURNerror);
    }

	//@2
	if (!gnb_association->nb_ue_associated)
	{
	    ngap_remove_gnb(gnb_association);
	    update_amf_app_stats_connected_gnb_sub();
		OAILOG_FUNC_RETURN (LOG_NGAP, RETURNok);
	}
	// >0 reserve
	
	
	OAILOG_FUNC_RETURN (LOG_NGAP, RETURNok);
}

int ng_setup_request_to_send_downlink_nas_transport(const sctp_assoc_id_t assoc_id,
		const sctp_stream_id_t stream, Ngap_NGAP_PDU_t *downlink_nas_transport_pdu)
{
	//printf("NGAP_send_downlink_nas_transport-------------encode\n");

	int assoc[1];
	sctp_data_t * sctp_data_p = NULL;
	Ngap_NGAP_PDU_t 		*pdu = NULL; 
	uint8_t * buffer_p = NULL;
	uint32_t length = 0;
	int rc = RETURNok;
	int ret;
	char errbuf[512] = {0};
	pdu = make_NGAP_DownlinkNasTransport();
		
			
	size_t errlen = sizeof(errbuf);
	ret = asn_check_constraints(&asn_DEF_Ngap_NGAP_PDU, pdu, errbuf, &errlen);
	if(ret != 0) {
		fprintf(stderr,"Constraintvalidationfailed:%s\n", errbuf);
	}
			
	size_t buffer_size = 1000;
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;
					
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		//printf("encode failued\n");
		return -1;
	}
					  
	bstring b = blk2bstr(buffer, er.encoded);
							
	printf("ng_setup_request_to_send_downlink_nas_transportassoc_id:%u, stream:%u,len:%d\n",assoc_id, stream, er.encoded); 
	rc =  ngap_amf_itti_send_sctp_request (&b, assoc_id, stream, 0);
					
	if(rc != RETURNok)
	{
		//printf("ng_setup_request_to_send_downlink_nas_transport send sctp client failed\n"); 
	}
	else
	{
		//printf("ng_setup_request_to_send_downlink_nas_transport send sctp client size:%d, succ \n", length);
	}	  

	return 0;
}
int ngap_amf_generate_ng_setup_failure(
	const sctp_assoc_id_t assoc_id,
    const Ngap_Cause_PR cause_type,
    const long cause_value,
    const long time_to_wait)
{
    OAILOG_FUNC_IN (LOG_NGAP);
	
	sctp_data_t * sctp_data_p = NULL;
	Ngap_NGAP_PDU_t 			*pdu = NULL;
	uint8_t * buffer_p = NULL;
	uint32_t length = 0;
	int rc = RETURNok;
	int ret;
    
    pdu = make_NGAP_SetupFailure(cause_type, cause_value, time_to_wait);
    if(!pdu)
	{
        OAILOG_ERROR(LOG_NGAP, "ng setup make_NGAP_SetupFailure  failed\n");
		rc = RETURNerror;
		goto ERROR;  
	}
    ret  = check_NGAP_pdu_constraints(pdu);
    if(ret < 0) 
	{
		OAILOG_ERROR(LOG_NGAP,"ng_setup_failure Constraint  validation  failed");
		rc = RETURNerror;
		goto ERROR;
    }

    // why :1024  ?
	size_t buffer_size = 1024;   
    void *buffer = calloc(1, buffer_size);
	
	asn_enc_rval_t er;
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		OAILOG_ERROR(LOG_NGAP,"ng_setup_failure encode failed\n");
		rc = RETURNerror;
		goto ERROR;
	}
			  
	bstring b = blk2bstr(buffer, er.encoded);

	//ngsetup request  stream_no: must be 0;
	rc =  ngap_amf_itti_send_sctp_request (&b, assoc_id, 0, 0);	
	if(rc != RETURNok)
	{
		OAILOG_ERROR(LOG_NGAP,"ngap_setup_failure, ngap send sctp failed, assoc_id:%u, stread_id:0, len:%d\n", assoc_id, er.encoded);
		rc = RETURNerror;
		goto ERROR;
		
	}

ERROR:
	ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	free(buffer);
    buffer = NULL;

    OAILOG_FUNC_RETURN (LOG_NGAP, rc); 
}


int
ngap_generate_ng_setup_response(
  const sctp_assoc_id_t assoc_id)
{
	OAILOG_FUNC_IN (LOG_NGAP); 
	
	sctp_data_t * sctp_data_p = NULL;
	Ngap_NGAP_PDU_t	 *pdu = NULL; 
	uint8_t * buffer_p = NULL;
	uint32_t length = 0;
	int rc = RETURNok;
	int ret;
	
	pdu = make_NGAP_SetupResponse();
	if(!pdu)
	{
        OAILOG_ERROR(LOG_NGAP, "ng setup response make_NGAP_SetupResponse  failed\n");
		rc = RETURNerror;
		goto ERROR;  
	}
	
	ret  = check_NGAP_pdu_constraints(pdu);
	if(ret < 0) 
	{
		OAILOG_ERROR(LOG_NGAP, "ng setup response Constraint validation  failed\n");
		rc = RETURNerror;
		goto ERROR; 
	}
   	OAILOG_DEBUG(LOG_NGAP,"ng setup response check_NGAP_pdu_constraints ret:%d\n", ret);   

	//wys:  1024 ?
	size_t buffer_size = 1024;  
	void *buffer = calloc(1,buffer_size);
	asn_enc_rval_t er;	   
	er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);
	if(er.encoded < 0)
	{
		OAILOG_ERROR(LOG_NGAP, "ng setup response encode failed,er.encoded:%d\n",er.encoded);
		rc = RETURNerror;
		goto ERROR; 
	}

    //ngsetup request  stream_no: must be 0;			 
	bstring b = blk2bstr(buffer, er.encoded);		  
	rc =  ngap_amf_itti_send_sctp_request (&b, assoc_id, 0, 0);			   
	if(rc != RETURNok)
	{
		OAILOG_ERROR(LOG_NGAP,"ngap_setup_response assoc_id:%u, stream:0,len:%d\n",assoc_id, er.encoded); 
		rc = RETURNerror;
		goto ERROR;
	}

	 
ERROR:
	ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
	free(buffer);
    buffer = NULL;

    OAILOG_FUNC_RETURN (LOG_NGAP, rc); 
}


int
ngap_amf_handle_ng_setup_request(
    const sctp_assoc_id_t assoc_id,
    const sctp_stream_id_t stream,
	Ngap_NGAP_PDU_t *pdu){

    OAILOG_FUNC_IN (LOG_NGAP);
	
    int rc = RETURNok;
    gnb_description_t   * gnb_association = NULL; 
	//gnb_description_t   * gnb_ref = NULL;
    uint32_t              gnb_id = 0;
    char                 *gnb_name = NULL;
    int				      gnb_name_size = 0;
    int                   ta_ret = 0;
    uint32_t              max_gnb_connected = 0;
    int i = 0;
	uint16_t                                mcc = 0;
    uint16_t                                mnc = 0;
    uint16_t                                mnc_len = 0;
	
    Ngap_NGSetupRequest_t                  *container = NULL;
    Ngap_NGSetupRequestIEs_t               *ie = NULL;
    Ngap_NGSetupRequestIEs_t               *ie_gnb_name = NULL;


    DevAssert (pdu != NULL);
    OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");
    asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    OAILOG_INFO(LOG_NGAP,"----------------------- DECODED NG SETUP REQUEST NGAP MSG --------------------------\n");

	container = &pdu->choice.initiatingMessage->value.choice.NGSetupRequest;

	
	//@1
	//ng setup request: stream_id must be 0;
    if( stream != 0 )  
    {   
        OAILOG_WARNING(LOG_NGAP, "ngap_setup_request,stream_id:%u\n", stream);
		//@7
        rc = ngap_amf_generate_ng_setup_failure(assoc_id, 
                                                Ngap_Cause_PR_protocol, 
                                                Ngap_CauseProtocol_unspecified, 
                                                Ngap_TimeToWait_v10s);
		OAILOG_FUNC_RETURN (LOG_NGAP, rc);
	}
    

    if((gnb_association = ngap_is_gnb_assoc_id_in_list(assoc_id)) == NULL) 
	{
        OAILOG_ERROR(LOG_NGAP, "Ignoring ng setup from unknown assoc %u", assoc_id);
        OAILOG_FUNC_RETURN (LOG_NGAP, RETURNok);
    }

	#if 0
	//@2
	if(gnb_association->ng_state == NGAP_RESETING || gnb_association->ng_state == NGAP_SHUTDOWN)
	{   
	    //@8
        rc  = ngap_amf_generate_ng_setup_failure(assoc_id,
                                                 Ngap_Cause_PR_transport, 
                                                 Ngap_CauseTransport_transport_resource_unavailable, 
                                                 Ngap_TimeToWait_v20s);
		OAILOG_FUNC_RETURN (LOG_NGAP, rc);
	}
    #endif
	
    OAILOG_INFO(LOG_NGAP,"New ng setup request incoming from \n");

	//RANNodeName
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_NGSetupRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_RANNodeName, false);
    if (ie) 
	{  
	   gnb_name = (char *) ie->value.choice.RANNodeName.buf;
       gnb_name_size = (int) ie->value.choice.RANNodeName.size;
	  
	   OAILOG_DEBUG(LOG_NGAP,"RANNodeName, gnb_name_size:%d,gnb_name:%s,\n", gnb_name_size, gnb_name);
    }
	#if 0
	else
	{
	   // free ?
       rc = RETURNerror;
	   //OAILOG_ERROR(LOG_NGAP, "ng_setup_request have not RANNodeName IE\n");
       //OAILOG_FUNC_RETURN (LOG_NGAP, rc);
	}
	#endif
	

	//GlobalRANNodeID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_NGSetupRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_GlobalRANNodeID, false);
    if (ie)
	{
    	switch(ie->value.choice.GlobalRANNodeID.present)
		{
    	    case Ngap_GlobalRANNodeID_PR_globalGNB_ID:
			{
			   Ngap_GlobalGNB_ID_t	*globalGNB_ID = ie->value.choice.GlobalRANNodeID.choice.globalGNB_ID;
			   if(globalGNB_ID)
			   {
                  //gnb_id
                  switch(globalGNB_ID->gNB_ID.present)
                  {
                     case Ngap_GNB_ID_PR_NOTHING:	/* No components present */
					 break;
	                 case Ngap_GNB_ID_PR_gNB_ID:
					 {
						 gnb_id  = BIT_STRING_to_uint32(&globalGNB_ID->gNB_ID.choice.gNB_ID);   
	                 }	   
					 break;
	                 case Ngap_GNB_ID_PR_choice_Extensions:
					 break;
				  }
			   }
               //pLMNIdentity
               const Ngap_PLMNIdentity_t * const plmn = &globalGNB_ID->pLMNIdentity;
               DevAssert (plmn != NULL);
               TBCD_TO_MCC_MNC (plmn, mcc, mnc, mnc_len);
			   
               OAILOG_DEBUG(LOG_NGAP,"pLMNIdentity, mnc:0x%x,mcc:0x%x,mnc_len:0x%x\n",  mcc, mnc, mnc_len);
			   
    		}
		    break;
    	    case Ngap_GlobalRANNodeID_PR_globalNgENB_ID:
		   	
    	    break;
    	    case Ngap_GlobalRANNodeID_PR_globalN3IWF_ID:
		   	
    	    break;
    	    case Ngap_GlobalRANNodeID_PR_choice_Extensions:
		   	
    	    break;
    	    default: //Ngap_GlobalRANNodeID_PR_NOTHING
    	   
    	    break;
    	}
    }

	#if 0
	else
	{
	   //free  ?
	   OAILOG_ERROR(LOG_NGAP, "ng_setup_request have not GlobalRANNodeID IE\n");
       //rc = RETURNerror;
       //OAILOG_FUNC_RETURN (LOG_NGAP, rc);
	}
	#endif
    //@3
	max_gnb_connected = amf_config.max_gnbs;
	if(nb_gnb_associated >= max_gnb_connected)
	{
         OAILOG_ERROR (LOG_NGAP, "There is too much gNB connected to AMF, rejecting the association\n");
         OAILOG_DEBUG (LOG_NGAP, "Connected = %d, maximum allowed = %d\n", nb_gnb_associated, max_gnb_connected);

		 //@9
         rc = ngap_amf_generate_ng_setup_failure(assoc_id,
                                                 Ngap_Cause_PR_misc,
                                                 Ngap_CauseMisc_control_processing_overload,
                                                 Ngap_TimeToWait_v20s);
         OAILOG_FUNC_RETURN (LOG_NGAP, rc);
    }
    
    //@4
	NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_NGSetupRequestIEs_t, ie, container, Ngap_ProtocolIE_ID_id_SupportedTAList, false);
	if (ie)
	{
		ta_ret	= ngap_amf_compare_ta_lists(&ie->value.choice.SupportedTAList);
		if (ta_ret != TA_LIST_RET_OK)
		{
			OAILOG_ERROR (LOG_NGAP, "No Common PLMN with gNB, generate_ng_setup_failure \n");
			//@10
			rc = ngap_amf_generate_ng_setup_failure(assoc_id,
													Ngap_Cause_PR_misc,
													Ngap_CauseMisc_unknown_PLMN,
													Ngap_TimeToWait_v20s);
			OAILOG_FUNC_RETURN (LOG_NGAP, rc);
		}
	}
    
    //@5
    //gnb_id,gnb_name,default_paging_drx
    gnb_association->gnb_id = gnb_id;
	if (gnb_name != NULL) 
	{
        memcpy(gnb_association->gnb_name, gnb_name, gnb_name_size);
        gnb_association->gnb_name[gnb_name_size] = '\0';
    }
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_NGSetupRequestIEs_t, ie, container,Ngap_ProtocolIE_ID_id_DefaultPagingDRX, false);
    if (ie) 
    {
       gnb_association->default_paging_drx = ie->value.choice.PagingDRX;
    }
	else
	{
	   //free  ?
	   OAILOG_ERROR(LOG_NGAP, "ng_setup_request have not default_paging_drx IE\n");
       rc = RETURNerror;
       OAILOG_FUNC_RETURN (LOG_NGAP, rc);
	}
  

	OAILOG_DEBUG(LOG_NGAP, "gnb_id:%d, gnb_name:%s,default_paging_drx:%d\n", 
	gnb_association->gnb_id, gnb_association->gnb_name, gnb_association->default_paging_drx);

    //@6
    rc = ngap_generate_ng_setup_response(assoc_id);
    if (rc == RETURNok) 
	{
	    //@11
        update_amf_app_stats_connected_gnb_add();
    }
    OAILOG_FUNC_RETURN (LOG_NGAP, rc);

	//printf("id:%d\n",ngSetupRequestIEs_p->id);
	//printf("criticality:%d\n",ngSetupRequestIEs_p->criticality);
	//printf("value.present:%d\n",ngSetupRequestIEs_p->value.present);
	
/*
    container = &pdu->choice.initiatingMessage->value.choice.NGSetupRequest;

    if (stream != 0) {
    	OAILOG_ERROR (LOG_NGAP, "Received new ng setup request on stream != 0\n");
    	//Send a Ngap setup failure with protocol cause unspecified
    	rc =  ngap_amf_generate_ng_setup_failure (assoc_id, Ngap_Cause_PR_protocol, Ngap_CauseProtocol_unspecified, -1);
    	OAILOG_FUNC_RETURN (LOG_NGAP, rc);
    }

    if ((gnb_association = ngap_is_gnb_assoc_id_in_list(assoc_id)) == NULL) {
      OAILOG_ERROR(LOG_NGAP, "Ignoring ng setup from unknown assoc %u", assoc_id);
      OAILOG_FUNC_RETURN (LOG_NGAP, RETURNok);
    }

    if (gnb_association->ng_state == NGAP_RESETING || gnb_association->ng_state == NGAP_SHUTDOWN) {
      OAILOG_WARNING(LOG_NGAP, "Ignoring ngsetup from gNB in state %s on assoc id %u",
      ng_gnb_state_str[gnb_association->ng_state], assoc_id);
      rc = ngap_amf_generate_ng_setup_failure(assoc_id,Ngap_Cause_PR_transport,
                                            Ngap_CauseTransport_transport_resource_unavailable,
                                            Ngap_TimeToWait_v20s);
      OAILOG_FUNC_RETURN (LOG_NGAP, rc);
    }

    log_queue_item_t *context = NULL;
    OAILOG_MESSAGE_START (OAILOG_LEVEL_DEBUG, LOG_NGAP, (&context), "New ng setup request incoming from ");

    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_NGSetupRequestIEs_t, ie, container,Ngap_ProtocolIE_ID_id_RANNodeName, false);
    if (ie) {
      OAILOG_MESSAGE_ADD (context, "%*s ", (int) ie->value.choice.RANNodeName.size, ie->value.choice.RANNodeName.buf);
      gnb_name = (char *) ie->value.choice.RANNodeName.buf;
      gnb_name_size = (int) ie->value.choice.RANNodeName.size;
    }

    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_NGSetupRequestIEs_t, ie, container,Ngap_ProtocolIE_ID_id_GlobalRANNodeID, false);
    if (ie){
    	switch(ie->value.choice.GlobalRANNodeID.present){
    	case Ngap_GlobalRANNodeID_PR_globalGNB_ID:
    		//
			break;
    	case Ngap_GlobalRANNodeID_PR_globalNgENB_ID:
    		break;
    	case Ngap_GlobalRANNodeID_PR_globalN3IWF_ID:
    		break;
    	case Ngap_GlobalRANNodeID_PR_choice_Extensions:
    		break;
    	default: //Ngap_GlobalRANNodeID_PR_NOTHING
    		break;
    	}


    }

*/
/*
    if(ngSetupRequest_p->globalRANNodeID.choice.globalGNB_ID.gNB_ID.present == GNB_ID_PR_gNB_ID){  //which gnb id ??
      uint8_t * gnb_id_buf = ngSetupRequest_p->globalRANNodeID.choice.globalGNB_ID.gNB_ID.choice.gNB_ID.buf;
      if(ngSetupRequest_p->globalRANNodeID.choice.globalGNB_ID.gNB_ID.choice.gNB_ID.size != 28){
        //TODO: handle case that size !=28
      }
      gnb_id = (gnb_id_buf[0] << 20) + (gnb_id_buf[1] << 12) + (gnb_id_buf[2] << 4) + ((gnb_id_buf[3] & 0xf0) >> 4);
      OAILOG_MESSAGE_ADD (context, "gNB id: %07x", gnb_id);
    } else {
    }
  */
/*
    OAILOG_MESSAGE_FINISH(context);
    max_gnb_connected = 16;

    if(nb_gnb_associated == max_gnb_connected){
      OAILOG_ERROR (LOG_NGAP, "There is too much gNB connected to MME, rejecting the association\n");
      OAILOG_DEBUG (LOG_NGAP, "Connected = %d, maximum allowed = %d\n", nb_gnb_associated, max_gnb_connected);
      rc = ngap_amf_generate_ng_setup_failure(assoc_id,
                                            Ngap_Cause_PR_misc,
                                            Ngap_CauseMisc_control_processing_overload,
                                            Ngap_TimeToWait_v20s);
      OAILOG_FUNC_RETURN (LOG_NGAP, rc);
    }


    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_NGSetupRequestIEs_t, ie, container,Ngap_ProtocolIE_ID_id_SupportedTAList, false);
    if (ie){
       ta_ret  = ngap_amf_compare_ta_lists(&ie->value.choice.SupportedTAList);
       if (ta_ret != TA_LIST_RET_OK) {
             OAILOG_ERROR (LOG_NGAP, "No Common PLMN with gNB, generate_ng_setup_failure\n");
             rc = ngap_amf_generate_ng_setup_failure(assoc_id,
                                                     Ngap_Cause_PR_misc,
                                                     Ngap_CauseMisc_unknown_PLMN,
                                                     Ngap_TimeToWait_v20s);
             OAILOG_FUNC_RETURN (LOG_NGAP, rc);
           }
    }

    OAILOG_DEBUG (LOG_NGAP, "Adding gNB to the list of served gNBs\n");

    gnb_association->gnb_id = gnb_id;
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_NGSetupRequestIEs_t, ie, container,Ngap_ProtocolIE_ID_id_DefaultPagingDRX, false);
 if (ie) gnb_association->default_paging_drx = ie->value.choice.PagingDRX;

    if (gnb_name != NULL) {
      memcpy(gnb_association->gnb_name, gnb_name,gnb_name_size);
      gnb_association->gnb_name[gnb_name_size] = '\0';
    }

    //ngap_dump_gnb(gnb_association);
    //rc = ngap_generate_ng_setup_response(gnb_association);
    if (rc == RETURNok) {
      //update_amf_app_stats_connected_gnb_add();
    }
    OAILOG_FUNC_RETURN (LOG_NGAP, rc);
*/

}

//------------------------------------------------------------------------------------------------------------

int
ngap_amf_handle_ng_initial_ue_message(
    const sctp_assoc_id_t assoc_id,
    const sctp_stream_id_t stream,
	Ngap_NGAP_PDU_t *pdu)
{
    OAILOG_FUNC_IN (LOG_NGAP);
	
    int      rc                                              = RETURNok;
    ran_ue_ngap_id_t ran_ue_ngap_id                          = 0;  //gnb_ue_ngap_id = 0;
    gnb_description_t  *gnb_ref                              = NULL;
    ue_description_t  *ue_ref                                = NULL;
	Ngap_UserLocationInformationNR_t *pUserLocationInfoNR    = NULL;
	
    Ngap_InitialUEMessage_t      *container                  = NULL;
	Ngap_InitialUEMessage_IEs_t  *ie_RAN_UE_NGAP_ID          = NULL;
	Ngap_InitialUEMessage_IEs_t	 *ie_NAS_PDU                 = NULL;
	Ngap_InitialUEMessage_IEs_t	 *ie_UserLocationInformation = NULL;
	Ngap_InitialUEMessage_IEs_t	 *ie_RRCEstablishmentCause   = NULL;
	Ngap_InitialUEMessage_IEs_t	 *ie_FiveG_S_TMSI            = NULL;
	Ngap_InitialUEMessage_IEs_t	 *ie_AMFSetID                = NULL;
	Ngap_InitialUEMessage_IEs_t	 *ie_UEContextRequest        = NULL;
	Ngap_InitialUEMessage_IEs_t	 *ie_AllowedNSSAI            = NULL;

    
   
	
    DevAssert (pdu != NULL); 
    printf("-------------------------------- DECODED INITIAL UE MESSAGE NGAP MSG ------------------------------\n");
    asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
    printf("-------------------------------- DECODED INITIAL UE MESSAGE NGAP MSG ------------------------------\n");
    container = &pdu->choice.initiatingMessage->value.choice.InitialUEMessage;
    
/********************** is gnb in list ************************************************/

    //@1
    if ((gnb_ref = ngap_is_gnb_assoc_id_in_list (assoc_id)) == NULL)
	{
    	OAILOG_ERROR (LOG_NGAP, "Unknown gNB on assoc_id %d\n", assoc_id);

		//@7
    	OAILOG_FUNC_RETURN (LOG_NGAP, RETURNerror);
    }  

/**************************************************************************************/

/********************** prase available parameters ************************************/
    //RAN_UE_NGAP_ID
    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_InitialUEMessage_IEs_t, ie_RAN_UE_NGAP_ID, container, Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID, false);
    if (ie_RAN_UE_NGAP_ID) 
	{  
		ran_ue_ngap_id  = ie_RAN_UE_NGAP_ID->value.choice.RAN_UE_NGAP_ID;
	    OAILOG_INFO(LOG_NGAP,"ng initial ue message,ran_ue_ngap_id:%u\n", ran_ue_ngap_id);
		
    }
/******************************************************************/
/*******************  context handle ******************************/
    #if 0
       ran_ue_ngap_id  = 0x90;
    #endif

    OAILOG_INFO (LOG_NGAP, "Received NGAP INITIAL_UE_MESSAGE GNB_UE_NGAP_ID " RAN_UE_NGAP_ID_FMT "\n", ran_ue_ngap_id);

	//@2
	ue_ref = ngap_is_ue_gnb_id_in_list(gnb_ref,ran_ue_ngap_id);
    if(ue_ref == NULL)
    {
	    //@3
        if ((ue_ref = ngap_new_ue (assoc_id, ran_ue_ngap_id)) == NULL) 
		{
            OAILOG_ERROR (LOG_NGAP, "NGAP:Initial UE Message- Failed to allocate NGAP UE Context, gNBUeNGAPId:" GNB_UE_NGAP_ID_FMT "\n", ran_ue_ngap_id);
            OAILOG_FUNC_RETURN (LOG_NGAP, RETURNerror);
        }
        
		ue_ref->ng_ue_state = NGAP_UE_WAITING_CRR;
        ue_ref->ran_ue_ngap_id = ran_ue_ngap_id;
        ue_ref->amf_ue_ngap_id = INVALID_AMF_UE_NGAP_ID;
		ue_ref->ngap_ue_context_rel_timer.id = NGAP_TIMER_INACTIVE_ID;
        ue_ref->ngap_ue_context_rel_timer.sec=  NGAP_UE_CONTEXT_REL_COMP_TIMER;
		
        ue_ref->sctp_stream_recv = stream;     
        ue_ref->sctp_stream_send = ue_ref->gnb->next_sctp_stream;
        ue_ref->gnb->next_sctp_stream += 1;
        if (ue_ref->gnb->next_sctp_stream >= ue_ref->gnb->instreams) 
		{
            ue_ref->gnb->next_sctp_stream = 1;
        }


	    //NAS_PDU
		NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_InitialUEMessage_IEs_t, ie_NAS_PDU, container, Ngap_ProtocolIE_ID_id_NAS_PDU, false);
	   
		//UserLocationInformation
		NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_InitialUEMessage_IEs_t, ie_UserLocationInformation, container, Ngap_ProtocolIE_ID_id_UserLocationInformation, false);
	    if (ie_UserLocationInformation) 
		{               
			switch(ie_UserLocationInformation->value.choice.UserLocationInformation.present)
			{
	            case Ngap_UserLocationInformation_PR_userLocationInformationEUTRA:
				break;
				case Ngap_UserLocationInformation_PR_userLocationInformationNR:
				{
					pUserLocationInfoNR = ie_UserLocationInformation->value.choice.UserLocationInformation.choice.userLocationInformationNR;
				}
				break;
				case Ngap_UserLocationInformation_PR_userLocationInformationN3IWF:
				break;
				default:
					OAILOG_WARNING(LOG_NGAP, "ng initial ue message,UserLocationInformation, don't known :%u\n",
					ie_UserLocationInformation->value.choice.UserLocationInformation.present);
				break; 
			}
	    }
		
	    //RRCEstablishmentCause
	    NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_InitialUEMessage_IEs_t, ie_RRCEstablishmentCause, container, Ngap_ProtocolIE_ID_id_RRCEstablishmentCause, false);

		//FiveG_S_TMSI
		NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_InitialUEMessage_IEs_t, ie_FiveG_S_TMSI, container, Ngap_ProtocolIE_ID_id_FiveG_S_TMSI, false);

		//AMFSetID
		NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_InitialUEMessage_IEs_t, ie_AMFSetID, container, Ngap_ProtocolIE_ID_id_AMFSetID, false);
	   
		//UEContextRequest
		NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_InitialUEMessage_IEs_t, ie_UEContextRequest, container, Ngap_ProtocolIE_ID_id_UEContextRequest, false);
	   
		//AllowedNSSAI
		NGAP_FIND_PROTOCOLIE_BY_ID(Ngap_InitialUEMessage_IEs_t, ie_AllowedNSSAI, container, Ngap_ProtocolIE_ID_id_AllowedNSSAI, false);
		


         //NR	 nR_CGI;tAI;
	    nr_tai_t         nr_tai = {.plmn = {0}, .tac = INVALID_TAC};
	    nr_cgi_t         nr_cgi = {.plmn = {0}, .cell_identity = {0}};
		fiveG_s_tmsi_t   nr_fiveG_s_tmsi = {.amf_set_id = 0, .amf_pointer = 0, .fiveG_s_tmsi = 0};
	    amf_set_id_t     nr_amf_set_id  = {.amf_set_id = 0};
		allowed_nssai_t  nr_allowed_nssai = {.s_nssai = NULL, .count = 0};


        DevAssert(pUserLocationInfoNR != NULL);
		const Ngap_TAI_t	  * const  tAI = &pUserLocationInfoNR->tAI;
				  
		//TAC
		DevAssert(tAI != NULL);
		DevAssert(tAI->tAC.size != 3);
		nr_tai.tac = asn1str_to_u24(&tAI->tAC);
				  
		//pLMNIdentity
		DevAssert (tAI->pLMNIdentity.size != 3);
		TBCD_TO_PLMN_T(&tAI->pLMNIdentity, &nr_tai.plmn);
						
		//CGI mandator
		const Ngap_NR_CGI_t * const nR_CGI = &pUserLocationInfoNR->nR_CGI;
						 
		//pLMNIdentity
		DevAssert(nR_CGI != NULL);
		DevAssert(nR_CGI->pLMNIdentity.size != 3);
		TBCD_TO_PLMN_T(&nR_CGI->pLMNIdentity, &nr_cgi.plmn);
						 
		//nRCellIdentity
		DevAssert(nR_CGI->nRCellIdentity.size != 36);
		BIT_STRING_TO_CELL_IDENTITY (&nR_CGI->nRCellIdentity, nr_cgi.cell_identity);

		
        //fiveG_s_tmsi_t
		Ngap_FiveG_S_TMSI_t	*pFiveG_S_TMSI = &ie_FiveG_S_TMSI->value.choice.FiveG_S_TMSI;
		DevAssert(pFiveG_S_TMSI != NULL);
		   
		//aMFSetID  10B
		DevAssert(pFiveG_S_TMSI->aMFSetID.size != 10);
		nr_fiveG_s_tmsi.amf_set_id  = (uint16_t)((*(uint16_t *)ie_FiveG_S_TMSI->value.choice.FiveG_S_TMSI.aMFSetID.buf)	& 0x3FF);  //10 BITS
		   
		//aMFPointer 6B;
		DevAssert(pFiveG_S_TMSI->aMFPointer.size != 6);
		nr_fiveG_s_tmsi.amf_pointer =  (uint8_t) ((*(uint8_t *)ie_FiveG_S_TMSI->value.choice.FiveG_S_TMSI.aMFPointer.buf) & 0x3F);  //6	BITS
		   
		//fiveG_TMSI 32B;
		OCTET_STRING_TO_INT32(&pFiveG_S_TMSI->fiveG_TMSI, nr_fiveG_s_tmsi.fiveG_s_tmsi);
	
		
		OAILOG_INFO(LOG_NGAP, "ng initial ue message, FiveG_S_TMSI, aMFSetID:%u,aMFPointer:%u, fiveG_s_tmsi:%\n", 
		nr_fiveG_s_tmsi.amf_set_id, nr_fiveG_s_tmsi.amf_pointer,  nr_fiveG_s_tmsi.fiveG_s_tmsi);


        //nr_amf_set_id 10B
        nr_amf_set_id.amf_set_id = (uint16_t)((*(uint16_t *)ie_AMFSetID->value.choice.AMFSetID.buf)  & 0x3FF); 
		OAILOG_INFO(LOG_NGAP, "ng initial ue message, AMFSetID:%u\n",nr_amf_set_id.amf_set_id);


        //nr_allowed_nssai
        if(ie_AllowedNSSAI && ie_AllowedNSSAI->value.choice.AllowedNSSAI.list.count != 0)
        {
            nr_allowed_nssai.count   = ie_AllowedNSSAI->value.choice.AllowedNSSAI.list.count;
            nr_allowed_nssai.s_nssai = calloc(nr_allowed_nssai.count, sizeof(allowed_nssai));

			//init  nr_allowed_nssai.s_nssai  ?
			int i = 0;
			for(; i < nr_allowed_nssai.count; i++)
			{
                memset(&nr_allowed_nssai.s_nssai[i], 0, sizeof(allowed_nssai));
			}
			
	        for (i = 0; i < ie_AllowedNSSAI->value.choice.AllowedNSSAI.list.count; i++)
		    {
		        Ngap_AllowedNSSAI_Item_t *pNgap_AllowedNSSAI_p = NULL;
		        pNgap_AllowedNSSAI_p = ie_AllowedNSSAI->value.choice.AllowedNSSAI.list.array[i];
				
				if(pNgap_AllowedNSSAI_p)
				{
				    OCTET_STRING_TO_INT8(&pNgap_AllowedNSSAI_p->s_NSSAI.sST, nr_allowed_nssai.s_nssai[i].sST);
					if(pNgap_AllowedNSSAI_p->s_NSSAI.sD)
					{
                    	nr_allowed_nssai.s_nssai[i].sD = asn1str_to_u24(pNgap_AllowedNSSAI_p->s_NSSAI.sD);  
					}
				}
	        }
		}

	    
		//ngap_amf_itti_amf_app_initial_ue_message(assoc_id,10, 100,100,bdata(nas_msg),blength(nas_msg),NULL,NULL,0,NULL,NULL,NULL,NULL);
		ngap_amf_itti_amf_app_initial_ue_message(
		assoc_id,
		ue_ref->gnb->gnb_id,
		ue_ref->ran_ue_ngap_id,
		ue_ref->amf_ue_ngap_id,
		ie_NAS_PDU->value.choice.NAS_PDU.buf,
	    ie_NAS_PDU->value.choice.NAS_PDU.size,
		&nr_tai,
		&nr_cgi,
		ie_UEContextRequest->value.choice.RRCEstablishmentCause,
		ie_FiveG_S_TMSI ?(&nr_fiveG_s_tmsi):NULL,
		ie_AMFSetID ? (&nr_amf_set_id):NULL,
		ie_AllowedNSSAI ? (&nr_allowed_nssai):NULL);

		//@5
		#if 0
	    if(ie_UEContextRequest  && ie_UEContextRequest->value.choice.present == Ngap_ProtocolIE_ID_id_UEContextRequest)
	    {
	        amf_ngap_handle_initial_context_setup();
	    }
		else
		{
	    	OAILOG_FUNC_RETURN (LOG_NGAP, RETURNok); 
		}
		#endif
	
    }
	else
	{
    	OAILOG_FUNC_RETURN (LOG_NGAP, RETURNok);
	}
	
    /******************************************************************/

	OAILOG_FUNC_RETURN (LOG_NGAP, RETURNok);
}


int ngap_amf_handle_ng_uplink_nas_transport(const sctp_assoc_id_t assoc_id,
    const sctp_stream_id_t stream,
	Ngap_NGAP_PDU_t *pdu)
{
    OAILOG_FUNC_IN (LOG_NGAP);
    int rc = RETURNok;
    
    int i = 0;
    Ngap_UplinkNASTransport_t                  *container = NULL;
    Ngap_UplinkNASTransport_IEs_t               *ie = NULL;
    bstring nas_msg;
    DevAssert (pdu != NULL);
	
	//debug print
	asn_fprint(stdout, &asn_DEF_Ngap_NGAP_PDU, pdu);
	
    container = &pdu->choice.initiatingMessage->value.choice.UplinkNASTransport;
	
	for (i = 0; i < container->protocolIEs.list.count; i++)
	{
        Ngap_UplinkNASTransport_IEs_t *uplinkNasTransportIes_p = NULL;
        uplinkNasTransportIes_p = container->protocolIEs.list.array[i];
		if(!uplinkNasTransportIes_p)
			continue;
		switch(uplinkNasTransportIes_p->id)
	    {
	     case  Ngap_ProtocolIE_ID_id_AMF_UE_NGAP_ID:
		 {
		 	//OAILOG_DEBUG(LOG_NGAP,"AMF_UE_NGAP_ID");
	        size_t i  = 0;
	        for(i ; i<uplinkNasTransportIes_p->value.choice.AMF_UE_NGAP_ID.size;i++)
	        {
	            //OAILOG_DEBUG(LOG_NGAP,"0x%x",uplinkNasTransportIes_p->value.choice.AMF_UE_NGAP_ID.buf[i]);
	        }
		 }
		 break;
         case  Ngap_ProtocolIE_ID_id_RAN_UE_NGAP_ID:
		 {
		 	 //OAILOG_DEBUG(LOG_NGAP,"RAN_UE_NGAP_ID:%lu",uplinkNasTransportIes_p->value.choice.RAN_UE_NGAP_ID);
		 }
		 break;
         case Ngap_ProtocolIE_ID_id_NAS_PDU:
		 {
		 	//printf("Ngap_ProtocolIE_ID_id_NAS_PDU---------\n");
			nas_msg =  blk2bstr(uplinkNasTransportIes_p->value.choice.NAS_PDU.buf,uplinkNasTransportIes_p->value.choice.NAS_PDU.size);
			test_ngap_amf_itti_nas_uplink_data_ind(&nas_msg);
		 }
		 break;
         case  Ngap_ProtocolIE_ID_id_UserLocationInformation:
		 {
				Ngap_UserLocationInformation_t	 UserLocationInformation =  uplinkNasTransportIes_p->value.choice.UserLocationInformation;
				switch(UserLocationInformation.present)
				{
				  case Ngap_UserLocationInformation_PR_userLocationInformationEUTRA:
				  {
				  	Ngap_UserLocationInformationEUTRA_t	*userLocationInformationEUTRA = UserLocationInformation.choice.userLocationInformationEUTRA;
					if(!userLocationInformationEUTRA)
						break;

				    //CGI
				    Ngap_EUTRA_CGI_t eUTRA_CGI = userLocationInformationEUTRA->eUTRA_CGI;
					
				    //CGI,pLMNIdentity
				    Ngap_PLMNIdentity_t	 cgi_pLMNIdentity  = eUTRA_CGI.pLMNIdentity;
	               
				    //OAILOG_DEBUG(LOG_NGAP,"CGI,pLMNIdentity:");
					size_t i = 0;
					for(; i<cgi_pLMNIdentity.size;i++)
					{
					   //OAILOG_DEBUG(LOG_NGAP,"0x%x",cgi_pLMNIdentity.buf[i]); 
					}
				    //CGI,eUTRACellIdentity
				    //OAILOG_DEBUG(LOG_NGAP,"CGI,eUTRACellIdentity:");
				    Ngap_EUTRACellIdentity_t	 eUTRACellIdentity = eUTRA_CGI.eUTRACellIdentity;
				    i  = 0;
				    for(; i<eUTRACellIdentity.size;i++)
					{
					   //OAILOG_DEBUG(LOG_NGAP,"0x%x",eUTRACellIdentity.buf[i]); 
					}

                    //TAI
                    //OAILOG_DEBUG(LOG_NGAP,"TAI");
                    Ngap_TAI_t tAI  =  userLocationInformationEUTRA->tAI;
                    //TAI,pLMNIdentity
                    //OAILOG_DEBUG(LOG_NGAP,"TAI.pLMNIdentity");
                    Ngap_PLMNIdentity_t	 pLMNIdentity  = tAI.pLMNIdentity;
					i  = 0;
					for(; i<pLMNIdentity.size;i++)
					{
                        //OAILOG_DEBUG(LOG_NGAP,"0x%x",pLMNIdentity.buf[i]);
					}
                    
                    //TAI,tAC
                    //OAILOG_DEBUG(LOG_NGAP,"TAI.tAC");
	                Ngap_TAC_t	 tAC = tAI.tAC;
					i  = 0;
					for(; i<tAC.size;i++)
					{
                        //OAILOG_DEBUG(LOG_NGAP,"0x%x",tAC.buf[i]);
					}
                    
					//timeStamp
					//OAILOG_DEBUG(LOG_NGAP,"timeStamp");
					Ngap_TimeStamp_t	*timeStamp = userLocationInformationEUTRA->timeStamp;
					i  = 0;
					if(!timeStamp)
						break;
					for(; i<timeStamp->size;i++)
					{
                        //OAILOG_DEBUG(LOG_NGAP,"0x%x",timeStamp->buf[i]);
					}
				  }
				  break;
				  case Ngap_UserLocationInformation_PR_userLocationInformationNR:
				  {
				  }
				  break;
	              case Ngap_UserLocationInformation_PR_userLocationInformationN3IWF:
		          {
				  }
				  break;
		
				  default:
				  	break;
				}
		 }
		 break;
	   }
	}

    return  0;
}

int
ngap_handle_new_association (
  sctp_new_peer_t * sctp_new_peer_p)
{
#if 1
  gnb_description_t                      *gnb_association = NULL;

  OAILOG_FUNC_IN (LOG_NGAP);
  DevAssert (sctp_new_peer_p != NULL);

  /*
   * Checking that the assoc id has a valid gNB attached to.
   */
  if ((gnb_association = ngap_is_gnb_assoc_id_in_list (sctp_new_peer_p->assoc_id)) == NULL) {
    OAILOG_DEBUG (LOG_NGAP, "Create gNB context for assoc_id: %d\n", sctp_new_peer_p->assoc_id);
    /*
     * Create new context
     */
    gnb_association = ngap_new_gnb ();

    if (gnb_association == NULL) {
      /*
       * We failed to allocate memory
       */
      OAILOG_ERROR (LOG_NGAP, "Failed to allocate gNB context for assoc_id: %d\n", sctp_new_peer_p->assoc_id);
      OAILOG_FUNC_RETURN(LOG_NGAP, RETURNok);
    }
    gnb_association->sctp_assoc_id = sctp_new_peer_p->assoc_id;
    hashtable_rc_t  hash_rc = hashtable_ts_insert (&g_ngap_gnb_coll, (const hash_key_t)gnb_association->sctp_assoc_id, (void *)gnb_association);
    if (HASH_TABLE_OK != hash_rc) {
      OAILOG_FUNC_RETURN (LOG_NGAP, RETURNerror);
    }
  } else if ((gnb_association->ng_state == NGAP_SHUTDOWN) || (gnb_association->ng_state == NGAP_RESETING)) {
    OAILOG_WARNING(LOG_NGAP, "Received new association request on an association that is being %s, ignoring",
                   ng_gnb_state_str[gnb_association->ng_state]);
    OAILOG_FUNC_RETURN(LOG_NGAP, RETURNerror);
  } else {
    OAILOG_DEBUG (LOG_NGAP, "gNB context already exists for assoc_id: %d, update it\n", sctp_new_peer_p->assoc_id);
  }

  gnb_association->sctp_assoc_id = sctp_new_peer_p->assoc_id;
  /*
   * Fill in in and out number of streams available on SCTP connection.
   */
  gnb_association->instreams = (sctp_stream_id_t) sctp_new_peer_p->instreams;
  gnb_association->outstreams = (sctp_stream_id_t) sctp_new_peer_p->outstreams;
  gnb_association->next_sctp_stream = 1;
  gnb_association->ng_state = NGAP_INIT;
  OAILOG_FUNC_RETURN (LOG_NGAP, RETURNok);
#endif

}


