#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "ngap_amf_setup_failure.h"

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

#include "sctp_gNB_defs.h"

#include  "bstrlib.h"
#include  "intertask_interface_types.h"

#include  "Ngap_CriticalityDiagnostics-IE-Item.h"

void add_NGSetupFailure_ie(Ngap_NGSetupFailure_t *ngapSetupFailure, Ngap_NGSetupFailureIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapSetupFailure->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
    }
}

//CriticalityDiagnostics

//CriticalityDiagnostics: procedureCode
void fill_CriticalityDiagnostics_with_procedureCode(
Ngap_CriticalityDiagnostics_t	 *CriticalityDiagnostics,
Ngap_ProcedureCode_t	procedureCode)
{
     CriticalityDiagnostics->procedureCode = calloc(1, sizeof(Ngap_ProcedureCode_t));
	*CriticalityDiagnostics->procedureCode = procedureCode;
} 
//CriticalityDiagnostics: triggeringMessage
void fill_CriticalityDiagnostics_with_triggeringMessage(
Ngap_CriticalityDiagnostics_t	 *CriticalityDiagnostics,
Ngap_TriggeringMessage_t	triggeringMessage)
{
     CriticalityDiagnostics->triggeringMessage = calloc(1, sizeof(Ngap_TriggeringMessage_t));
	*CriticalityDiagnostics->triggeringMessage = triggeringMessage;
} 
//CriticalityDiagnostics: procedureCriticality
void fill_CriticalityDiagnostics_with_procedureCriticality(
	Ngap_CriticalityDiagnostics_t	 *CriticalityDiagnostics,
	Ngap_Criticality_t	procedureCriticality)
{
    CriticalityDiagnostics->procedureCriticality = calloc(1, sizeof(Ngap_Criticality_t));
	*CriticalityDiagnostics->procedureCriticality = procedureCriticality;
} 

//CriticalityDiagnostics: iEsCriticalityDiagnostics:item
 Ngap_CriticalityDiagnostics_IE_Item_t * fill_CriticalityDiagnostics_with_iesCriticalityDiagnostics_Item()
{
   Ngap_CriticalityDiagnostics_IE_Item_t *pcdItem = NULL;
   pcdItem = calloc(1, sizeof(Ngap_CriticalityDiagnostics_IE_Item_t));
   pcdItem->iECriticality = 0x85;
   pcdItem->iE_ID = 0x86;
   pcdItem->typeOfError = 0x87;
   return pcdItem;
}

//CriticalityDiagnostics: iEsCriticalityDiagnostics
void fill_CriticalityDiagnostics_with_iesCriticalityDiagnostics_List(
Ngap_CriticalityDiagnostics_t	 *CriticalityDiagnostics)
{
    Ngap_CriticalityDiagnostics_IE_Item_t *pcdItem = NULL;
    
	pcdItem = fill_CriticalityDiagnostics_with_iesCriticalityDiagnostics_Item();
	ASN_SEQUENCE_ADD(&CriticalityDiagnostics->iEsCriticalityDiagnostics, pcdItem);
}

Ngap_NGSetupFailureIEs_t * make_CriticalityDiagnostics_ie(
Ngap_ProcedureCode_t procedureCode,
Ngap_TriggeringMessage_t	triggeringMessage,
Ngap_Criticality_t	procedureCriticality)
{
    Ngap_NGSetupFailureIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_NGSetupFailureIEs_t));
	ie->id = Ngap_ProtocolIE_ID_id_CriticalityDiagnostics; 
	ie->value.present = Ngap_NGSetupFailureIEs__value_PR_CriticalityDiagnostics;
	
    fill_CriticalityDiagnostics_with_procedureCode(&ie->value.choice.CriticalityDiagnostics,procedureCode);
	fill_CriticalityDiagnostics_with_triggeringMessage(&ie->value.choice.CriticalityDiagnostics,triggeringMessage);
    fill_CriticalityDiagnostics_with_procedureCriticality(&ie->value.choice.CriticalityDiagnostics,procedureCriticality);
    fill_CriticalityDiagnostics_with_iesCriticalityDiagnostics_List(&ie->value.choice.CriticalityDiagnostics);

	return ie;
}

//TimeTOWait
Ngap_NGSetupFailureIEs_t *make_TimeToWait_ie(e_Ngap_TimeToWait  TimeToWait)
{
    Ngap_NGSetupFailureIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_NGSetupFailureIEs_t));
    ie->id = Ngap_ProtocolIE_ID_id_TimeToWait; 
    ie->value.present = Ngap_NGSetupFailureIEs__value_PR_TimeToWait;
	ie->value.choice.TimeToWait = TimeToWait;
    
	return ie;
}


//cause
Ngap_NGSetupFailureIEs_t *make_Cause_radioNetwork_ie(e_Ngap_CauseRadioNetwork radioNetwork)
{
    Ngap_NGSetupFailureIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_NGSetupFailureIEs_t));
	ie->id = Ngap_ProtocolIE_ID_id_Cause; 
	ie->value.present = Ngap_NGSetupFailureIEs__value_PR_Cause;
	ie->value.choice.Cause.present =  Ngap_Cause_PR_radioNetwork;
	ie->value.choice.Cause.choice.radioNetwork = radioNetwork;

	printf("radioNetwork:0x%x\n", ie->value.choice.Cause.choice.radioNetwork);
    return ie;
}

Ngap_NGAP_PDU_t *make_NGAP_SetupFailure()
{

    Ngap_NGAP_PDU_t              *pdu = NULL;
	Ngap_NGSetupFailure_t        *ngapSetupFailure = NULL;
	Ngap_NGSetupFailureIEs_t     *ie = NULL;
	
    pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
   
	pdu->present = Ngap_NGAP_PDU_PR_unsuccessfulOutcome;
	pdu->choice.unsuccessfulOutcome = calloc(1, sizeof(Ngap_UnsuccessfulOutcome_t));
	pdu->choice.unsuccessfulOutcome->procedureCode = Ngap_ProcedureCode_id_NGSetup;
	pdu->choice.unsuccessfulOutcome->criticality = Ngap_Criticality_reject;
	pdu->choice.unsuccessfulOutcome->value.present = Ngap_UnsuccessfulOutcome__value_PR_NGSetupFailure;

	ngapSetupFailure = &pdu->choice.unsuccessfulOutcome->value.choice.NGSetupFailure;
    

	//Cause;
	//e_Ngap_CauseRadioNetwork
	ie = make_Cause_radioNetwork_ie(Ngap_CauseRadioNetwork_unspecified);
	add_NGSetupFailure_ie(ngapSetupFailure, ie);

	
	//Ngap_TimeToWait_t	 TimeToWait;
	//e_Ngap_TimeToWait
    ie  = make_TimeToWait_ie(Ngap_TimeToWait_v60s);
    add_NGSetupFailure_ie(ngapSetupFailure, ie);

	#if 0
	//CriticalityDiagnostics:procedureCode
	ie =  make_CriticalityDiagnostics_ie(Ngap_ProcedureCode_id_AMFConfigurationUpdate,0x82,0x83);
	add_NGSetupFailure_ie(ngapSetupFailure, ie);
    #endif
	
    return pdu;
}

