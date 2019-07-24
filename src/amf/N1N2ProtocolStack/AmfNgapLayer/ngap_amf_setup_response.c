#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "ngap_amf_setup_response.h"

#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_BroadcastPLMNItem.h"
#include "Ngap_GNB-ID.h"
#include "Ngap_GlobalGNB-ID.h"
#include "Ngap_PagingDRX.h"
#include "Ngap_SliceSupportItem.h"
#include "Ngap_SupportedTAItem.h"
#include "Ngap_GlobalRANNodeID.h"
#include "Ngap_SuccessfulOutcome.h"

#include "sctp_gNB_defs.h"

#include  "bstrlib.h"
#include  "intertask_interface_types.h"

#include  "Ngap_CriticalityDiagnostics-IE-Item.h"
#include  "Ngap_PLMNSupportItem.h"
#include  "log.h"
#include  "amf_config.h"
#include  "Ngap_GUAMI.h"
#include  "Ngap_ServedGUAMIItem.h"
#include  "conversions.h"

//AMFName
Ngap_NGSetupResponseIEs_t *make_AMFName_ie()
{
	Ngap_NGSetupResponseIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_NGSetupResponseIEs_t));

   	ie->id = Ngap_ProtocolIE_ID_id_AMFName;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_NGSetupResponseIEs__value_PR_AMFName;
	OCTET_STRING_fromBuf (&ie->value.choice.AMFName, bdata(amf_config.amf_name), blength (amf_config.amf_name));
	
	//OAILOG_DEBUG(LOG_NGAP,"response  backup AMFName:%s\n", ie->value.choice.AMFName.buf);
    return ie;
}


//RelativeAMFCapacity
Ngap_NGSetupResponseIEs_t * make_RelativeAMFCapacity_ie()
{
	Ngap_NGSetupResponseIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_NGSetupResponseIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_RelativeAMFCapacity;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_NGSetupResponseIEs__value_PR_RelativeAMFCapacity;
    ie->value.choice.RelativeAMFCapacity  =   amf_config.relative_capacity;
	
	//OAILOG_DEBUG(LOG_NGAP,"RelativeAMFCapacity:%d\n", ie->value.choice.RelativeAMFCapacity);
  
	return ie;
}

//ServedGUAMIList
void fill_aMFSetID(Ngap_AMFSetID_t *aMFSetID, uint16_t setid, uint16_t len)
{
    //OAILOG_DEBUG(LOG_NGAP, "fill_aMFSetID, setid:%u, len:%u\n", setid, len);
    aMFSetID->buf = calloc(len, sizeof(uint8_t));
	memset(aMFSetID->buf, 0, len );
	memcpy(aMFSetID->buf, &setid, len);
	aMFSetID->size =  len;
	//aMFSetID->bits_unused = 0;

	aMFSetID->bits_unused = 0x06;

	//OAILOG_DEBUG(LOG_NGAP,"aMFSetID, size:%u\n", aMFSetID->size);
}

void fill_aMFRegionID(Ngap_AMFRegionID_t *aMFRegionID, uint16_t setid, uint16_t len)
{
    OAILOG_DEBUG(LOG_NGAP, "fill_aMFRegionID, setid:%u, len:%u\n", setid, len);
	
    aMFRegionID->buf = calloc(1, sizeof(uint8_t));
    memset(aMFRegionID->buf, 0, 1 );
    memcpy(aMFRegionID->buf, &setid, 1);
    aMFRegionID->size =  len;
    aMFRegionID->bits_unused = 0;
	//aMFRegionID->bits_unused = 0x06; 
	//INT16_TO_BUFFER(setid, aMFRegionID->buf);
}
void  fill_aMFPointer(Ngap_AMFPointer_t *aMFPointer, uint16_t setid, uint16_t len)
{
    OAILOG_DEBUG(LOG_NGAP, "fill_aMFPointer, setid:%u, len:%u\n", setid, len);
	
    aMFPointer->buf = calloc(1, sizeof(uint8_t));
    memset(aMFPointer->buf, 0, 1 );
    memcpy(aMFPointer->buf, &setid, 1);
    aMFPointer->size =  len;
    aMFPointer->bits_unused = 02; 
}
Ngap_NGSetupResponseIEs_t * make_ServedGUAMIList_ie()
{
   Ngap_NGSetupResponseIEs_t *ie = NULL;
   ie = calloc(1, sizeof(Ngap_NGSetupResponseIEs_t));
   
   ie->id = Ngap_ProtocolIE_ID_id_ServedGUAMIList;
   ie->criticality = Ngap_Criticality_reject;
   ie->value.present = Ngap_NGSetupResponseIEs__value_PR_ServedGUAMIList;

   uint8_t nb_gummi = amf_config.guami.nb_gummi;
   Ngap_ServedGUAMIItem_t   *pGuimi = NULL;
   pGuimi  = calloc(nb_gummi, sizeof(Ngap_ServedGUAMIItem_t));
   
   uint8_t  i  = 0;
   for(;i <nb_gummi;  i++)
   {
	   //pLMNIdentity
       MCC_MNC_TO_PLMNID(amf_config.guami.plmn_mcc[i], amf_config.guami.plmn_mnc[i], amf_config.guami.plmn_mnc_len[i], &(pGuimi->gUAMI.pLMNIdentity));
	   
	   BIT_STRING_fromBuf(&(pGuimi[i].gUAMI.aMFRegionID), &amf_config.guami.amf_region_id[i], 8);
       BIT_STRING_fromBuf(&(pGuimi[i].gUAMI.aMFSetID), &amf_config.guami.amf_set_id[i], 10);
	   BIT_STRING_fromBuf(&(pGuimi[i].gUAMI.aMFPointer), &amf_config.guami.amf_pointer[i], 6);

	   ASN_SEQUENCE_ADD(&ie->value.choice.ServedGUAMIList.list, &pGuimi[i]);
   }
   return ie;
}


//PLMNSupportList
//Ngap_PLMNSupportItem_t

//pLMNIdentity
void fill_PLMNSupportItem_with_pLMNIdentity(Ngap_PLMNIdentity_t	 *pLMNIdentity)
{
    //OAILOG_FUNC_IN (LOG_NGAP);
    uint8_t plmn[3] = { 0x02, 0xF8, 0x29 };
    //uint8_t plmn[3] = { 0x02, 208, 93 };
	OCTET_STRING_fromBuf(pLMNIdentity, (const char*)plmn, 3);
    
	//MCC_MNC_TO_PLMNID(*amf_config.gummei.plmn_mcc, *amf_config.gummei.plmn_mnc, sizeof(*amf_config.gummei.plmn_mnc_len), pLMNIdentity);
	
    //OAILOG_FUNC_RETURN (LOG_NGAP,0);
	//OAILOG_DEBUG(LOG_NGAP,"pLMNIdentity: 0x%x,0x%x,0x%x\n", pLMNIdentity->buf[0],pLMNIdentity->buf[1],pLMNIdentity->buf[2]);
}

void fill_s_NSSAI_sST(Ngap_SST_t *sST, const uint16_t *sst)
{ 
    //uint8_t plmn[3] = { 0x02};
	//OCTET_STRING_fromBuf(sST, (const char*)plmn, 1);

	OCTET_STRING_fromBuf(sST, (const char*)sst, 1);
}

Ngap_SD_t	* fill_s_NSSAI_sD( const uint16_t SD)
{   
    Ngap_SD_t *sD = NULL;
    if (SD >= 0 )
    {
        uint32_t sd = ntohl(SD);
        const char *sd_ptr = (const char *)&sd + 1;
        sD = calloc(1, sizeof(Ngap_SD_t));
        
        OCTET_STRING_fromBuf(sD, sd_ptr, 3);
		//OAILOG_DEBUG (LOG_NGAP,"s_NSSAI.sD:0x%x,0x%x,0x%x",item->s_NSSAI.sD->buf[0],item->s_NSSAI.sD->buf[1],item->s_NSSAI.sD->buf[2]);
    }
	return sD;
}

void fill_sliceSupportItem_with_s_NSSAI(Ngap_S_NSSAI_t	 *s_NSSAI, const uint16_t *sst, const uint16_t sd)
{
    fill_s_NSSAI_sST(&s_NSSAI->sST, sst);
	s_NSSAI->sD = fill_s_NSSAI_sD(sd);
}
void fill_PLMNSupportItem_with_sliceSupportList(Ngap_SliceSupportList_t	 *sliceSupportList)
{   
    Ngap_SliceSupportItem_t *ss = NULL;
	ss = calloc(1, sizeof(Ngap_SliceSupportItem_t));
	uint16_t  t  =  0x02;
    fill_sliceSupportItem_with_s_NSSAI(&ss->s_NSSAI, &t, 0x01);
	ASN_SEQUENCE_ADD(&sliceSupportList->list, ss);
}

Ngap_PLMNSupportItem_t  *make_PLMNSupportItem()
{
    Ngap_PLMNSupportItem_t  *plmn = NULL;
    plmn = calloc(1, sizeof(Ngap_PLMNSupportItem_t));

	fill_PLMNSupportItem_with_pLMNIdentity(&plmn->pLMNIdentity);
	fill_PLMNSupportItem_with_sliceSupportList(&plmn->sliceSupportList);
	fill_PLMNSupportItem_with_sliceSupportList(&plmn->sliceSupportList);
 
	return plmn;
}


void make_sliceSupportList(Ngap_SliceSupportList_t	 *sliceSupportList)
{
   uint16_t  nb_slice = amf_config.slice_list.nb_slice;

   //Ngap_SliceSupportItem_t *ss = NULL;
   //ss = calloc(nb_slice_list, sizeof(Ngap_SliceSupportItem_t));

   Ngap_SliceSupportItem_t *ss = NULL;
   int i  = 0;
   for(; i < nb_slice; i++)
   {
       ss = calloc(1, sizeof(Ngap_SliceSupportItem_t));
       fill_sliceSupportItem_with_s_NSSAI(&(ss->s_NSSAI), &amf_config.slice_list.SST[i], amf_config.slice_list.SD[i]);

	   ASN_SEQUENCE_ADD(&sliceSupportList->list, ss);  
   }
}

Ngap_NGSetupResponseIEs_t * make_PLMNSupportList()
{
    Ngap_NGSetupResponseIEs_t *ie = NULL;
	ie = calloc(1, sizeof(Ngap_NGSetupResponseIEs_t));
	
	ie->id = Ngap_ProtocolIE_ID_id_PLMNSupportList;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_NGSetupResponseIEs__value_PR_PLMNSupportList;

    //Ngap_PLMNSupportItem_t  *plmn = NULL;
    //plmn= make_PLMNSupportItem();
    //ASN_SEQUENCE_ADD(&ie->value.choice.PLMNSupportList.list, plmn);

    uint16_t  nb_plmn_identity = amf_config.plmn_identity.nb_plmn_identity;
	Ngap_PLMNSupportItem_t	*plmn = NULL;
	//plmn = calloc(nb_plmn_identity, sizeof(Ngap_PLMNSupportItem_t));  //? ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);  result in core  ?
	
	int i  = 0;
	for(; i< nb_plmn_identity; i++)
	{
       plmn = calloc(1, sizeof(Ngap_PLMNSupportItem_t));

	   //pLMNIdentity: sliceSupportList = 1-to-many relationship
	   
	   //1: pLMNIdentity
	   MCC_MNC_TO_PLMNID(amf_config.plmn_identity.plmn_mcc[i], amf_config.plmn_identity.plmn_mnc[i], amf_config.plmn_identity.plmn_mnc_len[i], &(plmn->pLMNIdentity));

	   //many: sliceSupportList
	   make_sliceSupportList(&(plmn->sliceSupportList));
	   
       ASN_SEQUENCE_ADD(&ie->value.choice.PLMNSupportList.list, plmn);
	}
	
    return ie;
}
void add_NGSetupResponse_ie(Ngap_NGSetupResponse_t *ngapSetupResponse, Ngap_NGSetupResponseIEs_t *ie)
{
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapSetupResponse->protocolIEs.list, ie);
    if ( ret != 0 ) 
	{
        OAILOG_DEBUG(LOG_NGAP, "ng setup response Failed to add ie\n");
    }
}

Ngap_NGAP_PDU_t *make_NGAP_SetupResponse()
{
	Ngap_NGAP_PDU_t *pdu;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));
	
	pdu->present = Ngap_NGAP_PDU_PR_successfulOutcome;
	pdu->choice.successfulOutcome = calloc(1, sizeof(Ngap_SuccessfulOutcome_t));
	pdu->choice.successfulOutcome->procedureCode = Ngap_ProcedureCode_id_NGSetup;
	pdu->choice.successfulOutcome->criticality = Ngap_Criticality_reject;
	pdu->choice.successfulOutcome->value.present = Ngap_SuccessfulOutcome__value_PR_NGSetupResponse;
	
	Ngap_NGSetupResponse_t *ngapSetupResponse;
	ngapSetupResponse = &pdu->choice.successfulOutcome->value.choice.NGSetupResponse;

	//Make NGSetupResponse IEs and add it to message
    Ngap_NGSetupResponseIEs_t *ie = NULL;

	//AMFName
	ie  = make_AMFName_ie();
	add_NGSetupResponse_ie(ngapSetupResponse, ie);


	//RelativeAMFCapacity
	ie  = make_RelativeAMFCapacity_ie();
	add_NGSetupResponse_ie(ngapSetupResponse, ie);

    //ServedGUAMIList
    ie  = make_ServedGUAMIList_ie();
	add_NGSetupResponse_ie(ngapSetupResponse, ie);
	
    //PLMNSupportList
	//Ngap_PLMNSupportList_t	 PLMNSupportList;
	ie  = make_PLMNSupportList();
	add_NGSetupResponse_ie(ngapSetupResponse, ie);
    
	return pdu;
}

