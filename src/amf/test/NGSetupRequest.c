#include <stdio.h>
#include <stdlib.h>

#include "Ngap_ProtocolIE-Field.h"
#include "Ngap_NGAP-PDU.h"
#include "Ngap_InitiatingMessage.h"
#if 1
#include "Ngap_BroadcastPLMNItem.h"
#include "Ngap_GNB-ID.h"
#include "Ngap_GlobalGNB-ID.h"
#include "Ngap_PagingDRX.h"
#include "Ngap_SliceSupportItem.h"
#include "Ngap_SupportedTAItem.h"
#include "Ngap_UnsuccessfulOutcome.h"
#include "Ngap_GlobalRANNodeID.h"
#endif

#include "sctp_gNB_defs.h"
#include <unistd.h>
#include <arpa/inet.h>


int g_supportTaListCount = 0;

void mccmnc_to_pLMN_buf(char buf[3], const char *mcc, const char *mnc) {
    int i;

    char _mcc[3];
    for (i=0; i<3; i++)
      _mcc[i] = mcc[i] - '0';

    char _mnc[3];
    if (strlen(mnc) == 2) {
        _mnc[0] = mnc[0];
        _mnc[1] = mnc[1];
        _mnc[2] = '0' + 15;
    } else {
        for (i=0; i<3; i++)
            _mnc[i] = mnc[i];
    }
    for (i=0; i<3; i++)
      _mnc[i] = _mnc[i] - '0';

    buf[0]  = _mcc[1] << 4;
    buf[0] |= _mcc[0];
    buf[1]  = _mnc[2] << 4;
    buf[1] |= _mcc[2];
    buf[2]  = _mnc[1] << 4;
    buf[2] |= _mnc[0];
}

void fill_pLMNIdentity(void *dest, const char *mcc, const char *mnc) {
    char buf[3];
    mccmnc_to_pLMN_buf(buf, mcc, mnc);
	OCTET_STRING_fromBuf(dest, buf, 3);
}

void fill_gNB_ID(Ngap_GNB_ID_t *gnb_id, unsigned int index) {
    uint32_t gNB_ID = htonl(index);
    gnb_id->present = Ngap_GNB_ID_PR_gNB_ID;
	gnb_id->choice.gNB_ID.buf = calloc(4, sizeof(uint8_t));
	gnb_id->choice.gNB_ID.size = 4;
	memcpy(gnb_id->choice.gNB_ID.buf, &gNB_ID, 4);
}

void fill_tAC(Ngap_TAC_t *item, unsigned int tac) {
    uint32_t tAC = htonl(tac);
    const char *ptr = (void *)&tAC;
    OCTET_STRING_fromBuf(item, ptr + 1, 3);
}

void fill_GlobalRANNodeID_with_GlobalGNBID(Ngap_GlobalRANNodeID_t *ngap_GlobalRANNodeID) {
	ngap_GlobalRANNodeID->present = Ngap_GlobalRANNodeID_PR_globalGNB_ID;
    Ngap_GlobalGNB_ID_t *globalGNB_ID = calloc(1, sizeof(struct Ngap_GlobalGNB_ID));
	ngap_GlobalRANNodeID->choice.globalGNB_ID = globalGNB_ID;

	fill_pLMNIdentity(&globalGNB_ID->pLMNIdentity, "208", "89");
    fill_gNB_ID(&globalGNB_ID->gNB_ID, 513);
    //asn_fprint(stderr, &asn_DEF_Ngap_GlobalRANNodeID, ngap_GlobalRANNodeID);
}

typedef struct {
    int sst;
    int sd;
} snssai_t;

Ngap_SliceSupportItem_t *make_sliceSupportItem(const snssai_t slice) {
    Ngap_SliceSupportItem_t *item;
    item = calloc (1, sizeof(Ngap_SliceSupportItem_t));
    const char sst = slice.sst;
    OCTET_STRING_fromBuf(&item->s_NSSAI.sST, &sst, 1);
    if (slice.sd >= 0 ) {
        uint32_t sd = ntohl(slice.sd);
        const char *sd_ptr = (const char *)&sd + 1;
        Ngap_SD_t *sD = calloc(1, sizeof(Ngap_SD_t));
        item->s_NSSAI.sD = sD;
        OCTET_STRING_fromBuf(sD, sd_ptr, 3);
    }
    return item;
}


Ngap_BroadcastPLMNItem_t *make_Ngap_BroadcastPLMNItem(const char *mcc, const char *mnc,
                                                      const snssai_t slice_list[], const int slice_list_len) {
    Ngap_BroadcastPLMNItem_t *item;
    item = calloc (1, sizeof(Ngap_BroadcastPLMNItem_t));
	fill_pLMNIdentity(&item->pLMNIdentity, mcc, mnc);
    Ngap_SliceSupportItem_t *sliceSupportItem;
    int i;
    for (i=0; i<slice_list_len; i++) {
        sliceSupportItem = make_sliceSupportItem(slice_list[i]);
        ASN_SEQUENCE_ADD (&item->tAISliceSupportList.list, sliceSupportItem);
    }
    return item;
}

void fill_broadcastPLMNList_1(Ngap_BroadcastPLMNList_t *list) {
    Ngap_BroadcastPLMNItem_t *item;
    snssai_t slice_list[1] = { { 1, -1 } };
    item = make_Ngap_BroadcastPLMNItem("208", "89", slice_list, 1);
    ASN_SEQUENCE_ADD(list, item);

    snssai_t slice_list2[2] = { { 1, -1 }, { 4, 5000} };
    item = make_Ngap_BroadcastPLMNItem("208", "93", slice_list2, 2);
    ASN_SEQUENCE_ADD(list, item);
}

void fill_broadcastPLMNList_2(Ngap_BroadcastPLMNList_t *list) {
    Ngap_BroadcastPLMNItem_t *item;
    snssai_t slice_list[3] = { { 1, -1 }, { 2, -1 }, { 3, -1 } };
    item = make_Ngap_BroadcastPLMNItem("208", "89", slice_list, 3);
    ASN_SEQUENCE_ADD(list, item);
}

// IEs

Ngap_NGSetupRequestIEs_t *make_GlobalRANNodeID_ie() {
	Ngap_NGSetupRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_NGSetupRequestIEs_t));

	ie->id = Ngap_ProtocolIE_ID_id_GlobalRANNodeID;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_NGSetupRequestIEs__value_PR_GlobalRANNodeID;

    fill_GlobalRANNodeID_with_GlobalGNBID(&ie->value.choice.GlobalRANNodeID);
    //asn_fprint(stderr, &asn_DEF_Ngap_NGSetupRequestIEs, ie);
    return ie;
}

Ngap_NGSetupRequestIEs_t *make_RANNodeName_ie(const char *name) {
	Ngap_NGSetupRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_NGSetupRequestIEs_t));

   	ie->id = Ngap_ProtocolIE_ID_id_RANNodeName;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_NGSetupRequestIEs__value_PR_RANNodeName;
	OCTET_STRING_fromBuf (&ie->value.choice.RANNodeName, name, strlen (name));
    return ie;
}

Ngap_NGSetupRequestIEs_t *make_DefaultPagingDRX_ie(e_Ngap_PagingDRX drx ) {
	Ngap_NGSetupRequestIEs_t *ie;
	ie = calloc(1, sizeof(Ngap_NGSetupRequestIEs_t));

	ie->id =Ngap_ProtocolIE_ID_id_DefaultPagingDRX;
	ie->criticality = Ngap_Criticality_reject;
	ie->value.present = Ngap_NGSetupRequestIEs__value_PR_PagingDRX;
	ie->value.choice.PagingDRX = drx;
    return ie;
}

Ngap_SupportedTAItem_t *make_SupportedTaItem_1() {
    Ngap_SupportedTAItem_t *item;
    item = (Ngap_SupportedTAItem_t *)calloc(1, sizeof(Ngap_SupportedTAItem_t));
    fill_tAC(&item->tAC, 257);
    fill_broadcastPLMNList_1(&item->broadcastPLMNList);
    return item;
}

Ngap_SupportedTAItem_t *make_SupportedTaItem_2() {
    Ngap_SupportedTAItem_t *item;
    item = (Ngap_SupportedTAItem_t *)calloc(1, sizeof(Ngap_SupportedTAItem_t));
    fill_tAC(&item->tAC, 65537);
    fill_broadcastPLMNList_2(&item->broadcastPLMNList);
    return item;
}

Ngap_NGSetupRequestIEs_t *make_supportedTAList(void) {
	Ngap_NGSetupRequestIEs_t *ie = NULL;
    ie = calloc(1, sizeof(Ngap_NGSetupRequestIEs_t));
    ie->id =Ngap_ProtocolIE_ID_id_SupportedTAList;
    ie->criticality = Ngap_Criticality_reject;
    ie->value.present = Ngap_NGSetupRequestIEs__value_PR_SupportedTAList;

    Ngap_SupportedTAItem_t *ta;

    ta = make_SupportedTaItem_1();
    ASN_SEQUENCE_ADD(&ie->value.choice.SupportedTAList.list, ta);

    ta = make_SupportedTaItem_2();
    ASN_SEQUENCE_ADD(&ie->value.choice.SupportedTAList.list, ta);

    return ie;
}

void add_NGSetupRequest_ie(Ngap_NGSetupRequest_t *ngapSetupRequest, Ngap_NGSetupRequestIEs_t *ie) {
    int ret;
	ret = ASN_SEQUENCE_ADD(&ngapSetupRequest->protocolIEs.list, ie);
    if ( ret != 0 ) {
        fprintf(stderr, "Failed to add ie\n");
    }
}

// PDU funcs

void check_NGAP_pdu_constraints(Ngap_NGAP_PDU_t *pdu) {
    int ret;
    char errbuf[512];
    size_t errlen =sizeof(errbuf);
    ret = asn_check_constraints(&asn_DEF_Ngap_NGAP_PDU, pdu, errbuf, &errlen);
    if(ret != 0) {
        fprintf(stderr,"Constraintvalidationfailed:%s\n", errbuf);
    }
}
#include  "bstrlib.h"
#include  "intertask_interface_types.h"

void encode_pdu_to_aper_and_write_to_stdout(Ngap_NGAP_PDU_t *pdu) {
    size_t buffer_size = 1000;
    void *buffer = calloc(1,buffer_size);
    asn_enc_rval_t er;

    er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);

  #if 1
        printf("sctp client send buffer length(%d)\nbuffer:\t",er.encoded);
        int i=0;
        uint8_t * buffer_p = (uint8_t*)buffer;
        uint8_t * buffer_send = (uint8_t*)buffer;
        for(;i<er.encoded;buffer_p+=sizeof(uint8_t),i++)
          printf("%x",*((uint8_t*)buffer_p));
        printf("\n");
#endif    


	MessagesIds message_id = MESSAGES_ID_MAX;
    Ngap_NGAP_PDU_t decoded_pdu = {0};

	  
	bstring b = blk2bstr(buffer, er.encoded);

	 
	printf("NGAP_SetupRequest-------------decode, length:%d\n", er.encoded);
    ngap_amf_decode_pdu(&decoded_pdu, b,  &message_id);
    ngap_amf_handle_message(0,0,&decoded_pdu);

   #if 0
        Ngap_NGAP_PDU_t  decoded_pdu;
        Ngap_NGAP_PDU_t * ppdu = &decoded_pdu;
        asn_dec_rval_t rc = asn_decode(NULL,ATS_ALIGNED_CANONICAL_PER,&asn_DEF_Ngap_NGAP_PDU,(void**)&ppdu,buffer,er.encoded);
        printf("decode result(%d)\n",rc);
        printf("decoded message present(%d)\n",decoded_pdu.present);
        switch(decoded_pdu.present){
          case Ngap_NGAP_PDU_PR_initiatingMessage:
            printf("precedureCode(%d)\n",decoded_pdu.choice.initiatingMessage->procedureCode);
            printf("message type(%d)\n",decoded_pdu.choice.initiatingMessage->value.present);
        }  
   #endif

#if 1
    int assoc[1];
    sctp_data_t * sctp_data_p = NULL;
    char *local_ip_addr[] = {"10.112.43.231"};
    char remote_ip_addr[] = "10.112.43.231";
    sctp_data_p = (sctp_data_t *) calloc (1, sizeof(sctp_data_t));
    if (sctp_data_p == NULL)  exit(1);
    assoc[0] = sctp_connect_to_remote_host (local_ip_addr, 1, remote_ip_addr, 36412, SOCK_STREAM, sctp_data_p);
    sctp_send_msg (sctp_data_p, 60, 0, buffer_send,er.encoded);
#endif
    if ( er.encoded > -1 ) {
        int len;
        len = write(1, buffer, er.encoded);
        fprintf(stderr,"encoder returned %ld bytes, wrote %d bytes!\n", er.encoded, len);
    } else {
        fprintf(stderr,"encoding to aper failed !\n");
    }
}

Ngap_NGAP_PDU_t *make_NGAP_SetupRequest() 
{
	Ngap_NGAP_PDU_t *pdu;
	pdu = calloc(1, sizeof(Ngap_NGAP_PDU_t));

	pdu->present = Ngap_NGAP_PDU_PR_initiatingMessage;
	pdu->choice.initiatingMessage = calloc(1, sizeof(Ngap_InitiatingMessage_t));
	pdu->choice.initiatingMessage->procedureCode = Ngap_ProcedureCode_id_NGSetup;
	pdu->choice.initiatingMessage->criticality = Ngap_Criticality_reject;
	pdu->choice.initiatingMessage->value.present = Ngap_InitiatingMessage__value_PR_NGSetupRequest;

	Ngap_NGSetupRequest_t *ngapSetupRequest;
	ngapSetupRequest = &pdu->choice.initiatingMessage->value.choice.NGSetupRequest;

    // Make NGSetupRequest IEs and add it to message

	Ngap_NGSetupRequestIEs_t *ie;

    ie = make_GlobalRANNodeID_ie();
    add_NGSetupRequest_ie(ngapSetupRequest, ie);

    ie = make_RANNodeName_ie("test gNB");
    add_NGSetupRequest_ie(ngapSetupRequest, ie);

    ie = make_DefaultPagingDRX_ie(Ngap_PagingDRX_v128);
    add_NGSetupRequest_ie(ngapSetupRequest, ie);

    ie = make_supportedTAList();
    add_NGSetupRequest_ie(ngapSetupRequest, ie);

    return pdu;
}

int main( int argc, char * argv[]) {
    fprintf(stderr, "Capture loopback with wireshark and test with 2 terminals:\n");
    fprintf(stderr, "  terminal 1: $ socat SCTP-LISTEN:38412,reuseaddr,fork STDOUT\n");
    fprintf(stderr, "  terminal 2: $ ./NGSetupRequest | socat STDIN SCTP-CONNECT:127.0.0.1:38412,end-close\n\n");

    uint8_t * buffer_p = NULL;
	uint32_t length = 0;
	Ngap_NGAP_PDU_t *pdu;
	pdu = make_NGAP_SetupRequest();
	
    // debug
    asn_fprint(stderr, &asn_DEF_Ngap_NGAP_PDU, pdu);

    check_NGAP_pdu_constraints(pdu);
    //encode_pdu_to_aper_and_write_to_stdout(pdu);


	size_t buffer_size = 1000;
    void *buffer = calloc(1,buffer_size);
    asn_enc_rval_t er;

    er = aper_encode_to_buffer(&asn_DEF_Ngap_NGAP_PDU, NULL, pdu, buffer, buffer_size);

  #if 1
        printf("sctp client send buffer length(%d)\nbuffer:\t",er.encoded);
        int i=0;
        uint8_t * buffer_p = (uint8_t*)buffer;
        uint8_t * buffer_send = (uint8_t*)buffer;
        for(;i<er.encoded;buffer_p+=sizeof(uint8_t),i++)
          printf("%x",*((uint8_t*)buffer_p));
        printf("\n");
#endif    


	MessagesIds message_id = MESSAGES_ID_MAX;
    Ngap_NGAP_PDU_t decoded_pdu = {0};

	  
	bstring b = blk2bstr(buffer, er.encoded);

	 
	printf("NGAP_SetupRequest-------------decode, length:%d\n", er.encoded);
    ngap_amf_decode_pdu(&decoded_pdu, b,  &message_id);
    ngap_amf_handle_message(0,0,&decoded_pdu);


   
	
    ASN_STRUCT_FREE(asn_DEF_Ngap_NGAP_PDU, pdu);
}
