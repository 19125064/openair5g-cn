#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "PDUSessionEstablishmentAccept.h"

int decode_pdu_session_establishment_accept( pdu_session_establishment_accept_msg *pdu_session_establishment_accept, uint8_t* buffer, uint32_t len)
{
    uint32_t decoded = 0;
    int decoded_result = 0;

    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_DECODER (buffer, PDU_SESSION_ESTABLISHMENT_ACCEPT_MINIMUM_LENGTH, len);

#if 0
    if((decoded_result = decode_extended_protocol_discriminator (&pdu_session_establishment_accept->extendedprotocoldiscriminator, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_pdu_session_identity (&pdu_session_establishment_accept->pdusessionidentity, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_procedure_transaction_identity (&pdu_session_establishment_accept->proceduretransactionidentity, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_message_type (&pdu_session_establishment_accept->messagetype, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;
#endif
    if((decoded_result = decode__pdu_session_type (&pdu_session_establishment_accept->_pdusessiontype, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_ssc_mode (&pdu_session_establishment_accept->sscmode, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_qos_rules (&pdu_session_establishment_accept->qosrules, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_session_ambr (&pdu_session_establishment_accept->sessionambr, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

	while(len - decoded > 0)
	{
		//printf("encoding ies left(%d)\n",len-decoded);
		//printf("decoded(%d)\n",decoded);
		uint8_t ieiDecoded = *(buffer+decoded);
		//printf("ieiDecoded = 0x%x\n",ieiDecoded);
		//sleep(1);
		
		if(ieiDecoded == 0)
			break;

		switch(ieiDecoded&0xf0)
		{
			case PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_IEI:
				if((decoded_result = decode_alwayson_pdu_session_indication (&pdu_session_establishment_accept->alwaysonpdusessionindication, PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_IEI, buffer+decoded,len-decoded))<0)
					return decoded_result;
				else
				{
					decoded+=decoded_result;
					pdu_session_establishment_accept->presence |= PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE;
				}
			break;
		}
		switch(ieiDecoded)
		{
			case PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_IEI:
				if((decoded_result = decode__5gsm_cause (&pdu_session_establishment_accept->_5gsmcause, PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_IEI, buffer+decoded,len-decoded))<0)
					return decoded_result;
				else
				{
					decoded+=decoded_result;
					pdu_session_establishment_accept->presence |= PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_PRESENCE;
				}
			break;
			case PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_IEI:
				if((decoded_result = decode_pdu_address (&pdu_session_establishment_accept->pduaddress, PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_IEI, buffer+decoded,len-decoded))<0)
					return decoded_result;
				else
				{
					decoded+=decoded_result;
					pdu_session_establishment_accept->presence |= PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_PRESENCE;
				}
			break;
			case PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_IEI:
				if((decoded_result = decode_gprs_timer (&pdu_session_establishment_accept->gprstimer, PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_IEI, buffer+decoded,len-decoded))<0)
					return decoded_result;
				else
				{
					decoded+=decoded_result;
					pdu_session_establishment_accept->presence |= PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_PRESENCE;
				}
			break;
			case PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_IEI:
				if((decoded_result = decode_snssai (&pdu_session_establishment_accept->snssai, PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_IEI, buffer+decoded,len-decoded))<0)
					return decoded_result;
				else
				{
					decoded+=decoded_result;
					pdu_session_establishment_accept->presence |= PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_PRESENCE;
				}
			break;
#if 0
			case PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_IEI:
				if((decoded_result = decode_mapped_eps_bearer_contexts (&pdu_session_establishment_accept->mappedepsbearercontexts, PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_IEI, buffer+decoded,len-decoded))<0)
					return decoded_result;
				else
				{
					decoded+=decoded_result;
					pdu_session_establishment_accept->presence |= PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_PRESENCE;
				}
			break;
#endif
			case PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_IEI:
				if((decoded_result = decode_eap_message (&pdu_session_establishment_accept->eapmessage, PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_IEI, buffer+decoded,len-decoded))<0)
					return decoded_result;
				else
				{
					decoded+=decoded_result;
					pdu_session_establishment_accept->presence |= PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_PRESENCE;
				}
			break;
			case PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_IEI:
				if((decoded_result = decode_qos_flow_descriptions (&pdu_session_establishment_accept->qosflowdescriptions, PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_IEI, buffer+decoded,len-decoded))<0)
					return decoded_result;
				else
				{
					decoded+=decoded_result;
					pdu_session_establishment_accept->presence |= PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_PRESENCE;
				}
			break;
			case PDU_SESSION_ESTABLISHMENT_ACCEPT_E_P_C_O_IEI:
				if((decoded_result = decode_extended_protocol_configuration_options (&pdu_session_establishment_accept->extendedprotocolconfigurationoptions, PDU_SESSION_ESTABLISHMENT_ACCEPT_E_P_C_O_IEI, buffer+decoded,len-decoded))<0)
					return decoded_result;
				else
				{
					decoded+=decoded_result;
					pdu_session_establishment_accept->presence |= PDU_SESSION_ESTABLISHMENT_ACCEPT_E_P_C_O_PRESENCE;
				}
			break;
			case PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_IEI:
				if((decoded_result = decode_dnn (&pdu_session_establishment_accept->dnn, PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_IEI, buffer+decoded,len-decoded))<0)
					return decoded_result;
				else
				{
					decoded+=decoded_result;
					pdu_session_establishment_accept->presence |= PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_PRESENCE;
				}
			break;
			
		}
	}

    return decoded;
}


int encode_pdu_session_establishment_accept( pdu_session_establishment_accept_msg *pdu_session_establishment_accept, uint8_t* buffer, uint32_t len)
{
    uint32_t encoded = 0;
    int encoded_result = 0;
    
    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer, PDU_SESSION_ESTABLISHMENT_ACCEPT_MINIMUM_LENGTH, len);

	#if 0
    if((encoded_result = encode_extended_protocol_discriminator (pdu_session_establishment_accept->extendedprotocoldiscriminator, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_pdu_session_identity (pdu_session_establishment_accept->pdusessionidentity, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_procedure_transaction_identity (pdu_session_establishment_accept->proceduretransactionidentity, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_message_type (pdu_session_establishment_accept->messagetype, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;
	#endif
	
    if((encoded_result = encode__pdu_session_type (pdu_session_establishment_accept->_pdusessiontype, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_ssc_mode (pdu_session_establishment_accept->sscmode, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_qos_rules (pdu_session_establishment_accept->qosrules, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_session_ambr (pdu_session_establishment_accept->sessionambr, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

	if((pdu_session_establishment_accept->presence & PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_PRESENCE) == PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_PRESENCE)
    {
	    if((encoded_result = encode__5gsm_cause (pdu_session_establishment_accept->_5gsmcause, PDU_SESSION_ESTABLISHMENT_ACCEPT__5GSM_CAUSE_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}

	if((pdu_session_establishment_accept->presence & PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_PRESENCE) == PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_PRESENCE)
    {
	    if((encoded_result = encode_pdu_address (pdu_session_establishment_accept->pduaddress, PDU_SESSION_ESTABLISHMENT_ACCEPT_PDU_ADDRESS_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}

	if((pdu_session_establishment_accept->presence & PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_PRESENCE) == PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_PRESENCE)
    {
	    if((encoded_result = encode_gprs_timer (pdu_session_establishment_accept->gprstimer, PDU_SESSION_ESTABLISHMENT_ACCEPT_GPRS_TIMER_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}

	if((pdu_session_establishment_accept->presence & PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_PRESENCE) == PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_PRESENCE)
    {
	    if((encoded_result = encode_snssai (pdu_session_establishment_accept->snssai, PDU_SESSION_ESTABLISHMENT_ACCEPT_SNSSAI_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}

	if((pdu_session_establishment_accept->presence & PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE) == PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE)
    {
	    if((encoded_result = encode_alwayson_pdu_session_indication (pdu_session_establishment_accept->alwaysonpdusessionindication, PDU_SESSION_ESTABLISHMENT_ACCEPT_ALWAYSON_PDU_SESSION_INDICATION_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}
#if 0
	if((pdu_session_establishment_accept->presence & PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_PRESENCE) == PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_PRESENCE)
    {
	    if((encoded_result = encode_mapped_eps_bearer_contexts (pdu_session_establishment_accept->mappedepsbearercontexts, PDU_SESSION_ESTABLISHMENT_ACCEPT_MAPPED_EPS_BEARER_CONTEXTS_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}
#endif
	if((pdu_session_establishment_accept->presence & PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_PRESENCE) == PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_PRESENCE)
    {
	    if((encoded_result = encode_eap_message (pdu_session_establishment_accept->eapmessage, PDU_SESSION_ESTABLISHMENT_ACCEPT_EAP_MESSAGE_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}

	if((pdu_session_establishment_accept->presence & PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_PRESENCE) == PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_PRESENCE)
    {
	    if((encoded_result = encode_qos_flow_descriptions (pdu_session_establishment_accept->qosflowdescriptions, PDU_SESSION_ESTABLISHMENT_ACCEPT_QOS_FLOW_DESCRIPTIONS_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}
	if((pdu_session_establishment_accept->presence & PDU_SESSION_ESTABLISHMENT_ACCEPT_E_P_C_O_PRESENCE) == PDU_SESSION_ESTABLISHMENT_ACCEPT_E_P_C_O_PRESENCE)
    {
	    if((encoded_result = encode_extended_protocol_configuration_options (pdu_session_establishment_accept->extendedprotocolconfigurationoptions, PDU_SESSION_ESTABLISHMENT_ACCEPT_E_P_C_O_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}

	if((pdu_session_establishment_accept->presence & PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_PRESENCE) == PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_PRESENCE)
    {
	    if((encoded_result = encode_dnn (pdu_session_establishment_accept->dnn, PDU_SESSION_ESTABLISHMENT_ACCEPT_DNN_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}


    return encoded;
}
