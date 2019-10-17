#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "PDUSessionEstablishmentRequest.h"

int decode_pdu_session_establishment_request( pdu_session_establishment_request_msg *pdu_session_establishment_request, uint8_t* buffer, uint32_t len)
{
    uint32_t decoded = 0;
    int decoded_result = 0;

    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_DECODER (buffer, PDU_SESSION_ESTABLISHMENT_REQUEST_MINIMUM_LENGTH, len);

    #if 0
    if((decoded_result = decode_extended_protocol_discriminator (&pdu_session_establishment_request->extendedprotocoldiscriminator, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_pdu_session_identity (&pdu_session_establishment_request->pdusessionidentity, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_procedure_transaction_identity (&pdu_session_establishment_request->proceduretransactionidentity, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_message_type (&pdu_session_establishment_request->messagetype, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;
	#endif
   
    if((decoded_result = decode_intergrity_protection_maximum_data_rate (&pdu_session_establishment_request->intergrityprotectionmaximumdatarate, 0, buffer+decoded,len-decoded))<0)
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
			case PDU_SESSION_ESTABLISHMENT_REQUEST_PDU_SESSION_TYPE_IEI:
		        if ((decoded_result = decode__pdu_session_type (&pdu_session_establishment_request->_pdusessiontype, PDU_SESSION_ESTABLISHMENT_REQUEST_PDU_SESSION_TYPE_IEI, buffer+decoded,len-decoded)) < 0)
		        	return decoded_result;                
		        else
				{                                    
		          	decoded += decoded_result;
		          	pdu_session_establishment_request->presence |= PDU_SESSION_ESTABLISHMENT_REQUEST_PDU_SESSION_TYPE_PRESENT;
		        }
	      	break;
		    
		    case PDU_SESSION_ESTABLISHMENT_REQUEST_SSC_MODE_IEI:
		        if ((decoded_result = decode_ssc_mode (&pdu_session_establishment_request->sscmode, PDU_SESSION_ESTABLISHMENT_REQUEST_SSC_MODE_IEI, buffer+decoded,len-decoded)) < 0)
		        	return decoded_result;                
		        else
				{                                    
		          	decoded += decoded_result;
		          	pdu_session_establishment_request->presence |= PDU_SESSION_ESTABLISHMENT_REQUEST_SSC_MODE_PRESENT;
		        }
	      	break;

			case PDU_SESSION_ESTABLISHMENT_REQUEST_ALWAYSON_PDU_SESSION_REQUESTED_IEI:
		        if ((decoded_result = decode_alwayson_pdu_session_requested (&pdu_session_establishment_request->alwaysonpdusessionrequested, PDU_SESSION_ESTABLISHMENT_REQUEST_ALWAYSON_PDU_SESSION_REQUESTED_IEI, buffer+decoded,len-decoded)) < 0)
		        	return decoded_result;                
		        else
				{                                    
		          	decoded += decoded_result;
		          	pdu_session_establishment_request->presence |= PDU_SESSION_ESTABLISHMENT_REQUEST_ALWAYSON_PDU_SESSION_REQUESTED_PRESENT;
		        }
	      	break;
		}
		
    	switch(ieiDecoded)
		{
		    case PDU_SESSION_ESTABLISHMENT_REQUEST__5GSM_CAPABILITY_IEI:
		        if ((decoded_result = decode__5gsm_capability (&pdu_session_establishment_request->_5gsmcapability, PDU_SESSION_ESTABLISHMENT_REQUEST__5GSM_CAPABILITY_IEI, buffer+decoded,len-decoded)) < 0)
		        	return decoded_result;                
		        else
				{                                    
		          	decoded += decoded_result;
		          	pdu_session_establishment_request->presence |= PDU_SESSION_ESTABLISHMENT_REQUEST__5GSM_CAPABILITY_PRESENT;
		        }
	      	break;

		    case PDU_SESSION_ESTABLISHMENT_REQUEST_MAXIMUM_NUMBER_OF_SUPPORTED_IEI:
		        if ((decoded_result = decode_maximum_number_of_supported_packet_filters (&pdu_session_establishment_request->maximumnumberofsupportedpacketfilters, PDU_SESSION_ESTABLISHMENT_REQUEST_MAXIMUM_NUMBER_OF_SUPPORTED_IEI, buffer+decoded,len-decoded)) < 0)
		        	return decoded_result;                
		        else
				{                                    
		          	decoded += decoded_result;
		          	pdu_session_establishment_request->presence |= PDU_SESSION_ESTABLISHMENT_REQUEST_MAXIMUM_NUMBER_OF_SUPPORTED_PRESENT;
		        }
	      	break;
			
		    case PDU_SESSION_ESTABLISHMENT_REQUEST_SMPDUDN_REQUEST_CONTAINER_INFORMATION_IEI:
		        if ((decoded_result = decode_smpdudn_request_container (&pdu_session_establishment_request->smpdudnrequestcontainer, PDU_SESSION_ESTABLISHMENT_REQUEST_SMPDUDN_REQUEST_CONTAINER_INFORMATION_IEI, buffer+decoded,len-decoded)) < 0)
		        	return decoded_result;                
		        else
				{                                    
		          	decoded += decoded_result;
		          	pdu_session_establishment_request->presence |= PDU_SESSION_ESTABLISHMENT_REQUEST_SMPDUDN_REQUEST_CONTAINER_INFORMATION_PRESENT;
		        }
	      	break;

		    case PDU_SESSION_ESTABLISHMENT_REQUEST_E_P_C_O_IEI:
		        if ((decoded_result = decode_extended_protocol_configuration_options (&pdu_session_establishment_request->extendedprotocolconfigurationoptions, PDU_SESSION_ESTABLISHMENT_REQUEST_E_P_C_O_IEI, buffer+decoded,len-decoded)) < 0)
		        	return decoded_result;                
		        else
				{                                    
		          	decoded += decoded_result;
		          	pdu_session_establishment_request->presence |= PDU_SESSION_ESTABLISHMENT_REQUEST_E_P_C_O_PRESENT;
		        }
	      	break;
    	}
	}

    return decoded;
}


int encode_pdu_session_establishment_request( pdu_session_establishment_request_msg *pdu_session_establishment_request, uint8_t* buffer, uint32_t len)
{
	printf("encode_pdu_session_establishment_request, start -----------------------\n");
    uint32_t encoded = 0;
    int encoded_result = 0;
    
    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer, PDU_SESSION_ESTABLISHMENT_REQUEST_MINIMUM_LENGTH, len);
	#if 0
    if((encoded_result = encode_extended_protocol_discriminator (pdu_session_establishment_request->extendedprotocoldiscriminator, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_pdu_session_identity (pdu_session_establishment_request->pdusessionidentity, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_procedure_transaction_identity (pdu_session_establishment_request->proceduretransactionidentity, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_message_type (pdu_session_establishment_request->messagetype, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;
	#endif

	
    if((encoded_result = encode_intergrity_protection_maximum_data_rate (pdu_session_establishment_request->intergrityprotectionmaximumdatarate, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;
	
	if((pdu_session_establishment_request->presence & PDU_SESSION_ESTABLISHMENT_REQUEST_PDU_SESSION_TYPE_PRESENT) == PDU_SESSION_ESTABLISHMENT_REQUEST_PDU_SESSION_TYPE_PRESENT)
	{
	    if((encoded_result = encode__pdu_session_type (pdu_session_establishment_request->_pdusessiontype, PDU_SESSION_ESTABLISHMENT_REQUEST_PDU_SESSION_TYPE_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}

	if((pdu_session_establishment_request->presence & PDU_SESSION_ESTABLISHMENT_REQUEST_SSC_MODE_PRESENT) == PDU_SESSION_ESTABLISHMENT_REQUEST_SSC_MODE_PRESENT)
	{
	    if((encoded_result = encode_ssc_mode (pdu_session_establishment_request->sscmode, PDU_SESSION_ESTABLISHMENT_REQUEST_SSC_MODE_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}

	if((pdu_session_establishment_request->presence & PDU_SESSION_ESTABLISHMENT_REQUEST__5GSM_CAPABILITY_PRESENT) == PDU_SESSION_ESTABLISHMENT_REQUEST__5GSM_CAPABILITY_PRESENT)
	{

	    if((encoded_result = encode__5gsm_capability (pdu_session_establishment_request->_5gsmcapability, PDU_SESSION_ESTABLISHMENT_REQUEST__5GSM_CAPABILITY_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}
	
	if((pdu_session_establishment_request->presence & PDU_SESSION_ESTABLISHMENT_REQUEST_MAXIMUM_NUMBER_OF_SUPPORTED_PRESENT) == PDU_SESSION_ESTABLISHMENT_REQUEST_MAXIMUM_NUMBER_OF_SUPPORTED_PRESENT)
	{
	    if((encoded_result = encode_maximum_number_of_supported_packet_filters (pdu_session_establishment_request->maximumnumberofsupportedpacketfilters, PDU_SESSION_ESTABLISHMENT_REQUEST_MAXIMUM_NUMBER_OF_SUPPORTED_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}
	
	if((pdu_session_establishment_request->presence & PDU_SESSION_ESTABLISHMENT_REQUEST_ALWAYSON_PDU_SESSION_REQUESTED_PRESENT) == PDU_SESSION_ESTABLISHMENT_REQUEST_ALWAYSON_PDU_SESSION_REQUESTED_PRESENT)
	{
	    if((encoded_result = encode_alwayson_pdu_session_requested (pdu_session_establishment_request->alwaysonpdusessionrequested, PDU_SESSION_ESTABLISHMENT_REQUEST_ALWAYSON_PDU_SESSION_REQUESTED_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}
	
	if((pdu_session_establishment_request->presence & PDU_SESSION_ESTABLISHMENT_REQUEST_SMPDUDN_REQUEST_CONTAINER_INFORMATION_PRESENT) == PDU_SESSION_ESTABLISHMENT_REQUEST_SMPDUDN_REQUEST_CONTAINER_INFORMATION_PRESENT)
	{
	    if((encoded_result = encode_smpdudn_request_container (pdu_session_establishment_request->smpdudnrequestcontainer, PDU_SESSION_ESTABLISHMENT_REQUEST_SMPDUDN_REQUEST_CONTAINER_INFORMATION_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}
	
	if((pdu_session_establishment_request->presence & PDU_SESSION_ESTABLISHMENT_REQUEST_E_P_C_O_PRESENT) == PDU_SESSION_ESTABLISHMENT_REQUEST_E_P_C_O_PRESENT)
	{
	    if((encoded_result = encode_extended_protocol_configuration_options (pdu_session_establishment_request->extendedprotocolconfigurationoptions, PDU_SESSION_ESTABLISHMENT_REQUEST_E_P_C_O_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}

    return encoded;
}
