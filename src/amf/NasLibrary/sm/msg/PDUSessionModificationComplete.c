#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "PDUSessionModificationComplete.h"

int decode_pdu_session_modification_complete( pdu_session_modification_complete_msg *pdu_session_modification_complete, uint8_t* buffer, uint32_t len)
{
    uint32_t decoded = 0;
    int decoded_result = 0;

    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_DECODER (buffer, PDU_SESSION_MODIFICATION_COMPLETE_MINIMUM_LENGTH, len);

	#if 0
    if((decoded_result = decode_extended_protocol_discriminator (&pdu_session_modification_complete->extendedprotocoldiscriminator, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_pdu_session_identity (&pdu_session_modification_complete->pdusessionidentity, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_procedure_transaction_identity (&pdu_session_modification_complete->proceduretransactionidentity, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_message_type (&pdu_session_modification_complete->messagetype, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;
	#endif

	while(len - decoded > 0)
	{
		//printf("encoding ies left(%d)\n",len-decoded);
		//printf("decoded(%d)\n",decoded);
		uint8_t ieiDecoded = *(buffer+decoded);
		//printf("ieiDecoded = 0x%x\n",ieiDecoded);
		//sleep(1);
		
		if(ieiDecoded == 0)
			break;

		switch(ieiDecoded)
		{
			case PDU_SESSION_MODIFICATION_COMPLETE_E_P_C_O_IEI:
				if((decoded_result = decode_extended_protocol_configuration_options (&pdu_session_modification_complete->extendedprotocolconfigurationoptions, PDU_SESSION_MODIFICATION_COMPLETE_E_P_C_O_IEI, buffer+decoded,len-decoded))<0)
        			return decoded_result;
    			else
    			{
        			decoded+=decoded_result;
					pdu_session_modification_complete->presence |= PDU_SESSION_MODIFICATION_COMPLETE_E_P_C_O_PRESENCE;
    			}
			break;
		}
	}
    
    return decoded;
}


int encode_pdu_session_modification_complete( pdu_session_modification_complete_msg *pdu_session_modification_complete, uint8_t* buffer, uint32_t len)
{
    uint32_t encoded = 0;
    int encoded_result = 0;
    
    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer, PDU_SESSION_MODIFICATION_COMPLETE_MINIMUM_LENGTH, len);

	#if 0
    if((encoded_result = encode_extended_protocol_discriminator (pdu_session_modification_complete->extendedprotocoldiscriminator, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_pdu_session_identity (pdu_session_modification_complete->pdusessionidentity, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_procedure_transaction_identity (pdu_session_modification_complete->proceduretransactionidentity, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_message_type (pdu_session_modification_complete->messagetype, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;
	#endif

	if((pdu_session_modification_complete->presence & PDU_SESSION_MODIFICATION_COMPLETE_E_P_C_O_PRESENCE) == PDU_SESSION_MODIFICATION_COMPLETE_E_P_C_O_PRESENCE)
	{
	    if((encoded_result = encode_extended_protocol_configuration_options (pdu_session_modification_complete->extendedprotocolconfigurationoptions, PDU_SESSION_MODIFICATION_COMPLETE_E_P_C_O_IEI, buffer+encoded,len-encoded))<0)
	        return encoded_result;
	    else
	        encoded+=encoded_result;
	}

    return encoded;
}
