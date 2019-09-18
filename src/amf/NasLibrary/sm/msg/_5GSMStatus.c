#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "_5GSMStatus.h"

int decode__5gsm_status( _5gsm_status_msg *_5gsm_status, uint8_t* buffer, uint32_t len)
{
    uint32_t decoded = 0;
    int decoded_result = 0;

    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_DECODER (buffer, _5GSM_STATUS_MINIMUM_LENGTH, len);

	#if 0
    if((decoded_result = decode_extended_protocol_discriminator (&_5gsm_status->extendedprotocoldiscriminator, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_pdu_session_identity (&_5gsm_status->pdusessionidentity, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_procedure_transaction_identity (&_5gsm_status->proceduretransactionidentity, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;

    if((decoded_result = decode_message_type (&_5gsm_status->messagetype, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;
	#endif
	
    if((decoded_result = decode__5gsm_cause (&_5gsm_status->_5gsmcause, 0, buffer+decoded,len-decoded))<0)
        return decoded_result;
    else
        decoded+=decoded_result;


    return decoded;
}


int encode__5gsm_status( _5gsm_status_msg *_5gsm_status, uint8_t* buffer, uint32_t len)
{
    uint32_t encoded = 0;
    int encoded_result = 0;
    
    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer, _5GSM_STATUS_MINIMUM_LENGTH, len);

	#if 0
    if((encoded_result = encode_extended_protocol_discriminator (_5gsm_status->extendedprotocoldiscriminator, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_pdu_session_identity (_5gsm_status->pdusessionidentity, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_procedure_transaction_identity (_5gsm_status->proceduretransactionidentity, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;

    if((encoded_result = encode_message_type (_5gsm_status->messagetype, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;
	#endif
	
    if((encoded_result = encode__5gsm_cause (_5gsm_status->_5gsmcause, 0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;


    return encoded;
}
