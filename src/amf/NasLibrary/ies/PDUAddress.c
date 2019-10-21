#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "PDUAddress.h"

int encode_pdu_address ( PDUAddress pduaddress, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr = NULL;
    uint32_t encoded = 0;
    int encode_result = 0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,((iei > 0) ? PDU_ADDRESS_MINIMUM_LENGTH_TLV : PDU_ADDRESS_MINIMUM_LENGTH_TLV-1) , len);
    

	if( iei > 0 )
	{
		*buffer=iei;
		encoded++;
	}


    lenPtr = (buffer + encoded);
    encoded++;

	ENCODE_U8(buffer+encoded,(uint8_t)(pduaddress.pdu_session_type_value&0x07),encoded);

    if ((encode_result = encode_bstring (pduaddress.pdu_address_information, buffer + encoded, len - encoded)) < 0)//加密,实体,首地址,长度
        return encode_result;
    else
        encoded += encode_result;

    *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);
	
    return encoded;
}

int decode_pdu_address ( PDUAddress * pduaddress, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint8_t ielen=0;
	int decode_result = 0;
	uint8_t bitStream = 0x00;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    ielen = *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);

	DECODE_U8(buffer+decoded,bitStream,decoded);
	pduaddress->pdu_session_type_value = bitStream&0x07;

    if((decode_result = decode_bstring (&pduaddress->pdu_address_information, ielen-1, buffer + decoded, len - decoded)) < 0)
        return decode_result;
    else
        decoded += decode_result;
	
    return decoded;
}

