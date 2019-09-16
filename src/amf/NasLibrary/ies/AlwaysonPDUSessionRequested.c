#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "AlwaysonPDUSessionRequested.h"

int encode_alwayson_pdu_session_requested ( AlwaysonPDUSessionRequested alwaysonpdusessionrequested, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr;
    uint32_t encoded = 0;
    int encode_result;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,ALWAYSON_PDU_SESSION_REQUESTED_MINIMUM_LENGTH , len);
   

    if ((encode_result = encode_bstring (alwaysonpdusessionrequested, buffer + encoded, len - encoded)) < 0)//加密,实体,首地址,长度
        return encode_result;
    else
	{
    	*(buffer + encoded) = (*(buffer + encoded) & 0X01) | (iei & 0XF0);
    	encoded += encode_result;
    }

    return encoded;
}

int decode_alwayson_pdu_session_requested ( AlwaysonPDUSessionRequested * alwaysonpdusessionrequested, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint8_t ielen=1;
	int decode_result;

	if (iei > 0) 
	{
    	CHECK_IEI_DECODER ((*(buffer + decoded) & 0xF0), iei);
  	}

	*(buffer + decoded) &= 0X01;

    if((decode_result = decode_bstring (alwaysonpdusessionrequested, ielen, buffer + decoded, len - decoded)) < 0)
        return decode_result;
    else
        decoded += decode_result;
            return decoded;
}

