#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "SSCMode.h"

int encode_ssc_mode ( SSCMode sscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr;
    uint32_t encoded = 0;
    int encode_result;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,SSC_MODE_MINIMUM_LENGTH , len);

    if ((encode_result = encode_bstring (sscmode, buffer + encoded, len - encoded)) < 0)//加密,实体,首地址,长度
        return encode_result;
    else
	{
    	*(buffer + encoded) = (*(buffer + encoded) & 0X07) | (iei & 0XF0);
    	encoded += encode_result;
    }

    return encoded;
}

int decode_ssc_mode ( SSCMode * sscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint8_t ielen=1;
	int decode_result;
	
	if (iei > 0) 
	{
		CHECK_IEI_DECODER ((*(buffer + decoded) & 0xF0), iei);
	}
	
	*(buffer + decoded) &= 0X07;

    if((decode_result = decode_bstring (sscmode, ielen, buffer + decoded, len - decoded)) < 0)
        return decode_result;
    else
        decoded += decode_result;
            return decoded;
}

