#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "IntergrityProtectionMaximumDataRate.h"

int encode_intergrity_protection_maximum_data_rate ( IntergrityProtectionMaximumDataRate intergrityprotectionmaximumdatarate, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr = NULL;
    uint32_t encoded = 0;
    int encode_result = 0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,INTERGRITY_PROTECTION_MAXIMUM_DATA_RATE_MINIMUM_LENGTH , len);
    

    if( iei > 0)
    {
    	*buffer=iei;
        encoded++;
    }

    if ((encode_result = encode_bstring (intergrityprotectionmaximumdatarate, buffer + encoded, len - encoded)) < 0)//加密,实体,首地址,长度
        return encode_result;
    else
        encoded += encode_result;


    return encoded;
}

int decode_intergrity_protection_maximum_data_rate ( IntergrityProtectionMaximumDataRate * intergrityprotectionmaximumdatarate, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint8_t ielen=2;
	int decode_result = 0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    if((decode_result = decode_bstring (intergrityprotectionmaximumdatarate, ielen, buffer + decoded, len - decoded)) < 0)
        return decode_result;
    else
        decoded += decode_result;
            return decoded;
}

