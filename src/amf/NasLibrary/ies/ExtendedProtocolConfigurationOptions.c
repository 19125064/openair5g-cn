#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "ExtendedProtocolConfigurationOptions.h"

int encode_extended_protocol_configuration_options ( ExtendedProtocolConfigurationOptions extendedprotocolconfigurationoptions, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr = NULL;
    uint32_t encoded = 0;
    int encode_result = 0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MINIMUM_LENGTH , len);
    

    if( iei >0  )
    {
        *buffer=iei;
        encoded++;
    }


    lenPtr = (buffer + encoded);
    encoded++;
    encoded++;


    if ((encode_result = encode_bstring (extendedprotocolconfigurationoptions, buffer + encoded, len - encoded)) < 0)//加密,实体,首地址,长度
        return encode_result;
    else
        encoded += encode_result;

    uint32_t res = encoded - 2 - ((iei > 0) ? 1 : 0);
    *lenPtr =res/(1<<8);
    lenPtr++;
    *lenPtr = res%(1<<8);

    return encoded;
}

int decode_extended_protocol_configuration_options ( ExtendedProtocolConfigurationOptions * extendedprotocolconfigurationoptions, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint32_t ielen=0;
	int decode_result = 0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }


    ielen = *(buffer + decoded);
    decoded++;
    ielen = ( ielen << 8) + *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);


    if((decode_result = decode_bstring (extendedprotocolconfigurationoptions, ielen, buffer + decoded, len - decoded)) < 0)
        return decode_result;
    else
        decoded += decode_result;

	return decoded;
}

