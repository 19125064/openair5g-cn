#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "AllowedSSCMode.h"

int encode_allowed_ssc_mode ( AllowedSSCMode allowedsscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
    uint8_t bitStream = 0x00;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,ALLOWED_SSC_MODE_MINIMUM_LENGTH , len);
    
	if(iei > 0){
		bitStream |= (iei & 0xf0);
	}

	if(allowedsscmode.is_ssc3_allowed)
	{
		bitStream |= 0x04;
	}
	if(allowedsscmode.is_ssc2_allowed)
	{
		bitStream |= 0x02;
	}
	if(allowedsscmode.is_ssc1_allowed)
	{
		bitStream |= 0x01;
	}

	ENCODE_U8(buffer+encoded,bitStream,encoded);
	
    return encoded;
}

int decode_allowed_ssc_mode ( AllowedSSCMode * allowedsscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint8_t bitStream = 0x00;

	DECODE_U8(buffer+decoded,bitStream,decoded);

	if(iei != bitStream&0xf0){
		return -1;
	}
	if(iei > 0){
		bitStream = (bitStream & 0x07);	
	}

	if(bitStream & 0x01)
	{
		allowedsscmode->is_ssc1_allowed = true;
	}
	else
	{
		allowedsscmode->is_ssc1_allowed = false;
	}
	if(bitStream & 0x02)
	{
		allowedsscmode->is_ssc2_allowed = true;
	}
	else
	{
		allowedsscmode->is_ssc2_allowed = false;
	}
	if(bitStream & 0x04)
	{
		allowedsscmode->is_ssc3_allowed = true;
	}
	else
	{
		allowedsscmode->is_ssc3_allowed = false;
	}
	
	return decoded;
}

