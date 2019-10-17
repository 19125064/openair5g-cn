#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "_5GSMCause.h"

int encode__5gsm_cause ( _5GSMCause _5gsmcause, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
	
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,_5GSM_CAUSE_MINIMUM_LENGTH , len);
    

    if( iei > 0 )
    {
    	*buffer=iei;
    	encoded++;
    }

	ENCODE_U8(buffer+encoded,_5gsmcause,encoded);

    return encoded;
}

int decode__5gsm_cause ( _5GSMCause * _5gsmcause, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;

    if( iei > 0 )
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

	DECODE_U8(buffer+decoded,*_5gsmcause,decoded);

	return decoded;
}

