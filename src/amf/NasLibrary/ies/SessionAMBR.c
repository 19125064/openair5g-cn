#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "SessionAMBR.h"

int encode_session_ambr ( SessionAMBR sessionambr, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr = NULL;
    uint32_t encoded = 0;
    int encode_result;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,((iei > 0) ? SESSION_AMBR_MINIMUM_LENGTH_TLV : SESSION_AMBR_MINIMUM_LENGTH_LV) , len);
    
	if( iei >0  )
	{
		*buffer=iei;
		encoded++;
	}

    lenPtr = (buffer + encoded);
    encoded++;

	ENCODE_U8(buffer+encoded,sessionambr.uint_for_session_ambr_for_downlink,encoded);
	*(buffer + encoded) = sessionambr.session_ambr_for_downlink/(1<<8);
	encoded++;
	*(buffer + encoded) = sessionambr.session_ambr_for_downlink%(1<<8);
	encoded++;
	ENCODE_U8(buffer+encoded,sessionambr.uint_for_session_ambr_for_uplink,encoded);
	*(buffer + encoded) = sessionambr.session_ambr_for_uplink/(1<<8);
	encoded++;
	*(buffer + encoded) = sessionambr.session_ambr_for_uplink%(1<<8);
	encoded++;

    *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);
	
    return encoded;
}

int decode_session_ambr ( SessionAMBR * sessionambr, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint8_t ielen=0;
	uint8_t bit8Stream = 0;
	uint16_t bit16Stream = 0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    ielen = *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);


	DECODE_U8(buffer+decoded,bit8Stream,decoded);
	sessionambr->uint_for_session_ambr_for_downlink = bit8Stream;

	bit16Stream = *(buffer + decoded);
	decoded++;
	bit16Stream = ( bit16Stream << 8)+*(buffer + decoded);
	decoded++;
	sessionambr->session_ambr_for_downlink = bit16Stream;

	DECODE_U8(buffer+decoded,bit8Stream,decoded);
	sessionambr->uint_for_session_ambr_for_uplink = bit8Stream;

	bit16Stream = *(buffer + decoded);
	decoded++;
	bit16Stream = ( bit16Stream << 8)+*(buffer + decoded);
	decoded++;
	sessionambr->session_ambr_for_uplink = bit16Stream;

	return decoded;
}

