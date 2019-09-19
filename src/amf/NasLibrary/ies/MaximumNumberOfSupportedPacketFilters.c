#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "MaximumNumberOfSupportedPacketFilters.h"

int encode_maximum_number_of_supported_packet_filters ( MaximumNumberOfSupportedPacketFilters maximumnumberofsupportedpacketfilters, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
	
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS_MINIMUM_LENGTH , len);
    

    if( iei > 0 )
    {
        *buffer=iei;
        encoded++;
    }
	
	ENCODE_U8(buffer+encoded,(uint8_t)(maximumnumberofsupportedpacketfilters&0x00ff),encoded);
	ENCODE_U8(buffer+encoded,(uint8_t)((maximumnumberofsupportedpacketfilters & 0x700) >> 3),encoded);

    return encoded;
}

int decode_maximum_number_of_supported_packet_filters ( MaximumNumberOfSupportedPacketFilters * maximumnumberofsupportedpacketfilters, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint8_t bit8Stream = 0;
	uint16_t bit16Stream = 0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

	DECODE_U8(buffer+decoded,bit8Stream,decoded);
	bit16Stream |= bit8Stream;
	DECODE_U8(buffer+decoded,bit8Stream,decoded);
	bit16Stream |= (uint16_t)(bit8Stream << 3);
	
	*maximumnumberofsupportedpacketfilters = bit16Stream;
	
    return decoded;
}

