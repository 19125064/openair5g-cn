#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "SNSSAI.h"

int encode_snssai ( SNSSAI snssai, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
	uint8_t ielen = 0;
	uint8_t bitStream = 0;
	uint32_t bit32Stream = 0;
	
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,SNSSAI_MINIMUM_LENGTH , len);
    
	if( iei >0  )
	{
		*buffer=iei;
		encoded++;
	}
	
	ielen = snssai.len;

    *(buffer + encoded) = ielen;
    encoded++;

	bitStream = snssai.sst;
	ENCODE_U8(buffer+encoded,bitStream,encoded);

	if((ielen == SST_AND_SD_LENGHT) || (ielen == SST_AND_SD_AND_MAPPEDHPLMNSST_LENGHT) || (ielen == SST_AND_SD_AND_MAPPEDHPLMNSST_AND_MAPPEDHPLMNSD_LENGHT))
	{
		bit32Stream = snssai.sd;
		ENCODE_U8(buffer+encoded,(uint8_t)bit32Stream,encoded);
		ENCODE_U8(buffer+encoded,(uint8_t)(bit32Stream>>8),encoded);
		ENCODE_U8(buffer+encoded,(uint8_t)(bit32Stream>>16),encoded);
	}

	if((ielen == SST_AND_MAPPEDHPLMNSST_LENGHT) || (ielen == SST_AND_SD_AND_MAPPEDHPLMNSST_LENGHT) || (ielen == SST_AND_SD_AND_MAPPEDHPLMNSST_AND_MAPPEDHPLMNSD_LENGHT))
	{
		bitStream = snssai.mappedhplmnsst;
		ENCODE_U8(buffer+encoded,bitStream,encoded);
	}
	if(ielen == SST_AND_SD_AND_MAPPEDHPLMNSST_AND_MAPPEDHPLMNSD_LENGHT)
	{
		bit32Stream = snssai.mappedhplmnsd;
		ENCODE_U8(buffer+encoded,(uint8_t)bit32Stream,encoded);
		ENCODE_U8(buffer+encoded,(uint8_t)(bit32Stream>>8),encoded);
		ENCODE_U8(buffer+encoded,(uint8_t)(bit32Stream>>16),encoded);
	}
   
    return encoded;
}

int decode_snssai ( SNSSAI * snssai, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint8_t ielen=0;
	uint8_t bitStream = 0;
	uint32_t bit32Stream = 0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    ielen = *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);

	snssai->len = ielen;

	DECODE_U8(buffer+decoded,bitStream,decoded);
	snssai->sst = bitStream;

	if((ielen == SST_AND_SD_LENGHT) || (ielen == SST_AND_SD_AND_MAPPEDHPLMNSST_LENGHT) || (ielen == SST_AND_SD_AND_MAPPEDHPLMNSST_AND_MAPPEDHPLMNSD_LENGHT))
	{
		DECODE_U8(buffer+decoded,bitStream,decoded);
		bit32Stream = (uint32_t)(bitStream&0Xff);
		DECODE_U8(buffer+decoded,bitStream,decoded);
		bit32Stream |= (uint32_t)((bitStream<<8)&0xff00);
		DECODE_U8(buffer+decoded,bitStream,decoded);
		bit32Stream |= (uint32_t)((bitStream<<16)&0xff0000);
		
		snssai->sd = bit32Stream;
	}

	if((ielen == SST_AND_MAPPEDHPLMNSST_LENGHT) || (ielen == SST_AND_SD_AND_MAPPEDHPLMNSST_LENGHT) || (ielen == SST_AND_SD_AND_MAPPEDHPLMNSST_AND_MAPPEDHPLMNSD_LENGHT))
	{
		DECODE_U8(buffer+decoded,bitStream,decoded);
		snssai->mappedhplmnsst = bitStream;
	}
	if(ielen == SST_AND_SD_AND_MAPPEDHPLMNSST_AND_MAPPEDHPLMNSD_LENGHT)
	{
		DECODE_U8(buffer+decoded,bitStream,decoded);
		bit32Stream = (uint32_t)(bitStream&0Xff);
		DECODE_U8(buffer+decoded,bitStream,decoded);
		bit32Stream |= (uint32_t)((bitStream<<8)&0xff00);
		DECODE_U8(buffer+decoded,bitStream,decoded);
		bit32Stream |= (uint32_t)((bitStream<<16)&0xff0000);
		
		snssai->mappedhplmnsd = bit32Stream;
	}

	return decoded;
}

