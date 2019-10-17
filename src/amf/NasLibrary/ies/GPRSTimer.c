#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "GPRSTimer.h"

int encode_gprs_timer ( GPRSTimer gprstimer, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint32_t encoded = 0;
	uint8_t timeValue = 0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,GPRS_TIMER_MINIMUM_LENGTH , len);
    

	if( iei > 0 )
	{
		*buffer=iei;
		encoded++;
	}

	timeValue = (gprstimer.unit<<5) | gprstimer.timeValue;
    ENCODE_U8(buffer+encoded,timeValue,encoded);

    return encoded;
}

int decode_gprs_timer ( GPRSTimer * gprstimer, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	int decoded=0;
	uint8_t timeValue = 0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

	DECODE_U8(buffer+decoded,timeValue,decoded);
    gprstimer->unit = (uint8_t)((timeValue&0xe0)>>5);
    gprstimer->timeValue = (uint8_t)(timeValue&0x1f);

	return decoded;
}

