#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "GPRSTimer3.h"

int encode_gprs_timer3 ( GPRSTimer3 gprstimer3, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    uint8_t *lenPtr = NULL;
    uint32_t encoded = 0;
    uint8_t timeValue = 0;
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,GPRS_TIMER3_MINIMUM_LENGTH , len);

    if( iei > 0){
      *buffer=iei;
      encoded++;
    }

    lenPtr = (buffer + encoded);
    encoded++;

    timeValue = (gprstimer3.unit<<5) | gprstimer3.timeValue;
    ENCODE_U8(buffer+encoded,timeValue,encoded);

    *lenPtr = encoded - 1 - ((iei > 0) ? 1 : 0);    
    return encoded;
}

int decode_gprs_timer3 ( GPRSTimer3 * gprstimer3, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
    int decoded=0;
    uint8_t ielen=0;
    uint8_t timeValue = 0;

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }

    ielen = *(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);
    
    DECODE_U8(buffer+decoded,timeValue,decoded);
    gprstimer3->unit = (uint8_t)((timeValue&0xe0)>>5);
    gprstimer3->timeValue = (uint8_t)(timeValue&0x1f);

    return decoded;
}

