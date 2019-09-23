#ifndef _SSCMODE_H_
#define _SSCMODE_H_

#include <stdint.h>
#include "bstrlib.h"

#define SSC_MODE_MINIMUM_LENGTH 1
#define SSC_MODE_MAXIMUM_LENGTH 1


typedef struct{
  uint8_t ssc_mode_value:3;
}SSCMode;


int encode_ssc_mode ( SSCMode sscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_ssc_mode ( SSCMode * sscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
