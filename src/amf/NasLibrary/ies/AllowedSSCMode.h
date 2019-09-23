#include <stdint.h>
#include <stdbool.h>
#include "bstrlib.h"

#define ALLOWED_SSC_MODE_MINIMUM_LENGTH 1
#define ALLOWED_SSC_MODE_MAXIMUM_LENGTH 1

#define SSC_MODE1_NOT_ALLOWED	0
#define SSC_MODE1_ALLOWED		1
#define SSC_MODE2_NOT_ALLOWED	0
#define SSC_MODE2_ALLOWED		1
#define SSC_MODE3_NOT_ALLOWED	0
#define SSC_MODE3_ALLOWED		1

//typedef bstring AllowedSSCMode;
typedef struct{
	bool is_ssc1_allowed;
	bool is_ssc2_allowed;
	bool is_ssc3_allowed;
}AllowedSSCMode;


int encode_allowed_ssc_mode ( AllowedSSCMode allowedsscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_allowed_ssc_mode ( AllowedSSCMode * allowedsscmode, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

