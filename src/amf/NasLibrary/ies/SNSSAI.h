#ifndef _SNSSAI_H_
#define _SNSSAI_H_

#include <stdint.h>
#include "bstrlib.h"

#define SNSSAI_MINIMUM_LENGTH 3
#define SNSSAI_MAXIMUM_LENGTH 10

typedef enum{
	SST_LENGHT = 0b00000001,
	SST_AND_MAPPEDHPLMNSST_LENGHT = 0b00000010,
	SST_AND_SD_LENGHT = 0b00000100,
	SST_AND_SD_AND_MAPPEDHPLMNSST_LENGHT = 0b00000101,
	SST_AND_SD_AND_MAPPEDHPLMNSST_AND_MAPPEDHPLMNSD_LENGHT = 0b00001000
}length_of_snssai_contents;


typedef struct{
	length_of_snssai_contents len;
 	uint8_t sst;
	uint32_t sd:24;
	uint8_t mappedhplmnsst;
	uint32_t mappedhplmnsd;
} SNSSAI;

int encode_snssai ( SNSSAI snssai, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_snssai ( SNSSAI * snssai, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
