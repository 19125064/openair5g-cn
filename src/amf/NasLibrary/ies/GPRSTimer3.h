#ifndef _GPRS_TIMER3_H_
#define _GPRS_TIMER3_H_

#include <stdint.h>
#include "bstrlib.h"

#define GPRS_TIMER3_MINIMUM_LENGTH 3
#define GPRS_TIMER3_MAXIMUM_LENGTH 3

#define VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_10_MINUTES 0b000
#define VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR 	0b001
#define VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_10_HOURS 	0b010
#define VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS 	0b011
#define VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_30_SECONDS 0b100
#define VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_MINUTE 	0b101
#define VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_320_HOURS 	0b110
#define VALUE_INDICATES_THAT_THE_TIMER_IS_DEACTIVATED 	0b111

typedef struct{
  uint8_t unit:3;
  uint8_t timeValue:5;
} GPRSTimer3;

int encode_gprs_timer3 ( GPRSTimer3 gprstimer3, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_gprs_timer3 ( GPRSTimer3 * gprstimer3, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;


#endif
