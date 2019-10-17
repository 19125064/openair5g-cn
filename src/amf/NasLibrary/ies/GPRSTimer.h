#ifndef _GPRSTIMER_H_
#define _GPRSTIMER_H_

#include <stdint.h>
#include "bstrlib.h"

#define GPRS_TIMER_MINIMUM_LENGTH 2
#define GPRS_TIMER_MAXIMUM_LENGTH 2

#define GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS	0b000
#define	GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_MINUTE		0b001
#define GPRSTIMER_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_DECIHOURS	0b010
#define GPRSTIMER_VALUE_INDICATES_THAT_THE_TIMER_IS_DEACTIVATED		0b111

typedef struct{
  uint8_t unit:3;
  uint8_t timeValue:5;
} GPRSTimer;


int encode_gprs_timer ( GPRSTimer gprstimer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_gprs_timer ( GPRSTimer * gprstimer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
