#ifndef __5GSMCONGESTIONREATTEMPTINDICATOR_H_
#define __5GSMCONGESTIONREATTEMPTINDICATOR_H_

#include <stdint.h>


#define _5GSM_CONGESTION_REATTEMPT_INDICATOR_MINIMUM_LENGTH 3
#define _5GSM_CONGESTION_REATTEMPT_INDICATOR_MAXIMUM_LENGTH 3

#define THE_BACKOFF_TIMER_IS_APPLIED_IN_THE_REGISTERED_PLMN	0
#define THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS			1

typedef struct{
	uint8_t abo:1;
}_5GSMCongestionReattemptIndicator;

int encode__5gsm_congestion_reattempt_indicator ( _5GSMCongestionReattemptIndicator _5gsmcongestionreattemptindicator, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__5gsm_congestion_reattempt_indicator ( _5GSMCongestionReattemptIndicator * _5gsmcongestionreattemptindicator, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;


#endif
