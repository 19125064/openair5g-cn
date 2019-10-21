#ifndef _DNN_H_
#define _DNN_H_

#include <stdint.h>
#include "bstrlib.h"

#define DNN_MINIMUM_LENGTH 3
#define DNN_MAXIMUM_LENGTH 102


#define DNN_MINIMUM_LENGTH_TLV 3
#define DNN_MAXIMUM_LENGTH_TLV 102

typedef bstring DNN;

int encode_dnn ( DNN dnn, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_dnn ( DNN * dnn, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
