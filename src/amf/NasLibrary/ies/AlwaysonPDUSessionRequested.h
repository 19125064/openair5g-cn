#ifndef _ALWAYSONPDUSESSIONREQUESTED_H_
#define _ALWAYSONPDUSESSIONREQUESTED_H_

#include <stdint.h>
#include <stdbool.h>
#include "bstrlib.h"

#define ALWAYSON_PDU_SESSION_REQUESTED_MINIMUM_LENGTH 1
#define ALWAYSON_PDU_SESSION_REQUESTED_MAXIMUM_LENGTH 1

#define ALWAYSON_PDU_SESSION_NOT_REQUESTED	0
#define ALWAYSON_PDU_SESSION_REQUESTED		1

typedef struct{
	bool apsr_requested;
}AlwaysonPDUSessionRequested;


int encode_alwayson_pdu_session_requested ( AlwaysonPDUSessionRequested alwaysonpdusessionrequested, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_alwayson_pdu_session_requested ( AlwaysonPDUSessionRequested * alwaysonpdusessionrequested, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
