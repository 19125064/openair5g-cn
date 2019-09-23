#include <stdint.h>
#include "bstrlib.h"

#define SMPDUDN_REQUEST_CONTAINER_MINIMUM_LENGTH 3
#define SMPDUDN_REQUEST_CONTAINER_MAXIMUM_LENGTH 255

typedef bstring SMPDUDNRequestContainer;

int encode_smpdudn_request_container ( SMPDUDNRequestContainer smpdudnrequestcontainer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_smpdudn_request_container ( SMPDUDNRequestContainer * smpdudnrequestcontainer, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

