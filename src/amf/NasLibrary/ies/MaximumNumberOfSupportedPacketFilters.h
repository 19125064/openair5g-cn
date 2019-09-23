#include <stdint.h>
#include "bstrlib.h"

#define MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS_MINIMUM_LENGTH 3
#define MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS_MAXIMUM_LENGTH 3


typedef uint16_t MaximumNumberOfSupportedPacketFilters;


int encode_maximum_number_of_supported_packet_filters ( MaximumNumberOfSupportedPacketFilters maximumnumberofsupportedpacketfilters, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_maximum_number_of_supported_packet_filters ( MaximumNumberOfSupportedPacketFilters * maximumnumberofsupportedpacketfilters, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

