#include <stdint.h>
#include "bstrlib.h"

#define PDU_ADDRESS_MINIMUM_LENGTH 7
#define PDU_ADDRESS_MAXIMUM_LENGTH 15

#define PDU_ADDRESS_MINIMUM_LENGTH_TLV 7
#define PDU_ADDRESS_MAXIMUM_LENGTH_TLV 15

#define PDU_ADDRESS_IPV4	0x01
#define PDU_ADDRESS_IPV6	0x02
#define PDU_ADDRESS_IPV4V6	0x03

typedef struct{
	uint8_t pdu_session_type_value:3;
	bstring pdu_address_information;
}PDUAddress;


int encode_pdu_address ( PDUAddress pduaddress, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_pdu_address ( PDUAddress * pduaddress, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

