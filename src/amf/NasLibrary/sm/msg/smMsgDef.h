#include <stdint.h>
#include <asm/byteorder.h>
typedef struct {
//#ifdef __LITTLE_ENDIAN_BITFIELD
  //uint8_t extended_protocol_discriminator:4;
  //ebi_t   eps_bearer_identity:4;//3gpp_24.007.h
//#endif
//#ifdef __BIG_ENDIAN_BITFIELD
  //ebi_t   eps_bearer_identity:4;
  //uint8_t extended_protocol_discriminator:4;
//#endif
  //pti_t procedure_transaction_identity;
  uint8_t extended_protocol_discriminator;
  uint8_t pdu_session_identity;
  uint8_t proeduer_transaction_identity;
  uint8_t message_type;
} __attribute__((__packed__)) sm_msg_header_t;

