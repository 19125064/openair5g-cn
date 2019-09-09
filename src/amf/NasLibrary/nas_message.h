#include "mm_msg.h"
#include "sm_msg.h"
#include "common_types.h"



#define NAS_MESSAGE_SECURITY_HEADER_SIZE    7  //7*8bits

/*********************************************************/
/************************* 9.1 24501**********************/

/* Structure of security protected header */
typedef struct nas_message_security_header_s {
#ifdef __LITTLE_ENDIAN_BITFIELD
  extended_protocol_discriminator_t    extended_protocol_discriminator;//3gpp_24.501.h
  uint8_t                         security_header_type;
#endif
#ifdef __BIG_ENDIAN_BITFIELD
  uint8_t security_header_type;
  uint8_t extended_protocol_discriminator;
#endif
  uint32_t message_authentication_code;
  uint8_t sequence_number;
} nas_message_security_header_t;

/* Structure of plain NAS message */
typedef union {
  MM_msg mm;    /* NAS MM */
  SM_msg sm;    /* NAS SM  */
} nas_message_plain_t;


/* Structure of security protected NAS message */
typedef struct nas_message_security_protected_s {
  nas_message_security_header_t header;
  nas_message_plain_t plain;
} nas_message_security_protected_t;

/*
 * Structure of a layer 3 NAS message
 */
typedef struct {
  nas_message_security_header_t header;
  nas_message_security_protected_t security_protected;
  nas_message_plain_t plain;
} nas_message_t;

typedef struct nas_message_decode_status_s {
  uint8_t integrity_protected_message:1;
  uint8_t ciphered_message:1;
  uint8_t mac_matched:1;
  uint8_t security_context_available:1;
  int     fivegmm_cause;
} nas_message_decode_status_t;

int nas_message_encode(                   
    unsigned char              *buffer,
    const nas_message_t * const msg,
    size_t                      length,
    void                       *security);
