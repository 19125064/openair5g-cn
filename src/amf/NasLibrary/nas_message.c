#include "common_types.h"
#include "nas_message.h"
#include "log.h"
#include "gcc_diag.h"

#include "TLVDecoder.h"
#include "TLVEncoder.h"

#include <stdlib.h>             
#include <string.h>             

//#include "nas_itti_messaging.h"
#include "secu_defs.h"
#include "mmData.h"
#include "dynamic_memory_check.h"



/****************************************************************************/
/*******************  L O C A L    D E F I N I T I O N S  *******************/
/****************************************************************************/
#define SR_MAC_SIZE_BYTES 2

/* Functions used to decode layer 3 NAS messages */
static int _nas_message_header_decode (
    const unsigned char * const buffer,
    nas_message_security_header_t * const header,
    const size_t length,
    nas_message_decode_status_t * const status,
    bool * const is_sr);

static int _nas_message_plain_decode (
    const unsigned char *buffer,
    const nas_message_security_header_t * header,
    nas_message_plain_t * msg,
    size_t length);

static int _nas_message_protected_decode (
    unsigned char * const buffer,
    nas_message_security_header_t * header,
    nas_message_plain_t * msg,
    size_t length,
    fivegmm_security_context_t * const fivegmm_security_context,
    nas_message_decode_status_t * status);

/* Functions used to encode layer 3 NAS messages */
static int _nas_message_header_encode (
    unsigned char *buffer,
    const nas_message_security_header_t * header,
    size_t length);

static int _nas_message_plain_encode (
    unsigned char *buffer,
    const nas_message_security_header_t * header,
    const nas_message_plain_t * msg,
    size_t length);

static int _nas_message_protected_encode (
    unsigned char *buffer,
    const nas_message_security_protected_t * msg,
    size_t length,
    void *security);

/* Functions used to decrypt and encrypt layer 3 NAS messages */
static int _nas_message_decrypt (
    unsigned char * const dest,
    unsigned char * const src,
    uint8_t type,
    uint32_t code,
    uint8_t seq,
    size_t length,
    fivegmm_security_context_t * const fivegmm_security_context,
    nas_message_decode_status_t * status);

static int _nas_message_encrypt (
    unsigned char *dest,
    const unsigned char *src,
    uint8_t type,
    uint32_t code,
    uint8_t seq,
    int const direction,
    size_t length,
    fivegmm_security_context_t * const fivegmm_security_context);

/* Functions used for integrity protection of layer 3 NAS messages */
static uint32_t _nas_message_get_mac (
    const unsigned char *const buffer,
    size_t const length,
    int const direction,
    fivegmm_security_context_t * const fivegmm_security_context);




/****************************************************************************
 **                                                                        **
 ** Name:  nas_message_encode()                                      **
 **                                                                        **
 ** Description: Encode layer 3 NAS message                                **
 **                                                                        **
 ** Inputs   msg:   L3 NAS message structure to encode         **
 **    length:  Maximal capacity of the output buffer      **
 **    Others:  None                                       **
 **                                                                        **
 ** Outputs:   buffer:  Pointer to the encoded data buffer         **
 **      Return:  The number of bytes in the buffer if the   **
 **       data have been successfully encoded;       **
 **       A negative error code otherwise.           **
 **    Others:  None                                       **
 **                                                                        **
 ***************************************************************************/
int nas_message_encode (
    unsigned char *buffer,
    const nas_message_t * const msg,
    size_t length,
    void *security)
{
  OAILOG_FUNC_IN (LOG_NAS);
  fivegmm_security_context_t                 *fivegmm_security_context = (fivegmm_security_context_t *) security;
  int                                     bytes;

  /*
   * Encode the header
   */
  int                                     size = _nas_message_header_encode (buffer, &msg->header, length);
  //printf("_nas_message_header_encode, size:%d\n", size);
  if (size < 0) {
    OAILOG_FUNC_RETURN (LOG_NAS, TLV_BUFFER_TOO_SHORT);
  } else if (size > 2) {
    /*
     * Encode security protected NAS message
     */
    bytes = _nas_message_protected_encode (buffer + size, &msg->security_protected, length - size, fivegmm_security_context);
    
	#if 0
	for(i=0;i<11;i++)
      printf("after _nas_message_protected_encode : nas msg byte test bype[%d] = 0x%x\n",i,buffer[i]);
      printf("encode protected nas msg header 1.2.2\n");
	#endif
	
    /*
     * Integrity protect the NAS message
     */
    if (bytes > 0) {
      /*
       * Compute offset of the sequence number field
       */
      int                                     offset = size - sizeof (uint8_t);

      /*
       * Compute the NAS message authentication code
       */
      OAILOG_DEBUG (LOG_NAS, "offset %d = %d - %lu, hdr encode = %d, length = %lu bytes = %d\n", offset, size, sizeof (uint8_t), size, length, bytes);
      uint32_t                                mac = _nas_message_get_mac (buffer + offset,
                                                                          bytes + size - offset,
                                                                          SECU_DIRECTION_DOWNLINK,
                                                                          fivegmm_security_context);
      /*
       * Set the message authentication code of the NAS message
       */

      *(uint32_t *) (buffer + 2*sizeof (uint8_t)) = htonl (mac);
      if (fivegmm_security_context) {
        fivegmm_security_context->dl_count.seq_num += 1;

        if (!fivegmm_security_context->dl_count.seq_num) {
          fivegmm_security_context->dl_count.overflow += 1;
        }

        OAILOG_DEBUG (LOG_NAS, "Incremented fivegmm_security_context.dl_count.seq_num -> %u\n", fivegmm_security_context->dl_count.seq_num);
      } else {
        OAILOG_DEBUG (LOG_NAS, "Did not increment fivegmm_security_context.dl_count.seq_num because no security context\n");
      }
    }
    /*
     * Log message header
     */

  } else {
    /*
     * Encode plain NAS message
     */
    bytes = _nas_message_plain_encode (buffer, &msg->header, &msg->plain, length);
  }

  if (bytes < 0) {
    OAILOG_FUNC_RETURN (LOG_NAS, bytes);
  }

  if (size > 1) {
    OAILOG_FUNC_RETURN (LOG_NAS, size + bytes);
  }
 
  OAILOG_FUNC_RETURN (LOG_NAS, bytes);
}





int nas_message_decode (
    const unsigned char *const buffer,
    nas_message_t * msg,
    size_t length,
    void *security,
    nas_message_decode_status_t * status)
{
  OAILOG_FUNC_IN (LOG_NAS);
  fivegmm_security_context_t                 *fivegmm_security_context = (fivegmm_security_context_t *) security;
  int                                     bytes = 0;
  uint32_t                                mac   = 0;
  uint16_t                                short_mac  = 0;
  int                                     size  = 0;
  bool                                    is_sr = false;
  uint8_t                                 sequence_number = 0;
  uint8_t                                 temp_sequence_number = 0;
  /*
   * Decode the header
   */
  OAILOG_STREAM_HEX(OAILOG_LEVEL_DEBUG, LOG_NAS, "Incoming NAS message: ", buffer, length)
  if (fivegmm_security_context) {
    status->security_context_available = 1;
  }
  //printf("calling _nas_message_header_decode , length:%d\n", length);
  size  = _nas_message_header_decode (buffer, &msg->header, length, status, &is_sr);
  OAILOG_DEBUG (LOG_NAS, "_nas_message_header_decode returned size %d\n", size);

  if (size < 0) {
    OAILOG_FUNC_RETURN (LOG_NAS, TLV_BUFFER_TOO_SHORT);
  }
  if (size > 2) {
    // found security header
    /*
     * Compute offset of the sequence number field
     */
    int offset = size - sizeof (uint8_t);
    if (fivegmm_security_context) {
      status->security_context_available = 1;
      if (fivegmm_security_context->ul_count.seq_num > msg->header.sequence_number) {
        fivegmm_security_context->ul_count.overflow += 1;
      }
      fivegmm_security_context->ul_count.seq_num = msg->header.sequence_number;
      /*
       * Compute the NAS message authentication code, return 0 if no security context
       */
      mac = _nas_message_get_mac (buffer + offset,
          length - offset,
          SECU_DIRECTION_UPLINK,
          fivegmm_security_context);
      /*
       * Check NAS message integrity
       */
      if (mac == msg->header.message_authentication_code) {
        printf("mac_matched!!!!!!!!!!!!!!!!!!!\n");
        status->mac_matched = 1;
      } else {
        OAILOG_DEBUG (LOG_NAS, "msg->header.message_authentication_code = %04X != computed = %04X\n", msg->header.message_authentication_code, mac);
      }
    }

    /*
     * Decode security protected NAS message
     */
    bytes = _nas_message_protected_decode ((unsigned char *const)(buffer + size), &msg->header, &msg->plain, length - size, fivegmm_security_context, status);
  } else {
    /*
     * Decode plain NAS message
     */
    bytes = _nas_message_plain_decode (buffer, &msg->header, &msg->plain, length);
  }

  if (bytes < 0)  {
    OAILOG_FUNC_RETURN (LOG_NAS, bytes);
  }

  if (size > 1) {
    
    OAILOG_FUNC_RETURN (LOG_NAS, size + bytes);
  }
  OAILOG_FUNC_RETURN (LOG_NAS, bytes);
}



/****************************************************************************/
/*********************  L O C A L    F U N C T I O N S  *********************/
/****************************************************************************/

/****************************************************************************
 **                                                                        **
 ** Name:  _nas_message_header_encode()                              **
 **                                                                        **
 ** Description: Encode header of a security protected NAS message         **
 **                                                                        **
 ** Inputs   header:  Security header structure to encode        **
 **    length:  Maximal capacity of the output buffer      **
 **    Others:  None                                       **
 **                                                                        **
 ** Outputs:   buffer:  Pointer to the encoded data buffer         **
 **      Return:  The number of bytes in the buffer if the   **
 **       data have been successfully encoded;       **
 **       1, if the header is not a security header  **
 **       (header of plain NAS message);             **
 **       -1 otherwise.                              **
 **    Others:  None                                       **
 **                                                                        **
 ***************************************************************************/
static int _nas_message_header_encode (
    unsigned char *buffer,
    const nas_message_security_header_t * header,
    size_t length)
{
  //OAILOG_FUNC_IN (LOG_NAS);
  int                                     size = 0;

  /*
   * Encode the first octet of the header (security header type or EPS bearer
   * * * * identity, and protocol discriminator)
   */
  //ENCODE_U8 (buffer, *(uint8_t *) (header), size);
  ENCODE_U8 (buffer,header->extended_protocol_discriminator,size);
  //printf("extended_protocol_discriminator size = %d\n",size);
  //uint8_t decoded_protocol = 0,decoded_size = 0;
  //DECODE_U8(buffer,decoded_protocol,decoded_size);
  //printf("encoded nas header protocol(decode): %x\n",decoded_protocol);
  //printf("encoded nas header protocol: %x\n",*buffer);
  //printf("encoded nas header protocol: %x\n",header->extended_protocol_discriminator);
  
  ENCODE_U8 (buffer+size,header->security_header_type,size);
  
  //printf("security_header_type size = %d\n",size);
  //printf("encoded nas security header type: %x\n",buffer[size-1]);
  //printf("encoded nas security header type: %x\n",header->security_header_type);

  if (header->extended_protocol_discriminator == FIVEGS_MOBILITY_MANAGEMENT_MESSAGES || 
  	  header->extended_protocol_discriminator == FIVEGS_SESSION_MANAGEMENT_MESSAGES) {
    //printf("header->extended_protocol_discriminator == FIVEGS_MOBILITY_MANAGEMENT_MESSAGES\n");
    //printf("%x\n",header->security_header_type);
    if (header->security_header_type != SECURITY_HEADER_TYPE_NOT_PROTECTED) {
      //printf("header->security_header_type != SECURITY_HEADER_TYPE_NOT_PROTECTED\n");
      if (length < NAS_MESSAGE_SECURITY_HEADER_SIZE) {
        /*
         * The buffer is not big enough to contain security header
         */
        //OAILOG_WARNING(LOG_NAS, "NET-API   - The size of the header (%u) " "exceeds the buffer length (%lu)\n", NAS_MESSAGE_SECURITY_HEADER_SIZE, length);
        //OAILOG_FUNC_RETURN (LOG_NAS, RETURNerror);
      }

      /*
       * Encode the message authentication code
       */
	  ENCODE_U32 (buffer + size, header->message_authentication_code, size);
	  /*
       * Encode the sequence number
       */
      ENCODE_U8 (buffer + size, header->sequence_number, size);
    }
  }
  return size;
  //OAILOG_STREAM_HEX(OAILOG_LEVEL_DEBUG, LOG_NAS, "encode nas header Incoming NAS message: ", buffer, size)
  //OAILOG_FUNC_RETURN (LOG_NAS, size);
}

/****************************************************************************
 **                                                                        **
 ** Name:  _nas_message_protected_encode()                               **
 **                                                                        **
 ** Description: Encode security protected NAS message                     **
 **                                                                        **
 ** Inputs    msg:     Security protected NAS message structure            **
 **                    to encode                                           **
 **           length:  Maximal capacity of the output buffer               **
 **           Others:  None                                                **
 **                                                                        **
 ** Outputs:  buffer:  Pointer to the encoded data buffer                  **
 ** Return:   The number of bytes in the buffer if the                     **
 **           data have been successfully encoded;                         **
 **           A negative error code otherwise.                             **
 ** Others:   None                                                         **
 **                                                                        **
 ***************************************************************************/
static int _nas_message_protected_encode (
    unsigned char *buffer,
    const nas_message_security_protected_t * msg,
    size_t length,
    void *security)
{
  //OAILOG_FUNC_IN (LOG_NAS);
  fivegmm_security_context_t                 *fivegmm_security_context = (fivegmm_security_context_t *) security;
  int                                     bytes = TLV_BUFFER_TOO_SHORT;
  unsigned char                          *plain_msg = (unsigned char *)calloc (1, length);
  //printf("_nas_message_protected_encode(security header type:%x)\n",buffer[0]);
  if (plain_msg) {
    /*
     * Encode the security protected NAS message as plain NAS message
     */
    //printf("encode security protected NAS message as plain message 1.2.1.1\n");
    int                                     size = _nas_message_plain_encode (plain_msg, &msg->header,
                                                                             &msg->plain, length);

    //printf("_nas_message_plain_encode bytes:%d\n", size);
	//printf("encode security protected NAS message as plain message 1.2.1.2\n");

    if (size > 0) {
      /*
       * Encrypt the encoded plain NAS message
       */
      #if 0
      printf("_nas_message_encrypt(size=%d)\n",size);
      printf("msg->header.security_header_type(0x%x)\n",msg->header.security_header_type);
      printf("msg->header.message_authentication_code size(0x%d)\n",sizeof(msg->header.message_authentication_code));
      printf("msg->header.message_authentication_code(0x%x)\n",msg->header.message_authentication_code);
      printf("msg->header.sequence_number(0x%x)\n",msg->header.sequence_number);
      #endif
	  bytes = _nas_message_encrypt (buffer, plain_msg, msg->header.security_header_type, msg->header.message_authentication_code, msg->header.sequence_number,
                                    SECU_DIRECTION_DOWNLINK,
                                    size, fivegmm_security_context);
     //printf("_nas_message_encrypt, bytes: %d\n",bytes);
    }

    free_wrapper ((void**) &plain_msg);
  }
  return bytes;
  //OAILOG_FUNC_RETURN (LOG_NAS, bytes);
}

/****************************************************************************
 **                                                                        **
 ** Name:  _nas_message_plain_encode()                               **
 **                                                                        **
 ** Description: Encode plain NAS message                                  **
 **                                                                        **
 ** Inputs:  pd:    Protocol discriminator of the NAS message  **
 **       to encode                                  **
 **      msg:   Plain NAS message structure to encode      **
 **    length:  Maximal capacity of the output buffer      **
 **    Others:  None                                       **
 **                                                                        **
 ** Outputs:   buffer:  Pointer to the encoded data buffer         **
 **      Return:  The number of bytes in the buffer if the   **
 **       data have been successfully encoded;       **
 **       A negative error code otherwise.           **
 **    Others:  None                                       **
 **                                                                        **
 ***************************************************************************/
static int _nas_message_plain_encode (
    unsigned char *buffer,
    const nas_message_security_header_t * header,
    const nas_message_plain_t * msg,
    size_t length)
{
  //OAILOG_FUNC_IN (LOG_NAS);
  int                                     bytes = TLV_PROTOCOL_NOT_SUPPORTED;

  if (header->extended_protocol_discriminator == FIVEGS_MOBILITY_MANAGEMENT_MESSAGES) {
    /*
     * Encode EPS Mobility Management L3 message
     */
    //printf("Encode EPS Mobility Management L3 message 1.2.1.1.1\n");
    bytes = fivegmm_msg_encode ((MM_msg *) (&msg->mm), (uint8_t *) buffer, length);
	//printf("fivegmm_msg_encode bytes:%d\n", bytes);
    //printf("Encode EPS Mobility Management L3 message 1.2.1.1.2\n");
  } else if (header->extended_protocol_discriminator == FIVEGS_SESSION_MANAGEMENT_MESSAGES) {
    /*
     * Encode EPS Session Management L3 message
     */
    bytes = fivegsm_msg_encode ((SM_msg *) (&msg->sm), (uint8_t *) buffer, length);
  } else {
    /*
     * Discard L3 messages with not supported protocol discriminator
     */
    //OAILOG_WARNING(LOG_NAS, "NET-API   - Extended Protocol discriminator 0x%x is " "not supported\n", header->extended_protocol_discriminator);
  }
  return bytes;
  //OAILOG_FUNC_RETURN (LOG_NAS, bytes);
}


/****************************************************************************
 **                                                                        **
 ** Name:  _nas_message_encrypt()                                    **
 **                                                                        **
 ** Description: Encrypt plain NAS message                                 **
 **                                                                        **
 ** Inputs   src:   Pointer to the decrypted data buffer       **
 **    security_header_type:    The security header type                   **
 **    code:    The message authentication code            **
 **    seq:   The sequence number                        **
 **    direction: The sequence number                        **
 **    length:  Maximal capacity of the output buffer      **
 **    Others:  None                                       **
 **                                                                        **
 ** Outputs:   dest:    Pointer to the encrypted data buffer       **
 **      Return:  The number of bytes in the output buffer   **
 **       if data have been successfully encrypted;  **
 **       RETURNerror otherwise.                     **
 **    Others:  None                                       **
 **                                                                        **
 ***************************************************************************/
static int _nas_message_encrypt (
    unsigned char *dest,
    const unsigned char *src,
    uint8_t security_header_type,
    uint32_t code,
    uint8_t seq,
    int const direction,
    size_t length,
    fivegmm_security_context_t * const fivegmm_security_context)
{
  nas_stream_cipher_t                     stream_cipher = {0};
  uint32_t                                count = 0;

  //OAILOG_FUNC_IN (LOG_NAS);

  if (!fivegmm_security_context) {
    //OAILOG_ERROR(LOG_NAS, "No security context set for encryption protection algorithm\n");
    //OAILOG_FUNC_RETURN (LOG_NAS, 0);
  }
  switch (security_header_type) {
    case SECURITY_HEADER_TYPE_NOT_PROTECTED:
    case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED:
    case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_NEW:
      //OAILOG_DEBUG (LOG_NAS, "No encryption of message according to security header type 0x%02x\n", security_header_type);
      memcpy (dest, src, length);
      //OAILOG_FUNC_RETURN (LOG_NAS, length);
      break;
    case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED:
    case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED_NEW:
      //printf("SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED or SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED_NEW\n");
      switch (fivegmm_security_context->selected_algorithms.encryption) {
        case NAS_SECURITY_ALGORITHMS_NEA1:{
        //printf("NAS_SECURITY_ALGORITHMS_NEA1\n");
        if (direction == SECU_DIRECTION_UPLINK) {
          count = 0x00000000 | ((fivegmm_security_context->ul_count.overflow && 0x0000FFFF) << 8) | (fivegmm_security_context->ul_count.seq_num & 0x000000FF);
        } else {
          //printf("fivegmm_security_context->dl_count.overflow = %x\n",((fivegmm_security_context->dl_count.overflow & 0x0000FFFF) ));
          //printf("fivegmm_security_context->dl_count.seq_num = %x\n",fivegmm_security_context->dl_count.seq_num);
          count = 0x00000000 | ((fivegmm_security_context->dl_count.overflow & 0x0000FFFF) << 8) | (fivegmm_security_context->dl_count.seq_num & 0x000000FF);
        }
        //printf("count = %x\n",count);
        //OAILOG_DEBUG (LOG_NAS,
        //           "NAS_SECURITY_ALGORITHMS_EEA1 dir %s count.seq_num %u count %u\n",
        //           (direction == SECU_DIRECTION_UPLINK) ? "UPLINK" : "DOWNLINK", (direction == SECU_DIRECTION_UPLINK) ? fivegmm_security_context->ul_count.seq_num : fivegmm_security_context->dl_count.seq_num, count);
        //stream_cipher.key = fivegmm_security_context->knas_enc;
        //stream_cipher.key_length = AUTH_KNAS_ENC_SIZE;
        //stream_cipher.count = count;
        //stream_cipher.bearer = 0x00;    //33.401 section 8.1.1
        //stream_cipher.direction = direction;
        //stream_cipher.message = (uint8_t*)src;
        /*
         * length in bits
         */
        //stream_cipher.blength = length << 3;
        //nas_stream_encrypt_nea1 (&stream_cipher, (uint8_t*)dest);
        //OAILOG_FUNC_RETURN (LOG_NAS, length);
        memcpy (dest, src, length);
        return length;
          }
          break;
        case NAS_SECURITY_ALGORITHMS_NEA2:{
        if (direction == SECU_DIRECTION_UPLINK) {
          count = 0x00000000 | ((fivegmm_security_context->ul_count.overflow & 0x0000FFFF) << 8) | (fivegmm_security_context->ul_count.seq_num & 0x000000FF);
        } else {
          count = 0x00000000 | ((fivegmm_security_context->dl_count.overflow & 0x0000FFFF) << 8) | (fivegmm_security_context->dl_count.seq_num & 0x000000FF);
        }

        OAILOG_DEBUG (LOG_NAS,
                   "NAS_SECURITY_ALGORITHMS_EEA2 dir %s count.seq_num %u count %u\n",
                   (direction == SECU_DIRECTION_UPLINK) ? "UPLINK" : "DOWNLINK", (direction == SECU_DIRECTION_UPLINK) ? fivegmm_security_context->ul_count.seq_num : fivegmm_security_context->dl_count.seq_num, count);
        stream_cipher.key = fivegmm_security_context->knas_enc;
        stream_cipher.key_length = AUTH_KNAS_ENC_SIZE;
        stream_cipher.count = count;
        stream_cipher.bearer = 0x00;    
        stream_cipher.direction = direction;
        stream_cipher.message = (uint8_t*)src;
        /*
         * length in bits
         */
        stream_cipher.blength = length << 3;
        //nas_stream_encrypt_nea2 (&stream_cipher, (uint8_t*)dest);
        OAILOG_FUNC_RETURN (LOG_NAS, length);
          }
          break;
        case NAS_SECURITY_ALGORITHMS_NEA0:{
          OAILOG_DEBUG (LOG_NAS, "NAS_SECURITY_ALGORITHMS_EEA0 dir %d ul_count.seq_num %d dl_count.seq_num %d\n", direction, fivegmm_security_context->ul_count.seq_num, fivegmm_security_context->dl_count.seq_num);
          memcpy (dest, src, length);
          OAILOG_FUNC_RETURN (LOG_NAS, length);
          }
          break;
        default:{
          OAILOG_ERROR(LOG_NAS, "Unknown Cyphering protection algorithm %d\n", fivegmm_security_context->selected_algorithms.encryption);
          }
          break;
      }
      break;
   default:{
     OAILOG_ERROR(LOG_NAS, "Unknown security header type %u\n", security_header_type);
     OAILOG_FUNC_RETURN (LOG_NAS, 0);
     } 
     break;
  }
  OAILOG_FUNC_RETURN (LOG_NAS, length);
}


/****************************************************************************
 **                                                                        **
 ** Name:  _nas_message_get_mac()                                        **
 **                                                                        **
 ** Description: Run integrity algorithm onto cyphered or uncyphered NAS   **
 **    message encoded in the input buffer and return the compu-         **
 **    ted message authentication code                                   **
 **                                                                        **
 ** Inputs   buffer:  Pointer to the integrity protected data            **
 **       buffer                                                     **
 **    count:   Value of the uplink NAS counter                        **
 **    length:  Length of the input buffer                             **
 **      direction                                                         **
 **    Others:  None                                                   **
 **                                                                        **
 ** Outputs:   None                                                      **
 **      Return:  The message authentication code                    **
 **    Others:  None                                                   **
 **                                                                        **
 ***************************************************************************/
static uint32_t _nas_message_get_mac (
    const unsigned char *const buffer,
    size_t const length,
    int const direction,
    fivegmm_security_context_t * const fivegmm_security_context)
{
  //OAILOG_FUNC_IN (LOG_NAS);

  if (!fivegmm_security_context) {
    //OAILOG_DEBUG (LOG_NAS, "No security context set for integrity protection algorithm\n");
    //OAILOG_FUNC_RETURN (LOG_NAS, 0);
  }

  switch (fivegmm_security_context->selected_algorithms.integrity) {
    case NAS_SECURITY_ALGORITHMS_NIA1:{
      //printf("NAS_SECURITY_ALGORITHMS_NIA1\n");
      uint8_t                                 mac[4];
      nas_stream_cipher_t                     stream_cipher;
      uint32_t                                count;
      uint32_t                               *mac32;
      
      if (direction == SECU_DIRECTION_UPLINK) {
        count = 0x00000000 | ((fivegmm_security_context->ul_count.overflow & 0x0000FFFF) << 8) | (fivegmm_security_context->ul_count.seq_num & 0x000000FF);
      } else {
        count = 0x00000000 | ((fivegmm_security_context->dl_count.overflow & 0x0000FFFF) << 8) | (fivegmm_security_context->dl_count.seq_num & 0x000000FF);
      }
      
      //OAILOG_DEBUG (LOG_NAS,
      //           "NAS_SECURITY_ALGORITHMS_EIA1 dir %s count.seq_num %u count %u\n",
      //           (direction == SECU_DIRECTION_UPLINK) ? "UPLINK" : "DOWNLINK",
      //           (direction == SECU_DIRECTION_UPLINK) ? fivegmm_security_context->ul_count.seq_num : fivegmm_security_context->dl_count.seq_num, count);
      stream_cipher.key = fivegmm_security_context->knas_int;
      stream_cipher.key_length = AUTH_KNAS_INT_SIZE;
      stream_cipher.count = count;      
      stream_cipher.bearer = 0x00;      //33.401 section 8.1.1
      stream_cipher.direction = direction;
      stream_cipher.message = (uint8_t*)buffer;
      /*
       * length in bits
       */
      stream_cipher.blength = length << 3;
      nas_stream_encrypt_nia1 (&stream_cipher, mac);
      //OAILOG_DEBUG (LOG_NAS, "NAS_SECURITY_ALGORITHMS_EIA1 returned MAC %x.%x.%x.%x(%u) for length %lu direction %d, count %d\n",
      //    mac[0], mac[1], mac[2], mac[3], *((uint32_t *) & mac), length, direction, count);
      mac32 = (uint32_t *) & mac;
      //OAILOG_FUNC_RETURN (LOG_NAS, ntohl (*mac32));
      return ntohl (*mac32);
      }
      break;
    case NAS_SECURITY_ALGORITHMS_NIA2:{
      uint8_t                                 mac[4];
      nas_stream_cipher_t                     stream_cipher;
      uint32_t                                count;
      uint32_t                               *mac32;

      if (direction == SECU_DIRECTION_UPLINK) {
        count = 0x00000000 | ((fivegmm_security_context->ul_count.overflow & 0x0000FFFF) << 8) |
            (fivegmm_security_context->ul_count.seq_num & 0x000000FF);
      } else {
        count = 0x00000000 | ((fivegmm_security_context->dl_count.overflow & 0x0000FFFF) << 8) |
            (fivegmm_security_context->dl_count.seq_num & 0x000000FF);
      }

      OAILOG_DEBUG (LOG_NAS,
                 "NAS_SECURITY_ALGORITHMS_EIA2 dir %s count.seq_num %u count %u\n",
                 (direction == SECU_DIRECTION_UPLINK) ? "UPLINK" : "DOWNLINK", (direction == SECU_DIRECTION_UPLINK) ? fivegmm_security_context->ul_count.seq_num : fivegmm_security_context->dl_count.seq_num, count);
      stream_cipher.key = fivegmm_security_context->knas_int;
      stream_cipher.key_length = AUTH_KNAS_INT_SIZE;
      stream_cipher.count = count;
      stream_cipher.bearer = 0x00;      
      stream_cipher.direction = direction;
      stream_cipher.message = (uint8_t*)buffer;
      /*
       * length in bits
       */
      stream_cipher.blength = length << 3;
      //nas_stream_encrypt_nia2 (&stream_cipher, mac);
      OAILOG_DEBUG (LOG_NAS, "NAS_SECURITY_ALGORITHMS_EIA2 returned MAC %x.%x.%x.%x(%u) for length %lu direction %d, count %d\n",
          mac[0], mac[1], mac[2], mac[3], *((uint32_t *) & mac), length, direction, count);
      mac32 = (uint32_t *) & mac;
      OAILOG_FUNC_RETURN (LOG_NAS, ntohl (*mac32));
      }
      break;
    case NAS_SECURITY_ALGORITHMS_NIA0:{
      OAILOG_DEBUG (LOG_NAS,
               "NAS_SECURITY_ALGORITHMS_EIA0 dir %s count.seq_num %u\n",
               (direction == SECU_DIRECTION_UPLINK) ? "UPLINK" : "DOWNLINK", (direction == SECU_DIRECTION_UPLINK) ? fivegmm_security_context->ul_count.seq_num : fivegmm_security_context->dl_count.seq_num);
      OAILOG_FUNC_RETURN (LOG_NAS, 0);
      }
      break;
    default:
      OAILOG_ERROR(LOG_NAS, "Unknown integrity protection algorithm %d\n", fivegmm_security_context->selected_algorithms.integrity);
      break;
  }
  OAILOG_FUNC_RETURN (LOG_NAS, 0);
}



static int _nas_message_header_decode (
    const unsigned char * const buffer,
    nas_message_security_header_t * const header,
    const size_t length,
    nas_message_decode_status_t * const status,
    bool * const is_sr)
{
  OAILOG_FUNC_IN (LOG_NAS);
  int                                     size = 0;

  /*
   * Decode the first octet of the header 
   */
  DECODE_U8 (buffer, header->extended_protocol_discriminator , size);
  DECODE_U8 (buffer + size, header->security_header_type , size);
  OAILOG_DEBUG(LOG_NAS,"security header type(%x)\n",header->security_header_type&0x0f);
  *is_sr = false;
  if (header->extended_protocol_discriminator == FIVEGS_MOBILITY_MANAGEMENT_MESSAGES ||
  	  header->extended_protocol_discriminator == FIVEGS_SESSION_MANAGEMENT_MESSAGES) {
    if (header->security_header_type != SECURITY_HEADER_TYPE_NOT_PROTECTED) {
      if (status) {
        switch (header->security_header_type) {
          case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED:
          case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_NEW:
            status->integrity_protected_message = 1;
            break;
          case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED:
          case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED_NEW:
            status->integrity_protected_message = 1;
            status->ciphered_message   = 1;
            break;
/*
          case SECURITY_HEADER_TYPE_SERVICE_REQUEST:
            *is_sr = true;
            status->integrity_protected_message = 1;
            OAILOG_FUNC_RETURN (LOG_NAS, size);
            break;
*/
          default:;
        } 
      } 
      if (*is_sr == false)
      {
        if (length < NAS_MESSAGE_SECURITY_HEADER_SIZE) {
        /* 
         * The buffer is not big enough to contain security header
         */
         //OAILOG_WARNING(LOG_NAS, "NET-API   - The size of the header (%u) " "exceeds the buffer length (%lu)\n", NAS_MESSAGE_SECURITY_HEADER_SIZE, length);
         //OAILOG_FUNC_RETURN (LOG_NAS, RETURNerror);
        }
        // Decode the message authentication code
        DECODE_U32 (buffer + size, header->message_authentication_code, size);
        // Decode the sequence number
        DECODE_U8 (buffer + size, header->sequence_number, size);

		#if 0
		printf("decode size:%d, message_authentication_code:0x%x,sequence_number:0x%x\n",
		size,header->message_authentication_code,
		header->sequence_number);
		#endif
		
      } 
    } 
  } 
  //OAILOG_FUNC_RETURN (LOG_NAS, size);
  return size;
}


static int _nas_message_protected_decode (
    unsigned char * const buffer,
    nas_message_security_header_t * header,
    nas_message_plain_t * msg,
    size_t length,
    fivegmm_security_context_t * const fivegmm_security_context,
    nas_message_decode_status_t * const status)
{
  //OAILOG_FUNC_IN (LOG_NAS);
  int                                     bytes = TLV_BUFFER_TOO_SHORT;
  unsigned char                    *const plain_msg = (unsigned char *)calloc (1, length);

  if (plain_msg) {
    /*
     * Decrypt the security protected NAS message
     */
    //printf("_nas_message_decrypt  ------- start\n");
    //header->extended_protocol_discriminator = _nas_message_decrypt (
    int rc = _nas_message_decrypt (
        plain_msg,
        buffer,
        header->security_header_type,
        header->message_authentication_code,
        header->sequence_number,
        length, fivegmm_security_context,
        status);
	 //printf("_nas_message_decrypt  ------- end\n");
    /*
     * Decode the decrypted message as plain NAS message
     */
    //printf("calling _nas_message_plain_decode\n");
    bytes = _nas_message_plain_decode (plain_msg, header, msg, length);
	//printf("_nas_message_plain_decode bytes:%d\n", bytes);
    free_wrapper ((void**) &plain_msg);
  }
  return bytes;
  //OAILOG_FUNC_RETURN (LOG_NAS, bytes);
}

static int _nas_message_decrypt (
    unsigned char * const dest,
    unsigned char * const src,
    uint8_t security_header_type,
    uint32_t code,
    uint8_t seq,
    size_t length,
    fivegmm_security_context_t * const fivegmm_security_context,
    nas_message_decode_status_t * status)
{
  nas_stream_cipher_t                     stream_cipher = {0};
  uint32_t                                count = 0;
  uint8_t                                 direction = 0;

  //OAILOG_FUNC_IN (LOG_NAS);
  int                                     size = 0;
  nas_message_security_header_t           header = {0};

  direction = SECU_DIRECTION_UPLINK;

  switch (security_header_type) {
  case SECURITY_HEADER_TYPE_NOT_PROTECTED:
  case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED:
  case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_NEW:
    OAILOG_DEBUG (LOG_NAS, "No decryption of message length %lu according to security header type 0x%02x\n", length, security_header_type);
    memcpy (dest, src, length);
    //DECODE_U8 (dest, *(uint8_t *) (&header), size);
    //DECODE_U8(dest,header.extended_protocol_discriminator,size);
    //DECODE_U8(dest+size,header.security_header_type,size);
    //OAILOG_FUNC_RETURN (LOG_NAS, header.extended_protocol_discriminator);
    //LOG_FUNC_RETURN (LOG_NAS, length);
    break;

  case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED:
  case SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED_NEW:
    //printf("SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED or SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED_NEW\n");
    if ( fivegmm_security_context) {
      switch (fivegmm_security_context->selected_algorithms.encryption) {
        case NAS_SECURITY_ALGORITHMS_NEA1:{
          //printf("NAS_SECURITY_ALGORITHMS_NEA1\n");
          if (0 == status->mac_matched) {
            //OAILOG_ERROR(LOG_NAS, "MAC integrity failed\n");
            //OAILOG_FUNC_RETURN (LOG_NAS, 0);
          }
          if (direction == SECU_DIRECTION_UPLINK) {
            count = 0x00000000 | ((fivegmm_security_context->ul_count.overflow && 0x0000FFFF) << 8) | (fivegmm_security_context->ul_count.seq_num & 0x000000FF);
          } else {
            count = 0x00000000 | ((fivegmm_security_context->dl_count.overflow && 0x0000FFFF) << 8) | (fivegmm_security_context->dl_count.seq_num & 0x000000FF);
          }

          //OAILOG_DEBUG (LOG_NAS,
          //    "NAS_SECURITY_ALGORITHMS_EEA1 dir %s count.seq_num %u count %u\n",
          //    (direction == SECU_DIRECTION_UPLINK) ? "UPLINK" : "DOWNLINK",
          //    (direction == SECU_DIRECTION_UPLINK) ? fivegmm_security_context->ul_count.seq_num : fivegmm_security_context->dl_count.seq_num, count);
          stream_cipher.key = fivegmm_security_context->knas_enc;
          stream_cipher.key_length = AUTH_KNAS_ENC_SIZE;
          stream_cipher.count = count;
          stream_cipher.bearer = 0x00;    
          stream_cipher.direction = direction;
          stream_cipher.message = (uint8_t*)src;
          /*
           * length in bits
           */
          stream_cipher.blength = length << 3;
          memcpy (dest, src, length);
          //nas_stream_encrypt_nea1 (&stream_cipher, (uint8_t*)dest);
          /*
           * Decode the first octet (security header type or EPS bearer identity,
           * * * * and protocol discriminator)
           */
          //DECODE_U8 (dest, *(uint8_t *) (&header), size);
          //DECODE_U8(dest,header.extended_protocol_discriminator,size);
          //DECODE_U8(dest+size,header.security_header_type,size);
          //OAILOG_FUNC_RETURN (LOG_NAS, header.extended_protocol_discriminator);
        }
        break;
        case NAS_SECURITY_ALGORITHMS_NEA2:{
          if (0 == status->mac_matched) {
            OAILOG_ERROR(LOG_NAS, "MAC integrity failed\n");
            OAILOG_FUNC_RETURN (LOG_NAS, 0);
          }
          if (direction == SECU_DIRECTION_UPLINK) {
            count = 0x00000000 || ((fivegmm_security_context->ul_count.overflow && 0x0000FFFF) << 8) || (fivegmm_security_context->ul_count.seq_num & 0x000000FF);
          } else {
            count = 0x00000000 || ((fivegmm_security_context->dl_count.overflow && 0x0000FFFF) << 8) || (fivegmm_security_context->dl_count.seq_num & 0x000000FF);
          }

          OAILOG_DEBUG (LOG_NAS,
              "NAS_SECURITY_ALGORITHMS_EEA2 dir %s count.seq_num %u count %u\n",
              (direction == SECU_DIRECTION_UPLINK) ? "UPLINK" : "DOWNLINK",
              (direction == SECU_DIRECTION_UPLINK) ? fivegmm_security_context->ul_count.seq_num : fivegmm_security_context->dl_count.seq_num, count);
          stream_cipher.key = fivegmm_security_context->knas_enc;
          stream_cipher.key_length = AUTH_KNAS_ENC_SIZE;
          stream_cipher.count = count;
          stream_cipher.bearer = 0x00;    
          stream_cipher.direction = direction;
          stream_cipher.message = (uint8_t*)src;
          /*
           * length in bits
           */
          stream_cipher.blength = length << 3;
          //nas_stream_encrypt_nea2 (&stream_cipher, (uint8_t*)dest);
          /*
           * Decode the first octet (security header type or EPS bearer identity,
           * * * * and protocol discriminator)
           */
          //DECODE_U8 (dest, *(uint8_t *) (&header), size);
          DECODE_U8(dest,header.extended_protocol_discriminator,size);
          DECODE_U8(dest+size,header.security_header_type,size);
          OAILOG_FUNC_RETURN (LOG_NAS, header.extended_protocol_discriminator);
        }
        break;
        case NAS_SECURITY_ALGORITHMS_NEA0:
          OAILOG_DEBUG (LOG_NAS, "NAS_SECURITY_ALGORITHMS_EEA0 dir %d ul_count.seq_num %d dl_count.seq_num %d\n", direction, fivegmm_security_context->ul_count.seq_num, fivegmm_security_context->dl_count.seq_num);
          memcpy (dest, src, length);
          /*
           * Decode the first octet (security header type or EPS bearer identity,
           * * * * and protocol discriminator)
           */
          //DECODE_U8 (dest, *(uint8_t *) (&header), size);
          DECODE_U8(dest,header.extended_protocol_discriminator,size);
          DECODE_U8(dest+size,header.security_header_type,size);
          OAILOG_FUNC_RETURN (LOG_NAS, header.extended_protocol_discriminator);
          break;

        default:
          OAILOG_ERROR(LOG_NAS, "Unknown Cyphering protection algorithm %d\n", fivegmm_security_context->selected_algorithms.encryption);
          memcpy (dest, src, length);
          /*
           * Decode the first octet (security header type or EPS bearer identity,
           * * * * and protocol discriminator)
           */
          //DECODE_U8 (dest, *(uint8_t *) (&header), size);
          DECODE_U8(dest,header.extended_protocol_discriminator,size);
          DECODE_U8(dest+size,header.security_header_type,size);
          OAILOG_FUNC_RETURN (LOG_NAS, header.extended_protocol_discriminator);
          break;
      }
    } else {
      OAILOG_ERROR(LOG_NAS, "No security context\n");
      OAILOG_FUNC_RETURN (LOG_NAS, 0);
    }

    break;

  default:
    OAILOG_ERROR(LOG_NAS, "Unknown security header type %u", security_header_type);
    OAILOG_FUNC_RETURN (LOG_NAS, 0);
  };
}

static int _nas_message_plain_decode (
    const unsigned char *buffer,
    const nas_message_security_header_t * header,
    nas_message_plain_t * msg,
    size_t length)
{
  OAILOG_FUNC_IN (LOG_NAS);
  int                                     bytes = TLV_PROTOCOL_NOT_SUPPORTED;
  //printf("_nas_message_plain_decode extended_protocol_discriminator:%0x\n", header->extended_protocol_discriminator);
  if (header->extended_protocol_discriminator == FIVEGS_MOBILITY_MANAGEMENT_MESSAGES) {
    /*
     * Decode 5G Mobility Management L3 message
     */
    //printf("calling mm_msg_decode\n");
    bytes = mm_msg_decode (&msg->mm, (uint8_t *) buffer, length);
	//printf("mm_msg_decode bytes:%d\n", bytes);
  } else if (header->extended_protocol_discriminator == FIVEGS_SESSION_MANAGEMENT_MESSAGES) {
    /*
     * Decode 5G Session Management L3 message
     */
    bytes = sm_msg_decode (&msg->sm, (uint8_t *) buffer, length);
    printf("\ndukl esm_msg_decode\n");
  } else {
    /*
     * Discard L3 messages with not supported protocol discriminator
     */
    //OAILOG_WARNING(LOG_NAS, "NET-API   - Protocol discriminator 0x%x is " "not supported\n", header->protocol_discriminator);
  }
  return bytes;
  //OAILOG_FUNC_RETURN (LOG_NAS, bytes);
}
