#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "AuthenticationRequest.h"
#include "3gpp_ts24.501.h"

int decode_authentication_request( authentication_request_msg *authentication_request, uint8_t* buffer, uint32_t len)
{
  uint32_t                                decoded = 0;
  int                                     decoded_result = 0;

  //printf("decode_authentication_request len:%d\n", len);
  // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
  CHECK_PDU_POINTER_AND_LENGTH_DECODER (buffer, AUTHENTICATION_REQUEST_MINIMUM_LENGTH, len);

  /*
   * Decoding mandatory fields
   */
  if ((decoded_result = decode_u8_nas_key_set_identifier (&authentication_request->naskeysetidentifier, 0, *(buffer + decoded) >> 4, len - decoded)) < 0)
    return decoded_result;

  //printf("naskeysetidentifier decoded_result:%d,tsc:%d\n", decoded_result, authentication_request->naskeysetidentifier.tsc);
  decoded++;
   
  
  if ((decoded_result = decode_abba (&authentication_request->abba,0 , buffer + decoded, len - decoded)) < 0)
    return decoded_result;                
  else                                    
    decoded += decoded_result;

  
  while (len - decoded > 0) {
    //printf("encoding ies left(%d)\n",len-decoded);
    //printf("decoded(%d)\n",decoded);
    uint8_t ieiDecoded = *(buffer+decoded);
    //printf("ieiDecoded(%x)\n",ieiDecoded);
    if(ieiDecoded == 0)
      break;
    switch(ieiDecoded){
      case AUTHENTICATION_PARAMETER_RAND_IEI:
        if ((decoded_result = decode_authentication_parameter_rand (&authentication_request->authenticationparameterrand, AUTHENTICATION_PARAMETER_RAND_IEI, buffer + decoded, len - decoded)) < 0)
          return decoded_result;                
        else{                                    
          decoded += decoded_result;
          authentication_request->presence |= AUTHENTICATION_REQUEST_AUTHENTICATION_PARAMETER_RAND_PRESENT;
        }
      break;
      case AUTHENTICATION_PARAMETER_AUTN_IEI:
        if ((decoded_result = decode_authentication_parameter_autn (&authentication_request->authenticationparameterautn, AUTHENTICATION_PARAMETER_AUTN_IEI, buffer + decoded, len - decoded)) < 0)
          return decoded_result;
        else{
          decoded += decoded_result;
          authentication_request->presence |= AUTHENTICATION_REQUEST_AUTHENTICATION_PARAMETER_AUTN_PRESENT;
        }
      break;
      case AUTHENTICATION_REQUEST_EAP_MESSAGE_IEI:
        if ((decoded_result = decode_eap_message (&authentication_request->eapmessage, AUTHENTICATION_REQUEST_EAP_MESSAGE_IEI, buffer + decoded, len - decoded)) < 0)
          return decoded_result;
        else{
          decoded += decoded_result;
		  
          authentication_request->presence |= AUTHENTICATION_REQUEST_EAP_MESSAGE_PRESENT;
        }
      break;
  }
}

  return decoded;
}


int encode_authentication_request( authentication_request_msg *authentication_request, uint8_t* buffer, uint32_t len)
{
    uint32_t encoded = 0;
    int encoded_result = 0;
    
    // Check if we got a NULL pointer and if buffer length is >= minimum length expected for the message.
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer, AUTHENTICATION_REQUEST_MINIMUM_LENGTH, len);
    
    *(buffer + encoded) = ((encode_u8_nas_key_set_identifier(&authentication_request->naskeysetidentifier) & 0x0f) << 4) | 0x00;
    encoded ++;

    if((encoded_result = encode_abba (authentication_request->abba,0, buffer+encoded,len-encoded))<0)
        return encoded_result;
    else
        encoded+=encoded_result;
	
    if((authentication_request->presence & AUTHENTICATION_REQUEST_AUTHENTICATION_PARAMETER_RAND_PRESENT)
        == AUTHENTICATION_REQUEST_AUTHENTICATION_PARAMETER_RAND_PRESENT){
      if((encoded_result = encode_authentication_parameter_rand (authentication_request->authenticationparameterrand, AUTHENTICATION_PARAMETER_RAND_IEI, buffer+encoded,len-encoded))<0)
        return encoded_result;
      else
        encoded+=encoded_result;
    }
    if((authentication_request->presence & AUTHENTICATION_REQUEST_AUTHENTICATION_PARAMETER_AUTN_PRESENT)
        == AUTHENTICATION_REQUEST_AUTHENTICATION_PARAMETER_AUTN_PRESENT){
      if((encoded_result = encode_authentication_parameter_autn (authentication_request->authenticationparameterautn, AUTHENTICATION_PARAMETER_AUTN_IEI, buffer+encoded,len-encoded))<0)
        return encoded_result;
      else
        encoded+=encoded_result;
    }
    if((authentication_request->presence & AUTHENTICATION_REQUEST_EAP_MESSAGE_PRESENT)
        == AUTHENTICATION_REQUEST_EAP_MESSAGE_PRESENT){
      if((encoded_result = encode_eap_message (authentication_request->eapmessage, AUTHENTICATION_REQUEST_EAP_MESSAGE_IEI, buffer+encoded,len-encoded))<0)
        return encoded_result;
      else
        encoded+=encoded_result;
    }
    return encoded;
}
