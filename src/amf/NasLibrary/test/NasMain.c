#include <stdio.h>
#include <stdlib.h>

#include "nas_message.h"
//#include "sm_msg.h"
#include "bstrlib.h"
#include "mmData.h"
#include "common_types.h"
#include "common_defs.h"

#include "intertask_interface.h"
#include "dynamic_memory_check.h"
#include "assertions.h"
#include "intertask_interface_init.h"
#include "sctp_primitives_server.h"
#include "ngap_amf.h"
#include "amf_app.h"
#include "log.h"
#include "amf_config.h"
#include "pid_file.h"
#include "nas_amf.h"


#if 0

//add-test
#define BUF_LEN 512
int auth_request()
{
     printf("AUTHENTICATION_REQUEST------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = AUTHENTICATION_REQUEST;

	 memset (&mm_msg->specific_msg.authentication_request,		 0, sizeof (authentication_request_msg));

	 mm_msg->specific_msg.authentication_request.naskeysetidentifier.tsc = 1;
	 mm_msg->specific_msg.authentication_request.naskeysetidentifier.naskeysetidentifier = 0b101;

	 bstring abba = bfromcstralloc(10, "\0");
	 uint8_t bitStream_abba = 0b00110100;
	 abba->data = (unsigned char *)(&bitStream_abba);
	 abba->slen = 1;
	 mm_msg->specific_msg.authentication_request.abba = abba;

	 bstring rand = bfromcstralloc(16, "\0");
	 uint8_t tmp[]  = {};
 	 uint8_t bitStream_rand = 0b00110111;
	 rand->data = (unsigned char *)(&bitStream_rand);
	 rand->slen = 16;

	 mm_msg->specific_msg.authentication_request.presence = 0x07;
	 mm_msg->specific_msg.authentication_request.authenticationparameterrand = rand;
	 mm_msg->specific_msg.authentication_request.authenticationparameterautn = abba;
	 mm_msg->specific_msg.authentication_request.eapmessage = abba;

	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif

	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("naskey tsc:0x%x\n",mm_msg->specific_msg.authentication_request.naskeysetidentifier.tsc);
	 printf("naskey tsc:0x%x\n",mm_msg->specific_msg.authentication_request.naskeysetidentifier.naskeysetidentifier);
	 printf("abba buffer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.authentication_request.abba)->data));
	 printf("rand buffer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.authentication_request.authenticationparameterrand)->data));
	 printf("autn buffer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.authentication_request.authenticationparameterautn)->data));
	 printf("eap message buffer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.authentication_request.eapmessage)->data));

	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<20;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 printf("calling nas_message_decode-----------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;
	 printf("message type:0x%x\n",decoded_mm_msg->header.message_type);
	 printf("naskey tsc:0x%x\n",decoded_mm_msg->specific_msg.authentication_request.naskeysetidentifier.tsc);
	 printf("naskey tsc:0x%x\n",decoded_mm_msg->specific_msg.authentication_request.naskeysetidentifier.naskeysetidentifier);
	 printf("abba buffer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.authentication_request.abba)->data));
	 printf("rand buffer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.authentication_request.authenticationparameterrand)->data));
	 printf("autn buffer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.authentication_request.authenticationparameterautn)->data));
	 printf("eap message buffer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.authentication_request.eapmessage)->data));

     printf("AUTHENTICATION_REQUEST------------ end\n");
     return  0;
}

int auth_response()
{
     printf("AUTHENTICATION_RESPONSE------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = AUTHENTICATION_RESPONSE;

	 memset (&mm_msg->specific_msg.authentication_response,		 0, sizeof (authentication_response_msg));



	 bstring param = bfromcstralloc(10, "\0");
	 uint8_t bitStream_rand = 0b00110110;
	 param->data = (unsigned char *)(&bitStream_rand);
	 param->slen = 1;

     bstring eapmsg = bfromcstralloc(10, "\0");
	 uint8_t bitStream_eap = 0b00110101;
	 eapmsg->data = (unsigned char *)(&bitStream_eap);
	 eapmsg->slen = 1;


	 mm_msg->specific_msg.authentication_response.presence = 0x07;
	 mm_msg->specific_msg.authentication_response.authenticationresponseparameter = param;
	 mm_msg->specific_msg.authentication_response.eapmessage = eapmsg;

	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif

     printf("encode-----------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x,\nsecurity_header_type:0x%x,\nsequence_number:0x%x,\nmessage_authentication_code:0x%x,\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("presence:0x%x\n",mm_msg->specific_msg.authentication_response.presence);
	 printf("param:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.authentication_response.authenticationresponseparameter)->data));
	 printf("eap message buffer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.authentication_response.eapmessage)->data));

	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<30;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 //printf("calling nas_message_decode-----------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);

	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);
     printf("decode-----------------\n");
     printf("nas header  decode extended_protocol_discriminator:0x%x,\nsecurity_header_type:0x%x,\nsequence_number:0x%x,\nmessage_authentication_code:0x%x,\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;

	 printf("message type:0x%x\n",decoded_mm_msg->header.message_type);
	 printf("presence:0x%x\n",decoded_mm_msg->specific_msg.authentication_response.presence);
	 printf("param:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.authentication_response.authenticationresponseparameter)->data));
	 printf("eap message buffer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.authentication_response.eapmessage)->data));

	 printf("AUTHENTICATION_RESPONSE------------ end\n");
     return  0;
}

int auth_failure()
{
     printf("AUTHENTICATION_FAILURE------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = AUTHENTICATION_FAILURE;

	 memset (&mm_msg->specific_msg.authentication_failure,		 0, sizeof (authentication_failure_msg));

	 bstring param = bfromcstralloc(10, "\0");
	 uint8_t bitStream_rand = 0b00110110;
	 param->data = (unsigned char *)(&bitStream_rand);
	 param->slen = 1;



     mm_msg->specific_msg.authentication_failure._5gmmcause = 0x80;
	 mm_msg->specific_msg.authentication_failure.presence = 0x07;
	 mm_msg->specific_msg.authentication_failure.authenticationfailureparameter= param;


	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif

     printf("encode-----------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x,\nsecurity_header_type:0x%x,\nsequence_number:0x%x,\nmessage_authentication_code:0x%x,\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("presence:0x%x\n",mm_msg->specific_msg.authentication_failure.presence);
	 printf("5gmmcause :0x%x\n", mm_msg->specific_msg.authentication_failure._5gmmcause);
	 printf("param:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.authentication_failure.authenticationfailureparameter)->data));


	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<30;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 //printf("calling nas_message_decode-----------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);

	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);
     printf("decode-----------------\n");
     printf("nas header  decode extended_protocol_discriminator:0x%x,\nsecurity_header_type:0x%x,\nsequence_number:0x%x,\nmessage_authentication_code:0x%x,\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;


	 printf("message type:0x%x\n",decoded_mm_msg->header.message_type);
	 printf("presence:0x%x\n",decoded_mm_msg->specific_msg.authentication_failure.presence);
	 printf("5gmmcause :0x%x\n", decoded_mm_msg->specific_msg.authentication_failure._5gmmcause);
	 printf("param:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.authentication_failure.authenticationfailureparameter)->data));

	 printf("AUTHENTICATION_FAILURE------------ end\n");

     return  0;
}

int auth_reject()
{
     printf("AUTHENTICATION_REJECT------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = AUTHENTICATION_REJECT;

	 memset (&mm_msg->specific_msg.authentication_reject,		 0, sizeof (authentication_reject_msg));

	 bstring eapmsg = bfromcstralloc(10, "\0");
	 uint8_t bitStream_eapmsg = 0b00110110;
	 eapmsg->data = (unsigned char *)(&bitStream_eapmsg);
	 eapmsg->slen = 1;


	 mm_msg->specific_msg.authentication_reject.presence = 0x07;
	 mm_msg->specific_msg.authentication_reject.eapmessage= eapmsg;


	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif

     printf("encode-----------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x,\nsecurity_header_type:0x%x,\nsequence_number:0x%x,\nmessage_authentication_code:0x%x,\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("presence:0x%x\n",mm_msg->specific_msg.authentication_reject.presence);
	 printf("param:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.authentication_reject.eapmessage)->data));


	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<30;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 //printf("calling nas_message_decode-----------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);

	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);
     printf("decode-----------------\n");
     printf("nas header  decode extended_protocol_discriminator:0x%x,\nsecurity_header_type:0x%x,\nsequence_number:0x%x,\nmessage_authentication_code:0x%x,\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;

	 printf("message type:0x%x\n",decoded_mm_msg->header.message_type);
	 printf("presence:0x%x\n",decoded_mm_msg->specific_msg.authentication_reject.presence);
	 printf("param:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.authentication_reject.eapmessage)->data));


	 printf("AUTHENTICATION_REJECT------------ end\n");

     return 0;
}


int auth_result()
{
     printf("AUTHENTICATION_RESULT------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = AUTHENTICATION_RESULT;

	 memset (&mm_msg->specific_msg.authentication_result,		 0, sizeof (authentication_result_msg));

	 mm_msg->specific_msg.authentication_result.naskeysetidentifier.tsc = 1;
	 mm_msg->specific_msg.authentication_result.naskeysetidentifier.naskeysetidentifier = 0b101;

	 bstring abba = bfromcstralloc(10, "\0");
	 uint8_t bitStream_abba = 0b00110100;
	 abba->data = (unsigned char *)(&bitStream_abba);
	 abba->slen = 1;


	 bstring eapmsg = bfromcstralloc(10, "\0");
	 uint8_t bitStream_eap = 0b00110111;
	 eapmsg->data = (unsigned char *)(&bitStream_eap);
	 eapmsg->slen = 1;

     mm_msg->specific_msg.authentication_result.eapmessage = eapmsg;
	 mm_msg->specific_msg.authentication_result.presence   = 0x07;
	 mm_msg->specific_msg.authentication_result.abba       = abba;


	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif

     printf("encode-----------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("naskey tsc:0x%x\n",mm_msg->specific_msg.authentication_result.naskeysetidentifier.tsc);
	 printf("naskey tsc:0x%x\n",mm_msg->specific_msg.authentication_result.naskeysetidentifier.naskeysetidentifier);
	 printf("abba buffer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.authentication_result.abba)->data));
	 printf("presence:0x%x\n", mm_msg->specific_msg.authentication_result.presence);
	 printf("eap message buffer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.authentication_result.eapmessage)->data));


	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<30;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 //printf("calling nas_message_decode-----------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);

     printf("decode-----------------\n");
     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;
	 printf("message type:0x%x\n",decoded_mm_msg->header.message_type);
	 printf("naskey tsc:0x%x\n",decoded_mm_msg->specific_msg.authentication_result.naskeysetidentifier.tsc);
	 printf("naskey tsc:0x%x\n",decoded_mm_msg->specific_msg.authentication_result.naskeysetidentifier.naskeysetidentifier);
	 printf("abba buffer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.authentication_result.abba)->data));
	 printf("presence:0x%x\n", decoded_mm_msg->specific_msg.authentication_result.presence);
	 printf("eap message buffer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.authentication_result.eapmessage)->data));

     printf("AUTHENTICATION_REQUEST------------ end\n");
     return  0;
}

int reg_request()
{
     printf("REGISTRATION_REQUEST------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = REGISTRATION_REQUEST;

	 memset (&mm_msg->specific_msg.registration_request, 0, sizeof (registration_request_msg));

     mm_msg->specific_msg.registration_request._5gsregistrationtype.is_for = true;
	 mm_msg->specific_msg.registration_request._5gsregistrationtype.registration_type = 0x07;


	 mm_msg->specific_msg.registration_request.naskeysetidentifier.tsc = 1;
	 mm_msg->specific_msg.registration_request.naskeysetidentifier.naskeysetidentifier = 0b101;

	 mm_msg->specific_msg.registration_request.presence = 0x07;

     mm_msg->specific_msg.registration_request.non_current_native_nas_key_set_identifier.tsc =  1;
	 mm_msg->specific_msg.registration_request.non_current_native_nas_key_set_identifier.naskeysetidentifier = 4;


	 mm_msg->specific_msg.registration_request._5gmmcapability.is_HO_supported =  1;
	 mm_msg->specific_msg.registration_request._5gmmcapability.is_LPP_supported = 0;
	 mm_msg->specific_msg.registration_request._5gmmcapability.is_S1_mode_supported = 1;


	 mm_msg->specific_msg.registration_request.uesecuritycapability.nea = 0x11;
	 mm_msg->specific_msg.registration_request.uesecuritycapability.nia = 0x22;

	 //NSSAI nssai;
	 mm_msg->specific_msg.registration_request._5gstrackingareaidentity.mcc = 1;
	 mm_msg->specific_msg.registration_request._5gstrackingareaidentity.mnc = 2;
	 mm_msg->specific_msg.registration_request._5gstrackingareaidentity.tac = 3;


	 mm_msg->specific_msg.registration_request.s1uenetworkcapability.eea = 1;
	 mm_msg->specific_msg.registration_request.s1uenetworkcapability.eia = 2;


	 mm_msg->specific_msg.registration_request.uplinkdatastatus = 0x01;
	 mm_msg->specific_msg.registration_request.pdusessionstatus = 0x02;
	 mm_msg->specific_msg.registration_request.micoindication.raai = 0x1;
	 mm_msg->specific_msg.registration_request.uestatus.n1_mode_reg = 1;
	 mm_msg->specific_msg.registration_request.uestatus.s1_mode_reg = 0;

     //_5GSMobileIdentity AdditionalGUTI;
	 mm_msg->specific_msg.registration_request.allowedpdusessionstatus =  0x01;
	 mm_msg->specific_msg.registration_request.uesusagesetting = 0x01;
	 mm_msg->specific_msg.registration_request._5gsdrxparameters = 0x02;



	 bstring eps = bfromcstralloc(10, "\0");
	 uint8_t bitStream_eps = 0b00110100;
	 eps->data = (unsigned char *)(&bitStream_eps);
	 eps->slen = 1;

	 mm_msg->specific_msg.registration_request.epsnasmessagecontainer = eps;

	//LADNIndication ladnindication;
     mm_msg->specific_msg.registration_request.payloadcontainertype = 0x01;

	 bstring pay = bfromcstralloc(10, "\0");
	 uint8_t bitStream_pay = 0b00110100;
	 pay->data = (unsigned char *)(&bitStream_pay);
	 pay->slen = 1;

	 mm_msg->specific_msg.registration_request.payloadcontainer = pay;


	 mm_msg->specific_msg.registration_request.networkslicingindication.dcni  = 0;
	 mm_msg->specific_msg.registration_request.networkslicingindication.nssci = 1;
	 mm_msg->specific_msg.registration_request._5gsupdatetype.ng_ran_rcu = 0x22;
	 mm_msg->specific_msg.registration_request._5gsupdatetype.sms_requested = 0x11;

	 bstring nas = bfromcstralloc(10, "\0");
	 uint8_t bitStream_nas = 0b00110100;
	 nas->data = (unsigned char *)(&bitStream_nas);
	 nas->slen = 1;

	 mm_msg->specific_msg.registration_request.nasmessagecontainer = nas;

	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif

	 printf("encode-------------------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("_5gsregistrationtype :is_for:0x%x,reg_type:0x%x\n",
	 mm_msg->specific_msg.registration_request._5gsregistrationtype.is_for,
	 mm_msg->specific_msg.registration_request._5gsregistrationtype.registration_type);

	 printf("naskeysetidentifier: tsc:0x%x,naskeysetidentifier:0x%x\n",
	 mm_msg->specific_msg.registration_request.naskeysetidentifier.tsc,
	 mm_msg->specific_msg.registration_request.naskeysetidentifier.naskeysetidentifier);

	 printf("presence:0x%x\n",mm_msg->specific_msg.registration_request.presence);
	 printf("non_current_native_nas_key_set_identifier: tsc:0x%x,naskeysetidentifier:0x%x\n",
	 mm_msg->specific_msg.registration_request.non_current_native_nas_key_set_identifier.tsc,
	 mm_msg->specific_msg.registration_request.non_current_native_nas_key_set_identifier.naskeysetidentifier);

	 printf("_5gmmcapability: is_HO_supported:0x%x,is_LPP_supported:0x%x,is_S1_mode_supported:0x%x\n",
     mm_msg->specific_msg.registration_request._5gmmcapability.is_HO_supported,
	 mm_msg->specific_msg.registration_request._5gmmcapability.is_LPP_supported,
	 mm_msg->specific_msg.registration_request._5gmmcapability.is_S1_mode_supported);

     printf("uesecuritycapability nea:0x%x,nia:0x%x\n",
	 mm_msg->specific_msg.registration_request.uesecuritycapability.nea,
	 mm_msg->specific_msg.registration_request.uesecuritycapability.nia);

	 //NSSAI nssai;
	 printf("_5gstrackingareaidentity mcc:0x%x, mnc:0x%x,tac:0x%x\n",
	 mm_msg->specific_msg.registration_request._5gstrackingareaidentity.mcc,
	 mm_msg->specific_msg.registration_request._5gstrackingareaidentity.mnc,
	 mm_msg->specific_msg.registration_request._5gstrackingareaidentity.tac);

	 printf("s1uenetworkcapability eea:0x%x, eai:0x%x\n",
	 mm_msg->specific_msg.registration_request.s1uenetworkcapability.eea,
	 mm_msg->specific_msg.registration_request.s1uenetworkcapability.eia);

     printf("uplinkdatastatus:0x%x\n",
	 mm_msg->specific_msg.registration_request.uplinkdatastatus);
	 printf("pdusessionstatus:0x%x\n",
	 mm_msg->specific_msg.registration_request.pdusessionstatus);

	 printf("micoindication.raai:0x%x\n",
	 mm_msg->specific_msg.registration_request.micoindication.raai);

	 printf("uestatus: n1_mode_reg:0x%x,s1_mode_reg:0x%x\n",
	 mm_msg->specific_msg.registration_request.uestatus.n1_mode_reg,
	 mm_msg->specific_msg.registration_request.uestatus.s1_mode_reg);

     //_5GSMobileIdentity AdditionalGUTI;
     printf("allowedpdusessionstatus:0x%x\n",
	 mm_msg->specific_msg.registration_request.allowedpdusessionstatus);
	 printf("uesusagesetting:0x%x\n",
	 mm_msg->specific_msg.registration_request.uesusagesetting);
	 printf("_5gsdrxparameters:0x%x\n",
	 mm_msg->specific_msg.registration_request._5gsdrxparameters);

     printf("eapmessage:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.registration_request.epsnasmessagecontainer)->data));
	//LADNIndication ladnindication;
     printf("payloadcontainertype:0x%x\n",mm_msg->specific_msg.registration_request.payloadcontainertype);
	 printf("payloadcontainer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.registration_request.payloadcontainer)->data));

     printf("networkslicingindication,dcni:0x%x,nssci:0x%x\n",
     mm_msg->specific_msg.registration_request.networkslicingindication.dcni,
	 mm_msg->specific_msg.registration_request.networkslicingindication.nssci);

	 printf("_5gsupdatetype ng_ran_rcu:0x%x, sms_requested:0x%x\n",
	 mm_msg->specific_msg.registration_request._5gsupdatetype.ng_ran_rcu,
	 mm_msg->specific_msg.registration_request._5gsupdatetype.sms_requested);


	 printf("nasmessagecontainer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.registration_request.nasmessagecontainer)->data));
	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");


	 int i  = 10;
	 #if 0
	 for(; i<40; i++)
	   printf("i, data[i]: 0x%x\n", i, data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 //printf("calling nas_message_decode-----------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


     printf("decode-------------------------\n");
     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;

	 printf("message type:0x%x\n",decoded_mm_msg->header.message_type);
	 printf("_5gsregistrationtype :is_for:0x%x,reg_type:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request._5gsregistrationtype.is_for,
	 decoded_mm_msg->specific_msg.registration_request._5gsregistrationtype.registration_type);

	 printf("naskeysetidentifier: tsc:0x%x,naskeysetidentifier:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request.naskeysetidentifier.tsc,
	 decoded_mm_msg->specific_msg.registration_request.naskeysetidentifier.naskeysetidentifier);


	 printf("presence:0x%x\n",mm_msg->specific_msg.registration_request.presence);
	 printf("non_current_native_nas_key_set_identifier: tsc:0x%x,naskeysetidentifier:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request.non_current_native_nas_key_set_identifier.tsc,
	 decoded_mm_msg->specific_msg.registration_request.non_current_native_nas_key_set_identifier.naskeysetidentifier);


	 printf("_5gmmcapability: is_HO_supported:0x%x,is_LPP_supported:0x%x,is_S1_mode_supported:0x%x\n",
     decoded_mm_msg->specific_msg.registration_request._5gmmcapability.is_HO_supported,
	 decoded_mm_msg->specific_msg.registration_request._5gmmcapability.is_LPP_supported,
	 decoded_mm_msg->specific_msg.registration_request._5gmmcapability.is_S1_mode_supported);


	 printf("uesecuritycapability nea:0x%x,nia:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request.uesecuritycapability.nea,
	 decoded_mm_msg->specific_msg.registration_request.uesecuritycapability.nia);

	 //NSSAI nssai;
	 printf("_5gstrackingareaidentity mcc:0x%x, mnc:0x%x,tac:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request._5gstrackingareaidentity.mcc,
	 decoded_mm_msg->specific_msg.registration_request._5gstrackingareaidentity.mnc,

	 //ENCODE_U24->U32
	 decoded_mm_msg->specific_msg.registration_request._5gstrackingareaidentity.tac);

	 printf("s1uenetworkcapability eea:0x%x, eai:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request.s1uenetworkcapability.eea,
	 decoded_mm_msg->specific_msg.registration_request.s1uenetworkcapability.eia);


	 printf("uplinkdatastatus:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request.uplinkdatastatus);
	 printf("pdusessionstatus:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request.pdusessionstatus);

	 printf("micoindication.raai:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request.micoindication.raai);

	 printf("uestatus: n1_mode_reg:0x%x,s1_mode_reg:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request.uestatus.n1_mode_reg,
	 decoded_mm_msg->specific_msg.registration_request.uestatus.s1_mode_reg);

     //_5GSMobileIdentity AdditionalGUTI;
     printf("allowedpdusessionstatus:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request.allowedpdusessionstatus);
	 printf("uesusagesetting:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request.uesusagesetting);
	 printf("_5gsdrxparameters:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request._5gsdrxparameters);

     printf("eapmessage:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.registration_request.epsnasmessagecontainer)->data));
	//LADNIndication ladnindication;
     printf("payloadcontainertype:0x%x\n",decoded_mm_msg->specific_msg.registration_request.payloadcontainertype);
	 printf("payloadcontainer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.registration_request.payloadcontainer)->data));

	 printf("networkslicingindication,dcni:0x%x,nssci:0x%x\n",
     decoded_mm_msg->specific_msg.registration_request.networkslicingindication.dcni,
	 decoded_mm_msg->specific_msg.registration_request.networkslicingindication.nssci);

	 printf("_5gsupdatetyp,ng_ran_rcu:0x%x, sms_requested:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_request._5gsupdatetype.ng_ran_rcu,
	 decoded_mm_msg->specific_msg.registration_request._5gsupdatetype.sms_requested);

	 printf("nasmessagecontainer:0x%x\n",
	 *(unsigned char *)((decoded_mm_msg->specific_msg.registration_request.nasmessagecontainer)->data));
	 printf("REGISTRATION_REQUEST------------ end\n");

     return 0;
}

int reg_accept()
{
     printf("REGISTRATION_ACCEPT------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = REGISTRATION_ACCEPT;

	 memset (&mm_msg->specific_msg.registration_accept, 0, sizeof (registration_accept_msg));

	 mm_msg->specific_msg.registration_accept._5gsregistrationresult.is_SMS_allowed =  1;
	 mm_msg->specific_msg.registration_accept._5gsregistrationresult.registration_result_value = 0x07;

	 mm_msg->specific_msg.registration_accept.presence = 0x00b1fbc6;


	 for(int i = 0; i <15; i++)
	 {
         mm_msg->specific_msg.registration_accept.plmnlist[i].mcc =  i*2;
		 mm_msg->specific_msg.registration_accept.plmnlist[i].mnc =  i*3;

	 }

     #if 0
	 struct MccMnc mm;
	 memset(&mm, 0, sizeof(struct MccMnc));
	 mm.mcc = 0x21;
	 mm.mnc = 0x22;
	 mm.next= NULL;
	 #endif

	 struct PartialTrackingAreaIdentityList partialTrackingAreaIdentityList;
	 memset(&partialTrackingAreaIdentityList, 0, sizeof(struct PartialTrackingAreaIdentityList));
     partialTrackingAreaIdentityList.typeOfList = 0x2;
	 partialTrackingAreaIdentityList.numberOfElements = 2;
	 //partialTrackingAreaIdentityList.mcc_mnc = &mm;


	 struct TrackingAreaIdentity tai1, tai2;
	 memset(&tai1, 0, sizeof(tai1));
	 memset(&tai2, 0, sizeof(tai2));

	 tai2.tac = 0x21;
	 tai2.tacContinued = 0x22;
	 tai2.next = NULL;

	 tai1.tac = 0x11;
	 tai1.tacContinued = 0x12;
	 tai1.next = &tai2;


     //0b01
     struct MccMnc smm1, smm2;
     memset(&smm1, 0, sizeof(smm1));
     memset(&smm2, 0, sizeof(smm2));
     smm2.mcc = 0x02,
     smm2.mnc = 0x02,
     smm2.next = NULL;
     smm1.mcc = 0x01,
     smm1.mnc = 0x01,
     smm1.next = &smm2;

     partialTrackingAreaIdentityList.mcc_mnc = &smm1;
     partialTrackingAreaIdentityList.tai = &tai1;
	 partialTrackingAreaIdentityList.next = NULL;

	 _5GSTrackingAreaIdentityList  _5gstrackingareaidentitylist;

	 _5gstrackingareaidentitylist.listSize = 1;
     _5gstrackingareaidentitylist.partialTrackingAreaIdentityList =  &partialTrackingAreaIdentityList;
     mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist = _5gstrackingareaidentitylist;


	 mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.mpsi  = 0;
     mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.iwk_n26 =1;
     mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.emf = 0;
     mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.emc  = 1;
     mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.ims_VoPS_N3GPP  = 0;
     mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.ims_VoPS_3GPP  = 1;
     mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.mcsi = 0;
     mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.emcn = 1;

     mm_msg->specific_msg.registration_accept.pdusessionstatus  = 0x79;
     mm_msg->specific_msg.registration_accept.pdusessionreactivationresult =0x80;

     struct PduSessionID_CauseValue psc1,psc2;
     memset(&psc1, '\0',sizeof(struct PduSessionID_CauseValue));
     memset(&psc2, '\0',sizeof(struct PduSessionID_CauseValue));

     psc2.pduSessionID = 0x02;
     psc2.causeValue   = 0x02;
     psc2.next = NULL;

     psc1.pduSessionID = 0x01;
     psc1.causeValue   = 0x01;
     psc1.next = &psc2;

     mm_msg->specific_msg.registration_accept.pdusessionreactivationresulterrorcause.size = 2;
     mm_msg->specific_msg.registration_accept.pdusessionreactivationresulterrorcause.element =  &psc1;
          //LADNInformation ladninformation;
     mm_msg->specific_msg.registration_accept.micoindication.raai= true;
     mm_msg->specific_msg.registration_accept.networkslicingindication.dcni  = 0x00;
     mm_msg->specific_msg.registration_accept.networkslicingindication.nssci = 0x01;


     struct MccMnc smm11, smm12;
     memset(&smm11, 0, sizeof(smm11));
     memset(&smm12, 0, sizeof(smm12));
     smm12.mcc = 0x02,
     smm12.mnc = 0x02,
     smm12.next = NULL;

     smm11.mcc = 0x01,
     smm11.mnc = 0x01,
     smm11.next = NULL;

     struct TrackingAreaIdentity stai1, stai2;
     memset(&stai1, 0, sizeof(stai1));
     memset(&stai2, 0, sizeof(stai2));

     stai2.tac = 0x02;
     stai2.tacContinued = 0x02;
     stai2.next = NULL;

     stai1.tac = 0x01;
     stai1.tacContinued = 0x01;
     stai1.next = &stai2;



      struct PartialServiceAreaList  pSAreaList;
      memset(&pSAreaList, 0, sizeof(struct PartialServiceAreaList));
      pSAreaList.is_allowed = 1;
      pSAreaList.typeOfList = 0x00;
      pSAreaList.numberOfElements = 2;
      pSAreaList.mcc_mnc = &smm11;
      pSAreaList.tai = &stai1;

      ServiceAreaList servicearealist;
      memset(&servicearealist, 0, sizeof(ServiceAreaList));
      servicearealist.listSize = 1;
      servicearealist.partialServiceAreaList = &pSAreaList;

      mm_msg->specific_msg.registration_accept.servicearealist  = servicearealist;


      mm_msg->specific_msg.registration_accept.t3512.unit = 0x02;
      mm_msg->specific_msg.registration_accept.t3512.timeValue = 0x03;


      mm_msg->specific_msg.registration_accept.non_3gpp_deregistration_timer  = 0x0C;

      mm_msg->specific_msg.registration_accept.t3502  = 0x0D;

        //EmergencyNumberList emergencynumberlist;
        //ExtendedEmergencyNumberList extendedemergencynumberlist;
        //SORTransparentContainer sortransparentcontainer;


      bstring eapmessage = bfromcstralloc(10, "\0");
      uint8_t bitStream_eapmessage = 0b00110100;
      eapmessage->data = (unsigned char *)(&bitStream_eapmessage);
      eapmessage->slen = 1;

      mm_msg->specific_msg.registration_accept.eapmessage = eapmessage;
      mm_msg->specific_msg.registration_accept.nssaiinclusionmode = 0x0E;
      //OperatorDefinedAccessCategoryDefinitions operatordefinedaccesscategorydefinitions;
      mm_msg->specific_msg.registration_accept._5gsdrxparameters = 0x0F;


	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result


	 printf("encode-------------------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

     printf("_5gsregistrationresult,is_SMS_allowed:0x%x,registration_result_value:0x%x\n",
     mm_msg->specific_msg.registration_accept._5gsregistrationresult.is_SMS_allowed,
	 mm_msg->specific_msg.registration_accept._5gsregistrationresult.registration_result_value);

     printf("presence:0x%x\n",
	 mm_msg->specific_msg.registration_accept.presence);


	 for(int i = 0; i <15; i++)
	 {
	     printf("plmnlist[%d],mcc:0x%x,mcc:0x%x\n",
		 i,
         mm_msg->specific_msg.registration_accept.plmnlist[i].mcc,
		 mm_msg->specific_msg.registration_accept.plmnlist[i].mnc) ;

	 }


     printf("_5gstrackingareaidentitylist listsize:0x%x\n", mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.listSize);

	 printf("partialTrackingAreaIdentityList typeOfList:0x%x,numberOfElements:0x%x\n",
	 mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.partialTrackingAreaIdentityList->typeOfList,
	 mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.partialTrackingAreaIdentityList->numberOfElements);


	 int numberofelements1 = mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.partialTrackingAreaIdentityList->numberOfElements;
     struct MccMnc *smmcc = mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.partialTrackingAreaIdentityList->mcc_mnc;
	 for(int i  = 0; i<numberofelements1; i++)
	 {
	     printf("partialTrackingAreaIdentityList MccMnc mcc:0x%x, mnc:0x%x\n",
		 smmcc->mcc,smmcc->mnc);

		 if(smmcc->next)
           smmcc = smmcc->next;
     }

	 struct TrackingAreaIdentity *tailist = mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.partialTrackingAreaIdentityList->tai;
	 for(int i  = 0; i<numberofelements1; i++)
	 {
	     printf("partialTrackingAreaIdentityList tai tac:0x%x, tacContinued:0x%x\n",
		 tailist->tac,tailist->tacContinued);

		 if(tailist->next)
           tailist = tailist->next;
     }


	  printf("_5gsnetworkfeaturesupport,mpsi:0x%x,iwk_n26:0x%x,emf:0x%x,emc:0x%x,ims_VoPS_N3GPP:0x%x,ims_VoPS_3GPP:0x%x,mcsi:0x%x,emcn:0x%x\n",
      mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.mpsi,
      mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.iwk_n26,
      mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.emf,
      mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.emc,
      mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.ims_VoPS_N3GPP,
      mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.ims_VoPS_3GPP,
      mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.mcsi,
      mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.emcn);

      printf("pdusessionstatus:0x%x\n",
      mm_msg->specific_msg.registration_accept.pdusessionstatus);
      printf("pdusessionreactivationresult:0x%x\n",
      mm_msg->specific_msg.registration_accept.pdusessionreactivationresult);



      size = mm_msg->specific_msg.registration_accept.pdusessionreactivationresulterrorcause.size ;
      printf("pdusessionreactivationresulterrorcause size:0x%x\n",size);
      struct PduSessionID_CauseValue *pscTmp  = mm_msg->specific_msg.registration_accept.pdusessionreactivationresulterrorcause.element;
      for(int i = 0; i<size; i++)
      {
           printf("pdusessionreactivationresulterrorcause pduSessionID:0x%x,causeValue:0x%x\n", pscTmp->pduSessionID,pscTmp->causeValue);
		   pscTmp =  pscTmp->next;
      }
      //LADNInformation ladninformation;
      printf("micoindication,raai: 0x%x\n", mm_msg->specific_msg.registration_accept.micoindication.raai);

      printf("networkslicingindication,dcni:0x%x,nssci:0x%x\n",
      mm_msg->specific_msg.registration_accept.networkslicingindication.dcni ,
      mm_msg->specific_msg.registration_accept.networkslicingindication.nssci);


      size =  mm_msg->specific_msg.registration_accept.servicearealist.listSize;
      printf("servicearealist,listsize:0x%x\n", size);

      struct PartialServiceAreaList  *decodePsr = mm_msg->specific_msg.registration_accept.servicearealist.partialServiceAreaList;
      printf("servicearealist, partialServiceAreaList,is_allowed:0x%x,typeOfList:0x%x,numberOfElements:0x%x\n",
      decodePsr->is_allowed, decodePsr->typeOfList,decodePsr->numberOfElements);

      struct MccMnc *decmmc = decodePsr->mcc_mnc;
      for(int i = 0; i< size; i++)
      {
           printf("servicearealist, partialServiceAreaList,mcc_mnc,mcc:0x%x,mnc:0x%x\n",
           decmmc->mcc,decmmc->mnc);
		   if(decmmc->next)
               decmmc = decmmc->next;
      }
      struct TrackingAreaIdentity  *decodestai =  decodePsr->tai;
      for(int i = 0; i< size; i++)
      {
           printf("servicearealist, partialServiceAreaList,tai,tac:0x%x,tacContinued:0x%x\n",
           decodestai->tac,decodestai->tacContinued);
		   if(decodestai->next)
               decodestai = decodestai->next;
      }


      printf("t3512, unit:0x%x, timeValue:0x%x\n",
      mm_msg->specific_msg.registration_accept.t3512.unit,
      mm_msg->specific_msg.registration_accept.t3512.timeValue);

      printf("non_3gpp_deregistration_timer: 0x%x\n",
          mm_msg->specific_msg.registration_accept.non_3gpp_deregistration_timer);

      printf("t3502:0x%x\n",mm_msg->specific_msg.registration_accept.t3502);
        //EmergencyNumberList emergencynumberlist;
        //ExtendedEmergencyNumberList extendedemergencynumberlist;
        //SORTransparentContainer sortransparentcontainer;


      printf("eapmessage:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.registration_accept.eapmessage)->data));
      printf("nssaiinclusionmode:0x%x\n",mm_msg->specific_msg.registration_accept.nssaiinclusionmode);
      //OperatorDefinedAccessCategoryDefinitions operatordefinedaccesscategorydefinitions;
      printf("_5gsdrxparameters:0x%x\n",mm_msg->specific_msg.registration_accept._5gsdrxparameters);



     bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);

	 int i  = 0;

	 #if 0
	 for(; i<50; i++)
	   printf("reg_accept i, data[i]: 0x%x\n", i, data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 //printf("calling nas_message_decode-----------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


     printf("decode-------------------------\n");
	 printf("nas header decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;

	 printf("_5gsregistrationresult,is_SMS_allowed:0x%x,registration_result_value:0x%x\n",
     decoded_mm_msg->specific_msg.registration_accept._5gsregistrationresult.is_SMS_allowed,
	 decoded_mm_msg->specific_msg.registration_accept._5gsregistrationresult.registration_result_value);

     printf("presence:0x%x\n",
	 decoded_mm_msg->specific_msg.registration_accept.presence);


	 for(int i = 0; i <15; i++)
	 {
	     printf("plmnlist[%d],mcc:0x%x,mnc:0x%x\n",
		 i,
         decoded_mm_msg->specific_msg.registration_accept.plmnlist[i].mcc,
		 decoded_mm_msg->specific_msg.registration_accept.plmnlist[i].mnc) ;

	 }

	 //##########  *********************  ���볤�����⵼��listsize ����ȷ,��ϸ�뿴����;
	 #if 0
	 int decode__5gs_tracking_area_identity_list ( _5GSTrackingAreaIdentityList * _5gstrackingareaidentitylist, uint8_t iei, uint8_t * buffer, uint32_t len  )
     {
          ......

          while(len - decoded > 0){
           DECODE_U8(buffer+decoded,octet,decoded);
           _5gstrackingareaidentitylist->listSize += 1;

          ......

		  return 0;
     }
	 #endif



	 printf("_5gstrackingareaidentitylist listsize:0x%x\n", decoded_mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.listSize);

	 printf("partialTrackingAreaIdentityList typeOfList:0x%x,numberOfElements:0x%x\n",
		  decoded_mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.partialTrackingAreaIdentityList->typeOfList,
		  decoded_mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.partialTrackingAreaIdentityList->numberOfElements);


	 int numberofelements = decoded_mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.partialTrackingAreaIdentityList->numberOfElements;
     struct MccMnc *smmcc1 = decoded_mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.partialTrackingAreaIdentityList->mcc_mnc;
	 for(int i  = 0; i<numberofelements1; i++)
	 {
	     printf("partialTrackingAreaIdentityList MccMnc mcc:0x%x, mnc:0x%x\n",
		 smmcc1->mcc,smmcc1->mnc);

		 if(smmcc1->next)
             smmcc1 = smmcc1->next;
     }
	 struct TrackingAreaIdentity *tailist1 = decoded_mm_msg->specific_msg.registration_accept._5gstrackingareaidentitylist.partialTrackingAreaIdentityList->tai;
	 for(int i  = 0; i<numberofelements; i++)
	 {
		printf("partialTrackingAreaIdentityList tai tac:0x%x, tacContinued:0x%x\n",
		tailist1->tac,tailist1->tacContinued);
		if(tailist1->next)
		    tailist1 = tailist1->next;
	 }

	  printf("_5gsnetworkfeaturesupport,mpsi:0x%x,iwk_n26:0x%x,emf:0x%x,emc:0x%x,ims_VoPS_N3GPP:0x%x,ims_VoPS_3GPP:0x%x,mcsi:0x%x,emcn:0x%x\n",
      decoded_mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.mpsi,
      decoded_mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.iwk_n26,
      decoded_mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.emf,
      decoded_mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.emc,
      decoded_mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.ims_VoPS_N3GPP,
      decoded_mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.ims_VoPS_3GPP,
      decoded_mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.mcsi,
      decoded_mm_msg->specific_msg.registration_accept._5gsnetworkfeaturesupport.emcn);

      printf("PDUSessionStatus:0x%x\n",
      decoded_mm_msg->specific_msg.registration_accept.pdusessionstatus);
      printf("PDUSessionReactivationResult:0x%x\n",
      decoded_mm_msg->specific_msg.registration_accept.pdusessionreactivationresult);

	  size = decoded_mm_msg->specific_msg.registration_accept.pdusessionreactivationresulterrorcause.size ;
      printf("pdusessionreactivationresulterrorcause size:0x%x\n",size);
      struct PduSessionID_CauseValue *pscTmp1  = decoded_mm_msg->specific_msg.registration_accept.pdusessionreactivationresulterrorcause.element;
      for(int i = 0; i< size; i++)
      {
           if(!pscTmp1)
		        continue;
           printf("pdusessionreactivationresulterrorcause pduSessionID:0x%x,causeValue:0x%x\n", pscTmp1->pduSessionID,pscTmp1->causeValue);
		   pscTmp1 = pscTmp1->next;
      }
      //LADNInformation ladninformation;
      printf("micoindication,raai: 0x%x\n", decoded_mm_msg->specific_msg.registration_accept.micoindication.raai);

      printf("networkslicingindication,dcni:0x%x,nssci:0x%x\n",
      decoded_mm_msg->specific_msg.registration_accept.networkslicingindication.dcni ,
      decoded_mm_msg->specific_msg.registration_accept.networkslicingindication.nssci);

      size =  mm_msg->specific_msg.registration_accept.servicearealist.listSize;
      printf("servicearealist,listsize:0x%x\n", size);

      struct PartialServiceAreaList  *decodePsr1 = mm_msg->specific_msg.registration_accept.servicearealist.partialServiceAreaList;
      printf("servicearealist, partialServiceAreaList,is_allowed:0x%x,typeOfList:0x%x,numberOfElements:0x%x\n",
      decodePsr->is_allowed, decodePsr->typeOfList,decodePsr->numberOfElements);

      struct MccMnc *decmmc1 = decodePsr1->mcc_mnc;
      for(int i = 0; i< size; i++)
      {
           printf("servicearealist, partialServiceAreaList,mcc_mnc,mcc:0x%x,mnc:0x%x\n",
           decmmc1->mcc,decmmc1->mnc);
		   if(decmmc1->next)
              decmmc1 = decmmc1->next;
      }
      struct TrackingAreaIdentity  *decodestai1 =  decodePsr1->tai;
      for(int i = 0; i< size; i++)
      {
           printf("servicearealist, partialServiceAreaList,tai,tac:0x%x,tacContinued:0x%x\n",
           decodestai1->tac,decodestai1->tacContinued);
		   if(decodestai1->next)
               decodestai1 = decodestai1->next;
      }

      printf("t3512, unit:0x%x, timeValue:0x%x\n",
          decoded_mm_msg->specific_msg.registration_accept.t3512.unit,
      decoded_mm_msg->specific_msg.registration_accept.t3512.timeValue);

      printf("non_3gpp_deregistration_timer: 0x%x\n",
          decoded_mm_msg->specific_msg.registration_accept.non_3gpp_deregistration_timer);

      printf("t3502:0x%x\n", decoded_mm_msg->specific_msg.registration_accept.t3502);
      //EmergencyNumberList emergencynumberlist;
      //ExtendedEmergencyNumberList extendedemergencynumberlist;
      //SORTransparentContainer sortransparentcontainer;


      printf("eapmessage:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.registration_accept.eapmessage)->data));
      printf("nssaiinclusionmode:0x%x\n",decoded_mm_msg->specific_msg.registration_accept.nssaiinclusionmode);
      //OperatorDefinedAccessCategoryDefinitions operatordefinedaccesscategorydefinitions;
      printf("_5gsdrxparameters:0x%x\n",decoded_mm_msg->specific_msg.registration_accept._5gsdrxparameters);


	  printf("REGISTRATION_ACCEPT------------ end\n");

      return  0;
}
int reg_complete()
{

	 printf("AUTHENTICATION_COMPLETE------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = REGISTRATION_COMPLETE;

	 memset (&mm_msg->specific_msg.registration_complete,		 0, sizeof (registration_complete_msg));

	 mm_msg->specific_msg.registration_complete.sortransparentcontainer.sorHeader = 0x77;



	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif
     printf("encode-------------------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("sortransparentcontainer.sorHeader:0x%x\n", mm_msg->specific_msg.registration_complete.sortransparentcontainer.sorHeader);

	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<20;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 printf("decode-------------------------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;
	 printf("message type:0x%x\n",decoded_mm_msg->header.message_type);
	 printf("sortransparentcontainer.sorHeader:0x%x\n", decoded_mm_msg->specific_msg.registration_complete.sortransparentcontainer.sorHeader);


     printf("REGISTRATION_COMPLETE------------ END\n");
     return 0;
}
int reg_reject()
{
     printf("AUTHENTICATION_REJECT------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = REGISTRATION_REJECT;

	 memset (&mm_msg->specific_msg.registration_reject,		 0, sizeof (registration_reject_msg));

	 mm_msg->specific_msg.registration_reject._5gmmcause = 0x77;
	 mm_msg->specific_msg.registration_reject.presence = 0x07;
	 mm_msg->specific_msg.registration_reject.t3346  = 0x78;
	 mm_msg->specific_msg.registration_reject.t3502  = 0X79;

	 bstring eapmessage = bfromcstralloc(10, "\0");
     uint8_t bitStream_eapmessage = 0b00110100;
     eapmessage->data = (unsigned char *)(&bitStream_eapmessage);
     eapmessage->slen = 1;

     mm_msg->specific_msg.registration_reject.eapmessage = eapmessage;

	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif
     printf("encode-------------------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("_5gmmcause:0x%x\n", mm_msg->specific_msg.registration_reject._5gmmcause);
	 printf("presence:0x%x\n", mm_msg->specific_msg.registration_reject.presence);
	 printf("t3346:0x%x\n", mm_msg->specific_msg.registration_reject.t3346);
	 printf("t3502:0x%x\n", mm_msg->specific_msg.registration_reject.t3502);
	 printf("eapmessage:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.registration_reject.eapmessage)->data));
	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<20;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);

     printf("decode-------------------------\n");
     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;
	 printf("message type:0x%x\n",decoded_mm_msg->header.message_type);
	 printf("_5gmmcause:0x%x\n", decoded_mm_msg->specific_msg.registration_reject._5gmmcause);
	 printf("presence:0x%x\n", decoded_mm_msg->specific_msg.registration_reject.presence);
	 printf("t3346:0x%x\n", decoded_mm_msg->specific_msg.registration_reject.t3346);
	 printf("t3502:0x%x\n", decoded_mm_msg->specific_msg.registration_reject.t3502);
	 printf("eapmessage:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.registration_reject.eapmessage)->data));

     printf("REGISTRATION_REJECT------------ END\n");
     return 0;
}

int identity_request()
{
     printf("IDENTITY_REQUEST------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = IDENTITY_REQUEST;

	 memset (&mm_msg->specific_msg.identity_request,		 0, sizeof (identity_request_msg));

	 mm_msg->specific_msg.identity_request._5gsidentitytype.typeOfIdentity = 0x3;


	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif
     printf("encode-------------------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("typeOfIdentity:0x%x\n",  mm_msg->specific_msg.identity_request._5gsidentitytype.typeOfIdentity);

	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<20;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 printf("decode-------------------------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;
	 printf("message type:0x%x\n", decoded_mm_msg->header.message_type);
	 printf("typeOfIdentity:0x%x\n", decoded_mm_msg->specific_msg.identity_request._5gsidentitytype.typeOfIdentity);

     printf("IDENTITY_REQUEST------------ END\n");
     return 0;
}
int identity_response()
{
     printf("IDENTITY_RESPONSE------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = IDENTITY_RESPONSE;

	 memset (&mm_msg->specific_msg.identity_response,		 0, sizeof (identity_response_msg));

     mm_msg->specific_msg.identity_response._5gsmobileidentity.IdentityType = 0x12;
     mm_msg->specific_msg.identity_response._5gsmobileidentity.odd_even_indication = 0x13;

     /*5g-guti*/
     mm_msg->specific_msg.identity_response._5gsmobileidentity.mcc = 0x14;
     mm_msg->specific_msg.identity_response._5gsmobileidentity.mnc = 0x15;
     mm_msg->specific_msg.identity_response._5gsmobileidentity.amfRegionID = 0x15;
     mm_msg->specific_msg.identity_response._5gsmobileidentity.amfSetID = 0x16;
     mm_msg->specific_msg.identity_response._5gsmobileidentity.amfPointer = 0x17;
     mm_msg->specific_msg.identity_response._5gsmobileidentity._5g_tmsi = 0x18;

     /*imei imeisv*/
     mm_msg->specific_msg.identity_response._5gsmobileidentity.identity = 0x19;//???

     /*suci supi imsi*/
     mm_msg->specific_msg.identity_response._5gsmobileidentity.supi = 0x20;
     mm_msg->specific_msg.identity_response._5gsmobileidentity.routingIndicator = 0x21;
     mm_msg->specific_msg.identity_response._5gsmobileidentity.protectionSchemeID  = 0x22;
     mm_msg->specific_msg.identity_response._5gsmobileidentity.homeNetworkPublicKeyIdentifier = 0x23;
     mm_msg->specific_msg.identity_response._5gsmobileidentity.msin = 0x24;//???


	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif
     printf("encode-------------------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);

	 printf("IdentityType:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.IdentityType);
     printf("odd_even_indication:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.odd_even_indication);

     /*5g-guti*/
     printf("mcc:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.mcc);
     printf("mnc:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.mnc);
     printf("amfRegionID:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.amfRegionID);
     printf("amfSetID:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.amfSetID);
     printf("amfPointer:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.amfPointer);
     printf("_5g_tmsi:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity._5g_tmsi);

     /*imei imeisv*/
     printf("identity:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.identity);

     /*suci supi imsi*/
     printf("supi:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.supi);
     printf("routingIndicator:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.routingIndicator);
     printf("protectionSchemeID:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.protectionSchemeID);
     printf("homeNetworkPublicKeyIdentifier:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.homeNetworkPublicKeyIdentifier);
     printf("msin:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.msin);

	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<20;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 printf("decode-------------------------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;
	 printf("message type:0x%x\n", decoded_mm_msg->header.message_type);

	 printf("IdentityType:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.IdentityType);
     printf("odd_even_indication:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.odd_even_indication);

     /*5g-guti*/
     printf("mcc:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.mcc);
     printf("mnc:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.mnc);
     printf("amfRegionID:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.amfRegionID);
     printf("amfSetID:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.amfSetID);
     printf("amfPointer:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.amfPointer);
     printf("_5g_tmsi:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity._5g_tmsi);

     /*imei imeisv*/
     printf("identity:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.identity);

     /*suci supi imsi*/
     printf("supi:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.supi);
     printf("routingIndicator:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.routingIndicator);
     printf("protectionSchemeID:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.protectionSchemeID);
     printf("homeNetworkPublicKeyIdentifier:0x%x\n",mm_msg->specific_msg.identity_response._5gsmobileidentity.homeNetworkPublicKeyIdentifier);
     printf("msin:0x%x\n",decoded_mm_msg->specific_msg.identity_response._5gsmobileidentity.msin);

     printf("IDENTITY_RESPONSE------------ END\n");
     return 0;

}

int security_mode_command()
{
     printf("SECURITY_MODE_COMMAND------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = SECURITY_MODE_COMMAND;

	 memset (&mm_msg->specific_msg.security_mode_command,		 0, sizeof (security_mode_command_msg));


     mm_msg->specific_msg.security_mode_command.nassecurityalgorithms.typeOfCipheringAlgorithm = 0x03;
	 mm_msg->specific_msg.security_mode_command.nassecurityalgorithms.typeOfIntegrityProtectionAlgorithm = 0x04;

	 mm_msg->specific_msg.security_mode_command.naskeysetidentifier.tsc = 1;
	 mm_msg->specific_msg.security_mode_command.naskeysetidentifier.naskeysetidentifier = 0x02;

	 mm_msg->specific_msg.security_mode_command.uesecuritycapability.nea = 0x05;
	 mm_msg->specific_msg.security_mode_command.uesecuritycapability.nia = 0x06;
     mm_msg->specific_msg.security_mode_command.presence = 0x1f;

	 mm_msg->specific_msg.security_mode_command.imeisvrequest = 0x09;
	 mm_msg->specific_msg.security_mode_command.epsnassecurityalgorithms.typeOfCipheringAlgoithm = 0x01;
	 mm_msg->specific_msg.security_mode_command.epsnassecurityalgorithms.typeOfIntegrityProtectionAlgoithm = 0x02;

	 mm_msg->specific_msg.security_mode_command.additional5gsecurityinformation.hdp = 1;
	 mm_msg->specific_msg.security_mode_command.additional5gsecurityinformation.rinmr = 0;

     bstring eapmessage = bfromcstralloc(10, "\0");
     uint8_t bitStream_eapmessage = 0b00110100;
     eapmessage->data = (unsigned char *)(&bitStream_eapmessage);
     eapmessage->slen = 1;

	 mm_msg->specific_msg.security_mode_command.eapmessage =  eapmessage;

	 bstring abba = bfromcstralloc(10, "\0");
     uint8_t bitStream_abba = 0b00110100;
     abba->data = (unsigned char *)(&bitStream_abba);
     abba->slen = 1;
	 mm_msg->specific_msg.security_mode_command.abba =  abba;

	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif
     printf("encode-------------------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("nassecurityalgorithms,typeOfCipheringAlgorithm:0x%x,typeOfIntegrityProtectionAlgorithm:0x%x\n",
	    mm_msg->specific_msg.security_mode_command.nassecurityalgorithms.typeOfCipheringAlgorithm,
		mm_msg->specific_msg.security_mode_command.nassecurityalgorithms.typeOfIntegrityProtectionAlgorithm );
	 printf("naskeysetidentifier,tsc:0x%x,naskeysetidentifier:0x%x\n",
		mm_msg->specific_msg.security_mode_command.naskeysetidentifier.tsc,
		mm_msg->specific_msg.security_mode_command.naskeysetidentifier.naskeysetidentifier);
	 printf("uesecuritycapability.nea:0x%x,nia:0x%x\n",
		mm_msg->specific_msg.security_mode_command.uesecuritycapability.nea,
		mm_msg->specific_msg.security_mode_command.uesecuritycapability.nia);

	 printf("presence:0x%x\n",mm_msg->specific_msg.security_mode_command.presence);

	 printf("imeisvrequest:0x%x\n",mm_msg->specific_msg.security_mode_command.imeisvrequest);

	 printf("epsnassecurityalgorithms, typeOfCipheringAlgoithm:0x%x,typeOfIntegrityProtectionAlgoithm:0x%x\n",
		mm_msg->specific_msg.security_mode_command.epsnassecurityalgorithms.typeOfCipheringAlgoithm,
		mm_msg->specific_msg.security_mode_command.epsnassecurityalgorithms.typeOfIntegrityProtectionAlgoithm);

	 printf("additional5gsecurityinformation,hdp:0x%x,rinmr:0x%x\n",
		mm_msg->specific_msg.security_mode_command.additional5gsecurityinformation.hdp,
		mm_msg->specific_msg.security_mode_command.additional5gsecurityinformation.rinmr);

     printf("eap message buffer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.security_mode_command.eapmessage)->data));
	 printf("abba buffer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.security_mode_command.abba)->data));

	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<20;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 printf("decode-------------------------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;
	 printf("message type:0x%x\n", decoded_mm_msg->header.message_type);

	 printf("nassecurityalgorithms,typeOfCipheringAlgorithm:0x%x,typeOfIntegrityProtectionAlgorithm:0x%x\n",
			 decoded_mm_msg->specific_msg.security_mode_command.nassecurityalgorithms.typeOfCipheringAlgorithm,
			 decoded_mm_msg->specific_msg.security_mode_command.nassecurityalgorithms.typeOfIntegrityProtectionAlgorithm );
	 printf("naskeysetidentifier,tsc:0x%x,naskeysetidentifier:0x%x\n",
			 decoded_mm_msg->specific_msg.security_mode_command.naskeysetidentifier.tsc,
			 decoded_mm_msg->specific_msg.security_mode_command.naskeysetidentifier.naskeysetidentifier);
	 printf("uesecuritycapability.nea:0x%x,nia:0x%x\n",
			 decoded_mm_msg->specific_msg.security_mode_command.uesecuritycapability.nea,
			 decoded_mm_msg->specific_msg.security_mode_command.uesecuritycapability.nia);

     printf("presence:0x%x\n",decoded_mm_msg->specific_msg.security_mode_command.presence);

     printf("imeisvrequest:0x%x\n",decoded_mm_msg->specific_msg.security_mode_command.imeisvrequest);

	 printf("epsnassecurityalgorithms, typeOfCipheringAlgoithm:0x%x,typeOfIntegrityProtectionAlgoithm:0x%x\n",
			 decoded_mm_msg->specific_msg.security_mode_command.epsnassecurityalgorithms.typeOfCipheringAlgoithm,
			 decoded_mm_msg->specific_msg.security_mode_command.epsnassecurityalgorithms.typeOfIntegrityProtectionAlgoithm);

	 printf("additional5gsecurityinformation,hdp:0x%x,rinmr:0x%x\n",
			 decoded_mm_msg->specific_msg.security_mode_command.additional5gsecurityinformation.hdp,
			 decoded_mm_msg->specific_msg.security_mode_command.additional5gsecurityinformation.rinmr);

	 printf("eap message buffer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.security_mode_command.eapmessage)->data));
	 printf("abba buffer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.security_mode_command.abba)->data));

	 printf("SECURITY_MODE_COMMAND------------ END\n");
     return 0;
}
int security_mode_complete()
{
     printf("SECURITY_MODE_COMPLETE------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = SECURITY_MODE_COMPLETE;

	 memset (&mm_msg->specific_msg.security_mode_complete,		 0, sizeof (security_mode_complete_msg));

     mm_msg->specific_msg.security_mode_complete.presence = 0x07;


     bstring nasmsgcontainer = bfromcstralloc(10, "\0");
     uint8_t bitStream_nasmsgcontainer = 0b00110101;
     nasmsgcontainer->data = (unsigned char *)(&bitStream_nasmsgcontainer);
     nasmsgcontainer->slen = 1;

	 mm_msg->specific_msg.security_mode_complete.nasmessagecontainer =  nasmsgcontainer;


	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif
     printf("encode-------------------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("presence:0x%x\n",mm_msg->specific_msg.security_mode_complete.presence);
	 printf("nasmessagecontainer:0x%x\n",*(unsigned char *)((mm_msg->specific_msg.security_mode_complete.nasmessagecontainer)->data));

	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<20;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 printf("decode-------------------------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;
	 printf("message type:0x%x\n", decoded_mm_msg->header.message_type);


	 printf("presence:0x%x\n",decoded_mm_msg->specific_msg.security_mode_complete.presence);
	 printf("nasmessagecontainer:0x%x\n",*(unsigned char *)((decoded_mm_msg->specific_msg.security_mode_complete.nasmessagecontainer)->data));

	 printf("SECURITY_MODE_COMPLETE------------ END\n");
    return 0;
}
int security_mode_reject()
{
    printf("SECURITY_MODE_REJECT------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 MM_msg * mm_msg = &nas_msg.plain.mm;
	 mm_msg->header.extended_protocol_discriminator = FIVEGS_MOBILITY_MANAGEMENT_MESSAGES;
	 mm_msg->header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 mm_msg->header.message_type = SECURITY_MODE_REJECT;

	 memset (&mm_msg->specific_msg.security_mode_reject,		 0, sizeof (security_mode_reject_msg));

     mm_msg->specific_msg.security_mode_reject._5gmmcause = 0x19;


	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 nas_msg.security_protected.plain.mm = *mm_msg;

	 //complete mm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif
     printf("encode-------------------------\n");
	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);

	 printf("message type:0x%x\n",mm_msg->header.message_type);
	 printf("_5gmmcause:0x%x\n",mm_msg->specific_msg.security_mode_reject._5gmmcause);


	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 #if 0
	 for(;i<20;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 #endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 printf("decode-------------------------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 MM_msg * decoded_mm_msg = &decoded_nas_msg.plain.mm;
	 printf("message type:0x%x\n", decoded_mm_msg->header.message_type);
	 printf("_5gmmcause:0x%x\n", decoded_mm_msg->specific_msg.security_mode_reject._5gmmcause);

	 printf("SECURITY_MODE_REJECT------------ END\n");
     return 0;

}
#endif

#define BUF_LEN 512
int  establishment_request(void)
{
     printf("PDU_SESSION_ESTABLISHMENT_REQUEST------------ start\n");
     int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	 int bytes = 0;

	 nas_message_t	nas_msg;
	 memset (&nas_msg,		 0, sizeof (nas_message_t));

	 nas_msg.header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	 nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	 uint8_t sequencenumber = 0xfe;
	 //uint32_t mac = 0xffffeeee;
	 uint32_t mac = 0xffee;
	 nas_msg.header.sequence_number = sequencenumber;
	 nas_msg.header.message_authentication_code= mac;

	 nas_msg.security_protected.header = nas_msg.header;

	 SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	 sm_msg = &nas_msg.security_protected.plain.sm;
	 sm_msg->header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	 sm_msg->header.pdu_session_identity = 1;
     sm_msg->header.proeduer_transaction_identity = 1;
	 sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REQUEST;

/*********************sm_msg->specific_msg.pdu_session_establishment_request statr******************************/
	 
	 //memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));

     #if 0
	 sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocoldiscriminator = 0X2E;

	
	 bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	 uint8_t bitStream_pdusessionidentity = 0X01;
	 pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	 pdusessionidentity_tmp->slen = 1;
	 sm_msg->specific_msg.pdu_session_establishment_request.pdusessionidentity = pdusessionidentity_tmp;

	 bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	 uint8_t bitStream_proceduretransactionidentity = 0X01;
	 proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	 proceduretransactionidentity_tmp->slen = 1;
     sm_msg->specific_msg.pdu_session_establishment_request.proceduretransactionidentity = proceduretransactionidentity_tmp;

     sm_msg->specific_msg.pdu_session_establishment_request.messagetype = 0XC1;
     #endif


	 unsigned char bitStream_intergrityprotectionmaximumdatarate[2] = {0x01,0x02};
     bstring intergrityprotectionmaximumdatarate_tmp = bfromcstralloc(2, "\0");
     //intergrityprotectionmaximumdatarate_tmp->data = bitStream_intergrityprotectionmaximumdatarate;
     intergrityprotectionmaximumdatarate_tmp->slen = 2;
     memcpy(intergrityprotectionmaximumdatarate_tmp->data,bitStream_intergrityprotectionmaximumdatarate,sizeof(bitStream_intergrityprotectionmaximumdatarate));
     sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate = intergrityprotectionmaximumdatarate_tmp;

     sm_msg->specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value = 0x01;

     sm_msg->specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value = 0x01;

     sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported = MPTCP_FUNCTIONALITY_SUPPORTED;
	 sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported = EATSSS_LOW_LAYER_FUNCTIONALITY_NOT_SUPPORTED;
	 sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported = ETHERNET_PDN_TYPE_IN_S1_MODE_SUPPORTED;
	 sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported = MULTI_HOMED_IPV6_PDU_SESSION_SUPPORTED;
	 sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported = REFLECTIVE_QOS_NOT_SUPPORTED;

     
     sm_msg->specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters = 0x3ff;

     
     sm_msg->specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested = ALWAYSON_PDU_SESSION_REQUESTED;

     unsigned char bitStream_smpdudnrequestcontainer[3];
     bitStream_smpdudnrequestcontainer[0] = 0x11;
     bitStream_smpdudnrequestcontainer[1] = 0x22;
     bitStream_smpdudnrequestcontainer[2] = 0x33;
     bstring smpdudnrequestcontainer_tmp = bfromcstralloc(3, "\0");
     //smpdudnrequestcontainer_tmp->data = bitStream_smpdudnrequestcontainer;
     smpdudnrequestcontainer_tmp->slen = 3;
     memcpy(smpdudnrequestcontainer_tmp->data,bitStream_smpdudnrequestcontainer,sizeof(bitStream_smpdudnrequestcontainer));
     sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer = smpdudnrequestcontainer_tmp;

     unsigned char bitStream_extendedprotocolconfigurationoptions[4];
     bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
     bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
     bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
     bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
     bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
     //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
     extendedprotocolconfigurationoptions_tmp->slen = 4;
     memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
     sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

/*********************sm_msg->specific_msg.pdu_session_establishment_request end******************************/

	 size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	 //memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	 printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
	 nas_msg.plain.sm = *sm_msg;

	 //complete sm msg content
	 if(size <= 0){
	   return -1;
	 }

	 //construct security context
	 fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	 security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	 security->dl_count.overflow = 0xffff;
	 security->dl_count.seq_num =  0x23;
	 security->knas_enc[0] = 0x14;
	 security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	 security->knas_int[0] = 0x41;
	 //complete sercurity context

	 int length = BUF_LEN;
	 unsigned char data[BUF_LEN] = {'\0'};

	 bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	 #if 0
	 printf("1 start nas_message_encode \n");
	 printf("security %p\n",security);
	 printf("info %p\n",info);
	 #endif

	 printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 nas_msg.header.extended_protocol_discriminator,
	 nas_msg.header.security_header_type,
	 nas_msg.header.sequence_number,
	 nas_msg.header.message_authentication_code);



	 printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
	 sm_msg->header.extended_protocol_discriminator,
     sm_msg->header.pdu_session_identity,
	 sm_msg->header.proeduer_transaction_identity,
	 sm_msg->header.message_type);

     //printf("message type:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.messagetype);
     //printf("extendedprotocoldiscriminator:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocoldiscriminator);
     //printf("pdu identity buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_establishment_request.pdusessionidentity)->data));
     //printf("PTI buffer:0x%x\n",*(unsigned char *)((sm_msg->specific_msg.pdu_session_establishment_request.proceduretransactionidentity)->data));

	 printf("intergrity buffer:0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[0]),(unsigned char )((sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[1]));
     printf("_pdusessiontype bits_3:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
     printf("sscmode bits_3:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value);
     printf("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported,sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported);
     printf("maximum bits_11:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters);
     printf("Always-on bits_1 --- APSR:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested);
     printf("sm_pdu_dn buffer:0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[2]));
     printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[3]));

	 //bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	 bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	 //printf("2 nas_message_encode over\n");

	 int i = 0;

	 //#if 0
	 for(;i<20;i++)
	   printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	 //#endif

	 info->data = data;
	 info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	 //printf("start nas_message_decode bytes:%d\n", bytes);
	 bstring plain_msg = bstrcpy(info);
	 nas_message_security_header_t header = {0};
	 //fivegmm_security_context_t  * security = NULL;
	 nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	 nas_message_t	decoded_nas_msg;
	 memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	 int decoder_rc = RETURNok;
	 printf("calling nas_message_decode-----------\n");
	 //decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	 decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


     printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	 decoded_nas_msg.header.extended_protocol_discriminator,
	 decoded_nas_msg.header.security_header_type,
	 decoded_nas_msg.header.sequence_number,
	 decoded_nas_msg.header.message_authentication_code);

	 SM_msg * decoded_sm_msg = &decoded_nas_msg.plain.sm;
   
	 printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n", decoded_sm_msg->header.extended_protocol_discriminator,
    decoded_sm_msg->header.pdu_session_identity,
	decoded_sm_msg->header.proeduer_transaction_identity,
	decoded_sm_msg->header.message_type);

	printf("decoded_nas_msg.security_protected.plain.sm = %d\n",sizeof(decoded_nas_msg.security_protected.plain.sm));

     //printf("message type:0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_request.messagetype);
     //printf("extendedprotocoldiscriminator:0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocoldiscriminator);
     //printf("pdu identity buffer:0x%x\n",*(unsigned char *)((decoded_sm_msg->specific_msg.pdu_session_establishment_request.pdusessionidentity)->data));
     //printf("PTI buffer:0x%x\n",*(unsigned char *)((decoded_sm_msg->specific_msg.pdu_session_establishment_request.proceduretransactionidentity)->data));

	 printf("intergrity buffer:0x%x 0x%x\n",(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[0]),(unsigned char )((decoded_sm_msg->specific_msg.pdu_session_establishment_request.intergrityprotectionmaximumdatarate)->data[1]));
     printf("_pdusessiontype bits_3:0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_request._pdusessiontype.pdu_session_type_value);
     printf("sscmode bits_3:0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_request.sscmode.ssc_mode_value);
     printf("_5gsmcapability bits_5 --- MPTCP:0x%x ATS-LL:0x%x EPT-S1:0x%x MH6-PDU:0x%x RqoS:0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MPTCP_supported,decoded_sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_ATSLL_supported,decoded_sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_EPTS1_supported,decoded_sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_MH6PDU_supported,decoded_sm_msg->specific_msg.pdu_session_establishment_request._5gsmcapability.is_Rqos_supported);
     printf("maximum bits_11:0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_request.maximumnumberofsupportedpacketfilters);
     printf("Always-on bits_1 --- APSR:0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_request.alwaysonpdusessionrequested.apsr_requested);
     printf("sm_pdu_dn buffer:0x%x 0x%x 0x%x\n",(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[0]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[1]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_request.smpdudnrequestcontainer)->data[2]));
     printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_request.extendedprotocolconfigurationoptions)->data[3]));

     printf("PDU_SESSION_ESTABLISHMENT_REQUEST------------ end\n");
     return  0;
}

int establishment_accept(void)
{
	return 0;
}

int establishment_reject(void)
{
	printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.proeduer_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_ESTABLISHMENT_REJECT;

/*********************sm_msg->specific_msg.pdu_session_establishment_reject statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocoldiscriminator = 0X2E;

	
	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_establishment_reject.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_establishment_reject.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_establishment_reject.messagetype = 0XC1;
    #endif

	sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause = 0b00001000;
	
	sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit = VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
	sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue = 0;
	
	sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed = SSC_MODE1_ALLOWED;
	sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed = SSC_MODE2_NOT_ALLOWED;
	sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed = SSC_MODE3_ALLOWED;

	unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
	sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage = eapmessage_tmp;

	unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
	sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

	sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;

/*********************sm_msg->specific_msg.pdu_session_establishment_reject end******************************/
	
	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

	printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
			nas_msg.header.extended_protocol_discriminator,
			nas_msg.header.security_header_type,
			nas_msg.header.sequence_number,
			nas_msg.header.message_authentication_code);



	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
	sm_msg->header.extended_protocol_discriminator,
    sm_msg->header.pdu_session_identity,
	sm_msg->header.proeduer_transaction_identity,
	sm_msg->header.message_type);

   
	printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause);
    printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit,sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
	printf("allowedsscmode --- is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
	printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
    printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);


	//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	//printf("2 nas_message_encode over\n");

	int i = 0;

	//#if 0
	for(;i<20;i++)
		printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	//#endif

	info->data = data;
	info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	//printf("start nas_message_decode bytes:%d\n", bytes);
	bstring plain_msg = bstrcpy(info);
	nas_message_security_header_t header = {0};
	//fivegmm_security_context_t  * security = NULL;
	nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	nas_message_t	decoded_nas_msg;
	memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	int decoder_rc = RETURNok;
	printf("calling nas_message_decode-----------\n");
	//decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


    printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	decoded_nas_msg.header.extended_protocol_discriminator,
	decoded_nas_msg.header.security_header_type,
	decoded_nas_msg.header.sequence_number,
	decoded_nas_msg.header.message_authentication_code);

	SM_msg * decoded_sm_msg = &decoded_nas_msg.plain.sm;
   
	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n", decoded_sm_msg->header.extended_protocol_discriminator,
    decoded_sm_msg->header.pdu_session_identity,
	decoded_sm_msg->header.proeduer_transaction_identity,
	decoded_sm_msg->header.message_type);

	printf("decoded_nas_msg.security_protected.plain.sm = %d\n",sizeof(decoded_nas_msg.security_protected.plain.sm));

    
	printf("_5gsmcause: 0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcause);
	printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.unit,decoded_sm_msg->specific_msg.pdu_session_establishment_reject.gprstimer3.timeValue);
	printf("allowedsscmode --- is_ssc1_allowed: 0x%x, is_ssc2_allowed: 0x%x, is_ssc3_allowed: 0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc1_allowed,decoded_sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc2_allowed,decoded_sm_msg->specific_msg.pdu_session_establishment_reject.allowedsscmode.is_ssc3_allowed);
	printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(decoded_sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[0]),(unsigned char )(decoded_sm_msg->specific_msg.pdu_session_establishment_reject.eapmessage->data[1]));
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_establishment_reject.extendedprotocolconfigurationoptions)->data[3]));
	printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",decoded_sm_msg->specific_msg.pdu_session_establishment_reject._5gsmcongestionreattemptindicator.abo);
    
    printf("PDU_SESSION_ESTABLISHMENT_REJECT------------ end\n");
	return  0;
}

int authentication_command(void)
{
	printf("PDU_SESSION_AUTHENTICATION_COMMAND------------ start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.proeduer_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_COMMAND;

/*********************sm_msg->specific_msg.pdu_session_authentication_command statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocoldiscriminator = 0X2E;

	
	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_authentication_command.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_authentication_command.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_authentication_command.messagetype = 0XC1;
    #endif

	unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
	sm_msg->specific_msg.pdu_session_authentication_command.eapmessage = eapmessage_tmp;

	unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
	sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

/*********************sm_msg->specific_msg.pdu_session_authentication_command end******************************/
	
	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

	printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
			nas_msg.header.extended_protocol_discriminator,
			nas_msg.header.security_header_type,
			nas_msg.header.sequence_number,
			nas_msg.header.message_authentication_code);



	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
	sm_msg->header.extended_protocol_discriminator,
    sm_msg->header.pdu_session_identity,
	sm_msg->header.proeduer_transaction_identity,
	sm_msg->header.message_type);

   
	printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_authentication_command.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_authentication_command.eapmessage->data[1]));
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[3]));
    

	//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	//printf("2 nas_message_encode over\n");

	int i = 0;

	//#if 0
	for(;i<20;i++)
		printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	//#endif

	info->data = data;
	info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	//printf("start nas_message_decode bytes:%d\n", bytes);
	bstring plain_msg = bstrcpy(info);
	nas_message_security_header_t header = {0};
	//fivegmm_security_context_t  * security = NULL;
	nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	nas_message_t	decoded_nas_msg;
	memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	int decoder_rc = RETURNok;
	printf("calling nas_message_decode-----------\n");
	//decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


    printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	decoded_nas_msg.header.extended_protocol_discriminator,
	decoded_nas_msg.header.security_header_type,
	decoded_nas_msg.header.sequence_number,
	decoded_nas_msg.header.message_authentication_code);

	SM_msg * decoded_sm_msg = &decoded_nas_msg.plain.sm;
   
	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n", decoded_sm_msg->header.extended_protocol_discriminator,
    decoded_sm_msg->header.pdu_session_identity,
	decoded_sm_msg->header.proeduer_transaction_identity,
	decoded_sm_msg->header.message_type);

	printf("decoded_nas_msg.security_protected.plain.sm = %d\n",sizeof(decoded_nas_msg.security_protected.plain.sm));

    
	printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(decoded_sm_msg->specific_msg.pdu_session_authentication_command.eapmessage->data[0]),(unsigned char )(decoded_sm_msg->specific_msg.pdu_session_authentication_command.eapmessage->data[1]));
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_command.extendedprotocolconfigurationoptions)->data[3]));
	
    printf("PDU_SESSION_AUTHENTICATION_COMMAND------------ end\n");
	return  0;
}

int authentication_complete(void)
{
	printf("PDU_SESSION_AUTHENTICATION_COMPLETE------------ start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.proeduer_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_COMPLETE;

/*********************sm_msg->specific_msg.pdu_session_authentication_complete statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocoldiscriminator = 0X2E;

	
	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_authentication_complete.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_authentication_complete.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_authentication_complete.messagetype = 0XC1;
    #endif

	unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
	sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage = eapmessage_tmp;

	unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
	sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

/*********************sm_msg->specific_msg.pdu_session_authentication_complete end******************************/
	
	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

	printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
			nas_msg.header.extended_protocol_discriminator,
			nas_msg.header.security_header_type,
			nas_msg.header.sequence_number,
			nas_msg.header.message_authentication_code);



	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
	sm_msg->header.extended_protocol_discriminator,
    sm_msg->header.pdu_session_identity,
	sm_msg->header.proeduer_transaction_identity,
	sm_msg->header.message_type);

   
	printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage->data[1]));
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[3]));
    

	//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	//printf("2 nas_message_encode over\n");

	int i = 0;

	//#if 0
	for(;i<20;i++)
		printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	//#endif

	info->data = data;
	info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	//printf("start nas_message_decode bytes:%d\n", bytes);
	bstring plain_msg = bstrcpy(info);
	nas_message_security_header_t header = {0};
	//fivegmm_security_context_t  * security = NULL;
	nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	nas_message_t	decoded_nas_msg;
	memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	int decoder_rc = RETURNok;
	printf("calling nas_message_decode-----------\n");
	//decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


    printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	decoded_nas_msg.header.extended_protocol_discriminator,
	decoded_nas_msg.header.security_header_type,
	decoded_nas_msg.header.sequence_number,
	decoded_nas_msg.header.message_authentication_code);

	SM_msg * decoded_sm_msg = &decoded_nas_msg.plain.sm;
   
	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n", decoded_sm_msg->header.extended_protocol_discriminator,
    decoded_sm_msg->header.pdu_session_identity,
	decoded_sm_msg->header.proeduer_transaction_identity,
	decoded_sm_msg->header.message_type);

	printf("decoded_nas_msg.security_protected.plain.sm = %d\n",sizeof(decoded_nas_msg.security_protected.plain.sm));

    
	printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(decoded_sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage->data[0]),(unsigned char )(decoded_sm_msg->specific_msg.pdu_session_authentication_complete.eapmessage->data[1]));
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_complete.extendedprotocolconfigurationoptions)->data[3]));
	
    printf("PDU_SESSION_AUTHENTICATION_COMPLETE------------ end\n");
	return  0;
}

int authentication_result(void)
{
	printf("PDU_SESSION_AUTHENTICATION_RESULT------------ start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.proeduer_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_AUTHENTICATION_RESULT;

/*********************sm_msg->specific_msg.pdu_session_authentication_result statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocoldiscriminator = 0X2E;

	
	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_authentication_result.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_authentication_result.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_authentication_result.messagetype = 0XC1;
    #endif

	unsigned char bitStream_eapmessage[2] = {0x01,0x02};
    bstring eapmessage_tmp = bfromcstralloc(2, "\0");
    eapmessage_tmp->slen = 2;
    memcpy(eapmessage_tmp->data,bitStream_eapmessage,sizeof(bitStream_eapmessage));
	sm_msg->specific_msg.pdu_session_authentication_result.eapmessage = eapmessage_tmp;

	unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
	sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

/*********************sm_msg->specific_msg.pdu_session_authentication_result end******************************/
	
	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

	printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
			nas_msg.header.extended_protocol_discriminator,
			nas_msg.header.security_header_type,
			nas_msg.header.sequence_number,
			nas_msg.header.message_authentication_code);



	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
	sm_msg->header.extended_protocol_discriminator,
    sm_msg->header.pdu_session_identity,
	sm_msg->header.proeduer_transaction_identity,
	sm_msg->header.message_type);

   
	printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(sm_msg->specific_msg.pdu_session_authentication_result.eapmessage->data[0]),(unsigned char )(sm_msg->specific_msg.pdu_session_authentication_result.eapmessage->data[1]));
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[3]));
    

	//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	//printf("2 nas_message_encode over\n");

	int i = 0;

	//#if 0
	for(;i<20;i++)
		printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	//#endif

	info->data = data;
	info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	//printf("start nas_message_decode bytes:%d\n", bytes);
	bstring plain_msg = bstrcpy(info);
	nas_message_security_header_t header = {0};
	//fivegmm_security_context_t  * security = NULL;
	nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	nas_message_t	decoded_nas_msg;
	memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	int decoder_rc = RETURNok;
	printf("calling nas_message_decode-----------\n");
	//decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


    printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	decoded_nas_msg.header.extended_protocol_discriminator,
	decoded_nas_msg.header.security_header_type,
	decoded_nas_msg.header.sequence_number,
	decoded_nas_msg.header.message_authentication_code);

	SM_msg * decoded_sm_msg = &decoded_nas_msg.plain.sm;
   
	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n", decoded_sm_msg->header.extended_protocol_discriminator,
    decoded_sm_msg->header.pdu_session_identity,
	decoded_sm_msg->header.proeduer_transaction_identity,
	decoded_sm_msg->header.message_type);

	printf("decoded_nas_msg.security_protected.plain.sm = %d\n",sizeof(decoded_nas_msg.security_protected.plain.sm));

    
	printf("eapmessage buffer:0x%x 0x%x\n",(unsigned char)(decoded_sm_msg->specific_msg.pdu_session_authentication_result.eapmessage->data[0]),(unsigned char )(decoded_sm_msg->specific_msg.pdu_session_authentication_result.eapmessage->data[1]));
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_authentication_result.extendedprotocolconfigurationoptions)->data[3]));
	
    printf("PDU_SESSION_AUTHENTICATION_RESULT------------ end\n");
	return  0;
}

int modification_request(void)
{
	return 0;
}

int modification_reject(void)
{
	printf("PDU_SESSION_MODIFICATION_REJECT------------ start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.proeduer_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_MODIFICATION_REJECT;

/*********************sm_msg->specific_msg.pdu_session_modification_reject statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocoldiscriminator = 0X2E;

	
	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_modification_reject.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_modification_reject.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_modification_reject.messagetype = 0XC1;
    #endif

	sm_msg->specific_msg.pdu_session_modification_reject._5gsmcause = 0b00001000;
	
	sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.unit = VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR;
	sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.timeValue = 0;
	
	unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
	sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

	sm_msg->specific_msg.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo = THE_BACKOFF_TIMER_IS_APPLIED_IN_ALL_PLMNS;

/*********************sm_msg->specific_msg.pdu_session_modification_reject end******************************/
	
	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

	printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
			nas_msg.header.extended_protocol_discriminator,
			nas_msg.header.security_header_type,
			nas_msg.header.sequence_number,
			nas_msg.header.message_authentication_code);



	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
	sm_msg->header.extended_protocol_discriminator,
    sm_msg->header.pdu_session_identity,
	sm_msg->header.proeduer_transaction_identity,
	sm_msg->header.message_type);

   
	printf("_5gsmcause: 0x%x\n",sm_msg->specific_msg.pdu_session_modification_reject._5gsmcause);
    printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.unit,sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.timeValue);
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[3]));
    printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",sm_msg->specific_msg.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo);


	//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	//printf("2 nas_message_encode over\n");

	int i = 0;

	//#if 0
	for(;i<20;i++)
		printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	//#endif

	info->data = data;
	info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	//printf("start nas_message_decode bytes:%d\n", bytes);
	bstring plain_msg = bstrcpy(info);
	nas_message_security_header_t header = {0};
	//fivegmm_security_context_t  * security = NULL;
	nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	nas_message_t	decoded_nas_msg;
	memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	int decoder_rc = RETURNok;
	printf("calling nas_message_decode-----------\n");
	//decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


    printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	decoded_nas_msg.header.extended_protocol_discriminator,
	decoded_nas_msg.header.security_header_type,
	decoded_nas_msg.header.sequence_number,
	decoded_nas_msg.header.message_authentication_code);

	SM_msg * decoded_sm_msg = &decoded_nas_msg.plain.sm;
   
	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n", decoded_sm_msg->header.extended_protocol_discriminator,
    decoded_sm_msg->header.pdu_session_identity,
	decoded_sm_msg->header.proeduer_transaction_identity,
	decoded_sm_msg->header.message_type);

	printf("decoded_nas_msg.security_protected.plain.sm = %d\n",sizeof(decoded_nas_msg.security_protected.plain.sm));

    
	printf("_5gsmcause: 0x%x\n",decoded_sm_msg->specific_msg.pdu_session_modification_reject._5gsmcause);
	printf("gprstimer3 --- unit_bits_H3: 0x%x,timeValue_bits_L5: 0x%x\n",decoded_sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.unit,decoded_sm_msg->specific_msg.pdu_session_modification_reject.gprstimer3.timeValue);
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_modification_reject.extendedprotocolconfigurationoptions)->data[3]));
	printf("_5gsmcongestionreattemptindicator bits_1 --- abo:0x%x\n",decoded_sm_msg->specific_msg.pdu_session_modification_reject._5gsmcongestionreattemptindicator.abo);
    
    printf("PDU_SESSION_MODIFICATION_REJECT------------ end\n");
	return  0;
}

int modification_command(void)
{
	
	return  0;
}

int modification_complete(void)
{
	printf("PDU_SESSION_MODIFICATION_COMPLETE------------ start\n");
	int size = NAS_MESSAGE_SECURITY_HEADER_SIZE;
	int bytes = 0;

	nas_message_t	nas_msg;
	memset (&nas_msg,		 0, sizeof (nas_message_t));
	nas_msg.header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	nas_msg.header.security_header_type = SECURITY_HEADER_TYPE_INTEGRITY_PROTECTED_CYPHERED;
	uint8_t sequencenumber = 0xfe;
	//uint32_t mac = 0xffffeeee;
	uint32_t mac = 0xffee;
	nas_msg.header.sequence_number = sequencenumber;
	nas_msg.header.message_authentication_code= mac;
	nas_msg.security_protected.header = nas_msg.header;
	SM_msg * sm_msg;
	// memset (&sm_msg->specific_msg.pdu_session_establishment_request,		 0, sizeof (pdu_session_establishment_request_msg));
	sm_msg = &nas_msg.security_protected.plain.sm;
	sm_msg->header.extended_protocol_discriminator = FIVEGS_SESSION_MANAGEMENT_MESSAGES;
	sm_msg->header.pdu_session_identity = 1;
    sm_msg->header.proeduer_transaction_identity = 1;
	sm_msg->header.message_type = PDU_SESSION_MODIFICATION_COMPLETE;

/*********************sm_msg->specific_msg.pdu_session_modification_complete statr******************************/

    #if 0
	sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocoldiscriminator = 0X2E;

	
	bstring pdusessionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_pdusessionidentity = 0X01;
	pdusessionidentity_tmp->data = (unsigned char *)(&bitStream_pdusessionidentity);
	pdusessionidentity_tmp->slen = 1;
	sm_msg->specific_msg.pdu_session_modification_complete.pdusessionidentity = pdusessionidentity_tmp;

	bstring proceduretransactionidentity_tmp = bfromcstralloc(10, "\0");
	uint8_t bitStream_proceduretransactionidentity = 0X01;
	proceduretransactionidentity_tmp->data = (unsigned char *)(&bitStream_proceduretransactionidentity);
	proceduretransactionidentity_tmp->slen = 1;
    sm_msg->specific_msg.pdu_session_modification_complete.proceduretransactionidentity = proceduretransactionidentity_tmp;

    sm_msg->specific_msg.pdu_session_modification_complete.messagetype = 0XC1;
    #endif

	unsigned char bitStream_extendedprotocolconfigurationoptions[4];
    bitStream_extendedprotocolconfigurationoptions[0] = 0x12;
    bitStream_extendedprotocolconfigurationoptions[1] = 0x13;
    bitStream_extendedprotocolconfigurationoptions[2] = 0x14;
    bitStream_extendedprotocolconfigurationoptions[3] = 0x15;
    bstring extendedprotocolconfigurationoptions_tmp = bfromcstralloc(4, "\0");
    //extendedprotocolconfigurationoptions_tmp->data = bitStream_extendedprotocolconfigurationoptions;
    extendedprotocolconfigurationoptions_tmp->slen = 4;
    memcpy(extendedprotocolconfigurationoptions_tmp->data,bitStream_extendedprotocolconfigurationoptions,sizeof(bitStream_extendedprotocolconfigurationoptions));
	sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions = extendedprotocolconfigurationoptions_tmp;

	
/*********************sm_msg->specific_msg.pdu_session_modification_complete end******************************/
	
	size += MESSAGE_TYPE_MAXIMUM_LENGTH;

	//memcpy(&nas_msg.plain.sm,&nas_msg.security_protected.plain.sm,sizeof(nas_msg.security_protected.plain.sm));
	printf("nas_msg.security_protected.plain.sm = %d\n",sizeof(nas_msg.security_protected.plain.sm));
	nas_msg.plain.sm = *sm_msg;

	//complete sm msg content
	if(size <= 0){
		return -1;
	}

	//construct security context
	fivegmm_security_context_t * security = calloc(1,sizeof(fivegmm_security_context_t));
	security->selected_algorithms.encryption = NAS_SECURITY_ALGORITHMS_NEA1;
	security->dl_count.overflow = 0xffff;
	security->dl_count.seq_num =  0x23;
	security->knas_enc[0] = 0x14;
	security->selected_algorithms.integrity = NAS_SECURITY_ALGORITHMS_NIA1;
	security->knas_int[0] = 0x41;
	//complete sercurity context

	int length = BUF_LEN;
	unsigned char data[BUF_LEN] = {'\0'};

	bstring  info = bfromcstralloc(length, "\0");//info the nas_message_encode result

	#if 0
	printf("1 start nas_message_encode \n");
	printf("security %p\n",security);
	printf("info %p\n",info);
	#endif

	printf("nas header encode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
			nas_msg.header.extended_protocol_discriminator,
			nas_msg.header.security_header_type,
			nas_msg.header.sequence_number,
			nas_msg.header.message_authentication_code);



	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n",
	sm_msg->header.extended_protocol_discriminator,
    sm_msg->header.pdu_session_identity,
	sm_msg->header.proeduer_transaction_identity,
	sm_msg->header.message_type);

   
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[3]));
    

	//bytes = nas_message_encode (data, &nas_msg, 60/*don't know the size*/, security);
	bytes = nas_message_encode (data, &nas_msg, sizeof(data)/*don't know the size*/, security);


	//printf("2 nas_message_encode over\n");

	int i = 0;

	//#if 0
	for(;i<20;i++)
		printf("nas msg byte test bype[%d] = 0x%x\n",i,data[i]);
	//#endif

	info->data = data;
	info->slen = bytes;


   /*************************************************************************************************************************/
   /*********	  NAS DECODE	 ***********************/
   /************************************************************************************************************************/

	//printf("start nas_message_decode bytes:%d\n", bytes);
	bstring plain_msg = bstrcpy(info);
	nas_message_security_header_t header = {0};
	//fivegmm_security_context_t  * security = NULL;
	nas_message_decode_status_t   decode_status = {0};

   //  int bytes = nas_message_decrypt((*info)->data,plain_msg->data,&header,blength(*info),security,&decode_status);


	nas_message_t	decoded_nas_msg;
	memset (&decoded_nas_msg,		 0, sizeof (nas_message_t));

	int decoder_rc = RETURNok;
	printf("calling nas_message_decode-----------\n");
	//decoder_rc = nas_message_decode (plain_msg->data, &decoded_nas_msg, 60/*blength(info)*/, security, &decode_status);
	decoder_rc = nas_message_decode (data, &decoded_nas_msg, sizeof(data) /*blength(info)*/, security, &decode_status);


    printf("nas header  decode extended_protocol_discriminator:0x%x\n, security_header_type:0x%x\n,sequence_number:0x%x\n,message_authentication_code:0x%x\n",
	decoded_nas_msg.header.extended_protocol_discriminator,
	decoded_nas_msg.header.security_header_type,
	decoded_nas_msg.header.sequence_number,
	decoded_nas_msg.header.message_authentication_code);

	SM_msg * decoded_sm_msg = &decoded_nas_msg.plain.sm;
   
	printf("sm header,extended_protocol_discriminator:0x%x,pdu_session_identity:0x%x,proeduer_transaction_identity:0x%x, message type:0x%x\n", decoded_sm_msg->header.extended_protocol_discriminator,
    decoded_sm_msg->header.pdu_session_identity,
	decoded_sm_msg->header.proeduer_transaction_identity,
	decoded_sm_msg->header.message_type);

	printf("decoded_nas_msg.security_protected.plain.sm = %d\n",sizeof(decoded_nas_msg.security_protected.plain.sm));

    
	printf("extend_options buffer:0x%x 0x%x 0x%x 0x%x\n",(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[0]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[1]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[2]),(unsigned char)((decoded_sm_msg->specific_msg.pdu_session_modification_complete.extendedprotocolconfigurationoptions)->data[3]));
	
    printf("PDU_SESSION_MODIFICATION_COMPLETE------------ end\n");
	return 0;
}

int modification_command_reject(void)
{
	return 0;
}

int release_request(void)
{
	return 0;
}

int release_reject(void)
{
	return 0;
}

int release_command(void)
{
	return 0;
}

int release_complete(void)
{
	return 0;
}

int _5gsm_status_(void)
{
	return 0;
}


int main()
{
  	#if 0
  	auth_request();
  	auth_response();
  	auth_failure();
  	auth_reject();
  	auth_result();


  	reg_request();
  	reg_accept();
  	reg_complete();
  	reg_reject();
  


  	//identity_request();
	//identity_response();
	
  	
  	security_mode_command();
  	security_mode_complete();
  	security_mode_reject();
  	#endif

  	CHECK_INIT_RETURN (OAILOG_INIT (MAX_LOG_ENV, OAILOG_LEVEL_DEBUG, MAX_LOG_PROTOS));
	establishment_request();
	//establishment_accept();
	establishment_reject();
	authentication_command();
	authentication_complete();
	authentication_result();
	//modification_request();
	modification_reject();
	//modification_command();
	modification_complete();
	//modification_command_reject();
	//release_request();
	//release_reject();
	//release_command();
	//release_complete();
	//_5gsm_status_();

  	return 0;
}
