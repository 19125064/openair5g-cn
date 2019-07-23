#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "dynamic_memory_check.h"
#include "intertask_interface.h"
#include "assertions.h"
#include "intertask_interface_types.h"
#include "common_defs.h"
#include "log.h"
#include "asn_internal.h"
#include "hashtable.h"
#include "ngap_amf.h"
#include "amf_default_values.h"
#include "amf_config.h"
#include "Ngap_NGAP-PDU.h"

uint32_t                                nb_gnb_associated = 0;
hash_table_ts_t g_ngap_gnb_coll = {.mutex = PTHREAD_MUTEX_INITIALIZER, 0};// contains gNB_description_s, key is gNB_description_s.gnb_id (uint32_t);
hash_table_ts_t g_ngap_amf_id2assoc_id_coll = {.mutex = PTHREAD_MUTEX_INITIALIZER, 0};// contains sctp association id, key is amf_ue_ngap_id;



//TODO: get config info from a configuration file
static int ngap_send_init_sctp(void)
{
  MessageDef                             *message_p = NULL;
  message_p = itti_alloc_new_message (TASK_NGAP, SCTP_INIT_MSG);
  message_p->ittiMsg.sctpInit.port = NGAP_PORT_NUMBER;
  message_p->ittiMsg.sctpInit.ppid = NGAP_SCTP_PPID;
  message_p->ittiMsg.sctpInit.ipv4 = 1;
  message_p->ittiMsg.sctpInit.ipv6 = 0;
  message_p->ittiMsg.sctpInit.nb_ipv4_addr = 1;
/*
  int intAddress = 0;
  bstring address = NULL;
  bstring mask = NULL;
  bstring cidr = NULL;
  cidr = bfromcstr ("10.112.100.100/16");
  struct bstrList *list = bsplit (cidr, '/');
  AssertFatal(2 == list->qty, "Bad CIDR address %s", bdata(cidr));
  address = list->entry[0];
  mask    = list->entry[1];
  printf("address(%s);mask(%s)\n",address->data,mask->data);
  IPV4_STR_ADDR_TO_INT_NWBO (bdata(address), intAddress, "BAD IP ADDRESS FORMAT FOR S1-MME !\n");
*/
  message_p->ittiMsg.sctpInit.ipv4_address[0] = amf_config.ipv4.ng_amf; //1684303882;//1546416138;//117506058;
  message_p->ittiMsg.sctpInit.nb_ipv6_addr = 0;
  message_p->ittiMsg.sctpInit.ipv6_address[0] = "0:0:0:0:0:0:0:1";
  return itti_send_msg_to_task (TASK_SCTP, INSTANCE_DEFAULT, message_p);
}

void
ngap_amf_thread (
  __attribute__((unused))void * args)
{
    itti_mark_task_ready (TASK_NGAP);
    OAILOG_START_USE();
    while(1) {
      MessageDef * received_message_p = NULL;
      MessagesIds   message_id = MESSAGES_ID_MAX;
      itti_receive_msg (TASK_NGAP , &received_message_p);
      DevAssert (received_message_p != NULL);
      switch(ITTI_MSG_ID (received_message_p)){
        case MESSAGE_TEST:{
            OAILOG_DEBUG(LOG_NGAP,"NGAP TEST MSG\n");
          }
          break;
        case ACTIVATE_MESSAGE:{
        	 OAILOG_DEBUG(LOG_NGAP,"ACTIVATE MESSAGE\n");
            if (ngap_send_init_sctp () < 0) {
              OAILOG_CRITICAL (LOG_NGAP, "Error while sending SCTP_INIT_MSG to SCTP\n");
            }
          }
          break;
        case SCTP_NEW_ASSOCIATION:{
            OAILOG_DEBUG(LOG_NGAP,"SCTP_NEW_ASSOCIATION\n");
            ngap_handle_new_association(&received_message_p->ittiMsg.sctp_new_peer);
          }
          break;
        case SCTP_DATA_IND:{
            OAILOG_DEBUG(LOG_NGAP,"SCTP_DATA_IND(recv N2 Messages from AN)\n");
            Ngap_NGAP_PDU_t  message = {0};
            //printf("sctp server recv buffer(%x) length(%d)\n",(SCTP_DATA_IND (received_message_p).payload)->data,(SCTP_DATA_IND (received_message_p).payload)->slen);

      #if 0
        bstring b = blk2bstr((SCTP_DATA_IND (received_message_p).payload)->data, (SCTP_DATA_IND (received_message_p).payload)->slen);
        printf("before ngap_amf_decode_pdu sctp server recv buffer length(%d)\nbuffer:\t",b->slen);
        int i=0;
        uint8_t * buffer_p = (uint8_t*)b->data;
        for(;i<b->slen;buffer_p+=sizeof(uint8_t),i++)
          printf("%x",*((uint8_t*)buffer_p));
        printf("\n");
     #endif
            if (ngap_amf_decode_pdu (&message, SCTP_DATA_IND (received_message_p).payload, &message_id) < 0) {
              OAILOG_ERROR (LOG_NGAP, "Failed to decode new buffer\n");
            } else {
              ngap_amf_handle_message (SCTP_DATA_IND (received_message_p).assoc_id,
                                   SCTP_DATA_IND (received_message_p).stream, &message);
            }
            if (message_id != MESSAGES_ID_MAX) {
              //ngap_free_amf_decode_pdu(&message, message_id);
            }
            bdestroy (SCTP_DATA_IND (received_message_p).payload);

          }
          break;
        case NGAP_NAS_DL_DATA_REQ:{
          ngap_generate_downlink_nas_transport (NGAP_NAS_DL_DATA_REQ (received_message_p).ran_ue_ngap_id,
            NGAP_NAS_DL_DATA_REQ (received_message_p).amf_ue_ngap_id,
            &NGAP_NAS_DL_DATA_REQ (received_message_p).nas_msg);
        }
        break;
        case AMF_APP_NGAP_AMF_UE_ID_NOTIFICATION:{
          ngap_handle_amf_ue_id_notification(&AMF_APP_NGAP_AMF_UE_ID_NOTIFICATION(received_message_p));
        }
        break;

      }
    itti_free (ITTI_MSG_ORIGIN_ID (received_message_p), received_message_p);
    received_message_p = NULL;
    }
    return NULL;
}

bool ngap_ue_compare_by_amf_ue_id_cb (__attribute__((unused)) const hash_key_t keyP,
                                      void * const elementP, void * parameterP, void **resultP)
{
  amf_ue_ngap_id_t                      * amf_ue_ngap_id_p = (amf_ue_ngap_id_t*)parameterP;
  ue_description_t                       *ue_ref           = (ue_description_t*)elementP;
  if ( *amf_ue_ngap_id_p == ue_ref->amf_ue_ngap_id ) {
    *resultP = elementP;
    OAILOG_TRACE(LOG_NGAP, "Found ue_ref %p amf_ue_ngap_id " AMF_UE_NGAP_ID_FMT "\n", ue_ref, ue_ref->amf_ue_ngap_id);
    return true;
  }
  return false;
}

bool ngap_gnb_find_ue_by_amf_ue_id_cb (__attribute__((unused))const hash_key_t keyP,
                                       void * const elementP, void * parameterP, void **resultP)
{
  gnb_description_t                      *gnb_ref = (gnb_description_t*)elementP;

  hashtable_ts_apply_callback_on_elements((hash_table_ts_t * const)&gnb_ref->ue_coll, ngap_ue_compare_by_amf_ue_id_cb, parameterP, resultP);
  if (*resultP) {
    OAILOG_TRACE(LOG_NGAP, "Found ue_ref %p amf_ue_ngap_id " AMF_UE_NGAP_ID_FMT "\n", *resultP, ((ue_description_t*)(*resultP))->amf_ue_ngap_id);
    return true;
  }
  return false;
}


int 
ngap_amf_init(void)
{ 
    OAILOG_FUNC_IN(LOG_NGAP);
    OAILOG_DEBUG (LOG_NGAP, "Initializing NGAP interface\n");
    //if (get_asn1c_environment_version () < ASN1_MINIMUM_VERSION) {
      //OAILOG_ERROR (LOG_NGAP, "ASN1C version %d fount, expecting at least %d\n", get_asn1c_environment_version (), ASN1_MINIMUM_VERSION);
    //  return RETURNerror;
    //} else {
      //OAILOG_DEBUG (LOG_NGAP, "ASN1C version %d\n", get_asn1c_environment_version ());
    //}
  
    //OAILOG_DEBUG (LOG_NGAP, "NGAP Release v10.5\n");

    bstring bs1 = bfromcstr("ngap_gNB_coll");
    hash_table_ts_t * h = hashtable_ts_init(&g_ngap_gnb_coll,16,NULL,free_wrapper,bs1);
    bdestroy(bs1);
    if(!h) return RETURNerror;

    bstring bs2 = bfromcstr("ngap_amf_id2assoc_id_coll");
    h = hashtable_ts_init(&g_ngap_amf_id2assoc_id_coll,16,NULL,hash_free_int_func,bs2);
    bdestroy(bs2);
    if(!h) return RETURNerror;

    if (itti_create_task (TASK_NGAP, &ngap_amf_thread, NULL) < 0) {
      OAILOG_ERROR (LOG_NGAP, "Error while creating NGAP task\n");
      return RETURNerror;
    }
    OAILOG_DEBUG (LOG_NGAP, "Create TASK NGAP\n");
    if (ngap_send_init_sctp () < 0) {
      OAILOG_ERROR (LOG_NGAP, "Error while sendind SCTP_INIT_MSG to SCTP \n");
      return RETURNerror;
    }

    OAILOG_DEBUG (LOG_NGAP, "Initializing NGAP interface: DONE\n");
    OAILOG_FUNC_RETURN(LOG_NGAP,RETURNok);
    //return RETURNok;
}


gnb_description_t                      *
ngap_is_gnb_assoc_id_in_list (
  const sctp_assoc_id_t sctp_assoc_id)
{   
  gnb_description_t                      *gnb_ref = NULL;
  hashtable_ts_get(&g_ngap_gnb_coll, (const hash_key_t)sctp_assoc_id, (void**)&gnb_ref);
  return gnb_ref;
}

gnb_description_t                      *
ngap_new_gnb (
  void)
{   
  gnb_description_t                      *gnb_ref = NULL;
    
  gnb_ref = calloc (1, sizeof (gnb_description_t));
  /*
   * Something bad happened during malloc...
   * * * * May be we are running out of memory.
   * * * * TODO: Notify eNB with a cause like Hardware Failure.
   */
  DevAssert (gnb_ref != NULL);
  // Update number of eNB associated
  //nb_gnb_associated++;
  __sync_fetch_and_add(&nb_gnb_associated, 1);
  
  bstring bs = bfromcstr("ngap_ue_coll");
  hashtable_ts_init(&gnb_ref->ue_coll,16, NULL, free_wrapper, bs);
  bdestroy(bs);
  gnb_ref->nb_ue_associated = 0;
  return gnb_ref;
}

void ngap_remove_gnb(gnb_description_t *gnb_ref)
{
   if (gnb_ref == NULL)
     return;
   hashtable_ts_destroy(&gnb_ref->ue_coll);
   hashtable_ts_free (&g_ngap_gnb_coll, gnb_ref->sctp_assoc_id);
   //nb_enb_associated--;
   __sync_fetch_and_sub(&nb_gnb_associated, 1);
}


ue_description_t                       *
ngap_is_ue_gnb_id_in_list (
  gnb_description_t * gnb_ref,              
  const ran_ue_ngap_id_t ran_ue_ngap_id)    
{   
  ue_description_t                       *ue_ref = NULL;
  hashtable_ts_get ((hash_table_ts_t * const)&gnb_ref->ue_coll, (const hash_key_t)ran_ue_ngap_id, (void **)&ue_ref);
  return ue_ref;
}

ue_description_t                       *
ngap_is_ue_amf_id_in_list (
  const amf_ue_ngap_id_t amf_ue_ngap_id)
{ 
  ue_description_t                       *ue_ref = NULL;
  amf_ue_ngap_id_t                       *amf_ue_ngap_id_p = (amf_ue_ngap_id_t*)&amf_ue_ngap_id;
  
  hashtable_ts_apply_callback_on_elements(&g_ngap_gnb_coll, ngap_gnb_find_ue_by_amf_ue_id_cb, (void*)amf_ue_ngap_id_p, (void**)&ue_ref);
  OAILOG_TRACE(LOG_NGAP, "Return ue_ref %p \n", ue_ref);
  return ue_ref;
}

ue_description_t                       *
ngap_new_ue (
  const sctp_assoc_id_t sctp_assoc_id, ran_ue_ngap_id_t ran_ue_ngap_id)
{     
  gnb_description_t                      *gnb_ref = NULL;
  ue_description_t                       *ue_ref = NULL;

  gnb_ref = ngap_is_gnb_assoc_id_in_list (sctp_assoc_id);
  DevAssert (gnb_ref != NULL);
  ue_ref = calloc (1, sizeof (ue_description_t));
  /*
   * Something bad happened during malloc...
   * * * * May be we are running out of memory.
   * * * * TODO: Notify eNB with a cause like Hardware Failure.
   */
  DevAssert (ue_ref != NULL);
  ue_ref->gnb = gnb_ref;
  ue_ref->ran_ue_ngap_id = ran_ue_ngap_id;
    
  hashtable_rc_t  hashrc = hashtable_ts_insert (&gnb_ref->ue_coll, (const hash_key_t) ran_ue_ngap_id, (void *)ue_ref);
  if (HASH_TABLE_OK != hashrc) {
    OAILOG_ERROR(LOG_NGAP, "Could not insert UE descr in ue_coll: %s\n", hashtable_rc_code2string(hashrc));
    free_wrapper((void**) &ue_ref);
    return NULL;
  }
  // Increment number of UE
  gnb_ref->nb_ue_associated++;
  return ue_ref;
}

void ngap_notified_new_ue_amf_ngap_id_association (
    const sctp_assoc_id_t  sctp_assoc_id,
    const ran_ue_ngap_id_t ran_ue_ngap_id,
    const amf_ue_ngap_id_t amf_ue_ngap_id)
{ 
  gnb_description_t   *gnb_ref =  ngap_is_gnb_assoc_id_in_list (sctp_assoc_id);
  if (gnb_ref) {
    ue_description_t   *ue_ref = ngap_is_ue_gnb_id_in_list (gnb_ref,ran_ue_ngap_id);
    if (ue_ref) {     
      ue_ref->amf_ue_ngap_id = amf_ue_ngap_id;
      hashtable_rc_t  h_rc = hashtable_ts_insert (&g_ngap_amf_id2assoc_id_coll, (const hash_key_t) amf_ue_ngap_id, (void *)(uintptr_t)sctp_assoc_id);
      OAILOG_DEBUG(LOG_NGAP, "Associated  sctp_assoc_id %d, ran_ue_ngap_id " RAN_UE_NGAP_ID_FMT ", amf_ue_ngap_id " AMF_UE_NGAP_ID_FMT ":%s \n",
          sctp_assoc_id, ran_ue_ngap_id, amf_ue_ngap_id, hashtable_rc_code2string(h_rc));
      return; 
    }
    OAILOG_DEBUG(LOG_NGAP, "Could not find  ue  with ran_ue_ngap_id " RAN_UE_NGAP_ID_FMT "\n", ran_ue_ngap_id);
    return;
  }
  OAILOG_DEBUG(LOG_NGAP, "Could not find  gNB with sctp_assoc_id %d \n", sctp_assoc_id);
}   
