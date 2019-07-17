#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "assertions.h"
#include "conversions.h"
#include "ngap_common.h"
#include "ngap_amf_ta.h"
#include "amf_config.h"

static
int
ngap_amf_compare_plmn (
  const Ngap_BroadcastPLMNItem_t * Item)
{
  int                                     i = 0;
  uint16_t                                mcc = 0;
  uint16_t                                mnc = 0;
  uint16_t                                mnc_len = 0;

  const Ngap_PLMNIdentity_t * const plmn = &Item->pLMNIdentity;

  DevAssert (plmn != NULL);
  TBCD_TO_MCC_MNC (plmn, mcc, mnc, mnc_len);

  for (i = 0; i < 1; i++) 
  {
    OAILOG_TRACE (LOG_NGAP, "Comparing plmn_mcc:%d, ,mcc:%d, plmn_mnc:%d, mnc:%d, plmn_mnc_len:%d,len:%d\n",
    amf_config.served_tai.plmn_mcc[i], mcc,
    amf_config.served_tai.plmn_mnc[i], mnc,
    amf_config.served_tai.plmn_mnc_len[i], mnc_len);
	
    if ((amf_config.served_tai.plmn_mcc[i] == mcc) &&
        (amf_config.served_tai.plmn_mnc[i] == mnc) &&
        (amf_config.served_tai.plmn_mnc_len[i] == mnc_len))
    {
       return TA_LIST_AT_LEAST_ONE_MATCH;
    }
  }

  return TA_LIST_NO_MATCH;
}

static
  int
ngap_amf_compare_plmns (
  Ngap_BroadcastPLMNList_t * b_plmns)
{
  int                                     i =0;
  int                                     matching_occurence = 0;

  DevAssert (b_plmns != NULL);

  for (i = 0; i < b_plmns->list.count; i++) 
  {
     if (ngap_amf_compare_plmn (b_plmns->list.array[i]) == TA_LIST_AT_LEAST_ONE_MATCH)
     {
        matching_occurence++;
     }
  }

  if (matching_occurence == 0)
    return TA_LIST_NO_MATCH;
  else if (matching_occurence == b_plmns->list.count - 1)
    return TA_LIST_COMPLETE_MATCH;
  else
    return TA_LIST_AT_LEAST_ONE_MATCH;
}

static
  int
ngap_amf_compare_tac (
  const Ngap_TAC_t * const tac)
{
  int                                     i = 0;
  uint16_t                                tac_value = 0;

  DevAssert (tac != NULL);
  //OCTET_STRING_TO_TAC(tac, tac_value);
  OCTET_STRING_TO_TAC_24 (tac, tac_value);

  for(; i < amf_config.served_tai.nb_tai; i++)
  {
      OAILOG_DEBUG(LOG_NGAP,  "ngap_amf_compare_tac, tac:%u, tac_value:%u \n" ,
	  amf_config.served_tai.tac[i], tac_value);
	  
      if(amf_config.served_tai.tac[i] == tac_value)
      {
         return TA_LIST_AT_LEAST_ONE_MATCH;   
	  }
  }

  #if 0
  for (i = 0; i < 1; i++) {
    OAILOG_TRACE (LOG_NGAP, "Comparing config tac %d, received tac = %d\n", 1, tac_value);

    if (1 == tac_value)
      return TA_LIST_AT_LEAST_ONE_MATCH;
  }
  #endif

  return TA_LIST_NO_MATCH;
}

int                                         
ngap_amf_compare_ta_lists (                 
  Ngap_SupportedTAList_t * ta_list)            
{   
  int                                     i;
  int                                     tac_ret,
                                          bplmn_ret;

  DevAssert (ta_list != NULL);

  for (i = 0; i < ta_list->list.count; i++) {
    Ngap_SupportedTAItem_t    *ta;

    ta = ta_list->list.array[i];
    DevAssert (ta != NULL); 
    tac_ret = ngap_amf_compare_tac (&ta->tAC);
    bplmn_ret = ngap_amf_compare_plmns (&ta->broadcastPLMNList);
                                            
    if (tac_ret == TA_LIST_NO_MATCH && bplmn_ret == TA_LIST_NO_MATCH) {
      return TA_LIST_UNKNOWN_PLMN + TA_LIST_UNKNOWN_TAC;
    } else {
      if (tac_ret > TA_LIST_NO_MATCH && bplmn_ret == TA_LIST_NO_MATCH) {
        return TA_LIST_UNKNOWN_PLMN;
      } else if (tac_ret == TA_LIST_NO_MATCH && bplmn_ret > TA_LIST_NO_MATCH) {
        return TA_LIST_UNKNOWN_TAC;
      }
    }
  }

  return TA_LIST_RET_OK;
}

