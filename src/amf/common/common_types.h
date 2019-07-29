#ifndef FILE_COMMON_TYPES_SEEN
#define FILE_COMMON_TYPES_SEEN

#include <stdint.h>
#include "3gpp_38.401.h"
#include "3gpp_23.003.h"
#include "3gpp_24.007.h"
#include "3gpp_ts24.501.h"
#include "3gpp_24.501.h"


typedef uint16_t                 sctp_stream_id_t;
typedef uint32_t                 sctp_assoc_id_t;



//UE NGAP IDs

#define INVALID_RAN_UE_NGAP_ID_KEY 0xFFFFFFFFFFFFFFFF
#define RAN_UE_NGAP_ID_MASK        0x00FFFFFF
#define RAN_UE_NGAP_ID_FMT         "0x%06"PRIX32
#define GNB_UE_NGAP_ID_FMT         "0x%06"PRIX32
#define AMF_UE_NGAP_ID_FMT         "0x%08"PRIX32
#define INVALID_AMF_UE_NGAP_ID  0x0


typedef uint8_t       ksi_t;
#define KSI_NO_KEY_AVAILABLE     0x07

typedef uint32_t ipv4_nbo_t;


#endif
