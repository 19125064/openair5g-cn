#ifndef FILE_3GPP_23_003_SEEN
#define FILE_3GPP_23_003_SEEN

#include <stdint.h>

typedef struct plmn_s {
  uint8_t mcc_digit2:4;
  uint8_t mcc_digit1:4;
  uint8_t mnc_digit3:4;
  uint8_t mcc_digit3:4;
  uint8_t mnc_digit2:4;
  uint8_t mnc_digit1:4;
} plmn_t;

#define INVALID_TAC_0000                  (uint16_t)0x0000
#define INVALID_TAC_FFFE                  (uint16_t)0xFFFE


#define INVALID_TMSI                   UINT32_MAX        /*!< \brief  The network shall not allocate a TMSI with all 32 bits equal to 1
                                                                        (this is because the TMSI must be stored in the SIM, and the SIM uses 4 octets with all bits
                                                                        equal to 1 to indicate that no valid TMSI is available).  */
typedef uint16_t    tac_t;

typedef struct tai_s {
  plmn_t plmn;                                             /*!< \brief  <MCC> + <MNC>        */
  tac_t  tac;                                              /*!< \brief  Tracking Area Code   */
} tai_t;

typedef struct eci_s {
  uint32_t gnb_id:20; 
  uint32_t cell_id:8;
  uint32_t empty:4;
} ci_t;

typedef struct cgi_s {
  plmn_t   plmn;
  ci_t    cell_identity;           //28 bits 
} cgi_t;



#endif
