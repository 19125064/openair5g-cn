/**
* Nsmf_PDUSession
* SMF PDU Session Service. © 2019, 3GPP Organizational Partners (ARIB, ATIS, CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved. 
*
* The version of the OpenAPI document: 1.1.0.alpha-1
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
/*
 * SmContextUpdatedData.h
 *
 * 
 */

#ifndef SmContextUpdatedData_H_
#define SmContextUpdatedData_H_


#include "EbiArpMapping.h"
#include "Cause.h"
#include "RefToBinaryData.h"
#include <string>
#include "UpCnxState.h"
#include "HoState.h"
#include "N2SmInfoType.h"
#include <vector>
#include <nlohmann/json.hpp>

namespace oai {
namespace smf {
namespace model {

/// <summary>
/// 
/// </summary>
class  SmContextUpdatedData
{
public:
    SmContextUpdatedData();
    virtual ~SmContextUpdatedData();

    void validate();

    /////////////////////////////////////////////
    /// SmContextUpdatedData members

    /// <summary>
    /// 
    /// </summary>
    UpCnxState getUpCnxState() const;
    void setUpCnxState(UpCnxState const& value);
    bool upCnxStateIsSet() const;
    void unsetUpCnxState();
    /// <summary>
    /// 
    /// </summary>
    HoState getHoState() const;
    void setHoState(HoState const& value);
    bool hoStateIsSet() const;
    void unsetHoState();
    /// <summary>
    /// 
    /// </summary>
    std::vector<int32_t>& getReleaseEbiList();
    bool releaseEbiListIsSet() const;
    void unsetReleaseEbiList();
    /// <summary>
    /// 
    /// </summary>
    std::vector<EbiArpMapping>& getAllocatedEbiList();
    bool allocatedEbiListIsSet() const;
    void unsetAllocatedEbiList();
    /// <summary>
    /// 
    /// </summary>
    std::vector<EbiArpMapping>& getModifiedEbiList();
    bool modifiedEbiListIsSet() const;
    void unsetModifiedEbiList();
    /// <summary>
    /// 
    /// </summary>
    RefToBinaryData getN1SmMsg() const;
    void setN1SmMsg(RefToBinaryData const& value);
    bool n1SmMsgIsSet() const;
    void unsetN1SmMsg();
    /// <summary>
    /// 
    /// </summary>
    RefToBinaryData getN2SmInfo() const;
    void setN2SmInfo(RefToBinaryData const& value);
    bool n2SmInfoIsSet() const;
    void unsetN2SmInfo();
    /// <summary>
    /// 
    /// </summary>
    N2SmInfoType getN2SmInfoType() const;
    void setN2SmInfoType(N2SmInfoType const& value);
    bool n2SmInfoTypeIsSet() const;
    void unsetN2SmInfoType();
    /// <summary>
    /// 
    /// </summary>
    std::vector<std::string>& getEpsBearerSetup();
    bool epsBearerSetupIsSet() const;
    void unsetEpsBearerSetup();
    /// <summary>
    /// 
    /// </summary>
    bool isDataForwarding() const;
    void setDataForwarding(bool const value);
    bool dataForwardingIsSet() const;
    void unsetDataForwarding();
    /// <summary>
    /// 
    /// </summary>
    Cause getCause() const;
    void setCause(Cause const& value);
    bool causeIsSet() const;
    void unsetCause();

    friend void to_json(nlohmann::json& j, const SmContextUpdatedData& o);
    friend void from_json(const nlohmann::json& j, SmContextUpdatedData& o);
protected:
    UpCnxState m_UpCnxState;
    bool m_UpCnxStateIsSet;
    HoState m_HoState;
    bool m_HoStateIsSet;
    std::vector<int32_t> m_ReleaseEbiList;
    bool m_ReleaseEbiListIsSet;
    std::vector<EbiArpMapping> m_AllocatedEbiList;
    bool m_AllocatedEbiListIsSet;
    std::vector<EbiArpMapping> m_ModifiedEbiList;
    bool m_ModifiedEbiListIsSet;
    RefToBinaryData m_N1SmMsg;
    bool m_N1SmMsgIsSet;
    RefToBinaryData m_N2SmInfo;
    bool m_N2SmInfoIsSet;
    N2SmInfoType m_N2SmInfoType;
    bool m_N2SmInfoTypeIsSet;
    std::vector<std::string> m_EpsBearerSetup;
    bool m_EpsBearerSetupIsSet;
    bool m_DataForwarding;
    bool m_DataForwardingIsSet;
    Cause m_Cause;
    bool m_CauseIsSet;
};

}
}
}

#endif /* SmContextUpdatedData_H_ */
