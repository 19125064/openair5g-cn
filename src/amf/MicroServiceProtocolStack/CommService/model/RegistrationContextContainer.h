/**
* AMF Communicaiton Service
* AMF Communication Service
*
* OpenAPI spec version: 1.R15.0.0
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
/*
 * RegistrationContextContainer.h
 *
 * 
 */

#ifndef RegistrationContextContainer_H_
#define RegistrationContextContainer_H_


#include "ModelBase.h"

#include "AllowedNssai.h"
#include "UeContext.h"
#include <string>
#include "AccessType.h"

namespace org {
namespace openapitools {
namespace server {
namespace model {

/// <summary>
/// 
/// </summary>
class  RegistrationContextContainer
    : public ModelBase
{
public:
    RegistrationContextContainer();
    virtual ~RegistrationContextContainer();

    /////////////////////////////////////////////
    /// ModelBase overrides

    void validate() override;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json& json) override;

    /////////////////////////////////////////////
    /// RegistrationContextContainer members

    /// <summary>
    /// 
    /// </summary>
    UeContext getUeContext() const;
    void setUeContext(UeContext const& value);
        /// <summary>
    /// 
    /// </summary>
    std::string getLocalTimeZone() const;
    void setLocalTimeZone(std::string const& value);
    bool localTimeZoneIsSet() const;
    void unsetLocalTimeZone();
    /// <summary>
    /// 
    /// </summary>
    AccessType getAnType() const;
    void setAnType(AccessType const& value);
        /// <summary>
    /// 
    /// </summary>
    std::string getAnN2IPv4Address() const;
    void setAnN2IPv4Address(std::string const& value);
    bool anN2IPv4AddressIsSet() const;
    void unsetAnN2IPv4Address();
    /// <summary>
    /// 
    /// </summary>
    std::string getAnN2IPv6Addr() const;
    void setAnN2IPv6Addr(std::string const& value);
    bool anN2IPv6AddrIsSet() const;
    void unsetAnN2IPv6Addr();
    /// <summary>
    /// 
    /// </summary>
    AllowedNssai getAllowedNssai() const;
    void setAllowedNssai(AllowedNssai const& value);
    bool allowedNssaiIsSet() const;
    void unsetAllowedNssai();

protected:
    UeContext m_UeContext;

    std::string m_LocalTimeZone;
    bool m_LocalTimeZoneIsSet;
    AccessType m_AnType;

    std::string m_AnN2IPv4Address;
    bool m_AnN2IPv4AddressIsSet;
    std::string m_AnN2IPv6Addr;
    bool m_AnN2IPv6AddrIsSet;
    AllowedNssai m_AllowedNssai;
    bool m_AllowedNssaiIsSet;
};

}
}
}
}

#endif /* RegistrationContextContainer_H_ */
