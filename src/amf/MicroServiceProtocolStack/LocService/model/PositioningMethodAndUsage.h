/**
* AMF Location Service
* AMF Location Service
*
* OpenAPI spec version: 1.R15.0.0
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
/*
 * PositioningMethodAndUsage.h
 *
 * 
 */

#ifndef PositioningMethodAndUsage_H_
#define PositioningMethodAndUsage_H_


#include "ModelBase.h"

#include "Usage.h"
#include "PositioningMethod.h"
#include "PositioningMode.h"

namespace org {
namespace openapitools {
namespace server {
namespace model {

/// <summary>
/// 
/// </summary>
class  PositioningMethodAndUsage
    : public ModelBase
{
public:
    PositioningMethodAndUsage();
    virtual ~PositioningMethodAndUsage();

    /////////////////////////////////////////////
    /// ModelBase overrides

    void validate() override;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json& json) override;

    /////////////////////////////////////////////
    /// PositioningMethodAndUsage members

    /// <summary>
    /// 
    /// </summary>
    PositioningMethod getMethod() const;
    void setMethod(PositioningMethod const& value);
        /// <summary>
    /// 
    /// </summary>
    PositioningMode getMode() const;
    void setMode(PositioningMode const& value);
        /// <summary>
    /// 
    /// </summary>
    Usage getUsage() const;
    void setUsage(Usage const& value);
    
protected:
    PositioningMethod m_Method;

    PositioningMode m_Mode;

    Usage m_Usage;

};

}
}
}
}

#endif /* PositioningMethodAndUsage_H_ */