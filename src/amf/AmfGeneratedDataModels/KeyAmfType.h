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
 * KeyAmfType.h
 *
 * 
 */

#ifndef KeyAmfType_H_
#define KeyAmfType_H_


#include "ModelBase.h"


namespace org {
namespace openapitools {
namespace server {
namespace model {

/// <summary>
/// 
/// </summary>
class  KeyAmfType
    : public ModelBase
{
public:
    KeyAmfType();
    virtual ~KeyAmfType();

    /////////////////////////////////////////////
    /// ModelBase overrides

    void validate() override;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json& json) override;

    /////////////////////////////////////////////
    /// KeyAmfType members


protected:
};

}
}
}
}

#endif /* KeyAmfType_H_ */