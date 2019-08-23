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
 * TriggerType.h
 *
 * 
 */

#ifndef TriggerType_H_
#define TriggerType_H_


#include <nlohmann/json.hpp>

namespace oai {
namespace smf {
namespace model {

/// <summary>
/// 
/// </summary>
class  TriggerType
{
public:
    TriggerType();
    virtual ~TriggerType();

    void validate();

    /////////////////////////////////////////////
    /// TriggerType members


    friend void to_json(nlohmann::json& j, const TriggerType& o);
    friend void from_json(const nlohmann::json& j, TriggerType& o);
protected:
};

}
}
}

#endif /* TriggerType_H_ */
