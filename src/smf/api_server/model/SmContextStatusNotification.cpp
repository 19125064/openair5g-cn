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


#include "SmContextStatusNotification.h"

namespace oai {
namespace smf {
namespace model {

SmContextStatusNotification::SmContextStatusNotification()
{
    
}

SmContextStatusNotification::~SmContextStatusNotification()
{
}

void SmContextStatusNotification::validate()
{
    // TODO: implement validation
}

void to_json(nlohmann::json& j, const SmContextStatusNotification& o)
{
    j = nlohmann::json();
    j["statusInfo"] = o.m_StatusInfo;
}

void from_json(const nlohmann::json& j, SmContextStatusNotification& o)
{
    j.at("statusInfo").get_to(o.m_StatusInfo);
}

StatusInfo SmContextStatusNotification::getStatusInfo() const
{
    return m_StatusInfo;
}
void SmContextStatusNotification::setStatusInfo(StatusInfo const& value)
{
    m_StatusInfo = value;
    
}

}
}
}

