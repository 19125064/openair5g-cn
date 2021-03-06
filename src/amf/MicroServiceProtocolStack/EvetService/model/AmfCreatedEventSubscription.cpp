/**
* Namf_EventExposure Service
* AMF Event Exposure Service
*
* OpenAPI spec version: 1.R15.0.0
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/


#include "AmfCreatedEventSubscription.h"

namespace org {
namespace openapitools {
namespace server {
namespace model {

AmfCreatedEventSubscription::AmfCreatedEventSubscription()
{
    m_ReportsIsSet = false;
    m_SupportedFeatures = "";
    m_SupportedFeaturesIsSet = false;
    
}

AmfCreatedEventSubscription::~AmfCreatedEventSubscription()
{
}

void AmfCreatedEventSubscription::validate()
{
    // TODO: implement validation
}

nlohmann::json AmfCreatedEventSubscription::toJson() const
{
    nlohmann::json val = nlohmann::json::object();

    val["subscription"] = ModelBase::toJson(m_Subscription);
    if(m_ReportsIsSet)
    {
        val["reports"] = ModelBase::toJson(m_Reports);
    }
    if(m_SupportedFeaturesIsSet)
    {
        val["supportedFeatures"] = ModelBase::toJson(m_SupportedFeatures);
    }
    

    return val;
}

void AmfCreatedEventSubscription::fromJson(const nlohmann::json& val)
{
    if(val.find("reports") != val.end())
    {
        if(!val["reports"].is_null())
        {
            AmfEventReport newItem;
            newItem.fromJson(val["reports"]);
            setReports( newItem );
        }
        
    }
    if(val.find("supportedFeatures") != val.end())
    {
        setSupportedFeatures(val.at("supportedFeatures"));
    }
    
}


AmfEventSubscription AmfCreatedEventSubscription::getSubscription() const
{
    return m_Subscription;
}
void AmfCreatedEventSubscription::setSubscription(AmfEventSubscription const& value)
{
    m_Subscription = value;
    
}
AmfEventReport AmfCreatedEventSubscription::getReports() const
{
    return m_Reports;
}
void AmfCreatedEventSubscription::setReports(AmfEventReport const& value)
{
    m_Reports = value;
    m_ReportsIsSet = true;
}
bool AmfCreatedEventSubscription::reportsIsSet() const
{
    return m_ReportsIsSet;
}
void AmfCreatedEventSubscription::unsetReports()
{
    m_ReportsIsSet = false;
}
std::string AmfCreatedEventSubscription::getSupportedFeatures() const
{
    return m_SupportedFeatures;
}
void AmfCreatedEventSubscription::setSupportedFeatures(std::string const& value)
{
    m_SupportedFeatures = value;
    m_SupportedFeaturesIsSet = true;
}
bool AmfCreatedEventSubscription::supportedFeaturesIsSet() const
{
    return m_SupportedFeaturesIsSet;
}
void AmfCreatedEventSubscription::unsetSupportedFeatures()
{
    m_SupportedFeaturesIsSet = false;
}

}
}
}
}

