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


#include "AllowedSNssai.h"

namespace org {
namespace openapitools {
namespace server {
namespace model {

AllowedSNssai::AllowedSNssai()
{
    m_NsiInformationIsSet = false;
    m_MappedHomeSNssaiIsSet = false;
    
}

AllowedSNssai::~AllowedSNssai()
{
}

void AllowedSNssai::validate()
{
    // TODO: implement validation
}

nlohmann::json AllowedSNssai::toJson() const
{
    nlohmann::json val = nlohmann::json::object();

    val["allowedSNssai"] = ModelBase::toJson(m_AllowedSNssai);
    {
        nlohmann::json jsonArray;
        for( auto& item : m_NsiInformation )
        {
            jsonArray.push_back(ModelBase::toJson(item));
        }
        
        if(jsonArray.size() > 0)
        {
            val["nsiInformation"] = jsonArray;
        } 
    }
    if(m_MappedHomeSNssaiIsSet)
    {
        val["mappedHomeSNssai"] = ModelBase::toJson(m_MappedHomeSNssai);
    }
    

    return val;
}

void AllowedSNssai::fromJson(const nlohmann::json& val)
{
    {
        m_NsiInformation.clear();
        if(val.find("nsiInformation") != val.end())
        {
            for( auto& item : val["nsiInformation"] )
            {
                
                if(item.is_null())
                {
                    m_NsiInformation.push_back( NsiInformation() );
                }
                else
                {
                    NsiInformation newItem;
                    newItem.fromJson(item);
                    m_NsiInformation.push_back( newItem );
                }
                
            }
        }
    }
    if(val.find("mappedHomeSNssai") != val.end())
    {
        if(!val["mappedHomeSNssai"].is_null())
        {
            Snssai newItem;
            newItem.fromJson(val["mappedHomeSNssai"]);
            setMappedHomeSNssai( newItem );
        }
        
    }
    
}


Snssai AllowedSNssai::getAllowedSNssai() const
{
    return m_AllowedSNssai;
}
void AllowedSNssai::setAllowedSNssai(Snssai const& value)
{
    m_AllowedSNssai = value;
    
}
std::vector<NsiInformation>& AllowedSNssai::getNsiInformation()
{
    return m_NsiInformation;
}
bool AllowedSNssai::nsiInformationIsSet() const
{
    return m_NsiInformationIsSet;
}
void AllowedSNssai::unsetNsiInformation()
{
    m_NsiInformationIsSet = false;
}
Snssai AllowedSNssai::getMappedHomeSNssai() const
{
    return m_MappedHomeSNssai;
}
void AllowedSNssai::setMappedHomeSNssai(Snssai const& value)
{
    m_MappedHomeSNssai = value;
    m_MappedHomeSNssaiIsSet = true;
}
bool AllowedSNssai::mappedHomeSNssaiIsSet() const
{
    return m_MappedHomeSNssaiIsSet;
}
void AllowedSNssai::unsetMappedHomeSNssai()
{
    m_MappedHomeSNssaiIsSet = false;
}

}
}
}
}

