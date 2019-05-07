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


#include "N2InformationTransferReqData.h"

namespace org {
namespace openapitools {
namespace server {
namespace model {

N2InformationTransferReqData::N2InformationTransferReqData()
{
    m_TaiIsSet = false;
    m_EcgiIsSet = false;
    m_NcgiIsSet = false;
    m_GlobalRanNodeIdIsSet = false;
    m_SupportedFeatures = "";
    m_SupportedFeaturesIsSet = false;
    
}

N2InformationTransferReqData::~N2InformationTransferReqData()
{
}

void N2InformationTransferReqData::validate()
{
    // TODO: implement validation
}

nlohmann::json N2InformationTransferReqData::toJson() const
{
    nlohmann::json val = nlohmann::json::object();

    if(m_TaiIsSet)
    {
        val["tai"] = ModelBase::toJson(m_Tai);
    }
    if(m_EcgiIsSet)
    {
        val["ecgi"] = ModelBase::toJson(m_Ecgi);
    }
    if(m_NcgiIsSet)
    {
        val["ncgi"] = ModelBase::toJson(m_Ncgi);
    }
    {
        nlohmann::json jsonArray;
        for( auto& item : m_GlobalRanNodeId )
        {
            jsonArray.push_back(ModelBase::toJson(item));
        }
        
        if(jsonArray.size() > 0)
        {
            val["globalRanNodeId"] = jsonArray;
        } 
    }
    val["n2Information"] = ModelBase::toJson(m_N2Information);
    if(m_SupportedFeaturesIsSet)
    {
        val["supportedFeatures"] = ModelBase::toJson(m_SupportedFeatures);
    }
    

    return val;
}

void N2InformationTransferReqData::fromJson(const nlohmann::json& val)
{
    if(val.find("tai") != val.end())
    {
        if(!val["tai"].is_null())
        {
            Tai newItem;
            newItem.fromJson(val["tai"]);
            setTai( newItem );
        }
        
    }
    if(val.find("ecgi") != val.end())
    {
        if(!val["ecgi"].is_null())
        {
            Ecgi newItem;
            newItem.fromJson(val["ecgi"]);
            setEcgi( newItem );
        }
        
    }
    if(val.find("ncgi") != val.end())
    {
        if(!val["ncgi"].is_null())
        {
            Ncgi newItem;
            newItem.fromJson(val["ncgi"]);
            setNcgi( newItem );
        }
        
    }
    {
        m_GlobalRanNodeId.clear();
        if(val.find("globalRanNodeId") != val.end())
        {
            for( auto& item : val["globalRanNodeId"] )
            {
                
                if(item.is_null())
                {
                    m_GlobalRanNodeId.push_back( GlobalRanNodeId() );
                }
                else
                {
                    GlobalRanNodeId newItem;
                    newItem.fromJson(item);
                    m_GlobalRanNodeId.push_back( newItem );
                }
                
            }
        }
    }
    if(val.find("supportedFeatures") != val.end())
    {
        setSupportedFeatures(val.at("supportedFeatures"));
    }
    
}


Tai N2InformationTransferReqData::getTai() const
{
    return m_Tai;
}
void N2InformationTransferReqData::setTai(Tai const& value)
{
    m_Tai = value;
    m_TaiIsSet = true;
}
bool N2InformationTransferReqData::taiIsSet() const
{
    return m_TaiIsSet;
}
void N2InformationTransferReqData::unsetTai()
{
    m_TaiIsSet = false;
}
Ecgi N2InformationTransferReqData::getEcgi() const
{
    return m_Ecgi;
}
void N2InformationTransferReqData::setEcgi(Ecgi const& value)
{
    m_Ecgi = value;
    m_EcgiIsSet = true;
}
bool N2InformationTransferReqData::ecgiIsSet() const
{
    return m_EcgiIsSet;
}
void N2InformationTransferReqData::unsetEcgi()
{
    m_EcgiIsSet = false;
}
Ncgi N2InformationTransferReqData::getNcgi() const
{
    return m_Ncgi;
}
void N2InformationTransferReqData::setNcgi(Ncgi const& value)
{
    m_Ncgi = value;
    m_NcgiIsSet = true;
}
bool N2InformationTransferReqData::ncgiIsSet() const
{
    return m_NcgiIsSet;
}
void N2InformationTransferReqData::unsetNcgi()
{
    m_NcgiIsSet = false;
}
std::vector<GlobalRanNodeId>& N2InformationTransferReqData::getGlobalRanNodeId()
{
    return m_GlobalRanNodeId;
}
bool N2InformationTransferReqData::globalRanNodeIdIsSet() const
{
    return m_GlobalRanNodeIdIsSet;
}
void N2InformationTransferReqData::unsetGlobalRanNodeId()
{
    m_GlobalRanNodeIdIsSet = false;
}
N2InfoContainer N2InformationTransferReqData::getN2Information() const
{
    return m_N2Information;
}
void N2InformationTransferReqData::setN2Information(N2InfoContainer const& value)
{
    m_N2Information = value;
    
}
std::string N2InformationTransferReqData::getSupportedFeatures() const
{
    return m_SupportedFeatures;
}
void N2InformationTransferReqData::setSupportedFeatures(std::string const& value)
{
    m_SupportedFeatures = value;
    m_SupportedFeaturesIsSet = true;
}
bool N2InformationTransferReqData::supportedFeaturesIsSet() const
{
    return m_SupportedFeaturesIsSet;
}
void N2InformationTransferReqData::unsetSupportedFeatures()
{
    m_SupportedFeaturesIsSet = false;
}

}
}
}
}
