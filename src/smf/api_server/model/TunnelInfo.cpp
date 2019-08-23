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


#include "TunnelInfo.h"

namespace oai {
namespace smf {
namespace model {

TunnelInfo::TunnelInfo()
{
    m_Ipv4Addr = "";
    m_Ipv4AddrIsSet = false;
    m_Ipv6AddrIsSet = false;
    m_GtpTeid = "";
    
}

TunnelInfo::~TunnelInfo()
{
}

void TunnelInfo::validate()
{
    // TODO: implement validation
}

void to_json(nlohmann::json& j, const TunnelInfo& o)
{
    j = nlohmann::json();
    if(o.ipv4AddrIsSet())
        j["ipv4Addr"] = o.m_Ipv4Addr;
    if(o.ipv6AddrIsSet())
        j["ipv6Addr"] = o.m_Ipv6Addr;
    j["gtpTeid"] = o.m_GtpTeid;
}

void from_json(const nlohmann::json& j, TunnelInfo& o)
{
    if(j.find("ipv4Addr") != j.end())
    {
        j.at("ipv4Addr").get_to(o.m_Ipv4Addr);
        o.m_Ipv4AddrIsSet = true;
    } 
    if(j.find("ipv6Addr") != j.end())
    {
        j.at("ipv6Addr").get_to(o.m_Ipv6Addr);
        o.m_Ipv6AddrIsSet = true;
    } 
    j.at("gtpTeid").get_to(o.m_GtpTeid);
}

std::string TunnelInfo::getIpv4Addr() const
{
    return m_Ipv4Addr;
}
void TunnelInfo::setIpv4Addr(std::string const& value)
{
    m_Ipv4Addr = value;
    m_Ipv4AddrIsSet = true;
}
bool TunnelInfo::ipv4AddrIsSet() const
{
    return m_Ipv4AddrIsSet;
}
void TunnelInfo::unsetIpv4Addr()
{
    m_Ipv4AddrIsSet = false;
}
std::string TunnelInfo::getIpv6Addr() const
{
    return m_Ipv6Addr;
}
void TunnelInfo::setIpv6Addr(std::string const& value)
{
    m_Ipv6Addr = value;
    m_Ipv6AddrIsSet = true;
}
bool TunnelInfo::ipv6AddrIsSet() const
{
    return m_Ipv6AddrIsSet;
}
void TunnelInfo::unsetIpv6Addr()
{
    m_Ipv6AddrIsSet = false;
}
std::string TunnelInfo::getGtpTeid() const
{
    return m_GtpTeid;
}
void TunnelInfo::setGtpTeid(std::string const& value)
{
    m_GtpTeid = value;
    
}

}
}
}

