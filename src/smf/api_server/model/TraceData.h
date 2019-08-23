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
 * TraceData.h
 *
 * 
 */

#ifndef TraceData_H_
#define TraceData_H_


#include "TraceDepth.h"
#include <string>
#include <nlohmann/json.hpp>

namespace oai {
namespace smf {
namespace model {

/// <summary>
/// 
/// </summary>
class  TraceData
{
public:
    TraceData();
    virtual ~TraceData();

    void validate();

    /////////////////////////////////////////////
    /// TraceData members

    /// <summary>
    /// 
    /// </summary>
    std::string getTraceRef() const;
    void setTraceRef(std::string const& value);
        /// <summary>
    /// 
    /// </summary>
    TraceDepth getTraceDepth() const;
    void setTraceDepth(TraceDepth const& value);
        /// <summary>
    /// 
    /// </summary>
    std::string getNeTypeList() const;
    void setNeTypeList(std::string const& value);
        /// <summary>
    /// 
    /// </summary>
    std::string getEventList() const;
    void setEventList(std::string const& value);
        /// <summary>
    /// 
    /// </summary>
    std::string getCollectionEntityIpv4Addr() const;
    void setCollectionEntityIpv4Addr(std::string const& value);
    bool collectionEntityIpv4AddrIsSet() const;
    void unsetCollectionEntityIpv4Addr();
    /// <summary>
    /// 
    /// </summary>
    std::string getCollectionEntityIpv6Addr() const;
    void setCollectionEntityIpv6Addr(std::string const& value);
    bool collectionEntityIpv6AddrIsSet() const;
    void unsetCollectionEntityIpv6Addr();
    /// <summary>
    /// 
    /// </summary>
    std::string getInterfaceList() const;
    void setInterfaceList(std::string const& value);
    bool interfaceListIsSet() const;
    void unsetInterfaceList();

    friend void to_json(nlohmann::json& j, const TraceData& o);
    friend void from_json(const nlohmann::json& j, TraceData& o);
protected:
    std::string m_TraceRef;

    TraceDepth m_TraceDepth;

    std::string m_NeTypeList;

    std::string m_EventList;

    std::string m_CollectionEntityIpv4Addr;
    bool m_CollectionEntityIpv4AddrIsSet;
    std::string m_CollectionEntityIpv6Addr;
    bool m_CollectionEntityIpv6AddrIsSet;
    std::string m_InterfaceList;
    bool m_InterfaceListIsSet;
};

}
}
}

#endif /* TraceData_H_ */
