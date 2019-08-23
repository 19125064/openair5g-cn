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
 * UserLocation.h
 *
 * 
 */

#ifndef UserLocation_H_
#define UserLocation_H_


#include "EutraLocation.h"
#include "NrLocation.h"
#include "N3gaLocation.h"
#include <nlohmann/json.hpp>

namespace oai {
namespace smf {
namespace model {

/// <summary>
/// 
/// </summary>
class  UserLocation
{
public:
    UserLocation();
    virtual ~UserLocation();

    void validate();

    /////////////////////////////////////////////
    /// UserLocation members

    /// <summary>
    /// 
    /// </summary>
    EutraLocation getEutraLocation() const;
    void setEutraLocation(EutraLocation const& value);
    bool eutraLocationIsSet() const;
    void unsetEutraLocation();
    /// <summary>
    /// 
    /// </summary>
    NrLocation getNrLocation() const;
    void setNrLocation(NrLocation const& value);
    bool nrLocationIsSet() const;
    void unsetNrLocation();
    /// <summary>
    /// 
    /// </summary>
    N3gaLocation getN3gaLocation() const;
    void setN3gaLocation(N3gaLocation const& value);
    bool n3gaLocationIsSet() const;
    void unsetN3gaLocation();

    friend void to_json(nlohmann::json& j, const UserLocation& o);
    friend void from_json(const nlohmann::json& j, UserLocation& o);
protected:
    EutraLocation m_EutraLocation;
    bool m_EutraLocationIsSet;
    NrLocation m_NrLocation;
    bool m_NrLocationIsSet;
    N3gaLocation m_N3gaLocation;
    bool m_N3gaLocationIsSet;
};

}
}
}

#endif /* UserLocation_H_ */
