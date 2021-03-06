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


#include "PointUncertaintyCircle.h"

namespace org {
namespace openapitools {
namespace server {
namespace model {

PointUncertaintyCircle::PointUncertaintyCircle()
{
    m_Uncertainty = 0.0f;
    
}

PointUncertaintyCircle::~PointUncertaintyCircle()
{
}

void PointUncertaintyCircle::validate()
{
    // TODO: implement validation
}

nlohmann::json PointUncertaintyCircle::toJson() const
{
    nlohmann::json val = nlohmann::json::object();

    val["shape"] = ModelBase::toJson(m_Shape);
    val["point"] = ModelBase::toJson(m_Point);
    val["uncertainty"] = m_Uncertainty;
    

    return val;
}

void PointUncertaintyCircle::fromJson(const nlohmann::json& val)
{
    setUncertainty(val.at("uncertainty"));
    
}


SupportedGADShapes PointUncertaintyCircle::getShape() const
{
    return m_Shape;
}
void PointUncertaintyCircle::setShape(SupportedGADShapes const& value)
{
    m_Shape = value;
    
}
GeographicalCoordinates PointUncertaintyCircle::getPoint() const
{
    return m_Point;
}
void PointUncertaintyCircle::setPoint(GeographicalCoordinates const& value)
{
    m_Point = value;
    
}
float PointUncertaintyCircle::getUncertainty() const
{
    return m_Uncertainty;
}
void PointUncertaintyCircle::setUncertainty(float const value)
{
    m_Uncertainty = value;
    
}

}
}
}
}

