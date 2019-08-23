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

#include "IndividualSMContextApiImpl.h"

namespace oai {
namespace smf {
namespace api {

using namespace oai::smf::model;

IndividualSMContextApiImpl::IndividualSMContextApiImpl(std::shared_ptr<Pistache::Rest::Router> rtr)
    : IndividualSMContextApi(rtr)
    { }

void IndividualSMContextApiImpl::release_sm_context(const std::string &smContextRef, const SmContextReleaseData &smContextReleaseData, Pistache::Http::ResponseWriter &response) {
    response.send(Pistache::Http::Code::Ok, "Do some magic\n");
}
void IndividualSMContextApiImpl::retrieve_sm_context(const std::string &smContextRef, const SmContextRetrieveData &smContextRetrieveData, Pistache::Http::ResponseWriter &response) {
    response.send(Pistache::Http::Code::Ok, "Do some magic\n");
}
void IndividualSMContextApiImpl::update_sm_context(const std::string &smContextRef, const SmContextUpdateData &smContextUpdateData, Pistache::Http::ResponseWriter &response) {
    response.send(Pistache::Http::Code::Ok, "Do some magic\n");
}

}
}
}

