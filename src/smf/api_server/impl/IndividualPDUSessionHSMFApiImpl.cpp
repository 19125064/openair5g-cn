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

#include "IndividualPDUSessionHSMFApiImpl.h"

namespace oai {
namespace smf {
namespace api {

using namespace oai::smf::model;

IndividualPDUSessionHSMFApiImpl::IndividualPDUSessionHSMFApiImpl(std::shared_ptr<Pistache::Rest::Router> rtr)
    : IndividualPDUSessionHSMFApi(rtr)
    { }

void IndividualPDUSessionHSMFApiImpl::release_pdu_session(const std::string &pduSessionRef, const ReleaseData &releaseData, Pistache::Http::ResponseWriter &response) {
    response.send(Pistache::Http::Code::Ok, "Do some magic\n");
}
void IndividualPDUSessionHSMFApiImpl::update_pdu_session(const std::string &pduSessionRef, const HsmfUpdateData &hsmfUpdateData, Pistache::Http::ResponseWriter &response) {
    response.send(Pistache::Http::Code::Ok, "Do some magic\n");
}

}
}
}

