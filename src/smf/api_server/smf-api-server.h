/**
* RNI API
* The ETSI MEC ISG MEC012 Radio Network Information API described using OpenAPI
*
* OpenAPI spec version: 1.1.1
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/


#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"
#ifdef __linux__
#include <vector>
#include <signal.h>
#include <unistd.h>
#endif

#include "IndividualPDUSessionHSMFApiImpl.h"
#include "IndividualSMContextApiImpl.h"
#include "PDUSessionsCollectionApiImpl.h"
#include "SMContextsCollectionApiImpl.h"

using namespace oai::smf::api;
class SMFApiServer {
public:
	SMFApiServer(Pistache::Address address) : m_httpEndpoint(std::make_shared<Pistache::Http::Endpoint>(address))  {
		m_router = std::make_shared<Pistache::Rest::Router>();
		m_individualPDUSessionHSMFApiImpl = std::make_shared<IndividualPDUSessionHSMFApiImpl> (m_router);
		m_individualSMContextApiImpl = std::make_shared<IndividualSMContextApiImpl> (m_router);
		m_pduSessionsCollectionApiImpl = std::make_shared<PDUSessionsCollectionApiImpl> (m_router);
		m_smContextsCollectionApiImpl = std::make_shared<SMContextsCollectionApiImpl> (m_router);

	}
	void init(size_t thr = 1);
	void start();
	void shutdown();

private:
	std::shared_ptr<Pistache::Http::Endpoint> m_httpEndpoint;
	std::shared_ptr<Pistache::Rest::Router> m_router;
	std::shared_ptr<IndividualPDUSessionHSMFApiImpl> m_individualPDUSessionHSMFApiImpl;
	std::shared_ptr <IndividualSMContextApiImpl> m_individualSMContextApiImpl;
	std::shared_ptr <PDUSessionsCollectionApiImpl> m_pduSessionsCollectionApiImpl;
	std::shared_ptr <SMContextsCollectionApiImpl> m_smContextsCollectionApiImpl;

};


