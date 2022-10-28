#ifndef Dispatch_Quest_Processor_h
#define Dispatch_Quest_Processor_h

#include <thread>
#include "FPZKClient.h"

using namespace fpnn;

enum AddressType
{
	AT_IPv4 = 0,
	AT_IPv6 = 1,
	AT_Domain = 2
};

enum ProtoType
{
	PT_TCP = 0,
	PT_SSL = 1,
	PT_UDP = 2
};

struct ServiceNode
{
	int tcpCount;
	float CPULoad;
	float loadAvg;

	int port;
	int port6;
	int sslport;
	int sslport6;
	int uport;
	int uport6;
	std::string domain;
	std::string ipv4;
	std::string ipv6;

	int64_t weight;
	static int64_t weightBalance;

	ServiceNode(): tcpCount(0), CPULoad(0.), loadAvg(0.), port(0), port6(0),
		sslport(0), sslport6(0), uport(0), uport6(0), weight(0) {}
	void init(const FPZKClient::ServiceNode& sn);
	void sync(const FPZKClient::ServiceNode& sn);
	void affect() { weight += weightBalance; }
};
typedef std::shared_ptr<ServiceNode> ServiceNodePtr;

class ServiceStrategy
{
	int64_t clusterAlteredMsec;
	int64_t revision;
	int64_t updateMsec;
	std::map<std::string, ServiceNodePtr> endpointMap;
	std::map<std::string, std::set<ServiceNodePtr>> versionPools;

	void udapteAll(FPZKClient::ServiceInfosPtr sip);
	void udapteStatus(FPZKClient::ServiceInfosPtr sip);
	std::set<ServiceNodePtr> perpare(enum AddressType addrType, enum ProtoType, const std::string& version);
	std::string buildEndpoint(enum AddressType addrType, enum ProtoType protoType, ServiceNodePtr snp);

public:
	ServiceStrategy(): clusterAlteredMsec(0), revision(0), updateMsec(0) {}

	void updateCheck(FPZKClient::ServiceInfosPtr sip)
	{
		if (clusterAlteredMsec != sip->clusterAlteredMsec || revision != sip->revision)
			udapteAll(sip);
		else if (updateMsec != sip->updateMsec)
			udapteStatus(sip);
	}
	std::string findOne(enum AddressType addrType, enum ProtoType proto, const std::string& version);
	std::set<std::string> findAll(enum AddressType addrType, enum ProtoType, const std::string& version);
};

class DispatchStrategy
{
	FPZKClientPtr _fpzk;
	std::map<std::string, struct ServiceStrategy> _serviceStrategies;

public:
	DispatchStrategy(FPZKClientPtr fpzk): _fpzk(fpzk) {}

	std::string dispatch(const std::string& service, enum AddressType addrType, enum ProtoType, const std::string& version);
	std::set<std::string> getAllEndpoints(const std::string& service, enum AddressType addrType, enum ProtoType, const std::string& version);
};

//=========================================//
//-       DispatchQuestProcessor          -//
//=========================================//
class DispatchQuestProcessor: public IQuestProcessor
{
	QuestProcessorClassPrivateFields(DispatchQuestProcessor)

	FPZKClientPtr _fpzk;
	std::unordered_map<std::string, std::string> _allowedServers;
	static thread_local std::unique_ptr<DispatchStrategy> _strategy;

	FPAnswerPtr fetchEndpoint(const FPReaderPtr args, const FPQuestPtr quest, bool all);

public:
	DispatchQuestProcessor();

	FPAnswerPtr which(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci)
	{
		return fetchEndpoint(args, quest, false);
	}
	FPAnswerPtr whichall(const FPReaderPtr args, const FPQuestPtr quest, const ConnectionInfo& ci)
	{
		return fetchEndpoint(args, quest, true);
	}

	QuestProcessorClassBasicPublicFuncs
};

#endif
