#include "rdtsc.h"
#include "Setting.h"
#include "StringUtil.h"
#include "DispatchQuestProcessor.h"

using namespace fpnn;

int64_t ServiceNode::weightBalance = 31;
const int DispatchError_InvalidParameter = 100001;
thread_local std::unique_ptr<DispatchStrategy> DispatchQuestProcessor::_strategy(nullptr);

void ServiceNode::init(const FPZKClient::ServiceNode& sn)
{
	tcpCount = sn.tcpCount;
	CPULoad = sn.CPULoad;
	loadAvg = sn.loadAvg;

	port = sn.port;
	port6 = sn.port6;
	sslport = sn.sslport;
	sslport6 = sn.sslport6;
	uport = sn.uport;
	uport6 = sn.uport6;
	domain = sn.domain;
	ipv4 = sn.ipv4;
	ipv6 = sn.ipv6;

	weight = loadAvg * 1000 + tcpCount;
}

void ServiceNode::sync(const FPZKClient::ServiceNode& sn)
{
	tcpCount = sn.tcpCount;
	CPULoad = sn.CPULoad;
	loadAvg = sn.loadAvg;

	weight = loadAvg * 1000 + tcpCount;
}

//=========================================//
//-          Service Strategy             -//
//=========================================//
void ServiceStrategy::udapteAll(FPZKClient::ServiceInfosPtr sip)
{
	std::map<std::string, ServiceNodePtr> newEndpointMap;
	std::map<std::string, std::set<ServiceNodePtr>> newVersionPools;

	for (auto& epr: sip->nodeMap)
	{
		if (epr.second.online == false)
			continue;

		if (epr.second.port == 0 && epr.second.port6 == 0
			&& epr.second.uport == 0 && epr.second.uport6 == 0
			&& epr.second.sslport == 0 && epr.second.sslport6 == 0)
			continue;

		if (epr.second.domain.empty() && epr.second.ipv4.empty() && epr.second.ipv6.empty())
			continue;

		ServiceNodePtr snp(new ServiceNode());
		snp->init(epr.second);

		newVersionPools[epr.second.version].insert(snp);
		newVersionPools[""].insert(snp);
		newEndpointMap[epr.first] = snp;
	}

	clusterAlteredMsec = sip->clusterAlteredMsec;
	revision = sip->revision;
	updateMsec = sip->updateMsec;

	versionPools.swap(newVersionPools);
	endpointMap.swap(newEndpointMap);
}

void ServiceStrategy::udapteStatus(FPZKClient::ServiceInfosPtr sip)
{
	for (auto& epr: sip->nodeMap)
	{
		if (epr.second.online == false)
			continue;

		auto it = endpointMap.find(epr.first);
		if (it != endpointMap.end())
			it->second->sync(epr.second);
	}

	updateMsec = sip->updateMsec;
}

std::string ServiceStrategy::findOne(enum AddressType addrType, enum ProtoType protoType, const std::string& version)
{
	std::set<ServiceNodePtr> pool = perpare(addrType, protoType, version);
	if (pool.empty())
		return std::string();

	int64_t maxWeight = 0;
	for (auto& snp: pool)
	{
		if (snp->weight > maxWeight)
			maxWeight = snp->weight;
	}

	int64_t sumPriorWeight = 0;
	std::map<int64_t, std::set<ServiceNodePtr>> priorMap;
	if (maxWeight)
	{
		for (auto& snp: pool)
		{
			sumPriorWeight += (maxWeight - snp->weight);
			priorMap[maxWeight - snp->weight].insert(snp);
		}
	}

	if (maxWeight == 0 || sumPriorWeight == 0)
	{
		uint64_t idx = (slack_real_msec() + rdtsc()) % (uint64_t)pool.size();
		for (auto& snp: pool)
		{
			if (idx == 0)
			{
				snp->affect();
				return buildEndpoint(addrType, protoType, snp);
			}

			idx -= 1;
		}

		LOG_FATAL("Fatal logic error (same prior). Please send the log to wangxing.shi@ilivedata.com");
		return std::string();
	}

	//-- select one
	int64_t idx = (slack_real_msec() + (int64_t)rdtsc()) % sumPriorWeight;
	if (idx < 0)
		idx = -idx;

	for (auto it = priorMap.begin(); it != priorMap.end(); it++)
	{
		for (auto& snp: it->second)
		{
			idx -= it->first;
			
			if (idx <= 0)
			{
				snp->affect();
				return buildEndpoint(addrType, protoType, snp);
			}
		}
	}

	LOG_FATAL("Fatal logic error (different prior). Please send the log to wangxing.shi@ilivedata.com");
	return std::string();
}

std::string ServiceStrategy::buildEndpoint(enum AddressType addrType, enum ProtoType protoType, ServiceNodePtr snp)
{
	if (addrType == AT_IPv4)
	{
		if (protoType == PT_TCP)
			return (snp->ipv4 + ":" + std::to_string(snp->port));
		else if (protoType == PT_SSL)
			return (snp->ipv4 + ":" + std::to_string(snp->sslport));
		else
			return (snp->ipv4 + ":" + std::to_string(snp->uport));
	}
	else if (addrType == AT_IPv6)
	{
		if (protoType == PT_TCP)
			return (snp->ipv6 + ":" + std::to_string(snp->port6));
		else if (protoType == PT_SSL)
			return (snp->ipv6 + ":" + std::to_string(snp->sslport6));
		else
			return (snp->ipv6 + ":" + std::to_string(snp->uport6));
	}
	else
	{
		if (protoType == PT_TCP)
			return (snp->domain + ":" + std::to_string(snp->port));
		else if (protoType == PT_SSL)
			return (snp->domain + ":" + std::to_string(snp->sslport));
		else
			return (snp->domain + ":" + std::to_string(snp->uport));
	}
}

std::set<ServiceNodePtr> ServiceStrategy::perpare(enum AddressType addrType, enum ProtoType protoType, const std::string& version)
{
	std::set<ServiceNodePtr> rev;

	if (versionPools.find(version) == versionPools.end())
		return rev;

	std::set<ServiceNodePtr> &pool = versionPools[version];

	if (addrType == AT_IPv4)
	{
		if (protoType == PT_TCP)
		{
			for (auto& snp: pool)
				if (snp->ipv4.size() && snp->port)
					rev.insert(snp);
		}
		else if (protoType == PT_SSL)
		{
			for (auto& snp: pool)
				if (snp->ipv4.size() && snp->sslport)
					rev.insert(snp);
		}
		else
		{
			for (auto& snp: pool)
				if (snp->ipv4.size() && snp->uport)
					rev.insert(snp);
		}
	}
	else if (addrType == AT_IPv6)
	{
		if (protoType == PT_TCP)
		{
			for (auto& snp: pool)
				if (snp->ipv6.size() && snp->port6)
					rev.insert(snp);
		}
		else if (protoType == PT_SSL)
		{
			for (auto& snp: pool)
				if (snp->ipv6.size() && snp->sslport6)
					rev.insert(snp);
		}
		else
		{
			for (auto& snp: pool)
				if (snp->ipv6.size() && snp->uport6)
					rev.insert(snp);
		}
	}
	else
	{
		if (protoType == PT_TCP)
		{
			for (auto& snp: pool)
				if (snp->domain.size() && snp->port)
					rev.insert(snp);
		}
		else if (protoType == PT_SSL)
		{
			for (auto& snp: pool)
				if (snp->domain.size() && snp->sslport)
					rev.insert(snp);
		}
		else
		{
			for (auto& snp: pool)
				if (snp->domain.size() && snp->uport)
					rev.insert(snp);
		}
	}

	return rev;
}

std::set<std::string> ServiceStrategy::findAll(enum AddressType addrType, enum ProtoType protoType, const std::string& version)
{
	std::set<std::string> rev;

	if (versionPools.find(version) == versionPools.end())
		return rev;

	std::set<ServiceNodePtr> &pool = versionPools[version];

	if (addrType == AT_IPv4)
	{
		if (protoType == PT_TCP)
		{
			for (auto& snp: pool)
				if (snp->ipv4.size() && snp->port)
					rev.insert(snp->ipv4 + ":" + std::to_string(snp->port));
		}
		else if (protoType == PT_SSL)
		{
			for (auto& snp: pool)
				if (snp->ipv4.size() && snp->sslport)
					rev.insert(snp->ipv4 + ":" + std::to_string(snp->sslport));
		}
		else
		{
			for (auto& snp: pool)
				if (snp->ipv4.size() && snp->uport)
					rev.insert(snp->ipv4 + ":" + std::to_string(snp->uport));
		}
	}
	else if (addrType == AT_IPv6)
	{
		if (protoType == PT_TCP)
		{
			for (auto& snp: pool)
				if (snp->ipv6.size() && snp->port6)
					rev.insert(snp->ipv6 + ":" + std::to_string(snp->port6));
		}
		else if (protoType == PT_SSL)
		{
			for (auto& snp: pool)
				if (snp->ipv6.size() && snp->sslport6)
					rev.insert(snp->ipv6 + ":" + std::to_string(snp->sslport6));
		}
		else
		{
			for (auto& snp: pool)
				if (snp->ipv6.size() && snp->uport6)
					rev.insert(snp->ipv6 + ":" + std::to_string(snp->uport6));
		}
	}
	else
	{
		if (protoType == PT_TCP)
		{
			for (auto& snp: pool)
				if (snp->domain.size() && snp->port)
					rev.insert(snp->domain + ":" + std::to_string(snp->port));
		}
		else if (protoType == PT_SSL)
		{
			for (auto& snp: pool)
				if (snp->domain.size() && snp->sslport)
					rev.insert(snp->domain + ":" + std::to_string(snp->sslport));
		}
		else
		{
			for (auto& snp: pool)
				if (snp->domain.size() && snp->uport)
					rev.insert(snp->domain + ":" + std::to_string(snp->uport));
		}
	}

	return rev;
}

//=========================================//
//-          Dispatch Strategy            -//
//=========================================//
std::string DispatchStrategy::dispatch(const std::string& service, enum AddressType addrType, enum ProtoType protoType, const std::string& version)
{
	const FPZKClient::ServiceInfosPtr sip = _fpzk->getServiceInfos(service, "", "", false);
	if (!sip)
		return std::string();

	_serviceStrategies[service].updateCheck(sip);
	return _serviceStrategies[service].findOne(addrType, protoType, version);
}

std::set<std::string> DispatchStrategy::getAllEndpoints(const std::string& service, enum AddressType addrType, enum ProtoType protoType, const std::string& version)
{
	const FPZKClient::ServiceInfosPtr sip = _fpzk->getServiceInfos(service, "", "", false);
	if (!sip)
		return std::set<std::string>();

	_serviceStrategies[service].updateCheck(sip);
	return _serviceStrategies[service].findAll(addrType, protoType, version);
}

//=========================================//
//-       DispatchQuestProcessor          -//
//=========================================//
DispatchQuestProcessor::DispatchQuestProcessor()
{
	ServiceNode::weightBalance = Setting::getInt("Dispatch.weightBalance", 31);
	std::string allowedServers = Setting::getString("Dispatch.allowedServers");
	std::set<std::string> serverSets;
	StringUtil::split(allowedServers, ", ", serverSets);

	if (serverSets.empty())
	{
		LOG_FATAL("Config item Dispatch.allowedServers is invalid. No allowed service can be Dispatched.");
		exit(0);
	}

	for (auto server: serverSets)
	{
		std::vector<std::string> ss;
		StringUtil::split(server, "@", ss);
		if (ss.size() == 2)
			_allowedServers[ss[0]] = ss[1];
		else if (ss.size() == 1)	
			_allowedServers[ss[0]] = "";
		else
			LOG_ERROR("Invalid server %s in config item Dispatch.allowedServers.", server.c_str());
	}

	_fpzk = FPZKClient::create();
	_fpzk->monitorDetail(true, serverSets);

	registerMethod("which",    &DispatchQuestProcessor::which);
	registerMethod("whichall", &DispatchQuestProcessor::whichall);
}


FPAnswerPtr DispatchQuestProcessor::fetchEndpoint(const FPReaderPtr args, const FPQuestPtr quest, bool all)
{
	std::string service = args->wantString("what");
	std::string addrTypeStr = args->getString("addrType", "ipv4");
	std::string protoTypeStr = args->getString("proto", "tcp");
	std::string version = args->getString("version");

	auto it = _allowedServers.find(service);
	if (it == _allowedServers.end())
		return FPAWriter::errorAnswer(quest, DispatchError_InvalidParameter, "Disallowed service.", "Dispatcher");
	if (it->second.size() > 0)
		service += "@" + it->second;

	enum AddressType addrType;
	if (addrTypeStr == "ipv4")
		addrType = AT_IPv4;
	else if (addrTypeStr == "ipv6")
		addrType = AT_IPv6;
	else if (addrTypeStr == "domain")
		addrType = AT_Domain;
	else
		return FPAWriter::errorAnswer(quest, DispatchError_InvalidParameter, "Invalid address type.", "Dispatcher");

	enum ProtoType protoType;
	if (protoTypeStr == "tcp")
		protoType = PT_TCP;
	else if (protoTypeStr == "ssl" || protoTypeStr == "tls")
		protoType = PT_SSL;
	else if (protoTypeStr == "udp")
		protoType = PT_UDP;
	else
		return FPAWriter::errorAnswer(quest, DispatchError_InvalidParameter, "Invalid protocol type.", "Dispatcher");

	//-- check & init thread local data.
	if (_strategy == nullptr)
		_strategy.reset(new DispatchStrategy(_fpzk));

	FPAWriter aw(1, quest);
	if (all == false)
		aw.param("endpoint", _strategy->dispatch(service, addrType, protoType, version));
	else
		aw.param("endpoints", _strategy->getAllEndpoints(service, addrType, protoType, version));

	return aw.take();
}
