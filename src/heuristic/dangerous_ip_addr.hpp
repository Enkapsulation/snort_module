#pragma once
#include "risk_flag.hpp"

#include <arpa/inet.h>
#include <string>

class DangerousIpAddr
{
public:
	sockaddr_in m_ipAddr;
	Parameters::RiskFlag m_riskFlag;
	uint64_t m_packetCounter;
	double m_networkEntropy;

	DangerousIpAddr( sockaddr_in ipAddr, Parameters::RiskFlag riskFlag, uint64_t packetCounter, double networkEntropy );

	static sockaddr_in makeSockaddr( std::string ip );
};
