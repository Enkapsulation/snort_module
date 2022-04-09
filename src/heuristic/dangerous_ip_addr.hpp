#pragma once
#include "flag_config.hpp"

#include <arpa/inet.h>
#include <string>

class DangerousIpAddr
{
public:
	sockaddr_in m_ipAddr;
	Parameters::RiskFlag m_riskFlag;
	Parameters::AttackType m_attackType;
	Parameters::RangeFlag m_rangeFlag;
	Parameters::AccessFlag m_accessFlag;
	Parameters::AvailabilityFlag m_availabilityFlag;
	uint64_t m_packetCounter;
	float m_networkEntropy;

	DangerousIpAddr( sockaddr_in ipAddr,
					 Parameters::RiskFlag riskFlag,
					 Parameters::AttackType m_attackType,
					 Parameters::RangeFlag m_rangeFlag,
					 Parameters::AccessFlag m_accessFlag,
					 Parameters::AvailabilityFlag m_availabilityFlag,
					 uint64_t packetCounter,
					 float networkEntropy );

	void incrementCounter();

	static sockaddr_in makeSockaddr( std::string ip );
};
