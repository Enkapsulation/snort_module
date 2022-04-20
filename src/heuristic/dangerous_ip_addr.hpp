#pragma once
#include "flag_config.hpp"

#include <arpa/inet.h>
#include <iostream>
#include <string>

class DangerousIpAddr
{
public:
	sockaddr_in m_ipAddr;
	Parameters::Flag m_dangerousFlag;
	Parameters::Flag m_attackType;
	Parameters::Flag m_rangeFlag;
	Parameters::Flag m_accessFlag;
	Parameters::Flag m_availabilityFlag;
	uint64_t m_packetCounter;
	float m_networkEntropy;

	DangerousIpAddr( sockaddr_in ipAddr,
					 Parameters::Flag m_dangerousFlag,
					 Parameters::Flag m_attackType,
					 Parameters::Flag m_rangeFlag,
					 Parameters::Flag m_accessFlag,
					 Parameters::Flag m_availabilityFlag,
					 uint64_t packetCounter,
					 float networkEntropy );

	friend std::ostream& operator<<( std::ostream& output, const DangerousIpAddr& dangerousIpAddr );

	void incrementCounter();

	static sockaddr_in makeSockaddr( std::string ip );
	float getValueAllFlags() const;
};
