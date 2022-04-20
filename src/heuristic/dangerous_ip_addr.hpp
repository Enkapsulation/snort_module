#pragma once
#include "flag_config.hpp"

#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <vector>

class DangerousIpAddr
{
public:
	sockaddr_in m_ipAddr;
	uint64_t m_packetCounter;
	float m_networkEntropy;

	DangerousIpAddr( const std::vector< Parameters::Flag >& m_flags,
					 sockaddr_in ipAddr,
					 uint64_t packetCounter,
					 float networkEntropy );

	friend std::ostream& operator<<( std::ostream& output, const DangerousIpAddr& dangerousIpAddr );

	void incrementCounter();

	static sockaddr_in makeSockaddr( std::string ip );
	float getValueAllFlags() const;
	const std::vector< Parameters::Flag >& getAllFlags() const;

private:
	std::vector< Parameters::Flag > m_flags;
};
