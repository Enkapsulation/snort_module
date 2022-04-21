#pragma once
#include "flag_factory.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

class DangerousIpAddr
{
public:
	using Flags = std::vector< Parameters::Flag >;

	DangerousIpAddr( const Flags& m_flags,
					 sockaddr_in ipAddr,
					 std::string attackTypeId,
					 std::string dangerousTypeId,
					 uint64_t packetCounter,
					 float networkEntropy );

	friend std::ostream& operator<<( std::ostream& output, const DangerousIpAddr& dangerousIpAddr );

	void incrementCounter();
	void setNetworkEntropy( float networkEntropy );

	const Flags& getAllFlags() const;
	sockaddr_in getSockAddr() const;
	std::string getAttackTypeId() const;
	std::string getDangerousTypeId() const;
	uint64_t getPacketCounter() const;
	float getNetworkEntropy() const;
	float getValueAllFlags() const;

	static sockaddr_in makeSockaddr( std::string ip );

private:
	Flags m_flags;
	sockaddr_in m_ipAddr;
	std::string m_attackTypeId;
	std::string m_dangerousTypeId;
	uint64_t m_packetCounter;
	float m_networkEntropy;
};
