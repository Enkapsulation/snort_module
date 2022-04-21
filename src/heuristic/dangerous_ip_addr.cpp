#include "dangerous_ip_addr.hpp"
#include <functional>
#include <iostream>
#include <string>

DangerousIpAddr::DangerousIpAddr( const Flags& flags,
								  sockaddr_in ipAddr,
								  std::string attackTypeId,
								  std::string dangerousTypeId,
								  uint64_t packetCounter,
								  float networkEntropy )
	: m_flags( flags ),
	  m_attackTypeId( attackTypeId ),
	  m_dangerousTypeId( dangerousTypeId ),
	  m_ipAddr( ipAddr ),
	  m_packetCounter( packetCounter ),
	  m_networkEntropy( networkEntropy )
{
}

std::ostream& operator<<( std::ostream& output, const DangerousIpAddr& dangerousIpAddr )
{
	const auto ipAddInstr{ std::string( inet_ntoa( dangerousIpAddr.m_ipAddr.sin_addr ) ) };
	output << ipAddInstr << ",";

	for( const auto& flag : dangerousIpAddr.getAllFlags() )
	{
		output << flag.getIdentifier() << ",";
	}

	output << dangerousIpAddr.m_packetCounter << ",";
	output << dangerousIpAddr.m_networkEntropy << std::endl;
	return output;
}

void DangerousIpAddr::incrementCounter()
{
	++m_packetCounter;
}

void DangerousIpAddr::setNetworkEntropy( float networkEntropy )
{
	m_networkEntropy = networkEntropy;
}

const DangerousIpAddr::Flags& DangerousIpAddr::getAllFlags() const
{
	return m_flags;
}

sockaddr_in DangerousIpAddr::getSockAddr() const
{
	return m_ipAddr;
}

std::string DangerousIpAddr::getAttackTypeId() const
{
	return m_attackTypeId.data();
}

std::string DangerousIpAddr::getDangerousTypeId() const
{
	return m_dangerousTypeId.data();
}

uint64_t DangerousIpAddr::getPacketCounter() const
{
	return m_packetCounter;
}

float DangerousIpAddr::getNetworkEntropy() const
{
	return m_networkEntropy;
}

float DangerousIpAddr::getValueAllFlags() const
{
	float value{ 0.F };

	for( const auto& flag : m_flags )
	{
		value += flag.getValue();
	}

	return value;
}

sockaddr_in DangerousIpAddr::makeSockaddr( std::string ip )
{
	sockaddr_in ip_addr{};
	inet_pton( AF_INET, ip.c_str(), &ip_addr.sin_addr );
	return ip_addr;
}
