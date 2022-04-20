#include "dangerous_ip_addr.hpp"
#include <string>

DangerousIpAddr::DangerousIpAddr( const std::vector< Parameters::Flag >& flags,
								  sockaddr_in ipAddr,
								  uint64_t packetCounter,
								  float networkEntropy )
	: m_flags( flags ), m_ipAddr( ipAddr ), m_packetCounter( packetCounter ), m_networkEntropy( networkEntropy )
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

sockaddr_in DangerousIpAddr::makeSockaddr( std::string ip )
{
	sockaddr_in ip_addr{};
	inet_pton( AF_INET, ip.c_str(), &ip_addr.sin_addr );
	return ip_addr;
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

const std::vector< Parameters::Flag >& DangerousIpAddr::getAllFlags() const
{
	return m_flags;
}
