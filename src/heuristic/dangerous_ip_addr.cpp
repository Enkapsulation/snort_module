#include "dangerous_ip_addr.hpp"
#include <string>

DangerousIpAddr::DangerousIpAddr( sockaddr_in ipAddr,
								  Parameters::Flag dangerousFlag,
								  Parameters::Flag attackType,
								  Parameters::Flag rangeFlag,
								  Parameters::Flag accessFlag,
								  Parameters::Flag availabilityFlag,
								  uint64_t packetCounter,
								  float networkEntropy )
	: m_ipAddr( ipAddr ),
	  m_dangerousFlag( dangerousFlag ),
	  m_attackType( attackType ),
	  m_rangeFlag( rangeFlag ),
	  m_accessFlag( accessFlag ),
	  m_availabilityFlag( availabilityFlag ),
	  m_packetCounter( packetCounter ),
	  m_networkEntropy( networkEntropy )
{
}

std::ostream& operator<<( std::ostream& output, const DangerousIpAddr& dangerousIpAddr )
{
	const auto ipAddInstr{ std::string( inet_ntoa( dangerousIpAddr.m_ipAddr.sin_addr ) ) };
	output << ipAddInstr << ",";
	output << dangerousIpAddr.m_dangerousFlag.getIdentifier() << ",";
	output << dangerousIpAddr.m_attackType.getIdentifier() << ",";
	output << dangerousIpAddr.m_rangeFlag.getIdentifier() << ",";
	output << dangerousIpAddr.m_accessFlag.getIdentifier() << ",";
	output << dangerousIpAddr.m_availabilityFlag.getIdentifier() << ",";
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

	value += m_dangerousFlag.getValue();
	value += m_attackType.getValue();
	value += m_rangeFlag.getValue();
	value += m_accessFlag.getValue();
	value += m_availabilityFlag.getValue();

	return value;
}
