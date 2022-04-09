#include "dangerous_ip_addr.hpp"

DangerousIpAddr::DangerousIpAddr( sockaddr_in ipAddr,
								  Parameters::RiskFlag riskFlag,
								  Parameters::AttackType attackType,
								  Parameters::RangeFlag rangeFlag,
								  Parameters::AccessFlag accessFlag,
								  Parameters::AvailabilityFlag availabilityFlag,
								  uint64_t packetCounter,
								  float networkEntropy )
	: m_ipAddr( ipAddr ),
	  m_riskFlag( riskFlag ),
	  m_attackType( attackType ),
	  m_rangeFlag( rangeFlag ),
	  m_accessFlag( accessFlag ),
	  m_availabilityFlag( availabilityFlag ),
	  m_packetCounter( packetCounter ),
	  m_networkEntropy( networkEntropy )
{
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

	value += m_riskFlag.getValue();
	value += m_attackType.getValue();
	value += m_rangeFlag.getValue();
	value += m_accessFlag.getValue();
	value += m_availabilityFlag.getValue();

	return value;
}
