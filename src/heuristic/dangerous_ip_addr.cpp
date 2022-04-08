#include "dangerous_ip_addr.hpp"

DangerousIpAddr::DangerousIpAddr( sockaddr_in ipAddr,
								  Parameters::RiskFlag riskFlag,
								  uint64_t packetCounter,
								  double networkEntropy )
	: m_ipAddr( ipAddr ), m_riskFlag( riskFlag ), m_packetCounter( packetCounter ), m_networkEntropy( networkEntropy )
{
}