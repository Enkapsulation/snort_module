#include "heuristic_types.hpp"

static const std::map< std::string, eRiskFLag > string2RiskFLag
	= { { "H", eRiskFLag::H }, { "M", eRiskFLag::M }, { "L", eRiskFLag::L } };

eRiskFLag getRiskFlag( std::string riskFlag )
{
	const auto& risk_flag{ string2RiskFLag.find( riskFlag ) };
	if( risk_flag != string2RiskFLag.cend() )
	{
		return risk_flag->second;
	}
	return eRiskFLag::H;
}

static const std::map< std::string, eAttackTypes > string2AttackFlag = { { "D", eAttackTypes::ddos },
																		 { "P", eAttackTypes::phishing },
																		 { "M", eAttackTypes::malware },
																		 { "R", eAttackTypes::ransomware },
																		 { "S", eAttackTypes::dos } };

eAttackTypes getAttackFlag( std::string attackFlag )
{
	const auto& attack_flag{ string2AttackFlag.find( attackFlag ) };
	if( attack_flag != string2AttackFlag.cend() )
	{
		return attack_flag->second;
	}
	return eAttackTypes::malware;
}

static std::map< std::string, eRangeFlags > const string2RangeFlag
	= { { "S", eRangeFlags::single }, { "P", eRangeFlags::partial }, { "C", eRangeFlags::complete } };

eRangeFlags getRangeFlag( std::string rangeFlag )
{
	const auto& range_flag{ string2RangeFlag.find( rangeFlag ) };
	if( range_flag != string2RangeFlag.cend() )
	{
		return range_flag->second;
	}
	return eRangeFlags::complete;
}

static std::map< std::string, eAccessFlag > const string2AccessFlag
	= { { "N", eAccessFlag::none }, { "U", eAccessFlag::user } };

eAccessFlag getAccessFlag( std::string accessFlag )
{
	const auto& access_flag{ string2AccessFlag.find( accessFlag ) };
	if( access_flag != string2AccessFlag.cend() )
	{
		return access_flag->second;
	}
	return eAccessFlag::user;
}

static std::map< std::string, eAvailabilityFlags > const string2AvailabilityFlags = {
	{ "N", eAvailabilityFlags::none }, { "P", eAvailabilityFlags::partial }, { "C", eAvailabilityFlags::complete }
};

eAvailabilityFlags getAvailabilityFlags( std::string availabilityFlags )
{
	const auto& availability_flag{ string2AvailabilityFlags.find( availabilityFlags ) };
	if( availability_flag != string2AvailabilityFlags.cend() )
	{
		return availability_flag->second;
	}
	return eAvailabilityFlags::complete;
}

sockaddr_in DangerousIpAddr::makeSockaddr( std::string ip )
{
	sockaddr_in ip_addr{};
	inet_pton( AF_INET, ip.c_str(), &ip_addr.sin_addr );
	return ip_addr;
}
