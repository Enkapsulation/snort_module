#include "heuristic_types.hpp"

static const std::map< std::string, RiskFLag > string2RiskFLag
	= { { "H", RiskFLag::H }, { "M", RiskFLag::M }, { "L", RiskFLag::L } };

RiskFLag GetRiskFlag( std::string riskFlag )
{
	const auto& risk_flag{ string2RiskFLag.find( riskFlag ) };
	if( risk_flag != string2RiskFLag.cend() )
	{
		return risk_flag->second;
	}
	return RiskFLag::H;
}

static const std::map< std::string, AttackTypes > string2AttackFlag = { { "D", AttackTypes::ddos },
																		{ "P", AttackTypes::phishing },
																		{ "M", AttackTypes::malware },
																		{ "R", AttackTypes::ransomware },
																		{ "S", AttackTypes::dos } };

AttackTypes getAttackFlag( std::string attackFlag )
{
	const auto& attack_flag{ string2AttackFlag.find( attackFlag ) };
	if( attack_flag != string2AttackFlag.cend() )
	{
		return attack_flag->second;
	}
	return AttackTypes::malware;
}

static std::map< std::string, RangeFlags > const string2RangeFlag
	= { { "S", RangeFlags::single }, { "P", RangeFlags::partial }, { "C", RangeFlags::complete } };

RangeFlags getRangeFlag( std::string rangeFlag )
{
	const auto& range_flag{ string2RangeFlag.find( rangeFlag ) };
	if( range_flag != string2RangeFlag.cend() )
	{
		return range_flag->second;
	}
	return RangeFlags::complete;
}

static std::map< std::string, AccessFlag > const string2AccessFlag
	= { { "N", AccessFlag::none }, { "U", AccessFlag::user } };

AccessFlag getAccessFlag( std::string accessFlag )
{
	const auto& access_flag{ string2AccessFlag.find( accessFlag ) };
	if( access_flag != string2AccessFlag.cend() )
	{
		return access_flag->second;
	}
	return AccessFlag::user;
}

static std::map< std::string, AvailabilityFlags > const string2AvailabilityFlags
	= { { "N", AvailabilityFlags::none }, { "P", AvailabilityFlags::partial }, { "C", AvailabilityFlags::complete } };

AvailabilityFlags getAvailabilityFlags( std::string availabilityFlags )
{
	const auto& availability_flag{ string2AvailabilityFlags.find( availabilityFlags ) };
	if( availability_flag != string2AvailabilityFlags.cend() )
	{
		return availability_flag->second;
	}
	return AvailabilityFlags::complete;
}