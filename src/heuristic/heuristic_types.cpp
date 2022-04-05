#include "heuristic_types.hpp"

static const std::map< std::string, RiskFLag > string2RiskFLag
	= { { "H", RiskFLag::H }, { "M", RiskFLag::M }, { "L", RiskFLag::L } };

RiskFLag GetRiskFlag( std::string riskFlagStr )
{
	const auto& riskFlag{ string2RiskFLag.find( riskFlagStr ) };
	if( riskFlag != string2RiskFLag.cend() )
	{
		return riskFlag->second;
	}
	return RiskFLag::H;
}

AttackTypes getAttackFlag( std::string attackFlag )
{
	static std::map< std::string, AttackTypes > const string2AttackFlag = { { "D", AttackTypes::ddos },
																			{ "P", AttackTypes::phishing },
																			{ "M", AttackTypes::malware },
																			{ "R", AttackTypes::ransomware },
																			{ "S", AttackTypes::dos } };

	return string2AttackFlag.find( attackFlag )->second;
}

RangeFlags getRangeFlag( std::string rangeFlag )
{
	static std::map< std::string, RangeFlags > const string2RangeFlag
		= { { "S", RangeFlags::single }, { "P", RangeFlags::partial }, { "C", RangeFlags::complete } };

	return string2RangeFlag.find( rangeFlag )->second;
}

AccessFlag getAccessFlag( std::string accessFlag )
{
	static std::map< std::string, AccessFlag > const string2AccessFlag
		= { { "N", AccessFlag::none }, { "U", AccessFlag::user } };

	return string2AccessFlag.find( accessFlag )->second;
}

AvailabilityFlags getAvailabilityFlags( std::string availabilityFlags )
{
	static std::map< std::string, AvailabilityFlags > const string2AvailabilityFlags = {
		{ "N", AvailabilityFlags::none }, { "P", AvailabilityFlags::partial }, { "C", AvailabilityFlags::complete }
	};

	return string2AvailabilityFlags.find( availabilityFlags )->second;
}