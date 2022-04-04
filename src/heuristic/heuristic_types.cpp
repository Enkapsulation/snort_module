#include "heuristic_types.hpp"

RiskFLag GetRiskFlag( std::string riskFlag )
{
	static std::map< std::string, RiskFLag > const string2RiskFLag
		= { { "H", RiskFLag::H }, { "M", RiskFLag::M }, { "L", RiskFLag::L } };

	return string2RiskFLag.find( riskFlag )->second;
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
		= { { "S", AccessFlag::none }, { "P", AccessFlag::user } };

	return string2AccessFlag.find( accessFlag )->second;
}

AvailabilityFlags getAvailabilityFlags( std::string availabilityFlags )
{
	static std::map< std::string, AvailabilityFlags > const string2AvailabilityFlags = {
		{ "N", AvailabilityFlags::none }, { "P", AvailabilityFlags::partial }, { "C", AvailabilityFlags::complete }
	};

	return string2AvailabilityFlags.find( availabilityFlags )->second;
}