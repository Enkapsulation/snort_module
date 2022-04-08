#include "flag_config.hpp"
#include "flag_default_value.hpp"
#include "heuristic_types.hpp"
#include <iostream>
#include <string>

// RiskFLag::RiskFLag( double high, double medium, double low ) : m_high( high ), m_medium( medium ), m_low( low ) {}

// double RiskFLag::getFLagValue( std::string flag ) const
// {
// 	const auto& risk_flag{ riskFlagValue.find( flag ) };
// 	if( risk_flag != riskFlagValue.cend() )
// 	{
// 		return risk_flag->second;
// 	}
// 	return m_high;
// }

// void RiskFLag::setDefaultValue( std::string flag, double value )
// {
// 	const auto& risk_flag{ riskFlagValue.find( flag ) };
// 	if( risk_flag != riskFlagValue.cend() )
// 	{
// 		risk_flag->second = value;
// 	}
// 	else
// 	{
// 		std::cout << "[ERROR] Can't change value for risk flag" << std::endl;
// 	}
// }

// FlagManager::FlagManager() : RiskFLag(), AttackType(), RangeFLag(), AccessFlag(), AvailabilityFlag();