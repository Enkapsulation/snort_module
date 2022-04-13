#include "flag_config.hpp"
#include "flag_default_value.hpp"
#include <iostream>
#include <map>
#include <string>
namespace Parameters
{

static std::map< std::string, float > s_riskFlags
	= { { "Hrisk", Default::s_highRisk }, { "Mrisk", Default::s_mediumRisk }, { "Lrisk", Default::s_lowRisk } };

static std::map< std::string, float > s_attackFlags = { { "D", Default::s_attackTypeDDoS },
														{ "P", Default::s_attackTypePhishing },
														{ "M", Default::s_attackTypeMalware },
														{ "R", Default::s_attackTypeRansomware },
														{ "S", Default::s_attackTypeDoS } };
static std::map< std::string, float > s_rangeFlags
	= { { "S", Default::s_rangeSingle }, { "P", Default::s_rangePartial }, { "C", Default::s_rangeComplete } };

static std::map< std::string, float > s_availabilityFlags = { { "N", Default::s_availabilityNone },
															  { "P", Default::s_availabilityPartial },
															  { "C", Default::s_availabilityComplete } };

static std::map< std::string, float > s_accessFlags
	= { { "N", Default::s_accessNone }, { "U", Default::s_accessUser } };

bool setFlagsMaps( std::string identifier, float value )
{
	const auto isFound{ s_riskFlags.find( identifier ) != s_riskFlags.end() };
	if( isFound )
	{
		s_riskFlags[ identifier ] = value;
	}

	return isFound;
	return true;
}

RiskFlag::RiskFlag( std::string identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) ) {}

float RiskFlag::getValueFromIdentifier( std::string identifier ) const
{
	const auto& riskFlag{ s_riskFlags.find( identifier ) };

	if( riskFlag != s_riskFlags.end() )
	{
		return riskFlag->second;
	}

	return RiskFlag::getDefault();
}

float RiskFlag::getDefault() const
{
	return Default::s_riskFlagFactor * Default::s_highRisk;
}

AttackType::AttackType( std::string identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) ) {}

float AttackType::getValueFromIdentifier( std::string identifier ) const
{
	const auto& attackFlag{ s_attackFlags.find( identifier ) };

	if( attackFlag != s_attackFlags.cend() )
	{
		return attackFlag->second;
	}

	return AttackType::getDefault();
}

float AttackType::getDefault() const
{
	return Default::s_attackTypeFlagFactor * Default::s_attackTypeMalware;
}

RangeFlag::RangeFlag( std::string identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) ) {}

float RangeFlag::getValueFromIdentifier( std::string identifier ) const
{
	const auto& rangeFlag{ s_rangeFlags.find( identifier ) };

	if( rangeFlag != s_rangeFlags.cend() )
	{
		return rangeFlag->second;
	}

	return RangeFlag::getDefault();
}

float RangeFlag::getDefault() const
{
	return Default::s_rangeSingle;
}

AccessFlag::AccessFlag( std::string identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) ) {}

float AccessFlag::getValueFromIdentifier( std::string identifier ) const
{
	const auto& accessFlag{ s_accessFlags.find( identifier ) };

	if( accessFlag != s_accessFlags.cend() )
	{
		return accessFlag->second;
	}

	return AccessFlag::getDefault();
}

float AccessFlag::getDefault() const
{
	return Default::s_accessNone;
}

AvailabilityFlag::AvailabilityFlag( std::string identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) )
{
}

float AvailabilityFlag::getValueFromIdentifier( std::string identifier ) const
{
	const auto& availabilityFlag{ s_availabilityFlags.find( identifier ) };

	if( availabilityFlag != s_availabilityFlags.cend() )
	{
		return availabilityFlag->second;
	}

	return AvailabilityFlag::getDefault();
}

float AvailabilityFlag::getDefault() const
{
	return Default::s_availabilityNone;
}
} // namespace Parameters