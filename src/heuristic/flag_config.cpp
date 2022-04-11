#include "flag_config.hpp"
#include "flag_default_value.hpp"
#include <map>
#include <string>

namespace Parameters
{
RiskFlag::RiskFlag( char identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) ) {}

static const std::map< char, float > s_riskFlags
	= { { 'H', Default::s_highRisk }, { 'M', Default::s_mediumRisk }, { 'L', Default::s_lowRisk } };

float RiskFlag::getValueFromIdentifier( const char identifier ) const
{
	const auto& riskFlag{ s_riskFlags.find( identifier ) };

	if( riskFlag != s_riskFlags.cend() )
	{
		return riskFlag->second;
	}

	return getDefault();
}

float RiskFlag::getDefault() const
{
	return Default::s_riskFlagFactor * Default::s_highRisk;
}

static const std::map< char, float > s_attackFlags = { { 'D', Default::s_attackTypeDDoS },
													   { 'P', Default::s_attackTypePhishing },
													   { 'M', Default::s_attackTypeMalware },
													   { 'R', Default::s_attackTypeRansomware },
													   { 'S', Default::s_attackTypeDoS } };

AttackType::AttackType( char identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) ) {}

float AttackType::getValueFromIdentifier( const char identifier ) const
{
	const auto& attackFlag{ s_attackFlags.find( identifier ) };

	if( attackFlag != s_attackFlags.cend() )
	{
		return attackFlag->second;
	}

	return getDefault();
}

float AttackType::getDefault() const
{
	return Default::s_attackTypeFlagFactor * Default::s_attackTypeMalware;
}

static const std::map< char, float > s_rangeFlags
	= { { 'S', Default::s_rangeSingle }, { 'P', Default::s_rangePartial }, { 'C', Default::s_rangeComplete } };

RangeFlag::RangeFlag( char identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) ) {}

float RangeFlag::getValueFromIdentifier( const char identifier ) const
{
	const auto& rangeFlag{ s_rangeFlags.find( identifier ) };

	if( rangeFlag != s_rangeFlags.cend() )
	{
		return rangeFlag->second;
	}

	return getDefault();
}

float RangeFlag::getDefault() const
{
	return Default::s_rangeSingle;
}

static const std::map< char, float > s_accessFlags = { { 'N', Default::s_accessNone }, { 'U', Default::s_accessUser } };

AccessFlag::AccessFlag( char identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) ) {}

float AccessFlag::getValueFromIdentifier( const char identifier ) const
{
	const auto& accessFlag{ s_accessFlags.find( identifier ) };

	if( accessFlag != s_accessFlags.cend() )
	{
		return accessFlag->second;
	}

	return getDefault();
}

float AccessFlag::getDefault() const
{
	return Default::s_accessNone;
}

static const std::map< char, float > s_availabilityFlags = { { 'N', Default::s_availabilityNone },
															 { 'P', Default::s_availabilityPartial },
															 { 'C', Default::s_availabilityComplete } };

AvailabilityFlag::AvailabilityFlag( char identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) ) {}

float AvailabilityFlag::getValueFromIdentifier( const char identifier ) const
{
	const auto& availabilityFlag{ s_availabilityFlags.find( identifier ) };

	if( availabilityFlag != s_availabilityFlags.cend() )
	{
		return availabilityFlag->second;
	}

	return getDefault();
}

float AvailabilityFlag::getDefault() const
{
	return Default::s_availabilityNone;
}
} // namespace Parameters