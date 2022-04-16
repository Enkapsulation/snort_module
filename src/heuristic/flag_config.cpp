#include "flag_config.hpp"
#include "flag_default_value.hpp"
#include <array>
#include <iostream>
#include <map>
#include <string>
namespace Parameters
{

static std::map< std::string, float > s_dangerousFlags
	= { { "H", Default::s_dangerousHigh }, { "M", Default::s_dangerousMedium }, { "L", Default::s_dangerousLow } };

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

bool setFlagsMaps( std::string flagIdentifier, std::string identifier, float value )
{
	static constexpr size_t mapCount{ 5U };
	std::map< std::string, std::map< std::string, float >* > flagName{ { "dangerous", &s_dangerousFlags },
																	   { "attack", &s_attackFlags },
																	   { "range", &s_rangeFlags },
																	   { "availability", &s_availabilityFlags },
																	   { "access", &s_accessFlags } };

	const auto& flag{ flagName.find( flagIdentifier ) };

	if( flag != flagName.end() )
	{
		( *flag->second )[ identifier ] = value;
		return true;
	}

	return false;
}

DangerousFlag::DangerousFlag( std::string identifier ) : Flag( identifier, getValueFromIdentifier( identifier ) ) {}

float DangerousFlag::getValueFromIdentifier( std::string identifier ) const
{
	const auto& dangerousFlag{ s_dangerousFlags.find( identifier ) };

	if( dangerousFlag != s_dangerousFlags.end() )
	{
		return dangerousFlag->second;
	}

	return DangerousFlag::getDefault();
}

float DangerousFlag::getDefault() const
{
	return Default::s_dangerousFlagFactor * Default::s_dangerousHigh;
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