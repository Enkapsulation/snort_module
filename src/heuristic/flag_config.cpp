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

static std::map< std::string, float > s_attackFlags = { { "Dattack", Default::s_attackTypeDDoS },
														{ "Pattack", Default::s_attackTypePhishing },
														{ "Mattack", Default::s_attackTypeMalware },
														{ "Rattack", Default::s_attackTypeRansomware },
														{ "Sattack", Default::s_attackTypeDoS } };
static std::map< std::string, float > s_rangeFlags	= { { "Srange", Default::s_rangeSingle },
														{ "Prange", Default::s_rangePartial },
														{ "Crange", Default::s_rangeComplete } };

static std::map< std::string, float > s_availabilityFlags = { { "Navailability", Default::s_availabilityNone },
															  { "Pavailability", Default::s_availabilityPartial },
															  { "Cavailability", Default::s_availabilityComplete } };

static std::map< std::string, float > s_accessFlags
	= { { "Naccess", Default::s_accessNone }, { "Uaccess", Default::s_accessUser } };

bool setFlagsMaps( std::string identifier, float value )
{
	static constexpr size_t mapCount{ 5U };
	std::array< std::map< std::string, float >*, mapCount > allMaps{
		&s_dangerousFlags, &s_attackFlags, &s_rangeFlags, &s_availabilityFlags, &s_accessFlags
	};

	for( auto& map : allMaps )
	{
		std::cout << identifier << std::endl;
		if( map->find( identifier ) != map->end() )
		{
			( *map )[ identifier ] = value;
			return true;
		}
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
		std::cout << "ACCESS " << accessFlag->second;
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