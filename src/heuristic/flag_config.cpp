#include "flag_config.hpp"
#include "flag_default_value.hpp"
#include <array>
#include <iostream>
#include <map>
#include <string>
namespace Parameters
{
static FlagData s_dangerousFlags
	= { { "H", Default::s_dangerousHigh }, { "M", Default::s_dangerousMedium }, { "L", Default::s_dangerousLow } };

static FlagData s_attackFlags = { { "D", Default::s_attackTypeDDoS },
								  { "P", Default::s_attackTypePhishing },
								  { "M", Default::s_attackTypeMalware },
								  { "R", Default::s_attackTypeRansomware },
								  { "S", Default::s_attackTypeDoS } };

static FlagData s_rangeFlags
	= { { "S", Default::s_rangeSingle }, { "P", Default::s_rangePartial }, { "C", Default::s_rangeComplete } };

static FlagData s_availabilityFlags = { { "N", Default::s_availabilityNone },
										{ "P", Default::s_availabilityPartial },
										{ "C", Default::s_availabilityComplete } };

static FlagData s_accessFlags = { { "N", Default::s_accessNone }, { "U", Default::s_accessUser } };

bool FlagFactory::setFlagsData( std::string flagDataIdentifier, std::string identifier, float value )
{
	static constexpr size_t mapCount{ 5U };
	std::map< std::string, FlagData* > flagName{ { "dangerous", &s_dangerousFlags },
												 { "attack", &s_attackFlags },
												 { "range", &s_rangeFlags },
												 { "availability", &s_availabilityFlags },
												 { "access", &s_accessFlags } };

	const auto& flag{ flagName.find( flagDataIdentifier ) };

	if( flag != flagName.end() )
	{
		( *flag->second )[ identifier ] = value;
		return true;
	}

	return false;
}

Flag FlagFactory::createFlag( FlagType flagType, std::string identifier )
{
	float value;

	auto setValue
		= [ & ]( const FlagData& flagData ) { value = FlagFactory::getValueFromIdentifier( flagData, identifier ); };

	switch( flagType )
	{
	case FlagType::Dangerous:
		setValue( s_dangerousFlags );
		break;
	case FlagType::Attack:
		setValue( s_attackFlags );
		break;
	case FlagType::Range:
		setValue( s_rangeFlags );
		break;
	case FlagType::Access:
		setValue( s_accessFlags );
		break;
	case FlagType::Availability:
		setValue( s_availabilityFlags );
		break;
	default:
		value = 0;
		break;
	}
	value = FlagFactory::getValueFromIdentifier( s_dangerousFlags, identifier );

	return Flag( identifier, value );
}

float FlagFactory::getValueFromIdentifier( FlagData flagData, std::string identifier )
{
	const auto& flag{ flagData.find( identifier ) };

	if( flag != flagData.end() )
	{
		return flag->second;
	}

	return flagData.cbegin()->second;
}
} // namespace Parameters