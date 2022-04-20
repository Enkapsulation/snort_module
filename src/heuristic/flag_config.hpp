#pragma once
#include "flag.hpp"
#include <string>
namespace Parameters
{
using FlagData = std::map< std::string, float >;

enum class FlagType
{
	Dangerous,
	Attack,
	Range,
	Access,
	Availability
};

class FlagFactory
{
public:
	static Flag createFlag( FlagType flagType, std::string identifier );
	static bool setFlagsData( std::string flagDataIdentifier, std::string identifier, float value );

protected:
	static float getValueFromIdentifier( FlagData flagData, std::string identifier );
};

} // namespace Parameters