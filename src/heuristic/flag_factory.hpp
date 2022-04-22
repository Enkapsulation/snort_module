#pragma once
#include "flag.hpp"
namespace Parameters
{
using FlagData	   = std::map< std::string, float >;
using AllFlagsData = const std::map< std::string, FlagData* >;

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
	static FlagData s_accessFlags;
	static FlagData s_dangerousFlags;
	static FlagData s_attackFlags;
	static FlagData s_rangeFlags;
	static FlagData s_availabilityFlags;
	static AllFlagsData s_flagsData;
};

} // namespace Parameters