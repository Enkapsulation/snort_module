#include "flag_config.hpp"
#include "flag_default_value.hpp"
#include <map>
#include <string>

namespace Parameters
{
static const std::map< char, double > s_riskFlags
	= { { 'H', Default::s_highRisk }, { 'M', Default::s_mediumRisk }, { 'L', Default::s_lowRisk } };

float RiskFlag::getValueFromIdentifier() const
{
	const auto& riskFlag{ s_riskFlags.find( m_identifier ) };

	if( riskFlag != s_riskFlags.cend() )
	{
		return riskFlag->second;
	}

	return Default::s_highRisk;
}

static const std::map< char, double > s_attackFlags = { { 'D', Default::s_AttackTypeDDoS },
														{ 'P', Default::s_AttackTypePhishing },
														{ 'M', Default::s_AttackTypeMalware },
														{ 'R', Default::s_AttackTypeRansomware },
														{ 'S', Default::s_AttackTypeDoS } };

float AttackType::getValueFromIdentifier() const
{
	const auto& attackFlag{ s_attackFlags.find( m_identifier ) };

	if( attackFlag != s_riskFlags.cend() )
	{
		return attackFlag->second;
	}

	return Default::s_AttackTypeMalware;
}

static const std::map< char, double > s_rangeFlags
	= { { 'S', Default::s_rangeSingle }, { 'P', Default::s_rangePartial }, { 'C', Default::s_rangeComplete } };

float RangeFLag::getValueFromIdentifier() const
{
	const auto& rangeFlag{ s_rangeFlags.find( m_identifier ) };

	if( rangeFlag != s_riskFlags.cend() )
	{
		return rangeFlag->second;
	}

	return Default::s_rangePartial;
}

static const std::map< char, double > s_accessFlags
	= { { 'N', Default::s_accessNone }, { 'U', Default::s_accessUser } };

float AccessFlag::getValueFromIdentifier() const
{
	const auto& accessFlag{ s_accessFlags.find( m_identifier ) };

	if( accessFlag != s_riskFlags.cend() )
	{
		return accessFlag->second;
	}

	return Default::s_accessNone;
}

static const std::map< char, double > s_availabilityFlags = { { 'N', Default::s_availabilityNone },
															  { 'P', Default::s_availabilityPartial },
															  { 'C', Default::s_availabilityComplete } };

float AvailabilityFlag::getValueFromIdentifier() const
{
	const auto& availabilityFlag{ s_availabilityFlags.find( m_identifier ) };

	if( availabilityFlag != s_riskFlags.cend() )
	{
		return availabilityFlag->second;
	}

	return Default::s_availabilityComplete;
}
} // namespace Parameters