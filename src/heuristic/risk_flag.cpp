#include "risk_flag.hpp"
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
} // namespace Parameters