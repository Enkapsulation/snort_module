#pragma once

#include "flag_default_value.hpp"
#include <map>
#include <string>

using namespace defaultValueFlag;

class RiskFLag
{
public:
	RiskFLag( double high, double medium, double low );
	double getFLagValue( std::string ) const;

private:
	void setDefaultValue( std::string, double );

	double m_high{ defaultValueFlag::s_defaultRiskHigh };
	double m_medium{ defaultValueFlag::s_defaultRiskMedium };
	double m_low{ defaultValueFlag::s_defaultRiskLow };

	std::map< std::string, double > riskFlagValue = { { "H", m_high }, { "M", m_medium }, { "L", m_low } };
};

class AttackType
{
public:
	AttackType( double ddos, double phishing, double malware, double ransomware, double dos );
	double getFLagValue() const;

private:
	void setDefaultValue( std::string, double );

	double m_DDoS;
	double m_Phishing;
	double m_Malware;
	double m_Ransomware;
	double m_DoS;
};

class RangeFLag
{
public:
	RangeFLag( double single, double partial, double complete );
	double getFLagValue() const;

private:
	void setDefaultValue( std::string, double );

	double m_single;
	double m_partial;
	double m_complete;
};

class AccessFlag
{
public:
	AccessFlag( double none, double user );
	double getFLagValue() const;

private:
	void setDefaultValue( std::string, double );

	double m_none;
	double m_user;
};

class AvailabilityFlag
{
public:
	AvailabilityFlag( double none, double partial, double complete );
	double getFLagValue() const;

private:
	void setDefaultValue( std::string, double );

	double m_none;
	double m_partial;
	double m_complete;
};

class FlagManager
{
public:
	FlagManager();

private:
};