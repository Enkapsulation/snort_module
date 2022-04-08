#include <fstream>
#include <iostream>

#include "framework/value.h"
#include <arpa/inet.h>
#include <iterator>
#include <netinet/in.h>

#include "config.hpp"
#include "heuristic_types.hpp"
#include "utils.hpp"

HeuristicConfig::HeuristicConfig( double sensitivity,
								  double dangerousEntropy,
								  double packetValue,
								  std::string filenameMalicious )
	: m_sensitivity( sensitivity ),
	  m_dangerousEntropy( dangerousEntropy ),
	  m_packetValue( packetValue ),
	  m_filenameMalicious( filenameMalicious ),
	  m_filenameConfig( nullptr ),
	  m_dangerousIpAdresses()
{
}

HeuristicConfig::operator std::string() const
{
	std::string msg{};

	msg += "{ sensitivity: " + std::to_string( getSensitivity() ) + "\n";
	msg += " entropy: " + std::to_string( getDangerousEntropy() ) + "\n";
	msg += " default packet value: " + std::to_string( getPacketValue() ) + "\n";
	msg += " Filename: " + getFilenameMalicious() + "}";

	return msg;
}

bool HeuristicConfig::set( const snort::Value& value )
{
	const auto& valueName{ value.get_name() };

	if( valueName == s_sensitivityName.data() )
	{
		setSensitivity( value.get_real() );
	}
	else if( valueName == s_dangerousEntropyName.data() )
	{
		setDangerousEntropy( value.get_real() );
	}
	else if( valueName == s_packetValueName.data() )
	{
		setPacketValue( value.get_real() );
	}
	else if( valueName == s_filenameMaliciousName.data() )
	{
		setFilenameMalicious( value.get_as_string() );
		readCSV();
	}
	else if( valueName )
	{
	}
	else
	{
		return false;
	}

	return true;
}

HeuristicConfig HeuristicConfig::getDefaultConfig()
{
	return { s_defaultSensitivity, s_defaultDangerousEntropy, s_defaultPacketValue, s_defaultFilenameMalicious.data() };
}

double HeuristicConfig::getSensitivity() const
{
	return m_sensitivity;
}

double HeuristicConfig::getDangerousEntropy() const
{
	return m_dangerousEntropy;
}

double HeuristicConfig::getPacketValue() const
{
	return m_packetValue;
}

std::string HeuristicConfig::getFilenameMalicious() const
{
	return m_filenameMalicious;
}

std::shared_ptr< DangerousIpConfig > HeuristicConfig::getFilenameConfig() const
{
	return m_filenameConfig;
}

const std::vector< DangerousIpAddr >& HeuristicConfig::getDangerousIpAdresses() const
{
	return m_dangerousIpAdresses;
}

void HeuristicConfig::setSensitivity( double sensitivity )
{
	m_sensitivity = sensitivity;
};

void HeuristicConfig::setDangerousEntropy( double dangerousEntropy )
{
	m_dangerousEntropy = dangerousEntropy;
}

void HeuristicConfig::setPacketValue( double packetValue )
{
	m_packetValue = packetValue;
}

void HeuristicConfig::setFilenameMalicious( const std::string& filenameMalicious )
{
	m_filenameMalicious = filenameMalicious;
}

void HeuristicConfig::setFilenameConfig( std::shared_ptr< DangerousIpConfig > filenameConfig )
{
	m_filenameConfig = filenameConfig;
}

void HeuristicConfig::readCSV()
{
	std::ifstream maliciousFile( getFilenameMalicious() );

	if( maliciousFile.bad() )
	{
		std::cout << "ERROR: Where malicious file" << std::endl;
		return;
	}

	loadDangerousIp( maliciousFile );
}

void HeuristicConfig::loadDangerousIp( std::ifstream& file )
{
	for( const auto& row : CSVRange( file ) )
	{
		sockaddr_in ip_addr{ DangerousIpAddr::makeSockaddr( row[ adressIp ].c_str() ) };
		eRiskFLag risk_flag				= getRiskFlag( row[ riskFlag ] );
		eAttackTypes attack_type		= getAttackFlag( row[ attackType ] );
		eRangeFlags range				= getRangeFlag( row[ rangeFlag ] );
		eAccessFlag access				= getAccessFlag( row[ accessFlag ] );
		eAvailabilityFlags availability = getAvailabilityFlags( row[ avaiabilityFlag ] );
		auto packet_counter				= std::stoi( row[ counter ] );
		double network_entropy			= std::stod( row[ packetEntropy ] );

		DangerousIpAddr ipAddrInfo(
			ip_addr, attack_type, range, access, availability, risk_flag, packet_counter, network_entropy );

		m_dangerousIpAdresses.push_back( ipAddrInfo );
	}

	if( m_dangerousIpAdresses.empty() )
	{
		std::cout << "ERROR: Where malicious file" << std::endl;
	}
}
