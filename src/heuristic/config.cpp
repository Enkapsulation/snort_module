#include <fstream>
#include <iostream>

#include "flag.hpp"
#include "framework/value.h"
#include <arpa/inet.h>
#include <iterator>
#include <map>
#include <netinet/in.h>

#include "config.hpp"
#include "utils.hpp"

HeuristicConfig::HeuristicConfig( float sensitivity,
								  float dangerousEntropy,
								  float packetValue,
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

float HeuristicConfig::getSensitivity() const
{
	return m_sensitivity;
}

float HeuristicConfig::getDangerousEntropy() const
{
	return m_dangerousEntropy;
}

float HeuristicConfig::getPacketValue() const
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

void HeuristicConfig::setSensitivity( float sensitivity )
{
	m_sensitivity = sensitivity;
};

void HeuristicConfig::setDangerousEntropy( float dangerousEntropy )
{
	m_dangerousEntropy = dangerousEntropy;
}

void HeuristicConfig::setPacketValue( float packetValue )
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
		sockaddr_in ip_addr{ DangerousIpAddr::makeSockaddr( row[ AdressIp ].c_str() ) };

		auto getChar = [ & ]( CsvEncoder whichFlag ) { return row[ whichFlag ].data()[ 0 ]; };

		Parameters::RiskFlag riskFlag( getChar( RiskFlag ) );
		Parameters::AttackType attackTypeFlag( getChar( AttackType ) );
		Parameters::RangeFlag rangeFlag( getChar( RangeFlag ) );
		Parameters::AccessFlag accessFlag( getChar( AccessFlag ) );
		Parameters::AvailabilityFlag avaiabilityFlag( getChar( AvaiabilityFlag ) );

		auto packet_counter	  = std::stoi( row[ Counter ] );
		float network_entropy = std::stod( row[ PacketEntropy ] );

		DangerousIpAddr dangerousIpAddr( ip_addr,
										 riskFlag,
										 attackTypeFlag,
										 rangeFlag,
										 accessFlag,
										 avaiabilityFlag,
										 packet_counter,
										 network_entropy );

		m_dangerousIpAdresses.push_back( dangerousIpAddr );
	}

	if( m_dangerousIpAdresses.empty() )
	{
		std::cout << "ERROR: Where malicious file" << std::endl;
	}
}
