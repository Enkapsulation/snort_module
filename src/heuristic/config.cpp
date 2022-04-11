#include <fstream>
#include <iostream>

#include "flag.hpp"
#include "framework/value.h"
#include <arpa/inet.h>
#include <iterator>
#include <map>
#include <netinet/in.h>
#include <optional>
#include <string>

#include "config.hpp"
#include "utils.hpp"

HeuristicConfig::HeuristicConfig( float sensitivity, float entropy, float packetValue, std::string filenameMalicious )
	: m_sensitivity( sensitivity ),
	  m_entropy( entropy ),
	  m_packetValue( packetValue ),
	  m_filenameMalicious( filenameMalicious ),
	  m_filenameConfig( nullptr ),
	  m_dangerousIpAdresses()
{
}

std::optional< DangerousIpAddr* > HeuristicConfig::find( std::string ip ) const
{
	const auto ipToCompare{ DangerousIpAddr::makeSockaddr( ip ) };

	auto suspiciousIpAddrIterator
		= std::find_if( m_dangerousIpAdresses.begin(),
						m_dangerousIpAdresses.end(),
						[ & ]( const DangerousIpAddr& dangerousIpAddr )
						{ return dangerousIpAddr.m_ipAddr.sin_addr.s_addr == ipToCompare.sin_addr.s_addr; } );

	if( suspiciousIpAddrIterator != m_dangerousIpAdresses.cend() )
	{
		return const_cast< DangerousIpAddr* >( &( *suspiciousIpAddrIterator ) );
	}

	return std::nullopt;
}

HeuristicConfig::operator std::string() const
{
	std::string msg{};

	msg += "{ sensitivity: " + std::to_string( getSensitivity() ) + "\n";
	msg += " entropy: " + std::to_string( getEntropy() ) + "\n";
	msg += " default packet value: " + std::to_string( getPacketValue() ) + "\n";
	msg += " Filename: " + getFilenameMalicious() + "}";

	return msg;
}

bool HeuristicConfig::set( const snort::Value& value )
{

	const auto& valueName{ static_cast< std::string >( value.get_name() ) };

	if( valueName.empty() )
	{
		return false;
	}

	if( valueName == s_sensitivityName )
	{
		setSensitivity( value.get_real() );
	}
	else if( valueName == s_entropyName )
	{
		setEntropy( value.get_real() );
	}
	else if( valueName == s_packetValueName )
	{
		setPacketValue( value.get_real() );
	}
	else if( valueName == s_filenameMaliciousName )
	{
		setFilenameMalicious( value.get_as_string() );
		readCSV();
	}
	else
	{
		return false;
	}

	return true;
}

HeuristicConfig HeuristicConfig::getDefaultConfig()
{
	return { s_defaultSensitivity, s_defaultEntropy, s_defaultPacketValue, s_defaultFilenameMalicious.data() };
}

float HeuristicConfig::getSensitivity() const
{
	return m_sensitivity;
}

float HeuristicConfig::getEntropy() const
{
	return m_entropy;
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

void HeuristicConfig::setEntropy( float entropy )
{
	m_entropy = entropy;
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
