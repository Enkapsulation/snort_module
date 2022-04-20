#include <fstream>
#include <iostream>

#include "flag.hpp"
#include "flag_config.hpp"
#include "framework/value.h"
#include <arpa/inet.h>
#include <iterator>
#include <map>
#include <netinet/in.h>
#include <optional>
#include <ostream>
#include <string>

#include "config.hpp"
#include "utils.hpp"

HeuristicConfig::HeuristicConfig( float sensitivity, float entropy, float packetValue, std::string filenameMalicious )
	: m_filenameMalicious( filenameMalicious ), m_dangerousIpAdresses()
{
}

HeuristicConfig::~HeuristicConfig()
{
	saveAllDangerousIps();
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

	msg += "{\n sensitivity: " + std::to_string( getSensitivity() ) + "\n";
	msg += " entropy: " + std::to_string( getEntropy() ) + "\n";
	msg += " packet value: " + std::to_string( getPacketValue() ) + "\n";
	msg += " Filename: " + getFilenameMalicious() + "\n}";

	return msg;
}

bool HeuristicConfig::set( const char* rawString, const snort::Value& value )
{
	const std::string& valueName{ value.get_name() };
	const auto& fullParam{ static_cast< std::string >( rawString ) };

	if( valueName.empty() )
	{
		return false;
	}

	auto flagType = []( std::string flagIdentifier ) -> std::string
	{
		std::string first  = flagIdentifier.substr( flagIdentifier.find( "." ) + 1 );
		std::string second = first.substr( 0, first.find( "." ) );

		return second;
	};

	const auto isFlag{ Parameters::setFlagsMaps( flagType( fullParam ), valueName, value.get_real() ) };

	if( isFlag )
	{
		return true;
	}
	if( m_parameters.find( valueName ) != m_parameters.end() )
	{
		m_parameters[ valueName ] = value.get_real();
	}
	else if( valueName == s_filenameMaliciousName )
	{
		setFilenameMalicious( value.get_as_string() );
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

float HeuristicConfig::getValueFromParameters( HeuristicConfig::Key key ) const
{
	return m_parameters.find( key )->second;
}

float HeuristicConfig::getSensitivity() const
{
	return getValueFromParameters( s_sensitivityName.data() );
}

float HeuristicConfig::getEntropy() const
{
	return getValueFromParameters( s_entropyName.data() );
}

float HeuristicConfig::getPacketValue() const
{
	return getValueFromParameters( s_packetValueName.data() );
}

std::string HeuristicConfig::getFilenameMalicious() const
{
	return m_filenameMalicious;
}

const std::vector< DangerousIpAddr >& HeuristicConfig::getDangerousIpAdresses() const
{
	return m_dangerousIpAdresses;
}

void HeuristicConfig::setFilenameMalicious( const std::string& filenameMalicious )
{
	m_filenameMalicious = filenameMalicious;
}

void HeuristicConfig::saveAllDangerousIps()
{
	std::ofstream outputFile( "scan_result.csv", std::ios::app );

	if( !m_dangerousIpAdresses.empty() )
	{
		outputFile << std::endl << "----------- ENTER -----------" << std::endl;
	}

	for( const auto& ip : m_dangerousIpAdresses )
	{
		outputFile << ip;
	}
	outputFile.close();
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

		Parameters::DangerousFlag dangerousFlag( row[ DangerousFlag ] );
		Parameters::AttackType attackTypeFlag( row[ AttackType ] );
		Parameters::RangeFlag rangeFlag( row[ RangeFlag ] );
		Parameters::AccessFlag accessFlag( row[ AccessFlag ] );
		Parameters::AvailabilityFlag avaiabilityFlag( row[ AvaiabilityFlag ] );

		auto packet_counter	  = std::stoi( row[ Counter ] );
		float network_entropy = std::stod( row[ PacketEntropy ] );

		DangerousIpAddr dangerousIpAddr( ip_addr,
										 dangerousFlag,
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
